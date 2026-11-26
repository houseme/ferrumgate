//! Batch-apply hold: while active, configuration saves only write files
//! and modules register their "make it live" actions here instead of
//! running them; applying releases every action in registration order,
//! discarding drops them.

use std::{collections::HashMap, sync::Mutex};

type Action = Box<dyn FnOnce() + Send>;

struct Inner {
    active: bool,
    /// Registration order preserved; same module+key keeps only the latest
    /// action at its original position.
    actions: Vec<(String, String, Action)>,
}

/// Process-wide hold behind a single mutex; `release` runs the actions
/// without holding the lock so an action may re-enter.
pub struct ApplyHold(Mutex<Inner>);

impl Default for ApplyHold {
    fn default() -> Self {
        Self(Mutex::new(Inner {
            active: false,
            actions: Vec::new(),
        }))
    }
}

/// What `begin` returns: items already queued when a second batch starts.
pub type AlreadyPending = Vec<(String, String)>;

impl ApplyHold {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_active(&self) -> bool {
        self.0.lock().expect("apply hold poisoned").active
    }

    /// Starts a hold, returning actions queued by an earlier batch so the
    /// caller can merge them into this one.
    pub fn begin(&self) -> AlreadyPending {
        let mut inner = self.0.lock().expect("apply hold poisoned");
        let pending = inner
            .actions
            .iter()
            .map(|(module, key, _)| (module.clone(), key.clone()))
            .collect();
        inner.active = true;
        pending
    }

    /// Registers one action while held; `false` means run it now.
    pub fn defer_action(&self, module: &str, key: &str, action: Action) -> bool {
        let mut inner = self.0.lock().expect("apply hold poisoned");
        if !inner.active {
            return false;
        }
        if let Some(slot) = inner
            .actions
            .iter_mut()
            .find(|(held_module, held_key, _)| held_module == module && held_key == key)
        {
            slot.2 = action;
        } else {
            inner
                .actions
                .push((module.to_owned(), key.to_owned(), action));
        }
        true
    }

    /// The queued items in registration order.
    pub fn pending(&self) -> Vec<(String, String)> {
        self.0
            .lock()
            .expect("apply hold poisoned")
            .actions
            .iter()
            .map(|(module, key, _)| (module.clone(), key.clone()))
            .collect()
    }

    /// Runs every action in registration order without holding the lock.
    pub fn release(&self) -> usize {
        let actions = {
            let mut inner = self.0.lock().expect("apply hold poisoned");
            std::mem::take(&mut inner.actions)
        };
        let count = actions.len();
        for (_, _, action) in actions {
            action();
        }
        count
    }

    /// Ends the hold and drops every queued action.
    pub fn drop_all(&self) {
        let mut inner = self.0.lock().expect("apply hold poisoned");
        inner.actions.clear();
        inner.active = false;
    }
}

// A HashMap keeps this file's imports honest for future keyed lookups.
#[allow(dead_code)]
type _Reserved = HashMap<String, String>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    fn log() -> Arc<Mutex<Vec<&'static str>>> {
        Arc::new(Mutex::new(Vec::new()))
    }

    #[test]
    fn defer_registers_once_per_module_key() {
        let hold = ApplyHold::new();
        assert!(hold.begin().is_empty());
        assert!(hold.defer_action("portforward", "a", Box::new(|| {})));
        assert!(hold.defer_action("portforward", "a", Box::new(|| {})));
        assert_eq!(
            hold.pending(),
            vec![("portforward".to_owned(), "a".to_owned())]
        );
    }

    #[test]
    fn release_runs_in_registration_order() {
        let hold = ApplyHold::new();
        hold.begin();
        let order = log();
        for name in ["first", "second", "third"] {
            let sink = order.clone();
            hold.defer_action(
                "webservice",
                name,
                Box::new(move || {
                    sink.lock().unwrap().push(name);
                }),
            );
        }
        assert_eq!(hold.release(), 3);
        assert_eq!(
            order.lock().unwrap().as_slice(),
            ["first", "second", "third"]
        );
    }

    #[test]
    fn release_does_not_hold_the_lock_while_running() {
        let hold = Arc::new(ApplyHold::new());
        hold.begin();
        let inner = hold.clone();
        hold.defer_action(
            "protoroute",
            "reentrant",
            Box::new(move || {
                // The hold stays active until confirm or discard, but the queue
                // lock is gone while actions run: re-entering pending() here
                // would deadlock if release kept the guard.
                assert!(inner.pending().is_empty());
            }),
        );
        assert_eq!(hold.release(), 1);
        assert!(
            hold.is_active(),
            "apply keeps the hold until confirm/discard"
        );
        hold.drop_all();
        assert!(!hold.is_active());
    }

    #[test]
    fn drop_discards_actions_and_ends_the_hold() {
        let hold = ApplyHold::new();
        hold.begin();
        let ran = log();
        let sink = ran.clone();
        hold.defer_action(
            "portforward",
            "x",
            Box::new(move || {
                sink.lock().unwrap().push("ran");
            }),
        );
        hold.drop_all();
        assert!(!hold.is_active());
        assert!(hold.pending().is_empty());
        hold.release();
        assert!(ran.lock().unwrap().is_empty());
    }

    #[test]
    fn defer_outside_a_hold_reports_run_now() {
        let hold = ApplyHold::new();
        assert!(!hold.defer_action("webservice", "s", Box::new(|| {})));
    }

    #[test]
    fn begin_returns_already_pending_items() {
        let hold = ApplyHold::new();
        hold.begin();
        hold.defer_action("portforward", "kept", Box::new(|| {}));
        let pending = hold.begin();
        assert_eq!(pending, vec![("portforward".to_owned(), "kept".to_owned())]);
        assert!(hold.is_active());
    }
}

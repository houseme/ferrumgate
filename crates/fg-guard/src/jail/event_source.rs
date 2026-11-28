//! The `event` source (WP-52 §3.3): subscribes to the WP-16 event bus
//! and feeds every event whose kind name matches a jail's `target` into
//! [`JailEngine::on_event`]. The source address comes from the event
//! itself — `fields["ip"]` (the auth-module convention) or `args["ip"]` /
//! `args["addr"]` (knock publishes the peer as `addr`) — and events
//! without a parseable address are ignored.

use std::{net::IpAddr, sync::Arc};

use fg_core::events::{Event, EventBus};

use super::JailEngine;

/// Extracts the source address from an event, following the publisher
/// conventions; unparseable values are skipped.
pub fn event_ip(event: &Event) -> Option<IpAddr> {
    let candidates = event
        .fields
        .iter()
        .chain(event.args.iter())
        .filter(|(key, _)| *key == "ip" || *key == "addr")
        .map(|(_, value)| value.as_str());
    for candidate in candidates {
        if let Ok(ip) = candidate.parse::<IpAddr>() {
            return Some(ip.to_canonical());
        }
        // Knock publishes a socket address (`addr`).
        if let Ok(socket) = candidate.parse::<std::net::SocketAddr>() {
            return Some(socket.ip().to_canonical());
        }
    }
    None
}

/// Subscribes the engine to the bus. The subscription is stored inside
/// the engine; dropping the engine unregisters it. Fails only when the
/// bus is out of subscriber slots.
pub fn attach(engine: &Arc<JailEngine>, bus: &EventBus) -> anyhow::Result<()> {
    let engine_weak = Arc::downgrade(engine);
    let subscription = bus.subscribe(move |event: Arc<Event>| {
        let engine = engine_weak.clone();
        async move {
            let Some(engine) = engine.upgrade() else {
                return;
            };
            let kind = event.kind.info().name;
            let Some(ip) = event_ip(&event) else {
                return;
            };
            engine.on_event(kind, ip, event.time);
        }
    })?;
    engine.set_subscription(subscription);
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::bans::GuardService;
    use crate::jail::JailEngine;
    use crate::jail::validate::normalize_jail;
    use crate::jail::{Jail, JailSource};
    use crate::model::{FileConfig, Settings};
    use fg_core::events::{Event, Kind};

    #[tokio::test]
    async fn event_source_bans_on_auth_failed() {
        let bus = EventBus::new(64);
        let service = GuardService::open_memory(&Settings::default(), bus.clone());
        let engine = Arc::new(JailEngine::new(service, fg_net::banlist::system_clock()));
        let jail = normalize_jail(Jail {
            key: "ddeeffccbbaa".to_owned(),
            name: "admin".to_owned(),
            enable: true,
            source: JailSource::Event,
            target: "auth.failed".to_owned(),
            max_retry: 2,
            ..Jail::default()
        });
        engine
            .reload(&FileConfig {
                settings: Settings::default(),
                jails: vec![jail],
            })
            .expect("reload");
        attach(&engine, &bus).expect("subscribe");

        // Two failed admin logins from the same address (fields["ip"],
        // the auth-module convention) reach the threshold.
        for _ in 0..2 {
            bus.publish_with(|| {
                let mut event = Event::new(Kind::AuthFailed, "auth");
                event.fields.push(("ip", "203.0.113.44".to_owned()));
                event
            });
        }
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while std::time::Instant::now() < deadline {
            if engine.service().is_banned("203.0.113.44".parse().unwrap()) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(engine.service().is_banned("203.0.113.44".parse().unwrap()));

        // A knock rejection publishes the peer as args["addr"]; a waf
        // block as fields["ip"] on its own target kind. Events without a
        // parseable address never count.
        bus.publish_with(|| {
            let mut event = Event::new(Kind::KnockFailed, "knock");
            event.args.push(("addr", "203.0.113.45:5353".to_owned()));
            event.fields.push(("via", "tcp".to_owned()));
            event
        });
        bus.publish_with(|| {
            let mut event = Event::new(Kind::AuthFailed, "auth");
            event.args.push(("user", "root".to_owned()));
            event
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            !engine.service().is_banned("203.0.113.45".parse().unwrap()),
            "knock.failed is a different target kind"
        );
    }
}

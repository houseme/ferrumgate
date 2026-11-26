use std::{
    cell::Cell,
    collections::HashSet,
    future::{pending, ready},
    sync::Arc,
    time::{Duration, UNIX_EPOCH},
};

use anyhow::Result;
use fg_core::events::{
    Dropped, Event, EventBus, KINDS, Kind, Level, MAX_SUBSCRIBERS, SUBSCRIBER_CAPACITY,
};
use tokio::{
    sync::{mpsc, oneshot},
    time::timeout,
};

async fn next<T>(receiver: &mut mpsc::UnboundedReceiver<T>) -> T {
    timeout(Duration::from_secs(2), receiver.recv())
        .await
        .expect("event delivery deadline")
        .expect("event delivery channel closed")
}

#[test]
fn event_catalog_keys_and_defaults_match_the_pinned_types() {
    assert_eq!(KINDS.len(), 32);
    let mut unique = HashSet::new();
    for info in KINDS {
        assert!(unique.insert(info.name));
        assert_eq!(info.kind.info().name, info.name);
        assert_eq!(info.title_key, format!("events.{}.title", info.name));
        assert_eq!(info.description_key, format!("events.{}.desc", info.name));
    }
    assert_eq!(Kind::DdnsFailed.info().default_level, Level::Error);
    assert!(Level::Error > Level::Warn && Level::Warn > Level::Info);
    assert_eq!(Level::from("warn"), Level::Warn);
    assert_eq!(Level::from("unrecognized"), Level::Info);
}

#[tokio::test]
async fn saturated_ingress_counts_drops_and_skips_payload_construction() -> Result<()> {
    let bus = EventBus::new(1);
    bus.publish_with(|| panic!("no subscribers"));
    let (send, mut received) = mpsc::unbounded_channel();
    let _subscription = bus.subscribe(move |event| {
        send.send(event).unwrap();
        ready(())
    })?;
    let built = Cell::new(0);
    for _ in 0..10_000 {
        bus.publish_with(|| {
            built.set(built.get() + 1);
            Event::new(Kind::SslExpiring, "ssl")
        });
    }
    assert_eq!(built.get(), 1);
    assert_eq!(
        bus.dropped(),
        Dropped {
            ingress: 9_999,
            subscribers: 0
        }
    );
    let event = next(&mut received).await;
    assert_eq!(event.kind, Kind::SslExpiring);
    assert_eq!(event.level, Level::Warn);
    assert_ne!(event.time, UNIX_EPOCH);
    Ok(())
}

#[tokio::test]
async fn saturated_subscriber_does_not_delay_other_consumers() -> Result<()> {
    let bus = EventBus::default();
    let (slow, mut started) = mpsc::unbounded_channel();
    let _blocked = bus.subscribe(move |event| {
        slow.send(event).unwrap();
        pending()
    })?;
    let (fast, mut delivered) = mpsc::unbounded_channel();
    let _fast = bus.subscribe(move |event| {
        fast.send(event).unwrap();
        ready(())
    })?;

    bus.publish(Event::new(Kind::UpstreamDown, "webservice"));
    let slow_first = next(&mut started).await;
    let fast_first = next(&mut delivered).await;
    assert!(Arc::ptr_eq(&slow_first, &fast_first));
    for _ in 0..SUBSCRIBER_CAPACITY + 3 {
        bus.publish(Event::new(Kind::UpstreamUp, "webservice"));
        assert_eq!(next(&mut delivered).await.kind, Kind::UpstreamUp);
    }
    assert_eq!(
        bus.dropped(),
        Dropped {
            ingress: 0,
            subscribers: 3
        }
    );
    assert!(started.try_recv().is_err());
    Ok(())
}

#[tokio::test]
async fn subscriber_continues_after_a_handler_panics() -> Result<()> {
    let bus = EventBus::default();
    let (unstable, mut after_panic) = mpsc::unbounded_channel();
    let _unstable = bus.subscribe(move |event: Arc<Event>| {
        if event.kind == Kind::AuthFailed {
            panic!("injected handler panic");
        }
        let unstable = unstable.clone();
        async move {
            assert_ne!(event.kind, Kind::AuthBanned, "injected future panic");
            unstable.send(event.kind).unwrap();
        }
    })?;
    let (healthy, mut observed) = mpsc::unbounded_channel();
    let _healthy = bus.subscribe(move |event| {
        healthy.send(event.kind).unwrap();
        ready(())
    })?;
    for kind in [Kind::AuthFailed, Kind::AuthBanned, Kind::LoginSuccessful] {
        bus.publish(Event::new(kind, "system"));
        assert_eq!(next(&mut observed).await, kind);
    }
    assert_eq!(next(&mut after_panic).await, Kind::LoginSuccessful);
    Ok(())
}

#[tokio::test]
async fn subscriptions_start_at_registration_and_discard_queued_work_on_drop() -> Result<()> {
    let bus = EventBus::default();
    let (first, mut early) = mpsc::unbounded_channel();
    let (cancelled, stopped) = oneshot::channel::<()>();
    let mut cancelled = Some(cancelled);
    let early_subscription = bus.subscribe(move |event| {
        first.send(event).unwrap();
        let held_until_cancelled = cancelled.take();
        async move {
            let _held_until_cancelled = held_until_cancelled;
            pending().await
        }
    })?;
    bus.publish(Event::new(Kind::DdnsChanged, "ddns"));
    let (second, mut late) = mpsc::unbounded_channel();
    let _late_subscription = bus.subscribe(move |event| {
        second.send(event).unwrap();
        ready(())
    })?;
    bus.publish(Event::new(Kind::DdnsFailed, "ddns"));
    assert_eq!(next(&mut early).await.kind, Kind::DdnsChanged);
    assert_eq!(next(&mut late).await.kind, Kind::DdnsFailed);
    drop(early_subscription);
    assert!(timeout(Duration::from_secs(2), stopped).await?.is_err());
    bus.publish(Event::new(Kind::NotifyTest, "notify"));
    assert_eq!(next(&mut late).await.kind, Kind::NotifyTest);
    assert!(
        timeout(Duration::from_secs(2), early.recv())
            .await?
            .is_none()
    );
    Ok(())
}

#[tokio::test]
async fn subscriber_limit_releases_a_slot_and_last_bus_drop_cancels_workers() -> Result<()> {
    let bus = EventBus::default();
    let mut subscriptions = Vec::new();
    for _ in 0..MAX_SUBSCRIBERS {
        subscriptions.push(bus.subscribe(|_| ready(()))?);
    }
    assert!(bus.subscribe(|_| ready(())).is_err());
    drop(subscriptions.pop());
    let (send, mut receive) = mpsc::unbounded_channel();
    let subscription = bus.subscribe(move |event| {
        send.send(event).unwrap();
        pending()
    })?;
    bus.publish(Event::new(Kind::NotifyTest, "notify"));
    next(&mut receive).await;
    drop(bus);
    assert!(
        timeout(Duration::from_secs(2), receive.recv())
            .await?
            .is_none()
    );
    drop(subscription);
    Ok(())
}

#[tokio::test]
async fn concurrent_publishers_fill_the_bus_without_duplicating_events() -> Result<()> {
    let bus = EventBus::default();
    let (send, mut delivered) = mpsc::unbounded_channel();
    let _subscription = bus.subscribe(move |event| {
        send.send(event).unwrap();
        ready(())
    })?;
    std::thread::scope(|scope| {
        for publisher in 0..8 {
            let bus = &bus;
            scope.spawn(move || {
                for sequence in 0..8 {
                    bus.publish_with(|| {
                        let mut event = Event::new(Kind::NotifyTest, "notify");
                        event.args.push(("id", format!("{publisher}-{sequence}")));
                        event
                    });
                }
            });
        }
    });
    let mut ids = HashSet::new();
    for _ in 0..64 {
        assert!(ids.insert(next(&mut delivered).await.args[0].1.clone()));
    }
    assert_eq!(bus.dropped(), Dropped::default());
    Ok(())
}

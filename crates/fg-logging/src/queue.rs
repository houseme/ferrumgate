use std::{
    io,
    sync::{Arc, Condvar, Mutex, mpsc},
    thread,
    time::{Duration, Instant},
};

pub(super) struct Queue<T> {
    state: Mutex<Pending<T>>,
    wake: Condvar,
    limit: usize,
    threshold: usize,
}

struct Pending<T> {
    items: Vec<T>,
    writing: Option<Arc<Vec<T>>>,
    bytes: usize,
    lost: u64,
    closed: bool,
}

impl<T> Queue<T> {
    pub fn snapshot(&self, mut visit: impl FnMut(&T)) {
        let state = self.state.lock().expect("log queue poisoned");
        if let Some(writing) = &state.writing {
            writing.iter().for_each(&mut visit);
        }
        state.items.iter().for_each(visit);
    }

    pub fn push(&self, value: T, size: usize) {
        let mut state = self.state.lock().expect("log queue poisoned");
        if state.closed {
            return;
        }
        if size > self.limit - state.bytes {
            self.note_loss(&mut state);
            return;
        }
        let wake = state.items.is_empty()
            || (state.bytes < self.threshold && state.bytes + size >= self.threshold);
        state.bytes += size;
        state.items.push(value);
        if wake {
            self.wake.notify_one();
        }
    }

    pub fn record_loss(&self) {
        let mut state = self.state.lock().expect("log queue poisoned");
        if !state.closed {
            self.note_loss(&mut state);
        }
    }

    fn note_loss(&self, state: &mut Pending<T>) {
        state.lost = state.lost.saturating_add(1);
        if state.lost == 1 {
            self.wake.notify_one();
        }
    }

    fn close(&self) {
        self.state.lock().expect("log queue poisoned").closed = true;
        self.wake.notify_one();
    }

    fn take(&self, delay: Duration) -> Option<(Arc<Vec<T>>, u64)> {
        let state = self.state.lock().expect("log queue poisoned");
        let mut state = self
            .wake
            .wait_while(state, |s| !s.closed && s.items.is_empty() && s.lost == 0)
            .expect("log queue poisoned");
        if state.closed && state.items.is_empty() && state.lost == 0 {
            return None;
        }
        if !delay.is_zero() && state.lost == 0 && !state.closed && state.bytes < self.threshold {
            state = self
                .wake
                .wait_timeout_while(state, delay, |s| {
                    !s.closed && s.lost == 0 && s.bytes < self.threshold
                })
                .expect("log queue poisoned")
                .0;
        }
        state.bytes = 0;
        let batch = Arc::new(std::mem::take(&mut state.items));
        state.writing = Some(batch.clone());
        Some((batch, std::mem::take(&mut state.lost)))
    }
}

pub(super) struct Worker<T> {
    pub queue: Arc<Queue<T>>,
    done: mpsc::Receiver<io::Result<()>>,
}

impl<T: Send + Sync + 'static> Worker<T> {
    pub fn spawn(
        name: &str,
        limit: usize,
        threshold: usize,
        delay: Duration,
        mut process: impl FnMut(&[T], u64) -> io::Result<()> + Send + 'static,
    ) -> io::Result<Self> {
        let queue = Arc::new(Queue {
            state: Mutex::new(Pending {
                items: Vec::new(),
                writing: None,
                bytes: 0,
                lost: 0,
                closed: false,
            }),
            wake: Condvar::new(),
            limit,
            threshold,
        });
        let pending = queue.clone();
        let (done, completion) = mpsc::sync_channel(1);
        thread::Builder::new()
            .name(name.to_owned())
            .spawn(move || {
                let result = (|| {
                    while let Some((batch, lost)) = pending.take(delay) {
                        process(&batch, lost)?;
                        // This batch still owns the allocation until after unlocking.
                        pending.state.lock().expect("log queue poisoned").writing = None;
                    }
                    Ok(())
                })();
                let abandoned = {
                    let mut state = pending.state.lock().expect("log queue poisoned");
                    state.closed = true;
                    (std::mem::take(&mut state.items), state.writing.take())
                };
                drop(abandoned);
                drop(process);
                let _ = done.send(result);
            })?;
        Ok(Self {
            queue,
            done: completion,
        })
    }

    pub fn close(&self) {
        self.queue.close();
    }

    pub fn wait(&self, deadline: Instant) -> io::Result<()> {
        self.done
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .map_err(|error| {
                let kind = match error {
                    mpsc::RecvTimeoutError::Timeout => io::ErrorKind::TimedOut,
                    mpsc::RecvTimeoutError::Disconnected => io::ErrorKind::BrokenPipe,
                };
                io::Error::new(kind, "log worker did not finish")
            })?
    }
}

impl<T> Drop for Worker<T> {
    fn drop(&mut self) {
        self.queue.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn batch_threshold_flushes_without_waiting_for_periodic_timeout() -> io::Result<()> {
        let (send, received) = mpsc::channel();
        let worker = Worker::spawn(
            "fg-log-test",
            8,
            4,
            Duration::from_secs(60),
            move |items, lost| {
                send.send((items.to_vec(), lost)).unwrap();
                Ok(())
            },
        )?;
        worker.queue.push(1, 2);
        worker.queue.push(2, 2);
        assert_eq!(
            received.recv_timeout(Duration::from_secs(2)).unwrap(),
            (vec![1, 2], 0)
        );
        worker.close();
        worker.wait(Instant::now() + Duration::from_secs(2))
    }
}

//! 重启退避（WP-43 §3.3，纯逻辑）：进程退出后从 1 秒起指数增长到 60 秒；
//! 稳定运行超过 `stable_after`（默认 30 秒）后重置回初始值。正常停止不重启，
//! 因此这里只回答「下一次重启等多久」。

use std::time::Duration;

/// 初始退避：1 秒（上游 `backoff` 初值）。
pub const INITIAL: Duration = Duration::from_secs(1);
/// 最大退避：60 秒（上游 `maxBackoff`）。
pub const MAX: Duration = Duration::from_secs(60);
/// 稳定运行 30 秒后重置退避（上游 `stableRun`）。
pub const STABLE_AFTER: Duration = Duration::from_secs(30);

#[derive(Clone, Debug)]
pub struct Backoff {
    initial: Duration,
    max: Duration,
    stable_after: Duration,
    attempt: u32,
}

impl Default for Backoff {
    fn default() -> Self {
        Self::new(INITIAL, MAX, STABLE_AFTER)
    }
}

impl Backoff {
    pub fn new(initial: Duration, max: Duration, stable_after: Duration) -> Self {
        Self {
            initial,
            max,
            stable_after,
            attempt: 0,
        }
    }

    /// 上一次进程运行了 `ran_for` 后退出，返回下一次重启前要等待的时长；
    /// 稳定运行达标时退避先重置。每次调用都推进内部计数。
    pub fn next_delay(&mut self, ran_for: Duration) -> Duration {
        if ran_for >= self.stable_after {
            self.attempt = 0;
        }
        let factor = 1u64.checked_shl(self.attempt.min(63)).unwrap_or(u64::MAX);
        let factor = u32::try_from(factor).unwrap_or(u32::MAX);
        let delay = self.initial.saturating_mul(factor).min(self.max);
        self.attempt = self.attempt.saturating_add(1);
        delay
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_grows_to_60s_and_resets_after_30s() {
        let mut backoff = Backoff::default();
        // 短命进程（0 秒）：1、2、4、8、16、32、60、60……封顶 60 秒。
        let expected = [1, 2, 4, 8, 16, 32, 60, 60];
        for seconds in expected {
            let delay = backoff.next_delay(Duration::ZERO);
            assert_eq!(delay, Duration::from_secs(seconds), "attempt grew wrong");
        }
        // 稳定运行 30 秒后重置回初始值。
        assert_eq!(
            backoff.next_delay(Duration::from_secs(30)),
            Duration::from_secs(1)
        );
        assert_eq!(
            backoff.next_delay(Duration::from_secs(60)),
            Duration::from_secs(1)
        );
        // 之后重新指数增长。
        assert_eq!(
            backoff.next_delay(Duration::from_secs(29)),
            Duration::from_secs(2)
        );
    }
}

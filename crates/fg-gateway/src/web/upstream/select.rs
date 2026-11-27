//! Backend selection strategies (WP-23 step 2): weighted round-robin,
//! weighted random, ip_hash and least_conn. Pure logic over the eligible
//! candidate list the pool hands in.
#![allow(dead_code)]

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

use super::{Backend, Policy};

/// Expands candidates by weight: a backend with weight 3 appears three
/// times, so any ticket in `0..total` maps proportionally.
pub(crate) fn weighted_expand<'a>(candidates: &[&'a Backend]) -> Vec<&'a Backend> {
    candidates
        .iter()
        .flat_map(|backend| std::iter::repeat_n(*backend, backend.target.weight as usize))
        .collect()
}

/// Maps an arbitrary ticket onto the expanded list (modulo its length).
/// `expanded` is never empty: the pool hands in at least one candidate and
/// every weight is 1..=100, so no defensive `.max(1)` is needed.
pub(crate) fn pick_by_ticket<'a>(expanded: &[&'a Backend], ticket: u64) -> &'a Backend {
    expanded[(ticket % expanded.len() as u64) as usize]
}

/// Random u64 without pulling in the `rand` crate (workspace getrandom).
fn random_u64() -> u64 {
    let mut bytes = [0u8; 8];
    if getrandom::fill(&mut bytes).is_err() {
        // Entropy failure is practically impossible; fall back to a
        // counter-ish value so selection still rotates.
        return std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.subsec_nanos() as u64)
            .unwrap_or(0);
    }
    u64::from_le_bytes(bytes)
}

/// Stable per-process hash of the client address for `ip_hash`.
fn ip_ticket(client: IpAddr) -> u64 {
    let mut hasher = DefaultHasher::new();
    client.hash(&mut hasher);
    hasher.finish()
}

/// Picks one backend from the eligible candidates. `candidates` is never
/// empty (the pool falls back before calling).
pub fn pick<'a>(
    policy: Policy,
    candidates: &[&'a Backend],
    client: IpAddr,
    cursor: &AtomicU64,
) -> &'a Backend {
    debug_assert!(!candidates.is_empty(), "pool hands in non-empty candidates");
    if candidates.len() == 1 {
        return candidates[0];
    }
    match policy {
        Policy::RoundRobin => {
            let expanded = weighted_expand(candidates);
            let ticket = cursor.fetch_add(1, Relaxed);
            pick_by_ticket(&expanded, ticket)
        }
        Policy::Random => {
            let expanded = weighted_expand(candidates);
            pick_by_ticket(&expanded, random_u64())
        }
        Policy::IpHash => {
            let expanded = weighted_expand(candidates);
            pick_by_ticket(&expanded, ip_ticket(client))
        }
        Policy::LeastConn => {
            let mut best = candidates[0];
            let mut best_score = f64::INFINITY;
            for backend in candidates {
                let weight = f64::from(backend.target.weight);
                let score = f64::from(backend.state.conns.load(Relaxed)) / weight;
                if score < best_score {
                    best_score = score;
                    best = backend;
                }
            }
            best
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::atomic::Ordering::Relaxed;

    use super::*;
    use crate::web::upstream::parse_target;

    fn backend(line: &str) -> Backend {
        Backend::new(parse_target(line).unwrap())
    }

    fn candidates(backends: &[Backend]) -> Vec<&Backend> {
        backends.iter().collect()
    }

    fn ip(octet: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, octet))
    }

    /// `Backend` carries no identity fields, so pointer equality is the
    /// only way to tell which candidate was picked.
    fn is_same(picked: &Backend, backend: &Backend) -> bool {
        std::ptr::eq(picked, backend)
    }

    #[test]
    fn weighted_expand_repeats_each_backend_by_weight() {
        let heavy = backend("http://a.test:8001 weight=3");
        let light = backend("http://b.test:8002");
        let expanded = weighted_expand(&[&heavy, &light]);
        assert_eq!(expanded.len(), 4);
        let hosts: Vec<_> = expanded
            .iter()
            .map(|backend| backend.target.uri.host().unwrap())
            .collect();
        assert_eq!(hosts, ["a.test", "a.test", "a.test", "b.test"]);
    }

    #[test]
    fn round_robin_honors_weights() {
        let heavy = backend("http://a.test:8001 weight=3");
        let light = backend("http://b.test:8002");
        let backends = [heavy, light];
        let cands = candidates(&backends);
        let cursor = AtomicU64::new(0);
        let mut heavy_picks = 0;
        for _ in 0..40 {
            if is_same(pick(Policy::RoundRobin, &cands, ip(1), &cursor), &backends[0]) {
                heavy_picks += 1;
            }
        }
        // The expanded list is [a,a,a,b]; 40 tickets advance one shared
        // cursor through ten exact cycles: 30:10, not merely approximate.
        assert_eq!(heavy_picks, 30);
        assert_eq!(40 - heavy_picks, 10);
    }

    #[test]
    fn round_robin_rotates() {
        let a = backend("http://a.test:8001");
        let b = backend("http://b.test:8002");
        let c = backend("http://c.test:8003");
        let backends = [a, b, c];
        let cands = candidates(&backends);
        let cursor = AtomicU64::new(0);
        let order: Vec<bool> = (0..6)
            .map(|_| is_same(pick(Policy::RoundRobin, &cands, ip(1), &cursor), &backends[0]))
            .collect();
        // Equal weights cycle one candidate per ticket: a,b,c,a,b,c — so
        // `order` marks a pick at 0 and 3 only.
        assert_eq!(order, [true, false, false, true, false, false]);
    }

    #[test]
    fn random_respects_weights() {
        let heavy = backend("http://a.test:8001 weight=3");
        let light = backend("http://b.test:8002");
        let backends = [heavy, light];
        let cands = candidates(&backends);
        let cursor = AtomicU64::new(0);
        let mut heavy_picks = 0;
        for _ in 0..500 {
            if is_same(pick(Policy::Random, &cands, ip(1), &cursor), &backends[0]) {
                heavy_picks += 1;
            }
        }
        // 3:1 over 500 draws expects 375:125; ±40% guards against a broken
        // implementation (clamped to one side, off-by-one modulo, ...) —
        // not against sampling noise, which is far smaller.
        assert!(
            (225..=525).contains(&heavy_picks),
            "heavy bucket {heavy_picks}/500 is outside ±40% of 3:1"
        );
        let light_picks = 500 - heavy_picks;
        assert!(
            (75..=175).contains(&light_picks),
            "light bucket {light_picks}/500 is outside ±40% of 3:1"
        );
    }

    #[test]
    fn ip_hash_is_stable_per_client() {
        let heavy = backend("http://a.test:8001 weight=3");
        let light = backend("http://b.test:8002");
        let backends = [heavy, light];
        let cands = candidates(&backends);
        let cursor = AtomicU64::new(0);
        let client = ip(7);
        let first = pick(Policy::IpHash, &cands, client, &cursor);
        for round in 0u8..10 {
            // Interleave other clients and cursor-advancing round-robin
            // picks: neither may move this client's mapping.
            let _ = pick(Policy::IpHash, &cands, ip(20 + round), &cursor);
            let _ = pick(Policy::RoundRobin, &cands, client, &cursor);
            let again = pick(Policy::IpHash, &cands, client, &cursor);
            assert!(
                is_same(again, first),
                "same client must always map to the same backend"
            );
        }
        // Enough distinct clients must spread over both backends, or the
        // hash is not really mixing (degenerate modulo, constant ticket).
        let mut saw_heavy = false;
        let mut saw_light = false;
        for octet in 1..=64u8 {
            if is_same(pick(Policy::IpHash, &cands, ip(octet), &cursor), &backends[0]) {
                saw_heavy = true;
            } else {
                saw_light = true;
            }
        }
        assert!(saw_heavy && saw_light, "64 sampled clients hit one backend only");
    }

    #[test]
    fn least_conn_divides_by_weight() {
        // 6 conns / weight 2 = 3.0 beats 4 conns / weight 1 = 4.0: naive
        // min-conns would pick the lighter backend, weighted least_conn
        // correctly prefers the one carrying less load per unit weight.
        let heavy = backend("http://a.test:8001 weight=2");
        heavy.state.conns.store(6, Relaxed);
        let light = backend("http://b.test:8002 weight=1");
        light.state.conns.store(4, Relaxed);
        let backends = [heavy, light];
        let cands = candidates(&backends);
        let cursor = AtomicU64::new(0);
        assert!(is_same(
            pick(Policy::LeastConn, &cands, ip(1), &cursor),
            &backends[0]
        ));
    }

    #[test]
    fn least_conn_breaks_ties_by_candidate_order() {
        // 4/2 and 2/1 both score 2.0; the earlier candidate must win so
        // the choice stays deterministic.
        let first = backend("http://a.test:8001 weight=2");
        first.state.conns.store(4, Relaxed);
        let second = backend("http://b.test:8002 weight=1");
        second.state.conns.store(2, Relaxed);
        let backends = [first, second];
        let cands = candidates(&backends);
        let cursor = AtomicU64::new(0);
        assert!(is_same(
            pick(Policy::LeastConn, &cands, ip(1), &cursor),
            &backends[0]
        ));
    }

    #[test]
    fn single_candidate_short_circuit() {
        let only = backend("http://a.test:8001");
        let backends = [only];
        let cands = candidates(&backends);
        let cursor = AtomicU64::new(0);
        for policy in [Policy::RoundRobin, Policy::Random, Policy::IpHash, Policy::LeastConn] {
            assert!(is_same(pick(policy, &cands, ip(1), &cursor), &backends[0]));
        }
        // The fast path returns before any ticket work: the cursor must
        // stay untouched.
        assert_eq!(cursor.load(Relaxed), 0, "short circuit must not advance the cursor");
    }
}

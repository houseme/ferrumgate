//! Demo mode: a read-only visitors' tour. The rule tables decide which
//! management requests stay available; the login endpoint and response
//! overlay are the host crate's concern.

use axum::http::Method;

/// The message every blocked request receives.
pub const MESSAGE: &str = "演示模式下不可用";

/// Writes still allowed in demo mode: sign-in and sign-out, interface
/// preferences and pure checks that touch only the current session.
const ALLOWED_WRITES: [(&Method, &str); 7] = [
    (&Method::POST, "/api/login"),
    (&Method::POST, "/api/logout"),
    (&Method::POST, "/api/login/demo"),
    (&Method::PUT, "/api/account/ui-language"),
    (&Method::POST, "/api/account/ui-language"),
    (&Method::POST, "/api/account/password-check"),
    (&Method::POST, "/api/system/onboarding/dismiss"),
];

/// Reads always refused: file and storage contents, exports, outbound
/// update checks, terminals and Docker.
const BLOCKED_READ_PREFIXES: [&str; 8] = [
    "/api/system/update",
    "/api/backup/local",
    "/api/system/backup",
    "/api/system/diagnostics",
    "/api/system/upgrade",
    "/api/storage/files/",
    "/api/webterminal/",
    "/api/docker/",
];

/// Modules forced off in demo mode: they execute commands or reach the
/// host and containers.
pub const DISABLED_MODULES: [&str; 2] = ["docker", "webterminal"];

/// Whether demo mode is on for this process; set once at startup.
static ENABLED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Turns demo mode on; called once at startup from `-demo` or
/// `FERRUMGATE_DEMO=1`.
pub fn enable() {
    ENABLED.store(true, std::sync::atomic::Ordering::Release);
}

pub fn enabled() -> bool {
    ENABLED.load(std::sync::atomic::Ordering::Acquire)
}

/// Reads the process-wide switch from an env accessor; `-demo` wins.
pub fn from_environment_with(flag: bool, get: impl Fn(&str) -> Option<String>) -> bool {
    flag || get("FERRUMGATE_DEMO").is_some_and(|value| value == "1")
}

/// Pure rule: `true` when this request must be refused in demo mode,
/// regardless of the account role.
pub fn blocked(method: &Method, path: &str) -> bool {
    blocked_with(enabled(), method, path)
}

/// The rule against an explicit switch, keeping tests order-independent.
pub fn blocked_with(on: bool, method: &Method, path: &str) -> bool {
    if !on {
        return false;
    }
    if matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS) {
        // The cached update state is safe to read; only the check itself
        // makes outbound requests and stays blocked.
        if path == "/api/system/update/state" {
            return false;
        }
        return BLOCKED_READ_PREFIXES
            .iter()
            .any(|prefix| path == prefix.trim_end_matches('/') || path.starts_with(prefix));
    }
    !ALLOWED_WRITES
        .iter()
        .any(|(allowed_method, allowed_path)| method == *allowed_method && path == *allowed_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rules_are_off_unless_enabled() {
        assert!(!blocked_with(false, &Method::DELETE, "/api/ddns/rules/x"));
        assert!(blocked_with(true, &Method::DELETE, "/api/ddns/rules/x"));
    }

    #[test]
    fn writes_are_refused_except_session_preferences() {
        enable();
        for (method, path) in [
            (&Method::PUT, "/api/account/ui-language"),
            (&Method::POST, "/api/account/password-check"),
            (&Method::POST, "/api/system/onboarding/dismiss"),
            (&Method::POST, "/api/logout"),
        ] {
            assert!(!blocked(method, path), "{method} {path}");
        }
        assert!(blocked(&Method::POST, "/api/ddns/rules"));
        assert!(blocked(&Method::PUT, "/api/system/settings"));
        assert!(blocked(&Method::DELETE, "/api/account/users/x"));
    }

    #[test]
    fn sensitive_reads_are_refused_while_ordinary_reads_pass() {
        enable();
        for path in [
            "/api/system/backup",
            "/api/system/diagnostics",
            "/api/backup/local/2026.zip",
            "/api/system/update",
            "/api/webterminal/ws",
            "/api/docker/containers",
        ] {
            assert!(blocked(&Method::GET, path), "{path}");
        }
        for path in [
            "/api/ddns/rules",
            "/api/session",
            "/api/system/update/state",
            "/api/logs",
        ] {
            assert!(!blocked(&Method::GET, path), "{path}");
        }
    }

    #[test]
    fn environment_detection_accepts_only_the_exact_flag() {
        let get = |name: &str| (name == "FERRUMGATE_DEMO").then(|| "1".to_owned());
        assert!(from_environment_with(false, get));
        let get = |name: &str| (name == "FERRUMGATE_DEMO").then(|| "0".to_owned());
        assert!(!from_environment_with(false, get));
        let get = |_: &str| None;
        assert!(
            from_environment_with(true, get),
            "the explicit flag always wins"
        );
    }
}

//! Decides which management requests are audited and with which category.
//!
//! The rules mirror the upstream audit middleware: reads are recorded only
//! when they expose sensitive content or open an interactive channel, writes
//! are recorded unless they are read-only probes that would flood the log.

use axum::http::Method;

use super::Category;

/// `None` means the request is not audited.
pub fn classify(method: &Method, path: &str) -> Option<Category> {
    if !path.starts_with("/api/") {
        return None;
    }
    if matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS) {
        return sensitive_read(path).then_some(Category::Access);
    }
    (!skipped_write(method, path)).then_some(Category::Change)
}

fn sensitive_read(path: &str) -> bool {
    if matches!(path, "/api/system/backup" | "/api/system/diagnostics") {
        return true;
    }
    // The backup file list is polled by the interface and is not sensitive;
    // downloads below it are.
    if path == "/api/backup/local" {
        return false;
    }
    if let Some(file) = path.strip_prefix("/api/backup/local/") {
        return !file.is_empty();
    }
    path.split('/')
        .any(|segment| matches!(segment, "ws" | "exec" | "download" | "export" | "secrets"))
}

fn skipped_write(method: &Method, path: &str) -> bool {
    if matches!((method, path), (&Method::PUT, "/api/account/ui-language")) {
        return true;
    }
    if path == "/api/nettools" || path.starts_with("/api/nettools/") {
        return true;
    }
    matches!(
        (method, path),
        (
            &Method::POST,
            "/api/system/selfcheck"
                | "/api/system/public-ip"
                | "/api/account/passkeys/begin"
                | "/api/webservice/panels/preview"
                | "/api/webservice/panels/sunpanel"
                | "/api/system/access-path/check"
                | "/api/system/changeset/check"
        )
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn classify(method: &str, path: &str) -> Option<Category> {
        super::classify(&Method::from_bytes(method.as_bytes()).unwrap(), path)
    }

    #[test]
    fn classify_mutating_is_change() {
        for method in ["PUT", "POST", "DELETE", "PATCH"] {
            assert_eq!(classify(method, "/api/ddns/rules"), Some(Category::Change));
        }
    }

    #[test]
    fn classify_skips_read_only_posts() {
        for path in [
            "/api/system/selfcheck",
            "/api/system/public-ip",
            "/api/account/passkeys/begin",
            "/api/webservice/panels/preview",
            "/api/webservice/panels/sunpanel",
            "/api/system/access-path/check",
            "/api/system/changeset/check",
        ] {
            assert_eq!(classify("POST", path), None, "{path}");
        }
        assert_eq!(classify("PUT", "/api/account/ui-language"), None);
        assert_eq!(classify("POST", "/api/nettools/ping"), None);
        assert_eq!(classify("DELETE", "/api/nettools/dns/1"), None);
    }

    #[test]
    fn classify_sensitive_get_is_access() {
        for path in [
            "/api/system/backup",
            "/api/system/diagnostics",
            "/api/backup/local/2026.zip",
        ] {
            assert_eq!(classify("GET", path), Some(Category::Access), "{path}");
            assert_eq!(classify("HEAD", path), Some(Category::Access), "{path}");
        }
        // The polled backup list itself is not a sensitive read.
        assert_eq!(classify("GET", "/api/backup/local"), None);
        for segment in ["ws", "exec", "download", "export", "secrets"] {
            let path = format!("/api/webservice/site/{segment}");
            assert_eq!(classify("GET", &path), Some(Category::Access), "{path}");
        }
    }

    #[test]
    fn classify_plain_get_is_none() {
        for path in ["/api/ddns/rules", "/api/system/info", "/api/logs"] {
            assert_eq!(classify("GET", path), None, "{path}");
        }
        assert_eq!(classify("OPTIONS", "/api/ddns/rules"), None);
    }
}

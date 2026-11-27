//! Site types (WP-22): the [`SiteAction`] a compiled site takes for each
//! request and the [`dispatch`] from the model `site_type`.
//!
//! Sub-modules own the per-type details:
//! - [`redirect`]: redirect targets with `{...}` variable expansion
//!   (upstream `redirectvars.go`);
//! - [`location`]: per-path routing rules for proxy sites;
//! - [`static_site`] (inline here): the static-root wrapper over the
//!   legacy static serving engine.
//!
//! [`dispatch`] maps `site_type` (proxy | redirect | static | text |
//! close) onto a [`SiteAction`], collecting user-facing problems (one
//! string each) instead of failing the whole config.

pub mod location;
pub mod redirect;

pub use location::Locations;
pub use redirect::RedirectTarget;

use hyper::{body::Bytes, header::HeaderValue};

use crate::web::model::Site;

/// The `static` site type: files served straight from a filesystem root.
pub mod static_site {
    /// Compiled configuration of a static site.
    ///
    /// Carries what the serving engine ([`crate::static_files::StaticFiles`])
    /// needs. Opening the root touches the filesystem, so the actual
    /// compilation into `StaticFiles` stays async and is performed by the
    /// bridge when the site loads; this type is the pure-data handle the
    /// dispatcher hands over.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct StaticAction {
        /// Absolute filesystem root to serve.
        pub root: String,
    }
}

/// The action a compiled site takes for each request.
///
/// Built once at (re)load time by [`dispatch`]; the serving side matches
/// on it per request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SiteAction {
    /// Reverse-proxy to the site's configured targets.
    Proxy,
    /// Answer every request with a redirect to `target`.
    Redirect {
        target: RedirectTarget,
        /// 301 | 302 | 307 | 308 (302 when the model leaves it unset).
        code: u16,
        /// Whether the request path is appended to the target.
        keep_path: bool,
    },
    /// Serve files from a filesystem root.
    Static(static_site::StaticAction),
    /// Answer every request with a fixed body.
    Text {
        body: Bytes,
        content_type: HeaderValue,
    },
    /// The Close site type: the connection is terminated without a
    /// response (connection drop on HTTP/1.x, stream reset on HTTP/2+).
    Close,
}

/// The Close site type: the connection is terminated without a response.
///
/// Marker for the serving side: no response bytes are ever sent; the
/// connection is dropped (HTTP/1.x) or the stream is reset (HTTP/2+).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CloseAction;

/// Compiles a model [`Site`] into the [`SiteAction`] it serves, based on
/// `site_type`.
///
/// Errors are user-facing reasons (one per problem) suitable for display
/// next to the site in the interface.
pub fn dispatch(site: &Site) -> Result<SiteAction, Vec<String>> {
    match site.site_type.as_str() {
        "proxy" => Ok(SiteAction::Proxy),
        "redirect" => {
            let mut errors = Vec::new();
            // validate_target reports unknown `{xxx}` variables by name
            // and an empty list when the sampled target is not an
            // absolute URL.
            if let Err(reasons) = redirect::validate_target(&site.redirect_to) {
                if reasons.is_empty() {
                    errors.push("redirect target must be an absolute URL".to_string());
                } else {
                    errors.extend(
                        reasons
                            .into_iter()
                            .map(|token| format!("unknown redirect variable: {token}")),
                    );
                }
            }
            let code = if site.redirect_code == 0 {
                302
            } else {
                site.redirect_code
            };
            if !matches!(code, 301 | 302 | 307 | 308) {
                errors.push(format!(
                    "redirect code must be 301, 302, 307 or 308, got {code}"
                ));
            }
            if !errors.is_empty() {
                return Err(errors);
            }
            Ok(SiteAction::Redirect {
                target: redirect::parse_target(&site.redirect_to),
                code,
                keep_path: false,
            })
        }
        "static" => {
            if !std::path::Path::new(&site.root).is_absolute() {
                return Err(vec!["static root must be an absolute path".to_string()]);
            }
            Ok(SiteAction::Static(static_site::StaticAction {
                root: site.root.clone(),
            }))
        }
        "text" => {
            let content_type = if site.text_content_type.is_empty() {
                HeaderValue::from_static("text/plain; charset=utf-8")
            } else {
                HeaderValue::from_str(&site.text_content_type)
                    .map_err(|_| vec!["invalid text content type".to_string()])?
            };
            Ok(SiteAction::Text {
                body: site.text_body.clone().into(),
                content_type,
            })
        }
        "close" => Ok(SiteAction::Close),
        other => Err(vec![format!("unknown site_type: {other}")]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn site(site_type: &str) -> Site {
        Site {
            site_type: site_type.to_string(),
            ..Site::default()
        }
    }

    #[test]
    fn dispatch_proxy_redirect_static_text_close() {
        // proxy: no fields required.
        assert_eq!(dispatch(&site("proxy")), Ok(SiteAction::Proxy));

        // redirect: unset code falls back to 302, keep_path stays false.
        let mut redirect = site("redirect");
        redirect.redirect_to = "https://example.com/".to_string();
        match dispatch(&redirect) {
            Ok(SiteAction::Redirect {
                code, keep_path, ..
            }) => {
                assert_eq!(code, 302);
                assert!(!keep_path);
            }
            other => panic!("expected redirect action, got {other:?}"),
        }

        // redirect: an explicit code is preserved and {host} is accepted.
        redirect.redirect_code = 301;
        redirect.redirect_to = "https://{host}:8443/login".to_string();
        assert!(matches!(
            dispatch(&redirect),
            Ok(SiteAction::Redirect { code: 301, .. })
        ));

        // redirect: a target without scheme is an error.
        let mut bad_target = site("redirect");
        bad_target.redirect_to = "not-a-url".to_string();
        let errors = dispatch(&bad_target).expect_err("schemeless target must fail");
        assert!(
            errors[0].contains("absolute URL"),
            "unexpected error: {errors:?}"
        );

        // redirect: an empty target is an error.
        let empty = site("redirect");
        let errors = dispatch(&empty).expect_err("empty target must fail");
        assert!(
            errors[0].contains("absolute URL"),
            "unexpected error: {errors:?}"
        );

        // redirect: unknown variables are reported by name.
        let mut unknown_var = site("redirect");
        unknown_var.redirect_to = "https://{bogus}/".to_string();
        let errors = dispatch(&unknown_var).expect_err("unknown variable must fail");
        assert!(
            errors[0].contains("{bogus}"),
            "unexpected error: {errors:?}"
        );

        // redirect: a code outside 301|302|307|308 is an error.
        let mut bad_code = site("redirect");
        bad_code.redirect_to = "https://example.com/".to_string();
        bad_code.redirect_code = 300;
        let errors = dispatch(&bad_code).expect_err("bad code must fail");
        assert!(
            errors[0].contains("301, 302, 307 or 308"),
            "unexpected error: {errors:?}"
        );

        // static: absolute root is carried through.
        let mut static_config = site("static");
        static_config.root = "/var/www/docs".to_string();
        assert_eq!(
            dispatch(&static_config),
            Ok(SiteAction::Static(static_site::StaticAction {
                root: "/var/www/docs".to_string(),
            }))
        );

        // static: a relative (or empty) root is an error.
        let mut bad_root = site("static");
        bad_root.root = "var/www/docs".to_string();
        let errors = dispatch(&bad_root).expect_err("relative root must fail");
        assert!(
            errors[0].contains("absolute path"),
            "unexpected error: {errors:?}"
        );

        // text: empty content type falls back to the default.
        let mut text = site("text");
        text.text_body = "Under maintenance".to_string();
        match dispatch(&text) {
            Ok(SiteAction::Text { body, content_type }) => {
                assert_eq!(&body[..], &b"Under maintenance"[..]);
                assert_eq!(content_type.as_bytes(), b"text/plain; charset=utf-8");
            }
            other => panic!("expected text action, got {other:?}"),
        }

        // text: an explicit content type is preserved.
        text.text_content_type = "application/json".to_string();
        match dispatch(&text) {
            Ok(SiteAction::Text { content_type, .. }) => {
                assert_eq!(content_type.as_bytes(), b"application/json");
            }
            other => panic!("expected text action, got {other:?}"),
        }

        // close: no fields required.
        assert_eq!(dispatch(&site("close")), Ok(SiteAction::Close));
    }

    #[test]
    fn dispatch_unknown_type_errors() {
        let errors = dispatch(&site("bogus")).expect_err("unknown type must fail");
        assert_eq!(errors.len(), 1);
        assert!(
            errors[0].contains("unknown site_type"),
            "unexpected error: {errors:?}"
        );
        assert!(errors[0].contains("bogus"), "unexpected error: {errors:?}");

        // The empty default is unknown too, not silently proxied.
        let errors = dispatch(&site("")).expect_err("empty type must fail");
        assert_eq!(errors.len(), 1);
        assert!(
            errors[0].contains("unknown site_type"),
            "unexpected error: {errors:?}"
        );
    }
}

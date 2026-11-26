use std::sync::atomic::{AtomicUsize, Ordering};

use fg_admin::ApiJson;

use super::*;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LoginFixture {
    user: String,
}

#[tokio::test]
async fn public_routes_share_the_request_boundary_and_own_their_credentials() -> Result<()> {
    let attempts = Arc::new(AtomicUsize::new(0));
    let observed = attempts.clone();
    let registry = Registry::new(&["wol", "portforward"]);
    let enabled = registry.resolve_enabled(&["portforward".into()], false);
    let module_path = "/api/wol/public/agent/poll";
    let disabled = "/api/portforward/public/status";
    let absent = "/api/ddns/public/status";
    let admin = ApiRouter::new(move |headers| {
        observed.fetch_add(1, Ordering::Relaxed);
        principal(headers)
    })
    .with_modules(registry, enabled)
    .public_route(
        Method::POST,
        "/api/login",
        "Start a session",
        |ApiJson(login): ApiJson<LoginFixture>| async move { Json(json!({"user": login.user})) },
    )
    .public_route(
        Method::POST,
        module_path,
        "Module credential fixture",
        |headers: HeaderMap| async move {
            if headers
                .get("x-fixture-credential")
                .is_some_and(|value| value == "module-proof")
            {
                Ok(Json(json!({"ok": true})))
            } else {
                Err(ApiError::new(
                    StatusCode::UNAUTHORIZED,
                    "module credential required",
                ))
            }
        },
    )
    .public_route(Method::GET, disabled, "Disabled fixture", || async {
        StatusCode::OK
    })
    .public_route(Method::GET, absent, "Absent fixture", || async {
        StatusCode::OK
    })
    .route(
        Method::GET,
        "/api/login",
        "Protected fixture on the same path",
        || async { Json(json!([])) },
    )
    .finish();

    let operation = &admin.document()["paths"][module_path]["post"];
    assert_eq!(operation["security"], json!([]));
    assert_eq!(operation["x-required-scope"], "!public");
    assert_eq!(operation["x-token-allowed"], false);
    assert!(admin.document()["paths"]["/api/login"]["post"].is_null());
    assert_eq!(
        admin.document()["paths"]["/api/login"]["get"]["x-required-scope"],
        "!denied"
    );
    for path in [disabled, absent] {
        assert!(admin.document()["paths"][path].is_null());
    }
    let export = tempfile::tempdir()?;
    admin.export(export.path())?;
    let markdown = fs::read_to_string(export.path().join("API.md"))?;
    assert!(markdown.contains(module_path));
    assert!(!markdown.contains("| POST | `/api/login` |"));
    assert!(markdown.contains("| GET | `/api/login` |"));

    let server = Server::start(admin.router).await?;
    let content_type = ("content-type", "application/json");
    let login = r#"{"user":"fixture"}"#;
    let (status, headers, response) = server
        .call("POST", "/api/login", &[content_type], login)
        .await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(response, json!({"user": "fixture"}));
    assert_eq!(headers["cache-control"], "no-store");
    assert_eq!(headers["x-content-type-options"], "nosniff");
    for (headers, payload, status) in [
        (
            vec![content_type, ("origin", "https://other.test")],
            login,
            StatusCode::FORBIDDEN,
        ),
        (vec![], login, StatusCode::UNSUPPORTED_MEDIA_TYPE),
        (
            vec![content_type],
            r#"{"user":"fixture","extra":true}"#,
            StatusCode::BAD_REQUEST,
        ),
    ] {
        assert_eq!(
            server
                .call("POST", "/api/login", &headers, payload)
                .await?
                .0,
            status
        );
    }
    let oversized = Bytes::from(vec![b' '; (4 << 20) + 1]);
    assert_eq!(
        server
            .call("POST", "/api/login", &[content_type], oversized)
            .await?
            .0,
        StatusCode::PAYLOAD_TOO_LARGE
    );
    for id in [None, Some("admin"), Some("writer")] {
        let headers: Vec<_> = id.into_iter().map(|id| ("x-test-id", id)).collect();
        assert_eq!(
            server
                .call("POST", module_path, &headers, Body::empty())
                .await?
                .0,
            StatusCode::UNAUTHORIZED,
        );
    }
    assert_eq!(
        server
            .call(
                "POST",
                module_path,
                &[("x-fixture-credential", "module-proof")],
                Body::empty(),
            )
            .await?
            .2,
        json!({"ok": true})
    );
    assert_eq!(
        server.call("GET", disabled, &[], Body::empty()).await?.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        server.call("GET", absent, &[], Body::empty()).await?.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(attempts.load(Ordering::Relaxed), 0);
    assert_eq!(
        server
            .call("GET", "/api/login", &[], Body::empty())
            .await?
            .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(attempts.load(Ordering::Relaxed), 1);
    Ok(())
}

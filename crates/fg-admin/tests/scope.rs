use axum::http::Method;
use fg_admin::scope::{Access, required};

#[test]
fn scope_matches_every_pinned_upstream_operation() {
    let fixture = include_str!("fixtures/upstream-openapi-index.tsv");
    let mut checked = 0;
    let mut mismatches = Vec::new();
    for line in fixture.lines().filter(|line| !line.starts_with('#')) {
        let [method, path, scope, token] = line.split('\t').collect::<Vec<_>>().try_into().unwrap();
        let method = Method::from_bytes(method.as_bytes()).unwrap();
        let access = required(&method, path);
        if access.to_string() != scope
            || (!matches!(access, Access::SessionOnly | Access::Public)) != (token == "true")
        {
            mismatches.push(format!(
                "{method} {path}: expected {scope:?}/{token}, found {access}"
            ));
        }
        checked += 1;
    }
    assert_eq!(checked, 808);
    assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
}

#[test]
fn access_distinguishes_read_write_wildcards_and_compound_permissions() {
    let access = required(&Method::POST, "/api/wol/devices/key/shutdown");
    assert!(!access.allows_token(&["wol:write".into()]));
    assert!(!access.allows_token(&["wol:write".into(), "webterminal:read".into()]));
    assert!(access.allows_token(&["wol:write".into(), "webterminal:write".into()]));
    assert!(access.allows_token(&["*".into()]));
    assert!(
        !required(&Method::GET, "/api/docker/images/download").allows_token(&["*:read".into()])
    );
    assert!(
        required(&Method::HEAD, "/api/docker/logs/export").allows_token(&["docker:write".into()])
    );
    assert!(!required(&Method::POST, "/api/tokens").allows_token(&["*".into()]));
}

#[test]
#[should_panic(expected = "public API routes must provide their own authentication")]
fn public_credential_routes_cannot_use_the_normal_registration_path() {
    let _ = fg_admin::ApiRouter::default().route(
        Method::POST,
        "/api/wol/public/agent/poll",
        "Poll an agent",
        || async {},
    );
}

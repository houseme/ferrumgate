use anyhow::Result;
use http_body_util::BodyExt;
use hyper::{
    Method,
    header::{CONTENT_LENGTH, CONTENT_TYPE, LOCATION},
};

use super::common::*;

#[tokio::test]
async fn redirects_preserve_raw_path_and_use_the_validated_host() -> Result<()> {
    let routes = r#"
[[routes]]
host = "app.test"

[routes.response]
type = "redirect"
target = "https://{host}:8443/base"
status = 308
keep_path = true

[[routes]]
host = "app.test"
path_prefix = "/fixed"

[routes.response]
type = "redirect"
target = "https://example.test/final?keep=target"
keep_path = true
"#;
    let gateway = Gateway::spawn(&config(routes, "", "")).await?;
    let mut client = http_client(connect(gateway.addr).await?).await?;
    let response = send(
        &mut client,
        request(Method::GET, "/%2F/a?key=x%20y", "APP.TEST.:9000", full("")),
    )
    .await?;
    assert_eq!(response.status(), 308);
    assert_eq!(
        response.headers()[LOCATION],
        "https://app.test:8443/base/%2F/a?key=x%20y"
    );
    assert!(response.into_body().collect().await?.to_bytes().is_empty());
    let response = send(
        &mut client,
        request(Method::GET, "/fixed?drop=original", "app.test", full("")),
    )
    .await?;
    assert_eq!(response.status(), 302);
    assert_eq!(
        response.headers()[LOCATION],
        "https://example.test/final/fixed?keep=target"
    );
    assert_eq!(get(&mut client, "unconfigured.test", "/").await?.0, 404);
    Ok(())
}

#[tokio::test]
async fn fixed_text_returns_typed_utf8_and_head_metadata() -> Result<()> {
    let routes = r#"
[[routes]]
host = "app.test"
[routes.response]
type = "text"
body = "服务暂不可用"
status = 503
content_type = "text/plain; charset=utf-8"
"#;
    let gateway = Gateway::spawn(&config(routes, "", "")).await?;
    let mut client = http_client(connect(gateway.addr).await?).await?;
    for method in [Method::GET, Method::HEAD] {
        let reply = send(
            &mut client,
            request(method.clone(), "/", "app.test", full("")),
        )
        .await?;
        assert_eq!(reply.status(), 503);
        assert_eq!(reply.headers()[CONTENT_TYPE], "text/plain; charset=utf-8");
        assert_eq!(
            reply.headers()[CONTENT_LENGTH],
            "服务暂不可用".len().to_string()
        );
        let expected = if method == Method::HEAD {
            ""
        } else {
            "服务暂不可用"
        };
        assert_eq!(reply.into_body().collect().await?.to_bytes(), expected);
    }
    Ok(())
}

#[tokio::test]
async fn rejects_invalid_and_conflicting_site_actions() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let route = "[[routes]]\nhost = \"app.test\"\n";
    for action in [
        "[routes.response]\ntype = 'redirect'\ntarget = '//example.test'\n",
        "[routes.response]\ntype = 'redirect'\ntarget = 'https://user@example.test'\n",
        "[routes.response]\ntype = 'redirect'\ntarget = 'https://{host}@example.test'\n",
        "[routes.response]\ntype = 'redirect'\ntarget = 'https://example.test'\nstatus = 305\n",
        "[routes.response]\ntype = 'text'\nbody = 'forbidden body'\nstatus = 204\n",
        "[routes.response]\ntype = 'text'\nbody = 'ok'\ncontent_type = 'bad type'\n",
        "upstream = 'http://127.0.0.1:9000'\n[routes.response]\ntype = 'text'\nbody = 'ambiguous'\n",
    ] {
        let routes = route.to_owned() + action;
        assert!(
            !Gateway::check(dir.path(), &config(&routes, "", "")).await?,
            "{action}"
        );
    }
    Ok(())
}

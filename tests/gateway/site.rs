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

fn static_route(root: &std::path::Path) -> String {
    format!(
        r#"
[[routes]]
host = "app.test"
path_prefix = "/assets"
[routes.response]
type = "static"
root = "{}"
clean_urls = true
not_found = "404.html"
"#,
        root.display()
    )
}

#[tokio::test]
async fn serves_static_indexes_clean_urls_ranges_and_head() -> Result<()> {
    let root = tempfile::tempdir()?;
    std::fs::create_dir(root.path().join("guide"))?;
    std::fs::write(root.path().join("index.html"), "home")?;
    std::fs::write(root.path().join("guide/index.html"), "guide")?;
    std::fs::write(root.path().join("about.html"), "about")?;
    std::fs::write(root.path().join("hello world.txt"), "0123456789")?;
    std::fs::write(root.path().join("404.html"), "custom missing")?;
    let gateway = Gateway::spawn(&config(&static_route(root.path()), "", "")).await?;
    let mut client = http_client(connect(gateway.addr).await?).await?;
    for (path, expected) in [
        ("/assets", "home"),
        ("/assets/", "home"),
        ("/assets/guide/", "guide"),
        ("/assets/about?source=test", "about"),
    ] {
        let (status, body) = get(&mut client, "app.test", path).await?;
        assert_eq!((status, body.as_ref()), (200, expected.as_bytes()));
    }

    let path = "/assets/hello%20world.txt";
    let head = send(
        &mut client,
        request(Method::HEAD, path, "app.test", full("")),
    )
    .await?;
    assert_eq!(head.status(), 200);
    assert_eq!(head.headers()[CONTENT_LENGTH], "10");
    assert_eq!(head.headers()[CONTENT_TYPE], "text/plain");
    assert!(head.into_body().collect().await?.to_bytes().is_empty());

    for (range, expected) in [
        ("bytes=2-5", "2345"),
        ("bytes=-2", "89"),
        ("bytes=8-", "89"),
    ] {
        let mut req = request(Method::GET, path, "app.test", full(""));
        req.headers_mut().insert("range", range.parse()?);
        let reply = send(&mut client, req).await?;
        assert_eq!(reply.status(), 206);
        assert_eq!(reply.headers()["accept-ranges"], "bytes");
        let content_range = if expected == "2345" {
            "bytes 2-5/10"
        } else {
            "bytes 8-9/10"
        };
        assert_eq!(reply.headers()["content-range"], content_range);
        assert_eq!(reply.into_body().collect().await?.to_bytes(), expected);
    }
    let mut out_of_range = request(Method::GET, path, "app.test", full(""));
    out_of_range
        .headers_mut()
        .insert("range", "bytes=20-".parse()?);
    let reply = send(&mut client, out_of_range).await?;
    assert_eq!(reply.status(), 416);
    assert_eq!(reply.headers()["content-range"], "bytes */10");
    reply.into_body().collect().await?;

    let (status, missing) = get(&mut client, "app.test", "/assets/missing").await?;
    assert_eq!(
        (status, missing.as_ref()),
        (404, b"custom missing".as_slice())
    );
    let post = send(
        &mut client,
        request(Method::POST, path, "app.test", full("")),
    )
    .await?;
    assert_eq!(post.status(), 405);
    assert_eq!(post.headers()["allow"], "GET, HEAD");
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn confines_static_files_to_the_published_root() -> Result<()> {
    let root = tempfile::tempdir()?;
    let private = tempfile::tempdir()?;
    std::fs::write(private.path().join("private.txt"), "private path")?;
    std::os::unix::fs::symlink(
        private.path().join("private.txt"),
        root.path().join("outside.txt"),
    )?;
    std::fs::write(root.path().join("404.html"), "missing")?;
    assert!(!Gateway::check(root.path(), &config(&static_route(root.path()), "", "")).await?);

    let private_cfg = tempfile::tempdir()?;
    let ca = Ca::new()?;
    ca.identity("app.test")?.write(private.path(), "private")?;
    let certificate = format!(
        "[[certificates]]\nhost = 'app.test'\ncert_file = '{}'\nkey_file = '{}'\n",
        private.path().join("private.pem").display(),
        private.path().join("private.key").display()
    );
    assert!(
        !Gateway::check(
            private_cfg.path(),
            &config(
                &(static_route(private.path()) + &certificate),
                "tls = true",
                ""
            )
        )
        .await?
    );

    let gateway = Gateway::spawn(&config(&static_route(root.path()), "", "")).await?;
    let mut client = http_client(connect(gateway.addr).await?).await?;
    let (status, body) = get(&mut client, "app.test", "/assets/outside.txt").await?;
    assert_eq!((status, body.as_ref()), (404, b"missing".as_slice()));
    assert_eq!(
        get(&mut client, "app.test", "/assets/%2Fmissing").await?.0,
        400
    );
    Ok(())
}

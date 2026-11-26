use super::*;
use fg_logging::{Logs, Options};

const READ: [(&str, &str); 1] = [("x-test-id", "log-reader")];
const WRITE: [(&str, &str); 1] = [("x-test-id", "log-writer")];
const ROOT: [(&str, &str); 1] = [("x-test-id", "admin")];

fn log_principal(headers: &HeaderMap) -> Option<Principal> {
    principal(headers).or_else(|| {
        let scopes = match headers.get("x-test-id")?.to_str().ok()? {
            "log-reader" => vec!["webservice:read".into()],
            "log-writer" => vec!["webservice:write".into()],
            _ => return None,
        };
        Some(Principal::Token { scopes })
    })
}

#[tokio::test]
async fn log_queries_exports_and_clear_enforce_the_same_scope() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let record = |seq, source, message, fields| {
        json!({
            "seq":seq, "time":"2026-11-26T00:00:00Z", "level":"info",
            "source":source, "message":message, "fields":fields,
        })
    };
    let persisted = [
        record(1, "previous", "previous request", json!({"status":"200"})),
        record(
            2,
            "site",
            "request failed https://site.test/?token=fixture-url",
            json!({
                "status":"503", "ip":"192.0.2.55", "path":"=fixture-formula", "token":"fixture-field"
            }),
        ),
        record(
            3,
            "site",
            "admin request",
            json!({"status":"502","admin":"1"}),
        ),
    ];
    let file = dir.path().join("webservice.log");
    fs::write(&file, persisted.map(|row| row.to_string() + "\n").concat())?;
    let logs = Logs::start(
        Options {
            directory: Some(dir.path().to_owned()),
            lines: 1,
            ..Options::default()
        },
        std::io::sink(),
    )?;
    let registry = Registry::new(&["webservice", "portforward"]);
    let enabled = registry.resolve_enabled(&["portforward".into()], false);
    let admin = ApiRouter::new(log_principal)
        .with_modules(registry, enabled)
        .with_logs(logs.handle())
        .finish();
    let expected_spec = admin.document().clone();
    let server = Server::start(admin.router).await?;
    let path = "/api/webservice/logs";
    let (status, _, page) = server
        .call(
            "GET",
            &format!(
                "{path}?limit=5&since=1&status=5xx&hideAdmin=1&from=1795651200000&q=request+failed"
            ),
            &READ,
            Body::empty(),
        )
        .await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(page.as_array().unwrap().len(), 1);
    assert_eq!(page[0]["seq"], 2);
    assert_eq!(page[0]["fields"]["token"], SECRET_MASK);
    assert!(!page[0]["message"].as_str().unwrap().contains("fixture-url"));
    let (_, _, page) = server.call("GET", path, &READ, Body::empty()).await?;
    assert_eq!(page.as_array().unwrap().len(), 1);
    assert_eq!(page[0]["seq"], 3);
    for id in [READ, WRITE] {
        let (_, _, page) = server
            .call(
                "GET",
                &format!("{path}?limit=5&q=fixture-field"),
                &id,
                Body::empty(),
            )
            .await?;
        assert_eq!(page.as_array().unwrap().len(), usize::from(id == WRITE));
    }
    for query in [
        "limit=20001",
        "since=-1",
        "status=bogus",
        "from=2026",
        "from=1795651200000&to=1795651100000",
    ] {
        let (status, _, body) = server
            .call("GET", &format!("{path}?{query}"), &READ, Body::empty())
            .await?;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{query}");
        assert!(body["error"].is_string());
    }
    assert_eq!(
        server
            .call("GET", "/api/logs", &READ, Body::empty())
            .await?
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        server.call("DELETE", path, &READ, Body::empty()).await?.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        server
            .call("GET", "/api/portforward/logs", &ROOT, Body::empty())
            .await?
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        server
            .call("GET", "/api/ssl/logs", &ROOT, Body::empty())
            .await?
            .0,
        StatusCode::NOT_FOUND
    );
    let (_, _, sources) = server
        .call("GET", &format!("{path}/sources"), &READ, Body::empty())
        .await?;
    assert_eq!(sources, json!(["previous", "site"]));
    let export = format!("{path}/export?status=503");
    let (status, headers, ndjson) = server
        .call_raw(
            "GET",
            &export,
            &[READ[0], ("accept-encoding", "gzip")],
            Body::empty(),
        )
        .await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers["content-type"],
        "application/x-ndjson; charset=utf-8"
    );
    assert_eq!(headers["cache-control"], "no-store");
    assert!(headers.get("content-encoding").is_none());
    assert!(headers.get("content-length").is_none());
    let row: Value = serde_json::from_slice(&ndjson)?;
    assert_eq!(row["fields"]["token"], SECRET_MASK);
    assert!(!std::str::from_utf8(&ndjson)?.contains("fixture-url"));
    let (_, _, filtered) = server
        .call_raw(
            "GET",
            &format!("{export}&q=fixture-url"),
            &READ,
            Body::empty(),
        )
        .await?;
    assert!(filtered.is_empty());
    for id in [READ, WRITE] {
        let (status, headers, csv) = server
            .call_raw("GET", &format!("{export}&format=csv"), &id, Body::empty())
            .await?;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers["content-type"], "text/csv; charset=utf-8");
        assert_eq!(
            headers["content-disposition"],
            "attachment; filename=logs.csv"
        );
        let csv = std::str::from_utf8(&csv)?;
        assert!(csv.starts_with("\u{feff}time,"));
        assert!(csv.contains("'=fixture-formula"));
        assert_eq!(csv.contains("fixture-url"), id == WRITE);
    }
    let (_, _, spec) = server
        .call("GET", "/api/openapi.json", &READ, Body::empty())
        .await?;
    assert_eq!(spec, expected_spec);
    assert!(spec["paths"]["/api/ssl/logs"].is_null());
    assert!(spec["paths"]["/api/portforward/logs"].is_null());
    let operation = &spec["paths"][path]["get"];
    assert_eq!(operation["x-required-scope"], "webservice:read");
    let entries = &operation["responses"]["200"]["content"]["application/json"]["schema"];
    assert_eq!(entries["type"], "array");
    assert_eq!(entries["items"]["properties"]["seq"]["type"], "integer");
    assert_eq!(entries["items"]["properties"]["time"]["type"], "string");
    let parameters = operation["parameters"].as_array().unwrap();
    assert!(parameters.iter().any(|param| param["name"] == "hideAdmin"));
    assert!(!parameters.iter().any(|param| param["name"] == "format"));
    let export_doc = &spec["paths"][format!("{path}/export")]["get"];
    assert_eq!(export_doc["x-stream"], true);
    assert_eq!(
        export_doc["responses"]["200"]["content"]["text/csv"]["schema"]["format"],
        "binary"
    );
    assert_eq!(
        server.call("DELETE", path, &WRITE, Body::empty()).await?.2,
        json!({"ok":true})
    );
    assert_eq!(
        server
            .call("GET", &format!("{path}?limit=20"), &READ, Body::empty())
            .await?
            .2,
        json!([])
    );
    assert_eq!(
        server
            .call("GET", &format!("{path}/sources"), &READ, Body::empty())
            .await?
            .2,
        json!([])
    );
    logs.shutdown(Duration::from_secs(3))?;
    Ok(())
}

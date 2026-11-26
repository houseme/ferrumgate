use super::*;
use fg_admin::{Localizer, RequestLanguage, Translation};
use schemars::JsonSchema;

#[derive(Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct Item {
    #[serde(default)]
    key: String,
    name: String,
    settings: Settings,
}

#[derive(Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct Settings {
    port: u16,
}

#[derive(Serialize, JsonSchema)]
struct ItemView {
    key: String,
    name: String,
    settings: Settings,
    running: bool,
    stats: Stats,
}

#[derive(Serialize, JsonSchema)]
struct Stats {
    count: u64,
}

#[tokio::test]
async fn collection_round_trips_declared_display_fields_with_strict_writable_keys() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let store = ConfigStore::open(&dir.path().join("config"))?;
    let collection = Collection::<Item, ItemView>::open(
        store.clone(),
        "ddns",
        8,
        |row| &row.key,
        |row, key| row.key = key,
        |_| Ok(()),
        |row| ItemView {
            key: row.key.clone(),
            name: row.name.clone(),
            settings: row.settings.clone(),
            running: true,
            stats: Stats { count: 17 },
        },
    )?
    .with_item_schema()
    .view_only(&["running", "stats"]);
    let path = "/api/ddns/rules";
    let admin = collection
        .register(ApiRouter::new(principal), RULES)
        .finish();
    let paths = &admin.document()["paths"];
    let list = &paths[path]["get"]["responses"]["200"]["content"]["application/json"]["schema"];
    let view = &list["items"];
    assert_eq!(list["type"], "array");
    assert_eq!(view["properties"]["running"]["type"], "boolean");
    assert_eq!(
        view["properties"]["stats"]["properties"]["count"]["type"],
        "integer"
    );
    for (path, method) in [
        (path, "post"),
        (RULES.item, "put"),
        ("/api/ddns/rules/{key}/copy", "post"),
    ] {
        let operation = &paths[path][method];
        let request = &operation["requestBody"]["content"]["application/json"]["schema"];
        let output = &operation["responses"]["200"]["content"]["application/json"]["schema"];
        assert_eq!(request["required"], json!(["name", "settings"]));
        assert_eq!(request["additionalProperties"], false);
        assert_eq!(
            request["properties"]["settings"]["additionalProperties"],
            false
        );
        assert_eq!(request["properties"]["running"], json!({}));
        assert_eq!(request["properties"]["stats"], json!({}));
        assert_eq!(output["properties"], view["properties"]);
    }
    assert!(paths["/api/ddns/rules-enable"].is_null());
    let export = dir.path().join("api");
    admin.export(&export)?;
    let exported: Value = serde_json::from_slice(&fs::read(export.join("openapi.json"))?)?;
    assert_eq!(exported, *admin.document());
    assert!(fs::read_to_string(export.join("API.md"))?.contains("`/api/ddns/rules/{key}/copy`"));
    let server = Server::start(admin.router).await?;
    let draft =
        r#"{"name":"created","settings":{"port":80},"running":false,"stats":{"unchecked":[1,2]}}"#;
    let (status, _, created) = server.call("POST", path, &EDIT, draft).await?;
    assert_eq!(status, StatusCode::OK);
    let key = created["key"].as_str().unwrap();
    let item_path = format!("{path}/{key}");
    let before = store.load_raw("ddns")?;
    for bad in [
        r#"{"name":"one","n\u0061me":"two","settings":{"port":80},"running":true}"#,
        r#"{"name":"bad","settings":{"port":80,"stats":1},"running":true}"#,
        r#"{"name":"bad","settings":{"port":80},"runing":true}"#,
        r#"{"name":"bad","settings":{"port":80},"stats":[not-json]}"#,
        r#"{"name":"bad","settings":{"port":80},"running":true} {}"#,
        r#"["trailing array"]"#,
    ] {
        assert_eq!(
            server.call("PUT", &item_path, &EDIT, bad).await?.0,
            StatusCode::BAD_REQUEST,
            "accepted {bad}"
        );
    }
    assert_eq!(store.load_raw("ddns")?, before);

    let mut editable = server.call("GET", path, &EDIT, Body::empty()).await?.2[0].clone();
    editable["name"] = json!("round trip");
    editable["settings"]["port"] = json!(443);
    assert_eq!(
        server
            .call("PUT", &item_path, &EDIT, editable.to_string())
            .await?
            .0,
        StatusCode::OK
    );
    let copied = server
        .call(
            "POST",
            &format!("{item_path}/copy"),
            &EDIT,
            editable.to_string(),
        )
        .await?;
    assert_eq!(copied.0, StatusCode::OK);
    assert_ne!(copied.2["key"], key);
    let persisted: Value = serde_json::from_slice(&store.load_raw("ddns")?.unwrap())?;
    assert_eq!(persisted.as_array().unwrap().len(), 2);
    for item in persisted.as_array().unwrap() {
        assert_eq!(item["name"], "round trip");
        assert_eq!(item["settings"]["port"], 443);
        assert!(item.get("running").is_none());
        assert!(item.get("stats").is_none());
    }
    Ok(())
}

#[tokio::test]
async fn localization_negotiates_and_rewrites_only_declared_paths_before_redaction_and_gzip()
-> Result<()> {
    let localizer = Localizer::new(
        "en",
        "en",
        &["en", "zh-CN", "zh-TW", "de"],
        |lang, text| match (lang, text) {
            ("zh-TW", "ready") => {
                Some("可用 https://example.test/status?secret=fixture-translated".into())
            }
            ("zh-TW", "authentication required") => Some("請先登入".into()),
            ("de", "ready") => Some("bereit".into()),
            _ => None,
        },
    )?;
    let admin = ApiRouter::new(principal).with_localizer(localizer)
        .translated_route(Method::GET, "/api/ddns/localized", "Localized view", Translation::Fields(&["/status/label"]), |Extension(language): Extension<RequestLanguage>| async move {
            Json(json!({"lang":language.as_str(),"name":"ready","status":{"label":"ready"},"config":{"label":"ready"},"padding":"x".repeat(4096)}))
        })
        .translated_route(Method::GET, "/api/ddns/report", "Generated report", Translation::Generated, || async { Json(json!({"result":["ready"]})) })
        .finish();
    let server = Server::start(admin.router).await?;
    let path = "/api/ddns/localized";
    let weighted = "no;q=1, zh;q=0, ZH-tw;q=0.8, de;q=0.6";
    let (status, headers, compressed) = server
        .call_raw(
            "GET",
            path,
            &[
                ("x-test-id", "viewer"),
                ("accept-language", weighted),
                ("accept-encoding", "gzip"),
            ],
            Body::empty(),
        )
        .await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["content-language"], "zh-TW");
    assert_eq!(headers["content-encoding"], "gzip");
    for name in ["Accept-Language", "Accept-Encoding"] {
        assert!(headers.get_all("vary").iter().any(|entry| entry == name));
    }
    let mut json = String::new();
    flate2::read::GzDecoder::new(compressed.as_ref()).read_to_string(&mut json)?;
    assert!(!json.contains("fixture-translated"));
    let body: Value = serde_json::from_str(&json)?;
    assert_eq!(body["lang"], "zh-TW");
    assert_eq!(
        body["status"]["label"],
        "可用 https://example.test/status?secret=********"
    );
    assert_eq!(body["name"], "ready");
    assert_eq!(body["config"]["label"], "ready");

    let (_, headers, error) = server
        .call("GET", path, &[("accept-language", "zh-TW")], Body::empty())
        .await?;
    assert_eq!(headers["content-language"], "zh-TW");
    assert_eq!(error, json!({"error":"請先登入"}));
    let (_, headers, report) = server
        .call(
            "GET",
            "/api/ddns/report",
            &[("x-test-id", "admin"), ("accept-language", "de-DE")],
            Body::empty(),
        )
        .await?;
    assert_eq!(headers["content-language"], "de");
    assert_eq!(report, json!({"result":["bereit"]}));
    let (_, headers, fallback) = server
        .call(
            "GET",
            path,
            &[
                ("x-test-id", "admin"),
                ("accept-language", "unsupported;q=1"),
            ],
            Body::empty(),
        )
        .await?;
    assert!(headers.get("content-language").is_none());
    assert_eq!(fallback["lang"], "en");
    assert_eq!(fallback["status"]["label"], "ready");
    Ok(())
}

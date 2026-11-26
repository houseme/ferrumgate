use super::*;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Item {
    #[serde(default)]
    key: String,
    name: String,
    settings: Settings,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Settings {
    port: u16,
}

#[tokio::test]
async fn collection_round_trips_declared_display_fields_with_strict_writable_keys() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let store = ConfigStore::open(&dir.path().join("config"))?;
    let collection = Collection::<Item>::open(store.clone(), "ddns", 8, |row| &row.key, |row, key| row.key = key,
        |_| Ok(()), |row| json!({"key":row.key,"name":row.name,"settings":row.settings,"running":true,"stats":{"count":17}}),
    )?.view_only(&["running", "stats"]);
    let server = Server::start(
        collection
            .register(ApiRouter::new(principal), RULES)
            .finish()
            .router,
    )
    .await?;
    let path = "/api/ddns/rules";
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

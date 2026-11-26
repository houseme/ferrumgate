use std::{
    io::Write,
    process::{Command, Stdio},
    time::Duration,
};

use anyhow::Result;
use serde_json::{Value, json};
use tokio::process::Command as AsyncCommand;

const DEADLINE: Duration = Duration::from_secs(30);

/// Boots a real instance and returns (url, token). Mirrors tests/ctl.rs.
async fn start() -> Result<(String, String, tokio::process::Child)> {
    let directory = tempfile::tempdir()?;
    let accounts = directory.path().join("accounts");
    let config_path = directory.path().join("gateway.toml");
    {
        let store = fg_config::ConfigStore::open(&accounts)?;
        store.save(
            "account",
            &json!({
                "username":"operator",
                "passwordHash":bcrypt::hash("Fixture-initial$23", 4)?,
                "sessionSecret":"fixture-session-secret-for-mcp-tests",
            }),
        )?;
        let secret = format!("gtl_{}", "9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a");
        use ring::digest::{SHA256, digest};
        let hash = digest(&SHA256, secret.as_bytes());
        store.save("tokens", &json!({"tokens":[{
            "id":"abc123def456","name":"ops","group":"",
            "hash":data_encoding::HEXLOWER.encode(hash.as_ref()),
            "hint":"mcp","scopes":["ddns:write","webservice:read"],"legacy":false,"disabled":false,
            "createdAt":"2026-11-27T00:00:00Z",
        }]}))?;
        std::fs::write(directory.path().join(".token"), secret)?;
    }
    let backend = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let backend_addr = backend.local_addr()?;
    tokio::spawn(async move {
        loop {
            let _ = backend.accept().await;
        }
    });
    std::fs::write(
        &config_path,
        format!(
            "schema_version = 1\n\n[server]\nlisten = \"127.0.0.1:0\"\n\n\
             [[routes]]\nhost = \"app.test\"\npath_prefix = \"/\"\n\
             upstream = \"http://{backend_addr}\"\n"
        ),
    )?;
    let mut child = AsyncCommand::new(env!("CARGO_BIN_EXE_fgate"))
        .args(["serve", "--config"])
        .arg(&config_path)
        .args(["--admin-listen", "127.0.0.1:0", "--admin-dir"])
        .arg(&accounts)
        .env_remove("FERRUMGATE_LOG_LEVEL")
        .env_remove("FERRUMGATE_INITIAL_PASSWORD")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut stderr = child.stderr.take().expect("management output");
    let address = tokio::time::timeout(DEADLINE, async {
        use tokio::io::{AsyncBufReadExt, BufReader};
        let mut lines = BufReader::new(&mut stderr).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            if line.contains("management ready")
                && let Some(address) = line
                    .split_whitespace()
                    .find_map(|word| word.strip_prefix("listen="))
            {
                return Ok::<_, anyhow::Error>(address.to_owned());
            }
        }
        anyhow::bail!("management listener did not start")
    })
    .await??;
    // Keep draining stderr so the instance never blocks on a full pipe.
    // Keep draining stderr so the instance never blocks on a full pipe.
    tokio::spawn(async move {
        use tokio::io::{AsyncBufReadExt, BufReader};
        let mut lines = BufReader::new(stderr).lines();
        while lines.next_line().await.is_ok() {}
    });
    let token = std::fs::read_to_string(directory.path().join(".token"))?;

    Ok((format!("http://{address}"), token, child))
}

/// Drives one `fgate mcp` subprocess with a list of JSON-RPC requests and
/// collects its responses.
fn drive(url: &str, token: &str, extra: &[&str], requests: &[Value]) -> Result<Vec<Value>> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_fgate"))
        .arg("mcp")
        .arg("--url")
        .arg(url)
        .arg("--token")
        .arg(token)
        .args(extra)
        .env_remove("FERRUMGATE_URL")
        .env_remove("FERRUMGATE_TOKEN")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    {
        let mut stdin = child.stdin.take().expect("mcp stdin");
        for request in requests {
            serde_json::to_writer(&mut stdin, request)?;
            stdin.write_all(b"\n")?;
        }
    }
    drop(child.stdin.take());
    let output = child.wait_with_output()?;
    let responses = String::from_utf8(output.stdout)?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()?;
    Ok(responses)
}

#[tokio::test]
async fn mcp_initialize_lists_readonly_tools_and_rejects_writes() -> Result<()> {
    let (url, token, _instance) = start().await?;
    let requests = vec![
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}),
        json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{
            "name":"delete_webservice_logs","arguments":{}}}),
        json!({"jsonrpc":"2.0","id":4,"method":"bogus/method","params":{}}),
    ];
    let responses = drive(&url, &token, &[], &requests)?;
    eprintln!("MCP-RESPONSES: {responses:?}");
    assert_eq!(responses.len(), 4, "one response per request");

    assert_eq!(responses[0]["result"]["protocolVersion"], "2024-11-05");
    assert_eq!(responses[0]["result"]["serverInfo"]["name"], "ferrumgate");

    let tools = responses[1]["result"]["tools"].as_array().unwrap();
    assert!(!tools.is_empty());
    for tool in tools {
        // Read-only by default: no write methods, no secrets paths.
        assert!(
            tool["name"].as_str().unwrap().starts_with("get_"),
            "default list is GET-only: {}",
            tool["name"]
        );
        assert!(!tool["name"].as_str().unwrap().contains("secrets"));
        assert_eq!(tool["annotations"]["readOnlyHint"], true);
    }
    assert!(
        tools
            .iter()
            .all(|tool| tool["name"].as_str() != Some("delete_webservice_logs")),
        "delete tools stay hidden without --write"
    );

    // The hidden delete tool is still unknown in read-only mode.
    assert!(
        responses[2]["error"]["message"]
            .as_str()
            .unwrap()
            .contains("未知工具")
    );

    assert_eq!(responses[3]["error"]["code"], -32601);
    Ok(())
}

#[tokio::test]
async fn mcp_calls_a_tool_and_fills_path_parameters() -> Result<()> {
    let (url, token, _instance) = start().await?;
    let requests = vec![
        json!({"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{
            "name":"get_session","arguments":{}}}),
    ];
    let responses = drive(&url, &token, &[], &requests)?;
    let session = &responses[1]["result"]["content"][0]["text"];
    let text = session.as_str().unwrap();
    assert!(text.contains("api-token:ops"), "{text}");

    // Query objects flow into the request URL.
    let call = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "get_webservice_logs",
            "arguments": {"query": {"limit": 5}}
        }
    });
    let requests = vec![
        json!({"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}),
        call,
    ];
    let responses = drive(&url, &token, &[], &requests)?;
    assert!(responses[1]["result"]["content"][0]["text"].is_string());
    Ok(())
}

#[tokio::test]
async fn mcp_write_flag_still_respects_token_scopes() -> Result<()> {
    let (url, token, _instance) = start().await?;
    let requests = vec![
        json!({"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}),
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "delete_webservice_logs", "arguments": {}}
        }),
    ];
    let responses = drive(&url, &token, &["--write"], &requests)?;
    let tools = responses[0]["result"]["tools"].as_array().unwrap();
    assert!(
        tools
            .iter()
            .any(|tool| tool["name"] == json!("delete_webservice_logs")),
        "write tools appear with --write"
    );
    // The token lacks webservice:write, so the instance rejects the call.
    let error = responses[1]["error"]["message"].as_str().unwrap();
    assert!(error.contains("HTTP 403"), "{error}");
    Ok(())
}

//! `fgate mcp`: expose the management API as MCP tools over stdio using a
//! hand-written JSON-RPC 2.0 server (one message per line).

pub mod tools;

use std::io::{BufRead, Write};

use anyhow::Result;
use hyper::Method;
use serde_json::{Value, json};

use crate::ctl::client::ClientHandle;

const PROTOCOL: &str = "2024-11-05";
const SERVER_NAME: &str = "ferrumgate";

pub struct McpOptions {
    pub url: String,
    pub token: String,
    pub insecure: bool,
    pub write: bool,
}

/// Reads newline-framed JSON-RPC messages from stdin until EOF.
pub async fn run(options: McpOptions) -> Result<()> {
    // One client per message: MCP traffic is a handful of sequential calls,
    // and fresh connections sidestep pooled keep-alive edge cases.
    let make_client = || ClientHandle::new(options.token.clone(), options.insecure);
    let mut cached: Option<Vec<tools::Tool>> = None;
    let stdin = std::io::stdin();
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let Ok(message) = serde_json::from_str::<Value>(&line) else {
            respond_error(None, -32700, "解析错误")?;
            continue;
        };
        let id = message.get("id").cloned();
        if id.is_none() {
            // A notification: no response, per JSON-RPC.
            continue;
        }
        let method = message["method"].as_str().unwrap_or_default();
        let response = match method {
            "initialize" => initialize(),
            "tools/list" => {
                match tools_list(&make_client()?, &options.url, options.write, &mut cached).await {
                    Ok(list) => list,
                    Err(error) => {
                        respond_error(id, -32000, &error.to_string())?;
                        continue;
                    }
                }
            }
            "tools/call" => match tools_call(
                &make_client()?,
                &options.url,
                options.write,
                &cached,
                &message,
            )
            .await
            {
                Ok(result) => result,
                Err(error) => {
                    respond_error(id, -32000, &error.to_string())?;
                    continue;
                }
            },
            other => {
                respond_error(id, -32601, &format!("未知方法 {other}"))?;
                continue;
            }
        };
        write_response(id, response)?;
    }
    Ok(())
}

fn initialize() -> Value {
    json!({
        "protocolVersion": PROTOCOL,
        "capabilities": {"tools": {"listChanged": false}},
        "serverInfo": {"name": SERVER_NAME, "version": env!("CARGO_PKG_VERSION")},
    })
}

async fn tools_list(
    client: &ClientHandle,
    url: &str,
    write: bool,
    cached: &mut Option<Vec<tools::Tool>>,
) -> Result<Value> {
    if cached.is_none() {
        let document = match client
            .call(Method::GET, &format!("{url}/api/openapi.json"), None)
            .await?
        {
            Ok(bytes) => serde_json::from_slice(&bytes)?,
            Err(error) => anyhow::bail!("HTTP {}: {}", error.status, error.message),
        };
        *cached = Some(tools::build_tools(&document, write));
    }
    let list: Vec<Value> = cached
        .as_ref()
        .expect("the cache was just populated")
        .iter()
        .map(|tool| {
            json!({
                "name": tool.name,
                "description": tool.description,
                "inputSchema": tool.input_schema,
                "annotations": {
                    "readOnlyHint": tool.read_only,
                    "destructiveHint": tool.destructive,
                },
            })
        })
        .collect();
    Ok(json!({"tools": list}))
}

async fn tools_call(
    client: &ClientHandle,
    url: &str,
    write: bool,
    cached: &Option<Vec<tools::Tool>>,
    message: &Value,
) -> Result<Value> {
    let name = message["params"]["name"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("缺少工具名"))?;
    let arguments = &message["params"]["arguments"];
    let tools = cached.as_ref().map(Vec::as_slice).unwrap_or_default();
    let tool = tools
        .iter()
        .find(|tool| tool.name == name)
        .ok_or_else(|| anyhow::anyhow!("未知工具 {name}"))?;
    if !write && !tool.read_only {
        anyhow::bail!("默认只读；使用 --write 开启写操作");
    }
    let path = tools::fill_path(&tool.path, arguments).map_err(anyhow::Error::msg)?;
    let query = arguments
        .get("query")
        .and_then(|query| query.as_object())
        .filter(|entries| !entries.is_empty())
        .map(|entries| {
            entries
                .iter()
                .map(|(key, value)| {
                    let rendered = match value {
                        Value::String(text) => text.clone(),
                        other => other.to_string(),
                    };
                    format!("{}={}", url_escape(key), url_escape(&rendered))
                })
                .collect::<Vec<_>>()
                .join("&")
        });
    let target = match query {
        Some(query) => format!("{url}{path}?{query}"),
        None => format!("{url}{path}"),
    };
    let body = arguments
        .get("body")
        .filter(|body| !body.is_null())
        .map(serde_json::to_vec)
        .transpose()?;
    let bytes = match client.call(tool.method.clone(), &target, body).await? {
        Ok(bytes) => bytes,
        Err(error) => anyhow::bail!("HTTP {}: {}", error.status, error.message),
    };
    let text = tools::truncate(&String::from_utf8_lossy(&bytes));
    Ok(json!({
        "content": [{"type": "text", "text": text}],
        "isError": false,
    }))
}

fn url_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                escaped.push(byte as char)
            }
            _ => escaped.push_str(&format!("%{byte:02X}")),
        }
    }
    escaped
}

fn write_response(id: Option<Value>, result: Value) -> Result<()> {
    let mut response = serde_json::Map::new();
    response.insert("jsonrpc".to_owned(), json!("2.0"));
    if let Some(id) = id {
        response.insert("id".to_owned(), id);
    }
    response.insert("result".to_owned(), result);
    let stdout = std::io::stdout();
    let mut stdout = stdout.lock();
    serde_json::to_writer(&mut stdout, &Value::Object(response))?;
    stdout.write_all(b"\n")?;
    stdout.flush()?;
    Ok(())
}

fn respond_error(id: Option<Value>, code: i64, message: &str) -> Result<()> {
    let mut response = serde_json::Map::new();
    response.insert("jsonrpc".to_owned(), json!("2.0"));
    if let Some(id) = id {
        response.insert("id".to_owned(), id);
    }
    response.insert(
        "error".to_owned(),
        json!({"code": code, "message": message}),
    );
    let stdout = std::io::stdout();
    let mut stdout = stdout.lock();
    serde_json::to_writer(&mut stdout, &Value::Object(response))?;
    stdout.write_all(b"\n")?;
    stdout.flush()?;
    Ok(())
}

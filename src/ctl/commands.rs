//! `fgate ctl` verbs: `ls`, `get`, `post`, `put`, `delete`, `patch` and
//! `login`, with stable exit codes (0 success, 1 API failure, 2 usage).

use std::io::{Read, Write};

use anyhow::{Context, Result, anyhow};
use hyper::Method;

use super::{
    client::ClientHandle,
    config::{CtlConfig, Overrides},
};

pub enum Command {
    Ls {
        filter: Option<String>,
    },
    Get {
        path: String,
    },
    Call {
        method: Method,
        path: String,
        body: Option<String>,
    },
    Login {
        url: String,
        token: String,
    },
}

/// Reads a request body given as a JSON literal, `@file` or `-` (standard
/// input); anything that is not valid JSON is a usage error.
pub fn read_body(spec: &str) -> Result<Vec<u8>> {
    let raw = if let Some(file) = spec.strip_prefix('@') {
        std::fs::read(file).with_context(|| format!("read request body {file}"))?
    } else if spec == "-" {
        let mut raw = Vec::new();
        std::io::stdin().lock().read_to_end(&mut raw)?;
        raw
    } else {
        spec.as_bytes().to_vec()
    };
    serde_json::from_slice::<serde_json::Value>(&raw)
        .map_err(|error| anyhow!("请求体不是合法 JSON：{error}"))?;
    Ok(raw)
}

/// Validates that a target path belongs to the management API.
pub fn validate_path(path: &str) -> Result<()> {
    if !path.starts_with("/api/") && path != "/api" {
        return Err(anyhow!("路径必须以 /api/ 开头"));
    }
    Ok(())
}

pub struct CtlOptions {
    pub url: Option<String>,
    pub token: Option<String>,
    pub insecure: bool,
    pub raw: bool,
}

/// Runs one command; the return value is the process exit code.
pub async fn run(options: CtlOptions, command: Command) -> Result<i32> {
    let environment = match (
        std::env::var("FERRUMGATE_URL"),
        std::env::var("FERRUMGATE_TOKEN"),
    ) {
        (Ok(url), Ok(token)) => Some((url, token)),
        (Ok(url), Err(_)) => Some((url, String::new())),
        (Err(_), Ok(token)) => Some((String::new(), token)),
        (Err(_), Err(_)) => None,
    };
    let config = CtlConfig::resolve(
        CtlConfig::load(),
        environment,
        Overrides {
            url: options.url,
            token: options.token,
            insecure: options.insecure,
        },
    );
    match command {
        Command::Login { url, token } => run_login(url, token, config.insecure).await,
        command => {
            let client = ClientHandle::new(config.token, config.insecure)?;
            match command {
                Command::Ls { filter } => run_ls(&client, &config.url, filter.as_deref()).await,
                Command::Get { path } => {
                    validate_path(&path)?;
                    run_call(&client, &config.url, Method::GET, &path, None, options.raw).await
                }
                Command::Call { method, path, body } => {
                    validate_path(&path)?;
                    let body = match body {
                        Some(spec) => Some(read_body(&spec)?),
                        None => None,
                    };
                    run_call(&client, &config.url, method, &path, body, options.raw).await
                }
                _ => unreachable!("login handled above"),
            }
        }
    }
}

async fn run_call(
    client: &ClientHandle,
    base: &str,
    method: Method,
    path: &str,
    body: Option<Vec<u8>>,
    raw: bool,
) -> Result<i32> {
    let url = format!("{base}{path}");
    match client.call(method, &url, body).await? {
        Ok(bytes) => {
            report(&bytes, raw)?;
            Ok(0)
        }
        Err(error) => {
            println!("错误: HTTP {}: {}", error.status, error.message);
            Ok(1)
        }
    }
}

async fn run_ls(client: &ClientHandle, base: &str, filter: Option<&str>) -> Result<i32> {
    let document = match client
        .call(Method::GET, &format!("{base}/api/openapi.json"), None)
        .await?
    {
        Ok(bytes) => serde_json::from_slice::<serde_json::Value>(&bytes)
            .context("解析实例的 OpenAPI 文档")?,
        Err(error) => {
            println!("错误: HTTP {}: {}", error.status, error.message);
            return Ok(1);
        }
    };
    let Some(paths) = document["paths"].as_object() else {
        return Err(anyhow!("OpenAPI 文档缺少 paths"));
    };
    let mut operations = Vec::new();
    for (path, methods) in paths {
        let Some(methods) = methods.as_object() else {
            continue;
        };
        for (method, operation) in methods {
            // Session-only and public operations are invisible to tokens.
            if operation["x-token-allowed"].as_bool() != Some(true) {
                continue;
            }
            let summary = operation["summary"].as_str().unwrap_or_default();
            let line = format!("{method:<7} {path:<44} {summary}");
            match filter {
                Some(filter)
                    if !path.contains(filter)
                        && !summary.to_lowercase().contains(&filter.to_lowercase()) => {}
                _ => operations.push(line),
            }
        }
    }
    operations.sort();
    if operations.is_empty() {
        println!("没有匹配的接口");
    } else {
        println!("{}", operations.join("\n"));
    }
    Ok(0)
}

async fn run_login(url: String, token: String, insecure: bool) -> Result<i32> {
    if !url.starts_with("http://") && !url.starts_with("https://") {
        return Err(anyhow!("地址必须以 http:// 或 https:// 开头"));
    }
    let probe = ClientHandle::new(token.clone(), insecure)?;
    match probe
        .call(Method::GET, &format!("{url}/api/session"), None)
        .await?
    {
        Ok(_) => {
            let saved = CtlConfig {
                url,
                token,
                insecure,
            };
            let path = saved.save()?;
            println!("连接信息已保存到 {}", path.display());
            Ok(0)
        }
        Err(error) => {
            println!("错误: HTTP {}: {}", error.status, error.message);
            Ok(1)
        }
    }
}

fn report(bytes: &[u8], raw: bool) -> Result<()> {
    let stdout = std::io::stdout();
    let mut stdout = stdout.lock();
    if raw {
        stdout.write_all(bytes)?;
    } else {
        let value = serde_json::from_slice::<serde_json::Value>(bytes);
        match value {
            Ok(value) => {
                serde_json::to_writer_pretty(&mut stdout, &value)?;
                stdout.write_all(b"\n")?;
            }
            Err(_) => stdout.write_all(bytes)?,
        }
    }
    stdout.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_outside_the_api_are_rejected() {
        assert!(validate_path("/api/ddns").is_ok());
        assert!(validate_path("/api").is_ok());
        assert!(validate_path("/other/ddns").is_err());
        assert!(validate_path("api/ddns").is_err());
    }

    #[test]
    fn bodies_must_be_valid_json() {
        assert!(read_body(r#"{"a":1}"#).is_ok());
        assert!(read_body("[1,2,3]").is_ok());
        assert!(read_body("not json").is_err());
        let directory = tempfile::tempdir().expect("temp directory");
        let file = directory.path().join("body.json");
        std::fs::write(&file, r#"{"from":"file"}"#).expect("seed body file");
        assert!(read_body(&format!("@{}", file.display())).is_ok());
        let missing = directory.path().join("absent.json");
        assert!(read_body(&format!("@{}", missing.display())).is_err());
    }
}

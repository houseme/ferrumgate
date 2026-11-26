//! MCP tool generation from an instance's OpenAPI document.

use hyper::Method;
use serde_json::{Value, json};

const MAX_NAME: usize = 64;
const TRUNCATE: usize = 200_000;

#[derive(Clone, Debug)]
pub struct Tool {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
    pub read_only: bool,
    pub destructive: bool,
    pub method: Method,
    pub path: String,
}

/// Builds one tool per token-accessible operation. Without `write_enabled`
/// only `GET` / `HEAD` operations are exposed and paths containing
/// `secrets` never appear.
pub fn build_tools(document: &Value, write_enabled: bool) -> Vec<Tool> {
    let mut tools = Vec::new();
    let Some(paths) = document["paths"].as_object() else {
        return tools;
    };
    for (path, methods) in paths {
        let Some(methods) = methods.as_object() else {
            continue;
        };
        for (verb, operation) in methods {
            if operation["x-token-allowed"].as_bool() != Some(true) {
                continue;
            }
            let Ok(method) = Method::from_bytes(verb.to_ascii_uppercase().as_bytes()) else {
                continue;
            };
            let read_only = matches!(method, Method::GET | Method::HEAD);
            if !write_enabled && !read_only {
                continue;
            }
            if path.contains("secrets") {
                continue;
            }
            tools.push(Tool {
                name: String::new(),
                description: describe(operation, verb, path),
                input_schema: schema_for(operation, &method),
                read_only,
                destructive: method == Method::DELETE,
                method,
                path: path.clone(),
            });
        }
    }
    assign_names(&mut tools);
    tools.sort_by(|a, b| a.name.cmp(&b.name));
    tools
}

fn describe(operation: &Value, verb: &str, path: &str) -> String {
    let summary = operation["summary"].as_str().unwrap_or_default();
    let scope = operation["x-required-scope"]
        .as_str()
        .unwrap_or("any token");
    format!("{summary} [{verb} {path}, requires {scope}]")
}

/// Path parameters become required strings; GET tools get an optional
/// `query` object; operations with a request body get a `body` value.
fn schema_for(operation: &Value, method: &Method) -> Value {
    let mut properties = serde_json::Map::new();
    let mut required = Vec::new();
    for parameter in operation["parameters"].as_array().into_iter().flatten() {
        let Some(name) = parameter["name"].as_str() else {
            continue;
        };
        if parameter["in"] == "path" {
            properties.insert(
                name.to_owned(),
                json!({"type":"string", "description":"路径参数"}),
            );
            required.push(name.to_owned());
        }
    }
    if matches!(*method, Method::GET | Method::HEAD) {
        properties.insert(
            "query".to_owned(),
            json!({"type":"object", "description":"可选的查询参数"}),
        );
    }
    if operation["requestBody"].is_object() {
        properties.insert(
            "body".to_owned(),
            json!({"type":"object", "description":"请求体（JSON 对象）"}),
        );
        required.push("body".to_owned());
    }
    json!({"type":"object", "properties": properties, "required": required})
}

/// Tool names: method plus the path below `/api`, lowercased,
/// non-alphanumerics to `_`, braces dropped, capped at 64 characters,
/// deduplicated with a suffix.
fn assign_names(tools: &mut [Tool]) {
    let mut used: Vec<String> = Vec::new();
    for tool in tools.iter_mut() {
        let mut name = String::new();
        name.push_str(tool.method.as_str().to_ascii_lowercase().as_str());
        for segment in tool.path.split('/') {
            if segment.is_empty() || segment == "api" {
                continue;
            }
            name.push('_');
            for character in segment.trim_matches('{').trim_matches('}').chars() {
                name.push(if character.is_ascii_alphanumeric() {
                    character.to_ascii_lowercase()
                } else {
                    '_'
                });
            }
        }
        name.truncate(MAX_NAME);
        if used.contains(&name) {
            let base = name;
            let mut sequence = 2;
            loop {
                let suffix = format!("_{sequence}");
                let candidate = format!(
                    "{}{}",
                    &base[..MAX_NAME.saturating_sub(suffix.len()).min(base.len())],
                    suffix
                );
                if !used.contains(&candidate) {
                    name = candidate;
                    break;
                }
                sequence += 1;
            }
        }
        used.push(name.clone());
        tool.name = name;
    }
}

/// Truncates oversized results with an explanation.
pub fn truncate(text: &str) -> String {
    if text.chars().count() <= TRUNCATE {
        return text.to_owned();
    }
    let kept: String = text.chars().take(TRUNCATE).collect();
    format!("{kept}\n…（结果超过 200000 个字符，已截断；请缩小查询范围）")
}

/// Fills a tool's path template with arguments, e.g. `{key}` → value.
pub fn fill_path(path: &str, arguments: &Value) -> Result<String, String> {
    let mut filled = String::with_capacity(path.len());
    let mut rest = path;
    while let Some(start) = rest.find('{') {
        let Some(end) = rest[start..].find('}') else {
            return Err(format!("路径模板不完整：{path}"));
        };
        let name = &rest[start + 1..start + end];
        let value = arguments[name]
            .as_str()
            .ok_or_else(|| format!("缺少路径参数 {name}"))?;
        filled.push_str(&rest[..start]);
        filled.push_str(value);
        rest = &rest[start + end + 1..];
    }
    filled.push_str(rest);
    Ok(filled)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn document() -> Value {
        json!({
            "paths": {
                "/api/ddns/tasks": {
                    "get": {"summary": "List tasks", "x-token-allowed": true, "parameters": []},
                    "put": {"summary": "Replace tasks", "x-token-allowed": true,
                            "requestBody": {"content": {}}},
                },
                "/api/ddns/tasks/{key}/enable": {
                    "put": {"summary": "Enable", "x-token-allowed": true, "parameters": [
                        {"name": "key", "in": "path", "required": true}
                    ]},
                },
                "/api/ddns/tasks/{key}/secrets": {
                    "get": {"summary": "Read secret", "x-token-allowed": true},
                },
                "/api/account": {
                    "put": {"summary": "Session only", "x-token-allowed": false},
                },
            }
        })
    }

    #[test]
    fn readonly_default_hides_writes_and_secrets() {
        let document = document();
        let tools = build_tools(&document, false);
        assert!(tools.iter().all(|tool| tool.read_only));
        assert!(!tools.iter().any(|tool| tool.path.contains("secrets")));
        let writable = build_tools(&document, true);
        assert!(
            writable
                .iter()
                .any(|tool| !tool.read_only && tool.method == Method::PUT)
        );
        // The session-only operation never appears in either mode.
        for tool in build_tools(&document, true) {
            assert_ne!(tool.path, "/api/account");
        }
    }

    #[test]
    fn names_skip_the_api_segment_and_flatten_parameters() {
        let document = document();
        let tools = build_tools(&document, true);
        let names: Vec<_> = tools.iter().map(|tool| tool.name.as_str()).collect();
        assert!(names.contains(&"get_ddns_tasks"));
        assert!(names.contains(&"put_ddns_tasks_key_enable"), "{names:?}");
        for name in names {
            assert!(name.len() <= 64, "{name}");
        }
    }

    #[test]
    fn duplicate_names_get_a_numeric_suffix() {
        let document = json!({
            "paths": {
                "/api/ddns/a-b": {"get": {"x-token-allowed": true}},
                "/api/ddns/a_b": {"get": {"x-token-allowed": true}},
            }
        });
        let tools = build_tools(&document, false);
        let names: Vec<_> = tools.iter().map(|tool| tool.name.as_str()).collect();
        assert_eq!(names.len(), 2);
        assert_ne!(names[0], names[1], "collisions are deduplicated: {names:?}");
    }

    #[test]
    fn long_paths_are_capped_at_sixty_four_characters() {
        let long = format!("/api/ddns/{}", "x".repeat(120));
        let document = json!({"paths": {long.clone(): {"get": {"x-token-allowed": true}}}});
        let tools = build_tools(&document, false);
        assert!(tools[0].name.len() <= 64);
    }

    #[test]
    fn results_over_two_hundred_thousand_characters_are_truncated() {
        let text = "字".repeat(200_001);
        let truncated = truncate(&text);
        assert!(
            (200_000..200_060).contains(&truncated.chars().count()),
            "kept text plus the explanation note"
        );
        assert!(truncated.contains("已截断"));
        assert_eq!(truncate("short"), "short");
    }

    #[test]
    fn fill_path_requires_string_arguments() {
        let arguments = json!({"key": "abc"});
        assert_eq!(
            fill_path("/api/ddns/tasks/{key}/enable", &arguments).unwrap(),
            "/api/ddns/tasks/abc/enable"
        );
        let missing = json!({});
        assert!(fill_path("/api/ddns/tasks/{key}", &missing).is_err());
        let numeric = json!({"key": 7});
        assert!(fill_path("/api/ddns/tasks/{key}", &numeric).is_err());
    }

    #[test]
    fn path_parameters_are_required_and_bodies_optional_objects() {
        let tools = build_tools(&document(), true);
        let enable = tools
            .iter()
            .find(|tool| tool.name == "put_ddns_tasks_key_enable")
            .unwrap();
        assert_eq!(enable.input_schema["required"], json!(["key"]));
        let replace = tools
            .iter()
            .find(|tool| tool.name == "put_ddns_tasks")
            .unwrap();
        assert!(replace.input_schema["properties"]["body"].is_object());
    }
}

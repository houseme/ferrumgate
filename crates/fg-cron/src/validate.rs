//! Normalization and validation for the cron model (WP-62): pure functions
//! over plain data. `normalize` applies defaults (`timeout: 0` on HTTP
//! tasks) and drops stray fields; `validate` collects every problem instead
//! of stopping at the first, reusing the schedule parser for `spec`.

use crate::model::{FileConfig, HttpTask, TaskKind, limits};
use crate::schedule;

/// HTTP methods an HTTP task may use (WP-62 §3.3).
const HTTP_METHODS: [&str; 5] = ["GET", "POST", "PUT", "PATCH", "DELETE"];

/// A collected validation problem: the offending field path and reason.
#[derive(Debug, PartialEq, Eq)]
pub struct Problem {
    pub field: String,
    pub reason: String,
}

impl Problem {
    fn new(field: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            reason: reason.into(),
        }
    }
}

/// Applies defaults and trims user-entered text: HTTP timeouts normalize to
/// [`limits::HTTP_TIMEOUT_DEFAULT`] and clamp to [`limits::HTTP_TIMEOUT_MAX`];
/// a `command` task drops a stray `http` block.
pub fn normalize(mut config: FileConfig) -> FileConfig {
    for task in &mut config.tasks {
        task.key = task.key.trim().to_owned();
        task.name = task.name.trim().to_owned();
        task.group = task.group.trim().to_owned();
        task.spec = task.spec.trim().to_owned();
        task.command = task.command.trim().to_owned();
        task.remark = task.remark.trim().to_owned();
        match (&mut task.http, task.kind) {
            (Some(http), TaskKind::Http) => normalize_http(http),
            (http, TaskKind::Command) => *http = None,
            (None, TaskKind::Http) => {}
        }
    }
    config
}

fn normalize_http(http: &mut HttpTask) {
    http.url = http.url.trim().to_owned();
    http.method = http.method.trim().to_ascii_uppercase();
    http.body = http.body.clone();
    http.headers = http
        .headers
        .iter()
        .map(|header| header.trim().to_owned())
        .filter(|header| !header.is_empty())
        .collect();
    http.success_content = http
        .success_content
        .iter()
        .map(|needle| needle.trim().to_owned())
        .filter(|needle| !needle.is_empty())
        .collect();
    if http.timeout == 0 {
        http.timeout = limits::HTTP_TIMEOUT_DEFAULT;
    }
    http.timeout = http.timeout.min(limits::HTTP_TIMEOUT_MAX);
}

/// Validates a normalized config, collecting every problem.
pub fn validate(config: &FileConfig) -> Vec<Problem> {
    let mut problems = Vec::new();
    let mut keys = std::collections::BTreeSet::new();
    for task in &config.tasks {
        let prefix = if task.key.is_empty() {
            format!("tasks.{}", task.name)
        } else {
            format!("tasks.{}", task.key)
        };
        if task.key.is_empty() {
            problems.push(Problem::new("key", "key 不能为空"));
        } else if !keys.insert(task.key.as_str()) {
            problems.push(Problem::new("key", format!("重复的 key {}", task.key)));
        }
        if task.name.is_empty() {
            problems.push(Problem::new(format!("{prefix}.name"), "名称不能为空"));
        } else if task.name.chars().count() > limits::NAME_MAX_CHARS {
            problems.push(Problem::new(
                format!("{prefix}.name"),
                format!("名称最多 {} 个字符", limits::NAME_MAX_CHARS),
            ));
        }
        if task.group.chars().count() > limits::GROUP_MAX_CHARS {
            problems.push(Problem::new(
                format!("{prefix}.group"),
                format!("分组最多 {} 个字符", limits::GROUP_MAX_CHARS),
            ));
        }
        if task.remark.chars().count() > limits::REMARK_MAX_CHARS {
            problems.push(Problem::new(
                format!("{prefix}.remark"),
                format!("备注最多 {} 个字符", limits::REMARK_MAX_CHARS),
            ));
        }
        match schedule::parse(&task.spec) {
            Ok(_) => {}
            Err(error) => problems.push(Problem::new(format!("{prefix}.spec"), error.0)),
        }
        match task.kind {
            TaskKind::Command => {
                if task.command.is_empty() {
                    problems.push(Problem::new(format!("{prefix}.command"), "命令不能为空"));
                }
            }
            TaskKind::Http => {
                let Some(http) = &task.http else {
                    problems.push(Problem::new(
                        format!("{prefix}.http"),
                        "HTTP 任务需要填写请求配置",
                    ));
                    continue;
                };
                validate_http(&prefix, http, &mut problems);
            }
        }
    }
    problems
}

fn validate_http(prefix: &str, http: &HttpTask, problems: &mut Vec<Problem>) {
    let url_ok = http.url.starts_with("http://") || http.url.starts_with("https://");
    if !url_ok {
        problems.push(Problem::new(
            format!("{prefix}.http.url"),
            "URL 需以 http:// 或 https:// 开头",
        ));
    }
    if !HTTP_METHODS.contains(&http.method.as_str()) {
        problems.push(Problem::new(
            format!("{prefix}.http.method"),
            format!("方法只支持 {}", HTTP_METHODS.join(" / ")),
        ));
    }
    if http.headers.len() > limits::HTTP_HEADERS_MAX {
        problems.push(Problem::new(
            format!("{prefix}.http.headers"),
            format!("请求头最多 {} 条", limits::HTTP_HEADERS_MAX),
        ));
    }
    for header in &http.headers {
        if parse_header(header).is_none() {
            problems.push(Problem::new(
                format!("{prefix}.http.headers"),
                format!("请求头需为 \"名称: 值\"：{header}"),
            ));
        }
    }
}

/// Splits a raw `Key: Value` header line.
pub fn parse_header(header: &str) -> Option<(String, String)> {
    let (name, value) = header.split_once(':')?;
    let name = name.trim();
    if name.is_empty() || name.contains(char::is_whitespace) {
        return None;
    }
    Some((name.to_owned(), value.trim().to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Task;

    fn base_task() -> Task {
        Task {
            key: "abc123".into(),
            name: "backup".into(),
            spec: "@daily".into(),
            kind: TaskKind::Command,
            command: "echo hi".into(),
            ..Task::default()
        }
    }

    #[test]
    fn valid_config_has_no_problems() {
        let config = normalize(FileConfig {
            tasks: vec![base_task()],
        });
        assert!(validate(&config).is_empty());
    }

    #[test]
    fn normalize_applies_timeout_default_and_clamp() {
        let mut task = base_task();
        task.kind = TaskKind::Http;
        task.http = Some(HttpTask {
            url: " https://example.com ".into(),
            method: " get ".into(),
            headers: vec![" A: b ".into(), "".into()],
            timeout: 0,
            ..HttpTask::default()
        });
        let config = normalize(FileConfig { tasks: vec![task] });
        let http = config.tasks[0].http.as_ref().expect("kept");
        assert_eq!(http.timeout, limits::HTTP_TIMEOUT_DEFAULT);
        assert_eq!(http.url, "https://example.com");
        assert_eq!(http.method, "GET");
        assert_eq!(http.headers, ["A: b"]);
        let config = normalize(FileConfig {
            tasks: vec![Task {
                kind: TaskKind::Http,
                http: Some(HttpTask {
                    timeout: 100_000,
                    ..HttpTask::default()
                }),
                ..base_task()
            }],
        });
        assert_eq!(
            config.tasks[0].http.as_ref().expect("kept").timeout,
            limits::HTTP_TIMEOUT_MAX
        );
    }

    #[test]
    fn command_task_drops_stray_http_block() {
        let mut task = base_task();
        task.http = Some(HttpTask::default());
        let config = normalize(FileConfig { tasks: vec![task] });
        assert!(config.tasks[0].http.is_none());
    }

    #[test]
    fn problems_collected_for_every_broken_field() {
        let mut task = base_task();
        task.name = String::new();
        task.spec = "nope".into();
        task.command = String::new();
        let config = normalize(FileConfig { tasks: vec![task] });
        let fields: Vec<_> = validate(&config)
            .into_iter()
            .map(|problem| problem.field)
            .collect();
        assert!(fields.iter().any(|f| f.ends_with(".name")), "{fields:?}");
        assert!(fields.iter().any(|f| f.ends_with(".spec")), "{fields:?}");
        assert!(fields.iter().any(|f| f.ends_with(".command")), "{fields:?}");
    }

    #[test]
    fn http_task_needs_url_method_and_headers() {
        let mut task = base_task();
        task.kind = TaskKind::Http;
        task.http = Some(HttpTask {
            url: "ftp://example.com".into(),
            method: "TRACE".into(),
            headers: vec!["broken".into()],
            ..HttpTask::default()
        });
        let config = normalize(FileConfig { tasks: vec![task] });
        let problems = validate(&config);
        let text = format!("{problems:?}");
        assert!(text.contains("URL 需以"), "{problems:?}");
        assert!(text.contains("方法只支持"), "{problems:?}");
        assert!(text.contains("请求头需为"), "{problems:?}");
    }

    #[test]
    fn duplicate_keys_are_collected() {
        let config = normalize(FileConfig {
            tasks: vec![base_task(), base_task()],
        });
        let problems = validate(&config);
        assert!(problems.iter().any(|problem| problem.field == "key"));
    }

    #[test]
    fn header_parsing_requires_name() {
        assert_eq!(
            parse_header("X-Token: abc"),
            Some(("X-Token".into(), "abc".into()))
        );
        assert_eq!(parse_header(":v"), None);
        assert_eq!(parse_header("no colon"), None);
    }
}

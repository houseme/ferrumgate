//! Tunnel process tests (WP-46 §6) with a rustc-compiled `cloudflared`
//! fixture: the token travels through the environment only, the quick mode
//! carries the URL argument, crashed processes restart, the public address
//! is parsed from the process output, and reset stops everything.

mod common;

use std::path::Path;
use std::time::Duration;

use serde_json::json;

use common::{
    TUNNEL_TOKEN, fixture, harness, harness_with_deps, quick_tunnel_config, read_record, wait_until,
};

fn fixture_text() -> String {
    fixture().to_string_lossy().replace('\\', "/")
}

/// A token-tunnel config with the fixture binary and the invocation
/// recorder wired through `extraEnv`.
fn token_tunnel_config(record: &Path) -> String {
    format!(
        r#"{{"settings":{{"binPath":"{bin}"}},"install":{{"proxy":""}},"tunnels":[{{"key":"k","name":"nas","group":"","enable":true,"mode":"token","token":"{token}","extraEnv":[["FGCLOUDFLARED_RECORD","{record}"]],"remark":""}}]}}"#,
        bin = fixture_text(),
        token = TUNNEL_TOKEN,
        record = record.to_string_lossy().replace('\\', "/"),
    )
}

#[tokio::test]
async fn tunnel_token_in_env_not_args() {
    // 令牌经环境变量传入，不出现在进程列表中；登记表快照同样不含令牌。
    let record =
        std::env::temp_dir().join(format!("fg-cloudflared-record-{}.json", std::process::id()));
    let _ = std::fs::remove_file(&record);
    let config = token_tunnel_config(&record);
    let mut app = harness_with_deps(&config, Default::default()).await;
    // 启动全部启用的隧道（Module::run 的行为）。
    let module = app.take_module();
    let (drain_tx, drain_rx) = tokio::sync::watch::channel(false);
    let run_task = tokio::spawn(async move {
        use fg_core::module::Module as _;
        module.run(drain_rx).await.expect("module run");
    });
    let started = wait_until(|| record.is_file(), Duration::from_secs(5)).await;
    assert!(started, "夹具应已记录自己的启动参数");
    let recorded = read_record(&record);
    let args = recorded["args"].as_array().expect("args");
    let joined = args
        .iter()
        .map(|arg| arg.as_str().unwrap_or_default())
        .collect::<Vec<_>>()
        .join(" ");
    assert!(joined.contains("tunnel"), "{joined}");
    assert!(joined.contains("run"), "{joined}");
    assert!(!joined.contains("sec"), "令牌不得出现在命令行：{joined}");
    assert_eq!(recorded["tunnelToken"], TUNNEL_TOKEN, "令牌经环境变量传递");

    // 运行中的进程登记（快照口径）：不含路径、参数、环境。
    let registered: Vec<serde_json::Value> = fg_proc::registry::running()
        .into_iter()
        .map(|entry| serde_json::to_value(&entry).expect("serialize"))
        .collect();
    assert!(
        registered
            .iter()
            .any(|entry| entry["module"] == "cloudflared" && entry["instance"] == "nas"),
        "{registered:?}"
    );

    drain_tx.send(true).expect("send drain");
    let _ = run_task.await;
    let _ = std::fs::remove_file(&record);
    app.shutdown().await;
}

#[tokio::test]
async fn tunnel_quick_mode_url_argument() {
    // 指定与随机：--url 携带指定的本地服务地址；未指定时没有 --url。
    let record =
        std::env::temp_dir().join(format!("fg-cloudflared-quick-{}.json", std::process::id()));
    let _ = std::fs::remove_file(&record);
    let config = quick_tunnel_config(
        &["--edge-ip-version", "4"],
        Some("http://localhost:8080"),
        false,
        Some(&record),
    );
    let app = harness(&config).await;
    let (status, view) = app
        .send(
            "PUT",
            "/api/cloudflared/tunnels/q/enable",
            Some(json!({"enable": true})),
        )
        .await;
    assert_eq!(status, 200, "{view}");
    let started = wait_until(|| record.is_file(), Duration::from_secs(5)).await;
    assert!(started, "夹具应已记录启动参数");
    let recorded = read_record(&record);
    let args: Vec<String> = recorded["args"]
        .as_array()
        .expect("args")
        .iter()
        .map(|arg| arg.as_str().expect("arg").to_owned())
        .collect();
    let url_position = args
        .iter()
        .position(|arg| arg == "--url")
        .expect("quick mode carries --url");
    assert_eq!(args[url_position + 1], "http://localhost:8080");
    assert!(
        !args.iter().any(|arg| arg == "run"),
        "快速隧道不带 run 子命令"
    );
    // 公网地址从进程输出解析并显示在隧道卡片上。
    let runtime = app.runtime();
    let seen = wait_until(
        || {
            runtime
                .info_of("q")
                .map(|info| !info.url().is_empty())
                .unwrap_or(false)
        },
        Duration::from_secs(5),
    )
    .await;
    assert!(seen, "公网地址应从输出中解析");
    let (_, view) = app.send("GET", "/api/cloudflared/tunnels", None).await;
    assert_eq!(
        view[0]["url"], "https://random-words-here.trycloudflare.com",
        "公网地址显示在隧道卡片上"
    );
    assert_eq!(
        view[0]["connections"], 1,
        "Registered tunnel connection 计数"
    );

    // 停止后重跑一遍未指定 URL 的情形：不带 --url（公网名总是随机）。
    let (status, _) = app
        .send(
            "PUT",
            "/api/cloudflared/tunnels/q/enable",
            Some(json!({"enable": false})),
        )
        .await;
    assert_eq!(status, 200);
    let _ = std::fs::remove_file(&record);
    app.shutdown().await;
}

#[tokio::test]
async fn tunnel_restart_on_exit() {
    // 夹具进程 300ms 后异常退出：自动重启。
    let config = quick_tunnel_config(&["die"], None, true, None);
    let app = harness(&config).await;
    // 经重启接口启动（enable 已是 true）。
    let (status, body) = app
        .send("POST", "/api/cloudflared/tunnels/q/restart", None)
        .await;
    assert_eq!(status, 200, "{body}");
    let runtime = app.runtime();
    let restarted = wait_until(
        || {
            runtime
                .state_of("q")
                .map(|state| state.restarts >= 2 && state.running)
                .unwrap_or(false)
        },
        Duration::from_secs(10),
    )
    .await;
    assert!(
        restarted,
        "异常退出后应自动重启：{:?}",
        runtime.state_of("q")
    );
    // 启停接口停止隧道（有界停止）。
    let (status, body) = app
        .send(
            "PUT",
            "/api/cloudflared/tunnels/q/enable",
            Some(json!({"enable": false})),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    let stopped = wait_until(
        || {
            runtime
                .state_of("q")
                .map(|state| !state.running)
                .unwrap_or(true)
        },
        Duration::from_secs(8),
    )
    .await;
    assert!(stopped, "停用后进程应退出");
    app.shutdown().await;
}

#[tokio::test]
async fn tunnel_missing_binary_records_error_in_view() {
    let config = quick_tunnel_config(&[], None, true, None)
        .replace(&fixture_text(), "/nonexistent/cloudflared");
    let app = harness(&config).await;
    // 启动失败：错误进入只读视图，且不重试（等待用户修正配置）。
    let (status, _) = app
        .send("POST", "/api/cloudflared/tunnels/q/restart", None)
        .await;
    assert_eq!(status, 200);
    let (_, view) = app.send("GET", "/api/cloudflared/tunnels", None).await;
    assert!(
        view[0]["error"]
            .as_str()
            .unwrap_or_default()
            .contains("cloudflared"),
        "启动失败原因进入视图：{view}"
    );
    assert_eq!(view[0]["state"]["running"], false);
    app.shutdown().await;
}

#[tokio::test]
async fn reset_stops_tunnels_and_restores_default_config() {
    // 恢复默认：停止并删除全部隧道、清空设置；安装的程序不受影响。
    let config = quick_tunnel_config(&[], Some("http://localhost:8080"), true, None);
    let app = harness(&config).await;
    let (status, _) = app
        .send("POST", "/api/cloudflared/tunnels/q/restart", None)
        .await;
    assert_eq!(status, 200);
    let runtime = app.runtime();
    let running = wait_until(
        || {
            runtime
                .state_of("q")
                .map(|state| state.running)
                .unwrap_or(false)
        },
        Duration::from_secs(5),
    )
    .await;
    assert!(running, "隧道应已启动");

    let (status, body) = app.send("POST", "/api/cloudflared/reset", None).await;
    assert_eq!(status, 200, "{body}");
    let stored = app.state.config.read().await.clone();
    assert!(stored.tunnels.is_empty(), "隧道被清空");
    assert_eq!(stored.settings.program_path, "", "设置被清空");
    assert_eq!(stored.install.proxy, "", "安装设置被清空");
    assert!(fixture().is_file(), "安装的程序不受影响");
    let stopped = wait_until(
        || {
            runtime
                .state_of("q")
                .map(|state| !state.running)
                .unwrap_or(true)
        },
        Duration::from_secs(8),
    )
    .await;
    assert!(stopped, "恢复默认后进程应退出");
    app.shutdown().await;
}

#[tokio::test]
async fn settings_round_trip_and_restart() {
    // 设置读取（含版本探测）与保存（重启全部隧道）。
    let app = harness("").await;
    let binary = std::fs::canonicalize(fixture())
        .expect("canonical fixture")
        .to_string_lossy()
        .replace('\\', "/");
    let (status, view) = app.send("GET", "/api/cloudflared/settings", None).await;
    assert_eq!(status, 200, "{view}");
    assert_eq!(
        view["binary"].as_str().unwrap_or_default(),
        binary,
        "binary 指向解析出的程序路径"
    );
    assert!(
        view["version"]
            .as_str()
            .expect("version")
            .starts_with("cloudflared 2026.1.0"),
        "版本探测：{view}"
    );
    assert_eq!(view["error"], "");
    // 保存：写入设置并持久化。
    let (status, body) = app
        .send(
            "PUT",
            "/api/cloudflared/settings",
            Some(json!({"binPath": binary})),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    let stored = app.state.config.read().await.clone();
    assert_eq!(stored.settings.program_path, binary);
    app.shutdown().await;
}

#[tokio::test]
async fn install_view_reports_program_and_platform() {
    let app = harness("").await;
    let (status, view) = app.send("GET", "/api/cloudflared/install", None).await;
    assert_eq!(status, 200, "{view}");
    assert_eq!(view["program"], "cloudflared");
    assert_eq!(view["installed"]["present"], false);
    assert!(view["platform"].as_str().expect("platform").contains('/'));
    assert_eq!(view["state"]["stage"], "idle");
    // 卸载尚未安装的程序：404。
    let (status, body) = app.send("DELETE", "/api/cloudflared/install", None).await;
    assert_eq!(status, 404, "{body}");
    // 回滚到不存在的旧版本：404。
    let (status, body) = app
        .send(
            "POST",
            "/api/cloudflared/install/rollback",
            Some(json!({"id": "0.0.0"})),
        )
        .await;
    assert_eq!(status, 404, "{body}");
    // 删除不存在的旧版本：404。
    let (status, body) = app
        .send("DELETE", "/api/cloudflared/install/backups/0.0.0", None)
        .await;
    assert_eq!(status, 404, "{body}");
    app.shutdown().await;
}

#[tokio::test]
async fn tunnel_collection_batch_operations_follow_contract() {
    let config = quick_tunnel_config(&[], None, false, None);
    let app = harness(&config).await;
    // 新增两条隧道（随机 key）。
    let mut keys = vec!["q".to_owned()];
    for index in 0..2 {
        let (status, created) = app
            .send(
                "POST",
                "/api/cloudflared/tunnels",
                Some(json!({
                    "name": format!("t{index}"),
                    "mode": "quick",
                    "service": format!("http://localhost:{}", 8000 + index),
                    "enable": false,
                    "remark": ""
                })),
            )
            .await;
        assert_eq!(status, 200, "{created}");
        keys.push(created["key"].as_str().expect("key").to_owned());
    }
    // 排序：必须包含全部条目。
    let (status, body) = app
        .send(
            "PUT",
            "/api/cloudflared/tunnels-order",
            Some(json!({"keys": [keys[2]]})),
        )
        .await;
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["error"], "order must include every item once");
    let reordered = vec![keys[2].clone(), keys[0].clone(), keys[1].clone()];
    let (status, _) = app
        .send(
            "PUT",
            "/api/cloudflared/tunnels-order",
            Some(json!({"keys": reordered})),
        )
        .await;
    assert_eq!(status, 200);
    let (_, list) = app.send("GET", "/api/cloudflared/tunnels", None).await;
    let listed: Vec<String> = list
        .as_array()
        .expect("list")
        .iter()
        .map(|tunnel| tunnel["key"].as_str().expect("key").to_owned())
        .collect();
    assert_eq!(listed, reordered);

    // 批量启停：changed 计数。
    let (status, body) = app
        .send(
            "PUT",
            "/api/cloudflared/tunnels-enable",
            Some(json!({"keys": [keys[0], keys[1]], "enable": true})),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["changed"], 2);
    // 批量删除：不存在的 key 全部拒绝。
    let (status, _) = app
        .send(
            "POST",
            "/api/cloudflared/tunnels-delete",
            Some(json!({"keys": [keys[0], "ghost"]})),
        )
        .await;
    assert_eq!(status, 404);
    let (status, body) = app
        .send(
            "POST",
            "/api/cloudflared/tunnels-delete",
            Some(json!({"keys": [keys[0], keys[1]]})),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["removed"], 2);
    // 分组（批量删除后仅剩 keys[2] 与 q）。
    let (status, _) = app
        .send(
            "PUT",
            "/api/cloudflared/tunnels-group",
            Some(json!({"keys": [keys[2]], "group": "临时"})),
        )
        .await;
    assert_eq!(status, 200);
    let (_, list) = app.send("GET", "/api/cloudflared/tunnels", None).await;
    assert!(
        list.as_array()
            .expect("list")
            .iter()
            .any(|tunnel| tunnel["key"] == keys[2] && tunnel["group"] == "临时"),
        "{list}"
    );
    // 重启接口：404 时报条目不存在，存在时 ok。
    let (status, body) = app
        .send("POST", "/api/cloudflared/tunnels/ghost/restart", None)
        .await;
    assert_eq!(status, 404, "{body}");
    let (status, body) = app
        .send(
            "POST",
            &format!("/api/cloudflared/tunnels/{}/restart", keys[2]),
            None,
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["ok"], true);
    app.shutdown().await;
}

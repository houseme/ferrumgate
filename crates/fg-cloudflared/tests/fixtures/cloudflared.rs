//! Small executable fixture standing in for the official `cloudflared`
//! (conventions §4: Rust fixtures, no shell scripts). Compiled with rustc
//! by the test harness; see `tests/common/mod.rs`.
//!
//! Behavior:
//! - When `FGCLOUDFLARED_RECORD` is set, records the process arguments and
//!   the `TUNNEL_TOKEN` environment value to that file as JSON, so tests
//!   can assert the token travels through the environment only.
//! - `--version` (anywhere in argv) prints a version banner (the probe
//!   takes the first line).
//! - `die` anywhere in argv: sleep 300 ms, then exit 1 — exercises the
//!   auto-restart backoff.
//! - `--url …` in argv (quick tunnel): prints a trycloudflare public
//!   address line and a registered-connection line, then idles.
//! - Otherwise (token tunnel): prints a registered-connection line and
//!   idles until stopped.

use std::{env, process, thread, time::Duration};

fn json_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            _ => out.push(c),
        }
    }
    out
}

fn record(path: &str, args: &[String], token: &str) {
    let mut body = String::from("{\"args\":[");
    for (index, arg) in args.iter().enumerate() {
        if index > 0 {
            body.push(',');
        }
        body.push('"');
        body.push_str(&json_escape(arg));
        body.push('"');
    }
    body.push_str("],\"tunnelToken\":\"");
    body.push_str(&json_escape(token));
    body.push_str("\"}");
    let _ = std::fs::write(path, body);
}

fn idle() {
    thread::sleep(Duration::from_secs(60));
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let token = env::var("TUNNEL_TOKEN").unwrap_or_default();
    if let Ok(path) = env::var("FGCLOUDFLARED_RECORD") {
        record(&path, &args, &token);
    }
    if args.iter().any(|arg| arg == "--version") {
        println!("cloudflared 2026.1.0 (fixture)");
        return;
    }
    if args.iter().any(|arg| arg == "die") {
        thread::sleep(Duration::from_millis(300));
        process::exit(1);
    }
    if args.iter().any(|arg| arg == "--url") {
        println!("INF |  https://random-words-here.trycloudflare.com  |");
        println!("INF Registered tunnel connection connIndex=0");
        idle();
        return;
    }
    println!("INF Registered tunnel connection connIndex=0");
    idle();
}

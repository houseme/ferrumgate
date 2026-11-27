//! Small executable fixture standing in for external commands
//! (conventions §4: Rust fixtures, no shell scripts). Compiled with rustc
//! by the test harness; see `tests/common/mod.rs`.
//!
//! Subcommands:
//! - `env`                       print taskName / FERRUMGATE_TASKNAME values
//! - `sleep <seconds>`           sleep, then print `done`
//! - `emit <bytes>`              print that many `x` characters
//! - `exit <code>`               exit with the code

use std::{env, process, thread, time::Duration};

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("env") => {
            println!("taskName={}", env::var("taskName").unwrap_or_default());
            println!(
                "prefixed={}",
                env::var("FERRUMGATE_TASKNAME").unwrap_or_default()
            );
        }
        Some("sleep") => {
            let seconds: u64 = args
                .get(1)
                .and_then(|value| value.parse().ok())
                .unwrap_or(1);
            thread::sleep(Duration::from_secs(seconds));
            println!("done after {seconds}s");
        }
        Some("emit") => {
            let bytes: usize = args
                .get(1)
                .and_then(|value| value.parse().ok())
                .unwrap_or(0);
            let chunk = "x".repeat(4096);
            let mut out = String::new();
            while out.len() < bytes {
                out.push_str(&chunk);
            }
            out.truncate(bytes);
            println!("{out}");
        }
        Some("exit") => {
            let code: i32 = args
                .get(1)
                .and_then(|value| value.parse().ok())
                .unwrap_or(0);
            process::exit(code);
        }
        _ => {
            eprintln!("usage: fixture env|sleep <s>|emit <n>|exit <code>");
            process::exit(2);
        }
    }
}

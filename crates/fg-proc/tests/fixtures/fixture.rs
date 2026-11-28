//! Small executable fixture standing in for the managed programs
//! (conventions §4: Rust fixtures, no shell scripts). Compiled with rustc
//! by the test harness; see `tests/common/mod.rs`.
//!
//! Subcommands:
//! - `sleep <seconds>`     sleep, then print `done after Ns`
//! - `die <milliseconds>`  sleep, then exit with code 1 (crash with a
//!                         configurable lifetime so restart windows are
//!                         observable)
//! - `exit <code>`         exit with the code
//! - `echo <text>`         print the text to stdout
//! - `err <text>`          print the text to stderr
//! - `version`             print a two-line version banner (probe takes the first)
//! - `noisy`               print a colored / timestamped error line to stdout
//!                         and a login-URL line to stderr
//! - `ignoreterm <sec>`    ignore SIGTERM (unix), sleep, then exit 0 —
//!                         exercises the graceful-stop grace period

use std::{env, process, thread, time::Duration};

#[cfg(unix)]
extern "C" {
    fn signal(signum: i32, handler: usize) -> usize;
}

const SIGTERM: i32 = 15;
const SIG_IGN: usize = 1;

fn seconds_arg(args: &[String], default: u64) -> u64 {
    args.get(1).and_then(|value| value.parse().ok()).unwrap_or(default)
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("sleep") => {
            let seconds = seconds_arg(&args, 1);
            thread::sleep(Duration::from_secs(seconds));
            println!("done after {seconds}s");
        }
        Some("die") => {
            let millis: u64 = args
                .get(1)
                .and_then(|value| value.parse().ok())
                .unwrap_or(0);
            thread::sleep(Duration::from_millis(millis));
            process::exit(1);
        }
        Some("exit") => {
            let code = args.get(1).and_then(|value| value.parse().ok()).unwrap_or(0);
            process::exit(code);
        }
        Some("echo") => {
            println!("{}", args.get(1).cloned().unwrap_or_default());
        }
        Some("err") => {
            eprintln!("{}", args.get(1).cloned().unwrap_or_default());
        }
        Some("version") => {
            println!("fakeprog 1.2.3");
            println!("fixture build for tests");
        }
        Some("noisy") => {
            // 颜色码 + 回车 + 时间戳 + frp 风格级别，外加一个带一次性令牌
            // 的登录链接（打码口径验证）。
            println!("\u{1b}[31m2026-01-02 03:04:05 [E] connection refused\u{1b}[0m\r");
            eprintln!("login at https://login.tailscale.com/a/token123?x=1 done");
        }
        Some("ignoreterm") => {
            let seconds = seconds_arg(&args, 30);
            #[cfg(unix)]
            {
                // 忽略 SIGTERM：优雅停止必须走到宽限超时后的强制结束。
                // 这个 crate 是独立的测试夹具，不受 fg-proc 的
                // forbid(unsafe_code) 约束。
                unsafe {
                    signal(SIGTERM, SIG_IGN);
                }
            }
            thread::sleep(Duration::from_secs(seconds));
            println!("ignoreterm finished");
        }
        _ => {
            eprintln!("usage: fixture sleep <s>|exit <code>|echo <text>|err <text>|version|noisy|ignoreterm <s>");
            process::exit(2);
        }
    }
}

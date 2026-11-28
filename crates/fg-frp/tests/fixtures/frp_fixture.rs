//! Small executable fixture standing in for `frpc` / `frps` (conventions
//! §4: Rust fixtures, no shell scripts). Compiled with rustc by the test
//! harness; see `tests/common/mod.rs`.
//!
//! Behavior mirroring the real programs:
//! - `-v` / `--version`  print a version line and exit 0 (fg-proc probe)
//! - `-c <file>`         read the rendered config file (a missing or
//!                       key-less file exits 2), then stay alive until
//!                       terminated — like a connected frpc / serving frps

use std::{env, process, thread, time::Duration};

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("-v") | Some("--version") => {
            println!("1.2.3-fixture");
        }
        Some("-c") => {
            let Some(path) = args.get(1) else {
                eprintln!("usage: frp-fixture -c <config>");
                process::exit(2);
            };
            match std::fs::read_to_string(path) {
                Ok(content) => {
                    let looks_client = content.contains("serverAddr");
                    let looks_server = content.contains("bindPort");
                    if !looks_client && !looks_server {
                        eprintln!("config file misses frp root keys");
                        process::exit(2);
                    }
                    // Stay resident: the supervisor owns the lifecycle.
                    loop {
                        thread::sleep(Duration::from_secs(3600));
                    }
                }
                Err(error) => {
                    eprintln!("cannot read config: {error}");
                    process::exit(2);
                }
            }
        }
        _ => {
            eprintln!("usage: frp-fixture -v | -c <config>");
            process::exit(2);
        }
    }
}

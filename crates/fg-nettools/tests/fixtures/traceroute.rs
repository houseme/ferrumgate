//! Small executable fixture standing in for the system `traceroute`
//! (conventions §4: Rust fixtures, no shell scripts). Compiled with rustc
//! by the test harness; see `tests/traceroute.rs`.
//!
//! Modes:
//! - default: print two hops for the last argument (the target)
//! - `--fail`: print nothing on stdout, an error on stderr, exit 1

use std::process;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|argument| argument == "--fail") {
        eprintln!("traceroute: unknown host");
        process::exit(1);
    }
    let target = args.last().cloned().unwrap_or_else(|| "example.test".to_owned());
    println!("traceroute to {target}, 64 hops max");
    println!(" 1  192.0.2.1  0.5 ms");
    println!(" 2  192.0.2.9  1.5 ms");
    process::exit(0);
}

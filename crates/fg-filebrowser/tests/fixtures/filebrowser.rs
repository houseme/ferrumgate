//! rustc-compiled FileBrowser fixture: `--config <path>` reads the config
//! document and serves the listen port until stopped (mirroring the real
//! binary's observable surface for the instance tests). No external
//! crates — the config is scanned textually like Quantum scans its YAML.

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut config_path: Option<String> = None;
    let mut cursor = args.iter();
    while let Some(arg) = cursor.next() {
        if arg == "--config" {
            config_path = cursor.next().cloned();
        }
    }
    let Some(config_path) = config_path else {
        eprintln!("--config is required");
        std::process::exit(2);
    };
    let config = match std::fs::read_to_string(&config_path) {
        Ok(text) => text,
        Err(error) => {
            eprintln!("config unreadable: {error}");
            std::process::exit(3);
        }
    };
    // Expand ${FILEBROWSER_ADMIN_PASSWORD} like Quantum does, then record
    // whether the password arrived through the environment (never the file).
    let password = std::env::var("FILEBROWSER_ADMIN_PASSWORD").unwrap_or_default();
    let expanded = config.replace("${FILEBROWSER_ADMIN_PASSWORD}", &password);
    let port = field_u64(&expanded, "port").unwrap_or(8080);
    let listen = field_str(&expanded, "listen")
        .filter(|listen| !listen.is_empty())
        .unwrap_or_else(|| "0.0.0.0".to_string());
    // Mark readiness by binding the port; the parent probes it.
    let address = format!("{listen}:{port}");
    let listener = match std::net::TcpListener::bind(&address) {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!("bind {address} failed: {error}");
            std::process::exit(4);
        }
    };
    println!("fixture serving {address}");
    for stream in listener.incoming() {
        if let Ok(mut stream) = stream {
            use std::io::Write;
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok");
        }
    }
}

/// Reads `"key": <number>` from the pretty-printed config.
fn field_u64(text: &str, key: &str) -> Option<u64> {
    let needle = format!("\"{key}\": ");
    let start = text.find(&needle)? + needle.len();
    let rest = &text[start..];
    let digits: &str = rest
        .split(|ch: char| !ch.is_ascii_digit())
        .next()
        .unwrap_or("");
    if digits.is_empty() {
        None
    } else {
        digits.parse().ok()
    }
}

/// Reads `"key": "value"` from the pretty-printed config.
fn field_str(text: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\": \"");
    let start = text.find(&needle)? + needle.len();
    let rest = &text[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

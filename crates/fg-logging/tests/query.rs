use std::{
    collections::BTreeMap,
    fs::File,
    io::{self, Write},
    path::Path,
    time::Duration,
};

use anyhow::Result;
use fg_logging::{Entry, Filter, Format, Level, Logs, Module, Options};
use time::OffsetDateTime;
use tracing_subscriber::layer::SubscriberExt;

fn entry(seq: u64, message: String) -> Entry {
    Entry {
        seq,
        time: OffsetDateTime::from_unix_timestamp(seq as i64).unwrap(),
        level: Level::Warn,
        source: "probe".into(),
        message,
        fields: BTreeMap::new(),
    }
}

fn write_entry(output: &mut impl Write, entry: &Entry) -> Result<()> {
    serde_json::to_writer(&mut *output, entry)?;
    output.write_all(b"\n")?;
    Ok(())
}

fn open(dir: &Path, lines: usize) -> Result<Logs> {
    Logs::start(
        Options {
            directory: Some(dir.to_owned()),
            lines,
            ..Options::default()
        },
        io::sink(),
    )
}

#[test]
fn filter_combines_keywords_fields_time_level_and_ip() -> Result<()> {
    let mut item = entry(15, "UPSTREAM timeout from [::ffff:192.0.2.8]:443.".into());
    for (key, value) in [
        ("site", "App.Test"),
        ("host", "origin.example"),
        ("listener", "Main"),
        ("status", "503"),
        ("ip", "[::ffff:192.0.2.8]:443"),
    ] {
        item.fields.insert(key.into(), value.into());
    }
    let mut filter = Filter::default();
    filter.set_keywords(r#""upstream timeout" example -recovered"#, "ignored")?;
    filter.set_ips("::ffff:192.0.2.0/120,!192.0.2.9,10.4.")?;
    filter.set_statuses("418;500-504, 4xx")?;
    filter.min_level = Some(Level::Warn);
    filter.source = Some("PROBE".into());
    filter.host = Some("ORIGIN".into());
    filter.site = Some("app.test".into());
    filter.listener = Some("Main".into());
    filter.from = Some(item.time);
    filter.to = Some(item.time);
    filter.hide_banned = true;
    filter.hide_admin = true;
    assert!(filter.matches(&item));
    item.fields.remove("ip");
    assert!(filter.matches(&item));
    for (key, value) in [
        ("status", "200"),
        ("ip", "192.0.2.9"),
        ("deny", "ban"),
        ("admin", "yes"),
    ] {
        let previous = item.fields.insert(key.into(), value.into());
        assert!(!filter.matches(&item), "unexpected match on {key}");
        if let Some(previous) = previous {
            item.fields.insert(key.into(), previous);
        } else {
            item.fields.remove(key);
        }
    }
    assert!(filter.set_statuses("504-500").is_err());
    assert!(filter.set_ips("192.0.2.0/33").is_err());
    assert!(filter.matches(&item));
    filter.set_ips("192.0.2.,-10.4.8.9")?;
    assert!(filter.matches(&item));
    filter.set_keywords("timeout", r#""upstream timeout""#)?;
    assert!(!filter.matches(&item));
    Ok(())
}

#[test]
fn query_merges_rotated_current_and_live_records_across_block_edges() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let mut older = File::create(dir.path().join("webservice.log.1"))?;
    let mut current = File::create(dir.path().join("webservice.log"))?;
    for seq in 1..=240 {
        let file = if seq <= 120 { &mut older } else { &mut current };
        if seq == 214 {
            file.write_all(&vec![b'!'; 90 << 10])?;
            file.write_all(b"\n")?;
        }
        write_entry(
            file,
            &entry(
                seq,
                format!("record {seq} {}", "x".repeat((seq as usize % 241) + 400)),
            ),
        )?;
    }
    drop((older, current));
    let logs = open(dir.path(), 3)?;
    let default = Filter::default();
    let page = logs.query(Module::Web, 0, 128, 15, &default)?;
    assert_eq!(
        page.entries.iter().map(|item| item.seq).collect::<Vec<_>>(),
        (113..128).collect::<Vec<_>>()
    );
    assert_eq!(page.oldest_seq, 113);
    assert!(page.has_more);
    let across_corruption = logs.query(Module::Web, 210, 218, 20, &default)?;
    assert_eq!(
        across_corruption
            .entries
            .iter()
            .map(|item| item.seq)
            .collect::<Vec<_>>(),
        (211..218).collect::<Vec<_>>()
    );
    assert!(!across_corruption.has_more);
    assert_eq!(logs.query(Module::Web, 0, 0, 0, &default)?.entries.len(), 3);

    let mut filter = Filter::default();
    filter.set_keywords(r#""record 111""#, "")?;
    let filtered = logs.query(Module::Web, 0, 0, 10, &filter)?;
    assert_eq!(filtered.entries.len(), 1);
    assert_eq!(filtered.oldest_seq, 111);
    assert!(!filtered.has_more);
    assert!(logs.query(Module::Web, 0, 0, 20_001, &default).is_err());
    let mut output = Vec::new();
    logs.export(Module::Web, 0, 0, &default, Format::JsonLines, &mut output)?;
    let rows: Vec<Entry> = output
        .split(|&b| b == b'\n')
        .filter(|line| !line.is_empty())
        .map(serde_json::from_slice)
        .collect::<Result<_, _>>()?;
    assert_eq!(
        rows.iter().map(|item| item.seq).collect::<Vec<_>>(),
        (1..=240).collect::<Vec<_>>()
    );
    logs.shutdown(Duration::from_secs(3))?;
    Ok(())
}

#[test]
fn pending_entries_remain_queryable_after_ring_eviction() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let logs = open(dir.path(), 2)?;
    tracing::subscriber::with_default(tracing_subscriber::registry().with(logs.layer()), || {
        for sequence in 1..=40 {
            tracing::warn!(target: "fg_gateway::health", "probe {sequence}");
        }
    });
    let filter = Filter::default();
    let newest = logs.query(Module::Web, 0, 0, 4, &filter)?;
    assert_eq!(
        newest
            .entries
            .iter()
            .map(|item| item.seq)
            .collect::<Vec<_>>(),
        [37, 38, 39, 40]
    );
    let old = logs.query(Module::Web, 7, 13, 100, &filter)?;
    assert_eq!(
        old.entries.iter().map(|item| item.seq).collect::<Vec<_>>(),
        [8, 9, 10, 11, 12]
    );
    let mut output = Vec::new();
    logs.export(Module::Web, 0, 0, &filter, Format::JsonLines, &mut output)?;
    assert_eq!(
        output
            .split(|&byte| byte == b'\n')
            .filter(|line| !line.is_empty())
            .count(),
        40
    );
    logs.shutdown(Duration::from_secs(3))?;
    Ok(())
}

#[test]
fn csv_exports_safe_text_with_bom_quotes_and_newlines() -> Result<()> {
    let logs = Logs::start(Options::default(), io::sink())?;
    tracing::subscriber::with_default(tracing_subscriber::registry().with(logs.layer()), || {
        tracing::info!(target: "fg_gateway::server", site = " @SUM(1,2)", message = "=1+2, \"原文\"\n续行");
    });
    let mut output = Vec::new();
    logs.export(
        Module::System,
        0,
        0,
        &Filter::default(),
        Format::Csv,
        &mut output,
    )?;
    let text = String::from_utf8(output)?;
    assert!(text.starts_with("\u{feff}time,level,source,message,ip,host,site,"));
    assert!(text.contains("\"'=1+2, \"\"原文\"\"\n续行\""));
    assert!(text.contains("\"' @SUM(1,2)\""));
    assert!(text.ends_with("\r\n"));
    logs.shutdown(Duration::from_secs(3))?;
    Ok(())
}

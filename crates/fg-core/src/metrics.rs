//! Prometheus text-format (0.0.4) samples shared by the global endpoint
//! and module metric providers.

use std::{collections::BTreeMap, fmt::Write as _};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Counter,
    Gauge,
    Histogram,
}

impl Kind {
    fn text(self) -> &'static str {
        match self {
            Self::Counter => "counter",
            Self::Gauge => "gauge",
            Self::Histogram => "histogram",
        }
    }
}

/// One exported measurement. Samples with the same name aggregate into one
/// family; the optional `family` differentiates colliding names.
#[derive(Clone, Debug)]
pub struct Sample {
    pub name: String,
    pub family: Option<String>,
    pub help: &'static str,
    pub kind: Kind,
    pub labels: BTreeMap<String, String>,
    pub value: f64,
}

impl Sample {
    pub fn gauge(name: impl Into<String>, help: &'static str, value: f64) -> Self {
        Self {
            name: name.into(),
            family: None,
            help,
            kind: Kind::Gauge,
            labels: BTreeMap::new(),
            value,
        }
    }

    pub fn counter(name: impl Into<String>, help: &'static str, value: f64) -> Self {
        Self {
            kind: Kind::Counter,
            ..Self::gauge(name, help, value)
        }
    }

    pub fn label(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.labels.insert(name.into(), value.into());
        self
    }
}

/// Renders samples as Prometheus text: families sorted by name, HELP and
/// TYPE emitted once per family, samples in input order within a family,
/// labels sorted by key with values escaped.
pub fn write_text(samples: &[Sample]) -> String {
    let mut families: BTreeMap<&str, Vec<&Sample>> = BTreeMap::new();
    for sample in samples {
        let family = sample.family.as_deref().unwrap_or(&sample.name);
        families.entry(family).or_default().push(sample);
    }
    let mut text = String::new();
    for (family, members) in families {
        let first = members[0];
        let _ = writeln!(
            text,
            "# HELP {family} {}",
            first.help.replace('\\', "\\\\").replace('\n', "\\n")
        );
        let _ = writeln!(text, "# TYPE {family} {}", first.kind.text());
        for sample in members {
            let metric = sample.family.as_deref().unwrap_or(&sample.name);
            if sample.labels.is_empty() {
                let _ = writeln!(text, "{metric} {}", format_value(sample.value));
            } else {
                let labels: Vec<String> = sample
                    .labels
                    .iter()
                    .map(|(name, value)| format!("{name}=\"{}\"", escape(value)))
                    .collect();
                let _ = writeln!(
                    text,
                    "{metric}{{{}}} {}",
                    labels.join(","),
                    format_value(sample.value)
                );
            }
        }
    }
    text
}

fn format_value(value: f64) -> String {
    if value.is_finite() && value.fract() == 0.0 && value.abs() < 1e15 {
        format!("{}", value as i64)
    } else if value.is_finite() {
        format!("{value}")
    } else {
        // Prometheus text treats NaN and ±Inf as their special spellings.
        if value.is_nan() {
            "NaN".to_owned()
        } else if value > 0.0 {
            "+Inf".to_owned()
        } else {
            "-Inf".to_owned()
        }
    }
}

fn escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            _ => escaped.push(character),
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_groups_families_and_emits_help_once() {
        let samples = [
            Sample::gauge("ferrumgate_uptime_seconds", "Uptime", 120.0),
            Sample::counter("ferrumgate_events_total", "Events", 3.0).label("kind", "warn"),
            Sample::counter("ferrumgate_events_total", "Events", 5.0).label("kind", "info"),
            Sample::gauge("ferrumgate_uptime_seconds", "Uptime", 240.0),
        ];
        let text = write_text(&samples);
        assert_eq!(text.matches("# HELP ferrumgate_uptime_seconds").count(), 1);
        assert_eq!(
            text.matches("# TYPE ferrumgate_events_total counter")
                .count(),
            1
        );
        assert!(text.contains("ferrumgate_events_total{kind=\"info\"} 5"));
        assert!(text.contains("ferrumgate_events_total{kind=\"warn\"} 3"));
        // Family order is by name.
        let uptime = text.find("ferrumgate_uptime_seconds").unwrap();
        let events = text.find("ferrumgate_events_total").unwrap();
        assert!(events < uptime, "events sorts before uptime");
    }

    #[test]
    fn labels_are_key_sorted_and_escaped() {
        let sample = Sample::gauge("ferrumgate_x", "X", 1.0)
            .label("b", "plain")
            .label("a", "quote\"and\\slash\n");
        let text = write_text(&[sample]);
        assert!(
            text.contains(r#"ferrumgate_x{a="quote\"and\\slash\n",b="plain"} 1"#),
            "{text}"
        );
    }

    #[test]
    fn values_render_integers_without_fraction() {
        let samples = [
            Sample::gauge("g", "G", 42.0),
            Sample::gauge("h", "H", 1.5),
            Sample::gauge("n", "N", f64::NAN),
            Sample::gauge("p", "P", f64::INFINITY),
        ];
        let text = write_text(&samples);
        assert!(text.contains("\ng 42\n"), "{text}");
        assert!(text.contains("\nh 1.5\n"), "{text}");
        assert!(text.contains("\nn NaN\n"), "{text}");
        assert!(text.contains("\np +Inf\n"), "{text}");
    }

    #[test]
    fn overlapping_names_use_the_family_override() {
        let samples = [Sample {
            name: "port.connections".to_owned(),
            family: Some("ferrumgate_port_connections".to_owned()),
            ..Sample::gauge("", "", 1.0)
        }];
        let text = write_text(&samples);
        assert!(text.contains("ferrumgate_port_connections 1"), "{text}");
    }
}

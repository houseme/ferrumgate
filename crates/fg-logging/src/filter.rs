use std::net::{IpAddr, SocketAddr};

use anyhow::{Result, ensure};
use ipnet::IpNet;
use time::OffsetDateTime;

use crate::{Entry, Level};

const MAX_FILTER_BYTES: usize = 4096;
const MAX_TERMS: usize = 128;

#[derive(Default, PartialEq)]
pub struct Filter {
    pub min_level: Option<Level>,
    pub source: Option<String>,
    pub host: Option<String>,
    pub site: Option<String>,
    pub listener: Option<String>,
    pub from: Option<OffsetDateTime>,
    pub to: Option<OffsetDateTime>,
    pub hide_banned: bool,
    pub hide_admin: bool,
    terms: Vec<String>,
    excludes: Vec<String>,
    ips: Vec<Address>,
    excluded_ips: Vec<Address>,
    statuses: Vec<(u16, u16)>,
}

impl Filter {
    pub fn set_keywords(&mut self, query: &str, exclude: &str) -> Result<()> {
        ensure!(
            query.len().saturating_add(exclude.len()) <= MAX_FILTER_BYTES,
            "log keyword filter too long"
        );
        let mut terms = Vec::new();
        let mut excludes = Vec::new();
        for (excluded, label) in words(query) {
            if excluded {
                excludes.push(label);
            } else {
                terms.push(label);
            }
        }
        excludes.extend(words(exclude).map(|(_, label)| label));
        ensure!(
            terms.len() + excludes.len() <= MAX_TERMS,
            "too many log keywords"
        );
        self.terms = terms;
        self.excludes = excludes;
        Ok(())
    }

    pub fn set_ips(&mut self, query: &str) -> Result<()> {
        ensure!(
            query.len() <= MAX_FILTER_BYTES,
            "log address filter too long"
        );
        let mut ips = Vec::new();
        let mut excluded = Vec::new();
        for value in list(query) {
            if let Some(value) = value.strip_prefix(['!', '-']) {
                if !value.is_empty() {
                    excluded.push(Address::parse(value)?);
                }
            } else {
                ips.push(Address::parse(value)?);
            }
        }
        ensure!(
            ips.len() + excluded.len() <= MAX_TERMS,
            "too many log address predicates"
        );
        self.ips = ips;
        self.excluded_ips = excluded;
        Ok(())
    }

    pub fn set_statuses(&mut self, query: &str) -> Result<()> {
        ensure!(
            query.len() <= MAX_FILTER_BYTES,
            "log status filter too long"
        );
        let mut statuses = Vec::new();
        for status in list(query) {
            let (start, end) = match status.as_bytes() {
                [class @ b'1'..=b'5', b'x' | b'X', b'x' | b'X'] => {
                    let base = u16::from(class - b'0') * 100;
                    (base, base + 99)
                }
                _ => {
                    let (lo, hi) = status.split_once('-').unwrap_or((status, status));
                    (lo.parse::<u16>()?, hi.parse::<u16>()?)
                }
            };
            ensure!(
                start >= 100 && start <= end && end <= 599,
                "invalid HTTP status range"
            );
            statuses.push((start, end));
        }
        ensure!(
            statuses.len() <= MAX_TERMS,
            "too many log status predicates"
        );
        self.statuses = statuses;
        Ok(())
    }

    pub fn matches(&self, entry: &Entry) -> bool {
        let get = |key| entry.fields.get(key).map(String::as_str);
        if self.min_level.is_some_and(|level| entry.level < level)
            || self
                .source
                .as_ref()
                .is_some_and(|source| !equal(&entry.source, source))
            || self.from.is_some_and(|from| entry.time < from)
            || self.to.is_some_and(|to| entry.time > to)
            || self
                .site
                .as_ref()
                .is_some_and(|site| get("site").is_none_or(|value| !equal(value, site)))
            || self
                .listener
                .as_deref()
                .is_some_and(|listener| get("listener") != Some(listener))
            || (self.hide_banned && get("deny") == Some("ban"))
            || (self.hide_admin && get("admin").is_some_and(|admin| !admin.is_empty()))
        {
            return false;
        }
        if !self.statuses.is_empty()
            && get("status")
                .and_then(|code| code.parse::<u16>().ok())
                .is_none_or(|code| {
                    !self
                        .statuses
                        .iter()
                        .any(|&(start, end)| (start..=end).contains(&code))
                })
        {
            return false;
        }
        if let Some(host) = &self.host {
            let host = host.to_lowercase();
            let fields = [get("host"), get("site")];
            if if fields.iter().all(Option::is_none) {
                !entry.message.to_lowercase().contains(&host)
            } else {
                !fields
                    .into_iter()
                    .flatten()
                    .any(|value| value.to_lowercase().contains(&host))
            } {
                return false;
            }
        }
        if (!self.ips.is_empty() || !self.excluded_ips.is_empty()) && !self.matches_ip(entry) {
            return false;
        }
        if self.terms.is_empty() && self.excludes.is_empty() {
            return true;
        }
        let mut text = String::with_capacity(entry.source.len() + entry.message.len() + 1);
        text.push_str(&entry.source);
        text.push('\n');
        text.push_str(&entry.message);
        for (key, value) in &entry.fields {
            if key != "listener" {
                text.push('\n');
                text.push_str(value);
            }
        }
        if text.is_ascii() {
            text.make_ascii_lowercase();
        } else {
            text = text.to_lowercase();
        }
        self.terms.iter().all(|term| text.contains(term))
            && self.excludes.iter().all(|term| !text.contains(term))
    }

    fn matches_ip(&self, entry: &Entry) -> bool {
        let mut included = self.ips.is_empty();
        let mut accept = |text: &str| {
            let parsed = parse_ip(text);
            included |= self.ips.iter().any(|item| item.matches(text, parsed));
            self.excluded_ips
                .iter()
                .all(|item| !item.matches(text, parsed))
        };
        if let Some(ip) = entry.fields.get("ip").or_else(|| {
            entry
                .fields
                .get("source")
                .filter(|text| parse_ip(text).is_some())
        }) {
            return accept(ip) && included;
        }
        let no_exclusions = entry
            .message
            .split(|ch: char| !ch.is_ascii_hexdigit() && !matches!(ch, '.' | ':' | '[' | ']'))
            .filter(|token| token.contains(['.', ':']))
            .all(accept);
        no_exclusions && included
    }
}

fn list(text: &str) -> impl Iterator<Item = &str> {
    text.split(|ch: char| ch.is_whitespace() || matches!(ch, ',' | '，' | ';'))
        .filter(|value| !value.is_empty())
}

fn words(text: &str) -> impl Iterator<Item = (bool, String)> {
    let mut rest = text;
    std::iter::from_fn(move || {
        loop {
            rest = rest.trim_start();
            if rest.is_empty() {
                return None;
            }
            let excluded = rest.starts_with('-');
            if excluded {
                rest = &rest[1..];
            }
            let word;
            if let Some(phrase) = rest.strip_prefix('"') {
                (word, rest) = phrase.split_once('"').unwrap_or((phrase, ""));
            } else {
                let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
                (word, rest) = rest.split_at(end);
            }
            if !word.is_empty() {
                return Some((excluded, word.to_lowercase()));
            }
        }
    })
}

#[derive(PartialEq)]
enum Address {
    Exact(IpAddr),
    Network(IpNet),
    Fragment(String),
}

impl Address {
    fn parse(value: &str) -> Result<Self> {
        if value.contains('/') {
            let network: IpNet = value.parse()?;
            if let IpNet::V6(v6) = network
                && v6.prefix_len() >= 96
                && let Some(v4) = v6.addr().to_ipv4_mapped()
            {
                return Ok(Self::Network(IpNet::new(v4.into(), v6.prefix_len() - 96)?));
            }
            return Ok(Self::Network(network));
        }
        Ok(parse_ip(value).map_or_else(|| Self::Fragment(value.to_ascii_lowercase()), Self::Exact))
    }

    fn matches(&self, text: &str, address: Option<IpAddr>) -> bool {
        match self {
            Self::Exact(expected) => address == Some(*expected),
            Self::Network(network) => address.is_some_and(|addr| network.contains(&addr)),
            Self::Fragment(part) => address
                .map_or_else(|| text.to_ascii_lowercase(), |addr| addr.to_string())
                .contains(part),
        }
    }
}

fn parse_ip(value: &str) -> Option<IpAddr> {
    let value = value.trim_end_matches('.');
    value
        .parse::<IpAddr>()
        .ok()
        .or_else(|| value.parse::<SocketAddr>().ok().map(|address| address.ip()))
        .or_else(|| value.trim_matches(['[', ']']).parse::<IpAddr>().ok())
        .map(|address| address.to_canonical())
}

fn equal(left: &str, right: &str) -> bool {
    left.eq_ignore_ascii_case(right)
        || ((!left.is_ascii() || !right.is_ascii()) && left.to_lowercase() == right.to_lowercase())
}

use std::{
    cmp::Reverse,
    collections::{HashMap, HashSet},
    fmt,
    fs::File,
    net::IpAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, ensure};
use arc_swap::ArcSwap;
use data_encoding::{HEXLOWER, HEXLOWER_PERMISSIVE};
use fg_config::{ConfigStore, Loaded};
use ring::digest;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use time::OffsetDateTime;

use crate::account::open_lock;

mod migrate;

const STORE: &str = "tokens";
const PREFIX: &str = "gtl_";
const MAX_TOKENS: usize = 100;
const FLUSH_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TokenInput {
    pub name: String,
    pub scopes: Vec<String>,
    #[serde(default, with = "time::serde::rfc3339::option")]
    #[cfg_attr(feature = "schema", schemars(with = "Option<String>"))]
    pub expires_at: Option<OffsetDateTime>,
    #[serde(default)]
    pub disabled: bool,
    pub group: Option<String>,
}

#[derive(Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct TokenView {
    pub id: String,
    pub name: String,
    pub group: String,
    pub hint: String,
    pub scopes: Vec<String>,
    pub legacy: bool,
    pub disabled: bool,
    pub expired: bool,
    #[serde(with = "time::serde::rfc3339")]
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    #[cfg_attr(feature = "schema", schemars(with = "Option<String>"))]
    pub expires_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    #[cfg_attr(feature = "schema", schemars(with = "Option<String>"))]
    pub last_used_at: Option<OffsetDateTime>,
    #[serde(rename = "lastUsedIP")]
    pub last_used_ip: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TokenError {
    Invalid,
    Expired,
    Disabled,
}

impl fmt::Display for TokenError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid or expired API token")
    }
}

impl std::error::Error for TokenError {}

#[derive(Debug)]
pub enum TokenChangeError {
    Invalid(&'static str),
    NotFound,
}

impl fmt::Display for TokenChangeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Invalid(message) => message,
            Self::NotFound => "API token was not found",
        })
    }
}

impl std::error::Error for TokenChangeError {}

#[derive(Clone)]
pub struct TokenIdentity(Arc<Entry>);

impl TokenIdentity {
    pub fn id(&self) -> &str {
        &self.0.record.id
    }

    pub fn name(&self) -> &str {
        &self.0.record.name
    }

    pub fn scopes(&self) -> &[String] {
        &self.0.record.scopes
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct Record {
    id: String,
    name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    group: String,
    #[serde(serialize_with = "encode_hash", deserialize_with = "decode_hash")]
    hash: [u8; 32],
    hint: String,
    scopes: Vec<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    legacy: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    disabled: bool,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "time::serde::rfc3339::option"
    )]
    expires_at: Option<OffsetDateTime>,
}

#[derive(Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct Usage {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "time::serde::rfc3339::option"
    )]
    last_used_at: Option<OffsetDateTime>,
    #[serde(
        default,
        rename = "lastUsedIP",
        skip_serializing_if = "Option::is_none"
    )]
    last_used_ip: Option<IpAddr>,
}

struct Activity {
    live: Usage,
    saved: Usage,
}

struct Entry {
    record: Record,
    activity: Arc<Mutex<Activity>>,
}

impl Entry {
    fn new(record: Record, usage: Usage) -> Arc<Self> {
        Arc::new(Self {
            record,
            activity: Arc::new(Mutex::new(Activity {
                live: usage,
                saved: usage,
            })),
        })
    }

    fn view(&self, now: OffsetDateTime) -> TokenView {
        let record = &self.record;
        let usage = self.activity.lock().expect("token activity poisoned").live;
        TokenView {
            id: record.id.clone(),
            name: record.name.clone(),
            group: record.group.clone(),
            hint: record.hint.clone(),
            scopes: record.scopes.clone(),
            legacy: record.legacy,
            disabled: record.disabled,
            expired: record.expires_at.is_some_and(|expiry| expiry <= now),
            created_at: record.created_at,
            expires_at: record.expires_at,
            last_used_at: usage.last_used_at,
            last_used_ip: usage
                .last_used_ip
                .map_or_else(String::new, |ip| ip.to_string()),
        }
    }
}

#[derive(Deserialize, Serialize)]
struct StoredToken {
    #[serde(flatten)]
    record: Record,
    #[serde(flatten)]
    usage: Usage,
}

#[derive(Default, Deserialize, Serialize)]
struct TokenFile {
    #[serde(default, deserialize_with = "tokens_or_empty")]
    tokens: Vec<StoredToken>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    ordered: bool,
}

fn tokens_or_empty<'de, D: Deserializer<'de>>(input: D) -> Result<Vec<StoredToken>, D::Error> {
    Ok(Option::<Vec<StoredToken>>::deserialize(input)?.unwrap_or_default())
}

#[derive(Clone)]
struct Snapshot {
    entries: Vec<Arc<Entry>>,
    ordered: bool,
}

impl Snapshot {
    fn new_token_id(&self) -> Result<String> {
        let id = random_hex::<6>()?;
        ensure!(
            !self.entries.iter().any(|entry| entry.record.id == id),
            "API token identifier collision"
        );
        Ok(id)
    }

    fn index(&self, id: &str) -> Result<usize> {
        self.entries
            .iter()
            .position(|entry| entry.record.id == id)
            .ok_or_else(|| TokenChangeError::NotFound.into())
    }
}

struct Writer {
    domains: HashSet<String>,
    last_flush: Instant,
}

pub struct TokenManager {
    store: Arc<ConfigStore>,
    snapshot: ArcSwap<Snapshot>,
    writer: Mutex<Writer>,
    _owner: File,
}

impl TokenManager {
    pub fn open(
        store: Arc<ConfigStore>,
        domains: impl IntoIterator<Item = String>,
        now: Instant,
    ) -> Result<Self> {
        let owner = open_lock(&store, ".tokens.lock")?;
        owner
            .try_lock()
            .context("API token directory already has a writer")?;
        let data = match store.load::<TokenFile>(STORE)? {
            Loaded::Found(data) => data,
            Loaded::Missing => TokenFile::default(),
        };
        ensure!(
            data.tokens.len() <= MAX_TOKENS,
            "API token count exceeds 100"
        );
        let mut ids = HashSet::new();
        let mut hashes = HashSet::new();
        for token in &data.tokens {
            ensure!(
                token.record.id.len() == 12
                    && token.record.id.bytes().all(|byte| byte.is_ascii_hexdigit())
                    && ids.insert(&token.record.id)
                    && hashes.insert(token.record.hash),
                "invalid or duplicate API token record"
            );
        }
        let entries = data
            .tokens
            .into_iter()
            .map(|token| Entry::new(token.record, token.usage))
            .collect();
        Ok(Self {
            store,
            snapshot: ArcSwap::from_pointee(Snapshot {
                entries,
                ordered: data.ordered,
            }),
            writer: Mutex::new(Writer {
                domains: domains.into_iter().collect(),
                last_flush: now,
            }),
            _owner: owner,
        })
    }

    pub fn authenticate(
        &self,
        raw: &str,
        now: OffsetDateTime,
        address: Option<IpAddr>,
    ) -> Result<TokenIdentity, TokenError> {
        if raw.is_empty() || raw.len() > 4096 {
            return Err(TokenError::Invalid);
        }
        let modern = raw.strip_prefix(PREFIX).is_some_and(|hex| {
            hex.len() == 48
                && hex
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        });
        let digest = hash(raw);
        let snapshot = self.snapshot.load();
        let mut index = 0;
        let mut found = Choice::from(0);
        for (candidate, entry) in snapshot.entries.iter().enumerate() {
            let matches = digest.ct_eq(&entry.record.hash);
            index = u8::conditional_select(&index, &(candidate as u8), matches);
            found |= matches;
        }
        if !bool::from(found) {
            return Err(TokenError::Invalid);
        }
        let entry = &snapshot.entries[usize::from(index)];
        if !modern && !entry.record.legacy {
            return Err(TokenError::Invalid);
        }
        if entry.record.disabled {
            return Err(TokenError::Disabled);
        }
        if entry.record.expires_at.is_some_and(|expiry| expiry <= now) {
            return Err(TokenError::Expired);
        }
        let mut activity = entry.activity.lock().expect("token activity poisoned");
        if activity
            .live
            .last_used_at
            .is_none_or(|previous| previous <= now)
        {
            activity.live = Usage {
                last_used_at: Some(now),
                last_used_ip: address.map(|ip| ip.to_canonical()),
            };
        }
        Ok(TokenIdentity(entry.clone()))
    }

    pub fn list(&self, now: OffsetDateTime) -> Vec<TokenView> {
        let snapshot = self.snapshot.load();
        let mut views: Vec<_> = snapshot
            .entries
            .iter()
            .map(|entry| entry.view(now))
            .collect();
        if !snapshot.ordered {
            views.sort_by_key(|view| Reverse(view.created_at));
        }
        views
    }

    pub fn set_domains(&self, domains: impl IntoIterator<Item = String>) {
        let domains = domains.into_iter().collect();
        self.writer.lock().expect("token writer poisoned").domains = domains;
    }

    pub fn domains(&self) -> Vec<String> {
        let mut domains: Vec<_> = self
            .writer
            .lock()
            .expect("token writer poisoned")
            .domains
            .iter()
            .cloned()
            .collect();
        domains.sort_unstable();
        domains
    }

    pub fn create(&self, input: TokenInput, now: OffsetDateTime) -> Result<(TokenView, String)> {
        let mut writer = self.writer.lock().expect("token writer poisoned");
        let mut next = (**self.snapshot.load()).clone();
        ensure!(
            next.entries.len() < MAX_TOKENS,
            TokenChangeError::Invalid("API token limit reached")
        );
        let input = normalize(input, &writer.domains, now, None)?;
        let id = next.new_token_id()?;
        let raw = format!("{PREFIX}{}", random_hex::<24>()?);
        let record = Record {
            id,
            name: input.name,
            group: input.group.unwrap_or_default(),
            hash: hash(&raw),
            hint: hint(&raw),
            scopes: input.scopes,
            disabled: input.disabled,
            created_at: now,
            expires_at: input.expires_at,
            legacy: false,
        };
        let entry = Entry::new(record, Usage::default());
        let view = entry.view(now);
        next.entries.insert(0, entry);
        self.save(next, &mut writer)?;
        Ok((view, raw))
    }

    pub fn update(&self, id: &str, input: TokenInput, now: OffsetDateTime) -> Result<TokenView> {
        let mut writer = self.writer.lock().expect("token writer poisoned");
        let mut next = (**self.snapshot.load()).clone();
        let index = next.index(id)?;
        let old = &next.entries[index];
        let input = normalize(input, &writer.domains, now, Some(&old.record))?;
        let record = Record {
            name: input.name,
            scopes: input.scopes,
            expires_at: input.expires_at,
            disabled: input.disabled,
            group: input.group.unwrap_or_else(|| old.record.group.clone()),
            ..old.record.clone()
        };
        let entry = Arc::new(Entry {
            record,
            activity: old.activity.clone(),
        });
        let view = entry.view(now);
        next.entries[index] = entry;
        self.save(next, &mut writer)?;
        Ok(view)
    }

    pub fn regenerate(&self, id: &str) -> Result<String> {
        self.regenerate_with_view(id, OffsetDateTime::now_utc())
            .map(|(_, raw)| raw)
    }

    pub fn regenerate_with_view(
        &self,
        id: &str,
        now: OffsetDateTime,
    ) -> Result<(TokenView, String)> {
        let mut writer = self.writer.lock().expect("token writer poisoned");
        let mut next = (**self.snapshot.load()).clone();
        let index = next.index(id)?;
        let old = &next.entries[index];
        let raw = format!("{PREFIX}{}", random_hex::<24>()?);
        let record = Record {
            hash: hash(&raw),
            hint: hint(&raw),
            legacy: false,
            ..old.record.clone()
        };
        let entry = Entry::new(record, Usage::default());
        let view = entry.view(now);
        next.entries[index] = entry;
        self.save(next, &mut writer)?;
        Ok((view, raw))
    }

    pub fn order(&self, ids: &[String]) -> Result<()> {
        let mut writer = self.writer.lock().expect("token writer poisoned");
        let current = self.snapshot.load();
        ensure!(
            ids.len() == current.entries.len(),
            TokenChangeError::Invalid("token order must contain every token exactly once")
        );
        let mut remaining: HashMap<_, _> = current
            .entries
            .iter()
            .map(|entry| (entry.record.id.as_str(), entry))
            .collect();
        let entries = ids
            .iter()
            .map(|id| {
                remaining
                    .remove(id.as_str())
                    .cloned()
                    .ok_or(TokenChangeError::Invalid(
                        "token order contains an unknown or duplicate identifier",
                    ))
            })
            .collect::<Result<Vec<_>, _>>()?;
        if current.ordered
            && entries
                .iter()
                .zip(&current.entries)
                .all(|(a, b)| Arc::ptr_eq(a, b))
        {
            return Ok(());
        }
        self.save(
            Snapshot {
                entries,
                ordered: true,
            },
            &mut writer,
        )
    }

    pub fn set_group(&self, ids: &[String], group: &str) -> Result<()> {
        let group = group.trim();
        ensure!(
            valid_label(group),
            TokenChangeError::Invalid("invalid API token group")
        );
        ensure!(
            !ids.is_empty(),
            TokenChangeError::Invalid("select at least one token")
        );
        let mut remaining: HashSet<_> = ids.iter().map(String::as_str).collect();
        let mut writer = self.writer.lock().expect("token writer poisoned");
        let mut next = (**self.snapshot.load()).clone();
        let mut changed = false;
        for entry in &mut next.entries {
            if remaining.remove(entry.record.id.as_str()) && entry.record.group != group {
                let mut record = entry.record.clone();
                record.group = group.to_owned();
                *entry = Arc::new(Entry {
                    record,
                    activity: entry.activity.clone(),
                });
                changed = true;
            }
        }
        ensure!(remaining.is_empty(), TokenChangeError::NotFound);
        if changed {
            self.save(next, &mut writer)?;
        }
        Ok(())
    }

    pub fn delete(&self, id: &str) -> Result<()> {
        let mut writer = self.writer.lock().expect("token writer poisoned");
        let mut next = (**self.snapshot.load()).clone();
        let index = next.index(id)?;
        next.entries.remove(index);
        self.save(next, &mut writer)
    }

    pub fn flush_usage(&self, now: Instant) -> Result<bool> {
        self.flush(now, false)
    }

    pub fn flush_usage_on_shutdown(&self) -> Result<bool> {
        self.flush(Instant::now(), true)
    }

    fn flush(&self, now: Instant, force: bool) -> Result<bool> {
        let mut writer = self.writer.lock().expect("token writer poisoned");
        if !force && now.saturating_duration_since(writer.last_flush) < FLUSH_INTERVAL {
            return Ok(false);
        }
        let snapshot = self.snapshot.load();
        if !snapshot.entries.iter().any(|entry| {
            let activity = entry.activity.lock().expect("token activity poisoned");
            activity.live != activity.saved
        }) {
            return Ok(false);
        }
        let (saved, visible) = self.persist(&snapshot)?;
        if visible {
            writer.last_flush = now;
        }
        saved.map(|_| true)
    }

    fn save(&self, next: Snapshot, writer: &mut Writer) -> Result<()> {
        let (result, visible) = self.persist(&next)?;
        if visible {
            self.snapshot.store(Arc::new(next));
            writer.last_flush = Instant::now();
        }
        result
    }

    fn persist(&self, snapshot: &Snapshot) -> Result<(Result<()>, bool)> {
        let tokens: Vec<_> = snapshot
            .entries
            .iter()
            .map(|entry| StoredToken {
                record: entry.record.clone(),
                usage: entry.activity.lock().expect("token activity poisoned").live,
            })
            .collect();
        let data = TokenFile {
            tokens,
            ordered: snapshot.ordered,
        };
        let mut bytes = serde_json::to_vec_pretty(&data).context("encode API token records")?;
        bytes.push(b'\n');
        let saved = self.store.write_raw(STORE, &bytes).map(|_| ());
        let visible =
            saved.is_ok() || self.store.load_raw(STORE).ok().flatten().as_deref() == Some(&bytes);
        if visible {
            for (entry, stored) in snapshot.entries.iter().zip(data.tokens) {
                entry
                    .activity
                    .lock()
                    .expect("token activity poisoned")
                    .saved = stored.usage;
            }
        }
        Ok((saved, visible))
    }
}

fn normalize(
    mut input: TokenInput,
    domains: &HashSet<String>,
    now: OffsetDateTime,
    old: Option<&Record>,
) -> Result<TokenInput> {
    input.name = input.name.trim().to_owned();
    ensure!(
        !input.name.is_empty() && valid_label(&input.name),
        TokenChangeError::Invalid("invalid API token name")
    );
    if let Some(group) = &mut input.group {
        *group = group.trim().to_owned();
        ensure!(
            valid_label(group),
            TokenChangeError::Invalid("invalid API token group")
        );
    }
    ensure!(
        input
            .expires_at
            .is_none_or(|expires| expires > now
                || old.is_some_and(|record| record.expires_at == Some(expires))),
        TokenChangeError::Invalid("API token expiration must be in the future")
    );
    ensure!(
        !input.scopes.is_empty(),
        TokenChangeError::Invalid("API token requires at least one scope")
    );
    let valid_scope = |scope: &str| {
        scope == "*"
            || scope.split_once(':').is_some_and(|(domain, level)| {
                (domain == "*" || domains.contains(domain)) && matches!(level, "read" | "write")
            })
    };
    for scope in &mut input.scopes {
        *scope = scope.trim().to_owned();
        ensure!(
            valid_scope(scope) || old.is_some_and(|record| record.scopes.contains(scope)),
            TokenChangeError::Invalid("invalid API token scope")
        );
    }
    if let Some(old) = old {
        input.scopes.extend(
            old.scopes
                .iter()
                .filter(|scope| !valid_scope(scope))
                .cloned(),
        );
    }
    input.scopes.sort_unstable();
    input.scopes.dedup();
    Ok(input)
}

fn valid_label(label: &str) -> bool {
    label.chars().count() <= 64 && !label.chars().any(char::is_control)
}

fn hash(raw: &str) -> [u8; 32] {
    digest::digest(&digest::SHA256, raw.as_bytes())
        .as_ref()
        .try_into()
        .expect("SHA-256 digest length")
}

fn hint(raw: &str) -> String {
    format!("{}…{}", &raw[..PREFIX.len() + 4], &raw[raw.len() - 4..])
}

fn random_hex<const N: usize>() -> Result<String> {
    let mut bytes = [0; N];
    getrandom::fill(&mut bytes)
        .map_err(|_| anyhow::anyhow!("cannot generate API token material"))?;
    Ok(HEXLOWER.encode(&bytes))
}

fn encode_hash<S: Serializer>(hash: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&HEXLOWER.encode(hash))
}

fn decode_hash<'de, D: Deserializer<'de>>(input: D) -> Result<[u8; 32], D::Error> {
    let hash = String::deserialize(input)?;
    HEXLOWER_PERMISSIVE
        .decode(hash.as_bytes())
        .ok()
        .and_then(|value| value.try_into().ok())
        .ok_or_else(|| serde::de::Error::custom("invalid API token hash"))
}

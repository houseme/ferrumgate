use std::{collections::BTreeMap, sync::Arc};

use anyhow::{Result, anyhow, ensure};
use serde_json::value::RawValue;
use time::OffsetDateTime;

use super::{Entry, MAX_TOKENS, Record, TokenManager, Usage, hash};

impl TokenManager {
    /// Migrates the legacy `apiToken` field without archiving plaintext or replacing other settings.
    pub fn migrate_legacy_settings(&self, config_name: &str, now: OffsetDateTime) -> Result<bool> {
        let Some(previous) = self.store.load_raw(config_name)? else {
            return Ok(false);
        };
        let mut settings: BTreeMap<String, Box<RawValue>> = serde_json::from_slice(&previous)
            .map_err(|_| anyhow!("invalid settings for API token migration"))?;
        let Some(field) = settings.remove("apiToken") else {
            return Ok(false);
        };
        let raw: Option<String> = serde_json::from_str(field.get())
            .map_err(|_| anyhow!("legacy API token must be a string"))?;
        let Some(raw) = raw.filter(|raw| !raw.is_empty()) else {
            return Ok(false);
        };
        let mut next = serde_json::to_vec_pretty(&settings)
            .map_err(|_| anyhow!("encode settings after API token migration"))?;
        next.push(b'\n');
        self.import_legacy(&raw, now)?;
        ensure!(
            self.store
                .replace_unversioned(config_name, &previous, &next)?,
            "settings changed during API token migration"
        );
        Ok(true)
    }

    pub fn import_legacy(&self, raw: &str, now: OffsetDateTime) -> Result<bool> {
        ensure!(
            !raw.is_empty() && raw.len() <= 4096 && !raw.chars().any(char::is_control),
            "invalid legacy API token"
        );
        let hash = hash(raw);
        let mut writer = self.writer.lock().expect("token writer poisoned");
        let mut next = (**self.snapshot.load()).clone();
        if next.entries.iter().any(|entry| entry.record.hash == hash) {
            return Ok(false);
        }
        ensure!(next.entries.len() < MAX_TOKENS, "API token limit reached");
        let record = Record {
            id: next.new_token_id()?,
            name: "Legacy API token".into(),
            group: String::new(),
            hash,
            hint: legacy_hint(raw),
            scopes: vec!["*".into()],
            legacy: true,
            disabled: false,
            created_at: now,
            expires_at: None,
        };
        next.entries.insert(0, Entry::new(record, Usage::default()));
        self.save(next, &mut writer)?;
        Ok(true)
    }

    /// Copies explicit source grants to the target domain and leaves already covered grants alone.
    pub fn inherit_scopes(&self, from: &str, to: &str) -> Result<usize> {
        ensure!(
            valid_domain(from) && valid_domain(to),
            "invalid API token migration domain"
        );
        if from == to {
            return Ok(0);
        }
        let from_read = format!("{from}:read");
        let from_write = format!("{from}:write");
        let to_read = format!("{to}:read");
        let to_write = format!("{to}:write");
        let mut writer = self.writer.lock().expect("token writer poisoned");
        let mut next = (**self.snapshot.load()).clone();
        let mut changed = 0;
        for entry in &mut next.entries {
            let scopes = &entry.record.scopes;
            let grants = |scope: &str| scopes.iter().any(|grant| grant == scope);
            if grants("*") || grants("*:write") || grants(&to_write) {
                continue;
            }
            let inherit_write = grants(&from_write);
            let inherit_read =
                !inherit_write && grants(&from_read) && !grants("*:read") && !grants(&to_read);
            if inherit_write || inherit_read {
                let mut record = entry.record.clone();
                if inherit_write {
                    record.scopes.push(to_write.clone());
                }
                if inherit_read {
                    record.scopes.push(to_read.clone());
                }
                record.scopes.sort_unstable();
                *entry = Arc::new(Entry {
                    record,
                    activity: entry.activity.clone(),
                });
                changed += 1;
            }
        }
        if changed > 0 {
            self.save(next, &mut writer)?;
        }
        Ok(changed)
    }
}

fn valid_domain(domain: &str) -> bool {
    !domain.is_empty()
        && domain.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
}

fn legacy_hint(raw: &str) -> String {
    if raw.chars().count() <= 12 {
        return "…".into();
    }
    let first = raw.char_indices().nth(4).expect("legacy prefix").0;
    let last = raw.char_indices().nth_back(3).expect("legacy suffix").0;
    format!("{}…{}", &raw[..first], &raw[last..])
}

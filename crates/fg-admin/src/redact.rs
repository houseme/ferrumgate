use std::borrow::Cow;

use axum::http::HeaderName;
use fg_logging::Entry;
use percent_encoding::percent_decode_str;
use serde_json::Value;
use url::Url;

use crate::SECRET_MASK;

pub(super) fn redact(value: &mut Value) {
    redact_value(value, false);
}

pub(super) fn redact_log(entry: &Entry) -> Cow<'_, Entry> {
    let mut output = Cow::Borrowed(entry);
    if let Some(source) = redact_urls(&entry.source) {
        output.to_mut().source = source;
    }
    if let Some(message) = redact_urls(&entry.message) {
        output.to_mut().message = message;
    }
    if !entry.fields.is_empty() {
        let mut value = Value::Object(
            entry
                .fields
                .iter()
                .map(|(key, text)| (key.clone(), Value::String(text.clone())))
                .collect(),
        );
        redact(&mut value);
        if let Value::Object(fields) = value {
            for (key, masked) in fields {
                if let Value::String(masked) = masked
                    && entry.fields.get(&key) != Some(&masked)
                {
                    output.to_mut().fields.insert(key, masked);
                }
            }
        }
    }
    output
}

fn redact_value(value: &mut Value, credential: bool) {
    match value {
        Value::Object(object) => {
            let request_template = object.keys().any(|key| {
                key.eq_ignore_ascii_case("method") || key.eq_ignore_ascii_case("headers")
            });
            for (name, value) in object {
                let key = lowercase(name);
                match key.as_ref() {
                    key if secret_key(key) => {
                        if !value.is_boolean() {
                            opaque(value);
                        }
                    }
                    "headers" | "requestheaders" | "responseheaders" | "request_headers"
                    | "response_headers" => fields(value, ':', header_name),
                    "command" | "script" | "shutdowncommand" => opaque(value),
                    "body" if request_template => opaque(value),
                    key if key.contains("args") => opaque(value),
                    key if key.ends_with("env") => fields(value, '=', env_name),
                    "users" => users(value),
                    "credentials" => redact_value(value, true),
                    "extra" if credential => credential_extra(value),
                    _ => redact(value),
                }
            }
        }
        Value::Array(items) => items
            .iter_mut()
            .for_each(|item| redact_value(item, credential)),
        Value::String(text) => {
            if let Some(masked) = redact_urls(text) {
                *text = masked;
            }
        }
        _ => {}
    }
}

fn lowercase(key: &str) -> Cow<'_, str> {
    if key.bytes().any(|byte| byte.is_ascii_uppercase()) {
        Cow::Owned(key.to_ascii_lowercase())
    } else {
        Cow::Borrowed(key)
    }
}

fn secret_key(key: &str) -> bool {
    matches!(
        key,
        "password"
            | "passwordhash"
            | "secret"
            | "token"
            | "authsecret"
            | "privatekey"
            | "passphrase"
            | "clientsecret"
            | "apitoken"
            | "apikey"
            | "secretkey"
            | "adminpassword"
            | "totpsecret"
            | "psk"
            | "sessionsecret"
            | "agenttoken"
            | "authkey"
            | "setupkey"
            | "networksecret"
            | "enckey"
            | "hmackey"
            | "eabhmac"
            | "dashboardpwd"
            | "consumerkey"
            | "twofakey"
            | "signingkey"
            | "keypem"
            | "authmarkerkey"
            | "private_key"
            | "api_key"
            | "access_token"
            | "refresh_token"
            | "authorization"
    ) || (key.contains("password") && !key.starts_with("has") && !key.ends_with("enabled"))
}

fn opaque(value: &mut Value) {
    match value {
        Value::Null => {}
        Value::String(text) if text.is_empty() => {}
        Value::Object(object) => object.values_mut().for_each(opaque),
        Value::Array(items) => items.iter_mut().for_each(opaque),
        _ => *value = Value::String(SECRET_MASK.into()),
    }
}

fn credential_extra(extra: &mut Value) {
    if let Value::Object(entries) = extra {
        for (name, entry) in entries {
            if matches!(
                lowercase(name).as_ref(),
                "endpoint"
                    | "authtype"
                    | "proxied"
                    | "server"
                    | "url"
                    | "method"
                    | "successcontent"
                    | "hostedzoneid"
                    | "teamid"
            ) {
                redact(entry);
            } else {
                opaque(entry);
            }
        }
    } else {
        opaque(extra);
    }
}

fn fields(value: &mut Value, delimiter: char, valid_name: fn(&str) -> bool) {
    match value {
        Value::String(text) => {
            let mut result = String::with_capacity(text.len());
            for (index, line) in text.split('\n').enumerate() {
                if index != 0 {
                    result.push('\n');
                }
                match line.split_once(delimiter) {
                    Some((name, value)) if valid_name(name.trim()) => {
                        if value.trim().is_empty() {
                            result.push_str(line);
                        } else {
                            result.push_str(name);
                            result.push(delimiter);
                            if delimiter == ':' {
                                result.push(' ');
                            }
                            result.push_str(SECRET_MASK);
                        }
                    }
                    _ if line.trim().is_empty() => result.push_str(line),
                    _ => result.push_str(SECRET_MASK),
                }
            }
            *text = result;
        }
        Value::Array(items) => items
            .iter_mut()
            .for_each(|item| fields(item, delimiter, valid_name)),
        _ => opaque(value),
    }
}

fn header_name(name: &str) -> bool {
    HeaderName::from_bytes(name.as_bytes()).is_ok()
}

fn env_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn users(value: &mut Value) {
    let Value::Array(items) = value else {
        return redact(value);
    };
    for item in items {
        if let Value::String(text) = item
            && let Some((user, password)) = text.split_once(':')
            && !password.is_empty()
        {
            *text = format!("{user}:{SECRET_MASK}");
        } else {
            redact(item);
        }
    }
}

fn redact_urls(text: &str) -> Option<String> {
    let mut offset = 0;
    let mut copied = 0;
    let mut output: Option<String> = None;
    while let Some(marker) = text[offset..].find("://").map(|marker| marker + offset) {
        let start = text.as_bytes()[offset..marker]
            .iter()
            .rposition(|byte| !byte.is_ascii_alphanumeric() && !matches!(byte, b'+' | b'.' | b'-'))
            .map_or(offset, |start| offset + start + 1);
        offset = marker + 3;
        if !text
            .as_bytes()
            .get(start..marker)
            .and_then(|prefix| prefix.first())
            .is_some_and(u8::is_ascii_alphabetic)
        {
            continue;
        }
        let end = text[offset..]
            .find(|character: char| {
                character.is_whitespace() || matches!(character, '"' | '\'' | '<' | '>')
            })
            .map_or(text.len(), |end| offset + end);
        if end == offset {
            continue;
        }
        if let Some(masked) = redact_url(&text[start..end]) {
            let result = output.get_or_insert_with(|| String::with_capacity(text.len()));
            result.push_str(&text[copied..start]);
            result.push_str(&masked);
            copied = end;
        }
        offset = end;
    }
    if let Some(output) = &mut output {
        output.push_str(&text[copied..]);
    }
    output
}

fn redact_url(text: &str) -> Option<String> {
    let Ok(mut url) = Url::parse(text) else {
        return Some(SECRET_MASK.into());
    };
    let mut changed = false;
    if url.password().is_some() {
        if url.set_password(Some(SECRET_MASK)).is_err() {
            return Some(SECRET_MASK.into());
        }
        changed = true;
    } else if token_like(&percent_decode_str(url.username()).decode_utf8_lossy()) {
        if url.set_username(SECRET_MASK).is_err() {
            return Some(SECRET_MASK.into());
        }
        changed = true;
    }
    if url
        .path()
        .split('/')
        .any(|part| token_like(&percent_decode_str(part).decode_utf8_lossy()))
    {
        let mut path = String::with_capacity(url.path().len());
        for (index, part) in url.path().split('/').enumerate() {
            if index != 0 {
                path.push('/');
            }
            path.push_str(
                if token_like(&percent_decode_str(part).decode_utf8_lossy()) {
                    SECRET_MASK
                } else {
                    part
                },
            );
        }
        url.set_path(&path);
        changed = true;
    }
    if let Some(query) = url.query().filter(|query| !query.is_empty()) {
        let mut masked = String::with_capacity(query.len());
        for (index, part) in query.split('&').enumerate() {
            if index != 0 {
                masked.push('&');
            }
            if let Some((name, _)) = part.split_once('=') {
                if token_like(&percent_decode_str(name).decode_utf8_lossy()) {
                    masked.push_str(SECRET_MASK);
                } else {
                    masked.push_str(name);
                }
                masked.push('=');
            }
            masked.push_str(SECRET_MASK);
        }
        url.set_query(Some(&masked));
        changed = true;
    }
    if url.fragment().is_some_and(|part| !part.is_empty()) {
        url.set_fragment(Some(SECRET_MASK));
        changed = true;
    }
    changed.then(|| url.into())
}

fn token_like(part: &str) -> bool {
    part.len() >= 16
        && part.bytes().any(|byte| byte.is_ascii_alphabetic())
        && part.bytes().any(|byte| byte.is_ascii_digit())
}

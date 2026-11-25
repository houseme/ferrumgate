use crate::config::canonical_host;

pub(crate) fn normalize(raw: &str) -> Option<String> {
    if !raw.contains('*') {
        return canonical_host(raw).map(|host| host.into_owned());
    }
    if raw.bytes().filter(|&byte| byte == b'*').count() != 1 {
        return None;
    }
    let pattern = raw.strip_suffix('.').unwrap_or(raw).to_ascii_lowercase();
    if pattern.ends_with('.') {
        return None;
    }
    let check = pattern.replace('*', "x");
    canonical_host(&check)?;
    Some(pattern)
}

pub(crate) fn matches(pattern: &str, host: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    let Some((prefix, suffix)) = pattern.split_once('*') else {
        return pattern == host;
    };
    let Some(middle) = host
        .strip_prefix(prefix)
        .and_then(|rest| rest.strip_suffix(suffix))
    else {
        return false;
    };
    if (prefix.is_empty() && suffix.starts_with('.'))
        || (suffix.is_empty() && prefix.ends_with('.'))
    {
        return !middle.is_empty();
    }
    if prefix.ends_with('.') && suffix.starts_with('.') && middle.is_empty() {
        return false;
    }
    !middle.contains('.')
}

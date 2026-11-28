//! Line-oriented helpers for the text protocol recognizers (upstream
//! `textline.go`): incremental request-line reading with the 8 KiB cap and
//! the Host normalization shared by the HTTP refinement.

/// Incremental state of the HTTP Host scan: the start of the current line,
/// the buffer offset scanning has reached, and the first `Host` value found.
#[derive(Debug, Default)]
pub struct TextState {
    pub(super) line_start: usize,
    pub(super) scanned: usize,
    pub(super) host: Option<String>,
}

/// Finds the next line in `buf` starting at `line_start`, resuming the `\n`
/// search from `scanned` so incremental feeding stays linear. Returns the
/// line range (without trailing CRLF / LF) and the offset after `\n`.
pub(super) fn next_line_from(
    buf: &[u8],
    line_start: usize,
    scanned: usize,
) -> Option<(std::ops::Range<usize>, usize)> {
    let search_from = scanned.max(line_start);
    if search_from >= buf.len() {
        return None;
    }
    let end = search_from + buf[search_from..].iter().position(|&byte| byte == b'\n')?;
    let mut stop = end;
    if stop > line_start && buf[stop - 1] == b'\r' {
        stop -= 1;
    }
    Some((line_start..stop, end + 1))
}

#[cfg(test)]
fn next_line(buf: &[u8], from: usize) -> Option<(std::ops::Range<usize>, usize)> {
    next_line_from(buf, from, from)
}

/// Normalizes a `Host` header value for domain matching: lower-case,
/// brackets stripped from IPv6 literals, the port dropped and trailing
/// dots removed. `None` when nothing usable remains.
pub(super) fn normalize_host(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    let host = if let Some(rest) = value.strip_prefix('[') {
        // [v6]:port
        match rest.split_once(']') {
            Some((host, _)) => host,
            None => return None,
        }
    } else {
        // host:port with a single trailing colon part (IPv4 or a name).
        match value.rsplit_once(':') {
            Some((host, port))
                if !host.is_empty()
                    && host.find(':').is_none()
                    && port.chars().all(|c| c.is_ascii_digit())
                    && !port.is_empty() =>
            {
                host
            }
            _ => value,
        }
    };
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    (!host.is_empty()).then_some(host)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_line_splits_crlf_and_lf() {
        let buf = b"a\r\nbb\nccc";
        assert_eq!(next_line(buf, 0), Some((0..1, 3)));
        assert_eq!(next_line(buf, 3), Some((3..5, 6)));
        assert_eq!(next_line(buf, 6), None);
        let empty = b"\r\n";
        assert_eq!(next_line(empty, 0), Some((0..0, 2)));
    }

    #[test]
    fn normalize_host_strips_port_brackets_and_case() {
        assert_eq!(
            normalize_host("Shop.Example.:8443"),
            Some("shop.example".to_owned())
        );
        assert_eq!(
            normalize_host("[2001:DB8::1]:443"),
            Some("2001:db8::1".to_owned())
        );
        assert_eq!(
            normalize_host("backend.example."),
            Some("backend.example".to_owned())
        );
        assert_eq!(
            normalize_host("plain.example"),
            Some("plain.example".to_owned())
        );
        assert_eq!(normalize_host(""), None);
        assert_eq!(normalize_host("   "), None);
    }
}

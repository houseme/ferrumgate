//! Port-list parsing, target mapping and range collapsing (WP-36).
//!
//! This is the pure port-list form of the gateway listener parser: no
//! `SocketAddr`, no host part — just ports, ranges of ports and the
//! mapping of target ports onto listener ports.
#![allow(dead_code)]

use std::fmt;

/// Maximum number of ports accepted after range expansion, matching the
/// gateway listener cap.
pub const MAX_PORTS: usize = 64;

/// An error produced while parsing or mapping a port list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortError {
    /// The input was empty or contained an empty item between separators.
    Empty,
    /// A field was not a valid number.
    InvalidNumber(String),
    /// Port 0 is not a valid listener or target port.
    ZeroPort,
    /// A port was above 65535 and does not fit the `u16` port range.
    PortOutOfRange(u32),
    /// A range was written with `start > end`.
    ReversedRange { start: u16, end: u16 },
    /// The expanded list exceeded [`MAX_PORTS`] entries.
    TooManyPorts,
    /// The target list neither held one port nor matched the listener count.
    TargetCountMismatch { listeners: usize, targets: usize },
}

impl fmt::Display for PortError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "port list is empty or contains an empty item"),
            Self::InvalidNumber(token) => write!(f, "invalid port: {token:?}"),
            Self::ZeroPort => write!(f, "port 0 is not allowed"),
            Self::PortOutOfRange(value) => {
                write!(f, "port {value} is outside the valid range 1-65535")
            }
            Self::ReversedRange { start, end } => {
                write!(f, "invalid port range: start {start} > end {end}")
            }
            Self::TooManyPorts => write!(f, "port list supports up to {MAX_PORTS} entries"),
            Self::TargetCountMismatch { listeners, targets } => write!(
                f,
                "target must have one port or the same number of ports as the listener \
                 ({targets} targets for {listeners} listeners)"
            ),
        }
    }
}

impl std::error::Error for PortError {}

/// A parsed port list preserving the written order.
pub struct PortList {
    pub ports: Vec<u16>,
}

fn parse_number(part: &str) -> Result<u32, PortError> {
    part.parse::<u32>()
        .map_err(|_| PortError::InvalidNumber(part.to_owned()))
}

/// Parses a port list such as `443`, `443,8443`, `8000-8010` or
/// `80,8000-8002,9000`. Separators are `,` (ASCII), the full-width `，`
/// and space; items are trimmed and empty items are rejected. The written
/// order is preserved, including inside ranges.
pub fn parse_ports(s: &str) -> Result<PortList, PortError> {
    let max = u16::MAX as u32;
    let mut ports = Vec::new();
    for part in s.trim().split([',', '，', ' ']) {
        let part = part.trim();
        if part.is_empty() {
            return Err(PortError::Empty);
        }
        let (start, end) = match part.split_once('-') {
            Some((start, end)) => (parse_number(start.trim())?, parse_number(end.trim())?),
            None => {
                let port = parse_number(part)?;
                (port, port)
            }
        };
        if start == 0 {
            return Err(PortError::ZeroPort);
        }
        if start > max {
            return Err(PortError::PortOutOfRange(start));
        }
        if end > max {
            return Err(PortError::PortOutOfRange(end));
        }
        if start > end {
            return Err(PortError::ReversedRange {
                start: start as u16,
                end: end as u16,
            });
        }
        let count = end as usize - start as usize + 1;
        if ports.len() + count > MAX_PORTS {
            return Err(PortError::TooManyPorts);
        }
        ports.extend(start as u16..=end as u16);
    }
    if ports.is_empty() {
        return Err(PortError::Empty);
    }
    Ok(PortList { ports })
}

/// Maps a target list onto listen ports: one target is reused by every
/// listener, otherwise the lengths must match positionally.
pub fn map_targets(listen: &[u16], target: &PortList) -> Result<Vec<Vec<u16>>, PortError> {
    match target.ports.len() {
        1 => Ok(vec![target.ports.clone(); listen.len()]),
        len if len == listen.len() => Ok(target.ports.iter().map(|&port| vec![port]).collect()),
        len => Err(PortError::TargetCountMismatch {
            listeners: listen.len(),
            targets: len,
        }),
    }
}

/// Deduplicates, sorts and merges consecutive ports into ranges.
pub fn collapse(ports: &[u16]) -> Vec<(u16, u16)> {
    let mut sorted = ports.to_vec();
    sorted.sort_unstable();
    sorted.dedup();

    let mut ranges = Vec::new();
    let mut iter = sorted.into_iter();
    let Some(mut start) = iter.next() else {
        return ranges;
    };
    let mut end = start;
    for port in iter {
        if end.checked_add(1) == Some(port) {
            end = port;
        } else {
            ranges.push((start, end));
            start = port;
            end = port;
        }
    }
    ranges.push((start, end));
    ranges
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ports_mixed_forms_keep_order() {
        assert_eq!(parse_ports("443").unwrap().ports, [443]);
        assert_eq!(parse_ports("443,8443").unwrap().ports, [443, 8443]);
        assert_eq!(
            parse_ports("8000-8010").unwrap().ports,
            (8000..=8010).collect::<Vec<_>>()
        );
        assert_eq!(
            parse_ports("80,8000-8002,9000").unwrap().ports,
            [80, 8000, 8001, 8002, 9000]
        );
        // Full-width comma and space are separators; items are trimmed.
        assert_eq!(
            parse_ports("80，8443 9000").unwrap().ports,
            [80, 8443, 9000]
        );
        assert_eq!(parse_ports(" 80 ").unwrap().ports, [80]);
    }

    #[test]
    fn parse_ports_rejects_bad_input() {
        assert!(matches!(parse_ports("0"), Err(PortError::ZeroPort)));
        assert!(matches!(
            parse_ports("65536"),
            Err(PortError::PortOutOfRange(65536))
        ));
        assert!(matches!(
            parse_ports("10-5"),
            Err(PortError::ReversedRange { start: 10, end: 5 })
        ));
        assert!(matches!(parse_ports(""), Err(PortError::Empty)));
        assert!(matches!(parse_ports("1,,2"), Err(PortError::Empty)));
        assert!(matches!(
            parse_ports("80x"),
            Err(PortError::InvalidNumber(_))
        ));
        assert!(matches!(
            parse_ports("1-64,65"),
            Err(PortError::TooManyPorts)
        ));
        // Exactly the cap is fine.
        assert_eq!(parse_ports("1-64").unwrap().ports.len(), MAX_PORTS);
    }

    #[test]
    fn map_targets_one_or_equal_length() {
        // A single target is reused by every listener.
        let one = PortList { ports: vec![9080] };
        assert_eq!(
            map_targets(&[80, 81, 82], &one).unwrap(),
            [vec![9080], vec![9080], vec![9080]]
        );
        // Otherwise the target count must match positionally.
        let two = PortList {
            ports: vec![9080, 9081],
        };
        assert_eq!(
            map_targets(&[80, 81], &two).unwrap(),
            [vec![9080], vec![9081]]
        );
        // Any other length is an error.
        let three = PortList {
            ports: vec![1, 2, 3],
        };
        assert!(matches!(
            map_targets(&[80, 81], &three),
            Err(PortError::TargetCountMismatch {
                listeners: 2,
                targets: 3
            })
        ));
    }

    #[test]
    fn collapse_merges_ranges() {
        assert_eq!(
            collapse(&[80, 443, 81, 8000, 8001]),
            [(80, 81), (443, 443), (8000, 8001)]
        );
        assert_eq!(collapse(&[]), []);
        assert_eq!(collapse(&[65535, 65535, 65535]), [(65535, 65535)]);
        assert_eq!(collapse(&[1, 2, 3, 4]), [(1, 4)]);
    }
}

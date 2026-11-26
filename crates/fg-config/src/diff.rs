use std::collections::HashMap;

use serde::Serialize;

const MAX_CELLS: usize = 4_000_000;
const MAX_LINES: usize = 65_536;
const CONTEXT: usize = 3;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Op {
    Same,
    Add,
    Del,
    Fold,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
pub struct DiffLine {
    pub op: Op,
    pub text: String,
}

pub fn diff(old: &[u8], new: &[u8]) -> Vec<DiffLine> {
    if old == new {
        return if old.is_empty() {
            Vec::new()
        } else {
            vec![fold()]
        };
    }
    let old = String::from_utf8_lossy(old);
    let new = String::from_utf8_lossy(new);
    let a: Vec<_> = old.split_terminator('\n').take(MAX_LINES + 1).collect();
    let b: Vec<_> = new.split_terminator('\n').take(MAX_LINES + 1).collect();
    if a.len() > MAX_LINES || b.len() > MAX_LINES {
        return [(Op::Del, old), (Op::Add, new)]
            .into_iter()
            .filter(|(_, text)| !text.is_empty())
            .map(|(op, text)| DiffLine {
                op,
                text: text.into_owned(),
            })
            .collect();
    }

    let prefix = a
        .iter()
        .zip(&b)
        .take_while(|(left, right)| left == right)
        .count();
    let suffix = a[prefix..]
        .iter()
        .rev()
        .zip(b[prefix..].iter().rev())
        .take_while(|(left, right)| left == right)
        .count();
    let mid_a = &a[prefix..a.len() - suffix];
    let mid_b = &b[prefix..b.len() - suffix];
    let mut rows = Vec::with_capacity(a.len() + b.len() - prefix - suffix);
    rows.extend(a[..prefix].iter().map(|&line| (Op::Same, line)));
    if mid_a.is_empty() || mid_b.is_empty() || mid_a.len().saturating_mul(mid_b.len()) > MAX_CELLS {
        rows.extend(mid_a.iter().map(|&line| (Op::Del, line)));
        rows.extend(mid_b.iter().map(|&line| (Op::Add, line)));
    } else {
        lcs(mid_a, mid_b, &mut rows);
    }
    rows.extend(a[a.len() - suffix..].iter().map(|&line| (Op::Same, line)));
    collapse(&rows)
}

fn lcs<'a>(a: &[&'a str], b: &[&'a str], rows: &mut Vec<(Op, &'a str)>) {
    let mut ids = HashMap::new();
    let mut intern = |lines: &[&'a str]| {
        lines
            .iter()
            .map(|&line| {
                let next = ids.len();
                *ids.entry(line).or_insert(next)
            })
            .collect::<Vec<_>>()
    };
    let left = intern(a);
    let right = intern(b);
    let width = b.len();
    // One score row plus a packed trace. The bounded grid implies LCS length <= 2000.
    let mut scores = vec![0u16; width + 1];
    let mut deletes = vec![0u64; (a.len() * width).div_ceil(64)];
    for i in (0..a.len()).rev() {
        let mut diagonal = 0;
        for j in (0..width).rev() {
            let down = scores[j];
            if left[i] == right[j] {
                scores[j] = diagonal + 1;
            } else if down >= scores[j + 1] {
                let index = i * width + j;
                deletes[index / 64] |= 1 << (index % 64);
            } else {
                scores[j] = scores[j + 1];
            }
            diagonal = down;
        }
    }
    let (mut i, mut j) = (0, 0);
    while i < a.len() && j < b.len() {
        let index = i * width + j;
        if left[i] == right[j] {
            rows.push((Op::Same, a[i]));
            i += 1;
            j += 1;
        } else if deletes[index / 64] & (1 << (index % 64)) != 0 {
            rows.push((Op::Del, a[i]));
            i += 1;
        } else {
            rows.push((Op::Add, b[j]));
            j += 1;
        }
    }
    rows.extend(a[i..].iter().map(|&line| (Op::Del, line)));
    rows.extend(b[j..].iter().map(|&line| (Op::Add, line)));
}

fn collapse(rows: &[(Op, &str)]) -> Vec<DiffLine> {
    let mut result = Vec::new();
    let mut offset = 0;
    let line = |&(op, text): &(Op, &str)| DiffLine {
        op,
        text: text.to_owned(),
    };
    for group in rows.chunk_by(|a, b| (a.0 == Op::Same) == (b.0 == Op::Same)) {
        let start = offset;
        offset += group.len();
        if group[0].0 != Op::Same {
            result.extend(group.iter().map(line));
            continue;
        }
        let head = if start > 0 {
            group.len().min(CONTEXT)
        } else {
            0
        };
        let tail = if offset < rows.len() {
            (group.len() - head).min(CONTEXT)
        } else {
            0
        };
        result.extend(group[..head].iter().map(line));
        if head + tail < group.len() {
            result.push(fold());
        }
        result.extend(group[group.len() - tail..].iter().map(line));
    }
    result
}

fn fold() -> DiffLine {
    DiffLine {
        op: Op::Fold,
        text: "@".into(),
    }
}

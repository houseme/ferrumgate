use fg_config::{Op, diff};

#[test]
fn diff_keeps_three_context_lines_and_serializes_operations() {
    let old = b"1\n2\n3\n4\n5\nold\n6\n7\n8\n9\n10\n";
    let new = b"1\n2\n3\n4\n5\nnew\n6\n7\n8\n9\n10\n";
    let lines = diff(old, new);
    let sequence: Vec<_> = lines
        .iter()
        .map(|row| (row.op, row.text.as_str()))
        .collect();
    assert_eq!(
        sequence,
        [
            (Op::Fold, "@"),
            (Op::Same, "3"),
            (Op::Same, "4"),
            (Op::Same, "5"),
            (Op::Del, "old"),
            (Op::Add, "new"),
            (Op::Same, "6"),
            (Op::Same, "7"),
            (Op::Same, "8"),
            (Op::Fold, "@"),
        ]
    );
    assert_eq!(
        serde_json::to_value(&lines[4]).unwrap(),
        serde_json::json!({"op":"del", "text":"old"})
    );
}

#[test]
fn diff_tracks_internal_lcs_matches() {
    let lines = diff(b"a\nb\nc\nd\n", b"b\na\nd\nc\n");
    let sequence: Vec<_> = lines
        .iter()
        .map(|row| (row.op, row.text.as_str()))
        .collect();
    assert_eq!(
        sequence,
        [
            (Op::Del, "a"),
            (Op::Same, "b"),
            (Op::Del, "c"),
            (Op::Add, "a"),
            (Op::Same, "d"),
            (Op::Add, "c"),
        ]
    );
}

#[test]
fn diff_falls_back_for_excessive_grids_and_dense_inputs() {
    let old = "a\n".repeat(2001);
    let new = "b\n".repeat(2000);
    let result = diff(old.as_bytes(), new.as_bytes());
    assert_eq!(result.len(), 4001);
    assert!(result[..2001].iter().all(|line| line.op == Op::Del));
    assert!(result[2001..].iter().all(|line| line.op == Op::Add));
    let dense = "\n".repeat(65_537);
    let blocks = diff(dense.as_bytes(), new.as_bytes());
    assert_eq!(blocks.len(), 2);
    assert_eq!(
        (blocks[0].op, blocks[0].text.as_str()),
        (Op::Del, dense.as_str())
    );
    assert_eq!(
        (blocks[1].op, blocks[1].text.as_str()),
        (Op::Add, new.as_str())
    );
}

#[test]
fn diff_equal_inputs_are_folded_without_line_expansion() {
    let bytes = b"same\nfile\n";
    let lines = diff(bytes, bytes);
    assert_eq!(lines.len(), 1);
    assert_eq!((lines[0].op, lines[0].text.as_str()), (Op::Fold, "@"));
    assert!(diff(b"", b"").is_empty());
}

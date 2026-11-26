//! `{name}` placeholder substitution for translated strings.

/// Replaces `{name}` placeholders with the matching named argument. Missing
/// arguments keep their placeholder; extra arguments are ignored.
pub fn render(template: &str, args: &[(&str, &str)]) -> String {
    let mut rendered = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(start) = rest.find('{') {
        let Some(end) = rest[start + 1..].find('}') else {
            break;
        };
        let name = &rest[start + 1..start + 1 + end];
        rendered.push_str(&rest[..start]);
        if name.is_empty() || !name.bytes().all(is_name_byte) {
            // Not one of our placeholders; keep the braces verbatim.
            rendered.push_str(&rest[start..start + 2 + end]);
        } else if let Some((_, value)) = args.iter().find(|(arg, _)| arg == &name) {
            rendered.push_str(value);
        } else {
            rendered.push_str(&rest[start..start + 2 + end]);
        }
        rest = &rest[start + 2 + end..];
    }
    rendered.push_str(rest);
    rendered
}

fn is_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// The set of `{name}` placeholders in a template, in order.
pub fn placeholders(template: &str) -> Vec<&str> {
    let mut names = Vec::new();
    let mut rest = template;
    while let Some(start) = rest.find('{') {
        let Some(end) = rest[start + 1..].find('}') else {
            break;
        };
        let name = &rest[start + 1..start + 1 + end];
        if !name.is_empty() && name.bytes().all(is_name_byte) {
            names.push(name);
        }
        rest = &rest[start + 2 + end..];
    }
    names
}

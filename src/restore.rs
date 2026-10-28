use crate::fields;
use crate::json::{self, Edit, Str, Value, shift, splice};
use crate::placeholder;
use crate::redact::is_signed;
use crate::vault::Vault;

pub fn restore(body: &[u8], vault: &Vault) -> Option<Vec<u8>> {
    if !placeholder::contains(body) {
        return None;
    }

    let root = json::parse(body).ok()?;
    let mut edits = Vec::new();
    collect(&root, body, vault, false, false, 0, &mut edits);

    (!edits.is_empty()).then(|| splice(body, edits))
}

pub fn restore_json_text(text: &str, vault: &Vault) -> Option<String> {
    let mut edits = Vec::new();
    json_text_edits(text, vault, 0, &mut edits);
    if edits.is_empty() {
        return None;
    }

    let restored = splice(text.as_bytes(), edits);
    Some(String::from_utf8(restored).expect("restoring keeps UTF-8 intact"))
}

pub fn restore_text(text: &str, vault: &Vault, json_text: bool) -> Option<String> {
    let mut out = String::new();
    let mut at = 0;
    for (range, placeholder) in placeholder::find(text.as_bytes()) {
        let Some(value) = vault.value(placeholder) else {
            continue;
        };

        out.push_str(&text[at..range.start]);

        if json_text {
            out.push_str(&json::escape(&value));
        } else {
            out.push_str(&value);
        }

        at = range.end;
    }

    if at == 0 {
        return None;
    }

    out.push_str(&text[at..]);
    Some(out)
}

fn collect(
    value: &Value,
    source: &[u8],
    vault: &Vault,
    json_text: bool,
    payload: bool,
    depth: usize,
    edits: &mut Vec<Edit>,
) {
    match value {
        Value::Object { members, .. } => {
            if !payload && is_signed(value, source) {
                return;
            }

            let tool = members
                .iter()
                .any(|member| fields::identifies_a_tool(&member.key.decode(source).text));

            for member in members {
                restore_literal(&member.key, source, vault, edits);

                let key = member.key.decode(source).text;
                if payload || !fields::is_verified_key(&key) {
                    let inner = payload || (tool && fields::opens_payload(&key));
                    collect(
                        &member.value,
                        source,
                        vault,
                        fields::holds_json_text(&key),
                        inner,
                        depth + 1,
                        edits,
                    );
                }
            }
        }

        Value::Array { items, .. } => items
            .iter()
            .for_each(|item| collect(item, source, vault, false, payload, depth + 1, edits)),

        Value::String(literal) if json_text => {
            restore_json_literal(literal, source, vault, depth, edits);
        }

        Value::String(literal) => restore_literal(literal, source, vault, edits),
        Value::Scalar(_) => {}
    }
}

fn restore_literal(literal: &Str, source: &[u8], vault: &Vault, edits: &mut Vec<Edit>) {
    let contents = literal.contents();
    placeholder_edits(&source[contents.clone()], contents.start, vault, edits);
}

fn restore_json_literal(
    literal: &Str,
    source: &[u8],
    vault: &Vault,
    depth: usize,
    edits: &mut Vec<Edit>,
) {
    let decoded = literal.decode(source);
    let mut nested = Vec::new();
    json_text_edits(&decoded.text, vault, depth + 1, &mut nested);

    let offset = literal.contents().start;
    edits.extend(nested.into_iter().map(|edit| Edit {
        range: shift(decoded.raw_range(edit.range), offset),
        text: json::escape(&edit.text),
    }));
}

fn json_text_edits(text: &str, vault: &Vault, depth: usize, edits: &mut Vec<Edit>) {
    if !placeholder::contains(text.as_bytes()) {
        return;
    }

    match json::parse_nested(text.as_bytes(), depth) {
        Ok(root @ (Value::Object { .. } | Value::Array { .. })) => {
            collect(&root, text.as_bytes(), vault, false, true, depth, edits);
        }

        _ => placeholder_edits(text.as_bytes(), 0, vault, edits),
    }
}

fn placeholder_edits(text: &[u8], offset: usize, vault: &Vault, edits: &mut Vec<Edit>) {
    for (range, placeholder) in placeholder::find(text) {
        if let Some(value) = vault.value(placeholder) {
            edits.push(Edit {
                range: shift(range, offset),
                text: json::escape(&value),
            });
        }
    }
}

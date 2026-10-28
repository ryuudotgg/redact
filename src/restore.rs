use crate::fields;
use crate::json::{self, Edit, Str, Value, splice};
use crate::placeholder;
use crate::redact::is_signed;
use crate::vault::Vault;

pub fn restore(body: &[u8], vault: &Vault) -> Option<Vec<u8>> {
    if !placeholder::contains(body) {
        return None;
    }

    let root = json::parse(body).ok()?;
    let mut edits = Vec::new();
    collect(&root, body, vault, false, false, &mut edits);

    (!edits.is_empty()).then(|| splice(body, edits))
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
                restore_literal(&member.key, source, vault, false, edits);

                let key = member.key.decode(source).text;
                if payload || !fields::is_verified_key(&key) {
                    let inner = payload || (tool && fields::opens_payload(&key));
                    collect(
                        &member.value,
                        source,
                        vault,
                        fields::holds_json_text(&key),
                        inner,
                        edits,
                    );
                }
            }
        }

        Value::Array { items, .. } => items
            .iter()
            .for_each(|item| collect(item, source, vault, false, payload, edits)),

        Value::String(literal) => restore_literal(literal, source, vault, json_text, edits),
        Value::Scalar(_) => {}
    }
}

fn restore_literal(
    literal: &Str,
    source: &[u8],
    vault: &Vault,
    json_text: bool,
    edits: &mut Vec<Edit>,
) {
    let contents = literal.contents();
    for (range, placeholder) in placeholder::find(&source[contents.clone()]) {
        let Some(value) = vault.value(placeholder) else {
            continue;
        };

        let escaped = json::escape(&value);
        let text = if json_text {
            json::escape(&escaped)
        } else {
            escaped
        };

        edits.push(Edit {
            range: contents.start + range.start..contents.start + range.end,
            text,
        });
    }
}

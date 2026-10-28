use std::ops::Range;
use std::sync::Arc;

use crate::fields::{self, Format};
use crate::json::{self, Edit, Member, Str, Value, splice};
use crate::placeholder;
use crate::scanner::Scanner;
use crate::vault::{Known, Vault};

pub const NOTICE: &str = "Some values in this conversation, such as API keys, tokens and passwords, appear as references like redact-0123456789ab. \
Each reference stands in for a real value the user already has, and their tooling puts the value back wherever your output is used: \
in text, code, files, commands and tool arguments. Use a reference exactly where its value belongs, the way you would use the value itself, \
and copy it whole and unchanged. Do not alter, split or invent references, do not compute on them by hashing, encoding or measuring them, \
and do not swap in sample values.";

const MAX_PASSES: usize = 4;

pub struct Redacted {
    pub body: Vec<u8>,
    pub values: usize,
}

pub fn redact(
    body: &[u8],
    format: Format,
    scanner: &Scanner,
    vault: &Vault,
    notice: bool,
) -> Result<Option<Redacted>, json::Error> {
    let mut current: Option<Vec<u8>> = None;
    let mut values = 0;
    for _ in 0..MAX_PASSES {
        let source = current.as_deref().unwrap_or(body);
        let known_before = vault.len();

        let edits = find_edits(source, scanner, vault)?;
        if edits.is_empty() {
            break;
        }

        values += edits.len();
        current = Some(splice(source, edits));
        if vault.len() == known_before {
            break;
        }
    }

    let source = current.as_deref().unwrap_or(body);
    if notice
        && (carries_placeholder(source, vault) || continues_upstream(source, format, vault))
        && let Some(with_notice) = add_notice(source, format)?
    {
        current = Some(with_notice);
    }

    Ok(current.map(|body| Redacted { body, values }))
}

fn find_edits(source: &[u8], scanner: &Scanner, vault: &Vault) -> Result<Vec<Edit>, json::Error> {
    let root = json::parse(source)?;
    let mut walk = Walk {
        source,
        scanner,
        vault,
        known: vault.known(),
        edits: Vec::new(),
    };

    walk.value(&root, None, false, 0)?;
    Ok(walk.edits)
}

struct Walk<'a> {
    source: &'a [u8],
    scanner: &'a Scanner,
    vault: &'a Vault,
    known: Option<Arc<Known>>,
    edits: Vec<Edit>,
}

impl Walk<'_> {
    fn value(
        &mut self,
        value: &Value,
        key: Option<&str>,
        payload: bool,
        depth: usize,
    ) -> Result<(), json::Error> {
        match value {
            Value::Object { members, .. } => {
                if !payload && is_signed(value, self.source) {
                    return Ok(());
                }

                let tool = members
                    .iter()
                    .any(|member| fields::identifies_a_tool(&member.key.decode(self.source).text));

                for member in members {
                    self.string(&member.key, false, depth)?;

                    let key = member.key.decode(self.source).text;
                    if !payload && fields::is_verified_key(&key) {
                        continue;
                    }
                    if let Value::String(literal) = &member.value
                        && self.keyed(&key, literal)
                    {
                        continue;
                    }

                    let inner = payload || (tool && fields::opens_payload(&key));
                    self.value(&member.value, Some(&key), inner, depth + 1)?;
                }

                Ok(())
            }

            Value::Array { items, .. } => items
                .iter()
                .try_for_each(|item| self.value(item, None, payload, depth + 1)),

            Value::String(literal) => {
                self.string(literal, key.is_some_and(fields::holds_json_text), depth)
            }

            Value::Scalar(_) => Ok(()),
        }
    }

    fn keyed(&mut self, key: &str, literal: &Str) -> bool {
        let decoded = literal.decode(self.source);
        if !self.scanner.keyed(key, &decoded.text, self.vault) {
            return false;
        }

        let placeholder = self.vault.placeholder(&decoded.text);
        self.edits.push(Edit {
            range: literal.contents(),
            text: placeholder.to_string(),
        });

        true
    }

    fn string(&mut self, literal: &Str, json_text: bool, depth: usize) -> Result<(), json::Error> {
        let decoded = literal.decode(self.source);
        let text = decoded.text.as_ref();
        let offset = literal.contents().start;

        if text.is_empty() || fields::looks_like_blob(text) {
            return Ok(());
        }

        if json_text {
            match json::parse_nested(text.as_bytes(), depth + 1) {
                Ok(inner @ (Value::Object { .. } | Value::Array { .. })) => {
                    let mut nested = Walk {
                        source: text.as_bytes(),
                        scanner: self.scanner,
                        vault: self.vault,
                        known: self.known.clone(),
                        edits: Vec::new(),
                    };

                    nested.value(&inner, None, true, depth + 1)?;

                    for edit in nested.edits {
                        self.edits.push(Edit {
                            range: shift(decoded.raw_range(edit.range), offset),
                            text: edit.text,
                        });
                    }

                    return Ok(());
                }

                Err(json::Error::TooDeep) => return Err(json::Error::TooDeep),
                _ => {}
            }
        }

        for range in self.scanner.find(text, self.known.as_deref(), self.vault) {
            let placeholder = self.vault.placeholder(&text[range.clone()]);
            self.edits.push(Edit {
                range: shift(decoded.raw_range(range), offset),
                text: placeholder.to_string(),
            });
        }

        Ok(())
    }
}

pub fn is_signed(object: &Value, source: &[u8]) -> bool {
    let kind = object
        .get("type", source)
        .and_then(|kind| kind.as_str(source));

    let thought = object.get("thought", source).is_some_and(
        |thought| matches!(thought, Value::Scalar(span) if &source[span.clone()] == b"true"),
    );

    thought || kind.is_some_and(|kind| fields::is_signed_type(&kind))
}

// Codex over WebSocket keeps the history upstream and sends only the new turn.
fn continues_upstream(source: &[u8], format: Format, vault: &Vault) -> bool {
    format == Format::Responses
        && !vault.is_empty()
        && json::parse(source).is_ok_and(|root| {
            root.get("previous_response_id", source)
                .is_some_and(|id| id.as_str(source).is_some())
        })
}

fn carries_placeholder(source: &[u8], vault: &Vault) -> bool {
    placeholder::find(source).any(|(_, placeholder)| vault.value(placeholder).is_some())
}

fn add_notice(source: &[u8], format: Format) -> Result<Option<Vec<u8>>, json::Error> {
    let notice = json::escape(NOTICE);
    if memchr::memmem::find(source, notice.as_bytes()).is_some() {
        return Ok(None);
    }

    let root = json::parse(source)?;
    let Value::Object { members, span } = &root else {
        return Ok(None);
    };

    let typed_block = format!(r#"{{"type":"text","text":"{notice}"}}"#);
    let edit = match format {
        Format::Claude => match root.get("system", source) {
            Some(system) => append_text(system, &notice, &typed_block),
            None => Some(insert_member(
                members,
                span,
                &format!(r#""system":"{notice}""#),
            )),
        },

        Format::Responses => match root.get("instructions", source) {
            Some(instructions) => append_text(instructions, &notice, &typed_block),
            None => Some(insert_member(
                members,
                span,
                &format!(r#""instructions":"{notice}""#),
            )),
        },

        Format::Chat => root
            .get("messages", source)
            .and_then(|messages| chat_notice(messages, source, &notice, &typed_block)),

        Format::Gemini => gemini_notice(&root, members, span, source, &notice),
        Format::Other => None,
    };

    Ok(edit.map(|edit| splice(source, vec![edit])))
}

fn chat_notice(messages: &Value, source: &[u8], notice: &str, typed_block: &str) -> Option<Edit> {
    let Value::Array { items, span } = messages else {
        return None;
    };

    let first = items.first();
    let role = first
        .and_then(|message| message.get("role", source))
        .and_then(|role| role.as_str(source));

    if let (Some(message), Some("system" | "developer")) = (first, role.as_deref()) {
        return message
            .get("content", source)
            .and_then(|content| append_text(content, notice, typed_block));
    }

    let separator = if items.is_empty() { "" } else { "," };
    Some(Edit {
        range: span.start + 1..span.start + 1,
        text: format!(r#"{{"role":"system","content":"{notice}"}}{separator}"#),
    })
}

fn gemini_notice(
    root: &Value,
    members: &[Member],
    span: &Range<usize>,
    source: &[u8],
    notice: &str,
) -> Option<Edit> {
    let instruction = root
        .get("systemInstruction", source)
        .or_else(|| root.get("system_instruction", source));

    let part = format!(r#"{{"text":"{notice}"}}"#);
    match instruction {
        Some(instruction) => instruction
            .get("parts", source)
            .and_then(|parts| append_text(parts, notice, &part)),

        None => Some(insert_member(
            members,
            span,
            &format!(r#""systemInstruction":{{"parts":[{part}]}}"#),
        )),
    }
}

fn append_text(value: &Value, notice: &str, block: &str) -> Option<Edit> {
    match value {
        Value::String(literal) => {
            let end = literal.contents().end;
            Some(Edit {
                range: end..end,
                text: format!(r"\n\n{notice}"),
            })
        }

        Value::Array { items, span } => {
            let end = span.end - 1;
            let separator = if items.is_empty() { "" } else { "," };
            Some(Edit {
                range: end..end,
                text: format!("{separator}{block}"),
            })
        }

        Value::Scalar(span) => Some(Edit {
            range: span.clone(),
            text: format!(r#""{notice}""#),
        }),

        Value::Object { .. } => None,
    }
}

fn insert_member(members: &[Member], span: &Range<usize>, member: &str) -> Edit {
    let end = span.end - 1;
    let separator = if members.is_empty() { "" } else { "," };
    Edit {
        range: end..end,
        text: format!("{separator}{member}"),
    }
}

fn shift(range: Range<usize>, offset: usize) -> Range<usize> {
    range.start + offset..range.end + offset
}

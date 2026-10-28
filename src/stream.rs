use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use crate::fields::{self, Format};
use crate::placeholder;
use crate::restore::restore_text;
use crate::vault::Vault;

const STATE_TTL: Duration = Duration::from_hours(2);

#[derive(Debug, PartialEq, Eq)]
pub enum Chunk {
    Unchanged,
    Replace(Vec<u8>),
    Hold,
}

#[derive(Default)]
pub struct Streams {
    states: Mutex<HashMap<String, Tracked>>,
}

struct Tracked {
    stream: Arc<Mutex<Stream>>,
    touched: Instant,
}

struct Stream {
    format: Format,
    channels: BTreeMap<Channel, Pending>,
    held: Vec<u8>,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum Channel {
    Block(u64),
    Item(String, i64),
    Choice(u64, Option<u64>),
    Candidate(u64),
}

struct Pending {
    tail: String,
    json_text: bool,
    template: Option<Value>,
}

#[derive(Default)]
struct Outcome {
    changed: bool,
    flushed: Vec<Value>,
}

impl Streams {
    pub fn begin(&self, request: &str, format: Format) {
        let mut states = self.states.lock().unwrap_or_else(PoisonError::into_inner);
        states.retain(|_, tracked| tracked.touched.elapsed() < STATE_TTL);
        states.insert(request.to_owned(), Tracked::new(format));
    }

    pub fn chunk(&self, request: &str, format: Format, body: &[u8], vault: &Vault) -> Chunk {
        if vault.is_empty() {
            return Chunk::Unchanged;
        }

        let stream = {
            let mut states = self.states.lock().unwrap_or_else(PoisonError::into_inner);
            let tracked = states
                .entry(request.to_owned())
                .or_insert_with(|| Tracked::new(format));

            tracked.touched = Instant::now();
            Arc::clone(&tracked.stream)
        };

        let mut stream = stream.lock().unwrap_or_else(PoisonError::into_inner);
        stream.process(body, vault)
    }

    pub fn end(&self, request: &str) {
        self.states
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(request);
    }
}

impl Tracked {
    fn new(format: Format) -> Self {
        let stream = Stream {
            format,
            channels: BTreeMap::new(),
            held: Vec::new(),
        };

        Self {
            stream: Arc::new(Mutex::new(stream)),
            touched: Instant::now(),
        }
    }
}

impl Stream {
    fn process(&mut self, body: &[u8], vault: &Vault) -> Chunk {
        let mut input = std::mem::take(&mut self.held);
        let merged = !input.is_empty();
        if merged && !input.ends_with(b"\n") {
            input.push(b'\n');
        }
        input.extend_from_slice(body);

        if self.waits_for_data(&input) {
            self.held = input;
            return Chunk::Hold;
        }

        let mut out = Vec::with_capacity(input.len() + 64);
        let mut block_start = 0;
        let mut changed = merged;
        for line in input.split_inclusive(|&byte| byte == b'\n') {
            let content = line
                .strip_suffix(b"\n")
                .map_or(line, |rest| rest.strip_suffix(b"\r").unwrap_or(rest));

            if content.iter().all(u8::is_ascii_whitespace) {
                out.extend_from_slice(line);
                block_start = out.len();
                continue;
            }

            let (lead, framed) = match content {
                [b'd', b'a', b't', b'a', b':', b' ', ..] => (6, true),
                [b'd', b'a', b't', b'a', b':', ..] => (5, true),
                [b'{', ..] => (0, false),
                _ => {
                    out.extend_from_slice(line);
                    continue;
                }
            };

            let Ok(mut event) = serde_json::from_slice::<Value>(&content[lead..]) else {
                out.extend_from_slice(line);
                continue;
            };

            let outcome = self.event(&mut event, vault);
            if !outcome.flushed.is_empty() {
                let synthetic = render(&outcome.flushed, framed);
                let length = synthetic.len();
                out.splice(block_start..block_start, synthetic);
                block_start += length;
                changed = true;
            }

            if outcome.changed {
                out.extend_from_slice(&content[..lead]);
                out.extend_from_slice(
                    &serde_json::to_vec(&event).expect("a JSON value serializes"),
                );

                out.extend_from_slice(&line[content.len()..]);
                changed = true;
            } else {
                out.extend_from_slice(line);
            }

            if !framed {
                block_start = out.len();
            }
        }

        if changed {
            Chunk::Replace(out)
        } else {
            Chunk::Unchanged
        }
    }

    fn waits_for_data(&self, input: &[u8]) -> bool {
        if self.format != Format::Responses
            || !self
                .channels
                .values()
                .any(|pending| !pending.tail.is_empty())
        {
            return false;
        }

        let mut lines = input
            .split(|&byte| byte == b'\n')
            .map(|line| line.strip_suffix(b"\r").unwrap_or(line));

        let has_payload = lines
            .clone()
            .any(|line| line.starts_with(b"data:") || line.starts_with(b"{"));

        let flushes = lines.any(|line| {
            line.strip_prefix(b"event:")
                .is_some_and(|name| flushes_responses(name.trim_ascii()))
        });

        flushes && !has_payload
    }

    fn event(&mut self, event: &mut Value, vault: &Vault) -> Outcome {
        if !event.is_object() {
            return Outcome::default();
        }

        match self.format {
            Format::Claude => self.claude(event, vault),
            Format::Responses => self.responses(event, vault),
            Format::Chat => self.chat(event, vault),
            Format::Gemini => self.gemini(event, vault),
            Format::Other => Outcome {
                changed: restore_value(event, vault),
                flushed: Vec::new(),
            },
        }
    }

    fn claude(&mut self, event: &mut Value, vault: &Vault) -> Outcome {
        let kind = event["type"].as_str().unwrap_or_default().to_owned();
        let index = event["index"].as_u64().unwrap_or(0);
        match kind.as_str() {
            "content_block_delta" => {
                let (field, json_text) = match event["delta"]["type"].as_str() {
                    Some("text_delta") => ("text", false),
                    Some("input_json_delta") => ("partial_json", true),
                    _ => return Outcome::default(),
                };

                let Some(fragment) = event
                    .get_mut("delta")
                    .and_then(|delta| delta.get_mut(field))
                else {
                    return Outcome::default();
                };

                let changed = self.apply(
                    Channel::Block(index),
                    fragment,
                    json_text,
                    false,
                    None,
                    vault,
                );

                Outcome {
                    changed,
                    flushed: Vec::new(),
                }
            }

            "content_block_stop" => Outcome {
                changed: false,
                flushed: self.flush(|channel| *channel == Channel::Block(index)),
            },

            "message_delta" | "message_stop" | "error" => Outcome {
                changed: false,
                flushed: self.flush(|_| true),
            },

            _ => Outcome {
                changed: restore_value(event, vault),
                flushed: Vec::new(),
            },
        }
    }

    fn responses(&mut self, event: &mut Value, vault: &Vault) -> Outcome {
        let kind = event["type"].as_str().unwrap_or_default().to_owned();
        let item = event["item_id"]
            .as_str()
            .or_else(|| event["item"]["id"].as_str())
            .unwrap_or_default()
            .to_owned();

        let (content, json_text) = match kind.as_str() {
            "response.output_text.delta" | "response.refusal.delta" => {
                (event["content_index"].as_i64().unwrap_or(0), false)
            }

            "response.function_call_arguments.delta" => (-1, true),
            "response.custom_tool_call_input.delta" => (-1, false),
            kind if kind.starts_with("response.reasoning") => return Outcome::default(),
            kind if flushes_responses(kind.as_bytes()) => {
                let finishes_all = kind.rsplit('.').next() != Some("done");
                let flushed = self.flush(|channel| {
                    finishes_all || matches!(channel, Channel::Item(id, _) if *id == item)
                });

                return Outcome {
                    changed: restore_value(event, vault),
                    flushed,
                };
            }

            _ => {
                return Outcome {
                    changed: restore_value(event, vault),
                    flushed: Vec::new(),
                };
            }
        };

        let template = event.clone();
        let Some(fragment) = event.get_mut("delta") else {
            return Outcome::default();
        };

        let changed = self.apply(
            Channel::Item(item, content),
            fragment,
            json_text,
            false,
            Some(template),
            vault,
        );

        Outcome {
            changed,
            flushed: Vec::new(),
        }
    }

    fn chat(&mut self, event: &mut Value, vault: &Vault) -> Outcome {
        let mut changed = false;
        let Some(choices) = event["choices"].as_array_mut() else {
            return Outcome::default();
        };
        for choice in choices.iter_mut().filter(|choice| choice.is_object()) {
            let index = choice["index"].as_u64().unwrap_or(0);
            let finished = !choice["finish_reason"].is_null();
            if let Some(content) = choice
                .get_mut("delta")
                .and_then(|delta| delta.get_mut("content"))
            {
                changed |= self.apply(
                    Channel::Choice(index, None),
                    content,
                    false,
                    finished,
                    None,
                    vault,
                );
            }

            let calls = choice
                .get_mut("delta")
                .and_then(|delta| delta.get_mut("tool_calls"))
                .and_then(Value::as_array_mut);

            for call in calls.into_iter().flatten() {
                let tool = call["index"].as_u64();
                if let Some(arguments) = call
                    .get_mut("function")
                    .and_then(|function| function.get_mut("arguments"))
                {
                    changed |= self.apply(
                        Channel::Choice(index, tool),
                        arguments,
                        true,
                        finished,
                        None,
                        vault,
                    );
                }
            }

            if finished {
                changed |= self.drain_choice(index, choice);
            }
        }

        Outcome {
            changed,
            flushed: Vec::new(),
        }
    }

    fn drain_choice(&mut self, index: u64, choice: &mut Value) -> bool {
        let channels: Vec<Channel> = self
            .channels
            .keys()
            .filter(|channel| matches!(channel, Channel::Choice(choice, _) if *choice == index))
            .cloned()
            .collect();

        let mut changed = false;
        for channel in channels {
            let Some(pending) = self.channels.remove(&channel) else {
                continue;
            };
            if pending.tail.is_empty() {
                continue;
            }
            let Some(choice) = choice.as_object_mut() else {
                continue;
            };

            let delta = choice.entry("delta").or_insert_with(|| json!({}));
            let Some(delta) = delta.as_object_mut() else {
                continue;
            };
            match channel {
                Channel::Choice(_, None) => {
                    let existing = delta
                        .get("content")
                        .and_then(Value::as_str)
                        .unwrap_or_default();

                    let content = format!("{}{existing}", pending.tail);
                    delta.insert("content".to_owned(), Value::String(content));
                }

                Channel::Choice(_, Some(tool)) => {
                    let call = json!({ "index": tool, "function": { "arguments": pending.tail } });
                    match delta.get_mut("tool_calls").and_then(Value::as_array_mut) {
                        Some(calls) => calls.push(call),
                        None => {
                            delta.insert("tool_calls".to_owned(), json!([call]));
                        }
                    }
                }

                _ => continue,
            }

            changed = true;
        }

        changed
    }

    fn gemini(&mut self, event: &mut Value, vault: &Vault) -> Outcome {
        let mut changed = false;
        let Some(candidates) = event.get_mut("candidates").and_then(Value::as_array_mut) else {
            return Outcome {
                changed: restore_value(event, vault),
                flushed: Vec::new(),
            };
        };

        for candidate in candidates
            .iter_mut()
            .filter(|candidate| candidate.is_object())
        {
            let channel = Channel::Candidate(candidate["index"].as_u64().unwrap_or(0));
            let finished = !candidate["finishReason"].is_null();
            let parts = candidate
                .get_mut("content")
                .and_then(|content| content.get_mut("parts"))
                .and_then(Value::as_array_mut);

            let mut parts = parts
                .map(|parts| {
                    parts
                        .iter_mut()
                        .filter(|part| part["thought"].as_bool() != Some(true))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();

            let last_text = parts.iter().rposition(|part| part["text"].is_string());
            for (position, part) in parts.iter_mut().enumerate() {
                match part.get_mut("text") {
                    Some(text) => {
                        changed |= self.apply(
                            channel.clone(),
                            text,
                            false,
                            finished && Some(position) == last_text,
                            None,
                            vault,
                        );
                    }

                    None => changed |= restore_value(part, vault),
                }
            }

            if finished
                && let Some(pending) = self.channels.remove(&channel)
                && !pending.tail.is_empty()
            {
                let content = candidate
                    .as_object_mut()
                    .expect("filtered to objects")
                    .entry("content")
                    .or_insert_with(|| json!({ "role": "model" }));

                if let Some(content) = content.as_object_mut() {
                    let parts = content.entry("parts").or_insert_with(|| json!([]));
                    if let Some(parts) = parts.as_array_mut() {
                        parts.push(json!({ "text": pending.tail }));
                        changed = true;
                    }
                }
            }
        }

        Outcome {
            changed,
            flushed: Vec::new(),
        }
    }

    fn apply(
        &mut self,
        channel: Channel,
        value: &mut Value,
        json_text: bool,
        last: bool,
        template: Option<Value>,
        vault: &Vault,
    ) -> bool {
        let Value::String(fragment) = value else {
            return false;
        };

        let pending = self.channels.entry(channel).or_insert_with(|| Pending {
            tail: String::new(),
            json_text,
            template: None,
        });

        if template.is_some() {
            pending.template = template;
        }

        let mut text = std::mem::take(&mut pending.tail);
        text.push_str(fragment);
        let held = if last {
            0
        } else {
            placeholder::partial_suffix_len(text.as_bytes())
        };

        pending.tail = text.split_off(text.len() - held);

        let restored = restore_text(&text, vault, json_text).unwrap_or(text);
        if restored == *fragment {
            return false;
        }

        *fragment = restored;
        true
    }

    fn flush(&mut self, selected: impl Fn(&Channel) -> bool) -> Vec<Value> {
        let channels: Vec<Channel> = self
            .channels
            .keys()
            .filter(|channel| selected(channel))
            .cloned()
            .collect();

        let mut events = Vec::new();
        for channel in channels {
            let Some(pending) = self.channels.remove(&channel) else {
                continue;
            };
            if pending.tail.is_empty() {
                continue;
            }

            match (&channel, pending.template) {
                (Channel::Block(index), _) => {
                    let (kind, field) = if pending.json_text {
                        ("input_json_delta", "partial_json")
                    } else {
                        ("text_delta", "text")
                    };

                    events.push(json!({ "type": "content_block_delta", "index": index, "delta": { "type": kind, field: pending.tail } }));
                }

                (Channel::Item(..), Some(mut template)) => {
                    template["delta"] = Value::String(pending.tail);
                    if template.get("logprobs").is_some() {
                        template["logprobs"] = json!([]);
                    }
                    events.push(template);
                }

                _ => {}
            }
        }

        events
    }
}

fn flushes_responses(kind: &[u8]) -> bool {
    !kind.starts_with(b"response.reasoning")
        && (kind.ends_with(b".done")
            || matches!(
                kind,
                b"response.completed" | b"response.incomplete" | b"response.failed" | b"error"
            ))
}

fn render(events: &[Value], framed: bool) -> Vec<u8> {
    let mut out = Vec::new();
    for event in events {
        let data = serde_json::to_vec(event).expect("a JSON value serializes");
        if framed {
            out.extend_from_slice(b"event: ");
            out.extend_from_slice(event["type"].as_str().unwrap_or_default().as_bytes());
            out.extend_from_slice(b"\ndata: ");
            out.extend_from_slice(&data);
            out.extend_from_slice(b"\n\n");
        } else {
            out.extend_from_slice(&data);
            out.push(b'\n');
        }
    }

    out
}

pub fn restore_value(value: &mut Value, vault: &Vault) -> bool {
    restore_within(value, vault, false, false)
}

fn restore_within(value: &mut Value, vault: &Vault, json_text: bool, payload: bool) -> bool {
    match value {
        Value::Object(members) => {
            let kind = members.get("type").and_then(Value::as_str);
            let thought = members.get("thought").and_then(Value::as_bool) == Some(true);
            if !payload && (thought || kind.is_some_and(fields::is_signed_type)) {
                return false;
            }

            let tool = members.keys().any(|key| fields::identifies_a_tool(key));
            members
                .iter_mut()
                .filter(|(key, _)| payload || !fields::is_verified_key(key))
                .fold(false, |changed, (key, member)| {
                    let inner = payload || (tool && fields::opens_payload(key));
                    restore_within(member, vault, fields::holds_json_text(key), inner) | changed
                })
        }

        Value::Array(items) => items.iter_mut().fold(false, |changed, item| {
            restore_within(item, vault, false, payload) | changed
        }),

        Value::String(text) => match restore_text(text, vault, json_text) {
            Some(restored) => {
                *text = restored;
                true
            }

            None => false,
        },

        _ => false,
    }
}

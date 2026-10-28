use std::sync::LazyLock;

use serde_json::{Value, json};

use crate::fields::Format;
use crate::json;
use crate::placeholder::Key;
use crate::redact::{NOTICE, redact};
use crate::restore::restore;
use crate::scanner::Scanner;
use crate::stream::{Chunk, Streams};
use crate::testing::{ALNUM, Fake, github_token, password};
use crate::vault::Vault;

static SCANNER: LazyLock<Scanner> = LazyLock::new(Scanner::embedded);

fn vault() -> Vault {
    Vault::new(Key::fixed(42))
}

fn redact_json(vault: &Vault, format: Format, body: &Value) -> Value {
    let bytes = serde_json::to_vec(body).unwrap();
    let redacted = redact(&bytes, format, &SCANNER, vault, true)
        .unwrap()
        .expect("the body carries a secret");

    serde_json::from_slice(&redacted.body).unwrap()
}

fn redact_bytes(vault: &Vault, format: Format, body: &[u8]) -> Option<Vec<u8>> {
    redact(body, format, &SCANNER, vault, true)
        .unwrap()
        .map(|redacted| redacted.body)
}

fn placeholder(vault: &Vault, value: &str) -> String {
    vault.placeholder(value).to_string()
}

#[test]
fn claude_requests_hide_secrets_and_keep_signed_blocks() {
    let vault = vault();
    let (token, pw) = (github_token(1), password(2));
    let earlier = placeholder(&vault, "Earlier-Secret-77");
    let body = json!({
        "model": "claude-sonnet-5-5",
        "system": [{ "type": "text", "text": "You are helpful.", "cache_control": { "type": "ephemeral" } }],
        "messages": [
            { "role": "user", "content": "read my env" },
            { "role": "assistant", "content": [
                { "type": "thinking", "thinking": format!("the old value was {earlier}"), "signature": "c2lnbmF0dXJl" },
                { "type": "tool_use", "id": "toolu_01", "name": "bash", "input": { "command": "cat .env" } }
            ] },
            { "role": "user", "content": [
                { "type": "tool_result", "tool_use_id": "toolu_01", "content": format!("NODE_ENV=production\nGITHUB_TOKEN={token}\nDB_PASSWORD={pw}\n") }
            ] }
        ]
    });

    let input = serde_json::to_vec(&body).unwrap();
    let redacted: Value =
        serde_json::from_slice(&redact_bytes(&vault, Format::Claude, &input).unwrap()).unwrap();

    let result = redacted["messages"][2]["content"][0]["content"]
        .as_str()
        .unwrap();

    let expected = format!(
        "NODE_ENV=production\nGITHUB_TOKEN={}\nDB_PASSWORD={}\n",
        placeholder(&vault, &token),
        placeholder(&vault, &pw)
    );

    assert_eq!(result, expected);
    assert_eq!(redacted["messages"][1], body["messages"][1]);
    assert_eq!(redacted["system"][0], body["system"][0]);
    assert_eq!(
        redacted["system"][1],
        json!({ "type": "text", "text": NOTICE })
    );

    let without_notice = redact(&input, Format::Claude, &SCANNER, &vault, false)
        .unwrap()
        .unwrap()
        .body;

    let first_change = input
        .iter()
        .zip(&without_notice)
        .position(|(a, b)| a != b)
        .unwrap();

    let first_secret = String::from_utf8_lossy(&input).find(&token).unwrap();
    assert_eq!(
        first_change, first_secret,
        "bytes before the first secret changed"
    );
}

#[test]
fn redaction_is_deterministic_and_idempotent() {
    let vault = vault();
    let body = serde_json::to_vec(&json!({ "messages": [{ "role": "user", "content": format!("export GITHUB_TOKEN={}", github_token(3)) }] })).unwrap();

    let once = redact_bytes(&vault, Format::Claude, &body).unwrap();
    assert_eq!(redact_bytes(&vault, Format::Claude, &body).unwrap(), once);
    assert_eq!(redact_bytes(&vault, Format::Claude, &once), None);
}

#[test]
fn replayed_history_gets_the_same_placeholders() {
    let vault = vault();
    let key = Fake(9).take(ALNUM, 40);
    let first = redact_json(
        &vault,
        Format::Claude,
        &json!({ "messages": [
        { "role": "user", "content": [{ "type": "tool_result", "tool_use_id": "toolu_01", "content": format!("SERVICE_TOKEN={key}") }] }
    ] }),
    );

    let reference = placeholder(&vault, &key);
    assert!(first.to_string().contains(&reference));

    let replay = redact_json(
        &vault,
        Format::Claude,
        &json!({ "messages": [
        { "role": "assistant", "content": [{ "type": "tool_use", "id": "toolu_02", "name": "bash", "input": { "command": format!("deploy --with {key}") } }] },
        { "role": "user", "content": format!("did {key} work?") }
    ] }),
    );

    assert_eq!(
        replay["messages"][0]["content"][0]["input"]["command"],
        format!("deploy --with {reference}")
    );

    assert_eq!(
        replay["messages"][1]["content"],
        format!("did {reference} work?")
    );
}

#[test]
fn values_found_once_are_replaced_everywhere_in_the_same_body() {
    let vault = vault();
    let key = Fake(11).take(ALNUM, 40);
    let redacted = redact_json(
        &vault,
        Format::Claude,
        &json!({ "messages": [
        { "role": "user", "content": format!("is {key} still valid?") },
        { "role": "user", "content": format!("API_TOKEN={key}") }
    ] }),
    );

    let reference = placeholder(&vault, &key);
    assert_eq!(
        redacted["messages"][0]["content"],
        format!("is {reference} still valid?")
    );

    assert_eq!(
        redacted["messages"][1]["content"],
        format!("API_TOKEN={reference}")
    );
}

#[test]
fn a_full_vault_still_replaces_every_copy_of_a_new_value() {
    let vault = Vault::with_capacity(Key::fixed(42), 16);
    for index in 0..16 {
        vault.placeholder(&format!("filler-{index:04}"));
    }

    let key = Fake(11).take(ALNUM, 40);
    let redacted = redact_json(
        &vault,
        Format::Claude,
        &json!({ "messages": [
        { "role": "user", "content": format!("is {key} still valid?") },
        { "role": "user", "content": format!("API_TOKEN={key}") }
    ] }),
    );

    assert_eq!(
        redacted["messages"][0]["content"],
        format!("is {} still valid?", placeholder(&vault, &key))
    );
}

#[test]
fn tool_arguments_stay_valid_json() {
    let vault = vault();
    let pw = password(4);
    let arguments =
        serde_json::to_string(&json!({ "cmd": format!("export DB_PASSWORD={pw}") })).unwrap();

    let redacted = redact_json(
        &vault,
        Format::Responses,
        &json!({ "input": [
        { "type": "function_call", "call_id": "call_1", "name": "shell", "arguments": arguments }
    ] }),
    );

    let arguments: Value =
        serde_json::from_str(redacted["input"][0]["arguments"].as_str().unwrap()).unwrap();

    assert_eq!(
        arguments["cmd"],
        format!("export DB_PASSWORD={}", placeholder(&vault, &pw))
    );
}

#[test]
fn nested_tool_arguments_share_one_depth_limit() {
    let pw = password(4);
    let nest = |levels: usize, arrays: usize| {
        let mut arguments = json!({ "cmd": format!("export DB_PASSWORD={pw}") });
        for _ in 0..levels {
            for _ in 0..arrays {
                arguments = json!([arguments]);
            }
            arguments = json!({ "arguments": serde_json::to_string(&arguments).unwrap() });
        }

        serde_json::to_vec(&json!({ "input": [
            { "type": "function_call", "call_id": "call_1", "name": "shell", "arguments": arguments["arguments"] }
        ] }))
        .unwrap()
    };

    let (shallow, deep) = (nest(4, 10), nest(16, 100));

    let (shallow, deep) = std::thread::Builder::new()
        .stack_size(512 * 1024)
        .spawn(move || {
            let vault = vault();
            (
                redact(&shallow, Format::Responses, &SCANNER, &vault, false),
                redact(&deep, Format::Responses, &SCANNER, &vault, false),
            )
        })
        .unwrap()
        .join()
        .unwrap();

    let shallow = shallow.unwrap().expect("the body carries a secret").body;
    assert!(memchr::memmem::find(&shallow, pw.as_bytes()).is_none());
    assert!(matches!(deep, Err(json::Error::TooDeep)));
}

#[test]
fn secrets_in_object_keys_round_trip() {
    let vault = vault();
    let token = github_token(12);
    let redacted = redact_json(
        &vault,
        Format::Claude,
        &json!({ "messages": [
        { "role": "user", "content": [{ "type": "tool_result", "tool_use_id": "toolu_01", "content": "ok" }] },
        { "role": "assistant", "content": [{ "type": "tool_use", "id": "toolu_02", "name": "revoke", "input": { "tokens": { token.clone(): { "scopes": ["repo"] } } } }] }
    ] }),
    );

    let reference = placeholder(&vault, &token);

    assert!(!redacted.to_string().contains(&token));
    assert_eq!(
        redacted["messages"][1]["content"][0]["input"]["tokens"][&reference]["scopes"][0],
        "repo"
    );

    let body = serde_json::to_vec(&json!({ "type": "message", "role": "assistant", "content": [
        { "type": "tool_use", "id": "toolu_03", "name": "revoke", "input": { "tokens": { reference.clone(): true } } }
    ] }))
    .unwrap();

    let restored: Value = serde_json::from_slice(&restore(&body, &vault).unwrap()).unwrap();
    assert_eq!(restored["content"][0]["input"]["tokens"][&token], true);
}

#[test]
fn long_base64_assignments_are_not_blobs() {
    let vault = vault();
    let encoded = Fake(13).take(&[ALNUM, b"+/"].concat(), 3000);
    let redacted = redact_json(
        &vault,
        Format::Claude,
        &json!({ "messages": [
        { "role": "user", "content": [{ "type": "tool_result", "tool_use_id": "toolu_01", "content": format!("GOOGLE_CREDENTIALS_B64={encoded}") }] }
    ] }),
    );

    assert_eq!(
        redacted["messages"][0]["content"][0]["content"],
        format!("GOOGLE_CREDENTIALS_B64={}", placeholder(&vault, &encoded))
    );
}

#[test]
fn the_notice_lands_in_every_format() {
    let secret = format!("export GITHUB_TOKEN={}", github_token(5));
    let notice_after = |text: &str| format!("{text}\n\n{NOTICE}");

    let responses = redact_json(&vault(), Format::Responses, &json!({ "input": secret }));
    assert_eq!(responses["instructions"], NOTICE);
    let responses = redact_json(
        &vault(),
        Format::Responses,
        &json!({ "instructions": "Be brief.", "input": secret }),
    );

    assert_eq!(responses["instructions"], notice_after("Be brief."));

    let chat = redact_json(
        &vault(),
        Format::Chat,
        &json!({ "messages": [{ "role": "user", "content": secret }] }),
    );

    assert_eq!(
        chat["messages"][0],
        json!({ "role": "system", "content": NOTICE })
    );

    let chat = redact_json(
        &vault(),
        Format::Chat,
        &json!({ "messages": [{ "role": "developer", "content": "Be brief." }, { "role": "user", "content": secret }] }),
    );

    assert_eq!(chat["messages"][0]["content"], notice_after("Be brief."));

    let gemini = redact_json(
        &vault(),
        Format::Gemini,
        &json!({ "contents": [{ "role": "user", "parts": [{ "text": secret }] }] }),
    );

    assert_eq!(
        gemini["systemInstruction"],
        json!({ "parts": [{ "text": NOTICE }] })
    );

    let claude = redact_json(
        &vault(),
        Format::Claude,
        &json!({ "system": "Be brief.", "messages": [{ "role": "user", "content": secret }] }),
    );

    assert_eq!(claude["system"], notice_after("Be brief."));

    let again = redact_json(
        &vault(),
        Format::Claude,
        &json!({ "system": notice_after("Be brief."), "messages": [{ "role": "user", "content": secret }] }),
    );

    assert_eq!(again["system"], notice_after("Be brief."));
}

#[test]
fn clean_and_malformed_bodies() {
    let vault = vault();
    let clean =
        br#"{"messages":[{"role":"user","content":"const apiKey = process.env.OPENAI_API_KEY;"}]}"#;

    assert_eq!(redact_bytes(&vault, Format::Claude, clean), None);
    assert!(
        redact(
            br#"{"messages": [}"#,
            Format::Claude,
            &SCANNER,
            &vault,
            true
        )
        .is_err()
    );
}

#[test]
fn responses_are_restored_outside_signed_blocks() {
    let vault = vault();
    let (token, pw) = (github_token(6), password(7));
    let (token_ref, pw_ref) = (placeholder(&vault, &token), placeholder(&vault, &pw));
    let arguments =
        serde_json::to_string(&json!({ "cmd": format!("login --password {pw_ref}") })).unwrap();

    let body = serde_json::to_vec(&json!({
        "content": [
            { "type": "thinking", "thinking": format!("use {token_ref}"), "signature": "c2ln" },
            { "type": "text", "text": format!("Your token is {token_ref}.") },
            { "type": "tool_use", "id": "toolu_01", "name": "bash", "input": { "command": format!("gh auth login --with-token {token_ref}") } }
        ],
        "output": [{ "type": "function_call", "call_id": "call_1", "name": "shell", "arguments": arguments }],
        "unknown": "redact-0123456789ab"
    }))
    .unwrap();

    let restored: Value = serde_json::from_slice(&restore(&body, &vault).unwrap()).unwrap();
    assert_eq!(
        restored["content"][0]["thinking"],
        format!("use {token_ref}")
    );

    assert_eq!(
        restored["content"][1]["text"],
        format!("Your token is {token}.")
    );

    assert_eq!(
        restored["content"][2]["input"]["command"],
        format!("gh auth login --with-token {token}")
    );

    assert_eq!(restored["unknown"], "redact-0123456789ab");

    let arguments: Value =
        serde_json::from_str(restored["output"][0]["arguments"].as_str().unwrap()).unwrap();

    assert_eq!(arguments["cmd"], format!("login --password {pw}"));
}

#[test]
fn nested_tool_arguments_are_restored_at_their_own_depth() {
    let vault = vault();
    let pw = password(15);
    let inner = serde_json::to_string(
        &json!({ "cmd": format!("login --password {}", placeholder(&vault, &pw)) }),
    )
    .unwrap();

    let arguments = serde_json::to_string(&json!({ "tool": "shell", "arguments": inner })).unwrap();
    let item = json!({ "type": "function_call", "call_id": "call_1", "name": "dispatch", "arguments": arguments });

    let body = serde_json::to_vec(&json!({ "output": [item.clone()] })).unwrap();
    let restored: Value = serde_json::from_slice(&restore(&body, &vault).unwrap()).unwrap();

    let done =
        sse(&json!({ "type": "response.output_item.done", "output_index": 0, "item": item }));

    let streamed = events(&feed(
        &Streams::default(),
        &vault,
        Format::Responses,
        &[done],
    ));

    for arguments in [
        &restored["output"][0]["arguments"],
        &streamed[0]["item"]["arguments"],
    ] {
        let outer: Value = serde_json::from_str(arguments.as_str().unwrap()).unwrap();
        let inner: Value = serde_json::from_str(outer["arguments"].as_str().unwrap()).unwrap();
        assert_eq!(inner["cmd"], format!("login --password {pw}"));
    }
}

fn feed(streams: &Streams, vault: &Vault, format: Format, chunks: &[String]) -> String {
    streams.begin("request", format);

    let mut out = String::new();
    for chunk in chunks {
        match streams.chunk("request", format, chunk.as_bytes(), vault) {
            Chunk::Unchanged => out.push_str(chunk),
            Chunk::Replace(bytes) => out.push_str(&String::from_utf8(bytes).unwrap()),
            Chunk::Hold => {}
        }

        if !chunk.ends_with('\n') {
            out.push('\n');
        }
    }

    streams.end("request");
    out
}

fn events(stream: &str) -> Vec<Value> {
    stream
        .lines()
        .filter_map(|line| {
            line.strip_prefix("data: ")
                .or_else(|| line.starts_with('{').then_some(line))
        })
        .map(|data| serde_json::from_str(data).unwrap())
        .collect()
}

fn sse(event: &Value) -> String {
    format!(
        "event: {}\ndata: {event}\n\n",
        event["type"].as_str().unwrap()
    )
}

fn split(text: &str, at: &[usize]) -> Vec<String> {
    let mut pieces = Vec::new();
    let mut previous = 0;
    for &index in at {
        pieces.push(text[previous..index].to_owned());
        previous = index;
    }

    pieces.push(text[previous..].to_owned());
    pieces
}

#[test]
fn claude_streams_restore_split_placeholders() {
    let vault = vault();
    let (token, pw) = (github_token(8), password(9));
    let text = format!("The token is {}. Done", placeholder(&vault, &token));
    let arguments = serde_json::to_string(
        &json!({ "command": format!("login --password {}", placeholder(&vault, &pw)) }),
    )
    .unwrap();

    let mut chunks = vec![sse(
        &json!({ "type": "content_block_start", "index": 0, "content_block": { "type": "text", "text": "" } }),
    )];

    for piece in split(&text, &[14, 17, 23, 30]) {
        chunks.push(sse(&json!({ "type": "content_block_delta", "index": 0, "delta": { "type": "text_delta", "text": piece } })));
    }

    chunks.push(sse(&json!({ "type": "content_block_stop", "index": 0 })));

    for piece in split(&arguments, &[20, 40, 45]) {
        chunks.push(sse(&json!({ "type": "content_block_delta", "index": 1, "delta": { "type": "input_json_delta", "partial_json": piece } })));
    }

    chunks.push(
        sse(&json!({ "type": "content_block_stop", "index": 1 }))
            + &sse(&json!({ "type": "message_stop" })),
    );

    let events = events(&feed(&Streams::default(), &vault, Format::Claude, &chunks));
    let joined = |index: u64, field: &str| -> String {
        events
            .iter()
            .filter(|event| event["index"] == index && event["type"] == "content_block_delta")
            .map(|event| event["delta"][field].as_str().unwrap())
            .collect()
    };

    assert_eq!(joined(0, "text"), format!("The token is {token}. Done"));
    let input: Value = serde_json::from_str(&joined(1, "partial_json")).unwrap();
    assert_eq!(input["command"], format!("login --password {pw}"));
}

#[test]
fn claude_streams_flush_held_text_before_a_block_stops() {
    let vault = vault();
    vault.placeholder("Earlier-Secret-77");
    let chunks = [
        sse(
            &json!({ "type": "content_block_delta", "index": 0, "delta": { "type": "text_delta", "text": "waiting for r" } }),
        ),
        sse(&json!({ "type": "content_block_stop", "index": 0 })),
    ];

    let output = feed(&Streams::default(), &vault, Format::Claude, &chunks);
    let events = events(&output);
    let text: String = events
        .iter()
        .filter_map(|event| event["delta"]["text"].as_str())
        .collect();

    assert_eq!(text, "waiting for r");
    assert_eq!(events.last().unwrap()["type"], "content_block_stop");

    for block in output.split("\n\n").filter(|block| !block.is_empty()) {
        let (event, data) = block.split_once('\n').unwrap();
        let data: Value = serde_json::from_str(data.strip_prefix("data: ").unwrap()).unwrap();
        assert_eq!(
            event,
            format!("event: {}", data["type"].as_str().unwrap()),
            "{output}"
        );
    }
}

#[test]
fn claude_thinking_passes_through() {
    let vault = vault();
    let reference = placeholder(&vault, "Earlier-Secret-77");
    let chunk = sse(
        &json!({ "type": "content_block_delta", "index": 0, "delta": { "type": "thinking_delta", "thinking": reference } }),
    );

    let streams = Streams::default();
    streams.begin("request", Format::Claude);
    assert_eq!(
        streams.chunk("request", Format::Claude, chunk.as_bytes(), &vault),
        Chunk::Unchanged
    );
}

#[test]
fn responses_streams_hold_split_event_lines() {
    let vault = vault();
    let token = github_token(10);
    let reference = placeholder(&vault, &token);
    let delta = |delta: &str, sequence: u64| json!({ "type": "response.output_text.delta", "item_id": "msg_1", "output_index": 0, "content_index": 0, "delta": delta, "sequence_number": sequence });
    let full = format!("key {reference} end r");

    let mut chunks = Vec::new();
    for (sequence, piece) in (1..).zip(split(&full, &[8, 15])) {
        chunks.push("event: response.output_text.delta".to_owned());
        chunks.push(format!("data: {}", delta(&piece, sequence)));
    }

    chunks.push("event: response.output_text.done".to_owned());
    chunks.push(format!("data: {}", json!({ "type": "response.output_text.done", "item_id": "msg_1", "output_index": 0, "content_index": 0, "text": full, "sequence_number": 9 })));

    let streams = Streams::default();
    let output = feed(&streams, &vault, Format::Responses, &chunks);
    let events = events(&output);
    let deltas: String = events
        .iter()
        .filter(|event| event["type"] == "response.output_text.delta")
        .map(|event| event["delta"].as_str().unwrap())
        .collect();

    let done = events
        .iter()
        .find(|event| event["type"] == "response.output_text.done")
        .unwrap();

    assert_eq!(deltas, format!("key {token} end r"));
    assert_eq!(done["text"], format!("key {token} end r"));
    assert!(
        output.contains("event: response.output_text.delta\ndata: {"),
        "{output}"
    );

    assert!(
        output
            .find("\"type\":\"response.output_text.done\"")
            .unwrap()
            > output.rfind("response.output_text.delta").unwrap()
    );
}

#[test]
fn chat_streams_carry_tails_into_the_next_chunk() {
    let vault = vault();
    let (token, pw) = (github_token(12), password(13));
    let text = format!("use {} now", placeholder(&vault, &token));
    let arguments =
        serde_json::to_string(&json!({ "password": placeholder(&vault, &pw) })).unwrap();

    let mut chunks: Vec<String> = split(&text, &[6, 12]).into_iter().map(|piece| json!({ "choices": [{ "index": 0, "delta": { "content": piece }, "finish_reason": null }] }).to_string()).collect();
    for piece in split(&arguments, &[18, 24]) {
        chunks.push(json!({ "choices": [{ "index": 0, "delta": { "tool_calls": [{ "index": 0, "function": { "arguments": piece } }] }, "finish_reason": null }] }).to_string());
    }

    chunks.push(
        json!({ "choices": [{ "index": 0, "delta": {}, "finish_reason": "tool_calls" }] })
            .to_string(),
    );

    let events = events(&feed(&Streams::default(), &vault, Format::Chat, &chunks));
    let content: String = events
        .iter()
        .filter_map(|event| event["choices"][0]["delta"]["content"].as_str())
        .collect();

    let arguments: String = events
        .iter()
        .filter_map(|event| {
            event["choices"][0]["delta"]["tool_calls"][0]["function"]["arguments"].as_str()
        })
        .collect();

    assert_eq!(content, format!("use {token} now"));
    let arguments: Value = serde_json::from_str(&arguments).unwrap();
    assert_eq!(arguments["password"], pw);
}

#[test]
fn gemini_streams_restore_text_parts() {
    let vault = vault();
    let token = github_token(14);
    let text = format!("token {} r", placeholder(&vault, &token));

    let mut chunks: Vec<String> = split(&text, &[9, 20]).into_iter().map(|piece| json!({ "candidates": [{ "index": 0, "content": { "role": "model", "parts": [{ "text": piece }] } }] }).to_string()).collect();
    chunks.push(json!({ "candidates": [{ "index": 0, "content": { "role": "model", "parts": [] }, "finishReason": "STOP" }] }).to_string());

    let events = events(&feed(&Streams::default(), &vault, Format::Gemini, &chunks));
    let joined: String = events
        .iter()
        .flat_map(|event| {
            event["candidates"][0]["content"]["parts"]
                .as_array()
                .cloned()
                .unwrap_or_default()
        })
        .filter_map(|part| part["text"].as_str().map(str::to_owned))
        .collect();

    assert_eq!(joined, format!("token {token} r"));
}

#[test]
fn streamed_tool_keys_are_restored() {
    let vault = vault();
    let token = github_token(16);
    let chunk = json!({ "candidates": [{ "index": 0, "content": { "role": "model", "parts": [
        { "functionCall": { "name": "revoke", "args": { "tokens": { placeholder(&vault, &token): true } } } }
    ] }, "finishReason": "STOP" }] })
    .to_string();

    let events = events(&feed(&Streams::default(), &vault, Format::Gemini, &[chunk]));
    assert_eq!(
        events[0]["candidates"][0]["content"]["parts"][0]["functionCall"]["args"]["tokens"][&token],
        true
    );
}

#[test]
fn streams_skip_work_while_the_vault_is_empty() {
    let streams = Streams::default();
    let chunk = sse(
        &json!({ "type": "content_block_delta", "index": 0, "delta": { "type": "text_delta", "text": "hello r" } }),
    );

    assert_eq!(
        streams.chunk("request", Format::Claude, chunk.as_bytes(), &vault()),
        Chunk::Unchanged
    );
}

#[test]
fn responses_over_websocket_flush_as_bare_json() {
    let vault = vault();
    let token = github_token(15);
    let full = format!("key {} r", placeholder(&vault, &token));
    let event = |kind: &str, field: &str, value: &str| {
        json!({ "type": kind, "item_id": "msg_1", "output_index": 0, "content_index": 0, field: value }).to_string()
    };

    let mut chunks: Vec<String> = split(&full, &[9, 20])
        .iter()
        .map(|piece| event("response.output_text.delta", "delta", piece))
        .collect();

    chunks.push(event("response.output_text.done", "text", &full));

    let output = feed(&Streams::default(), &vault, Format::Responses, &chunks);
    let events = events(&output);
    let deltas: String = events
        .iter()
        .filter(|event| event["type"] == "response.output_text.delta")
        .map(|event| event["delta"].as_str().unwrap())
        .collect();

    assert_eq!(deltas, format!("key {token} r"));
    assert!(output.lines().all(|line| line.starts_with('{')), "{output}");
    assert_eq!(events.last().unwrap()["text"], format!("key {token} r"));
}

#[test]
fn secrets_under_structural_keys_are_still_replaced() {
    let vault = vault();
    let (token, key) = (github_token(16), Fake(17).take(ALNUM, 40));
    let redacted = redact_json(
        &vault,
        Format::Claude,
        &json!({ "messages": [
        { "role": "assistant", "content": [
            { "type": "thinking", "thinking": "plan", "signature": token.clone() },
            { "type": "tool_use", "id": "toolu_01", "name": "api", "input": { "id": token.clone(), "session": { "type": token.clone(), "session_id": format!("API_TOKEN={key}") } } }
        ] }
    ] }),
    );

    let reference = placeholder(&vault, &token);
    let input = &redacted["messages"][0]["content"][1]["input"];
    assert_eq!(input["id"], reference);
    assert_eq!(input["session"]["type"], reference);
    assert_eq!(
        input["session"]["session_id"],
        format!("API_TOKEN={}", placeholder(&vault, &key))
    );

    assert_eq!(redacted["messages"][0]["content"][0]["signature"], token);
}

#[test]
fn secret_named_keys_are_redacted_in_tool_payloads() {
    let vault = vault();
    let (password, key) = (Fake(18).take(ALNUM, 14), Fake(19).take(ALNUM, 32));
    let arguments =
        serde_json::to_string(&json!({ "host": "db.internal", "password": password })).unwrap();

    let claude = redact_json(
        &vault,
        Format::Claude,
        &json!({ "messages": [{ "role": "assistant", "content": [
        { "type": "tool_use", "id": "toolu_01", "name": "connect", "input": { "host": "db.internal", "password": password } }
    ] }] }),
    );

    let responses = redact_json(
        &vault,
        Format::Responses,
        &json!({ "input": [{ "type": "function_call", "call_id": "call_1", "name": "connect", "arguments": arguments }] }),
    );

    let gemini = redact_json(
        &vault,
        Format::Gemini,
        &json!({ "contents": [{ "role": "user", "parts": [
        { "functionResponse": { "name": "vault_read", "response": { "db_password": password, "apiKey": key } } }
    ] }] }),
    );

    let reference = placeholder(&vault, &password);
    assert_eq!(
        claude["messages"][0]["content"][0]["input"]["password"],
        reference
    );

    assert_eq!(
        claude["messages"][0]["content"][0]["input"]["host"],
        "db.internal"
    );

    let arguments: Value =
        serde_json::from_str(responses["input"][0]["arguments"].as_str().unwrap()).unwrap();

    assert_eq!(arguments["password"], reference);
    let response = &gemini["contents"][0]["parts"][0]["functionResponse"]["response"];
    assert_eq!(response["db_password"], reference);
    assert_eq!(response["apiKey"], placeholder(&vault, &key));
}

#[test]
fn signed_blocks_are_only_skipped_in_the_message_structure() {
    let vault = vault();
    let token = github_token(20);
    let redacted = redact_json(
        &vault,
        Format::Claude,
        &json!({ "messages": [{ "role": "assistant", "content": [
        { "type": "tool_use", "id": "toolu_01", "name": "save", "input": {
            "signature": token,
            "step": { "type": "reasoning", "note": format!("GITHUB_TOKEN={token}") },
            "part": { "thought": true, "text": token }
        } }
    ] }] }),
    );

    let reference = placeholder(&vault, &token);
    let input = &redacted["messages"][0]["content"][0]["input"];
    assert_eq!(input["signature"], reference);
    assert_eq!(input["step"]["note"], format!("GITHUB_TOKEN={reference}"));
    assert_eq!(input["part"]["text"], reference);

    let body = serde_json::to_vec(&json!({ "content": [{ "type": "tool_use", "id": "toolu_02", "name": "save", "input": { "signature": reference } }] })).unwrap();
    let restored: Value = serde_json::from_slice(&restore(&body, &vault).unwrap()).unwrap();
    assert_eq!(restored["content"][0]["input"]["signature"], token);
}

#[test]
fn continued_codex_turns_keep_the_notice() {
    let vault = vault();
    vault.placeholder("Earlier-Secret-77");
    let body = serde_json::to_vec(&json!({ "previous_response_id": "resp_1", "input": [{ "type": "message", "role": "user", "content": "next step" }] })).unwrap();

    let redacted: Value =
        serde_json::from_slice(&redact_bytes(&vault, Format::Responses, &body).unwrap()).unwrap();

    assert_eq!(redacted["instructions"], NOTICE);
    assert_eq!(
        redact_bytes(&Vault::new(Key::fixed(1)), Format::Responses, &body),
        None
    );
}

#[test]
fn placeholders_glued_to_a_word_are_restored_in_streams() {
    let vault = vault();
    let token = github_token(21);
    let text = format!("prefix{} end", placeholder(&vault, &token));
    let chunks: Vec<String> = split(&text, &[9, 16])
        .iter()
        .map(|piece| sse(&json!({ "type": "content_block_delta", "index": 0, "delta": { "type": "text_delta", "text": piece } })))
        .chain([sse(&json!({ "type": "content_block_stop", "index": 0 }))])
        .collect();

    let events = events(&feed(&Streams::default(), &vault, Format::Claude, &chunks));
    let joined: String = events
        .iter()
        .filter_map(|event| event["delta"]["text"].as_str())
        .collect();

    assert_eq!(joined, format!("prefix{token} end"));
}

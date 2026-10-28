use std::time::Instant;

use serde_json::json;

use crate::fields::Format;
use crate::placeholder::Key;
use crate::redact::redact;
use crate::scanner::Scanner;
use crate::testing::github_token;
use crate::vault::Vault;

const CLEAN: &str = include_str!("../tests/corpus/clean.txt");

fn session(bytes: usize) -> Vec<u8> {
    let mut messages = Vec::new();
    let mut size = 0;
    for turn in 0u64.. {
        let output = format!(
            "{CLEAN}\nSERVICE_TOKEN={}\n{CLEAN}",
            github_token(turn % 16)
        );

        size += output.len();
        messages.push(json!({ "role": "user", "content": [{ "type": "tool_result", "tool_use_id": format!("toolu_{turn}"), "content": output }] }));
        messages.push(json!({ "role": "assistant", "content": [{ "type": "text", "text": "Looking at the next file." }] }));
        if size >= bytes {
            break;
        }
    }

    serde_json::to_vec(&json!({ "model": "claude-sonnet-5-5", "system": "You are a coding agent.", "messages": messages })).unwrap()
}

#[test]
#[ignore = "run with cargo test --release -- --ignored"]
fn throughput() {
    let scanner = Scanner::embedded();
    let body = session(2 << 20);
    for (label, vault) in [
        ("first sight", Vault::new(Key::fixed(1))),
        ("replayed", Vault::new(Key::fixed(2))),
    ] {
        if label == "replayed" {
            redact(&body, Format::Claude, &scanner, &vault, true).unwrap();
        }

        let started = Instant::now();
        redact(&body, Format::Claude, &scanner, &vault, true).unwrap();
        let elapsed = started.elapsed();

        let megabytes = f64::from(u32::try_from(body.len()).unwrap()) / f64::from(1 << 20);
        println!(
            "{label}: {megabytes:.1} MiB in {elapsed:.1?} ({:.0} MiB/s)",
            megabytes / elapsed.as_secs_f64()
        );
    }
}

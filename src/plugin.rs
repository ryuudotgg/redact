use std::panic::{self, AssertUnwindSafe};
use std::sync::{Arc, PoisonError, RwLock};

use serde_json::{Value, json};

use crate::config::Config;
use crate::fields::Format;
use crate::host::{Host, Level};
use crate::json;
use crate::protocol::{self, Exchange, Lifecycle};
use crate::redact::redact;
use crate::restore::restore;
use crate::rules::{self, RuleSet};
use crate::scanner::Scanner;
use crate::stream::{Chunk, Streams};
use crate::vault::Vault;

pub struct Plugin {
    host: Host,
    vault: Arc<Vault>,
    engine: RwLock<Option<Arc<Engine>>>,
    streams: Streams,
}

struct Engine {
    scanner: Scanner,
    notice: bool,
}

impl Plugin {
    pub fn new(host: Host, vault: Arc<Vault>) -> Self {
        Self {
            host,
            vault,
            engine: RwLock::new(None),
            streams: Streams::default(),
        }
    }

    pub fn call(&self, method: &str, request: &[u8]) -> Value {
        let reply = panic::catch_unwind(AssertUnwindSafe(|| self.dispatch(method, request)));
        reply.unwrap_or_else(|_| {
            self.host.log(
                Level::Error,
                "redact failed while handling a call",
                json!({ "method": method }),
                "",
            );

            if method == "request.intercept_before" {
                protocol::reject(
                    500,
                    "redact could not scan this request, so it was not sent",
                )
            } else {
                protocol::error("internal", "redact failed while handling this call")
            }
        })
    }

    fn dispatch(&self, method: &str, request: &[u8]) -> Value {
        match method {
            "plugin.register" | "plugin.reconfigure" => self.configure(request),
            "request.intercept_before" => self.redact_request(request),
            "response.intercept_after" => self.restore_response(request),
            "response.intercept_stream_chunk" => self.restore_chunk(request),
            "request.complete" => self.complete(request),
            "request.intercept_after" | "plugin.quiesce" => protocol::unchanged(),
            _ => protocol::error(
                "unknown_method",
                &format!("redact does not handle {method}"),
            ),
        }
    }

    fn configure(&self, request: &[u8]) -> Value {
        let config = serde_json::from_slice::<Lifecycle>(request)
            .map_err(|error| error.to_string())
            .and_then(|lifecycle| Config::parse(&lifecycle.config_yaml));

        let engine = config.and_then(|config| {
            for key in config.unknown_keys() {
                self.host.log(
                    Level::Warn,
                    "redact ignores an unknown config key",
                    json!({ "key": key }),
                    "",
                );
            }

            Engine::build(&config)
        });

        let mut current = self.engine.write().unwrap_or_else(PoisonError::into_inner);
        match engine {
            Ok(engine) => {
                for id in engine.scanner.rules().unknown_disabled() {
                    self.host.log(
                        Level::Warn,
                        "redact has no rule with a disabled id",
                        json!({ "rule": id }),
                        "",
                    );
                }

                let (loaded, skipped) = (
                    engine.scanner.rules().len(),
                    engine.scanner.rules().skipped().len(),
                );

                self.host.log(
                    Level::Info,
                    "redact is ready",
                    json!({ "rules": loaded, "skipped_rules": skipped }),
                    "",
                );

                *current = Some(Arc::new(engine));
            }

            Err(error) if current.is_some() => {
                self.host.log(
                    Level::Error,
                    "redact rejected its new config and keeps the previous one",
                    json!({ "error": error }),
                    "",
                );
            }

            Err(error) => {
                self.host.log(
                    Level::Error,
                    "redact rejected its config and uses the embedded rules",
                    json!({ "error": error }),
                    "",
                );

                *current = Some(Arc::new(Engine::embedded()));
            }
        }

        protocol::registration()
    }

    fn engine(&self) -> Arc<Engine> {
        if let Some(engine) = &*self.engine.read().unwrap_or_else(PoisonError::into_inner) {
            return Arc::clone(engine);
        }

        let mut current = self.engine.write().unwrap_or_else(PoisonError::into_inner);
        Arc::clone(current.get_or_insert_with(|| Arc::new(Engine::embedded())))
    }

    fn redact_request(&self, request: &[u8]) -> Value {
        let Ok(exchange) = serde_json::from_slice::<Exchange>(request) else {
            return protocol::reject(
                500,
                "redact could not read this request, so it was not sent",
            );
        };

        let body = exchange
            .body
            .strip_prefix(BYTE_ORDER_MARK)
            .unwrap_or(&exchange.body);

        let engine = self.engine();
        if !looks_like_json(body) {
            let text = String::from_utf8_lossy(body);
            let known = self.vault.known();
            if engine
                .scanner
                .find(&text, known.as_deref(), &self.vault)
                .is_empty()
            {
                return protocol::unchanged();
            }

            self.host.log(
                Level::Warn,
                "redact rejected a request body that is not JSON and holds a secret",
                json!({}),
                &exchange.callback,
            );

            return protocol::reject(
                400,
                "redact found a secret in a request body it cannot rewrite, so it was not sent",
            );
        }

        let format = Format::from_source(&exchange.source_format);
        match redact(body, format, &engine.scanner, &self.vault, engine.notice) {
            Ok(Some(redacted)) => {
                let fields = json!({ "values": redacted.values, "format": exchange.source_format });
                self.host.log(
                    Level::Debug,
                    "redact replaced secrets in a request",
                    fields,
                    &exchange.callback,
                );

                protocol::body(&redacted.body)
            }

            Ok(None) => protocol::unchanged(),
            Err(json::Error::TooDeep) => {
                self.host.log(
                    Level::Warn,
                    "redact rejected a request body nested too deeply to scan",
                    json!({}),
                    &exchange.callback,
                );

                protocol::reject(
                    400,
                    "redact could not scan the request body because it is nested too deeply, so it was not sent",
                )
            }

            Err(json::Error::Syntax(_)) => {
                self.host.log(
                    Level::Warn,
                    "redact rejected a request body that is not valid JSON",
                    json!({}),
                    &exchange.callback,
                );

                protocol::reject(
                    400,
                    "redact could not parse the request body as JSON, so it was not sent",
                )
            }
        }
    }

    fn restore_response(&self, request: &[u8]) -> Value {
        let Ok(exchange) = serde_json::from_slice::<Exchange>(request) else {
            return protocol::unchanged();
        };

        match restore(&exchange.body, &self.vault) {
            Some(body) => protocol::body(&body),
            None => protocol::unchanged(),
        }
    }

    fn restore_chunk(&self, request: &[u8]) -> Value {
        let Ok(exchange) = serde_json::from_slice::<Exchange>(request) else {
            return protocol::unchanged();
        };

        let format = Format::from_source(&exchange.source_format);
        if exchange.chunk_index == protocol::HEADER_CHUNK {
            self.streams.begin(&exchange.request_id, format);
            return protocol::unchanged();
        }

        match self
            .streams
            .chunk(&exchange.request_id, format, &exchange.body, &self.vault)
        {
            Chunk::Unchanged => protocol::unchanged(),
            Chunk::Replace(body) => protocol::body(&body),
            Chunk::Hold => protocol::drop_chunk(),
        }
    }

    fn complete(&self, request: &[u8]) -> Value {
        if let Ok(exchange) = serde_json::from_slice::<Exchange>(request) {
            self.streams.end(&exchange.request_id);
        }

        protocol::unchanged()
    }
}

impl Engine {
    fn build(config: &Config) -> Result<Self, String> {
        let document = match &config.rules_file {
            Some(path) if !path.is_absolute() => {
                return Err(format!(
                    "rules_file must be an absolute path, not {}",
                    path.display()
                ));
            }

            Some(path) => std::fs::read_to_string(path)
                .map_err(|error| format!("cannot read {}: {error}", path.display()))?,

            None => rules::EMBEDDED.to_owned(),
        };

        let rules =
            RuleSet::load(&document, &config.disabled_rules).map_err(|error| error.to_string())?;

        Ok(Self {
            scanner: Scanner::new(rules, &config.allow)?,
            notice: config.notice(),
        })
    }

    fn embedded() -> Self {
        Self {
            scanner: Scanner::embedded(),
            notice: true,
        }
    }
}

const BYTE_ORDER_MARK: &[u8] = b"\xef\xbb\xbf";

fn looks_like_json(body: &[u8]) -> bool {
    matches!(
        body.iter().find(|byte| !byte.is_ascii_whitespace()),
        Some(b'{' | b'[')
    )
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;

    use super::*;
    use crate::placeholder::Key;
    use crate::testing::github_token;

    fn exchange(body: &[u8], chunk: i64) -> Vec<u8> {
        serde_json::to_vec(&json!({ "RequestID": "r1", "SourceFormat": "claude", "Body": STANDARD.encode(body), "ChunkIndex": chunk })).unwrap()
    }

    fn decoded_body(reply: &Value, field: &str) -> Vec<u8> {
        STANDARD
            .decode(reply["result"][field].as_str().unwrap())
            .unwrap()
    }

    #[test]
    fn registers_with_capabilities_and_metadata() {
        let plugin = Plugin::new(Host::detached(), Arc::new(Vault::new(Key::random())));
        let config = STANDARD.encode(
            "enabled: true\npriority: 0\nnotice: false\ndisabled_rules: [generic-api-key]\n",
        );

        let reply = plugin.call(
            "plugin.register",
            json!({ "config_yaml": config, "schema_version": 7 })
                .to_string()
                .as_bytes(),
        );

        assert_eq!(reply["ok"], true);
        assert_eq!(reply["result"]["schema_version"], 7);
        assert_eq!(reply["result"]["metadata"]["Name"], "redact");
        assert_eq!(reply["result"]["capabilities"]["request_interceptor"], true);
        assert!(!plugin.engine().notice);
    }

    #[test]
    fn a_broken_config_still_redacts() {
        let plugin = Plugin::new(Host::detached(), Arc::new(Vault::new(Key::random())));
        let config = STANDARD.encode("rules_file: /nonexistent/rules.toml\n");
        plugin.call(
            "plugin.register",
            json!({ "config_yaml": config }).to_string().as_bytes(),
        );

        let body = json!({ "messages": [{ "role": "user", "content": format!("export GITHUB_TOKEN={}", github_token(1)) }] }).to_string();
        let reply = plugin.call("request.intercept_before", &exchange(body.as_bytes(), 0));
        assert!(
            !String::from_utf8(decoded_body(&reply, "Body"))
                .unwrap()
                .contains(&github_token(1))
        );
    }

    #[test]
    fn an_empty_rules_file_keeps_the_rest_of_the_config() {
        let plugin = Plugin::new(Host::detached(), Arc::new(Vault::new(Key::random())));
        let config = STANDARD.encode("rules_file: \"\"\nnotice: false\n");
        plugin.call(
            "plugin.register",
            json!({ "config_yaml": config }).to_string().as_bytes(),
        );

        assert!(!plugin.engine().notice);
    }

    #[test]
    fn rejects_requests_it_cannot_parse() {
        let plugin = Plugin::new(Host::detached(), Arc::new(Vault::new(Key::random())));
        let reply = plugin.call(
            "request.intercept_before",
            &exchange(br#"{"messages": ["#, 0),
        );

        assert_eq!(reply["result"]["Terminate"], true);
        assert_eq!(reply["result"]["StatusCode"], 400);
    }

    #[test]
    fn passes_bodies_that_are_not_json() {
        let plugin = Plugin::new(Host::detached(), Arc::new(Vault::new(Key::random())));
        let reply = plugin.call(
            "request.intercept_before",
            &exchange(b"--boundary\r\nContent-Disposition: form-data", 0),
        );

        assert_eq!(reply, protocol::unchanged());
    }

    #[test]
    fn rejects_bodies_that_are_not_json_but_hold_a_secret() {
        let plugin = Plugin::new(Host::detached(), Arc::new(Vault::new(Key::random())));
        let body = format!(
            "x{}",
            json!({ "messages": [{ "role": "user", "content": format!("export GITHUB_TOKEN={}", github_token(1)) }] })
        );

        let reply = plugin.call("request.intercept_before", &exchange(body.as_bytes(), 0));

        assert_eq!(reply["result"]["Terminate"], true);
        assert_eq!(reply["result"]["StatusCode"], 400);
    }

    #[test]
    fn round_trips_through_the_plugin() {
        let plugin = Plugin::new(Host::detached(), Arc::new(Vault::new(Key::random())));
        let token = github_token(2);
        let body =
            json!({ "messages": [{ "role": "user", "content": format!("GITHUB_TOKEN={token}") }] })
                .to_string();

        let redacted = decoded_body(
            &plugin.call("request.intercept_before", &exchange(body.as_bytes(), 0)),
            "Body",
        );

        let upstream: Value = serde_json::from_slice(&redacted).unwrap();
        let reference = upstream["messages"][0]["content"]
            .as_str()
            .unwrap()
            .trim_start_matches("GITHUB_TOKEN=")
            .to_owned();

        let response =
            json!({ "content": [{ "type": "text", "text": format!("Token: {reference}") }] })
                .to_string();

        let restored = decoded_body(
            &plugin.call(
                "response.intercept_after",
                &exchange(response.as_bytes(), 0),
            ),
            "Body",
        );

        assert_eq!(
            serde_json::from_slice::<Value>(&restored).unwrap()["content"][0]["text"],
            format!("Token: {token}")
        );

        assert_eq!(
            plugin.call(
                "response.intercept_stream_chunk",
                &exchange(b"", protocol::HEADER_CHUNK)
            ),
            protocol::unchanged()
        );

        assert_eq!(
            plugin.call("request.complete", &exchange(b"", 0)),
            protocol::unchanged()
        );
    }

    #[test]
    fn redacts_bodies_that_start_with_a_byte_order_mark() {
        let plugin = Plugin::new(Host::detached(), Arc::new(Vault::new(Key::random())));
        let token = github_token(3);
        let body = [
            &b"\xef\xbb\xbf"[..],
            json!({ "messages": [{ "role": "user", "content": format!("GITHUB_TOKEN={token}") }] })
                .to_string()
                .as_bytes(),
        ]
        .concat();

        let reply = plugin.call("request.intercept_before", &exchange(&body, 0));
        let upstream = String::from_utf8(decoded_body(&reply, "Body")).unwrap();
        assert!(!upstream.contains(&token));
    }

    #[test]
    fn answers_unknown_methods() {
        let plugin = Plugin::new(Host::detached(), Arc::new(Vault::new(Key::random())));
        assert_eq!(
            plugin.call("model.list", b"{}")["error"]["code"],
            "unknown_method"
        );
    }
}

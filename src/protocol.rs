use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Value, json};

pub const SCHEMA_VERSION: u32 = 7;
pub const HEADER_CHUNK: i64 = -1;

#[derive(Deserialize)]
pub struct Lifecycle {
    #[serde(default, deserialize_with = "base64")]
    pub config_yaml: Vec<u8>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Exchange {
    #[serde(default, rename = "RequestID")]
    pub request_id: String,
    #[serde(default)]
    pub source_format: String,
    #[serde(default, deserialize_with = "base64")]
    pub body: Vec<u8>,
    #[serde(default)]
    pub chunk_index: i64,
    #[serde(default, rename = "host_callback_id")]
    pub callback: String,
}

fn base64<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
    let encoded: Option<String> = Option::deserialize(deserializer)?;
    encoded.map_or(Ok(Vec::new()), |encoded| {
        STANDARD.decode(encoded).map_err(serde::de::Error::custom)
    })
}

pub fn ok(result: Value) -> Value {
    let mut envelope = Map::new();
    envelope.insert("ok".to_owned(), Value::Bool(true));
    envelope.insert("result".to_owned(), result);
    Value::Object(envelope)
}

pub fn unchanged() -> Value {
    ok(json!({}))
}

pub fn body(bytes: &[u8]) -> Value {
    ok(json!({ "Body": STANDARD.encode(bytes) }))
}

pub fn drop_chunk() -> Value {
    ok(json!({ "DropChunk": true }))
}

pub fn error(code: &str, message: &str) -> Value {
    json!({ "ok": false, "error": { "code": code, "message": message, "retryable": false } })
}

pub fn reject(status: u16, message: &str) -> Value {
    let body = json!({ "error": { "type": "invalid_request_error", "message": message } });
    ok(json!({
        "Terminate": true,
        "StatusCode": status,
        "ResponseHeaders": { "Content-Type": ["application/json"] },
        "ResponseBody": STANDARD.encode(body.to_string()),
    }))
}

pub fn registration() -> Value {
    ok(json!({
        "schema_version": SCHEMA_VERSION,
        "metadata": {
            "Name": "redact",
            "Version": env!("CARGO_PKG_VERSION"),
            "Author": "Ryuu",
            "GitHubRepository": "https://github.com/ryuudotgg/redact",
            "Logo": "",
            "ConfigFields": [
                { "Name": "rules_file", "Type": "string", "Default": "", "Description": "Absolute path to a Gitleaks rules file that replaces the embedded rules." },
                { "Name": "disabled_rules", "Type": "array", "Default": [], "Description": "Gitleaks rule ids to turn off." },
                { "Name": "allow", "Type": "array", "Default": [], "Description": "Regular expressions matching values that are never redacted." },
                { "Name": "notice", "Type": "boolean", "Default": true, "Description": "Tell the model how to use placeholders when a request carries them." }
            ]
        },
        "capabilities": {
            "request_interceptor": true,
            "request_interceptor_omit_body_after": true,
            "response_interceptor": true,
            "response_stream_interceptor": true,
            "request_lifecycle_plugin": true
        }
    }))
}

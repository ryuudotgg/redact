#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Format {
    Claude,
    Chat,
    Responses,
    Gemini,
    Other,
}

impl Format {
    pub fn from_source(source: &str) -> Self {
        match source {
            "claude" => Self::Claude,
            "openai" => Self::Chat,
            "openai-response" => Self::Responses,
            "gemini" => Self::Gemini,
            _ => Self::Other,
        }
    }
}

// Providers verify a signature over these blocks, so editing one rejects the turn.
pub fn is_signed_type(kind: &str) -> bool {
    matches!(
        kind,
        "thinking" | "redacted_thinking" | "reasoning" | "reasoning_text"
    )
}

pub fn is_verified_key(key: &str) -> bool {
    matches!(
        key,
        "signature" | "encrypted_content" | "thoughtSignature" | "thought_signature"
    )
}

pub fn identifies_a_tool(key: &str) -> bool {
    matches!(key, "name" | "call_id" | "tool_use_id")
}

pub fn opens_payload(key: &str) -> bool {
    matches!(
        key,
        "input"
            | "args"
            | "arguments"
            | "response"
            | "output"
            | "result"
            | "action"
            | "content"
            | "structuredContent"
    )
}

pub fn holds_json_text(key: &str) -> bool {
    matches!(key, "arguments" | "partial_json")
}

const BLOB_LEN: usize = 2048;

pub fn looks_like_blob(text: &str) -> bool {
    let payload = text
        .strip_prefix("data:")
        .and_then(|rest| rest.split_once(";base64,"))
        .map_or(text, |(_, data)| data);

    let data = payload.trim_end_matches('=');
    payload.len() >= BLOB_LEN
        && payload.len() - data.len() <= 2
        && data
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognises_blobs() {
        let image = "A".repeat(BLOB_LEN);

        assert!(looks_like_blob(&image));
        assert!(looks_like_blob(&format!("data:image/png;base64,{image}")));
        assert!(looks_like_blob(&format!("{image}==")));

        assert!(!looks_like_blob(&format!("{image} ")));
        assert!(!looks_like_blob(&format!("{image}===")));
        assert!(!looks_like_blob(&format!("GOOGLE_CREDENTIALS_B64={image}")));
        assert!(!looks_like_blob("short"));
    }
}

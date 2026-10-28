use std::fmt;
use std::ops::Range;

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

const PREFIX: &str = "redact-";
const HEX_LEN: usize = 12;
pub const LEN: usize = PREFIX.len() + HEX_LEN;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Placeholder([u8; HEX_LEN / 2]);

pub struct Key([u8; 32]);

impl Key {
    pub fn random() -> Self {
        let mut bytes = [0; 32];
        getrandom::fill(&mut bytes).expect("the OS random source is available");
        Self(bytes)
    }

    #[cfg(test)]
    pub fn fixed(byte: u8) -> Self {
        Self([byte; 32])
    }
}

impl Placeholder {
    pub fn derive(key: &Key, value: &str, salt: u32) -> Self {
        let mut mac = Hmac::<Sha256>::new_from_slice(&key.0).expect("HMAC accepts any key length");
        mac.update(value.as_bytes());
        if salt > 0 {
            mac.update(&salt.to_le_bytes());
        }

        let digest = mac.finalize().into_bytes();
        let mut id = [0; HEX_LEN / 2];
        id.copy_from_slice(&digest[..HEX_LEN / 2]);
        Self(id)
    }

    fn parse(hex: &[u8]) -> Option<Self> {
        let mut id = [0; HEX_LEN / 2];
        for (byte, [high, low]) in id.iter_mut().zip(hex.as_chunks::<2>().0) {
            *byte = (nibble(*high)? << 4) | nibble(*low)?;
        }

        Some(Self(id))
    }
}

impl fmt::Display for Placeholder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(PREFIX)?;
        self.0.iter().try_for_each(|byte| write!(f, "{byte:02x}"))
    }
}

pub fn find(text: &[u8]) -> impl Iterator<Item = (Range<usize>, Placeholder)> + '_ {
    let finder = memchr::memmem::find_iter(text, PREFIX.as_bytes());
    finder.filter_map(|start| {
        let hex = text.get(start + PREFIX.len()..start + LEN)?;
        Placeholder::parse(hex).map(|placeholder| (start..start + LEN, placeholder))
    })
}

pub fn contains(text: &[u8]) -> bool {
    find(text).next().is_some()
}

pub fn partial_suffix_len(text: &[u8]) -> usize {
    let longest = text.len().min(LEN - 1);
    (1..=longest)
        .rev()
        .find(|&n| could_start_placeholder(&text[text.len() - n..]))
        .unwrap_or(0)
}

fn could_start_placeholder(fragment: &[u8]) -> bool {
    let prefix = PREFIX.as_bytes();
    let split = fragment.len().min(prefix.len());
    let (head, hex) = fragment.split_at(split);
    prefix.starts_with(head) && hex.iter().all(|&byte| nibble(byte).is_some())
}

fn nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_stable_placeholders() {
        let key = Key::fixed(7);
        let first = Placeholder::derive(&key, "value", 0);

        assert_eq!(first, Placeholder::derive(&key, "value", 0));
        assert_ne!(first, Placeholder::derive(&key, "value", 1));
        assert_ne!(first, Placeholder::derive(&Key::fixed(8), "value", 0));
        assert_eq!(first.to_string().len(), LEN);
    }

    #[test]
    fn finds_placeholders_anywhere() {
        let placeholder = Placeholder::derive(&Key::fixed(1), "value", 0);
        let text = format!("KEY={placeholder} and x{placeholder}y and redact-zzzzzzzzzzzz");

        let found: Vec<_> = find(text.as_bytes()).map(|(_, found)| found).collect();
        assert_eq!(found, [placeholder, placeholder]);
    }

    #[test]
    fn holds_back_only_what_could_become_a_placeholder() {
        assert_eq!(partial_suffix_len(b"token: red"), 3);
        assert_eq!(partial_suffix_len(b"key=xredact-3a7f"), 11);
        assert_eq!(partial_suffix_len(b"redact-3a7f9c21d0b"), 18);
        assert_eq!(partial_suffix_len(b"for"), 1);

        assert_eq!(partial_suffix_len(b"hello"), 0);
        assert_eq!(partial_suffix_len(b"redact-3a7g"), 0);
        assert_eq!(partial_suffix_len(b""), 0);
    }
}

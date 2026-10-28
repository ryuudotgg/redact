use std::borrow::Cow;
use std::ops::Range;

const MAX_DEPTH: usize = 128;

#[derive(Debug)]
pub enum Value {
    Object {
        members: Vec<Member>,
        span: Range<usize>,
    },
    Array {
        items: Vec<Value>,
        span: Range<usize>,
    },
    String(Str),
    Scalar(Range<usize>),
}

#[derive(Debug)]
pub struct Member {
    pub key: Str,
    pub value: Value,
}

#[derive(Debug, Clone)]
pub struct Str {
    pub span: Range<usize>,
    escaped: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Syntax(usize),
    TooDeep,
}

impl Value {
    pub fn get(&self, key: &str, source: &[u8]) -> Option<&Value> {
        let Value::Object { members, .. } = self else {
            return None;
        };
        members
            .iter()
            .find(|member| member.key.decode(source).text == key)
            .map(|member| &member.value)
    }

    pub fn as_str<'a>(&self, source: &'a [u8]) -> Option<Cow<'a, str>> {
        match self {
            Value::String(literal) => Some(literal.decode(source).text),
            _ => None,
        }
    }
}

impl Str {
    pub fn contents(&self) -> Range<usize> {
        self.span.start + 1..self.span.end - 1
    }

    pub fn decode<'a>(&self, source: &'a [u8]) -> Decoded<'a> {
        let contents = &source[self.contents()];
        if !self.escaped {
            let text = std::str::from_utf8(contents).expect("the parser validated UTF-8");
            return Decoded {
                text: Cow::Borrowed(text),
                segments: Vec::new(),
            };
        }

        unescape(contents)
    }
}

pub struct Decoded<'a> {
    pub text: Cow<'a, str>,
    segments: Vec<(usize, usize)>,
}

impl Decoded<'_> {
    pub fn raw_offset(&self, offset: usize) -> usize {
        let index = self
            .segments
            .partition_point(|&(decoded, _)| decoded <= offset);

        match index.checked_sub(1).map(|i| self.segments[i]) {
            Some((decoded, raw)) => raw + (offset - decoded),
            None => offset,
        }
    }

    pub fn raw_range(&self, range: Range<usize>) -> Range<usize> {
        self.raw_offset(range.start)..self.raw_offset(range.end)
    }
}

#[derive(Debug)]
pub struct Edit {
    pub range: Range<usize>,
    pub text: String,
}

pub fn splice(source: &[u8], mut edits: Vec<Edit>) -> Vec<u8> {
    edits.sort_by_key(|edit| edit.range.start);
    let mut out =
        Vec::with_capacity(source.len() + edits.iter().map(|edit| edit.text.len()).sum::<usize>());

    let mut at = 0;
    for edit in edits {
        out.extend_from_slice(&source[at..edit.range.start]);
        out.extend_from_slice(edit.text.as_bytes());
        at = edit.range.end;
    }

    out.extend_from_slice(&source[at..]);
    out
}

pub fn parse(source: &[u8]) -> Result<Value, Error> {
    parse_nested(source, 0)
}

pub fn parse_nested(source: &[u8], depth: usize) -> Result<Value, Error> {
    let mut parser = Parser { source, at: 0 };

    parser.skip_whitespace();
    let value = parser.value(depth)?;
    parser.skip_whitespace();

    if parser.at != source.len() {
        return Err(Error::Syntax(parser.at));
    }

    Ok(value)
}

pub fn escape_into(out: &mut Vec<u8>, text: &str) {
    let bytes = text.as_bytes();

    let mut start = 0;
    for (i, &byte) in bytes.iter().enumerate() {
        let escape: &[u8] = match byte {
            b'"' => b"\\\"",
            b'\\' => b"\\\\",
            b'\n' => b"\\n",
            b'\r' => b"\\r",
            b'\t' => b"\\t",
            0x08 => b"\\b",
            0x0c => b"\\f",
            0x00..=0x1f => &[],
            _ => continue,
        };

        out.extend_from_slice(&bytes[start..i]);

        if escape.is_empty() {
            out.extend_from_slice(format!("\\u{byte:04x}").as_bytes());
        } else {
            out.extend_from_slice(escape);
        }

        start = i + 1;
    }

    out.extend_from_slice(&bytes[start..]);
}

pub fn escape(text: &str) -> String {
    let mut out = Vec::with_capacity(text.len());
    escape_into(&mut out, text);
    String::from_utf8(out).expect("escaping keeps UTF-8 intact")
}

struct Parser<'a> {
    source: &'a [u8],
    at: usize,
}

impl Parser<'_> {
    fn value(&mut self, depth: usize) -> Result<Value, Error> {
        if depth > MAX_DEPTH {
            return Err(Error::TooDeep);
        }

        match self.peek() {
            Some(b'{') => self.object(depth),
            Some(b'[') => self.array(depth),
            Some(b'"') => self.string().map(Value::String),
            Some(b't') => self.literal(b"true"),
            Some(b'f') => self.literal(b"false"),
            Some(b'n') => self.literal(b"null"),
            Some(b'-' | b'0'..=b'9') => self.number(),
            _ => Err(self.error()),
        }
    }

    fn object(&mut self, depth: usize) -> Result<Value, Error> {
        let start = self.at;
        self.at += 1;
        let mut members = Vec::new();

        self.skip_whitespace();

        if self.eat(b'}') {
            return Ok(Value::Object {
                members,
                span: start..self.at,
            });
        }

        loop {
            self.skip_whitespace();
            if self.peek() != Some(b'"') {
                return Err(self.error());
            }

            let key = self.string()?;
            self.skip_whitespace();
            if !self.eat(b':') {
                return Err(self.error());
            }

            self.skip_whitespace();
            let value = self.value(depth + 1)?;
            members.push(Member { key, value });

            self.skip_whitespace();

            if self.eat(b'}') {
                return Ok(Value::Object {
                    members,
                    span: start..self.at,
                });
            }

            if !self.eat(b',') {
                return Err(self.error());
            }
        }
    }

    fn array(&mut self, depth: usize) -> Result<Value, Error> {
        let start = self.at;
        self.at += 1;
        let mut items = Vec::new();

        self.skip_whitespace();

        if self.eat(b']') {
            return Ok(Value::Array {
                items,
                span: start..self.at,
            });
        }

        loop {
            self.skip_whitespace();
            items.push(self.value(depth + 1)?);

            self.skip_whitespace();

            if self.eat(b']') {
                return Ok(Value::Array {
                    items,
                    span: start..self.at,
                });
            }

            if !self.eat(b',') {
                return Err(self.error());
            }
        }
    }

    fn string(&mut self) -> Result<Str, Error> {
        let start = self.at;
        self.at += 1;

        let mut escaped = false;
        loop {
            let Some(&byte) = self.source.get(self.at) else {
                return Err(self.error());
            };
            match byte {
                b'"' => break,
                b'\\' => {
                    escaped = true;
                    self.escape()?;
                }

                0x00..=0x1f => return Err(self.error()),
                _ => self.at += 1,
            }
        }

        self.at += 1;
        if std::str::from_utf8(&self.source[start + 1..self.at - 1]).is_err() {
            return Err(Error::Syntax(start));
        }

        Ok(Str {
            span: start..self.at,
            escaped,
        })
    }

    fn escape(&mut self) -> Result<(), Error> {
        let kind = self.source.get(self.at + 1).copied();
        match kind {
            Some(b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't') => self.at += 2,
            Some(b'u') => {
                let digits = self
                    .source
                    .get(self.at + 2..self.at + 6)
                    .ok_or(self.error())?;

                if !digits.iter().all(u8::is_ascii_hexdigit) {
                    return Err(self.error());
                }

                self.at += 6;
            }

            _ => return Err(self.error()),
        }

        Ok(())
    }

    fn number(&mut self) -> Result<Value, Error> {
        let start = self.at;

        while matches!(
            self.peek(),
            Some(b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9')
        ) {
            self.at += 1;
        }

        let text =
            std::str::from_utf8(&self.source[start..self.at]).map_err(|_| Error::Syntax(start))?;

        if text.parse::<f64>().is_err() {
            return Err(Error::Syntax(start));
        }

        Ok(Value::Scalar(start..self.at))
    }

    fn literal(&mut self, word: &[u8]) -> Result<Value, Error> {
        if !self.source[self.at..].starts_with(word) {
            return Err(self.error());
        }

        let start = self.at;
        self.at += word.len();
        Ok(Value::Scalar(start..self.at))
    }

    fn skip_whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.at += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.source.get(self.at).copied()
    }

    fn eat(&mut self, byte: u8) -> bool {
        if self.peek() != Some(byte) {
            return false;
        }
        self.at += 1;
        true
    }

    fn error(&self) -> Error {
        Error::Syntax(self.at)
    }
}

fn unescape(contents: &[u8]) -> Decoded<'static> {
    let mut text = String::with_capacity(contents.len());
    let mut segments = Vec::new();
    let mut at = 0;
    while at < contents.len() {
        let next = contents[at..]
            .iter()
            .position(|&byte| byte == b'\\')
            .map_or(contents.len(), |i| at + i);

        text.push_str(
            std::str::from_utf8(&contents[at..next]).expect("the parser validated UTF-8"),
        );

        if next == contents.len() {
            break;
        }

        let (decoded, width) = unescape_one(&contents[next..]);
        text.push(decoded);
        at = next + width;
        segments.push((text.len(), at));
    }

    Decoded {
        text: Cow::Owned(text),
        segments,
    }
}

fn unescape_one(escape: &[u8]) -> (char, usize) {
    match escape[1] {
        b'b' => ('\u{8}', 2),
        b'f' => ('\u{c}', 2),
        b'n' => ('\n', 2),
        b'r' => ('\r', 2),
        b't' => ('\t', 2),
        b'u' => unescape_unicode(escape),
        other => (char::from(other), 2),
    }
}

fn unescape_unicode(escape: &[u8]) -> (char, usize) {
    let unit = hex4(&escape[2..6]);
    if (0xd800..0xdc00).contains(&unit) && escape.get(6..8) == Some(b"\\u") {
        let low = escape
            .get(8..12)
            .filter(|digits| digits.iter().all(u8::is_ascii_hexdigit))
            .map(hex4);

        if let Some(low @ 0xdc00..0xe000) = low {
            let code = 0x10000 + ((unit - 0xd800) << 10) + (low - 0xdc00);
            return (
                char::from_u32(code).unwrap_or(char::REPLACEMENT_CHARACTER),
                12,
            );
        }
    }

    (
        char::from_u32(unit).unwrap_or(char::REPLACEMENT_CHARACTER),
        6,
    )
}

fn hex4(digits: &[u8]) -> u32 {
    digits.iter().fold(0, |code, &digit| {
        code * 16 + char::from(digit).to_digit(16).expect("checked hex digit")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decoded(literal: &str) -> String {
        let value = parse(literal.as_bytes()).unwrap();
        value.as_str(literal.as_bytes()).unwrap().into_owned()
    }

    #[test]
    fn parses_nested_documents() {
        let source = br#" {"a": [1, -2.5e3, true, null, {"b": "c"}], "d": {}} "#;
        let value = parse(source).unwrap();

        let a = value.get("a", source).unwrap();
        assert!(matches!(a, Value::Array { items, .. } if items.len() == 5));
        assert!(
            matches!(value.get("d", source), Some(Value::Object { members, .. }) if members.is_empty())
        );

        let Value::Array { span, .. } = a else {
            unreachable!()
        };

        assert_eq!(
            &source[span.clone()],
            br#"[1, -2.5e3, true, null, {"b": "c"}]"#
        );
    }

    #[test]
    fn rejects_malformed_documents() {
        for source in [
            &b"{"[..],
            b"{\"a\" 1}",
            b"[1,]",
            b"\"\x01\"",
            b"tru",
            b"1 2",
            b"\"\\x\"",
            b"--1",
        ] {
            assert!(matches!(parse(source), Err(Error::Syntax(_))), "{source:?}");
        }
    }

    #[test]
    fn rejects_deep_nesting() {
        let source = "[".repeat(MAX_DEPTH + 2) + &"]".repeat(MAX_DEPTH + 2);
        assert_eq!(parse(source.as_bytes()).unwrap_err(), Error::TooDeep);
    }

    #[test]
    fn decodes_escapes() {
        assert_eq!(decoded(r#""plain""#), "plain");
        assert_eq!(decoded(r#""a\nb\"c\\d\/e""#), "a\nb\"c\\d/e");
        assert_eq!(decoded(r#""\u003cb\u003e""#), "<b>");
        assert_eq!(decoded(r#""\ud83d\ude00""#), "\u{1f600}");
        assert_eq!(decoded(r#""\ud83d""#), "\u{fffd}");
    }

    #[test]
    fn maps_decoded_ranges_to_raw_ranges() {
        let source = br#""k=\u0041BC\n tail""#;
        let value = parse(source).unwrap();
        let Value::String(literal) = &value else {
            unreachable!()
        };

        let decoded = literal.decode(source);

        let text = decoded.text.as_ref();
        let start = text.find("ABC").unwrap();
        let raw = decoded.raw_range(start..start + 3);
        let contents = &source[literal.contents()];

        assert_eq!(&contents[raw], br"\u0041BC");
        let tail = text.find("tail").unwrap();
        assert_eq!(&contents[decoded.raw_range(tail..tail + 4)], b"tail");
    }

    #[test]
    fn escapes_what_json_requires() {
        assert_eq!(escape("a\"b\\c\nd\u{1}é"), "a\\\"b\\\\c\\nd\\u0001é");
    }
}

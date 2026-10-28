use std::ops::Range;
use std::sync::LazyLock;

use regex::bytes::{Regex, RegexBuilder};

const MIN_VALUE: usize = 6;
const MIN_PASSWORD: usize = 3;

static ASSIGNMENT: LazyLock<Regex> = LazyLock::new(|| {
    ascii(
        r#"(?xi)
        (?P<name> [a-z0-9_.\-]* (?: pass(?:word|wd|phrase)? | pwd | secrets? | tokens? | credentials? | creds | auth
                                  | (?: api | access | private | signing | encryption | master | client | license
                                      | secret | app | service | account | webhook ) [_.\-]? key ) [a-z0-9_.\-]* )
        ["']? [\t\x20]* (?P<separator> := | => | = | : ) [\t\x20]*
        (?P<value> "[^"\n]{1,512}" | '[^'\n]{1,512}' | `[^`\n]{1,512}` | [^\s"'`&]{1,512} )
        "#,
    )
});

static AUTHORIZATION: LazyLock<Regex> = LazyLock::new(|| {
    ascii(
        r#"(?i)\b(?:proxy-)?authorization["']?[\t\x20]*[:=][\t\x20]*["']?(?:bearer|basic|token|digest|apikey)[\t\x20]+(?P<value>[A-Za-z0-9._~+/=\-]{8,})"#,
    )
});

static URL_CREDENTIALS: LazyLock<Regex> = LazyLock::new(|| {
    ascii(
        r#"(?i)\b[a-z][a-z0-9+.\-]{1,24}://[^\s:/?#@"'<>\\]*:(?P<value>[^\s/?#@"'<>\\]{1,256})@[a-z0-9\[\]._\-]+"#,
    )
});

static MEMBER_CHAIN: LazyLock<Regex> =
    LazyLock::new(|| ascii(r"^[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)+$"));
static WORDS_ONLY: LazyLock<Regex> = LazyLock::new(|| ascii(r"^[A-Za-z_.\-]+$"));
static NUMBER: LazyLock<Regex> = LazyLock::new(|| ascii(r"^[0-9.,_+\-]+$"));
static VERSION: LazyLock<Regex> =
    LazyLock::new(|| ascii(r"^[\^~=<>v]*[0-9]+(?:\.(?:[0-9]+|x|\*))*(?:[\-+][0-9A-Za-z.\-]+)?$"));
static PACKAGE_SPEC: LazyLock<Regex> = LazyLock::new(|| {
    ascii(r"^(?:workspace|npm|file|link|portal|patch|catalog|github|git\+[a-z]+):")
});

const SECRET_WORDS: &[&str] = &[
    "password",
    "passwd",
    "passphrase",
    "pwd",
    "pass",
    "secret",
    "secrets",
    "token",
    "tokens",
    "credential",
    "credentials",
    "creds",
    "apikey",
    "accesskey",
    "privatekey",
    "secretkey",
    "signingkey",
    "clientsecret",
];

const KEY_QUALIFIERS: &[&str] = &[
    "api",
    "auth",
    "access",
    "private",
    "signing",
    "encryption",
    "master",
    "client",
    "license",
    "secret",
    "app",
    "service",
    "account",
    "webhook",
];

const METADATA_WORDS: &[&str] = &[
    "id",
    "ids",
    "type",
    "types",
    "name",
    "names",
    "url",
    "uri",
    "endpoint",
    "host",
    "path",
    "file",
    "dir",
    "length",
    "len",
    "size",
    "count",
    "limit",
    "ttl",
    "expiry",
    "expires",
    "expiration",
    "timeout",
    "header",
    "headers",
    "field",
    "label",
    "prefix",
    "suffix",
    "format",
    "env",
    "var",
    "version",
    "mode",
    "policy",
    "enabled",
    "required",
    "regex",
    "pattern",
    "placeholder",
    "hint",
    "description",
    "help",
    "message",
    "error",
    "errors",
    "hash",
    "salt",
    "rounds",
    "strength",
    "min",
    "max",
    "provider",
    "store",
    "storage",
    "cache",
    "manager",
    "service",
    "client",
    "handler",
    "middleware",
    "schema",
    "model",
    "input",
    "button",
    "visible",
    "visibility",
    "reset",
    "confirm",
    "confirmation",
    "changed",
    "policy",
    "rotation",
    "scope",
    "scopes",
    "usage",
    "audience",
    "issuer",
    "flow",
    "grant",
    "refresh",
    "budget",
    "estimate",
    "estimator",
    "counter",
    "tokenizer",
    "kind",
    "key",
];

const DUMMY_FRAGMENTS: &[&str] = &[
    "xxxx",
    "****",
    "....",
    "changeme",
    "change_me",
    "change-me",
    "your",
    "example",
    "placeholder",
    "replace",
    "redacted",
    "dummy",
    "sample",
    "<",
    ">",
];

const DUMMY_WORDS: &[&str] = &[
    "password",
    "passwd",
    "pass",
    "pwd",
    "secret",
    "token",
    "user",
    "username",
    "null",
    "none",
    "nil",
    "undefined",
    "true",
    "false",
    "empty",
    "string",
    "required",
    "optional",
    "test",
    "testing",
    "admin",
];

pub fn assignments(text: &[u8], found: &mut Vec<Range<usize>>) {
    for captures in ASSIGNMENT.captures_iter(text) {
        let (Some(name), Some(separator), Some(value)) = (
            captures.name("name"),
            captures.name("separator"),
            captures.name("value"),
        ) else {
            continue;
        };

        if separator.as_bytes() == b"=" && is_comparison(text, separator.range()) {
            continue;
        }
        if !names_a_secret(name.as_bytes()) {
            continue;
        }
        let Some(literal) = Literal::read(text, value.range()) else {
            continue;
        };
        if literal.quoted || starts_a_config_line(text, name.start()) {
            found.push(literal.range);
        }
    }
}

pub fn authorization_headers(text: &[u8], found: &mut Vec<Range<usize>>) {
    for captures in AUTHORIZATION.captures_iter(text) {
        let Some(value) = captures.name("value") else {
            continue;
        };
        if !WORDS_ONLY.is_match(value.as_bytes()) {
            found.push(value.range());
        }
    }
}

pub fn url_credentials(text: &[u8], found: &mut Vec<Range<usize>>) {
    for captures in URL_CREDENTIALS.captures_iter(text) {
        let Some(value) = captures.name("value") else {
            continue;
        };

        let password = value.as_bytes();
        if password.len() >= MIN_PASSWORD
            && !is_template(password)
            && !is_dummy(password)
            && !password.iter().all(|&byte| byte == b'*')
        {
            found.push(value.range());
        }
    }
}

struct Literal {
    range: Range<usize>,
    quoted: bool,
}

impl Literal {
    fn read(text: &[u8], range: Range<usize>) -> Option<Self> {
        let raw = &text[range.clone()];
        let quoted = matches!(raw.first(), Some(b'"' | b'\'' | b'`'));

        let (range, ends_code) = if quoted {
            (range.start + 1..range.end - 1, false)
        } else {
            let trimmed = raw
                .iter()
                .rposition(|byte| !matches!(byte, b',' | b';'))
                .map_or(0, |i| i + 1);

            (range.start..range.start + trimmed, trimmed < raw.len())
        };

        let plausible = !ends_code && plausible_literal(&text[range.clone()], quoted);
        plausible.then_some(Self { range, quoted })
    }
}

pub fn keyed_secret(name: &str, value: &str) -> bool {
    names_a_secret(name.as_bytes()) && plausible_literal(value.as_bytes(), true)
}

fn plausible_literal(value: &[u8], quoted: bool) -> bool {
    let shaped = if quoted {
        !value.iter().any(u8::is_ascii_whitespace)
    } else {
        !looks_like_code(value)
    };

    shaped
        && value.len() >= MIN_VALUE
        && !is_template(value)
        && !is_dummy(value)
        && !WORDS_ONLY.is_match(value)
        && !NUMBER.is_match(value)
        && !VERSION.is_match(value)
        && !PACKAGE_SPEC.is_match(value)
}

fn names_a_secret(name: &[u8]) -> bool {
    let words = split_words(name);
    let Some(last) = words.last() else {
        return false;
    };

    let named = words
        .iter()
        .any(|word| SECRET_WORDS.contains(&word.as_str()))
        || words
            .windows(2)
            .any(|pair| pair[1] == "key" && KEY_QUALIFIERS.contains(&pair[0].as_str()));

    named && (!METADATA_WORDS.contains(&last.as_str()) || ends_with_key_pair(&words))
}

fn ends_with_key_pair(words: &[String]) -> bool {
    match words {
        [.., qualifier, last] => last == "key" && KEY_QUALIFIERS.contains(&qualifier.as_str()),
        _ => false,
    }
}

fn split_words(name: &[u8]) -> Vec<String> {
    let mut words = Vec::new();
    let mut word = String::new();
    for (i, &byte) in name.iter().enumerate() {
        if matches!(byte, b'_' | b'-' | b'.') {
            if !word.is_empty() {
                words.push(std::mem::take(&mut word));
            }
            continue;
        }

        let previous = i.checked_sub(1).map(|j| name[j]);
        if byte.is_ascii_uppercase()
            && previous.is_some_and(|p| p.is_ascii_lowercase() || p.is_ascii_digit())
            && !word.is_empty()
        {
            words.push(std::mem::take(&mut word));
        }

        word.push(char::from(byte.to_ascii_lowercase()));
    }

    if !word.is_empty() {
        words.push(word);
    }

    words
}

fn starts_a_config_line(text: &[u8], name_start: usize) -> bool {
    if text[name_start] == b'-' {
        return true;
    }

    let line_start = text[..name_start]
        .iter()
        .rposition(|&byte| byte == b'\n')
        .map_or(0, |i| i + 1);

    let before = &text[line_start..name_start];
    if let Some(&last) = before.last()
        && matches!(last, b'"' | b'\'' | b'-' | b'?' | b'&')
    {
        return true;
    }

    let lead = before
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .map_or(&before[before.len()..], |i| &before[i..]);

    lead.is_empty() || [&b"export "[..], b"set ", b"- ", b"ENV ", b"ARG "].contains(&lead)
}

fn is_comparison(text: &[u8], separator: Range<usize>) -> bool {
    let after = text.get(separator.end).copied();
    let before = separator.start.checked_sub(1).map(|i| text[i]);
    after == Some(b'=') || matches!(before, Some(b'!' | b'<' | b'>' | b'='))
}

fn looks_like_code(value: &[u8]) -> bool {
    value.iter().any(|byte| b"()[]{}<>".contains(byte))
        || MEMBER_CHAIN.is_match(value)
        || value.windows(2).any(|pair| pair == b"::" || pair == b"->")
        || matches!(value.first(), Some(b'@' | b'&' | b'*' | b'!'))
}

fn is_template(value: &[u8]) -> bool {
    value.first() == Some(&b'$')
        || value
            .windows(2)
            .any(|pair| matches!(pair, b"{{" | b"${" | b"#{" | b"%(" | b"<%"))
        || (value.len() > 2
            && matches!(
                (value[0], value[value.len() - 1]),
                (b'%', b'%') | (b'@', b'@') | (b'<', b'>')
            ))
}

fn is_dummy(value: &[u8]) -> bool {
    let lower = value.to_ascii_lowercase();
    DUMMY_WORDS.iter().any(|word| lower == word.as_bytes())
        || DUMMY_FRAGMENTS.iter().any(|fragment| {
            lower
                .windows(fragment.len())
                .any(|window| window == fragment.as_bytes())
        })
}

fn ascii(pattern: &str) -> Regex {
    RegexBuilder::new(pattern)
        .unicode(false)
        .build()
        .expect("detector patterns compile")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detected(text: &str) -> Vec<&str> {
        let mut found = Vec::new();
        assignments(text.as_bytes(), &mut found);
        authorization_headers(text.as_bytes(), &mut found);
        url_credentials(text.as_bytes(), &mut found);
        found.into_iter().map(|range| &text[range]).collect()
    }

    #[test]
    fn splits_names_into_words() {
        assert_eq!(split_words(b"OPENAI_API_KEY"), ["openai", "api", "key"]);
        assert_eq!(split_words(b"authHeader"), ["auth", "header"]);
        assert_eq!(split_words(b"x-api-key"), ["x", "api", "key"]);
        assert_eq!(split_words(b"dbPassword2"), ["db", "password2"]);
    }

    #[test]
    fn recognises_secret_names() {
        for name in [
            "DB_PASSWORD",
            "apiKey",
            "x-api-key",
            "GITHUB_TOKEN",
            "client_secret",
            "AUTH_KEY",
            "stripeSecretKey",
            "DB_PASS",
        ] {
            assert!(names_a_secret(name.as_bytes()), "{name}");
        }

        for name in [
            "token_type",
            "TOKEN_URL",
            "PASSWORD_MIN_LENGTH",
            "API_KEY_ID",
            "authHeader",
            "tokenizer",
            "author",
            "primary_key",
            "cache_key",
            "AUTH",
            "next-auth",
        ] {
            assert!(!names_a_secret(name.as_bytes()), "{name}");
        }
    }

    #[test]
    fn finds_literal_values() {
        assert_eq!(detected("DB_PASSWORD=hunter2"), ["hunter2"]);
        assert_eq!(detected("export STRIPE_TOKEN=Zx81Qm4kLp9"), ["Zx81Qm4kLp9"]);
        assert_eq!(detected("  api_key: 7f3a9c21d0b4e8"), ["7f3a9c21d0b4e8"]);
        assert_eq!(
            detected(r#"const apiKey = "Zx81Qm4kLp9";"#),
            ["Zx81Qm4kLp9"]
        );

        assert_eq!(
            detected(r#"{"access_token": "Zx81.Qm4k-Lp9"}"#),
            ["Zx81.Qm4k-Lp9"]
        );

        assert_eq!(
            detected("curl -H 'x-api-key: Zx81Qm4kLp9' https://api.test"),
            ["Zx81Qm4kLp9"]
        );

        assert_eq!(detected("mytool --token=Zx81Qm4kLp9 run"), ["Zx81Qm4kLp9"]);
        assert_eq!(
            detected("https://api.test/v1?api_key=Zx81Qm4kLp9&page=2"),
            ["Zx81Qm4kLp9"]
        );
    }

    #[test]
    fn leaves_code_alone() {
        for line in [
            "const apiKey = process.env.OPENAI_API_KEY;",
            r#"api_key = os.environ["STRIPE_KEY"]"#,
            "const token = await getToken(user);",
            "password: z.string().min(8),",
            "headers: { Authorization: `Bearer ${token}` },",
            r#"if (!secret) throw new Error("missing secret");"#,
            "const authHeader = req.headers.authorization;",
            "export const ACCESS_TOKEN_TTL = 3600;",
            "NEXT_PUBLIC_API_URL=https://api.example.com",
            r#"token_type: "Bearer","#,
            "key={item.id}",
            "  apiKey: token2,",
            "password: string;",
            r#"password: "Enter your password""#,
            "DB_PASSWORD=${DB_PASSWORD}",
            "token: $GITHUB_TOKEN",
            r#"if (token == "abcdef123") {"#,
            "API_KEY=your-api-key-here",
            r#"password = "changeme123""#,
            "SECRET_KEY_BASE=",
        ] {
            assert_eq!(detected(line), Vec::<&str>::new(), "{line}");
        }
    }

    #[test]
    fn finds_authorization_headers() {
        assert_eq!(
            detected(r#"-H "Authorization: Bearer Zx81Qm4kLp9aB""#),
            ["Zx81Qm4kLp9aB"]
        );

        assert_eq!(
            detected("Authorization: Bearer undefined"),
            Vec::<&str>::new()
        );
    }

    #[test]
    fn finds_passwords_in_urls() {
        assert_eq!(
            detected("DATABASE_URL=postgres://app:hunter2pass@db.internal:5432/app"),
            ["hunter2pass"]
        );

        assert_eq!(detected("redis://:s3cr3t@cache:6379"), ["s3cr3t"]);

        for url in [
            "postgres://user:password@localhost/db",
            "postgres://app:${DB_PASSWORD}@db/app",
            "https://user:***@host",
            "git@github.com:org/repo.git",
        ] {
            assert_eq!(detected(url), Vec::<&str>::new(), "{url}");
        }
    }
}

use crate::placeholder::Key;
use crate::scanner::Scanner;
use crate::testing::{ALNUM, BASE32, DIGITS, Fake, URL_SAFE};
use crate::vault::Vault;

const CLEAN: &str = include_str!("../tests/corpus/clean.txt");

fn provider_keys(seed: u64) -> Vec<(&'static str, String)> {
    let mut fake = Fake(seed);
    vec![
        ("github", ["gh", "p_", &fake.take(ALNUM, 36)].concat()),
        (
            "github fine grained",
            [
                "github",
                "_pat_",
                &fake.take(ALNUM, 22),
                "_",
                &fake.take(ALNUM, 59),
            ]
            .concat(),
        ),
        (
            "anthropic",
            ["sk-", "ant-api03-", &fake.take(URL_SAFE, 93), "AA"].concat(),
        ),
        (
            "openai",
            [
                "sk-",
                "proj-",
                &fake.take(URL_SAFE, 74),
                "T3Blbk",
                "FJ",
                &fake.take(URL_SAFE, 74),
            ]
            .concat(),
        ),
        ("stripe", ["sk_", "live_", &fake.take(ALNUM, 32)].concat()),
        ("aws", ["AK", "IA", &fake.take(BASE32, 16)].concat()),
        (
            "slack",
            [
                "xo",
                "xb-",
                &fake.take(DIGITS, 12),
                "-",
                &fake.take(DIGITS, 13),
                "-",
                &fake.take(ALNUM, 24),
            ]
            .concat(),
        ),
        ("google", ["AI", "za", &fake.take(URL_SAFE, 35)].concat()),
        ("npm", ["np", "m_", &fake.take(ALNUM, 36)].concat()),
    ]
}

fn unformatted_key(seed: u64) -> String {
    Fake(seed).take(ALNUM, 40)
}

fn assert_finds_exactly(scanner: &Scanner, text: &str, value: &str, label: &str) {
    let found: Vec<&str> = scanner
        .find(text, None, &Vault::new(Key::fixed(0)))
        .into_iter()
        .map(|range| &text[range])
        .collect();

    assert_eq!(found, [value], "{label}: {text}");
}

#[test]
fn clean_lines_stay_clean() {
    let scanner = Scanner::embedded();
    let vault = Vault::new(Key::fixed(0));
    let flagged: Vec<String> = CLEAN
        .lines()
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| {
            let found = scanner.find(line, None, &vault);
            (!found.is_empty()).then(|| {
                format!(
                    "{line}\n    flagged: {:?}",
                    found
                        .iter()
                        .map(|range| &line[range.clone()])
                        .collect::<Vec<_>>()
                )
            })
        })
        .collect();

    assert!(
        flagged.is_empty(),
        "clean lines were flagged:\n{}",
        flagged.join("\n")
    );
}

#[test]
fn provider_keys_are_found_in_every_context() {
    let scanner = Scanner::embedded();
    for seed in 1..=8 {
        for (provider, key) in provider_keys(seed) {
            for context in [
                format!("SERVICE_TOKEN={key}"),
                format!(r#"{{"token": "{key}"}}"#),
                format!("export SERVICE_API_KEY={key}"),
                format!(r#"curl -H "Authorization: Bearer {key}" https://api.test/v1/me"#),
                format!(r#"const client = new Client("{key}");"#),
                format!("the key is {key} if you need it"),
                format!("  api_key: {key}\n  region: eu-west-1"),
                format!("$ cat .env\nNODE_ENV=production\nSERVICE_KEY={key}\nPORT=3000\n"),
            ] {
                assert_finds_exactly(&scanner, &context, &key, provider);
            }
        }
    }
}

#[test]
fn unformatted_keys_are_found_when_named() {
    let scanner = Scanner::embedded();
    for seed in 1..=8 {
        let key = unformatted_key(seed);
        for context in [
            format!("SERVICE_TOKEN={key}"),
            format!(r#"{{"client_secret": "{key}"}}"#),
            format!("export DB_PASSWORD={key}"),
            format!(r#"curl -H "Authorization: Bearer {key}" https://api.test/v1/me"#),
            format!(r#"curl -H "X-Api-Key: {key}" https://api.test/v1/me"#),
            format!("  api_key: {key}"),
            format!("mytool login --token={key}"),
            format!("postgres://app:{key}@db.internal:5432/app"),
        ] {
            assert_finds_exactly(&scanner, &context, &key, "unformatted");
        }
    }
}

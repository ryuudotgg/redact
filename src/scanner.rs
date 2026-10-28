use std::ops::Range;

use regex::RegexSet;

use crate::rules::{self, RuleSet};
use crate::vault::{Known, Vault};
use crate::{detect, placeholder};

pub struct Scanner {
    rules: RuleSet,
    allow: Option<RegexSet>,
}

impl Scanner {
    pub fn new(rules: RuleSet, allow: &[String]) -> Result<Self, String> {
        let allow = if allow.is_empty() {
            None
        } else {
            Some(
                RegexSet::new(allow)
                    .map_err(|error| format!("an allow pattern does not compile: {error}"))?,
            )
        };

        Ok(Self { rules, allow })
    }

    pub fn embedded() -> Self {
        let rules = RuleSet::load(rules::EMBEDDED, &[]).expect("the embedded rules load");
        Self { rules, allow: None }
    }

    pub fn rules(&self) -> &RuleSet {
        &self.rules
    }

    pub fn find(&self, text: &str, known: Option<&Known>, vault: &Vault) -> Vec<Range<usize>> {
        let bytes = text.as_bytes();
        let mut found = Vec::new();

        self.rules.find(bytes, &mut found);
        detect::assignments(bytes, &mut found);
        detect::authorization_headers(bytes, &mut found);
        detect::url_credentials(bytes, &mut found);

        if let Some(known) = known {
            known.find(bytes, &mut found);
        }
        if found.is_empty() {
            return found;
        }

        let ours: Vec<Range<usize>> = placeholder::find(bytes)
            .filter(|(_, placeholder)| vault.value(*placeholder).is_some())
            .map(|(range, _)| range)
            .collect();

        found.retain(|range| {
            !ours
                .iter()
                .any(|placeholder| range.start < placeholder.end && placeholder.start < range.end)
                && !self.allows(&text[widen_to_chars(text, range.clone())])
        });

        for range in &mut found {
            *range = widen_to_chars(text, range.clone());
        }

        union(found)
    }

    pub fn keyed(&self, key: &str, value: &str, vault: &Vault) -> bool {
        let ours = placeholder::find(value.as_bytes())
            .any(|(_, placeholder)| vault.value(placeholder).is_some());

        detect::keyed_secret(key, value) && !ours && !self.allows(value)
    }

    fn allows(&self, value: &str) -> bool {
        self.allow
            .as_ref()
            .is_some_and(|allow| allow.is_match(value))
    }
}

fn widen_to_chars(text: &str, mut range: Range<usize>) -> Range<usize> {
    while !text.is_char_boundary(range.start) {
        range.start -= 1;
    }
    while !text.is_char_boundary(range.end) {
        range.end += 1;
    }
    range
}

fn union(mut ranges: Vec<Range<usize>>) -> Vec<Range<usize>> {
    ranges.sort_unstable_by_key(|range| range.start);

    let mut merged: Vec<Range<usize>> = Vec::with_capacity(ranges.len());
    for range in ranges {
        match merged.last_mut() {
            Some(last) if range.start < last.end => last.end = last.end.max(range.end),
            _ => merged.push(range),
        }
    }

    merged
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::placeholder::Key;
    use crate::vault::Vault;

    #[test]
    fn unions_overlapping_findings() {
        assert_eq!(
            union(vec![10..20, 0..5, 3..8, 15..25, 30..31]),
            [0..8, 10..25, 30..31]
        );
    }

    #[test]
    fn skips_existing_placeholders() {
        let scanner = Scanner::embedded();
        let vault = Vault::new(Key::fixed(9));
        let placeholder = vault.placeholder("Zx81Qm4kLp9");

        let text = format!("DB_PASSWORD={placeholder}\nAPI_TOKEN={placeholder}");
        assert_eq!(
            scanner.find(&text, vault.known().as_deref(), &vault),
            Vec::<Range<usize>>::new()
        );

        let unknown = "API_TOKEN=redact-0123456789abZx81Qm4kLp9";
        let found = scanner.find(unknown, None, &vault);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0], 10..unknown.len());
    }

    #[test]
    fn allow_patterns_cover_every_detector() {
        let rules = RuleSet::load(rules::EMBEDDED, &[]).unwrap();
        let scanner = Scanner::new(rules, &["^KeepMe123$".to_owned()]).unwrap();
        let vault = Vault::new(Key::fixed(9));
        vault.placeholder("KeepMe123");

        for text in [
            "DB_PASSWORD=KeepMe123",
            "postgres://app:KeepMe123@db/app",
            "echo KeepMe123",
        ] {
            assert_eq!(
                scanner.find(text, vault.known().as_deref(), &vault),
                Vec::<Range<usize>>::new(),
                "{text}"
            );
        }

        assert!(!scanner.keyed("password", "KeepMe123", &vault));
        assert!(scanner.keyed("password", "OtherPass456", &vault));
        let reference = vault.placeholder("OtherPass456").to_string();
        assert!(!scanner.keyed("password", &reference, &vault));
    }

    #[test]
    fn widens_findings_to_char_boundaries() {
        let text = "a€b";
        assert_eq!(widen_to_chars(text, 2..3), 1..4);
    }
}

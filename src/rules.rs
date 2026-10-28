use std::ops::Range;

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use regex::bytes::{Regex, RegexBuilder, RegexSet, RegexSetBuilder};
use serde::Deserialize;

pub const EMBEDDED: &str = include_str!("../rules/gitleaks.toml");

const REGEX_SIZE_LIMIT: usize = 64 << 20;

pub struct RuleSet {
    rules: Vec<Rule>,
    keywords: AhoCorasick,
    keyword_rules: Vec<Vec<usize>>,
    unconditional: Vec<usize>,
    global: Vec<Allowlist>,
    skipped: Vec<String>,
    unknown_disabled: Vec<String>,
}

struct Rule {
    regex: Regex,
    secret_group: usize,
    entropy: f64,
    allowlists: Vec<Allowlist>,
}

struct Allowlist {
    target: Target,
    regexes: Option<RegexSet>,
    stopwords: Option<AhoCorasick>,
    all: bool,
    unsupported_checks: bool,
}

#[derive(Clone, Copy)]
enum Target {
    Secret,
    Match,
    Line,
}

pub struct Candidate<'t> {
    text: &'t [u8],
    full: Range<usize>,
    secret: Range<usize>,
}

#[derive(Debug)]
pub enum Error {
    Parse(toml::de::Error),
    Allowlist { rule: String, pattern: String },
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Parse(error) => write!(f, "the rules file is not valid TOML: {error}"),
            Error::Allowlist { rule, pattern } => write!(
                f,
                "an allowlist of {rule} has a pattern that does not compile: {pattern}"
            ),
        }
    }
}

#[derive(Deserialize)]
struct Document {
    extend: Option<Extend>,
    #[serde(default)]
    rules: Vec<RawRule>,
    allowlist: Option<RawAllowlist>,
    #[serde(default)]
    allowlists: Vec<RawAllowlist>,
}

#[derive(Deserialize)]
struct Extend {
    #[serde(default, rename = "useDefault")]
    use_default: bool,
    #[serde(default, rename = "disabledRules")]
    disabled_rules: Vec<String>,
}

#[derive(Deserialize)]
struct RawRule {
    id: String,
    regex: Option<String>,
    #[serde(default)]
    keywords: Vec<String>,
    #[serde(default)]
    entropy: f64,
    #[serde(default, rename = "secretGroup")]
    secret_group: usize,
    allowlist: Option<RawAllowlist>,
    #[serde(default)]
    allowlists: Vec<RawAllowlist>,
}

#[derive(Deserialize)]
struct RawAllowlist {
    condition: Option<String>,
    #[serde(rename = "regexTarget")]
    regex_target: Option<String>,
    #[serde(default)]
    regexes: Vec<String>,
    #[serde(default)]
    stopwords: Vec<String>,
    #[serde(default)]
    paths: Vec<String>,
    #[serde(default)]
    commits: Vec<String>,
}

impl RuleSet {
    pub fn load(document: &str, disabled: &[String]) -> Result<Self, Error> {
        let mut document: Document = toml::from_str(document).map_err(Error::Parse)?;
        if let Some(extend) = document.extend.take()
            && extend.use_default
        {
            let base: Document = toml::from_str(EMBEDDED).map_err(Error::Parse)?;
            let own = std::mem::take(&mut document.rules);
            let mut rules: Vec<RawRule> = base
                .rules
                .into_iter()
                .filter(|rule| {
                    !extend
                        .disabled_rules
                        .iter()
                        .any(|id| id.eq_ignore_ascii_case(&rule.id))
                        && !own
                            .iter()
                            .any(|mine| mine.id.eq_ignore_ascii_case(&rule.id))
                })
                .collect();

            rules.extend(own);
            document.rules = rules;
            document
                .allowlists
                .extend(base.allowlist.into_iter().chain(base.allowlists));
        }

        let unknown_disabled = disabled
            .iter()
            .filter(|id| {
                !document
                    .rules
                    .iter()
                    .any(|rule| rule.id.eq_ignore_ascii_case(id))
            })
            .cloned()
            .collect();

        let global = document
            .allowlist
            .into_iter()
            .chain(document.allowlists)
            .map(|raw| Allowlist::compile(raw, "global"))
            .collect::<Result<Vec<_>, _>>()?;

        let mut rules = Vec::new();
        let mut keywords = Vec::new();
        let mut keyword_rules: Vec<Vec<usize>> = Vec::new();
        let mut unconditional = Vec::new();
        let mut skipped = Vec::new();
        for raw in document.rules {
            if disabled.iter().any(|id| id.eq_ignore_ascii_case(&raw.id)) {
                continue;
            }
            let Some(pattern) = raw.regex.as_deref() else {
                continue;
            };

            let Some(regex) = compile(pattern) else {
                skipped.push(raw.id);
                continue;
            };

            let index = rules.len();
            let allowlists = raw
                .allowlist
                .into_iter()
                .chain(raw.allowlists)
                .map(|allowlist| Allowlist::compile(allowlist, &raw.id))
                .collect::<Result<_, _>>()?;

            rules.push(Rule {
                regex,
                secret_group: raw.secret_group,
                entropy: raw.entropy,
                allowlists,
            });

            if raw.keywords.is_empty() {
                unconditional.push(index);
            }

            for keyword in raw.keywords {
                let keyword = keyword.to_ascii_lowercase();
                if let Some(at) = keywords.iter().position(|known| *known == keyword) {
                    keyword_rules[at].push(index);
                } else {
                    keywords.push(keyword);
                    keyword_rules.push(vec![index]);
                }
            }
        }

        let keywords = AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .build(&keywords)
            .expect("keyword automaton builds");

        Ok(Self {
            rules,
            keywords,
            keyword_rules,
            unconditional,
            global,
            skipped,
            unknown_disabled,
        })
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn skipped(&self) -> &[String] {
        &self.skipped
    }

    pub fn unknown_disabled(&self) -> &[String] {
        &self.unknown_disabled
    }

    pub fn find(&self, text: &[u8], found: &mut Vec<Range<usize>>) {
        let mut applies = vec![false; self.rules.len()];
        for &index in &self.unconditional {
            applies[index] = true;
        }

        for hit in self.keywords.find_overlapping_iter(text) {
            for &index in &self.keyword_rules[hit.pattern().as_usize()] {
                applies[index] = true;
            }
        }

        for (rule, _) in self
            .rules
            .iter()
            .zip(&applies)
            .filter(|(_, applies)| **applies)
        {
            for captures in rule.regex.captures_iter(text) {
                let Some(candidate) = Candidate::from_captures(text, &captures, rule.secret_group)
                else {
                    continue;
                };

                if rule.entropy != 0.0 && entropy(candidate.secret()) <= rule.entropy {
                    continue;
                }
                if self
                    .global
                    .iter()
                    .chain(&rule.allowlists)
                    .any(|allowlist| allowlist.allows(&candidate))
                {
                    continue;
                }

                found.push(candidate.secret);
            }
        }
    }
}

impl<'t> Candidate<'t> {
    fn from_captures(
        text: &'t [u8],
        captures: &regex::bytes::Captures<'_>,
        secret_group: usize,
    ) -> Option<Self> {
        let whole = captures.get(0)?;
        let full = trim_newlines(text, whole.range());

        let secret = if captures.len() < 2 {
            full.clone()
        } else if secret_group > 0 {
            captures.get(secret_group)?.range()
        } else {
            (1..captures.len())
                .find_map(|group| captures.get(group).filter(|m| !m.is_empty()))
                .map_or(full.clone(), |m| m.range())
        };

        if secret.is_empty() {
            return None;
        }

        Some(Self { text, full, secret })
    }

    fn secret(&self) -> &'t [u8] {
        &self.text[self.secret.clone()]
    }

    fn line(&self) -> &'t [u8] {
        let start = self.text[..self.full.start]
            .iter()
            .rposition(|&byte| byte == b'\n')
            .map_or(0, |i| i + 1);

        let end = self.text[self.full.end..]
            .iter()
            .position(|&byte| byte == b'\n')
            .map_or(self.text.len(), |i| self.full.end + i);

        &self.text[start..end]
    }
}

impl Allowlist {
    fn compile(raw: RawAllowlist, owner: &str) -> Result<Self, Error> {
        let target = match raw.regex_target.as_deref() {
            Some("match") => Target::Match,
            Some("line") => Target::Line,
            _ => Target::Secret,
        };

        let regexes = if raw.regexes.is_empty() {
            None
        } else {
            let patterns: Vec<String> = raw
                .regexes
                .iter()
                .map(|pattern| translate(pattern))
                .collect();

            let set = RegexSetBuilder::new(&patterns)
                .unicode(false)
                .size_limit(REGEX_SIZE_LIMIT)
                .build();

            let set = set.or_else(|_| {
                RegexSetBuilder::new(&patterns)
                    .size_limit(REGEX_SIZE_LIMIT)
                    .build()
            });

            Some(set.map_err(|_| Error::Allowlist {
                rule: owner.to_owned(),
                pattern: raw.regexes.join(" | "),
            })?)
        };

        let stopwords = if raw.stopwords.is_empty() {
            None
        } else {
            let words: Vec<String> = raw
                .stopwords
                .iter()
                .map(|word| word.to_ascii_lowercase())
                .collect();

            Some(
                AhoCorasickBuilder::new()
                    .ascii_case_insensitive(true)
                    .match_kind(MatchKind::LeftmostFirst)
                    .build(words)
                    .expect("stopword automaton builds"),
            )
        };

        Ok(Self {
            target,
            regexes,
            stopwords,
            all: raw
                .condition
                .is_some_and(|condition| condition.eq_ignore_ascii_case("and")),
            unsupported_checks: !raw.paths.is_empty() || !raw.commits.is_empty(),
        })
    }

    fn allows(&self, candidate: &Candidate<'_>) -> bool {
        let target = match self.target {
            Target::Secret => candidate.secret(),
            Target::Match => &candidate.text[candidate.full.clone()],
            Target::Line => candidate.line(),
        };

        let regex = self
            .regexes
            .as_ref()
            .map(|set| !target.is_empty() && set.is_match(target));

        let stopword = self
            .stopwords
            .as_ref()
            .map(|words| words.is_match(candidate.secret()));

        if self.all {
            !self.unsupported_checks
                && (regex.is_some() || stopword.is_some())
                && regex.unwrap_or(true)
                && stopword.unwrap_or(true)
        } else {
            regex.unwrap_or(false) || stopword.unwrap_or(false)
        }
    }
}

// Gitleaks rules are RE2 patterns, where \w, \d, \s and \b are ASCII only.
fn compile(pattern: &str) -> Option<Regex> {
    let pattern = translate(pattern);
    let ascii = RegexBuilder::new(&pattern)
        .unicode(false)
        .size_limit(REGEX_SIZE_LIMIT)
        .build();

    ascii
        .or_else(|_| {
            RegexBuilder::new(&pattern)
                .size_limit(REGEX_SIZE_LIMIT)
                .build()
        })
        .ok()
}

// RE2 reads a brace that cannot start a repetition as a literal; Rust's regex rejects it.
fn translate(pattern: &str) -> String {
    let chars: Vec<char> = pattern.chars().collect();

    let mut out = String::with_capacity(pattern.len() + 8);
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            '\\' => {
                out.extend(chars.get(i..(i + 2).min(chars.len())).into_iter().flatten());
                i += 2;
            }

            '[' => {
                let end = class_end(&chars, i);
                out.extend(&chars[i..end]);
                i = end;
            }

            '{' => {
                let repeats = out
                    .chars()
                    .last()
                    .is_some_and(|last| !matches!(last, '(' | '|'));

                if let Some(end) = repetition_end(&chars, i).filter(|_| repeats) {
                    out.extend(&chars[i..end]);
                    i = end;
                } else {
                    out.push_str("\\{");
                    i += 1;
                }
            }

            '}' => {
                out.push_str("\\}");
                i += 1;
            }

            other => {
                out.push(other);
                i += 1;
            }
        }
    }

    out
}

fn class_end(chars: &[char], start: usize) -> usize {
    let mut i = start + 1;
    if chars.get(i) == Some(&'^') {
        i += 1;
    }
    if chars.get(i) == Some(&']') {
        i += 1;
    }

    while i < chars.len() {
        match chars[i] {
            '\\' => i += 2,
            '[' if chars.get(i + 1) == Some(&':') => {
                let close = (i + 2..chars.len().saturating_sub(1))
                    .find(|&j| chars[j] == ':' && chars[j + 1] == ']');

                i = close.map_or(i + 1, |j| j + 2);
            }

            ']' => return i + 1,
            _ => i += 1,
        }
    }

    chars.len()
}

fn repetition_end(chars: &[char], start: usize) -> Option<usize> {
    let mut i = start + 1;
    let digits = |i: &mut usize| {
        let from = *i;
        while chars.get(*i).is_some_and(char::is_ascii_digit) {
            *i += 1;
        }
        *i > from
    };

    if !digits(&mut i) {
        return None;
    }
    if chars.get(i) == Some(&',') {
        i += 1;
        digits(&mut i);
    }

    (chars.get(i) == Some(&'}')).then_some(i + 1)
}

fn trim_newlines(text: &[u8], range: Range<usize>) -> Range<usize> {
    let slice = &text[range.clone()];
    let start = slice.iter().take_while(|&&byte| byte == b'\n').count();
    let end = slice.len()
        - slice[start..]
            .iter()
            .rev()
            .take_while(|&&byte| byte == b'\n')
            .count();

    range.start + start..range.start + end
}

pub fn entropy(bytes: &[u8]) -> f64 {
    let Ok(length) = u32::try_from(bytes.len()) else {
        return 0.0;
    };
    if length == 0 {
        return 0.0;
    }

    let mut counts = [0u32; 256];
    for &byte in bytes {
        counts[usize::from(byte)] += 1;
    }

    let length = f64::from(length);
    counts
        .iter()
        .filter(|&&count| count > 0)
        .map(|&count| {
            let share = f64::from(count) / length;
            -share * share.log2()
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn embedded() -> RuleSet {
        RuleSet::load(EMBEDDED, &[]).unwrap()
    }

    fn found(rules: &RuleSet, text: &str) -> Vec<String> {
        let mut ranges = Vec::new();
        rules.find(text.as_bytes(), &mut ranges);
        ranges
            .into_iter()
            .map(|range| text[range].to_owned())
            .collect()
    }

    #[test]
    fn every_embedded_rule_compiles() {
        let rules = embedded();
        assert!(
            rules.skipped().is_empty(),
            "rules that failed to compile: {:?}",
            rules.skipped()
        );

        assert!(rules.len() > 200);
    }

    #[test]
    fn honours_secret_groups_and_keywords() {
        let rules = RuleSet::load(
            r#"
            [[rules]]
            id = "demo"
            regex = '''demo_key\s*=\s*([a-z0-9]{12})'''
            keywords = ["demo_key"]
            "#,
            &[],
        )
        .unwrap();

        assert_eq!(
            found(&rules, "DEMO_KEY = a1b2c3d4e5f6"),
            Vec::<String>::new()
        );

        assert_eq!(found(&rules, "demo_key = a1b2c3d4e5f6"), ["a1b2c3d4e5f6"]);
    }

    #[test]
    fn applies_entropy_and_allowlists() {
        let rules = RuleSet::load(
            r#"
            [allowlist]
            regexes = ['''^allowed''']

            [[rules]]
            id = "demo"
            regex = '''tok_([A-Za-z0-9]+)'''
            entropy = 2.5
            [[rules.allowlists]]
            stopwords = ["sample"]
            [[rules.allowlists]]
            condition = "AND"
            regexTarget = "line"
            regexes = ['''# fixture''']
            paths = ['''\.md$''']
            "#,
            &[],
        )
        .unwrap();

        assert_eq!(found(&rules, "tok_aaaaaaaa"), Vec::<String>::new());
        assert_eq!(found(&rules, "tok_Zx81Qm4kLp"), ["Zx81Qm4kLp"]);
        assert_eq!(found(&rules, "tok_allowedQm4kLp"), Vec::<String>::new());
        assert_eq!(found(&rules, "tok_SAMPLE81Qm4k"), Vec::<String>::new());
        assert_eq!(found(&rules, "tok_Zx81Qm4kLp # fixture"), ["Zx81Qm4kLp"]);
        assert_eq!(
            found(&rules, "tok_Zx81Qm4kLp # gitleaks:allow"),
            ["Zx81Qm4kLp"]
        );
    }

    #[test]
    fn translates_literal_braces() {
        assert_eq!(translate(r"^\$(?:\d+|{\d+})$"), r"^\$(?:\d+|\{\d+\})$");
        assert_eq!(
            translate(r"^\{\{[ \t]*[\w ().|]+[ \t]*}}$"),
            r"^\{\{[ \t]*[\w ().|]+[ \t]*\}\}$"
        );

        assert_eq!(translate(r"a{2,}b{3}[{}]x{1,4}"), r"a{2,}b{3}[{}]x{1,4}");
        assert_eq!(translate(r"[[:alnum:]{]{8}"), r"[[:alnum:]{]{8}");
    }

    #[test]
    fn disables_rules_by_id() {
        let rules = RuleSet::load(
            EMBEDDED,
            &["GENERIC-API-KEY".to_owned(), "no-such-rule".to_owned()],
        )
        .unwrap();

        assert_eq!(rules.len(), embedded().len() - 1);
        assert_eq!(rules.unknown_disabled(), ["no-such-rule"]);
    }

    #[test]
    fn extends_the_default_rules() {
        let custom = r#"
            [extend]
            useDefault = true
            disabledRules = ["generic-api-key"]

            [[rules]]
            id = "internal-token"
            regex = '''itk_[a-z0-9]{16}'''
            keywords = ["itk_"]
        "#;

        let rules = RuleSet::load(custom, &[]).unwrap();

        assert_eq!(rules.len(), embedded().len());
        assert_eq!(
            found(&rules, "itk_a1b2c3d4e5f6a7b8"),
            ["itk_a1b2c3d4e5f6a7b8"]
        );
    }

    #[test]
    fn measures_entropy_in_bits() {
        assert!(entropy(b"").abs() < f64::EPSILON);
        assert!(entropy(b"aaaa").abs() < f64::EPSILON);
        assert!((entropy(b"abcd") - 2.0).abs() < f64::EPSILON);
    }
}

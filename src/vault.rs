use std::collections::HashMap;
use std::ops::Range;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, PoisonError, RwLock};

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};

use crate::placeholder::{Key, Placeholder};

const MAX_VALUES: usize = 4096;
const MIN_KNOWN_LEN: usize = 6;

pub struct Vault {
    key: Key,
    capacity: usize,
    clock: AtomicU64,
    state: RwLock<State>,
}

#[derive(Default)]
struct State {
    by_value: HashMap<Arc<str>, Entry>,
    by_placeholder: HashMap<Placeholder, Arc<str>>,
    known: Option<Arc<Known>>,
    generation: u64,
}

struct Entry {
    placeholder: Placeholder,
    used: AtomicU64,
}

pub struct Known {
    automaton: AhoCorasick,
}

impl Vault {
    pub fn new(key: Key) -> Self {
        Self::with_capacity(key, MAX_VALUES)
    }

    fn with_capacity(key: Key, capacity: usize) -> Self {
        Self {
            key,
            capacity,
            clock: AtomicU64::new(0),
            state: RwLock::default(),
        }
    }

    fn tick(&self) -> u64 {
        self.clock.fetch_add(1, Ordering::Relaxed)
    }

    pub fn placeholder(&self, value: &str) -> Placeholder {
        if let Some(entry) = self
            .state
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .by_value
            .get(value)
        {
            entry.used.store(self.tick(), Ordering::Relaxed);
            return entry.placeholder;
        }

        let mut state = self.state.write().unwrap_or_else(PoisonError::into_inner);
        if let Some(entry) = state.by_value.get(value) {
            return entry.placeholder;
        }
        if state.by_value.len() >= self.capacity {
            state.evict(self.capacity.div_ceil(16));
        }

        let value: Arc<str> = Arc::from(value);
        let placeholder = (0..=u32::MAX)
            .map(|salt| Placeholder::derive(&self.key, &value, salt))
            .find(|candidate| !state.by_placeholder.contains_key(candidate))
            .expect("some salt is free");

        let used = AtomicU64::new(self.tick());
        state
            .by_value
            .insert(Arc::clone(&value), Entry { placeholder, used });

        state.by_placeholder.insert(placeholder, value);
        state.known = None;
        state.generation += 1;
        placeholder
    }

    pub fn value(&self, placeholder: Placeholder) -> Option<Arc<str>> {
        let state = self.state.read().unwrap_or_else(PoisonError::into_inner);
        let value = state.by_placeholder.get(&placeholder)?;
        if let Some(entry) = state.by_value.get(value) {
            entry.used.store(self.tick(), Ordering::Relaxed);
        }

        Some(Arc::clone(value))
    }

    pub fn len(&self) -> usize {
        self.state
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .by_value
            .len()
    }

    pub fn is_empty(&self) -> bool {
        self.state
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .by_value
            .is_empty()
    }

    pub fn known(&self) -> Option<Arc<Known>> {
        let (generation, values) = {
            let state = self.state.read().unwrap_or_else(PoisonError::into_inner);
            if let Some(known) = &state.known {
                return Some(Arc::clone(known));
            }

            let values: Vec<Arc<str>> = state
                .by_value
                .keys()
                .filter(|value| value.len() >= MIN_KNOWN_LEN)
                .cloned()
                .collect();

            (state.generation, values)
        };

        if values.is_empty() {
            return None;
        }

        let automaton = AhoCorasickBuilder::new()
            .match_kind(MatchKind::LeftmostLongest)
            .build(values.iter().map(AsRef::<str>::as_ref))
            .expect("known values build an automaton");

        let known = Arc::new(Known { automaton });

        let mut state = self.state.write().unwrap_or_else(PoisonError::into_inner);
        if state.generation == generation {
            state.known = Some(Arc::clone(&known));
        }
        Some(known)
    }
}

impl State {
    fn evict(&mut self, count: usize) {
        let mut ages: Vec<(u64, Arc<str>)> = self
            .by_value
            .iter()
            .map(|(value, entry)| (entry.used.load(Ordering::Relaxed), Arc::clone(value)))
            .collect();

        ages.sort_unstable_by_key(|(used, _)| *used);

        for (_, value) in ages.into_iter().take(count) {
            if let Some(entry) = self.by_value.remove(&value) {
                self.by_placeholder.remove(&entry.placeholder);
            }
        }

        self.known = None;
        self.generation += 1;
    }
}

impl Known {
    pub fn find(&self, text: &[u8], found: &mut Vec<Range<usize>>) {
        for hit in self.automaton.find_iter(text) {
            let before = hit.start().checked_sub(1).map(|i| text[i]);
            let after = text.get(hit.end()).copied();
            if !before.is_some_and(|byte| byte.is_ascii_alphanumeric())
                && !after.is_some_and(|byte| byte.is_ascii_alphanumeric())
            {
                found.push(hit.range());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_values_both_ways() {
        let vault = Vault::new(Key::fixed(3));
        assert!(vault.is_empty());

        let placeholder = vault.placeholder("Zx81Qm4kLp9");
        assert_eq!(vault.placeholder("Zx81Qm4kLp9"), placeholder);
        assert_ne!(vault.placeholder("another-value-1"), placeholder);
        assert_eq!(vault.value(placeholder).as_deref(), Some("Zx81Qm4kLp9"));
    }

    #[test]
    fn evicts_the_least_recently_used_values_when_full() {
        let vault = Vault::with_capacity(Key::fixed(4), 16);
        let first = vault.placeholder("value-0000");

        for index in 1..16 {
            vault.placeholder(&format!("value-{index:04}"));
        }
        vault.value(first);
        vault.placeholder("value-0016");

        assert_eq!(vault.len(), 16);
        assert_eq!(vault.value(first).as_deref(), Some("value-0000"));
        assert_eq!(
            vault.placeholder("value-0016"),
            vault.placeholder("value-0016")
        );

        assert!(
            vault
                .value(Placeholder::derive(&Key::fixed(4), "value-0001", 0))
                .is_none()
        );
    }

    #[test]
    fn finds_known_values_on_word_boundaries() {
        let vault = Vault::new(Key::fixed(3));
        vault.placeholder("Zx81Qm4kLp9");
        vault.placeholder("short");

        let text = b"echo Zx81Qm4kLp9; xZx81Qm4kLp9; short";
        let mut found = Vec::new();
        vault.known().unwrap().find(text, &mut found);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0], 5..16);
    }
}

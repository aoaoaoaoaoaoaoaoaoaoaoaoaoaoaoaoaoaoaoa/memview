use crate::model::Bytes;
use regex::Regex;

#[derive(Clone, Debug)]
pub struct Search {
    pattern: String,
    regex: Regex,
}

impl Search {
    pub fn compile(pattern: String) -> Result<Option<Self>, String> {
        if pattern.is_empty() {
            return Ok(None);
        }
        Regex::new(&pattern)
            .map(|regex| Some(Self { pattern, regex }))
            .map_err(|error| error.to_string())
    }

    #[must_use]
    pub fn pattern(&self) -> &str {
        &self.pattern
    }

    #[must_use]
    pub fn matches(&self, value: &str) -> bool {
        self.regex.is_match(value)
    }
}

#[derive(Clone, Debug, Default)]
pub struct SearchDraft {
    input: String,
    error: Option<String>,
}

impl SearchDraft {
    #[must_use]
    pub fn new(active: Option<&Search>) -> Self {
        Self {
            input: active.map_or_else(String::new, |search| search.pattern().to_string()),
            error: None,
        }
    }

    #[must_use]
    pub fn from_input(input: String) -> Self {
        Self { input, error: None }
    }

    #[must_use]
    pub fn input(&self) -> &str {
        &self.input
    }

    #[must_use]
    pub fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }

    pub fn push(&mut self, character: char) {
        self.input.push(character);
        self.error = None;
    }

    pub fn backspace(&mut self) {
        let _ = self.input.pop();
        self.error = None;
    }

    pub fn clear(&mut self) {
        self.input.clear();
        self.error = None;
    }

    pub fn fail(&mut self, error: String) {
        self.error = Some(error);
    }

    #[must_use]
    pub fn into_input(self) -> String {
        self.input
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum SearchRole {
    #[default]
    Ordinary,
    Match,
    Context,
}

impl SearchRole {
    #[must_use]
    pub fn is_context(self) -> bool {
        self == Self::Context
    }
}

#[derive(Clone, Debug)]
pub struct SearchSummary {
    pub matches: usize,
    pub total: Bytes,
    pub lens: &'static str,
}

impl SearchSummary {
    #[must_use]
    pub const fn new(lens: &'static str) -> Self {
        Self {
            matches: 0,
            total: Bytes::ZERO,
            lens,
        }
    }

    pub fn strike(&mut self, value: Bytes) {
        self.matches += 1;
        self.total += value;
    }

    pub fn hit(&mut self) {
        self.matches += 1;
    }

    pub fn attribute(&mut self, value: Bytes) {
        self.total += value;
    }
}

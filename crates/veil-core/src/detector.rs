use regex::{Regex, RegexSet};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::LazyLock;

/// Types of sensitive PII or secret entities detected by `pii-veil-core`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EntityKind {
    Email,
    CreditCard,
    Iban,
    OpenAiKey,
    AnthropicKey,
    AwsAccessKey,
    GitHubToken,
    SlackToken,
    GoogleApiKey,
    StripeKey,
    JwtToken,
    PrivateKey,
    ConnectionUri,
    WebhookUrl,
    Phone,
    IpV4,
    IpV6,
    MacAddress,
    NationalId,
    Custom(String),
}

impl EntityKind {
    /// Returns the short canonical label used for placeholder tokens (e.g. `EMAIL`, `CREDIT_CARD`).
    pub fn label(&self) -> &str {
        match self {
            EntityKind::Email => "EMAIL",
            EntityKind::CreditCard => "CREDIT_CARD",
            EntityKind::Iban => "IBAN",
            EntityKind::OpenAiKey => "OPENAI_KEY",
            EntityKind::AnthropicKey => "ANTHROPIC_KEY",
            EntityKind::AwsAccessKey => "AWS_KEY",
            EntityKind::GitHubToken => "GITHUB_TOKEN",
            EntityKind::SlackToken => "SLACK_TOKEN",
            EntityKind::GoogleApiKey => "GOOGLE_API_KEY",
            EntityKind::StripeKey => "STRIPE_KEY",
            EntityKind::JwtToken => "JWT_TOKEN",
            EntityKind::PrivateKey => "PRIVATE_KEY",
            EntityKind::ConnectionUri => "CONNECTION_URI",
            EntityKind::WebhookUrl => "WEBHOOK_URL",
            EntityKind::Phone => "PHONE",
            EntityKind::IpV4 => "IPV4",
            EntityKind::IpV6 => "IPV6",
            EntityKind::MacAddress => "MAC_ADDRESS",
            EntityKind::NationalId => "NATIONAL_ID",
            EntityKind::Custom(name) => name.as_str(),
        }
    }

    /// Priority used when resolving overlapping spans (higher wins).
    pub fn priority(&self) -> u8 {
        match self {
            EntityKind::PrivateKey => 105,
            EntityKind::ConnectionUri => 102,
            EntityKind::WebhookUrl => 101,
            EntityKind::JwtToken => 100,
            EntityKind::AnthropicKey => 98,
            EntityKind::OpenAiKey => 95,
            EntityKind::StripeKey => 95,
            EntityKind::GitHubToken => 95,
            EntityKind::SlackToken => 95,
            EntityKind::GoogleApiKey => 92,
            EntityKind::AwsAccessKey => 90,
            EntityKind::Email => 85,
            EntityKind::Iban => 82,
            EntityKind::CreditCard => 80,
            EntityKind::IpV6 => 72,
            EntityKind::IpV4 => 70,
            EntityKind::MacAddress => 68,
            EntityKind::NationalId => 65,
            EntityKind::Phone => 60,
            EntityKind::Custom(_) => 88,
        }
    }
}

/// A detected sensitive span within an input text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectedSpan {
    pub kind: EntityKind,
    pub start: usize,
    pub end: usize,
    pub original: String,
}

const PATTERN_JWT: &str =
    r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b";
const PATTERN_ANTHROPIC: &str = r"\bsk-ant-(?:api03-|sid01-)?[A-Za-z0-9_\-]{20,160}\b";
const PATTERN_OPENAI: &str = r"\bsk-(?:proj-|live-|test-)?[A-Za-z0-9_\-]{20,160}\b";
const PATTERN_STRIPE: &str = r"\b(?:sk|rk|pk)_(?:live|test)_[0-9a-zA-Z]{24,99}\b";
const PATTERN_GITHUB: &str =
    r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}\b|\bgithub_pat_[A-Za-z0-9_]{22,255}\b";
const PATTERN_SLACK: &str = r"\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9\-]*\b";
const PATTERN_GOOGLE_API: &str = r"\bAIza[0-9A-Za-z_\-]{35}\b";
const PATTERN_AWS: &str = r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b";
const PATTERN_PRIVATE_KEY: &str = r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----";
const PATTERN_CONN_URI: &str = r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis(?:s)?|amqp(?:s)?)://[^\s\x22\x27<>]+:[^\s\x22\x27<>@]+@[^\s\x22\x27<>]+";
const PATTERN_WEBHOOK: &str = r"https://(?:hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]+|(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]+)";
const PATTERN_EMAIL: &str = r"(?i)\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,24}\b";
const PATTERN_IBAN: &str = r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){3,7}(?:[ ]?[A-Z0-9]{1,3})?\b";
const PATTERN_CREDIT_CARD: &str = r"\b(?:\d[ \-]*?){13,19}\b";
const PATTERN_IPV4: &str = r"\b(?:\d{1,3}\.){3}\d{1,3}\b";
const PATTERN_IPV6: &str =
    r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b";
const PATTERN_MAC: &str = r"\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b";
// Matches US SSN (123-45-6789), AR CUIT/CUIL (20-12345678-9), CL RUT (12.345.678-5 / 12345678-K), ES DNI/NIE (12345678Z / X1234567L)
const PATTERN_NATIONAL_ID: &str = r"\b(?:\d{3}-\d{2}-\d{4}|\d{2}-\d{8}-\d|\d{1,2}\.\d{3}\.\d{3}-[\dkK]|\d{7,8}-[\dkK]|\d{8}[A-HJ-NP-TV-Z]|[XYZxyz]\d{7}[A-HJ-NP-TV-Za-hj-np-tv-z])\b";
const PATTERN_PHONE: &str =
    r"(?:\+\d{1,3}[\s\-]?)?(?:\(\d{2,4}\)[\s\-]?|\b\d{2,4}[\s\-])\d{3,4}[\s\-]\d{3,4}\b";

static BUILTIN_REGEX_SET: LazyLock<RegexSet> = LazyLock::new(|| {
    RegexSet::new([
        PATTERN_JWT,
        PATTERN_ANTHROPIC,
        PATTERN_OPENAI,
        PATTERN_STRIPE,
        PATTERN_GITHUB,
        PATTERN_SLACK,
        PATTERN_GOOGLE_API,
        PATTERN_AWS,
        PATTERN_PRIVATE_KEY,
        PATTERN_CONN_URI,
        PATTERN_WEBHOOK,
        PATTERN_EMAIL,
        PATTERN_IBAN,
        PATTERN_CREDIT_CARD,
        PATTERN_IPV4,
        PATTERN_IPV6,
        PATTERN_MAC,
        PATTERN_NATIONAL_ID,
        PATTERN_PHONE,
    ])
    .expect("valid builtin regex set")
});

static JWT_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(PATTERN_JWT).unwrap());
static ANTHROPIC_KEY_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(PATTERN_ANTHROPIC).unwrap());
static OPENAI_KEY_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(PATTERN_OPENAI).unwrap());
static STRIPE_KEY_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(PATTERN_STRIPE).unwrap());
static GITHUB_TOKEN_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(PATTERN_GITHUB).unwrap());
static SLACK_TOKEN_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(PATTERN_SLACK).unwrap());
static GOOGLE_API_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(PATTERN_GOOGLE_API).unwrap());
static AWS_KEY_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(PATTERN_AWS).unwrap());
static PRIVATE_KEY_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(PATTERN_PRIVATE_KEY).unwrap());
static CONN_URI_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(PATTERN_CONN_URI).unwrap());
static WEBHOOK_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(PATTERN_WEBHOOK).unwrap());
static EMAIL_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(PATTERN_EMAIL).unwrap());
static IBAN_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(PATTERN_IBAN).unwrap());
static CREDIT_CARD_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(PATTERN_CREDIT_CARD).unwrap());
static IPV4_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(PATTERN_IPV4).unwrap());
static IPV6_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(PATTERN_IPV6).unwrap());
static MAC_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(PATTERN_MAC).unwrap());
static NATIONAL_ID_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(PATTERN_NATIONAL_ID).unwrap());
static PHONE_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(PATTERN_PHONE).unwrap());

/// Validates a credit card number using the Luhn checksum algorithm.
pub fn is_valid_luhn(candidate: &str) -> bool {
    let digits: Vec<u32> = candidate
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();

    if !(13..=19).contains(&digits.len()) {
        return false;
    }

    // Reject trivial all-same digit sequences like 0000000000000000
    if digits.iter().all(|&d| d == digits[0]) {
        return false;
    }

    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(idx, &d)| {
            if idx % 2 == 1 {
                let doubled = d * 2;
                if doubled > 9 {
                    doubled - 9
                } else {
                    doubled
                }
            } else {
                d
            }
        })
        .sum();

    sum.is_multiple_of(10)
}

/// Validates an International Bank Account Number (IBAN) using the ISO 13616 Mod-97 algorithm.
pub fn is_valid_iban(candidate: &str) -> bool {
    let clean: Vec<char> = candidate
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();

    if !(15..=34).contains(&clean.len()) {
        return false;
    }

    if !clean[0].is_ascii_uppercase()
        || !clean[1].is_ascii_uppercase()
        || !clean[2].is_ascii_digit()
        || !clean[3].is_ascii_digit()
    {
        return false;
    }

    // Rearrange: move first 4 chars to the end, then compute mod 97 iteratively
    let mut remainder: u64 = 0;
    for &ch in clean[4..].iter().chain(clean[..4].iter()) {
        if ch.is_ascii_digit() {
            remainder = (remainder * 10 + (ch as u64 - b'0' as u64)) % 97;
        } else if ch.is_ascii_uppercase() {
            let val = (ch as u64 - b'A' as u64) + 10;
            remainder = (remainder * 100 + val) % 97;
        } else {
            return false;
        }
    }

    remainder == 1
}

/// Validates a Spanish DNI (`12345678Z`) or NIE (`X1234567L`) using the official Modulo-23 table.
pub fn is_valid_spanish_dni_nie(candidate: &str) -> bool {
    const TABLE: &[u8; 23] = b"TRWAGMYFPDXBNJZSQVHLCKE";
    let clean = candidate.trim().to_ascii_uppercase();
    if clean.len() != 9 {
        return false;
    }
    let bytes = clean.as_bytes();
    let first_digit = match bytes[0] {
        b'0'..=b'9' => (bytes[0] - b'0') as u32,
        b'X' => 0,
        b'Y' => 1,
        b'Z' => 2,
        _ => return false,
    };

    let mut num = first_digit;
    for &b in &bytes[1..8] {
        if !b.is_ascii_digit() {
            return false;
        }
        num = num * 10 + (b - b'0') as u32;
    }

    let expected_letter = TABLE[(num % 23) as usize];
    bytes[8] == expected_letter
}

/// Validates an Argentine CUIT/CUIL (`20-12345678-6`) using the official Modulo-11 weights.
pub fn is_valid_arg_cuit(candidate: &str) -> bool {
    const WEIGHTS: [u32; 10] = [5, 4, 3, 2, 7, 6, 5, 4, 3, 2];
    let digits: Vec<u32> = candidate
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();

    if digits.len() != 11 {
        return false;
    }

    let sum: u32 = digits[..10]
        .iter()
        .zip(WEIGHTS.iter())
        .map(|(&d, &w)| d * w)
        .sum();

    let rem = 11 - (sum % 11);
    let expected = match rem {
        11 => 0,
        10 => 9,
        other => other,
    };

    digits[10] == expected
}

/// Validates a Chilean RUT (`12.345.678-5` or `12345678-K`) using Modulo-11 check digit.
pub fn is_valid_chilean_rut(candidate: &str) -> bool {
    let Some((body, verifier_str)) = candidate.split_once('-') else {
        return false;
    };
    if verifier_str.len() != 1 {
        return false;
    }
    let verifier = verifier_str.chars().next().unwrap().to_ascii_uppercase();
    let digits: Vec<u32> = body
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();

    if !(7..=8).contains(&digits.len()) {
        return false;
    }

    let mut factor = 2u32;
    let mut sum = 0u32;
    for &d in digits.iter().rev() {
        sum += d * factor;
        factor = if factor == 7 { 2 } else { factor + 1 };
    }

    let rem = 11 - (sum % 11);
    let expected = match rem {
        11 => '0',
        10 => 'K',
        n => char::from_digit(n, 10).unwrap_or('?'),
    };

    verifier == expected
}

/// Validates a candidate National ID (US SSN, Spanish DNI/NIE, Argentine CUIT, or Chilean RUT).
pub fn is_valid_national_id(candidate: &str) -> bool {
    let bytes = candidate.as_bytes();
    // 1. US SSN: XXX-XX-XXXX
    if bytes.len() == 11 && bytes[3] == b'-' && bytes[6] == b'-' {
        let area: u16 = candidate[0..3].parse().unwrap_or(0);
        let group: u8 = candidate[4..6].parse().unwrap_or(0);
        let serial: u16 = candidate[7..11].parse().unwrap_or(0);
        return area != 0 && area != 666 && area < 900 && group != 0 && serial != 0;
    }
    // 2. Argentine CUIT/CUIL: XX-XXXXXXXX-X
    if bytes.len() == 13 && bytes[2] == b'-' && bytes[11] == b'-' {
        return is_valid_arg_cuit(candidate);
    }
    // 3. Spanish DNI / NIE: 9 chars ending in letter
    if bytes.len() == 9 && bytes[8].is_ascii_alphabetic() {
        return is_valid_spanish_dni_nie(candidate);
    }
    // 4. Chilean RUT: contains '-' with 1 verifier char
    if candidate.contains('-') {
        return is_valid_chilean_rut(candidate);
    }
    false
}

/// Validates that an IPv4 candidate has valid 0..=255 octets.
pub fn is_valid_ipv4(candidate: &str) -> bool {
    let parts: Vec<&str> = candidate.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    parts.iter().all(|part| part.parse::<u8>().is_ok())
}

/// Custom user-defined regex rule.
#[derive(Debug, Clone)]
pub struct CustomRule {
    pub name: String,
    pub pattern: Regex,
}

/// Detector pipeline configuration.
#[derive(Debug, Clone)]
pub struct DetectorPipeline {
    custom_rules: Vec<CustomRule>,
    disabled_kinds: HashSet<EntityKind>,
    allowlist_exact: HashSet<String>,
    allowlist_suffixes: Vec<String>,
}

impl Default for DetectorPipeline {
    fn default() -> Self {
        Self::new()
    }
}

impl DetectorPipeline {
    pub fn new() -> Self {
        Self {
            custom_rules: Vec::new(),
            disabled_kinds: HashSet::new(),
            allowlist_exact: HashSet::new(),
            allowlist_suffixes: Vec::new(),
        }
    }

    /// Registers a custom entity detector with a label (e.g., `"EMPLOYEE_ID"`) and regex pattern.
    pub fn add_custom_rule(
        &mut self,
        name: impl Into<String>,
        regex_pattern: &str,
    ) -> Result<(), regex::Error> {
        let compiled = Regex::new(regex_pattern)?;
        self.custom_rules.push(CustomRule {
            name: name.into(),
            pattern: compiled,
        });
        Ok(())
    }

    /// Disables a specific built-in [`EntityKind`] from being detected.
    pub fn disable_entity(&mut self, kind: EntityKind) {
        self.disabled_kinds.insert(kind);
    }

    /// Adds an allowlist entry.
    /// - If it starts with `@` (e.g. `"@example.com"`), any email ending with that domain suffix is ignored.
    /// - Otherwise, exact matches (case-insensitive) are ignored (e.g. `"127.0.0.1"`, `"test@company.com"`).
    pub fn add_allowlist(&mut self, entry: impl Into<String>) {
        let trimmed = entry.into().trim().to_ascii_lowercase();
        if trimmed.is_empty() {
            return;
        }
        if trimmed.starts_with('@') {
            self.allowlist_suffixes.push(trimmed);
        } else {
            self.allowlist_exact.insert(trimmed);
        }
    }

    fn is_allowed(&self, candidate: &str) -> bool {
        if self.allowlist_exact.is_empty() && self.allowlist_suffixes.is_empty() {
            return false;
        }
        let lower = candidate.to_ascii_lowercase();
        if self.allowlist_exact.contains(&lower) {
            return true;
        }
        self.allowlist_suffixes
            .iter()
            .any(|suffix| lower.ends_with(suffix))
    }

    #[inline]
    fn push_matches(&self, raw: &mut Vec<DetectedSpan>, re: &Regex, kind: EntityKind, text: &str) {
        if self.disabled_kinds.contains(&kind) {
            return;
        }
        for m in re.find_iter(text) {
            let s = m.as_str();
            if !self.is_allowed(s) {
                raw.push(DetectedSpan {
                    kind: kind.clone(),
                    start: m.start(),
                    end: m.end(),
                    original: s.to_string(),
                });
            }
        }
    }

    /// Scans `text` for all sensitive entities and returns non-overlapping spans sorted by byte offset.
    /// Uses a single-pass `RegexSet` pre-filter to skip non-matching entity classes in $O(N)$ time.
    pub fn detect(&self, text: &str) -> Vec<DetectedSpan> {
        if text.is_empty() {
            return Vec::new();
        }

        let mut raw: Vec<DetectedSpan> = Vec::new();
        let matches = BUILTIN_REGEX_SET.matches(text);

        if matches.matched_any() {
            if matches.matched(0) {
                self.push_matches(&mut raw, &JWT_RE, EntityKind::JwtToken, text);
            }
            if matches.matched(1) {
                self.push_matches(&mut raw, &ANTHROPIC_KEY_RE, EntityKind::AnthropicKey, text);
            }
            if matches.matched(2) {
                self.push_matches(&mut raw, &OPENAI_KEY_RE, EntityKind::OpenAiKey, text);
            }
            if matches.matched(3) {
                self.push_matches(&mut raw, &STRIPE_KEY_RE, EntityKind::StripeKey, text);
            }
            if matches.matched(4) {
                self.push_matches(&mut raw, &GITHUB_TOKEN_RE, EntityKind::GitHubToken, text);
            }
            if matches.matched(5) {
                self.push_matches(&mut raw, &SLACK_TOKEN_RE, EntityKind::SlackToken, text);
            }
            if matches.matched(6) {
                self.push_matches(&mut raw, &GOOGLE_API_RE, EntityKind::GoogleApiKey, text);
            }
            if matches.matched(7) {
                self.push_matches(&mut raw, &AWS_KEY_RE, EntityKind::AwsAccessKey, text);
            }
            if matches.matched(8) {
                self.push_matches(&mut raw, &PRIVATE_KEY_RE, EntityKind::PrivateKey, text);
            }
            if matches.matched(9) {
                self.push_matches(&mut raw, &CONN_URI_RE, EntityKind::ConnectionUri, text);
            }
            if matches.matched(10) {
                self.push_matches(&mut raw, &WEBHOOK_RE, EntityKind::WebhookUrl, text);
            }
            if matches.matched(11) {
                self.push_matches(&mut raw, &EMAIL_RE, EntityKind::Email, text);
            }
            if matches.matched(12) && !self.disabled_kinds.contains(&EntityKind::Iban) {
                for m in IBAN_RE.find_iter(text) {
                    let s = m.as_str();
                    if is_valid_iban(s) && !self.is_allowed(s) {
                        raw.push(DetectedSpan {
                            kind: EntityKind::Iban,
                            start: m.start(),
                            end: m.end(),
                            original: s.to_string(),
                        });
                    }
                }
            }
            if matches.matched(13) && !self.disabled_kinds.contains(&EntityKind::CreditCard) {
                for m in CREDIT_CARD_RE.find_iter(text) {
                    let s = m.as_str();
                    if is_valid_luhn(s) && !self.is_allowed(s) {
                        raw.push(DetectedSpan {
                            kind: EntityKind::CreditCard,
                            start: m.start(),
                            end: m.end(),
                            original: s.to_string(),
                        });
                    }
                }
            }
            if matches.matched(14) && !self.disabled_kinds.contains(&EntityKind::IpV4) {
                for m in IPV4_RE.find_iter(text) {
                    let s = m.as_str();
                    if is_valid_ipv4(s) && !self.is_allowed(s) {
                        raw.push(DetectedSpan {
                            kind: EntityKind::IpV4,
                            start: m.start(),
                            end: m.end(),
                            original: s.to_string(),
                        });
                    }
                }
            }
            if matches.matched(15) {
                self.push_matches(&mut raw, &IPV6_RE, EntityKind::IpV6, text);
            }
            if matches.matched(16) {
                self.push_matches(&mut raw, &MAC_RE, EntityKind::MacAddress, text);
            }
            if matches.matched(17) && !self.disabled_kinds.contains(&EntityKind::NationalId) {
                for m in NATIONAL_ID_RE.find_iter(text) {
                    let s = m.as_str();
                    if is_valid_national_id(s) && !self.is_allowed(s) {
                        raw.push(DetectedSpan {
                            kind: EntityKind::NationalId,
                            start: m.start(),
                            end: m.end(),
                            original: s.to_string(),
                        });
                    }
                }
            }
            if matches.matched(18) && !self.disabled_kinds.contains(&EntityKind::Phone) {
                for m in PHONE_RE.find_iter(text) {
                    let s = m.as_str();
                    let digit_count = s.chars().filter(|c| c.is_ascii_digit()).count();
                    if (7..=15).contains(&digit_count) && !self.is_allowed(s) {
                        raw.push(DetectedSpan {
                            kind: EntityKind::Phone,
                            start: m.start(),
                            end: m.end(),
                            original: s.to_string(),
                        });
                    }
                }
            }
        }

        for rule in &self.custom_rules {
            for m in rule.pattern.find_iter(text) {
                let s = m.as_str();
                if !self.is_allowed(s) {
                    raw.push(DetectedSpan {
                        kind: EntityKind::Custom(rule.name.clone()),
                        start: m.start(),
                        end: m.end(),
                        original: s.to_string(),
                    });
                }
            }
        }

        resolve_overlaps(raw)
    }
}

/// Resolves overlapping spans by keeping higher priority or longer matches, then sorting by start position.
fn resolve_overlaps(mut spans: Vec<DetectedSpan>) -> Vec<DetectedSpan> {
    if spans.len() <= 1 {
        return spans;
    }

    // Sort by start asc, then length desc, then priority desc
    spans.sort_by(|a, b| {
        a.start
            .cmp(&b.start)
            .then_with(|| (b.end - b.start).cmp(&(a.end - a.start)))
            .then_with(|| b.kind.priority().cmp(&a.kind.priority()))
    });

    let mut accepted: Vec<DetectedSpan> = Vec::with_capacity(spans.len());
    for candidate in spans {
        if let Some(last) = accepted.last_mut() {
            if candidate.start < last.end {
                // Overlap detected: only replace if strictly higher priority and covers at least as much
                if candidate.kind.priority() > last.kind.priority()
                    && (candidate.end - candidate.start) >= (last.end - last.start)
                {
                    *last = candidate;
                }
                continue;
            }
        }
        accepted.push(candidate);
    }

    accepted
}

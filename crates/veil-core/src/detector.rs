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
// Matches regional National IDs:
// - US SSN (123-45-6789)
// - AR CUIT/CUIL (20-12345678-6)
// - CL RUT (12.345.678-5 / 12345678-K)
// - ES DNI/NIE (12345678Z / X1234567L)
// - BR CPF (529.982.247-25) & CNPJ (11.222.333/0001-81)
// - MX CURP (18 chars, e.g. VECJ880326HDFRRR03)
// - CA SIN (130-692-544 / 130 692 544)
// - UK NINO (AB 12 34 56 C / AB123456C)
// - IN Aadhaar (XXXX XXXX XXXX) & PAN (ABCPD1234F)
// - DE Steuer-ID (11 digits, e.g. 86095742719)
const PATTERN_NATIONAL_ID: &str = r"\b(?:\d{2}\.\d{3}\.\d{3}/\d{4}-\d{2}|\d{3}\.\d{3}\.\d{3}-\d{2}|[A-Z][AEIOUX][A-Z]{2}\d{6}[HMX](?:AS|BC|BS|CC|CS|CH|CL|CM|DF|DG|GT|GR|HG|JC|MC|MN|MS|NT|NL|OC|PL|QT|QR|SP|SL|SR|TC|TS|TL|VZ|YN|ZS|NE)[B-DF-HJ-NP-TV-ZX]{3}[0-9A-Z]\d|[A-Z]{3}[ABCFGHLJPT][A-Z]\d{4}[A-Z]|[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z](?:[ ]?\d{2}){3}[ ]?[A-D]|[2-9]\d{3}[ ]\d{4}[ ]\d{4}|\d{3}-\d{2}-\d{4}|\d{3}[ \-]\d{3}[ \-]\d{3}|\d{2}-\d{8}-\d|\d{1,2}\.\d{3}\.\d{3}-[\dkK]|\d{7,8}-[\dkK]|\d{8}[A-HJ-NP-TV-Z]|[XYZxyz]\d{7}[A-HJ-NP-TV-Za-hj-np-tv-z]|[1-9]\d{10})\b";
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

/// Validates a credit card candidate using Luhn checksum, separator consistency,
/// and official IIN/BIN issuer prefix + network length rules to eliminate false positives
/// on Snowflake IDs, timestamps, IMEIs, and tracking numbers.
pub fn is_valid_credit_card(candidate: &str) -> bool {
    // Reject mixed separators (both spaces and hyphens) or consecutive separators
    let has_space = candidate.contains(' ');
    let has_hyphen = candidate.contains('-');
    if (has_space && has_hyphen) || candidate.contains("  ") || candidate.contains("--") {
        return false;
    }

    let digits: Vec<u8> = candidate
        .bytes()
        .filter(|b| b.is_ascii_digit())
        .map(|b| b - b'0')
        .collect();
    let len = digits.len();
    if !(13..=19).contains(&len) {
        return false;
    }

    let p1 = digits[0];
    let p2 = (digits[0] as u16) * 10 + (digits[1] as u16);
    let p3 = p2 * 10 + (digits[2] as u16);
    let p4 = p3 * 10 + (digits[3] as u16);

    let valid_iin = match p1 {
        // Visa: 13, 16, or 19 digits
        4 => matches!(len, 13 | 16 | 19),
        // Mastercard: 51-55 (16 digits)
        5 if (51..=55).contains(&p2) => len == 16,
        // Mastercard 2-series: 2221-2720 (16 digits)
        2 if (2221..=2720).contains(&p4) => len == 16,
        // American Express: 34, 37 (15 digits)
        3 if matches!(p2, 34 | 37) => len == 15,
        // Diners Club: 300-305, 36, 38, 39 (14 or 16 digits)
        3 if (300..=305).contains(&p3) || matches!(p2, 36 | 38 | 39) => matches!(len, 14 | 16),
        // JCB: 3528-3589 (16..=19 digits)
        3 if (3528..=3589).contains(&p4) => (16..=19).contains(&len),
        // Discover: 6011, 644-649, 65 (16 or 19 digits)
        6 if p4 == 6011 || (644..=649).contains(&p3) || p2 == 65 => matches!(len, 16 | 19),
        // UnionPay: 62 (16..=19 digits)
        6 if p2 == 62 => (16..=19).contains(&len),
        _ => false,
    };

    valid_iin && is_valid_luhn(candidate)
}

/// Computes Shannon entropy (bits per byte) in $O(N)$ using a zero-allocation stack histogram.
pub fn shannon_entropy(s: &str) -> f64 {
    let bytes = s.as_bytes();
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let len = bytes.len() as f64;
    let mut entropy = 0.0f64;
    for &c in &counts {
        if c > 0 {
            let p = (c as f64) / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Returns `true` if a candidate secret looks like a documentation placeholder or low-entropy dummy.
fn is_placeholder_secret(candidate: &str, min_entropy: f64) -> bool {
    let lower = candidate.to_ascii_lowercase();
    const PLACEHOLDER_TOKENS: &[&str] = &[
        "example",
        "placeholder",
        "your-",
        "your_",
        "dummy",
        "sample",
        "changeme",
        "replace_me",
        "replace-me",
        "insert_",
        "insert-",
        "redacted",
        "xxxx",
        "00000000",
        "1234567890",
    ];
    if PLACEHOLDER_TOKENS.iter().any(|p| lower.contains(p)) {
        return true;
    }
    let body = candidate
        .strip_prefix("sk-ant-api03-")
        .or_else(|| candidate.strip_prefix("sk-ant-sid01-"))
        .or_else(|| candidate.strip_prefix("sk-ant-"))
        .or_else(|| candidate.strip_prefix("sk-proj-"))
        .or_else(|| candidate.strip_prefix("sk-live-"))
        .or_else(|| candidate.strip_prefix("sk-test-"))
        .or_else(|| candidate.strip_prefix("sk-"))
        .or_else(|| candidate.strip_prefix("github_pat_"))
        .or_else(|| candidate.strip_prefix("xoxb-"))
        .or_else(|| candidate.strip_prefix("xoxp-"))
        .or_else(|| candidate.strip_prefix("xoxa-"))
        .or_else(|| candidate.strip_prefix("xoxr-"))
        .or_else(|| candidate.strip_prefix("xoxs-"))
        .or_else(|| candidate.strip_prefix("AIza"))
        .or_else(|| candidate.strip_prefix("AKIA"))
        .or_else(|| candidate.strip_prefix("ASIA"))
        .or_else(|| candidate.strip_prefix("ABIA"))
        .or_else(|| candidate.strip_prefix("ACCA"))
        .unwrap_or(candidate);

    shannon_entropy(body) < min_entropy
}

/// Rejects retina asset filenames (`hero@2x.png`, `logo@3x.webp`) and code paths matched as emails.
fn is_valid_email_candidate(candidate: &str) -> bool {
    let lower = candidate.to_ascii_lowercase();
    const NON_EMAIL_EXTENSIONS: &[&str] = &[
        ".png", ".jpg", ".jpeg", ".webp", ".svg", ".gif", ".ico", ".avif", ".bmp", ".css", ".js",
        ".mjs", ".ts", ".tsx", ".jsx", ".rs", ".py", ".go", ".java", ".json", ".yaml", ".yml",
        ".toml", ".xml", ".wasm", ".map",
    ];
    !NON_EMAIL_EXTENSIONS.iter().any(|ext| lower.ends_with(ext))
}

/// Extracts a lowercase UTF-8-safe context window around `[start..end]` in `text`.
fn context_window(text: &str, start: usize, end: usize, radius: usize) -> String {
    let mut win_start = start.saturating_sub(radius);
    while win_start < text.len() && !text.is_char_boundary(win_start) {
        win_start += 1;
    }
    let mut win_end = (end + radius).min(text.len());
    while win_end > 0 && !text.is_char_boundary(win_end) {
        win_end -= 1;
    }
    text[win_start..win_end].to_ascii_lowercase()
}

/// Returns `true` if the IPv4 match is likely a software version (`v1.2.3.4`, `Section 1.2.3.4`, `0.1.4.0`).
fn is_likely_version_not_ipv4(text: &str, start: usize, candidate: &str) -> bool {
    // 0.x.x.x (except 0.0.0.0) is almost always a software version (e.g. 0.1.4.0)
    if candidate.starts_with("0.") && candidate != "0.0.0.0" {
        return true;
    }
    // Check immediately preceding char for 'v' / 'V' (e.g. v1.2.3.4)
    if start > 0 {
        let prev_byte = text.as_bytes()[start - 1];
        if prev_byte == b'v' || prev_byte == b'V' {
            return true;
        }
    }
    let mut pre_start = start.saturating_sub(24);
    while pre_start < start && !text.is_char_boundary(pre_start) {
        pre_start += 1;
    }
    let prefix = text[pre_start..start].to_ascii_lowercase();
    const VERSION_DAMPENERS: &[&str] = &[
        "version", "ver.", "release", "section", "sec.", "kernel", "runtime", "build", "revision",
        "rfc ",
    ];
    VERSION_DAMPENERS.iter().any(|kw| prefix.contains(kw))
}

/// Rejects short Rust/C++ hex namespaces (`dead::beef`, `cafe::babe`) while keeping valid IPv6 addresses.
fn is_valid_ipv6_candidate(text: &str, start: usize, end: usize, candidate: &str) -> bool {
    if candidate.parse::<std::net::Ipv6Addr>().is_err() {
        return false;
    }
    let colon_count = candidate.bytes().filter(|&b| b == b':').count();
    if colon_count >= 3 {
        return true;
    }
    // For short `xxxx::yyyy` (exactly 2 colons), require explicit network context
    let ctx = context_window(text, start, end, 32);
    const IPV6_CONTEXT: &[&str] = &["ipv6", "ip6", "addr", "host", "fe80", "2001", "fd00"];
    IPV6_CONTEXT.iter().any(|kw| ctx.contains(kw))
}

/// Validates a phone candidate against dates (`2026-1125-1312`), port lists (`8080 3000 5432`),
/// and repeated digits (`0000-0000-0000`).
fn is_valid_phone_candidate(text: &str, start: usize, end: usize, candidate: &str) -> bool {
    let digits: Vec<u8> = candidate
        .bytes()
        .filter(|b| b.is_ascii_digit())
        .map(|b| b - b'0')
        .collect();
    if !(7..=15).contains(&digits.len()) {
        return false;
    }
    // Reject all-same digits (e.g. 0000-0000-0000)
    if digits.iter().all(|&d| d == digits[0]) {
        return false;
    }
    // Reject year-like date/timestamp prefixes (19xx-xxxx-xxxx or 20xx-xxxx-xxxx)
    if (candidate.starts_with("19") || candidate.starts_with("20"))
        && candidate.as_bytes().get(4) == Some(&b'-')
    {
        return false;
    }
    // International '+' prefix or parenthesized area code is high-confidence phone syntax
    if candidate.starts_with('+') || (candidate.contains('(') && candidate.contains(')')) {
        return true;
    }
    // Bare space/hyphen-separated digit groups require phone context nearby
    let ctx = context_window(text, start, end, 48);
    const PHONE_CONTEXT: &[&str] = &[
        "phone", "tel", "call", "mobile", "cell", "cel", "fax", "whatsapp", "contact", "llamar",
        "fono", "móvil", "movil",
    ];
    PHONE_CONTEXT.iter().any(|kw| ctx.contains(kw))
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

/// Validates an Argentine CUIT/CUIL (`20-12345678-6`) using official AFIP prefixes and Modulo-11 weights.
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

    // Validate official AFIP 2-digit prefix (individuals: 20, 23, 24, 27; entities: 30, 33, 34)
    let prefix = digits[0] * 10 + digits[1];
    if !matches!(prefix, 20 | 23 | 24 | 27 | 30 | 33 | 34) {
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

/// Validates a Brazilian CPF (`529.982.247-25`) using dual Modulo-11 check digits.
pub fn is_valid_brazil_cpf(candidate: &str) -> bool {
    let digits: Vec<u32> = candidate
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();
    if digits.len() != 11 || digits.iter().all(|&d| d == digits[0]) {
        return false;
    }
    let sum1: u32 = digits[..9]
        .iter()
        .enumerate()
        .map(|(i, &d)| d * (10 - i as u32))
        .sum();
    let d1 = match (sum1 * 10) % 11 {
        10 => 0,
        other => other,
    };
    if digits[9] != d1 {
        return false;
    }
    let sum2: u32 = digits[..10]
        .iter()
        .enumerate()
        .map(|(i, &d)| d * (11 - i as u32))
        .sum();
    let d2 = match (sum2 * 10) % 11 {
        10 => 0,
        other => other,
    };
    digits[10] == d2
}

/// Validates a Brazilian CNPJ (`11.222.333/0001-81`) using dual Modulo-11 weights.
pub fn is_valid_brazil_cnpj(candidate: &str) -> bool {
    const W1: [u32; 12] = [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2];
    const W2: [u32; 13] = [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2];
    let digits: Vec<u32> = candidate
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();
    if digits.len() != 14 || digits.iter().all(|&d| d == digits[0]) {
        return false;
    }
    let sum1: u32 = digits[..12]
        .iter()
        .zip(W1.iter())
        .map(|(&d, &w)| d * w)
        .sum();
    let d1 = if sum1 % 11 < 2 { 0 } else { 11 - (sum1 % 11) };
    if digits[12] != d1 {
        return false;
    }
    let sum2: u32 = digits[..13]
        .iter()
        .zip(W2.iter())
        .map(|(&d, &w)| d * w)
        .sum();
    let d2 = if sum2 % 11 < 2 { 0 } else { 11 - (sum2 % 11) };
    digits[13] == d2
}

/// Validates a Mexican CURP (18 chars) including date range, state code, and official RENAPO Mod-10 check digit.
pub fn is_valid_mexico_curp(candidate: &str) -> bool {
    const DICT: &str = "0123456789ABCDEFGHIJKLMNÑOPQRSTUVWXYZ";
    let clean = candidate.trim().to_uppercase();
    let chars: Vec<char> = clean.chars().collect();
    if chars.len() != 18 {
        return false;
    }
    let month: u32 = match clean[6..8].parse() {
        Ok(m) if (1..=12).contains(&m) => m,
        _ => return false,
    };
    let day: u32 = match clean[8..10].parse() {
        Ok(d) if (1..=31).contains(&d) => d,
        _ => return false,
    };
    if month == 2 && day > 29 {
        return false;
    }
    let Some(expected_digit) = chars[17].to_digit(10) else {
        return false;
    };
    let mut sum = 0u32;
    for (i, &ch) in chars[..17].iter().enumerate() {
        let Some(pos) = DICT.chars().position(|c| c == ch) else {
            return false;
        };
        sum += (pos as u32) * (18 - i as u32);
    }
    let calc = (10 - (sum % 10)) % 10;
    expected_digit == calc
}

/// Validates a Canadian Social Insurance Number (SIN, e.g. `130-692-544`) using the Luhn checksum.
pub fn is_valid_canada_sin(candidate: &str) -> bool {
    let digits: Vec<u32> = candidate
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();
    if digits.len() != 9
        || digits[0] == 0
        || digits[0] == 8
        || digits.iter().all(|&d| d == digits[0])
    {
        return false;
    }
    let sum: u32 = digits
        .iter()
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

/// Validates a UK National Insurance Number (NINO, e.g. `AB 12 34 56 C`) using HMRC prefix/suffix rules.
pub fn is_valid_uk_nino(candidate: &str) -> bool {
    let clean: String = candidate
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .map(|c| c.to_ascii_uppercase())
        .collect();
    let b = clean.as_bytes();
    if b.len() != 9 {
        return false;
    }
    if matches!(b[0], b'D' | b'F' | b'I' | b'Q' | b'U' | b'V') || !b[0].is_ascii_uppercase() {
        return false;
    }
    if matches!(b[1], b'D' | b'F' | b'I' | b'O' | b'Q' | b'U' | b'V') || !b[1].is_ascii_uppercase()
    {
        return false;
    }
    if matches!(&clean[0..2], "BG" | "GB" | "NK" | "KN" | "TN" | "NT" | "ZZ") {
        return false;
    }
    if !b[2..8].iter().all(|c| c.is_ascii_digit()) {
        return false;
    }
    matches!(b[8], b'A' | b'B' | b'C' | b'D')
}

/// Validates an Indian Aadhaar number (`XXXX XXXX XXXX`, 12 digits starting with 2..=9)
/// using the official Verhoeff dihedral checksum algorithm.
pub fn is_valid_india_aadhaar(candidate: &str) -> bool {
    const D: [[usize; 10]; 10] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
        [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
        [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
        [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
        [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
        [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
        [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
        [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
        [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
    ];
    const P: [[usize; 10]; 8] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
        [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
        [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
        [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
        [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
        [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
        [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
    ];
    let digits: Vec<usize> = candidate
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10).map(|d| d as usize))
        .collect();
    if digits.len() != 12 || digits[0] < 2 || digits.iter().all(|&d| d == digits[0]) {
        return false;
    }
    let mut c = 0usize;
    for (i, &d) in digits.iter().rev().enumerate() {
        c = D[c][P[i % 8][d]];
    }
    c == 0
}

/// Validates an Indian Permanent Account Number (PAN, e.g. `ABCPD1234F`).
pub fn is_valid_india_pan(candidate: &str) -> bool {
    let b = candidate.trim().as_bytes();
    if b.len() != 10 {
        return false;
    }
    b[0..3].iter().all(|c| c.is_ascii_uppercase())
        && matches!(
            b[3],
            b'A' | b'B' | b'C' | b'F' | b'G' | b'H' | b'L' | b'J' | b'P' | b'T'
        )
        && b[4].is_ascii_uppercase()
        && b[5..9].iter().all(|c| c.is_ascii_digit())
        && b[9].is_ascii_uppercase()
}

/// Validates a German Tax Identification Number (Steuer-ID / IdNr, e.g. `86095742719`)
/// using the official digit-frequency rule and ISO/IEC 7064 Mod 11,10 check digit.
pub fn is_valid_german_steuer_id(candidate: &str) -> bool {
    let digits: Vec<u32> = candidate
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();
    if digits.len() != 11 || digits[0] == 0 {
        return false;
    }
    let mut freq = [0u8; 10];
    for &d in &digits[..10] {
        freq[d as usize] += 1;
    }
    let count_two = freq.iter().filter(|&&f| f == 2).count();
    let count_three = freq.iter().filter(|&&f| f == 3).count();
    let count_more = freq.iter().filter(|&&f| f > 3).count();
    if count_more > 0
        || !((count_two == 1 && count_three == 0) || (count_three == 1 && count_two == 0))
    {
        return false;
    }
    // Reject 3 consecutive identical digits in the first 10 digits
    if digits[..10]
        .windows(3)
        .any(|w| w[0] == w[1] && w[1] == w[2])
    {
        return false;
    }
    let mut product = 10u32;
    for &d in &digits[..10] {
        let mut sum = (d + product) % 10;
        if sum == 0 {
            sum = 10;
        }
        product = (2 * sum) % 11;
    }
    let expected = (11 - product) % 10;
    digits[10] == expected
}

/// Validates a candidate National ID across all supported regional formats
/// (US SSN, ES DNI/NIE, AR CUIT, CL RUT, BR CPF/CNPJ, MX CURP, CA SIN, UK NINO, IN Aadhaar/PAN, DE Steuer-ID).
pub fn is_valid_national_id(candidate: &str) -> bool {
    let bytes = candidate.as_bytes();
    // 1. Brazilian CNPJ: XX.XXX.XXX/XXXX-XX
    if bytes.len() == 18 && candidate.contains('/') {
        return is_valid_brazil_cnpj(candidate);
    }
    // 2. Mexican CURP: 18 alphanumeric chars without '/'
    if bytes.len() == 18 && !candidate.contains('/') {
        return is_valid_mexico_curp(candidate);
    }
    // 3. Brazilian CPF: XXX.XXX.XXX-XX
    if bytes.len() == 14 && bytes[3] == b'.' && bytes[7] == b'.' && bytes[11] == b'-' {
        return is_valid_brazil_cpf(candidate);
    }
    // 4. Indian Aadhaar: XXXX XXXX XXXX (14 chars with spaces)
    if bytes.len() == 14 && bytes[4] == b' ' && bytes[9] == b' ' {
        return is_valid_india_aadhaar(candidate);
    }
    // 5. Indian PAN: 10 uppercase alphanumeric chars
    if bytes.len() == 10 && bytes[0].is_ascii_uppercase() && bytes[9].is_ascii_uppercase() {
        return is_valid_india_pan(candidate);
    }
    // 6. UK NINO: AA 12 34 56 C (13 chars) or AA123456C (9 chars)
    if (bytes.len() == 13 || bytes.len() == 9)
        && bytes[0].is_ascii_uppercase()
        && bytes[1].is_ascii_uppercase()
    {
        return is_valid_uk_nino(candidate);
    }
    // 7. US SSN: XXX-XX-XXXX
    if bytes.len() == 11 && bytes[3] == b'-' && bytes[6] == b'-' {
        let area: u16 = candidate[0..3].parse().unwrap_or(0);
        let group: u8 = candidate[4..6].parse().unwrap_or(0);
        let serial: u16 = candidate[7..11].parse().unwrap_or(0);
        return area != 0 && area != 666 && area < 900 && group != 0 && serial != 0;
    }
    // 8. Canadian SIN: XXX-XXX-XXX or XXX XXX XXX
    if bytes.len() == 11
        && ((bytes[3] == b'-' && bytes[7] == b'-') || (bytes[3] == b' ' && bytes[7] == b' '))
    {
        return is_valid_canada_sin(candidate);
    }
    // 9. German Steuer-ID: 11 digits
    if bytes.len() == 11 && bytes.iter().all(|b| b.is_ascii_digit()) {
        return is_valid_german_steuer_id(candidate);
    }
    // 10. Argentine CUIT/CUIL: XX-XXXXXXXX-X
    if bytes.len() == 13 && bytes[2] == b'-' && bytes[11] == b'-' {
        return is_valid_arg_cuit(candidate);
    }
    // 11. Spanish DNI / NIE: 9 chars ending in letter
    if bytes.len() == 9 && bytes[8].is_ascii_alphabetic() {
        return is_valid_spanish_dni_nie(candidate);
    }
    // 12. Chilean RUT: contains '-' with 1 verifier char
    if candidate.contains('-') {
        return is_valid_chilean_rut(candidate);
    }
    false
}

/// Validates that an IPv4 candidate has valid 0..=255 octets with no leading zeros (rejects `01.02.03.04`).
pub fn is_valid_ipv4(candidate: &str) -> bool {
    let parts: Vec<&str> = candidate.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    parts
        .iter()
        .all(|part| !(part.len() > 1 && part.starts_with('0')) && part.parse::<u8>().is_ok())
}

/// Validates a National ID candidate with surrounding context to suppress false positives on
/// bare invoice/SKU IDs colliding with un-dotted Chilean RUTs (`12345678-5`), bare 11-digit
/// German Steuer-IDs, or bare 9-digit Canadian SINs.
fn is_valid_national_id_in_context(text: &str, start: usize, end: usize, candidate: &str) -> bool {
    if !is_valid_national_id(candidate) {
        return false;
    }
    let bytes = candidate.as_bytes();

    // Bare un-dotted Chilean RUT (`12345678-5`) can collide ~9% with invoice/order IDs
    let is_undotted_rut = candidate.contains('-')
        && !candidate.contains('.')
        && candidate.len() <= 10
        && candidate.matches('-').count() == 1;
    if is_undotted_rut {
        if start > 0 && text.as_bytes()[start - 1] == b'#' {
            return false;
        }
        let ctx = context_window(text, start, end, 48);
        const RUT_DAMPENERS: &[&str] = &["invoice", "order", "sku", "ticket", "build", "batch"];
        if RUT_DAMPENERS.iter().any(|kw| ctx.contains(kw)) {
            return false;
        }
        const RUT_CONTEXT: &[&str] = &[
            "rut",
            "run",
            "dni",
            "cliente",
            "titular",
            "contribuyente",
            "chile",
            "fiscal",
            "tax",
        ];
        return RUT_CONTEXT.iter().any(|kw| ctx.contains(kw));
    }

    // Bare 11-digit German Steuer-ID (`86095742719`) requires tax/Steuer context
    if bytes.len() == 11 && bytes.iter().all(|b| b.is_ascii_digit()) {
        let ctx = context_window(text, start, end, 48);
        const DE_CONTEXT: &[&str] = &[
            "steuer",
            "idnr",
            "tin",
            "tax",
            "identifikationsnummer",
            "finanzamt",
            "fiscal",
        ];
        return DE_CONTEXT.iter().any(|kw| ctx.contains(kw));
    }

    // Canadian SIN (`XXX-XXX-XXX` or `XXX XXX XXX`) requires SIN/tax/Canada context
    if bytes.len() == 11
        && ((bytes[3] == b'-' && bytes[7] == b'-') || (bytes[3] == b' ' && bytes[7] == b' '))
    {
        let ctx = context_window(text, start, end, 48);
        const CA_CONTEXT: &[&str] = &["sin", "social insurance", "canada", "cra", "tax", "payroll"];
        return CA_CONTEXT.iter().any(|kw| ctx.contains(kw));
    }

    true
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

    #[inline]
    fn push_secret_matches(
        &self,
        raw: &mut Vec<DetectedSpan>,
        re: &Regex,
        kind: EntityKind,
        text: &str,
        min_entropy: f64,
    ) {
        if self.disabled_kinds.contains(&kind) {
            return;
        }
        for m in re.find_iter(text) {
            let s = m.as_str();
            if !is_placeholder_secret(s, min_entropy) && !self.is_allowed(s) {
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
                self.push_secret_matches(
                    &mut raw,
                    &ANTHROPIC_KEY_RE,
                    EntityKind::AnthropicKey,
                    text,
                    3.0,
                );
            }
            if matches.matched(2) {
                self.push_secret_matches(
                    &mut raw,
                    &OPENAI_KEY_RE,
                    EntityKind::OpenAiKey,
                    text,
                    3.0,
                );
            }
            if matches.matched(3) {
                self.push_secret_matches(
                    &mut raw,
                    &STRIPE_KEY_RE,
                    EntityKind::StripeKey,
                    text,
                    3.0,
                );
            }
            if matches.matched(4) {
                self.push_secret_matches(
                    &mut raw,
                    &GITHUB_TOKEN_RE,
                    EntityKind::GitHubToken,
                    text,
                    3.0,
                );
            }
            if matches.matched(5) {
                self.push_secret_matches(
                    &mut raw,
                    &SLACK_TOKEN_RE,
                    EntityKind::SlackToken,
                    text,
                    2.6,
                );
            }
            if matches.matched(6) {
                self.push_secret_matches(
                    &mut raw,
                    &GOOGLE_API_RE,
                    EntityKind::GoogleApiKey,
                    text,
                    3.0,
                );
            }
            if matches.matched(7) {
                self.push_secret_matches(
                    &mut raw,
                    &AWS_KEY_RE,
                    EntityKind::AwsAccessKey,
                    text,
                    2.8,
                );
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
            if matches.matched(11) && !self.disabled_kinds.contains(&EntityKind::Email) {
                for m in EMAIL_RE.find_iter(text) {
                    let s = m.as_str();
                    if is_valid_email_candidate(s) && !self.is_allowed(s) {
                        raw.push(DetectedSpan {
                            kind: EntityKind::Email,
                            start: m.start(),
                            end: m.end(),
                            original: s.to_string(),
                        });
                    }
                }
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
                    if is_valid_credit_card(s) && !self.is_allowed(s) {
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
                    if is_valid_ipv4(s)
                        && !is_likely_version_not_ipv4(text, m.start(), s)
                        && !self.is_allowed(s)
                    {
                        raw.push(DetectedSpan {
                            kind: EntityKind::IpV4,
                            start: m.start(),
                            end: m.end(),
                            original: s.to_string(),
                        });
                    }
                }
            }
            if matches.matched(15) && !self.disabled_kinds.contains(&EntityKind::IpV6) {
                for m in IPV6_RE.find_iter(text) {
                    let s = m.as_str();
                    if is_valid_ipv6_candidate(text, m.start(), m.end(), s) && !self.is_allowed(s) {
                        raw.push(DetectedSpan {
                            kind: EntityKind::IpV6,
                            start: m.start(),
                            end: m.end(),
                            original: s.to_string(),
                        });
                    }
                }
            }
            if matches.matched(16) {
                self.push_matches(&mut raw, &MAC_RE, EntityKind::MacAddress, text);
            }
            if matches.matched(17) && !self.disabled_kinds.contains(&EntityKind::NationalId) {
                for m in NATIONAL_ID_RE.find_iter(text) {
                    let s = m.as_str();
                    if is_valid_national_id_in_context(text, m.start(), m.end(), s)
                        && !self.is_allowed(s)
                    {
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
                    if is_valid_phone_candidate(text, m.start(), m.end(), s) && !self.is_allowed(s)
                    {
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
pub(crate) fn resolve_overlaps(mut spans: Vec<DetectedSpan>) -> Vec<DetectedSpan> {
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

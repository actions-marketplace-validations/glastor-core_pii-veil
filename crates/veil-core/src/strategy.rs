use crate::detector::EntityKind;
use serde::{Deserialize, Serialize};

/// Strategy used to replace detected PII or secrets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RedactionMode {
    /// Replaces with numbered semantic tokens like `[EMAIL_1]`, `[CREDIT_CARD_1]`.
    /// Best for LLM prompts so the model understands entity relationships and can reference them.
    #[default]
    Placeholder,
    /// Replaces with deterministic realistic fake values (e.g., `carlos.mendez.4a9f@example.org`).
    /// Preserves format validation (emails, Luhn cards, Mod-97 IBANs, IPv4, phones) across SQL dumps and test fixtures.
    Synthetic,
    /// Partially masks sensitive values (`j***@empresa.com`, `****-****-****-4242`).
    /// Best for irreversible application logging and observability.
    Mask,
}

const FIRST_NAMES: &[&str] = &[
    "alex", "carlos", "elena", "sofia", "mateo", "lucia", "diego", "valeria", "marco", "camila",
    "andres", "paula", "javier", "clara", "gabriel", "nora",
];

const LAST_NAMES: &[&str] = &[
    "gomez",
    "rodriguez",
    "mendez",
    "silva",
    "torres",
    "vargas",
    "castro",
    "morales",
    "ortega",
    "navarro",
    "rios",
    "vega",
    "molina",
    "delgado",
    "romero",
    "suarez",
];

const DOMAINS: &[&str] = &[
    "example.org",
    "example.com",
    "example.net",
    "demo-corp.internal",
];

/// Computes a fast, deterministic 64-bit keyed hash (SplitMix64 + FNV-1a keyed rounds)
/// so identical PII values map to identical synthetic aliases across runs.
pub fn keyed_hash64(secret_key: &[u8], category: &str, value: &str) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in secret_key {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h ^= 0xff;
    for &b in category.as_bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h ^= 0xfe;
    for &b in value.as_bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    // Final SplitMix64 avalanche mixing
    let mut z = h.wrapping_add(0x9e3779b97f4a7c15);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
    z ^ (z >> 31)
}

/// Generates a replacement string according to the chosen `RedactionMode`.
pub fn generate_replacement(
    mode: RedactionMode,
    kind: &EntityKind,
    original: &str,
    index: usize,
    secret_key: &[u8],
) -> String {
    match mode {
        RedactionMode::Placeholder => format!("[{}_{}]", kind.label(), index),
        RedactionMode::Synthetic => generate_synthetic(kind, original, secret_key),
        RedactionMode::Mask => generate_masked(kind, original),
    }
}

fn generate_synthetic(kind: &EntityKind, original: &str, secret_key: &[u8]) -> String {
    let h = keyed_hash64(secret_key, kind.label(), original);
    match kind {
        EntityKind::Email => {
            let first = FIRST_NAMES[(h as usize) % FIRST_NAMES.len()];
            let last = LAST_NAMES[((h >> 8) as usize) % LAST_NAMES.len()];
            let domain = DOMAINS[((h >> 16) as usize) % DOMAINS.len()];
            let tag = (h >> 24) & 0xffff;
            format!("{}.{}.{:04x}@{}", first, last, tag, domain)
        }
        EntityKind::CreditCard => {
            // Generate a deterministic Luhn-valid 16-digit test card starting with 4000-00
            let mid = h % 1_000_000_000;
            let base15 = format!("400000{:09}", mid);
            let check = compute_luhn_check_digit(&base15);
            let full = format!("{}{}", base15, check);
            format!(
                "{}-{}-{}-{}",
                &full[0..4],
                &full[4..8],
                &full[8..12],
                &full[12..16]
            )
        }
        EntityKind::Iban => {
            // Generate a deterministic ISO 13616 Mod-97 valid 22-character DE IBAN
            let acct = h % 10_000_000_000;
            let bban = format!("50010517{:010}", acct);
            let check = compute_iban_de_check_digits(&bban);
            format!(
                "DE{:02} {} {} {} {} {}",
                check,
                &bban[0..4],
                &bban[4..8],
                &bban[8..12],
                &bban[12..16],
                &bban[16..18]
            )
        }
        EntityKind::Phone => {
            let line = 1000 + ((h % 8999) as u16);
            let prefix = 200 + (((h >> 16) % 799) as u16);
            format!("+1-555-{:03}-{:04}", prefix, line)
        }
        EntityKind::IpV4 => {
            // Uses private documentation subnet 10.254.x.y
            let oct3 = ((h >> 8) & 0xff) as u8;
            let oct4 = 1 + ((h & 0xfd) as u8);
            format!("10.254.{}.{}", oct3, oct4)
        }
        EntityKind::IpV6 => {
            // Uses RFC 3849 IPv6 documentation prefix 2001:db8::
            format!(
                "2001:db8:{:04x}:{:04x}::{:04x}",
                (h & 0xffff) as u16,
                ((h >> 16) & 0xffff) as u16,
                ((h >> 32) & 0xffff) as u16
            )
        }
        EntityKind::MacAddress => {
            // Locally administered unicast MAC prefix 02:00:5e:...
            format!(
                "02:00:5e:{:02x}:{:02x}:{:02x}",
                (h & 0xff) as u8,
                ((h >> 8) & 0xff) as u8,
                ((h >> 16) & 0xff) as u8
            )
        }
        EntityKind::NationalId => {
            let a = 100 + ((h % 650) as u16);
            let b = 10 + (((h >> 12) % 89) as u16);
            let c = 1000 + (((h >> 24) % 8999) as u16);
            format!("{:03}-{:02}-{:04}", a, b, c)
        }
        EntityKind::ConnectionUri => {
            let scheme = original.split("://").next().unwrap_or("postgres");
            format!(
                "{}://synth_user_{:04x}:synth_pass_{:08x}@db-{:04x}.demo-corp.internal:5432/app_db",
                scheme,
                (h & 0xffff) as u16,
                ((h >> 16) & 0xffff_ffff) as u32,
                ((h >> 48) & 0xffff) as u16
            )
        }
        EntityKind::WebhookUrl => {
            format!(
                "https://hooks.slack.com/services/T00SYNTH00/B00SYNTH00/synth{:016x}",
                h
            )
        }
        EntityKind::OpenAiKey => format!("sk-synth-{:016x}{:08x}", h, (h >> 32) as u32),
        EntityKind::AnthropicKey => format!("sk-ant-api03-synth{:016x}{:08x}", h, (h >> 24) as u32),
        EntityKind::AwsAccessKey => format!("AKIA{:016X}", h),
        EntityKind::GitHubToken => format!("ghp_synth{:016x}{:015x}", h, h.rotate_left(17)),
        EntityKind::SlackToken => format!(
            "xoxb-000000000000-{:012}-synth{:08x}",
            h % 1_000_000_000_000,
            (h >> 32) as u32
        ),
        EntityKind::GoogleApiKey => {
            format!("AIzaSySynth{:016x}{:012x}", h, (h >> 16) & 0xffff_ffff_ffff)
        }
        EntityKind::StripeKey => format!("sk_test_synth{:016x}{:08x}", h, (h >> 16) as u32),
        EntityKind::JwtToken => format!(
            "eyJhbGciOiJIUzI1NiJ9.eyJzeW50aCI6InRydWUifQ.synth_{:016x}",
            h
        ),
        EntityKind::PrivateKey => format!(
            "-----BEGIN PRIVATE KEY-----\nSYNTHETIC_KEY_{:016X}\n-----END PRIVATE KEY-----",
            h
        ),
        EntityKind::Custom(label) => format!("<{}_SYNTH_{:08x}>", label, (h & 0xffff_ffff) as u32),
    }
}

fn compute_iban_de_check_digits(bban: &str) -> u64 {
    // DE00 moved to end => "131400"
    let mut rem: u64 = 0;
    for b in bban.bytes().chain(b"131400".iter().copied()) {
        rem = (rem * 10 + (b - b'0') as u64) % 97;
    }
    98 - rem
}

fn compute_luhn_check_digit(first_15_digits: &str) -> u32 {
    let sum: u32 = first_15_digits
        .chars()
        .filter_map(|c| c.to_digit(10))
        .rev()
        .enumerate()
        .map(|(idx, d)| {
            // Since check digit will be at rev index 0, the rightmost of first_15 is at rev index 1 (doubled)
            if idx % 2 == 0 {
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

    (10 - (sum % 10)) % 10
}

fn generate_masked(kind: &EntityKind, original: &str) -> String {
    match kind {
        EntityKind::Email => {
            if let Some((user, domain)) = original.split_once('@') {
                let first_char = user.chars().next().unwrap_or('*');
                format!("{}***@{}", first_char, domain)
            } else {
                "***@***".to_string()
            }
        }
        EntityKind::CreditCard => {
            let digits: Vec<char> = original.chars().filter(|c| c.is_ascii_digit()).collect();
            let last4: String = digits
                .iter()
                .rev()
                .take(4)
                .copied()
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect();
            format!("****-****-****-{}", last4)
        }
        EntityKind::Iban => {
            let clean: Vec<char> = original
                .chars()
                .filter(|c| !c.is_ascii_whitespace())
                .collect();
            if clean.len() >= 8 {
                let prefix: String = clean.iter().take(4).collect();
                let suffix: String = clean.iter().skip(clean.len() - 4).collect();
                format!("{} **** **** **** {}", prefix, suffix)
            } else {
                "****IBAN****".to_string()
            }
        }
        EntityKind::ConnectionUri => {
            if let Some((scheme, rest)) = original.split_once("://") {
                if let Some((_, host_part)) = rest.split_once('@') {
                    return format!("{}://***:***@{}", scheme, host_part);
                }
            }
            "***://***:***@***".to_string()
        }
        EntityKind::Phone => {
            let digits: Vec<char> = original.chars().filter(|c| c.is_ascii_digit()).collect();
            let last3: String = digits
                .iter()
                .rev()
                .take(3)
                .copied()
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect();
            format!("+***-***-*{}", last3)
        }
        EntityKind::PrivateKey => {
            "-----BEGIN PRIVATE KEY----- [REDACTED] -----END PRIVATE KEY-----".to_string()
        }
        _ => {
            let chars: Vec<char> = original.chars().collect();
            if chars.len() <= 6 {
                "***REDACTED***".to_string()
            } else {
                let prefix: String = chars.iter().take(4).collect();
                let suffix: String = chars.iter().skip(chars.len() - 3).collect();
                format!("{}...***...{}", prefix, suffix)
            }
        }
    }
}

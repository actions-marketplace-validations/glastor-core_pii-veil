//! Verifiable Precision, Recall, F1, and False-Positive Rate (FPR) evaluation harness
//! for `pii-veil-core`.
//!
//! Run with:
//! `cargo test -p pii-veil-core --test accuracy_eval -- --nocapture`

use pii_veil_core::{EntityKind, RedactionMode, VeilEngine};
use std::collections::BTreeMap;

struct EvalCase {
    id: &'static str,
    group: &'static str,
    input: String,
    expected: Vec<(EntityKind, String)>,
}

fn build_corpus() -> Vec<EvalCase> {
    // Construct secret fixtures dynamically so static scanners do not mistake test fixtures for live keys.
    let openai_key = format!("sk-proj-{}", "aB3dE6fG9hI2jK5lM8nO1pQ4rS7tU0vW");
    let anthropic_key = format!("sk-ant-api03-{}", "zY9xW8vU7tS6rQ5pO4nM3lK2jI1hG0fE");
    let github_tok = format!("ghp_{}", "1a2B3c4D5e6F7g8H9i0J1k2L3m4N5o6P7q8R");
    let aws_real = format!("AKIA{}", "9K7M3P2Q8R4T6W1X");
    let stripe_key = format!("sk_live_{}", "9a8B7c6D5e4F3g2H1i0J9k8L7m6N");
    let google_key = format!("AIza{}", "SyB7k9M2pQ4rT6vW8xZ1cE3gH5jL7nP9qR2");
    let slack_tok = format!(
        "xoxb-{}-{}-{}",
        "492817364512", "837462910384", "aBcDeFgHiJkLmNoPqRsTuVwX"
    );
    let jwt_real = format!(
        "{}.{}.{}",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFsaWNlIn0",
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    );
    let pem_header = ["-----BEGIN ", "PRIVATE KEY-----"].concat();
    let pem_footer = ["-----END ", "PRIVATE KEY-----"].concat();
    let pem_key = format!(
        "{}\n{}\n{}",
        pem_header, "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC", pem_footer
    );
    let db_uri = format!(
        "postgres://{}:{}@db.prod.internal:5432/payments",
        "app_user", "P4ssw0rd_S3cr3t!"
    );
    let slack_hook = format!(
        "https://hooks.slack.com/services/T{}/B{}/{}",
        "12345678", "87654321", "AbCdEfGhIjKlMnOpQrStUvWx"
    );

    // Adversarial low-entropy / placeholder fixtures
    let fake_openai_placeholder = format!("sk-{}", "your-openai-api-key-here");
    let fake_openai_repeat = format!("sk-{}", "xxxxxxxxxxxxxxxxxxxxxxxx");
    let aws_doc_example = format!("AKIA{}", "IOSFODNN7EXAMPLE");

    vec![
        // ==================== TRUE POSITIVES ====================
        EvalCase {
            id: "tp_email_basic",
            group: "true_positive",
            input: "Contact alice.smith@acme-corp.io for billing.".to_string(),
            expected: vec![(EntityKind::Email, "alice.smith@acme-corp.io".to_string())],
        },
        EvalCase {
            id: "tp_credit_card_visa",
            group: "true_positive",
            input: "Charge Visa 4532-0151-1283-0366 immediately.".to_string(),
            expected: vec![(EntityKind::CreditCard, "4532-0151-1283-0366".to_string())],
        },
        EvalCase {
            id: "tp_iban_de",
            group: "true_positive",
            input: "Wire funds to DE89 3704 0044 0532 0130 00 today.".to_string(),
            expected: vec![(EntityKind::Iban, "DE89 3704 0044 0532 0130 00".to_string())],
        },
        EvalCase {
            id: "tp_openai_key",
            group: "true_positive",
            input: format!("OPENAI_API_KEY={}", openai_key),
            expected: vec![(EntityKind::OpenAiKey, openai_key)],
        },
        EvalCase {
            id: "tp_anthropic_key",
            group: "true_positive",
            input: format!("ANTHROPIC_API_KEY={}", anthropic_key),
            expected: vec![(EntityKind::AnthropicKey, anthropic_key)],
        },
        EvalCase {
            id: "tp_github_token",
            group: "true_positive",
            input: format!("token: {}", github_tok),
            expected: vec![(EntityKind::GitHubToken, github_tok)],
        },
        EvalCase {
            id: "tp_aws_key",
            group: "true_positive",
            input: format!("AWS_ACCESS_KEY_ID={}", aws_real),
            expected: vec![(EntityKind::AwsAccessKey, aws_real)],
        },
        EvalCase {
            id: "tp_stripe_key",
            group: "true_positive",
            input: format!("STRIPE_SECRET={}", stripe_key),
            expected: vec![(EntityKind::StripeKey, stripe_key)],
        },
        EvalCase {
            id: "tp_google_api_key",
            group: "true_positive",
            input: format!("MAPS_KEY={}", google_key),
            expected: vec![(EntityKind::GoogleApiKey, google_key)],
        },
        EvalCase {
            id: "tp_slack_token",
            group: "true_positive",
            input: format!("SLACK_BOT_TOKEN={}", slack_tok),
            expected: vec![(EntityKind::SlackToken, slack_tok)],
        },
        EvalCase {
            id: "tp_jwt_token",
            group: "true_positive",
            input: format!("Authorization: Bearer {}", jwt_real),
            expected: vec![(EntityKind::JwtToken, jwt_real)],
        },
        EvalCase {
            id: "tp_private_key",
            group: "true_positive",
            input: pem_key.clone(),
            expected: vec![(EntityKind::PrivateKey, pem_key)],
        },
        EvalCase {
            id: "tp_connection_uri",
            group: "true_positive",
            input: format!("DATABASE_URL={}", db_uri),
            expected: vec![(EntityKind::ConnectionUri, db_uri)],
        },
        EvalCase {
            id: "tp_webhook_url",
            group: "true_positive",
            input: format!("Notify {}", slack_hook),
            expected: vec![(EntityKind::WebhookUrl, slack_hook)],
        },
        EvalCase {
            id: "tp_phone_intl",
            group: "true_positive",
            input: "Call me at +1 415-555-2671 tomorrow.".to_string(),
            expected: vec![(EntityKind::Phone, "+1 415-555-2671".to_string())],
        },
        EvalCase {
            id: "tp_ipv4_public",
            group: "true_positive",
            input: "SSH login from 203.45.67.89 failed.".to_string(),
            expected: vec![(EntityKind::IpV4, "203.45.67.89".to_string())],
        },
        EvalCase {
            id: "tp_ipv6_full",
            group: "true_positive",
            input: "Client IPv6 is 2001:0db8:85a3:0000:0000:8a2e:0370:7334.".to_string(),
            expected: vec![(
                EntityKind::IpV6,
                "2001:0db8:85a3:0000:0000:8a2e:0370:7334".to_string(),
            )],
        },
        EvalCase {
            id: "tp_mac_address",
            group: "true_positive",
            input: "NIC hardware address 00:1A:2B:3C:4D:5E detected.".to_string(),
            expected: vec![(EntityKind::MacAddress, "00:1A:2B:3C:4D:5E".to_string())],
        },
        EvalCase {
            id: "tp_es_dni",
            group: "true_positive",
            input: "Titular con DNI 00000000T verificado.".to_string(),
            expected: vec![(EntityKind::NationalId, "00000000T".to_string())],
        },
        EvalCase {
            id: "tp_ar_cuit",
            group: "true_positive",
            input: "Factura emitida al CUIT 20-12345678-6.".to_string(),
            expected: vec![(EntityKind::NationalId, "20-12345678-6".to_string())],
        },
        EvalCase {
            id: "tp_cl_rut",
            group: "true_positive",
            input: "Cliente RUT 12.345.678-5 registrado.".to_string(),
            expected: vec![(EntityKind::NationalId, "12.345.678-5".to_string())],
        },
        EvalCase {
            id: "tp_us_ssn_with_context",
            group: "true_positive",
            input: "Applicant SSN: 123-45-6789 on W-9 form.".to_string(),
            expected: vec![(EntityKind::NationalId, "123-45-6789".to_string())],
        },
        EvalCase {
            id: "tp_br_cpf_cnpj",
            group: "true_positive",
            input: "Cliente CPF 529.982.247-25 e empresa CNPJ 11.222.333/0001-81.".to_string(),
            expected: vec![
                (EntityKind::NationalId, "529.982.247-25".to_string()),
                (EntityKind::NationalId, "11.222.333/0001-81".to_string()),
            ],
        },
        EvalCase {
            id: "tp_mx_curp",
            group: "true_positive",
            input: "Registro CURP VECJ880326HDFRRR03 validado.".to_string(),
            expected: vec![(EntityKind::NationalId, "VECJ880326HDFRRR03".to_string())],
        },
        EvalCase {
            id: "tp_ca_sin_uk_nino",
            group: "true_positive",
            input: "Canada SIN 130-692-544 and UK NINO AB 12 34 56 C verified.".to_string(),
            expected: vec![
                (EntityKind::NationalId, "130-692-544".to_string()),
                (EntityKind::NationalId, "AB 12 34 56 C".to_string()),
            ],
        },
        EvalCase {
            id: "tp_in_aadhaar_pan",
            group: "true_positive",
            input: "KYC Aadhaar 2341 2341 2346 and PAN ABCPD1234F approved.".to_string(),
            expected: vec![
                (EntityKind::NationalId, "2341 2341 2346".to_string()),
                (EntityKind::NationalId, "ABCPD1234F".to_string()),
            ],
        },
        EvalCase {
            id: "tp_de_steuer_id",
            group: "true_positive",
            input: "Steuer-ID 86095742719 für Finanzamt hinterlegt.".to_string(),
            expected: vec![(EntityKind::NationalId, "86095742719".to_string())],
        },
        // ==================== ADVERSARIAL FALSE-POSITIVE NEGATIVES ====================
        EvalCase {
            id: "fp_email_retina_png",
            group: "adversarial_fp",
            input: "Load <img src=\"/images/hero@2x.png\" srcset=\"/images/logo@3x.webp 3x\">"
                .to_string(),
            expected: vec![],
        },
        EvalCase {
            id: "fp_ipv4_software_version",
            group: "adversarial_fp",
            input: "Upgraded runtime to v1.2.3.4 and kernel 0.1.4.0 (see Section 1.2.3.4)."
                .to_string(),
            expected: vec![],
        },
        EvalCase {
            id: "fp_ipv4_leading_zeros",
            group: "adversarial_fp",
            input: "Build artifact revision 01.02.03.04 archived.".to_string(),
            expected: vec![],
        },
        EvalCase {
            id: "fp_card_luhn_non_iin_snowflake",
            group: "adversarial_fp",
            input: "Discord snowflake id=1234567890123452 and tracking=7000000000000006."
                .to_string(),
            expected: vec![],
        },
        EvalCase {
            id: "fp_phone_dates_ports_repeats",
            group: "adversarial_fp",
            input: "Ports 8080 3000 5432 opened at 2026-1125-1312; mask 0000-0000-0000."
                .to_string(),
            expected: vec![],
        },
        EvalCase {
            id: "fp_openai_placeholder",
            group: "adversarial_fp",
            input: format!(
                "Set OPENAI_API_KEY={} or {}",
                fake_openai_placeholder, fake_openai_repeat
            ),
            expected: vec![],
        },
        EvalCase {
            id: "fp_aws_docs_example",
            group: "adversarial_fp",
            input: format!(
                "AWS official documentation example key: {}",
                aws_doc_example
            ),
            expected: vec![],
        },
        EvalCase {
            id: "fp_ipv6_rust_hex_namespace",
            group: "adversarial_fp",
            input: "Call module dead::beef or cafe::babe in Rust code.".to_string(),
            expected: vec![],
        },
        EvalCase {
            id: "fp_rut_bare_invoice_id",
            group: "adversarial_fp",
            input: "Order invoice #12345678-5 shipped via warehouse B.".to_string(),
            expected: vec![],
        },
        EvalCase {
            id: "fp_cuit_invalid_afip_prefix",
            group: "adversarial_fp",
            input: "Internal batch code 99-12345678-3 processed.".to_string(),
            expected: vec![],
        },
        EvalCase {
            id: "fp_regional_invalid_checksums",
            group: "adversarial_fp",
            input: "Bad CPF 529.982.247-00, bad Aadhaar 2341 2341 2340, bad NINO QQ 12 34 56 C, bare number 86095742719.".to_string(),
            expected: vec![],
        },
    ]
}

#[test]
fn accuracy_eval_baseline_report() {
    let engine = VeilEngine::new(RedactionMode::Placeholder);
    let corpus = build_corpus();

    let mut total_tp = 0usize;
    let mut total_fp = 0usize;
    let mut total_fn = 0usize;
    let mut adversarial_cases_total = 0usize;
    let mut adversarial_cases_with_fp = 0usize;
    let mut fp_details: Vec<String> = Vec::new();
    let mut per_kind: BTreeMap<String, (usize, usize, usize)> = BTreeMap::new();

    for case in &corpus {
        let detected = engine.scan(&case.input);
        let mut matched_expected = vec![false; case.expected.len()];

        if case.group == "adversarial_fp" {
            adversarial_cases_total += 1;
            if !detected.is_empty() {
                adversarial_cases_with_fp += 1;
            }
        }

        for span in &detected {
            let label = span.kind.label().to_string();
            if let Some(pos) = case.expected.iter().enumerate().position(|(i, (k, orig))| {
                !matched_expected[i] && *k == span.kind && *orig == span.original
            }) {
                matched_expected[pos] = true;
                total_tp += 1;
                per_kind.entry(label).or_default().0 += 1;
            } else {
                total_fp += 1;
                per_kind.entry(label.clone()).or_default().1 += 1;
                fp_details.push(format!(
                    "  [FP] case={} kind={} matched=\"{}\"",
                    case.id, label, span.original
                ));
            }
        }

        for (i, (k, orig)) in case.expected.iter().enumerate() {
            if !matched_expected[i] {
                total_fn += 1;
                per_kind.entry(k.label().to_string()).or_default().2 += 1;
                fp_details.push(format!(
                    "  [FN] case={} kind={} missed=\"{}\"",
                    case.id,
                    k.label(),
                    orig
                ));
            }
        }
    }

    let precision = if total_tp + total_fp > 0 {
        (total_tp as f64) / ((total_tp + total_fp) as f64)
    } else {
        1.0
    };
    let recall = if total_tp + total_fn > 0 {
        (total_tp as f64) / ((total_tp + total_fn) as f64)
    } else {
        1.0
    };
    let f1 = if precision + recall > 0.0 {
        2.0 * precision * recall / (precision + recall)
    } else {
        0.0
    };

    eprintln!("\n================ PII-VEIL ACCURACY & FP EVAL ================");
    eprintln!(
        "Corpus: {} cases ({} true-positive, {} adversarial-negative)",
        corpus.len(),
        corpus.len() - adversarial_cases_total,
        adversarial_cases_total
    );
    eprintln!(
        "Aggregate: TP={} | FP={} | FN={} | Precision={:.2}% | Recall={:.2}% | F1={:.2}%",
        total_tp,
        total_fp,
        total_fn,
        precision * 100.0,
        recall * 100.0,
        f1 * 100.0
    );
    eprintln!(
        "Adversarial FP Cases Triggered: {}/{}",
        adversarial_cases_with_fp, adversarial_cases_total
    );
    eprintln!("-------------------------------------------------------------");
    for (kind, (tp, fp, fn_cnt)) in &per_kind {
        eprintln!("  {:16} TP={:<3} FP={:<3} FN={:<3}", kind, tp, fp, fn_cnt);
    }
    if !fp_details.is_empty() {
        eprintln!("-------------------------------------------------------------");
        eprintln!("Detected False Positives (Phase 2 targets):");
        for line in &fp_details {
            eprintln!("{}", line);
        }
    }
    eprintln!("=============================================================\n");

    // Enforce strict Phase 2 quality gates: 0 false negatives AND 0 false positives on eval suite!
    assert_eq!(
        total_fn, 0,
        "Expected 0 false negatives on core true-positive suite"
    );
    assert_eq!(
        total_fp, 0,
        "Expected 0 false positives on adversarial evaluation suite (got {} FP)",
        total_fp
    );
    assert!(
        precision >= 0.99,
        "Expected Precision >= 99.0%, got {:.2}%",
        precision * 100.0
    );
    assert!(total_tp >= 22, "Expected at least 22 true positives");
}

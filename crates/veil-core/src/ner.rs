//! Layered Defense Tier-1 NER (Named Entity Recognition) integration.
//!
//! `pii-veil-core` keeps its Tier-0 deterministic fast path (`~160 µs`, `< 15 MB` RAM) free of
//! heavy ML dependencies by default. Teams that also need unstructured **Person Names** or
//! **Physical Addresses** can either:
//! 1. Implement [`NerDetector`] with their own ONNX (`ort`), `candle`, or local inference backend
//!    and attach it via `VeilEngine::with_ner_detector(...)`.
//! 2. Enable the lightweight opt-in `ner` Cargo feature to use [`HeuristicNerDetector`], a
//!    zero-model-download contextual Tier-1 detector for English and Spanish names & addresses.

use crate::detector::DetectedSpan;

/// Pluggable Tier-1 NER detector for unstructured PII (person names, physical addresses,
/// organizations, medical terms) in the Layered Defense architecture.
pub trait NerDetector: Send + Sync + std::fmt::Debug {
    /// Detects unstructured sensitive spans in `text`.
    /// Returned spans are merged with Tier-0 deterministic spans via overlap resolution.
    fn detect_unstructured(&self, text: &str) -> Vec<DetectedSpan>;
}

#[cfg(feature = "ner")]
mod heuristic {
    use super::NerDetector;
    use crate::detector::{DetectedSpan, EntityKind};
    use regex::Regex;
    use std::sync::LazyLock;

    // Contextual person-name cues in English and Spanish followed by 2-3 capitalized words.
    static PERSON_CUE_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            r"(?x)
            \b(?:
                Patient|Customer|Client|Applicant|User|Employee|Contact|Sender|Recipient|
                Dear|Hello|Hi|Mr\.?|Mrs\.?|Ms\.?|Dr\.?|Prof\.?|
                Paciente|Cliente|Titular|Usuario|Empleado|Contacto|Estimado|Estimada|Hola|Sr\.?|Sra\.?|Dr\.?|Dra\.?
            )[:\s,]+
            (?P<name>[A-ZÁÉÍÓÚÑ][a-záéíóúñ]{1,20}(?:\s+[A-ZÁÉÍÓÚÑ][a-záéíóúñ]{1,20}){1,2})
            \b",
        )
        .expect("valid person cue regex")
    });

    // Physical street addresses in English (`742 Evergreen Terrace`) and Spanish (`Av. Corrientes 1234`, `Calle Mayor 45`).
    static ADDRESS_EN_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            r"\b\d{1,5}\s+[A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]+){0,3}\s+(?:Street|St\.?|Avenue|Ave\.?|Road|Rd\.?|Boulevard|Blvd\.?|Drive|Dr\.?|Lane|Ln\.?|Terrace|Court|Ct\.?|Way|Place|Pl\.?)\b",
        )
        .expect("valid en address regex")
    });

    static ADDRESS_ES_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            r"\b(?:Calle|Av\.?|Avenida|Paseo|Plaza|Carrera|Camino)\s+[A-ZÁÉÍÓÚÑ][a-záéíóúñA-ZÁÉÍÓÚÑ]+(?:\s+[A-ZÁÉÍÓÚÑa-záéíóúñ]+){0,3}\s+\d{1,5}\b",
        )
        .expect("valid es address regex")
    });

    /// Zero-dependency, sub-millisecond contextual Tier-1 NER detector (opt-in via `--features ner`).
    ///
    /// Detects unstructured `PERSON` names (when preceded by high-precision English/Spanish cues)
    /// and `ADDRESS` street locations without downloading external ML weights.
    #[derive(Debug, Default, Clone)]
    pub struct HeuristicNerDetector;

    impl HeuristicNerDetector {
        pub fn new() -> Self {
            Self
        }
    }

    impl NerDetector for HeuristicNerDetector {
        fn detect_unstructured(&self, text: &str) -> Vec<DetectedSpan> {
            let mut spans = Vec::new();

            for caps in PERSON_CUE_RE.captures_iter(text) {
                if let Some(m) = caps.name("name") {
                    spans.push(DetectedSpan {
                        kind: EntityKind::Custom("PERSON".to_string()),
                        start: m.start(),
                        end: m.end(),
                        original: m.as_str().to_string(),
                    });
                }
            }

            for m in ADDRESS_EN_RE.find_iter(text) {
                spans.push(DetectedSpan {
                    kind: EntityKind::Custom("ADDRESS".to_string()),
                    start: m.start(),
                    end: m.end(),
                    original: m.as_str().to_string(),
                });
            }

            for m in ADDRESS_ES_RE.find_iter(text) {
                spans.push(DetectedSpan {
                    kind: EntityKind::Custom("ADDRESS".to_string()),
                    start: m.start(),
                    end: m.end(),
                    original: m.as_str().to_string(),
                });
            }

            spans
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::{RedactionMode, VeilEngine};
        use std::sync::Arc;

        #[test]
        fn test_layered_ner_person_and_address_roundtrip() {
            let engine = VeilEngine::new(RedactionMode::Placeholder)
                .with_ner_detector(Arc::new(HeuristicNerDetector::new()));

            let prompt = "Patient: Maria Gonzalez (maria@clinic.org) lives at 742 Evergreen Terrace and Av. Corrientes 1234.";
            let res = engine.redact(prompt);

            assert!(res.text.contains("[PERSON_1]"));
            assert!(res.text.contains("[EMAIL_1]"));
            assert!(res.text.contains("[ADDRESS_1]"));
            assert!(res.text.contains("[ADDRESS_2]"));
            assert!(!res.text.contains("Maria Gonzalez"));
            assert!(!res.text.contains("742 Evergreen Terrace"));
            assert!(!res.text.contains("Av. Corrientes 1234"));
            assert_eq!(res.vault.restore(&res.text), prompt);
        }

        #[test]
        fn test_layered_ner_no_false_positives_on_code() {
            let engine = VeilEngine::new(RedactionMode::Placeholder)
                .with_ner_detector(Arc::new(HeuristicNerDetector::new()));

            let code = "fn process_request(cfg: ServerConfig) -> Result<HttpResponse, ApiError> { Ok(resp) }";
            let spans = engine.scan(code);
            assert!(
                spans.is_empty(),
                "Expected 0 NER spans on Rust code, got {:?}",
                spans
            );
        }
    }
}

#[cfg(feature = "ner")]
pub use heuristic::HeuristicNerDetector;

use crate::model::{Finding, Severity};
use regex::Regex;
use std::collections::HashSet;
use std::sync::LazyLock;

fn finding(category: &str, severity: Severity, detector: &str) -> Finding {
    Finding {
        category: category.into(),
        severity,
        detector: detector.into(),
    }
}

static PATTERNS: LazyLock<Vec<(Regex, &'static str, Severity, &'static str)>> = LazyLock::new(
    || {
        vec![
    (Regex::new(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----").unwrap(), "private_key", Severity::Critical, "private_key"),
    (Regex::new(r"\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b").unwrap(), "credential", Severity::High, "aws_access_key_id"),
    (Regex::new(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b|\bgithub_pat_[A-Za-z0-9_]{22,255}\b").unwrap(), "credential", Severity::Critical, "github_token"),
    (Regex::new(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b").unwrap(), "credential", Severity::High, "jwt"),
    (Regex::new(r#"(?im)\b(?:api[_-]?key|access[_-]?token|client[_-]?secret|auth[_-]?token)\b\s*[:=]\s*["']?([A-Za-z0-9_\-/+=]{20,})["']?"#).unwrap(), "credential", Severity::High, "api_key_assignment"),
    (Regex::new(r#"(?im)\b(?:nik|national\s+id|nomor\s+induk\s+kependudukan|ktp)\b\s*(?:no\.?|number)?\s*[:=#-]?\s*["']?(\d{16})["']?"#).unwrap(), "pii", Severity::High, "nik"),
]
    },
);

static EMAIL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?(?:\.[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?)+\b").unwrap()
});

fn luhn(digits: &[u8]) -> bool {
    if digits.len() < 13 || digits.len() > 19 || digits.iter().all(|d| *d == digits[0]) {
        return false;
    }
    let mut sum = 0_u32;
    let mut double = false;
    for digit in digits.iter().rev() {
        let mut value = (digit - b'0') as u32;
        if double {
            value *= 2;
            if value > 9 {
                value -= 9;
            }
        }
        sum += value;
        double = !double;
    }
    sum % 10 == 0
}

fn credit_cards(text: &str) -> bool {
    text.split(|c: char| !(c.is_ascii_digit() || c.is_whitespace() || c == '-'))
        .filter(|candidate| candidate.chars().any(|c| c.is_ascii_digit()))
        .any(|candidate| {
            let digits: Vec<u8> = candidate.bytes().filter(u8::is_ascii_digit).collect();
            luhn(&digits)
        })
}

/// Returns only categories, severities and detector names. Matched text never escapes.
pub fn detect(text: &str) -> Vec<Finding> {
    let mut results = Vec::new();
    let mut seen = HashSet::new();
    for (pattern, category, severity, detector) in PATTERNS.iter() {
        if pattern.is_match(text) && seen.insert(*detector) {
            results.push(finding(category, *severity, detector));
        }
    }
    if credit_cards(text) {
        results.push(finding("financial", Severity::High, "credit_card_luhn"));
    }
    if EMAIL.is_match(text) {
        results.push(finding("pii", Severity::Low, "email"));
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detectors(text: &str) -> HashSet<String> {
        detect(text).into_iter().map(|f| f.detector).collect()
    }

    #[test]
    fn detects_required_credentials() {
        assert!(detectors("-----BEGIN RSA PRIVATE KEY-----\nsecret").contains("private_key"));
        assert!(detectors("AWS key AKIAIOSFODNN7EXAMPLE").contains("aws_access_key_id"));
        assert!(detectors(&format!("ghp_{}", "a".repeat(36))).contains("github_token"));
        assert!(detectors("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c").contains("jwt"));
        assert!(
            detectors("api_key = \"Abcdef0123456789_longSecret\"").contains("api_key_assignment")
        );
    }

    #[test]
    fn rejects_malformed_and_low_confidence_credentials() {
        assert!(!detectors("AKIA1234 or ghp_short or key=hello").contains("aws_access_key_id"));
        assert!(!detectors("my-api-key-is-not-an-assignment").contains("api_key_assignment"));
        assert!(!detectors("api_key = \"short\"").contains("api_key_assignment"));
        assert!(!detectors("eyx.aa.bb").contains("jwt"));
        assert!(!detectors("-----BEGIN PUBLIC KEY-----").contains("private_key"));
    }

    #[test]
    fn validates_credit_cards_and_repeated_digits() {
        assert!(detectors("card 4111-1111-1111-1111").contains("credit_card_luhn"));
        assert!(detectors("card 5555555555554444").contains("credit_card_luhn"));
        assert!(!detectors("card 4111-1111-1111-1112").contains("credit_card_luhn"));
        assert!(!detectors("0000-0000-0000-0000").contains("credit_card_luhn"));
        assert!(!detectors("order 1234567890123").contains("credit_card_luhn"));
    }

    #[test]
    fn nik_requires_conservative_context() {
        assert!(detectors("NIK: 3201234567890001").contains("nik"));
        assert!(detectors("nomor induk kependudukan = 3201234567890001").contains("nik"));
        assert!(!detectors("transaction 3201234567890001").contains("nik"));
        assert!(!detectors("NIK: 12345").contains("nik"));
    }

    #[test]
    fn emails_require_plausible_domain() {
        assert!(detectors("Contact alice@example.com").contains("email"));
        assert!(!detectors("not-an-email @ localhost").contains("email"));
    }

    #[test]
    fn findings_are_deduplicated_and_metadata_only() {
        let found = detect("a@example.com b@example.com");
        assert_eq!(found.len(), 1);
        assert!(!format!("{found:?}").contains("a@example.com"));
    }
}

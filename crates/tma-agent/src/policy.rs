use crate::model::{Action, Finding, InspectionStatus, Policy, Rule, Severity};
use chrono::Utc;
use uuid::Uuid;

pub fn defaults() -> Policy {
    Policy {
        name: "Baseline protection".into(),
        version: Uuid::nil(),
        generated_at: chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc),
        failure_mode: Action::Block,
        allowed_file_types: crate::inspect::TEXT_EXTENSIONS
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
        tags: vec![
            "credential".into(),
            "private_key".into(),
            "pii".into(),
            "financial".into(),
            "identity:id:nik".into(),
            "environment:env".into(),
        ],
        rules: vec![
            Rule {
                id: Uuid::from_u128(1),
                name: "Block high-confidence credentials".into(),
                enabled: true,
                priority: 10,
                action: Action::Block,
                categories: vec!["credential".into(), "private_key".into()],
                min_severity: Severity::High,
                providers: vec![],
                tags: vec![],
            },
            Rule {
                id: Uuid::from_u128(2),
                name: "Audit personal and financial data".into(),
                enabled: true,
                priority: 20,
                action: Action::Audit,
                categories: vec!["pii".into(), "financial".into()],
                min_severity: Severity::Medium,
                providers: vec![],
                tags: vec![],
            },
            Rule {
                id: Uuid::from_u128(3),
                name: "Allow inspected content".into(),
                enabled: true,
                priority: 1000,
                action: Action::Allow,
                categories: vec![],
                min_severity: Severity::Low,
                providers: vec![],
                tags: vec![],
            },
        ],
    }
}

pub fn validate(policy: &Policy) -> anyhow::Result<()> {
    if !matches!(policy.failure_mode, Action::Block | Action::Audit) {
        anyhow::bail!("failure_mode must be block or audit")
    }
    if policy.allowed_file_types.is_empty()
        || policy.allowed_file_types.iter().any(|extension| {
            !crate::inspect::TEXT_EXTENSIONS
                .iter()
                .any(|supported| supported.eq_ignore_ascii_case(extension))
        })
    {
        anyhow::bail!("allowed_file_types must contain supported text formats")
    }
    if policy.tags.len() > 100
        || policy.tags.iter().any(|tag| {
            tag.is_empty()
                || tag.len() > 64
                || !tag.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b':' | b'_' | b'-')
                })
                || !tag.as_bytes()[0].is_ascii_lowercase()
        })
    {
        anyhow::bail!("policy contains invalid data tags")
    }
    let configured_tags = policy.tags.iter().collect::<std::collections::HashSet<_>>();
    let mut ids = std::collections::HashSet::new();
    for rule in &policy.rules {
        if rule.name.trim().is_empty() || !ids.insert(rule.id) {
            anyhow::bail!("invalid or duplicate policy rule")
        }
        if rule.tags.len() > 50 || rule.tags.iter().any(|tag| !configured_tags.contains(tag)) {
            anyhow::bail!("policy rule references an invalid or disabled data tag")
        }
    }
    Ok(())
}

pub fn decide(
    policy: &Policy,
    provider: &str,
    status: InspectionStatus,
    findings: &[Finding],
) -> (Action, u8) {
    let risk_score = findings
        .iter()
        .map(|finding| match finding.severity {
            Severity::Low => 25,
            Severity::Medium => 50,
            Severity::High => 80,
            Severity::Critical => 100,
        })
        .max()
        .unwrap_or(0);
    if !status.complete() {
        return (policy.failure_mode, risk_score);
    }
    let decision = policy
        .rules
        .iter()
        .filter(|rule| rule.enabled)
        .filter(|rule| {
            rule.providers.is_empty()
                || rule
                    .providers
                    .iter()
                    .any(|p| p.eq_ignore_ascii_case(provider))
        })
        .filter(|rule| {
            (rule.categories.is_empty() && rule.tags.is_empty())
                || findings.iter().any(|finding| {
                    let category_match = rule
                        .categories
                        .iter()
                        .any(|category| category == &finding.category);
                    let tag_match = rule.tags.iter().any(|tag| {
                        tag.eq_ignore_ascii_case(&finding.detector)
                            || tag
                                .rsplit(':')
                                .next()
                                .is_some_and(|name| name.eq_ignore_ascii_case(&finding.detector))
                    });
                    (category_match || tag_match) && finding.severity >= rule.min_severity
                })
        })
        .min_by_key(|rule| rule.priority)
        .map(|rule| rule.action)
        .unwrap_or(Action::Allow);
    (decision, risk_score)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(category: &str, severity: Severity) -> Finding {
        Finding {
            category: category.into(),
            severity,
            detector: "test".into(),
        }
    }

    #[test]
    fn lowest_priority_number_wins() {
        let mut policy = defaults();
        policy.rules.push(Rule {
            id: Uuid::new_v4(),
            name: "audit".into(),
            enabled: true,
            priority: 5,
            action: Action::Audit,
            categories: vec!["credential".into()],
            min_severity: Severity::Low,
            providers: vec![],
            tags: vec![],
        });
        assert_eq!(
            decide(
                &policy,
                "chatgpt",
                InspectionStatus::Complete,
                &[finding("credential", Severity::High)]
            )
            .0,
            Action::Audit
        );
    }

    #[test]
    fn provider_scope_and_severity_are_enforced() {
        let mut policy = defaults();
        policy.rules.clear();
        policy.rules.push(Rule {
            id: Uuid::new_v4(),
            name: "chatgpt critical only".into(),
            enabled: true,
            priority: 1,
            action: Action::Block,
            categories: vec!["pii".into()],
            min_severity: Severity::Critical,
            providers: vec!["chatgpt".into()],
            tags: vec![],
        });
        assert_eq!(
            decide(
                &policy,
                "claude",
                InspectionStatus::Complete,
                &[finding("pii", Severity::Critical)]
            )
            .0,
            Action::Allow
        );
        assert_eq!(
            decide(
                &policy,
                "chatgpt",
                InspectionStatus::Complete,
                &[finding("pii", Severity::High)]
            )
            .0,
            Action::Allow
        );
        assert_eq!(
            decide(
                &policy,
                "chatgpt",
                InspectionStatus::Complete,
                &[finding("pii", Severity::Critical)]
            )
            .0,
            Action::Block
        );
    }

    #[test]
    fn incomplete_inspection_never_silently_allows() {
        for status in [
            InspectionStatus::Incomplete,
            InspectionStatus::Failed,
            InspectionStatus::Unsupported,
            InspectionStatus::Timeout,
        ] {
            assert_eq!(decide(&defaults(), "chatgpt", status, &[]).0, Action::Block);
        }
        let mut policy = defaults();
        policy.failure_mode = Action::Audit;
        assert_eq!(
            decide(&policy, "chatgpt", InspectionStatus::Failed, &[]).0,
            Action::Audit
        );
        assert!(validate(&defaults()).is_ok());
        policy.failure_mode = Action::Allow;
        assert!(validate(&policy).is_err());
    }

    #[test]
    fn dashboard_default_wildcard_allow_is_valid() {
        let body = r#"{
          "version":"00000000-0000-0000-0000-000000000001",
          "generated_at":"2026-11-26T00:00:00Z","failure_mode":"block",
          "rules":[
            {"id":"00000000-0000-0000-0000-000000000001","name":"Block credentials","enabled":true,"priority":10,"action":"block","categories":["credential","private_key"],"min_severity":"high","providers":[]},
            {"id":"00000000-0000-0000-0000-000000000002","name":"Final allow","enabled":true,"priority":1000,"action":"allow","categories":[],"min_severity":"low","providers":[]}
          ]
        }"#;
        let policy: Policy = serde_json::from_str(body).unwrap();
        validate(&policy).unwrap();
        assert_eq!(
            decide(&policy, "chatgpt", InspectionStatus::Complete, &[]).0,
            Action::Allow
        );
        assert_eq!(
            decide(
                &policy,
                "chatgpt",
                InspectionStatus::Complete,
                &[finding("credential", Severity::High)]
            )
            .0,
            Action::Block
        );
    }
}

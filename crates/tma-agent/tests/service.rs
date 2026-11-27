use tma_agent::config::Config;
use tma_agent::model::*;
use tma_agent::service::Agent;
use uuid::Uuid;

fn agent() -> (tempfile::TempDir, Agent) {
    let directory = tempfile::tempdir().unwrap();
    let config = Config {
        install_dir: directory.path().into(),
        control_plane_url: None,
        enrollment_token: None,
        device_id: Some(Uuid::new_v4()),
        device_token: Some("device-token".into()),
        ipc_credential: "test-credential-that-is-long-enough".into(),
        development: false,
    };
    let agent = Agent::open(config, &directory.path().join("events.db")).unwrap();
    (directory, agent)
}

#[test]
fn inspection_to_enforcement_is_durable_metadata_only() {
    let (_directory, agent) = agent();
    let request_id = Uuid::new_v4();
    let response = agent.handle(Request::Inspect {
        request_id,
        provider: "chatgpt".into(),
        channel: "browser".into(),
        application: "Chrome".into(),
        file: None,
        prompt: Some(PromptInput::Structured {
            text: "api_key = \"Abcdef0123456789_longSecret\"".into(),
        }),
        file_size: None,
        sha256: None,
        policy_version: None,
    });
    let Response::Inspection {
        event_id,
        decision,
        inspection_complete,
        ..
    } = response
    else {
        panic!("wrong response")
    };
    assert!(inspection_complete);
    assert_eq!(decision, Action::Block);
    let ack_id = Uuid::new_v4();
    assert_ne!(ack_id, request_id);
    let ack = agent.handle(Request::EnforcementResult {
        request_id: ack_id,
        event_id,
        enforcement_status: EnforcementStatus::Prevented,
        enforcement_confirmed: true,
    });
    assert!(matches!(
        ack,
        Response::EnforcementResultAck { accepted: true, .. }
    ));
    let store = agent.store.lock().unwrap();
    assert_eq!(store.stats().unwrap().pending, 1);
}

#[test]
fn unsupported_file_fails_closed_and_ack_rejects_unknown_event() {
    let (_directory, agent) = agent();
    let response = agent.handle(Request::Inspect {
        request_id: Uuid::new_v4(),
        provider: "claude".into(),
        channel: "browser".into(),
        application: "Chrome".into(),
        file: Some(FileInput {
            name: "report.pdf".into(),
            content_base64: "dGV4dA==".into(),
        }),
        prompt: None,
        file_size: None,
        sha256: None,
        policy_version: None,
    });
    let Response::Inspection {
        inspection_status,
        decision,
        ..
    } = response
    else {
        panic!("wrong response")
    };
    assert_eq!(inspection_status, InspectionStatus::Unsupported);
    assert_eq!(decision, Action::Block);
    let ack = agent.handle(Request::EnforcementResult {
        request_id: Uuid::new_v4(),
        event_id: Uuid::new_v4(),
        enforcement_status: EnforcementStatus::Confirmed,
        enforcement_confirmed: true,
    });
    assert!(matches!(
        ack,
        Response::EnforcementResultAck {
            accepted: false,
            ..
        }
    ));
}

#[test]
fn health_is_not_protected_with_only_builtin_policy() {
    let (_directory, agent) = agent();
    let response = agent.handle(Request::Health {
        request_id: Uuid::new_v4(),
    });
    let Response::Health {
        status,
        policy_version,
        ..
    } = response
    else {
        panic!("wrong response")
    };
    assert_eq!(status, AgentStatus::Limited);
    assert_eq!(policy_version, Uuid::nil());
}

#[test]
fn missing_enrollment_is_pending_and_health_does_not_mark_browser_connected() {
    let directory = tempfile::tempdir().unwrap();
    let config = Config {
        install_dir: directory.path().into(),
        control_plane_url: None,
        enrollment_token: None,
        device_id: None,
        device_token: None,
        ipc_credential: "test-credential-that-is-long-enough".into(),
        development: false,
    };
    let agent = Agent::open(config, &directory.path().join("events.db")).unwrap();
    assert_eq!(agent.status(), AgentStatus::PendingEnrollment);
    let response = agent.handle(Request::Health {
        request_id: Uuid::new_v4(),
    });
    let Response::Health {
        status, connection, ..
    } = response
    else {
        panic!("wrong response")
    };
    assert_eq!(status, AgentStatus::PendingEnrollment);
    assert!(!connection.enrolled);
    assert_eq!(connection.device_id, None);
    assert!(!connection.control_plane_configured);
}

#[test]
fn persisted_device_credentials_disable_enrollment_retry_and_survive_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("events.db");
    let device_id = Uuid::new_v4();
    let config = Config {
        install_dir: directory.path().into(),
        control_plane_url: Some("http://127.0.0.1:1".into()),
        enrollment_token: Some("consumed-pairing-code".into()),
        device_id: Some(device_id),
        device_token: Some("device-token".into()),
        ipc_credential: "test-credential-that-is-long-enough".into(),
        development: false,
    };
    let agent = Agent::open(config.clone(), &database).unwrap();
    assert!(matches!(
        agent.sync_once(),
        Err(tma_agent::service::SyncError::Heartbeat(_))
    ));
    assert_eq!(agent.config.read().unwrap().device_id, Some(device_id));
    assert_eq!(
        agent.config.read().unwrap().enrollment_token.as_deref(),
        Some("consumed-pairing-code")
    );
    drop(agent);
    let reopened = Agent::open(config, &database).unwrap();
    assert_eq!(reopened.connection_health().device_id, Some(device_id));
    assert!(reopened.connection_health().enrolled);
    assert!(matches!(
        reopened.sync_once(),
        Err(tma_agent::service::SyncError::Heartbeat(_))
    ));
}

#[test]
fn failed_enrollment_keeps_pairing_code_and_returns_error() {
    let directory = tempfile::tempdir().unwrap();
    let config = Config {
        install_dir: directory.path().into(),
        control_plane_url: Some("http://127.0.0.1:1".into()),
        enrollment_token: Some("retryable-pairing-code".into()),
        device_id: None,
        device_token: None,
        ipc_credential: "test-credential-that-is-long-enough".into(),
        development: false,
    };
    let agent = Agent::open(config, &directory.path().join("events.db")).unwrap();
    assert!(matches!(
        agent.sync_once(),
        Err(tma_agent::service::SyncError::NotEnrolled(_))
    ));
    let config = agent.config.read().unwrap();
    assert_eq!(config.device_id, None);
    assert_eq!(config.device_token, None);
    assert_eq!(
        config.enrollment_token.as_deref(),
        Some("retryable-pairing-code")
    );
    drop(config);
    assert_eq!(
        agent.connection_health().control_plane_state,
        tma_agent::service::ControlPlaneState::EnrollmentFailed
    );
}

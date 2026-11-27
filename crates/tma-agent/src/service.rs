use crate::config::Config;
use crate::inspect::{inspect_file, inspect_prompt};
use crate::model::*;
use crate::store::Store;
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use uuid::Uuid;

pub struct Agent {
    pub config: RwLock<Config>,
    data_dir: PathBuf,
    pub store: Mutex<Store>,
    browser_connected: AtomicBool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlPlaneState {
    NotConfigured,
    Connected,
    Unreachable,
    EnrollmentFailed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
pub struct ConnectionHealth {
    pub enrolled: bool,
    pub device_id: Option<Uuid>,
    pub control_plane_configured: bool,
    pub control_plane_state: ControlPlaneState,
    pub last_heartbeat: Option<String>,
    pub last_policy_sync: Option<String>,
}

#[derive(Debug)]
pub enum SyncError {
    NotConfigured,
    NotEnrolled(String),
    Heartbeat(anyhow::Error),
    Policy(anyhow::Error),
    Upload(anyhow::Error),
}

impl std::fmt::Display for SyncError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotConfigured => write!(formatter, "control plane URL is not configured"),
            Self::NotEnrolled(error) => write!(formatter, "agent is not enrolled: {error}"),
            Self::Heartbeat(error) => write!(formatter, "heartbeat failed: {error}"),
            Self::Policy(error) => write!(formatter, "policy synchronization failed: {error}"),
            Self::Upload(error) => write!(formatter, "queue upload failed: {error}"),
        }
    }
}

impl std::error::Error for SyncError {}

impl Agent {
    pub fn open(config: Config, database: &Path) -> anyhow::Result<Self> {
        let data_dir = database
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_owned();
        Ok(Self {
            config: RwLock::new(config),
            data_dir,
            store: Mutex::new(Store::open(database)?),
            browser_connected: AtomicBool::new(false),
        })
    }

    pub fn status(&self) -> AgentStatus {
        let config = self.config.read().unwrap();
        if config.device_id.is_none() || config.device_token.is_none() {
            return AgentStatus::PendingEnrollment;
        }
        let ready = self
            .store
            .lock()
            .unwrap()
            .policy()
            .map(|policy| policy.version != Uuid::nil() && crate::policy::validate(&policy).is_ok())
            .unwrap_or(false);
        if ready && self.browser_connected.load(Ordering::Relaxed) {
            AgentStatus::Protected
        } else {
            AgentStatus::Limited
        }
    }

    pub fn connection_health(&self) -> ConnectionHealth {
        let config = self.config.read().unwrap().clone();
        let store = self.store.lock().unwrap();
        ConnectionHealth {
            enrolled: config.device_id.is_some() && config.device_token.is_some(),
            device_id: config.device_id,
            control_plane_configured: config.control_plane_url.is_some(),
            control_plane_state: store
                .meta("connection_state")
                .ok()
                .flatten()
                .and_then(|state| serde_json::from_str(&state).ok())
                .unwrap_or(if config.control_plane_url.is_some() {
                    ControlPlaneState::Unreachable
                } else {
                    ControlPlaneState::NotConfigured
                }),
            last_heartbeat: store.meta("last_heartbeat").ok().flatten(),
            last_policy_sync: store.meta("last_policy_sync").ok().flatten(),
        }
    }

    pub fn handle(&self, request: Request) -> Response {
        match request {
            Request::Health {
                request_id,
                browser,
            } => {
                if browser {
                    self.browser_connected.store(true, Ordering::Relaxed);
                }
                let policy_version = self
                    .store
                    .lock()
                    .unwrap()
                    .policy()
                    .map(|p| p.version)
                    .unwrap_or(Uuid::nil());
                Response::Health {
                    request_id,
                    status: self.status(),
                    agent_version: env!("CARGO_PKG_VERSION").into(),
                    policy_version,
                    connection: self.connection_health(),
                }
            }
            Request::Inspect {
                request_id,
                provider,
                channel,
                application,
                file,
                prompt,
                ..
            } => {
                self.browser_connected.store(true, Ordering::Relaxed);
                let (mut inspection, file_name) = match (file, prompt) {
                    (Some(file), None) => {
                        let name = Path::new(&file.name)
                            .file_name()
                            .and_then(|n| n.to_str())
                            .unwrap_or("unknown")
                            .chars()
                            .take(1024)
                            .collect::<String>();
                        (inspect_file(&file), name)
                    }
                    (None, Some(prompt)) => (inspect_prompt(prompt.text()), String::new()),
                    _ => {
                        return Response::Error {
                            request_id: Some(request_id),
                            code: "invalid_input".into(),
                            message: "exactly one of file and prompt is required".into(),
                        }
                    }
                };
                let store = self.store.lock().unwrap();
                let policy = match store.policy() {
                    Ok(policy) => policy,
                    Err(_) => {
                        let policy = crate::policy::defaults();
                        let event_id = Uuid::new_v4();
                        let _ = store.enqueue(&SecurityEvent {
                            event_id,
                            occurred_at: chrono::Utc::now(),
                            channel,
                            provider,
                            application,
                            file_name,
                            file_size: inspection.file_size,
                            sha256: inspection.sha256,
                            inspection_status: InspectionStatus::Failed,
                            inspection_complete: false,
                            policy_decision: Action::Block,
                            enforcement_component: "browser_extension".into(),
                            enforcement_status: EnforcementStatus::Pending,
                            enforcement_confirmed: false,
                            findings: vec![],
                            risk_score: 100,
                            policy_version: policy.version,
                        });
                        return Response::Inspection {
                            request_id,
                            inspection_status: InspectionStatus::Failed,
                            inspection_complete: false,
                            decision: Action::Block,
                            risk_score: 100,
                            findings: vec![],
                            policy_version: policy.version,
                            event_id,
                        };
                    }
                };
                if !file_name.is_empty() {
                    let extension = Path::new(&file_name)
                        .extension()
                        .and_then(|value| value.to_str())
                        .map(str::to_ascii_lowercase)
                        .or_else(|| {
                            file_name
                                .eq_ignore_ascii_case(".env")
                                .then(|| "env".to_owned())
                        });
                    let allowed = extension.is_some_and(|extension| {
                        policy
                            .allowed_file_types
                            .iter()
                            .any(|value| value.eq_ignore_ascii_case(&extension))
                    });
                    if !allowed {
                        inspection.status = InspectionStatus::Unsupported;
                        inspection.findings.clear();
                    }
                }
                let (decision, risk_score) = crate::policy::decide(
                    &policy,
                    &provider,
                    inspection.status,
                    &inspection.findings,
                );
                let event_id = Uuid::new_v4();
                let event = SecurityEvent {
                    event_id,
                    occurred_at: chrono::Utc::now(),
                    channel,
                    provider,
                    application,
                    file_name,
                    file_size: inspection.file_size,
                    sha256: inspection.sha256,
                    inspection_status: inspection.status,
                    inspection_complete: inspection.status.complete(),
                    policy_decision: decision,
                    enforcement_component: "browser_extension".into(),
                    enforcement_status: EnforcementStatus::Pending,
                    enforcement_confirmed: false,
                    findings: inspection.findings.clone(),
                    risk_score,
                    policy_version: policy.version,
                };
                if let Err(error) = store.enqueue(&event) {
                    return Response::Error {
                        request_id: Some(request_id),
                        code: "persistence_failed".into(),
                        message: format!("inspection blocked: {error}"),
                    };
                }
                Response::Inspection {
                    request_id,
                    inspection_status: inspection.status,
                    inspection_complete: inspection.status.complete(),
                    decision,
                    risk_score,
                    findings: inspection.findings,
                    policy_version: policy.version,
                    event_id,
                }
            }
            Request::EnforcementResult {
                request_id,
                event_id,
                enforcement_status,
                enforcement_confirmed,
            } => {
                match self.store.lock().unwrap().update_enforcement(
                    event_id,
                    enforcement_status,
                    enforcement_confirmed,
                ) {
                    Ok(accepted) => Response::EnforcementResultAck {
                        request_id,
                        event_id,
                        accepted,
                    },
                    Err(error) => Response::Error {
                        request_id: Some(request_id),
                        code: "invalid_enforcement".into(),
                        message: error.to_string(),
                    },
                }
            }
        }
    }

    pub fn sync_once(&self) -> Result<(), SyncError> {
        let config = self.enroll_if_needed()?;
        let (Some(url), Some(token)) = (&config.control_plane_url, &config.device_token) else {
            return Err(SyncError::NotConfigured);
        };
        let heartbeat = crate::control_plane::heartbeat(
            url,
            token,
            self.status(),
            self.browser_connected.load(Ordering::Relaxed),
        )
        .map_err(|error| {
            self.record_connection_state(ControlPlaneState::Unreachable);
            SyncError::Heartbeat(error)
        })?;
        {
            let store = self.store.lock().unwrap();
            store
                .set_meta("last_heartbeat", &heartbeat.server_time.to_rfc3339())
                .map_err(SyncError::Heartbeat)?;
        }
        let policy = crate::control_plane::fetch_policy(url, token).map_err(|error| {
            self.record_connection_state(ControlPlaneState::Unreachable);
            SyncError::Policy(error)
        })?;
        {
            let store = self.store.lock().unwrap();
            if store.policy().map(|p| p.version).ok() != Some(policy.version) {
                store.save_policy(&policy).map_err(SyncError::Policy)?;
            }
            store
                .set_meta("last_policy_sync", &chrono::Utc::now().to_rfc3339())
                .map_err(SyncError::Policy)?;
            store
                .set_meta("connection_state", "\"connected\"")
                .map_err(SyncError::Policy)?;
        }
        self.store
            .lock()
            .unwrap()
            .flush(url, token)
            .map_err(SyncError::Upload)?;
        Ok(())
    }

    fn enroll_if_needed(&self) -> Result<Config, SyncError> {
        let config = self.config.read().unwrap().clone();
        let Some(url) = &config.control_plane_url else {
            return Err(SyncError::NotConfigured);
        };
        if config.device_id.is_some() && config.device_token.is_some() {
            return Ok(config);
        }
        let Some(code) = &config.enrollment_token else {
            self.record_connection_state(ControlPlaneState::Unreachable);
            return Err(SyncError::NotEnrolled("pairing code is missing".into()));
        };
        let hostname = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "windows-agent".into());
        let enrollment =
            crate::control_plane::enroll(url, code, &hostname, env!("CARGO_PKG_VERSION")).map_err(
                |error| {
                    self.record_connection_state(ControlPlaneState::EnrollmentFailed);
                    SyncError::NotEnrolled(error.to_string())
                },
            )?;
        let mut updated = config.clone();
        updated.device_id = Some(enrollment.device_id);
        updated.device_token = Some(enrollment.device_token);
        updated.enrollment_token = None;
        updated
            .save(&self.data_dir.join("config.json"))
            .map_err(|error| SyncError::NotEnrolled(format!("saving enrollment: {error}")))?;
        *self.config.write().unwrap() = updated.clone();
        Ok(updated)
    }
    fn record_connection_state(&self, state: ControlPlaneState) {
        let _ = self.store.lock().unwrap().set_meta(
            "connection_state",
            &serde_json::to_string(&state).expect("connection state serializes"),
        );
    }

    pub fn run_sync_loop(self: &Arc<Self>, stopping: Arc<AtomicBool>) {
        while !stopping.load(Ordering::Relaxed) {
            let _ = self.sync_once();
            for _ in 0..10 {
                if stopping.load(Ordering::Relaxed) {
                    return;
                }
                std::thread::sleep(Duration::from_secs(1));
            }
        }
    }
}

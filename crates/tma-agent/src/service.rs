use crate::config::Config;
use crate::inspect::{inspect_file, inspect_prompt};
use crate::model::*;
use crate::store::Store;
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
        let ready = self
            .store
            .lock()
            .unwrap()
            .policy()
            .map(|policy| policy.version != Uuid::nil() && crate::policy::validate(&policy).is_ok())
            .unwrap_or(false);
        if !ready {
            AgentStatus::Limited
        } else if self.browser_connected.load(Ordering::Relaxed) {
            AgentStatus::Protected
        } else {
            AgentStatus::Limited
        }
    }

    pub fn handle(&self, request: Request) -> Response {
        match request {
            Request::Health { request_id } => {
                self.browser_connected.store(true, Ordering::Relaxed);
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
                let (inspection, file_name) = match (file, prompt) {
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

    pub fn sync_once(&self) {
        self.enroll_if_needed();
        let config = self.config.read().unwrap().clone();
        let (Some(url), Some(token)) = (&config.control_plane_url, &config.device_token) else {
            return;
        };
        let _ = crate::control_plane::heartbeat(
            url,
            token,
            self.status(),
            self.browser_connected.load(Ordering::Relaxed),
        );
        if let Ok(policy) = crate::control_plane::fetch_policy(url, token) {
            let current = { self.store.lock().unwrap().policy().map(|p| p.version).ok() };
            if current != Some(policy.version) {
                let _ = self.store.lock().unwrap().save_policy(&policy);
            }
        }
        let _ = self.store.lock().unwrap().flush(url, token);
    }

    fn enroll_if_needed(&self) {
        let config = self.config.read().unwrap().clone();
        let (Some(url), Some(code)) = (&config.control_plane_url, &config.enrollment_token) else {
            return;
        };
        if config.device_id.is_some() && config.device_token.is_some() {
            return;
        }
        let hostname = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "windows-agent".into());
        if let Ok(enrollment) =
            crate::control_plane::enroll(url, code, &hostname, env!("CARGO_PKG_VERSION"))
        {
            let mut updated = config.clone();
            updated.device_id = Some(enrollment.device_id);
            updated.device_token = Some(enrollment.device_token);
            updated.enrollment_token = None;
            if updated.save(&self.data_dir.join("config.json")).is_ok() {
                *self.config.write().unwrap() = updated;
            }
        }
    }

    pub fn run_sync_loop(self: &Arc<Self>, stopping: Arc<AtomicBool>) {
        while !stopping.load(Ordering::Relaxed) {
            self.sync_once();
            for _ in 0..30 {
                if stopping.load(Ordering::Relaxed) {
                    return;
                }
                std::thread::sleep(Duration::from_secs(1));
            }
        }
    }
}

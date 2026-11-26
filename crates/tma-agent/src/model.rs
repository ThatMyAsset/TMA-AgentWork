use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const MAX_MESSAGE_SIZE: usize = 1024 * 1024;
pub const MAX_INPUT_BYTES: usize = 768 * 1024;
pub const MAX_TEXT_DEPTH: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Block,
    Audit,
    Allow,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub category: String,
    pub severity: Severity,
    pub detector: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InspectionStatus {
    Complete,
    Incomplete,
    Failed,
    Unsupported,
    Timeout,
}

impl InspectionStatus {
    pub fn complete(self) -> bool {
        self == Self::Complete
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementStatus {
    Pending,
    Confirmed,
    Prevented,
    Failed,
    NotRequired,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileInput {
    pub name: String,
    pub content_base64: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PromptInput {
    Text(String),
    Structured { text: String },
}

impl PromptInput {
    pub fn text(&self) -> &str {
        match self {
            Self::Text(text) | Self::Structured { text } => text,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Request {
    Inspect {
        request_id: Uuid,
        provider: String,
        channel: String,
        application: String,
        file: Option<FileInput>,
        prompt: Option<PromptInput>,
        #[serde(default)]
        file_size: Option<u64>,
        #[serde(default)]
        sha256: Option<String>,
        #[serde(default)]
        policy_version: Option<Uuid>,
    },
    Health {
        request_id: Uuid,
    },
    EnforcementResult {
        request_id: Uuid,
        event_id: Uuid,
        enforcement_status: EnforcementStatus,
        enforcement_confirmed: bool,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Response {
    Health {
        request_id: Uuid,
        status: AgentStatus,
        agent_version: String,
        policy_version: Uuid,
    },
    Inspection {
        request_id: Uuid,
        inspection_status: InspectionStatus,
        inspection_complete: bool,
        decision: Action,
        risk_score: u8,
        findings: Vec<Finding>,
        policy_version: Uuid,
        event_id: Uuid,
    },
    #[serde(rename = "enforcement_result_ack")]
    EnforcementResultAck {
        request_id: Uuid,
        event_id: Uuid,
        accepted: bool,
    },
    Error {
        request_id: Option<Uuid>,
        code: String,
        message: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentStatus {
    PendingEnrollment,
    Limited,
    Protected,
    Degraded,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: Uuid,
    pub name: String,
    pub enabled: bool,
    pub priority: i32,
    pub action: Action,
    pub categories: Vec<String>,
    pub min_severity: Severity,
    #[serde(default)]
    pub providers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub version: Uuid,
    pub generated_at: chrono::DateTime<chrono::Utc>,
    pub failure_mode: Action,
    pub rules: Vec<Rule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Enrollment {
    pub device_id: Uuid,
    pub device_token: String,
    pub policy_version: Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatReply {
    pub policy_version: Uuid,
    pub server_time: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Heartbeat {
    pub agent_version: String,
    pub status: AgentStatus,
    pub inspection_engine_ready: bool,
    pub browser_connected: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub event_id: Uuid,
    pub occurred_at: chrono::DateTime<chrono::Utc>,
    pub channel: String,
    pub provider: String,
    pub application: String,
    pub file_name: String,
    pub file_size: u64,
    pub sha256: String,
    pub inspection_status: InspectionStatus,
    pub inspection_complete: bool,
    pub policy_decision: Action,
    pub enforcement_component: String,
    pub enforcement_status: EnforcementStatus,
    pub enforcement_confirmed: bool,
    pub findings: Vec<Finding>,
    pub risk_score: u8,
    pub policy_version: Uuid,
}

use crate::model::{Enrollment, Heartbeat, HeartbeatReply, Policy, SecurityEvent};
use std::time::Duration;

fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(10))
        .build()
}

fn base(url: &str) -> String {
    url.trim_end_matches('/').to_owned()
}

pub fn enroll(
    url: &str,
    code: &str,
    hostname: &str,
    agent_version: &str,
) -> anyhow::Result<Enrollment> {
    let response = agent().post(&format!("{}/api/v1/agents/enroll", base(url)))
        .send_json(serde_json::json!({"code": code, "hostname": hostname, "os": std::env::consts::OS, "agent_version": agent_version}))?;
    Ok(response.into_json()?)
}

pub fn fetch_policy(url: &str, token: &str) -> anyhow::Result<Policy> {
    let response = agent()
        .get(&format!("{}/api/v1/agent/policies", base(url)))
        .set("Authorization", &format!("Bearer {token}"))
        .call()?;
    let policy: Policy = response.into_json()?;
    crate::policy::validate(&policy)?;
    Ok(policy)
}

pub fn heartbeat(
    url: &str,
    token: &str,
    status: crate::model::AgentStatus,
    browser_connected: bool,
) -> anyhow::Result<HeartbeatReply> {
    let response = agent()
        .post(&format!("{}/api/v1/agent/heartbeat", base(url)))
        .set("Authorization", &format!("Bearer {token}"))
        .send_json(Heartbeat {
            agent_version: env!("CARGO_PKG_VERSION").into(),
            status,
            inspection_engine_ready: true,
            browser_connected,
        })?;
    Ok(response.into_json()?)
}

pub fn upload_event(url: &str, token: &str, event: &SecurityEvent) -> anyhow::Result<()> {
    // Metadata-only DTO is enforced by the type; raw inspected text never reaches this client.
    agent()
        .post(&format!("{}/api/v1/events", base(url)))
        .set("Authorization", &format!("Bearer {token}"))
        .send_json(event)?;
    Ok(())
}

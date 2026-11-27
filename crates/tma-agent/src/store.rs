use crate::model::{EnforcementStatus, Policy, SecurityEvent};
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;
use std::time::{Duration, Instant};
use uuid::Uuid;

pub struct Store {
    connection: Connection,
    last_upload: Instant,
}

#[derive(Debug, serde::Serialize)]
pub struct QueueStats {
    pub pending: usize,
    pub dead_lettered: usize,
    pub oldest_pending: Option<String>,
}

impl Store {
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        let connection = Connection::open(path)?;
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS events (
                event_id TEXT PRIMARY KEY,
                body TEXT NOT NULL CHECK(json_valid(body)),
                attempts INTEGER NOT NULL DEFAULT 0,
                next_attempt_at INTEGER NOT NULL DEFAULT 0,
                last_error TEXT,
                created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
            );
            CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS events_due ON events(next_attempt_at, created_at);",
        )?;
        crate::platform::restrict_file(path)?;
        Ok(Self {
            connection,
            last_upload: Instant::now() - Duration::from_secs(60),
        })
    }

    pub fn meta(&self, key: &str) -> anyhow::Result<Option<String>> {
        self.connection
            .query_row("SELECT value FROM meta WHERE key=?1", [key], |row| row.get(0))
            .optional()
            .map_err(Into::into)
    }

    pub fn set_meta(&self, key: &str, value: &str) -> anyhow::Result<()> {
        self.connection.execute(
            "INSERT INTO meta(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    pub fn save_policy(&self, policy: &Policy) -> anyhow::Result<()> {
        crate::policy::validate(policy)?;
        self.connection.execute("INSERT INTO meta(key,value) VALUES('policy',?1) ON CONFLICT(key) DO UPDATE SET value=excluded.value", [serde_json::to_string(policy)?])?;
        Ok(())
    }

    pub fn policy(&self) -> anyhow::Result<Policy> {
        let body: Option<String> = self
            .connection
            .query_row("SELECT value FROM meta WHERE key='policy'", [], |row| {
                row.get(0)
            })
            .optional()?;
        match body {
            Some(body) => Ok(serde_json::from_str(&body)?),
            None => {
                let policy = crate::policy::defaults();
                self.save_policy(&policy)?;
                Ok(policy)
            }
        }
    }

    pub fn enqueue(&self, event: &SecurityEvent) -> anyhow::Result<()> {
        validate_event(event)?;
        self.connection.execute(
            "INSERT INTO events(event_id,body) VALUES(?1,?2) ON CONFLICT(event_id) DO NOTHING",
            params![event.event_id.to_string(), serde_json::to_string(event)?],
        )?;
        Ok(())
    }

    pub fn update_enforcement(
        &self,
        event_id: Uuid,
        status: EnforcementStatus,
        confirmed: bool,
    ) -> anyhow::Result<bool> {
        if confirmed
            != matches!(
                status,
                EnforcementStatus::Confirmed | EnforcementStatus::Prevented
            )
        {
            anyhow::bail!("enforcement status and boolean disagree");
        }
        let transaction = self.connection.unchecked_transaction()?;
        let body: Option<String> = transaction
            .query_row(
                "SELECT body FROM events WHERE event_id=?1",
                [event_id.to_string()],
                |row| row.get(0),
            )
            .optional()?;
        let Some(body) = body else { return Ok(false) };
        let mut event: SecurityEvent = serde_json::from_str(&body)?;
        event.enforcement_status = status;
        event.enforcement_confirmed = confirmed;
        transaction.execute(
            "UPDATE events SET body=?2,next_attempt_at=0,last_error=NULL WHERE event_id=?1",
            params![event_id.to_string(), serde_json::to_string(&event)?],
        )?;
        transaction.commit()?;
        Ok(true)
    }

    fn due(&self, limit: usize) -> anyhow::Result<Vec<(Uuid, SecurityEvent)>> {
        let now = chrono::Utc::now().timestamp_millis();
        let mut statement = self.connection.prepare("SELECT event_id,body FROM events WHERE next_attempt_at<=?1 ORDER BY created_at LIMIT ?2")?;
        let rows = statement.query_map(params![now, limit as i64], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        rows.map(|row| {
            let (id, body) = row?;
            Ok((Uuid::parse_str(&id)?, serde_json::from_str(&body)?))
        })
        .collect()
    }

    pub fn flush(&mut self, url: &str, token: &str) -> anyhow::Result<usize> {
        if self.last_upload.elapsed() < Duration::from_secs(1) {
            return Ok(0);
        }
        self.last_upload = Instant::now();
        let pending = self.due(50)?;
        let mut sent = 0;
        for (id, event) in pending {
            match crate::control_plane::upload_event(url, token, &event) {
                Ok(()) => {
                    self.connection
                        .execute("DELETE FROM events WHERE event_id=?1", [id.to_string()])?;
                    sent += 1;
                }
                Err(error) => {
                    let attempts: u32 = self.connection.query_row(
                        "SELECT attempts FROM events WHERE event_id=?1",
                        [id.to_string()],
                        |row| row.get(0),
                    )?;
                    let delay = Duration::from_secs(2_u64.saturating_pow(attempts.min(10)))
                        .min(Duration::from_secs(300));
                    let next = (chrono::Utc::now() + chrono::Duration::from_std(delay)?)
                        .timestamp_millis();
                    let message = error.to_string();
                    let safe_error = message.chars().take(500).collect::<String>();
                    self.connection.execute("UPDATE events SET attempts=attempts+1,next_attempt_at=?2,last_error=?3 WHERE event_id=?1", params![id.to_string(), next, safe_error])?;
                    break;
                }
            }
        }
        Ok(sent)
    }

    pub fn stats(&self) -> anyhow::Result<QueueStats> {
        let pending: usize =
            self.connection
                .query_row("SELECT count(*) FROM events", [], |row| row.get(0))?;
        let dead_lettered: usize = self.connection.query_row(
            "SELECT count(*) FROM events WHERE attempts>=20",
            [],
            |row| row.get(0),
        )?;
        let oldest_pending: Option<String> =
            self.connection
                .query_row("SELECT min(created_at) FROM events", [], |row| row.get(0))?;
        Ok(QueueStats {
            pending,
            dead_lettered,
            oldest_pending,
        })
    }
}

pub fn validate_event(event: &SecurityEvent) -> anyhow::Result<()> {
    if event.inspection_complete != event.inspection_status.complete() {
        anyhow::bail!("inspection status and boolean disagree");
    }
    if event.enforcement_confirmed
        != matches!(
            event.enforcement_status,
            EnforcementStatus::Confirmed | EnforcementStatus::Prevented
        )
    {
        anyhow::bail!("enforcement status and boolean disagree");
    }
    if event.file_name.len() > 1024
        || event.provider.len() > 100
        || event.application.len() > 100
        || event.findings.len() > 100
    {
        anyhow::bail!("event metadata exceeds limits");
    }
    if event.sha256.is_empty() {
        if !event.file_name.is_empty() || event.file_size != 0 {
            anyhow::bail!("prompt event has file metadata")
        }
    } else if event.sha256.len() != 64
        || !event.sha256.bytes().all(|b| b.is_ascii_hexdigit())
        || event.sha256.chars().any(|c| c.is_ascii_uppercase())
    {
        anyhow::bail!("invalid SHA-256 metadata");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Action, InspectionStatus};
    use chrono::Utc;

    fn event() -> SecurityEvent {
        SecurityEvent {
            event_id: Uuid::new_v4(),
            occurred_at: Utc::now(),
            channel: "browser".into(),
            provider: "chatgpt".into(),
            application: "Chrome".into(),
            file_name: String::new(),
            file_size: 0,
            sha256: String::new(),
            inspection_status: InspectionStatus::Complete,
            inspection_complete: true,
            policy_decision: Action::Block,
            enforcement_component: "browser_extension".into(),
            enforcement_status: EnforcementStatus::Pending,
            enforcement_confirmed: false,
            findings: vec![],
            risk_score: 100,
            policy_version: Uuid::new_v4(),
        }
    }

    #[test]
    fn queue_is_durable_and_idempotent() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("queue.db");
        let value = event();
        {
            let store = Store::open(&path).unwrap();
            store.enqueue(&value).unwrap();
            store.enqueue(&value).unwrap();
            assert_eq!(store.stats().unwrap().pending, 1);
            assert!(store
                .update_enforcement(value.event_id, EnforcementStatus::Prevented, true)
                .unwrap());
        }
        let store = Store::open(&path).unwrap();
        let due = store.due(10).unwrap();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].1.enforcement_status, EnforcementStatus::Prevented);
        assert!(due[0].1.enforcement_confirmed);
    }

    #[test]
    fn metadata_survives_reopen_and_updates() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("queue.db");
        {
            let store = Store::open(&path).unwrap();
            store.set_meta("connection_state", "\\"connected\\"").unwrap();
            store.set_meta("last_heartbeat", "2026-11-27T00:00:00Z").unwrap();
            store.set_meta("last_heartbeat", "2026-11-27T00:01:00Z").unwrap();
        }
        let store = Store::open(&path).unwrap();
        assert_eq!(store.meta("connection_state").unwrap().as_deref(), Some("\\"connected\\""));
        assert_eq!(store.meta("last_heartbeat").unwrap().as_deref(), Some("2026-11-27T00:01:00Z"));
        assert_eq!(store.meta("missing").unwrap(), None);
    }

    #[test]
    fn persisted_policy_survives_reopen() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("queue.db");
        let mut policy = crate::policy::defaults();
        policy.version = Uuid::new_v4();
        Store::open(&path).unwrap().save_policy(&policy).unwrap();
        assert_eq!(
            Store::open(&path).unwrap().policy().unwrap().version,
            policy.version
        );
    }

    #[test]
    fn semantic_validation_rejects_inconsistent_event() {
        let mut value = event();
        value.inspection_complete = false;
        assert!(validate_event(&value).is_err());
        value.inspection_complete = true;
        value.enforcement_confirmed = true;
        assert!(validate_event(&value).is_err());
    }
}

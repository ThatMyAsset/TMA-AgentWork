//! Restricted complex-document parser worker. Phase 1 intentionally parses no complex formats.
//! Parent launches with a restricted token and Job Object; protocol remains length-prefixed JSON.
use std::io::{self, Read, Write};
use tma_agent::model::{Response, MAX_MESSAGE_SIZE};
use uuid::Uuid;

fn main() {
    if let Err(error) = run() {
        let _ = writeln!(io::stderr(), "tma-parser: {error}");
        std::process::exit(1);
    }
}

fn run() -> anyhow::Result<()> {
    let mut stdin = io::stdin().lock();
    let mut stdout = io::stdout().lock();
    let mut header = [0_u8; 4];
    while stdin.read_exact(&mut header).is_ok() {
        let size = u32::from_le_bytes(header) as usize;
        if size == 0 || size > MAX_MESSAGE_SIZE {
            anyhow::bail!("invalid parser frame")
        }
        let mut body = vec![0_u8; size];
        stdin.read_exact(&mut body)?;
        let value: serde_json::Value = serde_json::from_slice(&body)?;
        let request_id = value
            .get("request_id")
            .and_then(|v| v.as_str())
            .and_then(|v| Uuid::parse_str(v).ok());
        let response = Response::Error {
            request_id,
            code: "unsupported_format".into(),
            message: "complex document parsing is outside the Phase 1 text-only slice".into(),
        };
        tma_agent::protocol::write_frame(&mut stdout, &serde_json::to_vec(&response)?)?;
    }
    Ok(())
}

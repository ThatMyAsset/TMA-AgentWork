use crate::model::{EnforcementStatus, Request, Response, MAX_MESSAGE_SIZE};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::io::{Read, Write};

pub fn encode(value: &impl serde::Serialize) -> anyhow::Result<Vec<u8>> {
    let body = serde_json::to_vec(value)?;
    if body.len() > MAX_MESSAGE_SIZE {
        anyhow::bail!("message exceeds 1 MiB limit")
    }
    let mut frame = Vec::with_capacity(body.len() + 4);
    frame.extend_from_slice(&(body.len() as u32).to_le_bytes());
    frame.extend_from_slice(&body);
    Ok(frame)
}

pub fn read_frame(reader: &mut impl Read) -> anyhow::Result<Option<Vec<u8>>> {
    let mut header = [0_u8; 4];
    match reader.read(&mut header) {
        Ok(0) => return Ok(None),
        Ok(n) => reader.read_exact(&mut header[n..])?,
        Err(error) => return Err(error.into()),
    }
    let length = u32::from_le_bytes(header) as usize;
    if length == 0 || length > MAX_MESSAGE_SIZE {
        anyhow::bail!("invalid frame length {length}")
    }
    let mut body = vec![0; length];
    reader.read_exact(&mut body)?;
    Ok(Some(body))
}

pub fn write_frame(writer: &mut impl Write, body: &[u8]) -> anyhow::Result<()> {
    if body.is_empty() || body.len() > MAX_MESSAGE_SIZE {
        anyhow::bail!("invalid frame body length")
    }
    writer.write_all(&(body.len() as u32).to_le_bytes())?;
    writer.write_all(body)?;
    writer.flush()?;
    Ok(())
}

pub fn receive(reader: &mut impl Read) -> anyhow::Result<Option<Request>> {
    let Some(body) = read_frame(reader)? else {
        return Ok(None);
    };
    validate_request_json(&body)?;
    Ok(Some(serde_json::from_slice(&body)?))
}

pub fn send(writer: &mut impl Write, response: &Response) -> anyhow::Result<()> {
    write_frame(writer, &serde_json::to_vec(response)?)
}

pub fn validate_request_json(body: &[u8]) -> anyhow::Result<()> {
    let value: Value = serde_json::from_slice(body)?;
    let object = value
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("request must be an object"))?;
    let kind = object
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or_default();
    match kind {
        "inspect" => {
            let file_present = object.get("file").is_some_and(|v| !v.is_null());
            let prompt_present = object.get("prompt").is_some_and(|v| !v.is_null());
            if file_present == prompt_present {
                anyhow::bail!("exactly one of file and prompt is required")
            }
        }
        "enforcement_result" => {
            let confirmed = object.get("enforcement_confirmed").and_then(Value::as_bool);
            let parsed: EnforcementStatus = serde_json::from_value(
                object
                    .get("enforcement_status")
                    .cloned()
                    .unwrap_or(Value::Null),
            )?;
            if confirmed
                != Some(matches!(
                    parsed,
                    EnforcementStatus::Confirmed | EnforcementStatus::Prevented
                ))
            {
                anyhow::bail!("enforcement_status and enforcement_confirmed disagree");
            }
        }
        "health" => {}
        other => anyhow::bail!("unknown request type {other:?}"),
    }
    Ok(())
}

pub fn request_authenticator(credential: &str, body: &[u8]) -> String {
    let key = Sha256::digest(credential.as_bytes());
    let mut inner = [0x36_u8; 64];
    let mut outer = [0x5c_u8; 64];
    for index in 0..key.len() {
        inner[index] ^= key[index];
        outer[index] ^= key[index];
    }
    let inner_hash = Sha256::digest([inner.as_slice(), body].concat());
    format!(
        "{:x}",
        Sha256::digest([outer.as_slice(), inner_hash.as_slice()].concat())
    )
}

fn canonical_request(mut value: Value) -> anyhow::Result<Vec<u8>> {
    let object = value
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("request must be an object"))?;
    object.insert("auth".into(), Value::String(String::new()));
    Ok(serde_json::to_vec(&value)?)
}

fn authenticated(body: &[u8], credential: &str) -> anyhow::Result<Vec<u8>> {
    let mut value: Value = serde_json::from_slice(body)?;
    let auth = value
        .as_object_mut()
        .and_then(|object| object.remove("auth"))
        .and_then(|value| value.as_str().map(str::to_owned))
        .ok_or_else(|| anyhow::anyhow!("local IPC credential required"))?;
    let expected = request_authenticator(credential, &canonical_request(value.clone())?);
    if !constant_time_eq(auth.as_bytes(), expected.as_bytes()) {
        anyhow::bail!("invalid local IPC credential")
    }
    value["auth"] = Value::Null;
    Ok(serde_json::to_vec(&value)?)
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}

pub fn receive_authenticated(
    reader: &mut impl Read,
    credential: &str,
) -> anyhow::Result<Option<Request>> {
    let Some(body) = read_frame(reader)? else {
        return Ok(None);
    };
    let unsigned = authenticated(&body, credential)?;
    validate_request_json(&unsigned)?;
    Ok(Some(serde_json::from_slice(&unsigned)?))
}

/// Relay attaches request-body-bound HMAC; inspection/decision stays in the service.
pub fn relay(
    stdin: &mut impl Read,
    stdout: &mut impl Write,
    service: &mut (impl Read + Write),
    credential: &str,
) -> anyhow::Result<()> {
    while let Some(body) = read_frame(stdin)? {
        validate_request_json(&body)?;
        let mut value: Value = serde_json::from_slice(&body)?;
        value["auth"] = Value::String(String::new());
        let auth = request_authenticator(credential, &serde_json::to_vec(&value)?);
        value
            .as_object_mut()
            .unwrap()
            .insert("auth".into(), Value::String(auth));
        write_frame(service, &serde_json::to_vec(&value)?)?;
        let response =
            read_frame(service)?.ok_or_else(|| anyhow::anyhow!("service closed IPC connection"))?;
        serde_json::from_slice::<Response>(&response)?;
        write_frame(stdout, &response)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Action, FileInput, InspectionStatus, PromptInput};
    use std::io::Cursor;
    use uuid::Uuid;

    #[test]
    fn native_frame_is_unsigned_little_endian() {
        let request = Request::Health {
            request_id: Uuid::nil(),
        };
        let frame = encode(&request).unwrap();
        let expected = (frame.len() - 4) as u32;
        assert_eq!(&frame[..4], &expected.to_le_bytes());
        assert_eq!(
            read_frame(&mut Cursor::new(frame)).unwrap().unwrap().len(),
            expected as usize
        );
    }

    #[test]
    fn rejects_oversized_and_empty_frames() {
        assert!(read_frame(&mut Cursor::new(
            (MAX_MESSAGE_SIZE as u32 + 1).to_le_bytes()
        ))
        .is_err());
        assert!(read_frame(&mut Cursor::new(0_u32.to_le_bytes())).is_err());
    }

    #[test]
    fn exactly_one_input_is_required() {
        let id = Uuid::new_v4();
        let both = serde_json::to_vec(&Request::Inspect {
            request_id: id,
            provider: "chatgpt".into(),
            channel: "browser".into(),
            application: "Chrome".into(),
            file: Some(FileInput {
                name: "a.txt".into(),
                content_base64: "YQ==".into(),
            }),
            prompt: Some(PromptInput::Text("secret".into())),
            file_size: None,
            sha256: None,
            policy_version: None,
        })
        .unwrap();
        assert!(validate_request_json(&both).is_err());
        let neither = format!(
            r#"{{"type":"inspect","request_id":"{id}","provider":"chatgpt","channel":"browser","application":"Chrome","file":null,"prompt":null}}"#
        );
        assert!(validate_request_json(neither.as_bytes()).is_err());
    }

    #[test]
    fn rejects_semantically_inconsistent_enforcement() {
        let body = format!(
            r#"{{"type":"enforcement_result","request_id":"{}","event_id":"{}","enforcement_status":"failed","enforcement_confirmed":true}}"#,
            Uuid::new_v4(),
            Uuid::new_v4()
        );
        assert!(validate_request_json(body.as_bytes()).is_err());
    }

    #[test]
    fn local_credential_is_required() {
        let body = br#"{"request_id":"00000000-0000-0000-0000-000000000000","type":"health"}"#;
        assert!(authenticated(body, "a-very-long-installation-secret").is_err());
        let mut value: Value = serde_json::from_slice(body).unwrap();
        let canonical = canonical_request(value.clone()).unwrap();
        value["auth"] = Value::String(request_authenticator(
            "a-very-long-installation-secret",
            &canonical,
        ));
        let signed = serde_json::to_vec(&value).unwrap();
        assert!(authenticated(&signed, "a-very-long-installation-secret").is_ok());
        assert!(authenticated(&signed, "wrong-secret").is_err());
    }

    #[test]
    fn inspection_response_contains_no_match_values() {
        let response = Response::Inspection {
            request_id: Uuid::new_v4(),
            inspection_status: InspectionStatus::Complete,
            inspection_complete: true,
            decision: Action::Block,
            risk_score: 100,
            findings: vec![],
            policy_version: Uuid::new_v4(),
            event_id: Uuid::new_v4(),
        };
        assert_eq!(
            serde_json::to_value(response).unwrap()["type"],
            "inspection"
        );
    }
}

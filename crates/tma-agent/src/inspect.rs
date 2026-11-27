use crate::detect::detect;
use crate::model::{FileInput, Finding, InspectionStatus, MAX_INPUT_BYTES, MAX_TEXT_DEPTH};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use std::path::Path;

pub const TEXT_EXTENSIONS: &[&str] = &[
    "txt",
    "md",
    "markdown",
    "mdx",
    "rst",
    "csv",
    "tsv",
    "json",
    "jsonl",
    "ndjson",
    "xml",
    "html",
    "htm",
    "yaml",
    "yml",
    "toml",
    "ini",
    "conf",
    "config",
    "properties",
    "log",
    "env",
    "sql",
    "py",
    "js",
    "jsx",
    "mjs",
    "cjs",
    "ts",
    "tsx",
    "go",
    "rs",
    "c",
    "h",
    "cc",
    "cpp",
    "hpp",
    "hxx",
    "cs",
    "java",
    "kt",
    "kts",
    "swift",
    "php",
    "rb",
    "sh",
    "bash",
    "zsh",
    "ps1",
    "bat",
    "cmd",
    "css",
    "scss",
    "less",
    "vue",
    "svelte",
    "tf",
    "tfvars",
    "hcl",
    "dockerignore",
    "gitignore",
    "dockerfile",
    "makefile",
];

#[derive(Debug)]
pub struct Inspection {
    pub status: InspectionStatus,
    pub findings: Vec<Finding>,
    pub file_size: u64,
    pub sha256: String,
}

fn depth_within_limit(text: &str) -> bool {
    let mut depth = 0_usize;
    let mut quoted = false;
    let mut escaped = false;
    for byte in text.bytes() {
        if quoted {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                quoted = false;
            }
            continue;
        }
        match byte {
            b'"' => quoted = true,
            b'{' | b'[' => {
                depth += 1;
                if depth > MAX_TEXT_DEPTH {
                    return false;
                }
            }
            b'}' | b']' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    true
}

pub fn inspect_file(file: &FileInput) -> Inspection {
    use sha2::{Digest, Sha256};
    let empty = || Inspection {
        status: InspectionStatus::Failed,
        findings: vec![],
        file_size: 0,
        sha256: String::new(),
    };
    let name = Path::new(&file.name)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default();
    // Reject non-canonical base64 and whitespace rather than silently discarding bytes.
    if file.content_base64.len() > MAX_INPUT_BYTES * 4 / 3 + 4 {
        return Inspection {
            status: InspectionStatus::Incomplete,
            ..empty()
        };
    }
    let Ok(bytes) = STANDARD.decode(&file.content_base64) else {
        return empty();
    };
    let size = bytes.len() as u64;
    let sha256 = format!("{:x}", Sha256::digest(&bytes));
    let base = |status| Inspection {
        status,
        findings: vec![],
        file_size: size,
        sha256: sha256.clone(),
    };
    let lower_name = name.to_ascii_lowercase();
    let extension =
        Path::new(name)
            .extension()
            .and_then(|e| e.to_str())
            .or(match lower_name.as_str() {
                ".env" => Some("env"),
                ".gitignore" => Some("gitignore"),
                ".dockerignore" => Some("dockerignore"),
                "dockerfile" => Some("dockerfile"),
                "makefile" => Some("makefile"),
                _ => None,
            });
    let supported = extension.is_some_and(|extension| {
        TEXT_EXTENSIONS
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(extension))
    });
    if !supported {
        return base(InspectionStatus::Unsupported);
    }
    if bytes.len() > MAX_INPUT_BYTES {
        return base(InspectionStatus::Incomplete);
    }
    let Ok(text) = std::str::from_utf8(&bytes) else {
        return base(InspectionStatus::Unsupported);
    };
    if !depth_within_limit(text) {
        return base(InspectionStatus::Incomplete);
    }
    Inspection {
        status: InspectionStatus::Complete,
        findings: detect(text),
        file_size: size,
        sha256,
    }
}

pub fn inspect_prompt(prompt: &str) -> Inspection {
    let status = if prompt.len() > MAX_INPUT_BYTES || !depth_within_limit(prompt) {
        InspectionStatus::Incomplete
    } else {
        InspectionStatus::Complete
    };
    Inspection {
        status,
        findings: if status.complete() {
            detect(prompt)
        } else {
            vec![]
        },
        file_size: 0,
        sha256: String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(name: &str, bytes: &[u8]) -> FileInput {
        FileInput {
            name: name.into(),
            content_base64: STANDARD.encode(bytes),
        }
    }

    #[test]
    fn clean_utf8_text_is_complete() {
        let result = inspect_file(&file("notes.txt", "ordinary project notes".as_bytes()));
        assert_eq!(result.status, InspectionStatus::Complete);
        assert_eq!(result.sha256.len(), 64);
        assert!(result.findings.is_empty());
    }

    #[test]
    fn rejects_binary_invalid_utf8_and_oversize() {
        assert_eq!(
            inspect_file(&file("notes.txt", &[0xff, 0xfe])).status,
            InspectionStatus::Unsupported
        );
        assert_eq!(
            inspect_file(&file("notes.pdf", b"text")).status,
            InspectionStatus::Unsupported
        );
        assert_eq!(
            inspect_file(&file("notes.txt", &vec![b'a'; MAX_INPUT_BYTES + 1])).status,
            InspectionStatus::Incomplete
        );
        assert_eq!(
            inspect_file(&file("notes.txt", &vec![b'a'; MAX_INPUT_BYTES + 1]))
                .findings
                .len(),
            0
        );
    }

    #[test]
    fn rejects_excess_depth_without_scanning() {
        let deep = "[".repeat(MAX_TEXT_DEPTH + 1);
        assert_eq!(inspect_prompt(&deep).status, InspectionStatus::Incomplete);
        assert!(inspect_prompt(&deep).findings.is_empty());
    }

    #[test]
    fn malformed_base64_fails_instead_of_becoming_clean() {
        assert_eq!(
            inspect_file(&FileInput {
                name: "a.env".into(),
                content_base64: "not base64!!".into()
            })
            .status,
            InspectionStatus::Failed
        );
    }
}

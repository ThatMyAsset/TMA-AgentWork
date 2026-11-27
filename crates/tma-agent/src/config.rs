use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub install_dir: PathBuf,
    #[serde(default)]
    pub control_plane_url: Option<String>,
    #[serde(default, skip_serializing)]
    pub enrollment_token: Option<String>,
    #[serde(default)]
    pub development: bool,
    #[serde(default)]
    pub device_id: Option<Uuid>,
    #[serde(default, skip_serializing)]
    pub device_token: Option<String>,
    pub ipc_credential: String,
}

impl Config {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let value =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let mut config: Self = serde_json::from_str(&value)?;
        if config.ipc_credential.len() < 32 {
            anyhow::bail!("invalid IPC credential")
        }
        if let Some(url) = &config.control_plane_url {
            let parsed = http::Uri::try_from(url.as_str())?;
            // The persisted installer profile is authoritative. A machine-wide
            // environment variable must not silently weaken production URL checks.
            let development = config.development;
            let secure = parsed.scheme_str() == Some("https");
            let http = parsed.scheme_str() == Some("http");
            let loopback = parsed
                .host()
                .is_some_and(|host| matches!(host, "127.0.0.1" | "localhost" | "[::1]" | "::1"));
            let valid_host = parsed.host().is_some()
                && !parsed
                    .authority()
                    .is_some_and(|authority| authority.as_str().contains('@'));
            if parsed.authority().is_some_and(|authority| {
                let host = authority.host();
                let suffix = &authority.as_str()[host.len()..];
                suffix
                    .strip_prefix(':')
                    .is_some_and(|port| port.parse::<u16>().is_err())
            }) {
                anyhow::bail!("control plane URL has an invalid port")
            }
            if !valid_host || !(secure || (http && (loopback || development))) {
                anyhow::bail!("control plane must use HTTPS, except development HTTP")
            }
            if parsed
                .port()
                .is_some_and(|port| port.as_str().parse::<u16>().is_err())
            {
                anyhow::bail!("control plane URL has an invalid port")
            }
        }
        if config.device_token.is_none() {
            if let Ok(token) = std::fs::read_to_string(path.with_file_name("device-token")) {
                config.device_token = Some(token.trim().to_owned());
            }
        }
        if config.enrollment_token.is_none() {
            if let Ok(code) = std::fs::read_to_string(path.with_file_name("pairing-code")) {
                config.enrollment_token = Some(code.trim().to_owned());
            }
        }
        Ok(config)
    }

    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        let temporary = path.with_extension("tmp");
        std::fs::write(&temporary, serde_json::to_vec_pretty(self)?)?;
        crate::platform::restrict_file(&temporary)?;
        if path.exists() {
            std::fs::remove_file(path)?;
        }
        std::fs::rename(temporary, path)?;
        if let Some(token) = &self.device_token {
            let token_path = path.with_file_name("device-token");
            std::fs::write(&token_path, token.as_bytes())?;
            crate::platform::restrict_file(&token_path)?;
        }
        crate::platform::restrict_file(path)?;
        crate::platform::restrict_ipc_config(path)?;
        if self.enrollment_token.is_none() {
            let _ = std::fs::remove_file(path.with_file_name("pairing-code"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn load(url: &str, development: bool) -> anyhow::Result<Config> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("config.json");
        std::fs::write(
            &path,
            serde_json::json!({
                "install_dir": directory.path(),
                "control_plane_url": url,
                "development": development,
                "ipc_credential": "test-credential-that-is-long-enough"
            })
            .to_string(),
        )?;
        Config::load(&path)
    }

    #[test]
    fn development_accepts_and_preserves_direct_http_ip() {
        let config = load("http://43.157.201.52:18080", true).unwrap();
        assert_eq!(
            config.control_plane_url.as_deref(),
            Some("http://43.157.201.52:18080")
        );
    }

    #[test]
    fn development_rejects_malformed_and_credential_urls() {
        for url in [
            "43.157.201.52:18080",
            "http://43.157.201.52:bad",
            "http://user:secret@43.157.201.52:18080",
            "https://user:secret@dlp.example.com",
        ] {
            assert!(load(url, true).is_err(), "{url}");
        }
    }

    #[test]
    fn https_and_loopback_http_remain_accepted_without_development() {
        assert!(load("https://dlp.example.com", false).is_ok());
        assert!(load("http://127.0.0.1:18080", false).is_ok());
        assert!(load("http://43.157.201.52:18080", false).is_err());
    }
}

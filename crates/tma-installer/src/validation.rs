use std::net::IpAddr;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    Install,
    Repair,
    Uninstall { purge: bool },
}

impl Operation {
    pub fn argument(self) -> &'static str {
        match self {
            Self::Install => "install",
            Self::Repair => "repair",
            Self::Uninstall { .. } => "uninstall",
        }
    }

    pub fn verb(self) -> &'static str {
        match self {
            Self::Install => "Install agent",
            Self::Repair => "Repair / upgrade",
            Self::Uninstall { .. } => "Uninstall",
        }
    }

    pub fn needs_configuration(self) -> bool {
        !matches!(self, Self::Uninstall { .. })
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct Configuration {
    pub control_plane_url: String,
    pub pairing_code: String,
    pub chrome_extension_id: String,
    pub edge_extension_id: Option<String>,
}

pub fn validate_url(value: &str) -> Result<String, &'static str> {
    let value = value.trim().trim_end_matches('/');
    let (scheme, remainder) = value
        .split_once("://")
        .ok_or("Enter an HTTPS control-plane URL, such as https://dlp.example.com")?;
    let (authority, _) = remainder
        .split_once(['/', '?', '#'])
        .unwrap_or((remainder, ""));
    if authority.is_empty()
        || authority.contains('@')
        || authority.chars().any(char::is_whitespace)
        || value.chars().any(char::is_control)
    {
        return Err("Control-plane URL has an invalid host, credentials, or whitespace");
    }
    if scheme != "https" {
        let host = authority
            .strip_prefix('[')
            .and_then(|host| host.split_once(']').map(|(host, _)| host))
            .unwrap_or_else(|| authority.split(':').next().unwrap_or(""));
        let loopback = host.eq_ignore_ascii_case("localhost")
            || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback());
        if scheme != "http" || !loopback {
            return Err("Use HTTPS; plain HTTP is allowed only for loopback development");
        }
    }
    let port = if let Some(rest) = authority.strip_prefix('[') {
        let Some((host, suffix)) = rest.split_once(']') else {
            return Err("Control-plane URL has an invalid bracketed host");
        };
        if host.parse::<IpAddr>().is_err() || (!suffix.is_empty() && !suffix.starts_with(':')) {
            return Err("Control-plane URL has an invalid host or port");
        }
        suffix.strip_prefix(':')
    } else {
        if authority.starts_with(':') || authority.matches(':').count() > 1 {
            return Err("Control-plane URL has an invalid host or port");
        }
        authority.rsplit_once(':').map(|(_, port)| port)
    };
    if port.is_some_and(|port| port.is_empty() || port.parse::<u16>().is_err() || port == "0") {
        return Err("Control-plane URL has an invalid port");
    }
    Ok(value.to_owned())
}

pub fn validate_pairing_code(value: &str) -> Result<String, &'static str> {
    let value = value.trim();
    if value.len() < 16
        || value.len() > 256
        || value.chars().any(char::is_whitespace)
        || !value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_-".contains(c))
    {
        return Err("Paste the complete one-time pairing code (no spaces)");
    }
    Ok(value.to_owned())
}

pub fn validate_extension_id(value: &str, browser: &str) -> Result<String, String> {
    let value = value.trim();
    if value.len() != 32 || !value.bytes().all(|b| (b'a'..=b'p').contains(&b)) {
        return Err(format!(
            "{browser} extension ID must be 32 lowercase letters (a–p)"
        ));
    }
    Ok(value.to_owned())
}

pub fn validate_configuration(
    url: &str,
    pairing_code: &str,
    chrome: &str,
    edge: &str,
) -> Result<Configuration, String> {
    let edge = edge.trim();
    Ok(Configuration {
        control_plane_url: validate_url(url).map_err(str::to_owned)?,
        pairing_code: validate_pairing_code(pairing_code).map_err(str::to_owned)?,
        chrome_extension_id: validate_extension_id(chrome, "Chrome")?,
        edge_extension_id: if edge.is_empty() {
            None
        } else {
            Some(validate_extension_id(edge, "Edge")?)
        },
    })
}

pub fn validate_repair_configuration(
    url: &str,
    pairing_code: &str,
    chrome: &str,
    edge: &str,
) -> Result<Configuration, String> {
    if !url.is_empty() {
        validate_url(url)?;
    }
    if !pairing_code.is_empty() {
        validate_pairing_code(pairing_code)?;
    }
    if !chrome.is_empty() {
        validate_extension_id(chrome, "Chrome")?;
    }
    if !edge.is_empty() {
        validate_extension_id(edge, "Edge")?;
    }
    Ok(Configuration {
        control_plane_url: url.trim().to_owned(),
        pairing_code: pairing_code.trim().to_owned(),
        chrome_extension_id: chrome.trim().to_owned(),
        edge_extension_id: if edge.trim().is_empty() {
            None
        } else {
            Some(edge.trim().to_owned())
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_https_and_trailing_slash() {
        assert_eq!(
            validate_url(" https://dlp.example.com/ ").unwrap(),
            "https://dlp.example.com"
        );
        assert_eq!(
            validate_url("https://dlp.example.com:8443/tma").unwrap(),
            "https://dlp.example.com:8443/tma"
        );
    }

    #[test]
    fn accepts_only_loopback_http() {
        for url in [
            "http://localhost:8080",
            "http://127.0.0.1",
            "http://[::1]:8080",
        ] {
            assert!(validate_url(url).is_ok(), "{url}");
        }
        for url in [
            "http://dlp.example.com",
            "http://localhost.evil.test",
            "ftp://localhost",
        ] {
            assert!(validate_url(url).is_err(), "{url}");
        }
    }

    #[test]
    fn rejects_malformed_urls() {
        for url in [
            "",
            "dlp.example.com",
            "https://",
            "https://user:secret@dlp.example.com",
            "https://dlp.example.com:0",
            "https://dlp.example.com:70000",
            "https://dlp example.com",
            "https://[::1]:bad",
            "https://:443",
            "https://dlp.example.com:443:8443",
        ] {
            assert!(validate_url(url).is_err(), "{url}");
        }
    }

    #[test]
    fn validates_dashboard_pairing_code_and_rejects_whitespace() {
        let code = format!("tma_pair_{}", "A".repeat(43));
        assert_eq!(validate_pairing_code(&code).unwrap(), code);
        assert!(validate_pairing_code("short").is_err());
        assert!(validate_pairing_code("tma_pair_with space").is_err());
        assert!(validate_pairing_code("tma_pair_with/slash").is_err());
    }

    #[test]
    fn validates_chromium_extension_ids() {
        assert_eq!(
            validate_extension_id(&"a".repeat(32), "Chrome").unwrap(),
            "a".repeat(32)
        );
        for id in [&"a".repeat(31), &"z".repeat(32), &"A".repeat(32)] {
            assert!(validate_extension_id(id, "Chrome").is_err());
        }
    }

    #[test]
    fn optional_edge_id_stays_empty() {
        let config = validate_configuration(
            "https://dlp.example.com",
            "tma_pair_abcdefghijklmnop",
            &"a".repeat(32),
            " ",
        )
        .unwrap();
        assert_eq!(config.edge_extension_id, None);
    }

    #[test]
    fn repair_keeps_blank_fields_and_validates_supplied_values() {
        let config = validate_repair_configuration("", "", "", "").unwrap();
        assert!(config.control_plane_url.is_empty());
        assert!(config.pairing_code.is_empty());
        assert!(config.chrome_extension_id.is_empty());
        assert_eq!(config.edge_extension_id, None);
        assert!(validate_repair_configuration("http://remote.test", "", "", "").is_err());
        assert!(validate_repair_configuration("", "short", "", "").is_err());
        assert!(validate_repair_configuration("", "", "invalid", "").is_err());
        assert!(validate_repair_configuration("", "", "", &"a".repeat(32)).is_ok());
    }
}

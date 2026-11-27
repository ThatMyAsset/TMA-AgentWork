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
    pub development: bool,
}

pub fn development_mode_value(value: Option<&str>, existing: bool) -> bool {
    match value.map(str::trim) {
        Some(value) if value.eq_ignore_ascii_case("true") => true,
        Some(value) if value.eq_ignore_ascii_case("false") => false,
        _ => existing,
    }
}

pub fn validate_url(value: &str, development: bool) -> Result<String, &'static str> {
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
        if scheme != "http" || !(loopback || development) {
            return Err("Use HTTPS, or enable TMA_DEVELOPMENT=true for development HTTP");
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

pub fn validate_firefox_extension_id(value: &str) -> Result<String, String> {
    let value = value.trim();
    if value.len() < 3
        || value.len() > 128
        || value.chars().any(char::is_whitespace)
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"@._+-{}".contains(&b))
    {
        return Err(
            "Firefox Add-on ID must be a valid Gecko ID, such as thatmyassets-dlp@example.com"
                .to_owned(),
        );
    }
    Ok(value.to_owned())
}

pub fn validate_configuration(
    url: &str,
    pairing_code: &str,
    chrome: &str,
    edge: &str,
    development: bool,
) -> Result<Configuration, String> {
    let chrome = if chrome.trim().is_empty() {
        String::new()
    } else {
        validate_extension_id(chrome, "Chromium")?
    };
    let edge = edge.trim();
    let firefox = if edge.is_empty() {
        None
    } else {
        Some(validate_firefox_extension_id(edge)?)
    };
    if chrome.is_empty() && firefox.is_none() {
        return Err("Enter a Chromium extension ID or Firefox Add-on ID".into());
    }
    Ok(Configuration {
        control_plane_url: validate_url(url, development).map_err(str::to_owned)?,
        pairing_code: validate_pairing_code(pairing_code).map_err(str::to_owned)?,
        chrome_extension_id: chrome,
        edge_extension_id: firefox,
        development,
    })
}

pub fn validate_repair_configuration(
    url: &str,
    pairing_code: &str,
    chrome: &str,
    edge: &str,
    development: bool,
) -> Result<Configuration, String> {
    if !url.is_empty() {
        validate_url(url, development)?;
    }
    if !pairing_code.is_empty() {
        validate_pairing_code(pairing_code)?;
    }
    let chromium = if chrome.trim().is_empty() {
        String::new()
    } else {
        validate_extension_id(chrome, "Chromium")?
    };
    let firefox = if edge.trim().is_empty() {
        None
    } else {
        Some(validate_firefox_extension_id(edge)?)
    };
    Ok(Configuration {
        control_plane_url: url.trim().to_owned(),
        pairing_code: pairing_code.trim().to_owned(),
        chrome_extension_id: chromium,
        edge_extension_id: firefox,
        development,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn development_setting_preserves_existing_value_unless_explicitly_overridden() {
        assert!(development_mode_value(None, true));
        assert!(!development_mode_value(None, false));
        assert!(development_mode_value(Some("true"), false));
        assert!(!development_mode_value(Some("false"), true));
        assert!(development_mode_value(Some("invalid"), true));
    }

    #[test]
    fn accepts_https_and_trailing_slash() {
        assert_eq!(
            validate_url(" https://dlp.example.com/ ", false).unwrap(),
            "https://dlp.example.com"
        );
        assert_eq!(
            validate_url("https://dlp.example.com:8443/tma", false).unwrap(),
            "https://dlp.example.com:8443/tma"
        );
    }

    #[test]
    fn accepts_direct_http_ip_only_in_development() {
        for url in [
            "http://localhost:8080",
            "http://127.0.0.1",
            "http://[::1]:8080",
        ] {
            assert!(validate_url(url, false).is_ok(), "{url}");
        }
        assert_eq!(
            validate_url("http://43.157.201.52:18080", true).unwrap(),
            "http://43.157.201.52:18080"
        );
        for url in [
            "http://dlp.example.com",
            "http://43.157.201.52:18080",
            "http://localhost.evil.test",
            "ftp://localhost",
        ] {
            assert!(validate_url(url, false).is_err(), "{url}");
        }
    }

    #[test]
    fn rejects_malformed_urls() {
        for url in [
            "",
            "dlp.example.com",
            "https://",
            "http://43.157.201.52:bad",
            "http://user:secret@43.157.201.52:18080",
            "https://user:secret@dlp.example.com",
            "https://dlp.example.com:0",
            "https://dlp.example.com:70000",
            "https://dlp example.com",
            "https://[::1]:bad",
            "https://:443",
            "https://dlp.example.com:443:8443",
        ] {
            assert!(validate_url(url, true).is_err(), "{url}");
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
            false,
        )
        .unwrap();
        assert_eq!(config.edge_extension_id, None);
        assert!(!config.development);
    }

    #[test]
    fn repair_keeps_blank_fields_and_validates_supplied_values() {
        let config = validate_repair_configuration("", "", "", "", false).unwrap();
        assert!(config.control_plane_url.is_empty());
        assert!(config.pairing_code.is_empty());
        assert!(config.chrome_extension_id.is_empty());
        assert_eq!(config.edge_extension_id, None);
        assert!(!config.development);
        assert!(validate_repair_configuration("http://remote.test", "", "", "", false).is_err());
        let development =
            validate_repair_configuration("http://43.157.201.52:18080", "", "", "", true).unwrap();
        assert!(development.development);
        assert!(validate_repair_configuration("", "short", "", "", false).is_err());
        assert!(validate_repair_configuration("", "", "invalid", "", false).is_err());
        assert!(validate_repair_configuration("", "", "", &"a".repeat(32), false).is_ok());
    }
}

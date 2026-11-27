#![cfg_attr(windows, windows_subsystem = "windows")]

mod validation;

#[cfg(not(windows))]
fn main() {
    eprintln!("tma-installer is supported only on Windows");
    std::process::exit(1);
}

#[cfg(windows)]
fn main() {
    let arguments: Vec<_> = std::env::args_os().collect();
    let gui = arguments.len() == 1;
    if !gui && arguments.get(1).map_or(true, |arg| arg != "--worker") {
        unsafe {
            windows_sys::Win32::System::Console::AttachConsole(
                windows_sys::Win32::System::Console::ATTACH_PARENT_PROCESS,
            );
        }
    }
    if let Err(error) = installer::run() {
        if gui {
            installer::show_fatal_error(&format!(
                "ThatMyAssets setup could not start.\n\n{error:#}"
            ));
        } else if arguments.get(1).map_or(true, |arg| arg != "--worker") {
            eprintln!("tma-installer: {error:#}");
        }
        std::process::exit(1);
    }
}

#[cfg(windows)]
mod installer {
    mod gui;
    include!(concat!(env!("OUT_DIR"), "/payloads.rs"));
    use crate::validation;
    use anyhow::{bail, Context};
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::path::{Path, PathBuf};
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::Foundation::{LocalFree, ERROR_SERVICE_MARKED_FOR_DELETE};
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SetNamedSecurityInfoW,
        SDDL_REVISION_1, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::DACL_SECURITY_INFORMATION;
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, DELETE, MOVEFILE_DELAY_UNTIL_REBOOT,
    };
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegCreateKeyExW, RegDeleteTreeW, RegSetValueExW, HKEY, HKEY_LOCAL_MACHINE,
        KEY_SET_VALUE, REG_OPTION_NON_VOLATILE, REG_SZ,
    };
    use windows_sys::Win32::System::Services::*;
    use windows_sys::Win32::UI::Shell::IsUserAnAdmin;

    const SERVICE_NAME: &str = "TMAAgent";
    const HOST_NAME: &str = "com.thatmyassets.dlp";
    const INSTALL_DIR: &str = r"C:\Program Files\ThatMyAssets\Agent";
    const DATA_DIR: &str = r"C:\ProgramData\ThatMyAssets";
    const BINARIES: &[&str] = &[
        "tma-agent.exe",
        "tma-relay.exe",
        "tma-parser.exe",
        "tma-doctor.exe",
    ];

    fn wide(value: impl AsRef<OsStr>) -> Vec<u16> {
        value.as_ref().encode_wide().chain(Some(0)).collect()
    }
    fn random_credential() -> anyhow::Result<String> {
        let mut bytes = [0_u8; 32];
        getrandom::getrandom(&mut bytes)?;
        Ok(URL_SAFE_NO_PAD.encode(bytes))
    }

    fn stored_development_mode() -> bool {
        let path = Path::new(DATA_DIR).join("config.json");
        std::fs::read_to_string(path)
            .ok()
            .and_then(|text| serde_json::from_str::<serde_json::Value>(&text).ok())
            .and_then(|value| value.get("development").and_then(serde_json::Value::as_bool).map(bool::to_owned))
            .unwrap_or(false)
    }

    fn development_mode() -> bool {
        validation::development_mode_value(
            std::env::var("TMA_DEVELOPMENT").ok().as_deref(),
            stored_development_mode(),
        )
    }

    struct ScHandle(SC_HANDLE);
    impl Drop for ScHandle {
        fn drop(&mut self) {
            unsafe {
                CloseServiceHandle(self.0);
            }
        }
    }

    fn set_acl(path: &Path, sddl: &str) -> anyhow::Result<()> {
        let sddl = wide(sddl);
        let path_wide = wide(path.as_os_str());
        let mut descriptor = null_mut();
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                null_mut(),
            )
        } == 0
        {
            bail!("security descriptor: {}", std::io::Error::last_os_error())
        }
        let mut dacl = null_mut();
        let mut present = 0;
        let mut defaulted = 0;
        let ok = unsafe {
            windows_sys::Win32::Security::GetSecurityDescriptorDacl(
                descriptor,
                &mut present,
                &mut dacl,
                &mut defaulted,
            )
        };
        if ok == 0 || present == 0 {
            unsafe {
                LocalFree(descriptor);
            }
            bail!(
                "security descriptor DACL: {}",
                std::io::Error::last_os_error()
            );
        }
        let result = unsafe {
            SetNamedSecurityInfoW(
                path_wide.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | 0x80000000,
                null_mut(),
                null_mut(),
                dacl,
                null_mut(),
            )
        };
        unsafe {
            LocalFree(descriptor);
        }
        if result != 0 {
            bail!(
                "SetNamedSecurityInfoW({}) returned {result}",
                path.display()
            )
        }
        Ok(())
    }

    fn acl(path: &Path, users_read: bool) -> anyhow::Result<()> {
        set_acl(
            path,
            if users_read {
                "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGX;;;BU)"
            } else {
                "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;LS)"
            },
        )
    }

    fn acl_with_users(path: &Path) -> anyhow::Result<()> {
        set_acl(path, "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;LS)(A;;GR;;;AU)")
    }

    use std::io::Write;
    use std::sync::{Mutex, OnceLock};

    static WORKER_OUTPUT: OnceLock<Mutex<std::fs::File>> = OnceLock::new();

    fn emit(kind: &str, value: &str, detail: &str) {
        let clean = |text: &str| text.replace(['|', '\r', '\n'], " ");
        let line = format!("{kind}|{}|{}\n", clean(value), clean(detail));
        if let Some(output) = WORKER_OUTPUT.get() {
            if let Ok(mut output) = output.lock() {
                let _ = output.write_all(line.as_bytes());
                let _ = output.flush();
            }
        }
    }

    fn progress(percent: u32, detail: &str) {
        emit("progress", &percent.to_string(), detail);
    }

    pub fn run() -> anyhow::Result<()> {
        let mut args = std::env::args().skip(1);
        let Some(command) = args.next() else {
            return gui::run();
        };
        match command.as_str() {
            "--worker" => {
                let operation = args.next().context("worker operation required")?;
                let report = args.next().context("worker report path required")?;
                let purge = args.next().as_deref() == Some("--purge");
                let report = std::fs::OpenOptions::new()
                    .append(true)
                    .open(report)
                    .context("opening setup progress report")?;
                let _ = WORKER_OUTPUT.set(Mutex::new(report));
                if operation != "uninstall" {
                    let development = development_mode();
                    for variable in ["TMA_CONTROL_PLANE_URL", "TMA_PAIRING_CODE", "TMA_CHROME_EXTENSION_ID", "TMA_EDGE_EXTENSION_ID"] {
                        if let Ok(value) = std::env::var(variable) {
                            if !value.is_empty() {
                                let result = match variable {
                                    "TMA_CONTROL_PLANE_URL" => validation::validate_url(&value, development).map(|_| ()).map_err(str::to_owned),
                                    "TMA_PAIRING_CODE" => validation::validate_pairing_code(&value).map(|_| ()).map_err(str::to_owned),
                                    "TMA_CHROME_EXTENSION_ID" => validation::validate_extension_id(&value, "Chrome").map(|_| ()),
                                    _ => validation::validate_extension_id(&value, "Edge").map(|_| ()),
                                };
                                if let Err(error) = result {
                                    emit("result", "error", &format!("{variable}: {error}"));
                                    return Err(anyhow::anyhow!(error));
                                }
                            }
                        }
                    }
                }
                let result = match operation.as_str() {
                    "install" => install(),
                    "repair" | "upgrade" => install(),
                    "uninstall" => uninstall(purge),
                    _ => bail!("invalid worker operation"),
                };
                match result {
                    Ok(()) => {
                        if operation == "uninstall" {
                            emit("result", "removed", if purge {
                                "Agent removed. Local events and enrollment were permanently erased."
                            } else {
                                "Agent service and binaries removed. Local events and enrollment were preserved."
                            });
                        }
                        Ok(())
                    }
                    Err(error) => {
                        emit("result", "error", &format!("{error:#}"));
                        Err(error)
                    }
                }
            }
            "install" | "repair" | "upgrade" => {
                let development = development_mode();
                if let Ok(url) = std::env::var("TMA_CONTROL_PLANE_URL") {
                    if !url.is_empty() {
                        validation::validate_url(&url, development).map_err(|error| anyhow::anyhow!(error))?;
                    }
                }
                if let Ok(code) = std::env::var("TMA_PAIRING_CODE") {
                    if !code.is_empty() {
                        validation::validate_pairing_code(&code).map_err(|error| anyhow::anyhow!(error))?;
                    }
                }
                for (variable, browser) in [("TMA_CHROME_EXTENSION_ID", "Chrome"), ("TMA_EDGE_EXTENSION_ID", "Edge")] {
                    if let Ok(id) = std::env::var(variable) {
                        if !id.is_empty() {
                            validation::validate_extension_id(&id, browser).map_err(anyhow::Error::msg)?;
                        }
                    }
                }
                install()
            }
            "uninstall" => uninstall(args.any(|arg| arg == "--purge")),
            "register-extension" => register_extension(args.next().context("Chrome extension ID required")?, args.next()),
            _ => bail!("usage: tma-installer [install|repair|upgrade | uninstall [--purge] | register-extension <chrome-id> [edge-id]]"),
        }
    }

    pub fn show_fatal_error(message: &str) {
        unsafe {
            windows_sys::Win32::UI::WindowsAndMessaging::MessageBoxW(
                null_mut(),
                wide(message).as_ptr(),
                wide("ThatMyAssets Agent setup").as_ptr(),
                windows_sys::Win32::UI::WindowsAndMessaging::MB_OK
                    | windows_sys::Win32::UI::WindowsAndMessaging::MB_ICONERROR,
            );
        }
    }

    fn require_admin() -> anyhow::Result<()> {
        if unsafe { IsUserAnAdmin() } == 0 {
            bail!("Run elevated as Administrator")
        }
        Ok(())
    }

    fn install() -> anyhow::Result<()> {
        require_admin()?;
        progress(2, "Verifying administrator access and embedded payloads");
        let source = std::env::current_exe()?
            .parent()
            .context("installer directory")?
            .to_owned();
        if PAYLOADS.is_empty() {
            for name in BINARIES {
                if !source.join(name).is_file() {
                    bail!(
                        "development installer requires {}; production setup.exe embeds payloads",
                        source.join(name).display()
                    )
                }
            }
        }
        let install = PathBuf::from(INSTALL_DIR);
        let data = PathBuf::from(DATA_DIR);
        std::fs::create_dir_all(&install)?;
        std::fs::create_dir_all(&data)?;
        acl(&install, true)?;
        acl(&data, false)?;
        progress(12, "Preparing protected program and data directories");

        // Stop before replacement; SCM recovery settings survive an in-place upgrade.
        let manager = open_manager(SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE)?;
        if let Ok(service) = open_service(SERVICE_STOP | SERVICE_QUERY_STATUS) {
            stop_service(service.0)?;
        }
        progress(
            25,
            "Installing agent, relay, parser and diagnostic binaries",
        );
        for (name, compressed) in PAYLOADS {
            use std::io::Read;
            let destination = install.join(name);
            let mut decoder = flate2::read::ZlibDecoder::new(*compressed);
            let mut bytes = Vec::new();
            decoder
                .read_to_end(&mut bytes)
                .with_context(|| format!("decompressing embedded {name}"))?;
            std::fs::write(&destination, bytes)
                .with_context(|| format!("installing {}", destination.display()))?;
            acl(&destination, true)?;
        }
        for name in BINARIES {
            if PAYLOADS.iter().any(|(embedded, _)| embedded == name) {
                continue;
            }
            let destination = install.join(name);
            std::fs::copy(source.join(name), &destination)
                .with_context(|| format!("installing {}", destination.display()))?;
            acl(&destination, true)?;
        }
        progress(
            55,
            "Preserving enrollment and protecting local configuration",
        );
        let config_path = data.join("config.json");
        let mut config = if config_path.exists() {
            std::fs::read_to_string(&config_path)?.parse::<serde_json::Value>()?
        } else {
            serde_json::json!({})
        };
        config["install_dir"] = serde_json::Value::String(INSTALL_DIR.into());
        if config
            .get("ipc_credential")
            .and_then(|v| v.as_str())
            .map_or(true, |v| v.len() < 32)
            || std::env::var_os("TMA_ROTATE_IPC_CREDENTIAL").is_some()
        {
            config["ipc_credential"] = serde_json::Value::String(random_credential()?);
        }
        config["development"] = serde_json::Value::Bool(development_mode());
        if let Ok(url) = std::env::var("TMA_CONTROL_PLANE_URL") {
            if !url.is_empty() {
                config["control_plane_url"] = serde_json::Value::String(url);
            }
        }
        if let Ok(code) = std::env::var("TMA_PAIRING_CODE") {
            if !code.is_empty() {
                let code_path = data.join("pairing-code");
                std::fs::write(&code_path, code.as_bytes())?;
                acl(&code_path, false)?;
            }
        }
        std::fs::write(&config_path, serde_json::to_vec_pretty(&config)?)?;
        // Relay needs read-only local credential. Authenticated Users cannot modify protected config.
        acl_with_users(&config_path)?;
        progress(68, "Configuring automatic startup and service recovery");

        let binary = format!("\"{}\"", install.join("tma-agent.exe").display());
        let service =
            match open_service(SERVICE_CHANGE_CONFIG | SERVICE_START | SERVICE_QUERY_STATUS) {
                Ok(service) => {
                    if unsafe {
                        ChangeServiceConfigW(
                            service.0,
                            SERVICE_NO_CHANGE,
                            SERVICE_NO_CHANGE,
                            SERVICE_AUTO_START,
                            wide(&binary).as_ptr(),
                            null(),
                            null_mut(),
                            null(),
                            wide(r"NT AUTHORITY\LocalService").as_ptr(),
                            null(),
                            null(),
                        )
                    } == 0
                    {
                        bail!("ChangeServiceConfigW: {}", std::io::Error::last_os_error())
                    }
                    service
                }
                Err(_) => {
                    let handle = unsafe {
                        CreateServiceW(
                            manager.0,
                            wide(SERVICE_NAME).as_ptr(),
                            wide("ThatMyAssets DLP Agent").as_ptr(),
                            SERVICE_CHANGE_CONFIG
                                | SERVICE_START
                                | SERVICE_QUERY_STATUS
                                | SERVICE_STOP,
                            SERVICE_WIN32_OWN_PROCESS,
                            SERVICE_AUTO_START,
                            SERVICE_ERROR_NORMAL,
                            wide(&binary).as_ptr(),
                            null(),
                            null_mut(),
                            null(),
                            wide(r"NT AUTHORITY\LocalService").as_ptr(),
                            null(),
                        )
                    };
                    if handle.is_null() {
                        bail!("CreateServiceW: {}", std::io::Error::last_os_error())
                    }
                    ScHandle(handle)
                }
            };
        configure_recovery(service.0)?;
        progress(78, "Registering the authenticated browser relay");
        register_host(&install.join("tma-relay.exe"))?;
        progress(84, "Starting the agent service");
        if unsafe { StartServiceW(service.0, 0, null()) } == 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(1056) {
                return Err(error).context("StartServiceW");
            }
        }
        wait_service_running(service.0, std::time::Duration::from_secs(30))?;
        progress(92, "Checking local enrollment and protection health");
        let health = health_report(&install);
        emit("result", &health.0, &health.1);
        println!("{}", health.1);
        println!("Native host {HOST_NAME} registered for Chrome and Edge.");
        Ok(())
    }

    pub fn health_report(install: &Path) -> (String, String) {
        use std::os::windows::process::CommandExt;
        if !install.join("tma-doctor.exe").is_file() {
            return ("unavailable".into(), "Agent is not installed or its diagnostic binary is missing. Protection is not confirmed.".into());
        }
        let output = std::process::Command::new(install.join("tma-doctor.exe"))
            .arg("health")
            .creation_flags(windows_sys::Win32::System::Threading::CREATE_NO_WINDOW)
            .output();
        let health = output
            .ok()
            .filter(|output| output.status.success())
            .and_then(|output| serde_json::from_slice::<serde_json::Value>(&output.stdout).ok());
        let status = health
            .as_ref()
            .and_then(|health| health["status"].as_str())
            .unwrap_or("unavailable")
            .to_owned();
        let message = match health {
            Some(health) => {
                let connection = &health["connection"];
                let enrolled = connection["enrolled"].as_bool().unwrap_or(false);
                let configured = connection["control_plane_configured"].as_bool().unwrap_or(false);
                let reachable = connection["control_plane_state"].as_str() == Some("connected");
                if !configured {
                    "Service running, but control plane URL is not configured. Enrollment and protection cannot connect.".to_owned()
                } else if !enrolled {
                    "Service running, but device enrollment is incomplete. Verify control plane connectivity and pairing code.".to_owned()
                } else if !reachable {
                    "Service running and enrolled, but control plane is unreachable or has not connected. Check network and control plane availability.".to_owned()
                } else {
                    match status.as_str() {
                        "protected" => "Protected: control plane, valid policy and browser connection confirmed.".to_owned(),
                        "limited" => "Service running, enrolled and control plane connected. Valid policy or browser connection is still required.".to_owned(),
                        "pending_enrollment" => "Service running, but device credentials are incomplete. Re-enrollment is required.".to_owned(),
                        "degraded" => "Service running with degraded health. Protection is not confirmed; run tma-doctor health.".to_owned(),
                        _ => "Service running. Health is not yet available; use Recheck health.".to_owned(),
                    }
                }
            }
            None => "Service health is unavailable. Check that the agent service is running and local IPC is accessible.".to_owned(),
        };
        (status, message)
    }
    fn wait_service_running(handle: SC_HANDLE, timeout: std::time::Duration) -> anyhow::Result<()> {
        let started = std::time::Instant::now();
        let mut status: SERVICE_STATUS = unsafe { std::mem::zeroed() };
        while started.elapsed() < timeout {
            if unsafe { QueryServiceStatus(handle, &mut status) } == 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            if status.dwCurrentState == SERVICE_RUNNING {
                return Ok(());
            }
            if status.dwCurrentState == SERVICE_STOPPED {
                bail!("service stopped during startup")
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        bail!(
            "service did not reach SERVICE_RUNNING within {} seconds",
            timeout.as_secs()
        )
    }

    fn open_manager(access: u32) -> anyhow::Result<ScHandle> {
        let handle = unsafe { OpenSCManagerW(null(), null(), access) };
        if handle.is_null() {
            Err(std::io::Error::last_os_error()).context("OpenSCManagerW (elevation required)")
        } else {
            Ok(ScHandle(handle))
        }
    }
    fn open_service(access: u32) -> anyhow::Result<ScHandle> {
        let manager = open_manager(SC_MANAGER_CONNECT)?;
        let handle = unsafe { OpenServiceW(manager.0, wide(SERVICE_NAME).as_ptr(), access) };
        if handle.is_null() {
            Err(std::io::Error::last_os_error()).context("OpenServiceW")
        } else {
            Ok(ScHandle(handle))
        }
    }

    fn stop_service(handle: SC_HANDLE) -> anyhow::Result<()> {
        let mut status: SERVICE_STATUS = unsafe { std::mem::zeroed() };
        if unsafe { ControlService(handle, SERVICE_CONTROL_STOP, &mut status) } == 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(1062) {
                return Err(error.into());
            }
        }
        for _ in 0..100 {
            if unsafe { QueryServiceStatus(handle, &mut status) } == 0 {
                break;
            }
            if status.dwCurrentState == SERVICE_STOPPED {
                return Ok(());
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        bail!("service did not stop within 10 seconds")
    }

    fn configure_recovery(handle: SC_HANDLE) -> anyhow::Result<()> {
        let mut actions = [
            SC_ACTION {
                Type: SC_ACTION_RESTART,
                Delay: 5000,
            },
            SC_ACTION {
                Type: SC_ACTION_RESTART,
                Delay: 15000,
            },
            SC_ACTION {
                Type: SC_ACTION_RESTART,
                Delay: 60000,
            },
        ];
        let failure = SERVICE_FAILURE_ACTIONSW {
            dwResetPeriod: 86400,
            lpRebootMsg: null_mut(),
            lpCommand: null_mut(),
            cActions: actions.len() as u32,
            lpsaActions: actions.as_mut_ptr(),
        };
        if unsafe {
            ChangeServiceConfig2W(
                handle,
                SERVICE_CONFIG_FAILURE_ACTIONS,
                &failure as *const _ as *mut _,
            )
        } == 0
        {
            bail!("setting SCM recovery: {}", std::io::Error::last_os_error())
        }
        let mut flag = SERVICE_FAILURE_ACTIONS_FLAG {
            fFailureActionsOnNonCrashFailures: 1,
        };
        if unsafe {
            ChangeServiceConfig2W(
                handle,
                SERVICE_CONFIG_FAILURE_ACTIONS_FLAG,
                &mut flag as *mut _ as *mut _,
            )
        } == 0
        {
            bail!(
                "enabling non-crash recovery: {}",
                std::io::Error::last_os_error()
            )
        }
        Ok(())
    }

    fn registry_string(root: HKEY, path: &str, value: &str) -> anyhow::Result<()> {
        let mut key = null_mut();
        let result = unsafe {
            RegCreateKeyExW(
                root,
                wide(path).as_ptr(),
                0,
                null(),
                REG_OPTION_NON_VOLATILE,
                KEY_SET_VALUE,
                null(),
                &mut key,
                null_mut(),
            )
        };
        if result != 0 {
            bail!("RegCreateKeyExW {path}: {result}")
        }
        let wide_value = wide(value);
        let bytes: &[u8] = unsafe {
            std::slice::from_raw_parts(wide_value.as_ptr() as *const u8, wide_value.len() * 2)
        };
        let result =
            unsafe { RegSetValueExW(key, null(), 0, REG_SZ, bytes.as_ptr(), bytes.len() as u32) };
        unsafe {
            RegCloseKey(key);
        }
        if result != 0 {
            bail!("RegSetValueExW {path}: {result}")
        }
        Ok(())
    }

    fn register_host(relay: &Path) -> anyhow::Result<()> {
        let data = PathBuf::from(DATA_DIR);
        let manifest = data.join("native-host.json");
        let mut origins = std::fs::read(&manifest)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
            .and_then(|value| value["allowed_origins"].as_array().cloned())
            .unwrap_or_default();
        for variable in ["TMA_CHROME_EXTENSION_ID", "TMA_EDGE_EXTENSION_ID"] {
            if let Ok(id) = std::env::var(variable) {
                if !id.is_empty() {
                    let origin = format!("chrome-extension://{id}/");
                    if !origins.iter().any(|item| item.as_str() == Some(&origin)) {
                        origins.push(origin.into());
                    }
                }
            }
        }
        // Empty origins deliberately prevents browser access until a real extension ID is configured.
        let manifest_body = serde_json::json!({"name": HOST_NAME, "description": "ThatMyAssets authenticated native messaging relay", "path": relay.to_string_lossy(), "type": "stdio", "allowed_origins": origins});
        std::fs::write(&manifest, serde_json::to_vec_pretty(&manifest_body)?)?;
        acl(&manifest, true)?;
        registry_string(
            HKEY_LOCAL_MACHINE,
            &format!(r"Software\Google\Chrome\NativeMessagingHosts\{HOST_NAME}"),
            &manifest.to_string_lossy(),
        )?;
        registry_string(
            HKEY_LOCAL_MACHINE,
            &format!(r"Software\Microsoft\Edge\NativeMessagingHosts\{HOST_NAME}"),
            &manifest.to_string_lossy(),
        )?;
        Ok(())
    }

    fn register_extension(chrome: String, edge: Option<String>) -> anyhow::Result<()> {
        require_admin()?;
        validation::validate_extension_id(&chrome, "Chrome").map_err(anyhow::Error::msg)?;
        if let Some(id) = &edge {
            validation::validate_extension_id(id, "Edge").map_err(anyhow::Error::msg)?;
            std::env::set_var("TMA_EDGE_EXTENSION_ID", id);
        }
        std::env::set_var("TMA_CHROME_EXTENSION_ID", &chrome);
        register_host(&PathBuf::from(INSTALL_DIR).join("tma-relay.exe"))?;
        println!("Native Messaging allowlist updated; reload browser extensions");
        Ok(())
    }

    fn uninstall(purge: bool) -> anyhow::Result<()> {
        require_admin()?;
        progress(10, "Stopping and removing the agent service");
        let _manager = open_manager(SC_MANAGER_CONNECT)?;
        if let Ok(service) = open_service(SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS) {
            let _ = stop_service(service.0);
            if unsafe { DeleteService(service.0) } == 0 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() != Some(ERROR_SERVICE_MARKED_FOR_DELETE as i32) {
                    return Err(error.into());
                }
            }
        }
        progress(40, "Removing Chrome and Edge native host registrations");
        for path in [
            format!(r"Software\Google\Chrome\NativeMessagingHosts\{HOST_NAME}"),
            format!(r"Software\Microsoft\Edge\NativeMessagingHosts\{HOST_NAME}"),
        ] {
            let result = unsafe { RegDeleteTreeW(HKEY_LOCAL_MACHINE, wide(&path).as_ptr()) };
            if result != 0 && result != 2 {
                bail!("removing native host registration: {result}")
            }
        }
        progress(65, "Removing installed binaries");
        for name in BINARIES {
            let path = PathBuf::from(INSTALL_DIR).join(name);
            if path.exists()
                && std::fs::remove_file(&path).is_err()
                && unsafe {
                    MoveFileExW(
                        wide(path.as_os_str()).as_ptr(),
                        null(),
                        MOVEFILE_DELAY_UNTIL_REBOOT,
                    )
                } == 0
            {
                bail!(
                    "scheduling binary removal: {}",
                    std::io::Error::last_os_error()
                )
            }
        }
        progress(
            85,
            if purge {
                "Permanently erasing local events and enrollment"
            } else {
                "Preserving local events and enrollment"
            },
        );
        if purge && Path::new(DATA_DIR).exists() {
            std::fs::remove_dir_all(DATA_DIR).context(
                "removing queued events and enrollment; use without --purge to preserve",
            )?;
            println!(
                "Removed service, binaries, native registrations, local events and enrollment."
            );
        } else {
            let _ = std::fs::remove_file(PathBuf::from(DATA_DIR).join("native-host.json"));
            println!("Removed service and binaries. Preserved {} for reinstallation; use uninstall --purge to erase it.", DATA_DIR);
        }
        progress(100, "Removal complete");
        Ok(())
    }
}

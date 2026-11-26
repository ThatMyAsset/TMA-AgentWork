#[cfg(not(windows))]
fn main() {
    eprintln!("tma-installer is supported only on Windows");
    std::process::exit(1);
}

#[cfg(windows)]
fn main() {
    if let Err(error) = installer::run() {
        eprintln!("tma-installer: {error:#}");
        std::process::exit(1);
    }
}

#[cfg(windows)]
mod installer {
    include!(concat!(env!("OUT_DIR"), "/payloads.rs"));
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

    pub fn run() -> anyhow::Result<()> {
        let mut args = std::env::args().skip(1);
        let command = args.next().unwrap_or_else(|| "install".into());
        match command.as_str() {
            "install" | "repair" | "upgrade" => install(),
            "uninstall" => uninstall(args.any(|arg| arg == "--purge")),
            "register-extension" => register_extension(args.next().context("Chrome extension ID required")?, args.next()),
            _ => bail!("usage: tma-installer install|repair|upgrade | uninstall [--purge] | register-extension <chrome-id> [edge-id]"),
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

        // Stop before replacement; SCM recovery settings survive an in-place upgrade.
        let manager = open_manager(SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE)?;
        if let Ok(service) = open_service(SERVICE_STOP | SERVICE_QUERY_STATUS) {
            stop_service(service.0)?;
        }
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
            .is_none_or(|v| v.len() < 32)
            || std::env::var_os("TMA_ROTATE_IPC_CREDENTIAL").is_some()
        {
            config["ipc_credential"] = serde_json::Value::String(random_credential()?);
        }
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
        register_host(&install.join("tma-relay.exe"))?;
        if unsafe { StartServiceW(service.0, 0, null()) } == 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(1056) {
                return Err(error).context("StartServiceW");
            }
        }
        wait_service_running(service.0, std::time::Duration::from_secs(30))?;
        match std::process::Command::new(install.join("tma-doctor.exe")).arg("health").output() {
            Ok(output) if output.status.success() => println!("Service running; local health: {}", String::from_utf8_lossy(&output.stdout).trim()),
            _ => println!("Service running; health pending. Enrollment/browser connection may be incomplete; run tma-doctor.exe health."),
        }
        println!("Native host {HOST_NAME} registered for Chrome and Edge. Set allowed extension IDs with register-extension.");
        Ok(())
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
                Delay: 1000,
            },
            SC_ACTION {
                Type: SC_ACTION_RESTART,
                Delay: 5000,
            },
            SC_ACTION {
                Type: SC_ACTION_RESTART,
                Delay: 30000,
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
        let origins = std::env::var("TMA_CHROME_EXTENSION_ID")
            .ok()
            .filter(|id| !id.is_empty())
            .map(|id| vec![format!("chrome-extension://{id}/")])
            .unwrap_or_default();
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
        std::env::set_var("TMA_CHROME_EXTENSION_ID", &chrome);
        register_host(&PathBuf::from(INSTALL_DIR).join("tma-relay.exe"))?;
        // Edge ID is written separately because Chrome and Edge accepted origins can differ.
        if let Some(edge) = edge {
            let manifest = PathBuf::from(DATA_DIR).join("native-host.json");
            let mut value: serde_json::Value = serde_json::from_slice(&std::fs::read(&manifest)?)?;
            value["allowed_origins"]
                .as_array_mut()
                .context("origins")?
                .push(format!("chrome-extension://{edge}/").into());
            std::fs::write(&manifest, serde_json::to_vec_pretty(&value)?)?;
            acl(&manifest, true)?;
        }
        println!("Native Messaging allowlist updated; reload browser extensions");
        Ok(())
    }

    fn uninstall(purge: bool) -> anyhow::Result<()> {
        require_admin()?;
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
        for path in [
            format!(r"Software\Google\Chrome\NativeMessagingHosts\{HOST_NAME}"),
            format!(r"Software\Microsoft\Edge\NativeMessagingHosts\{HOST_NAME}"),
        ] {
            let result = unsafe { RegDeleteTreeW(HKEY_LOCAL_MACHINE, wide(&path).as_ptr()) };
            if result != 0 && result != 2 {
                bail!("removing native host registration: {result}")
            }
        }
        for name in BINARIES {
            let path = PathBuf::from(INSTALL_DIR).join(name);
            if path.exists() && std::fs::remove_file(&path).is_err() {
                if unsafe {
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
        }
        if purge {
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
        Ok(())
    }
}

use serde::Serialize;
use std::io::{Read, Write};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ServiceState {
    Running,
    Stopped,
    Starting,
    Stopping,
    Unknown,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ServiceInfo {
    pub state: ServiceState,
    pub auto_start: bool,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct IpcStatus {
    pub pipe_exists: bool,
    pub acl_restricted: bool,
    pub credential_configured: bool,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct BrowserRegistration {
    pub chromium: bool,
    pub firefox: bool,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ParserWorkerState {
    Ready,
    Unavailable,
    Faulted,
}
#[derive(Debug, Serialize)]
pub struct Diagnostics {
    pub install_dir: String,
    pub binary_exists: bool,
    pub service: ServiceInfo,
    pub ipc: IpcStatus,
    pub parser_worker: ParserWorkerState,
    pub browsers: BrowserRegistration,
}

pub const PIPE_NAME: &str = r"\\.\pipe\ThatMyAssetsAgent";
pub const SERVICE_NAME: &str = "TMAAgent";

#[cfg(windows)]
mod windows {
    use super::*;
    use crate::config::Config;
    use anyhow::bail;
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr::{null, null_mut};
    use std::time::Duration;
    use windows_sys::Win32::Foundation::{
        CloseHandle, LocalFree, ERROR_PIPE_BUSY, GENERIC_READ, GENERIC_WRITE, HANDLE,
        INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SetNamedSecurityInfoW,
        SDDL_REVISION_1, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::DACL_SECURITY_INFORMATION;
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAG_OVERLAPPED, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
        PIPE_ACCESS_DUPLEX,
    };
    use windows_sys::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_BYTE,
        PIPE_TYPE_BYTE, PIPE_WAIT,
    };
    use windows_sys::Win32::System::Services::*;

    pub fn wide(value: impl AsRef<OsStr>) -> Vec<u16> {
        value.as_ref().encode_wide().chain(Some(0)).collect()
    }
    #[derive(Debug)]
    pub struct OwnedHandle(pub HANDLE);
    // Windows handles may be closed from the thread that owns this connection.
    unsafe impl Send for OwnedHandle {}
    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }

    pub struct Pipe {
        pub handle: OwnedHandle,
    }
    impl Pipe {
        pub fn server() -> anyhow::Result<Self> {
            let sddl = wide("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;AU)");
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
                bail!(
                    "creating pipe security descriptor: {}",
                    std::io::Error::last_os_error()
                )
            }
            let attributes = windows_sys::Win32::Security::SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<windows_sys::Win32::Security::SECURITY_ATTRIBUTES>()
                    as u32,
                lpSecurityDescriptor: descriptor,
                bInheritHandle: 0,
            };
            let handle = unsafe {
                CreateNamedPipeW(
                    wide(PIPE_NAME).as_ptr(),
                    PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                    PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                    16,
                    65536,
                    65536,
                    5000,
                    &attributes,
                )
            };
            unsafe {
                LocalFree(descriptor);
            }
            if handle == INVALID_HANDLE_VALUE {
                bail!("CreateNamedPipeW: {}", std::io::Error::last_os_error())
            }
            Ok(Self {
                handle: OwnedHandle(handle),
            })
        }
        pub fn connect(&self) -> anyhow::Result<()> {
            if unsafe { ConnectNamedPipe(self.handle.0, null_mut()) } == 0 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() != Some(535) {
                    return Err(error.into());
                }
            }
            Ok(())
        }
        pub fn disconnect(&self) {
            unsafe {
                DisconnectNamedPipe(self.handle.0);
            }
        }
        pub fn cancel_connect(&self) -> anyhow::Result<()> {
            use windows_sys::Win32::System::IO::CancelIoEx;
            if unsafe { CancelIoEx(self.handle.0, null()) } == 0 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() != Some(1168) {
                    return Err(error.into());
                }
            }
            Ok(())
        }
        pub fn client(timeout: Duration) -> anyhow::Result<Self> {
            let started = std::time::Instant::now();
            loop {
                let handle = unsafe {
                    CreateFileW(
                        wide(PIPE_NAME).as_ptr(),
                        GENERIC_READ | GENERIC_WRITE,
                        0,
                        null(),
                        OPEN_EXISTING,
                        0,
                        null_mut(),
                    )
                };
                if handle != INVALID_HANDLE_VALUE {
                    return Ok(Self {
                        handle: OwnedHandle(handle),
                    });
                }
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() != Some(ERROR_PIPE_BUSY as i32)
                    || started.elapsed() >= timeout
                {
                    return Err(error.into());
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }

    fn overlap(
        handle: HANDLE,
        write: bool,
        buffer: &mut [u8],
        timeout: Duration,
    ) -> std::io::Result<usize> {
        use windows_sys::Win32::Foundation::WAIT_OBJECT_0;
        use windows_sys::Win32::Storage::FileSystem::{ReadFile, WriteFile};
        use windows_sys::Win32::System::Threading::{CreateEventW, WaitForSingleObject};
        use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
        let event = unsafe { CreateEventW(null(), 1, 0, null()) };
        if event.is_null() {
            return Err(std::io::Error::last_os_error());
        }
        let event = OwnedHandle(event);
        let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
        overlapped.hEvent = event.0;
        let mut transferred = 0;
        let ok = unsafe {
            if write {
                WriteFile(
                    handle,
                    buffer.as_ptr(),
                    buffer.len() as u32,
                    &mut transferred,
                    &mut overlapped,
                )
            } else {
                ReadFile(
                    handle,
                    buffer.as_mut_ptr(),
                    buffer.len() as u32,
                    &mut transferred,
                    &mut overlapped,
                )
            }
        };
        if ok == 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(997) {
                return Err(error);
            }
            if unsafe {
                WaitForSingleObject(event.0, timeout.as_millis().min(u32::MAX as u128) as u32)
            } != WAIT_OBJECT_0
            {
                unsafe {
                    CancelIoEx(handle, &overlapped);
                }
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "named pipe I/O timeout",
                ));
            }
            if unsafe { GetOverlappedResult(handle, &overlapped, &mut transferred, 0) } == 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
        Ok(transferred as usize)
    }
    impl Read for Pipe {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            overlap(self.handle.0, false, buffer, Duration::from_secs(30))
        }
    }
    impl Write for Pipe {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            overlap(
                self.handle.0,
                true,
                &mut buffer.to_vec(),
                Duration::from_secs(30),
            )
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
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
        if unsafe {
            windows_sys::Win32::Security::GetSecurityDescriptorDacl(
                descriptor,
                &mut present,
                &mut dacl,
                &mut defaulted,
            )
        } == 0
            || present == 0
        {
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

    pub fn restrict_file(path: &Path) -> anyhow::Result<()> {
        // Test/development stores owned by an interactive user retain owner access.
        // Installed service stores live in ProgramData, whose root already grants LocalService.
        set_acl(path, "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;LS)(A;;GA;;;OW)")
    }

    pub fn restrict_ipc_config(path: &Path) -> anyhow::Result<()> {
        set_acl(path, "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;LS)(A;;GR;;;AU)")
    }

    struct ScHandle(SC_HANDLE);
    impl Drop for ScHandle {
        fn drop(&mut self) {
            unsafe {
                CloseServiceHandle(self.0);
            }
        }
    }
    pub fn service_info() -> ServiceInfo {
        unsafe {
            let manager = OpenSCManagerW(null(), null(), SC_MANAGER_CONNECT);
            if manager.is_null() {
                return ServiceInfo {
                    state: ServiceState::Unknown,
                    auto_start: false,
                };
            }
            let manager = ScHandle(manager);
            let service = OpenServiceW(
                manager.0,
                wide(SERVICE_NAME).as_ptr(),
                SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG,
            );
            if service.is_null() {
                return ServiceInfo {
                    state: ServiceState::Stopped,
                    auto_start: false,
                };
            }
            let service = ScHandle(service);
            let mut status = std::mem::zeroed();
            if QueryServiceStatus(service.0, &mut status) == 0 {
                return ServiceInfo {
                    state: ServiceState::Unknown,
                    auto_start: false,
                };
            }
            let mut needed = 0;
            QueryServiceConfigW(service.0, null_mut(), 0, &mut needed);
            let mut data = vec![0_u8; needed as usize];
            let auto_start =
                QueryServiceConfigW(service.0, data.as_mut_ptr() as _, needed, &mut needed) != 0
                    && (*(data.as_ptr() as *const QUERY_SERVICE_CONFIGW)).dwStartType
                        == SERVICE_AUTO_START;
            ServiceInfo {
                state: match status.dwCurrentState {
                    SERVICE_RUNNING => ServiceState::Running,
                    SERVICE_STOPPED => ServiceState::Stopped,
                    SERVICE_START_PENDING => ServiceState::Starting,
                    SERVICE_STOP_PENDING => ServiceState::Stopping,
                    _ => ServiceState::Unknown,
                },
                auto_start,
            }
        }
    }
    pub fn pipe_exists() -> bool {
        let handle = unsafe {
            CreateFileW(
                wide(PIPE_NAME).as_ptr(),
                0,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                null(),
                OPEN_EXISTING,
                0,
                null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            false
        } else {
            unsafe {
                CloseHandle(handle);
            }
            true
        }
    }
    pub fn acl_restricted() -> bool {
        // Pipe is created only with D:P SYSTEM/Administrators/AuthenticatedUsers ACL.
        pipe_exists()
    }
    pub fn browser_registration() -> BrowserRegistration {
        use windows_sys::Win32::System::Registry::{
            RegCloseKey, RegOpenKeyExW, HKEY_LOCAL_MACHINE, KEY_READ,
        };
        fn exists(path: &str) -> bool {
            let mut key = null_mut();
            let result = unsafe {
                RegOpenKeyExW(
                    HKEY_LOCAL_MACHINE,
                    wide(path).as_ptr(),
                    0,
                    KEY_READ,
                    &mut key,
                )
            };
            if result == 0 {
                unsafe {
                    RegCloseKey(key);
                }
                true
            } else {
                false
            }
        }
        BrowserRegistration {
            chromium: exists(r"Software\Google\Chrome\NativeMessagingHosts\com.thatmyassets.dlp"),
            firefox: exists(r"Software\Mozilla\NativeMessagingHosts\com.thatmyassets.dlp"),
        }
    }
    pub fn diagnostics(config: &Config) -> Diagnostics {
        let worker_ready = config.install_dir.join("tma-parser.exe").is_file();
        Diagnostics {
            install_dir: config.install_dir.display().to_string(),
            binary_exists: config.install_dir.join("tma-agent.exe").is_file(),
            service: service_info(),
            ipc: IpcStatus {
                pipe_exists: pipe_exists(),
                acl_restricted: acl_restricted(),
                credential_configured: config.ipc_credential.len() >= 32,
            },
            parser_worker: if worker_ready {
                ParserWorkerState::Ready
            } else {
                ParserWorkerState::Unavailable
            },
            browsers: browser_registration(),
        }
    }
}

#[cfg(not(windows))]
mod fallback {
    use super::*;
    use crate::config::Config;
    pub fn restrict_file(path: &Path) -> anyhow::Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }
    pub fn restrict_ipc_config(path: &Path) -> anyhow::Result<()> {
        restrict_file(path)
    }
    pub fn diagnostics(config: &Config) -> Diagnostics {
        Diagnostics {
            install_dir: config.install_dir.display().to_string(),
            binary_exists: config.install_dir.join("tma-agent.exe").is_file(),
            service: ServiceInfo {
                state: ServiceState::Unknown,
                auto_start: false,
            },
            ipc: IpcStatus {
                pipe_exists: false,
                acl_restricted: false,
                credential_configured: config.ipc_credential.len() >= 32,
            },
            parser_worker: ParserWorkerState::Unavailable,
            browsers: BrowserRegistration {
                chromium: false,
                firefox: false,
            },
        }
    }
}

#[cfg(not(windows))]
pub use fallback::*;
#[cfg(windows)]
pub use windows::*;

use std::path::Path;

#[derive(Debug)]
pub struct ParserWorker {
    #[cfg(windows)]
    handle: crate::platform::OwnedHandle,
    #[cfg(not(windows))]
    child: std::process::Child,
}

impl ParserWorker {
    /// Launch a no-inherited-handle parser in a kill-on-close, resource-limited Windows Job Object.
    #[cfg(windows)]
    pub fn launch(path: &Path) -> anyhow::Result<Self> {
        use anyhow::bail;
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
            SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_LIMIT_PROCESS_MEMORY,
        };
        use windows_sys::Win32::System::Threading::{
            CreateProcessW, ResumeThread, CREATE_SUSPENDED, PROCESS_INFORMATION, STARTUPINFOW,
        };
        let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if job.is_null() {
            bail!("CreateJobObjectW: {}", std::io::Error::last_os_error())
        }
        let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        limits.BasicLimitInformation.LimitFlags =
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_PROCESS_MEMORY;
        limits.ProcessMemoryLimit = 128 * 1024 * 1024;
        if unsafe {
            SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                &limits as *const _ as *const _,
                std::mem::size_of_val(&limits) as u32,
            )
        } == 0
        {
            unsafe {
                CloseHandle(job);
            }
            bail!(
                "SetInformationJobObject: {}",
                std::io::Error::last_os_error()
            );
        }
        let mut startup: STARTUPINFOW = unsafe { std::mem::zeroed() };
        startup.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        let mut process: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
        let mut executable = path
            .as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect::<Vec<_>>();
        if unsafe {
            CreateProcessW(
                executable.as_ptr(),
                executable.as_mut_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                0,
                CREATE_SUSPENDED,
                std::ptr::null(),
                std::ptr::null(),
                &startup,
                &mut process,
            )
        } == 0
        {
            unsafe {
                CloseHandle(job);
            }
            bail!("CreateProcessW: {}", std::io::Error::last_os_error());
        }
        if unsafe { AssignProcessToJobObject(job, process.hProcess) } == 0 {
            unsafe {
                CloseHandle(process.hThread);
                CloseHandle(process.hProcess);
                CloseHandle(job);
            }
            bail!(
                "AssignProcessToJobObject: {}",
                std::io::Error::last_os_error()
            );
        }
        unsafe {
            ResumeThread(process.hThread);
            CloseHandle(process.hThread);
            CloseHandle(job);
        }
        Ok(Self {
            handle: crate::platform::OwnedHandle(process.hProcess),
        })
    }

    #[cfg(not(windows))]
    pub fn launch(path: &Path) -> anyhow::Result<Self> {
        let child = std::process::Command::new(path)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()?;
        Ok(Self { child })
    }

    #[cfg(windows)]
    pub fn alive(&mut self) -> bool {
        unsafe {
            windows_sys::Win32::System::Threading::WaitForSingleObject(self.handle.0, 0)
                == windows_sys::Win32::Foundation::WAIT_TIMEOUT
        }
    }

    #[cfg(not(windows))]
    pub fn alive(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    #[cfg(windows)]
    fn stop(&mut self) {
        unsafe {
            windows_sys::Win32::System::Threading::TerminateProcess(self.handle.0, 1);
            windows_sys::Win32::System::Threading::WaitForSingleObject(self.handle.0, 5000);
        }
    }

    #[cfg(not(windows))]
    fn stop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for ParserWorker {
    fn drop(&mut self) {
        self.stop();
    }
}

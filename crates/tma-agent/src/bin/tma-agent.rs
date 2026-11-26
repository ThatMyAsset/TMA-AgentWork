use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

static STOP: AtomicBool = AtomicBool::new(false);

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|arg| arg == "--console") {
        if let Err(error) = run_server() {
            let _ = writeln!(std::io::stderr(), "tma-agent: {error}");
            std::process::exit(1);
        }
        return;
    }
    #[cfg(windows)]
    if let Err(error) = windows_service::run() {
        let _ = writeln!(std::io::stderr(), "tma-agent SCM: {error}");
        std::process::exit(1);
    }
    #[cfg(not(windows))]
    {
        let _ = writeln!(
            std::io::stderr(),
            "Use --console for non-SCM diagnostics; production service is Windows-only"
        );
        std::process::exit(1);
    }
}

fn agent() -> anyhow::Result<Arc<tma_agent::service::Agent>> {
    let data = tma_agent::default_data_dir();
    let config = tma_agent::config::Config::load(&data.join("config.json"))?;
    Ok(Arc::new(tma_agent::service::Agent::open(
        config,
        &data.join("events.db"),
    )?))
}

fn serve_connection(
    agent: &tma_agent::service::Agent,
    stream: &mut (impl std::io::Read + std::io::Write),
) -> anyhow::Result<()> {
    let credential = agent.config.read().unwrap().ipc_credential.clone();
    while let Some(request) = tma_agent::protocol::receive_authenticated(stream, &credential)? {
        tma_agent::protocol::send(stream, &agent.handle(request))?;
    }
    Ok(())
}

#[cfg(windows)]
fn run_server() -> anyhow::Result<()> {
    let agent = agent()?;
    let sync = Arc::clone(&agent);
    let stopping = Arc::new(AtomicBool::new(false));
    let sync_stopping = Arc::clone(&stopping);
    let sync_thread = std::thread::spawn(move || sync.run_sync_loop(sync_stopping));
    windows_service::set_running();
    while !STOP.load(Ordering::Relaxed) {
        let pipe = tma_agent::platform::Pipe::server()?;
        pipe.connect()?;
        if STOP.load(Ordering::Relaxed) {
            break;
        }
        let agent = Arc::clone(&agent);
        std::thread::spawn(move || {
            let mut stream = pipe;
            let _ = serve_connection(&agent, &mut stream);
            stream.disconnect();
        });
    }
    stopping.store(true, Ordering::Relaxed);
    let _ = sync_thread.join();
    Ok(())
}

#[cfg(not(windows))]
fn run_server() -> anyhow::Result<()> {
    let agent = agent()?;
    agent.sync_once();
    let response = agent.handle(tma_agent::model::Request::Health {
        request_id: uuid::Uuid::new_v4(),
    });
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

#[cfg(windows)]
mod windows_service {
    use super::*;
    use windows_sys::Win32::Foundation::{
        ERROR_CALL_NOT_IMPLEMENTED, ERROR_SERVICE_SPECIFIC_ERROR,
    };
    use windows_sys::Win32::System::Services::*;
    static mut STATUS_HANDLE: SERVICE_STATUS_HANDLE = std::ptr::null_mut();

    fn set_status(state: u32, exit_code: u32) {
        let status = SERVICE_STATUS {
            dwServiceType: SERVICE_WIN32_OWN_PROCESS,
            dwCurrentState: state,
            dwControlsAccepted: if state == SERVICE_RUNNING {
                SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
            } else {
                0
            },
            dwWin32ExitCode: exit_code,
            dwServiceSpecificExitCode: 0,
            dwCheckPoint: 0,
            dwWaitHint: if state == SERVICE_RUNNING { 0 } else { 10000 },
        };
        unsafe {
            SetServiceStatus(STATUS_HANDLE, &status);
        }
    }

    pub fn set_running() {
        set_status(SERVICE_RUNNING, 0);
    }

    unsafe extern "system" fn control_handler(
        control: u32,
        _event: u32,
        _data: *mut core::ffi::c_void,
        _context: *mut core::ffi::c_void,
    ) -> u32 {
        match control {
            SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
                STOP.store(true, Ordering::Relaxed);
                let _ = tma_agent::platform::Pipe::client(std::time::Duration::from_millis(100));
                set_status(SERVICE_STOP_PENDING, 0);
                0
            }
            SERVICE_CONTROL_INTERROGATE => 0,
            _ => ERROR_CALL_NOT_IMPLEMENTED,
        }
    }

    unsafe extern "system" fn service_main(_argc: u32, _argv: *mut *mut u16) {
        STATUS_HANDLE = RegisterServiceCtrlHandlerExW(
            tma_agent::platform::wide(tma_agent::platform::SERVICE_NAME).as_ptr(),
            Some(control_handler),
            std::ptr::null_mut(),
        );
        if STATUS_HANDLE.is_null() {
            return;
        }
        set_status(SERVICE_START_PENDING, 0);
        match run_server() {
            Ok(()) => set_status(SERVICE_STOPPED, 0),
            Err(_) => set_status(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR),
        }
    }

    pub fn run() -> anyhow::Result<()> {
        let name = tma_agent::platform::wide(tma_agent::platform::SERVICE_NAME);
        let table = [
            SERVICE_TABLE_ENTRYW {
                lpServiceName: name.as_ptr() as *mut u16,
                lpServiceProc: Some(service_main),
            },
            SERVICE_TABLE_ENTRYW {
                lpServiceName: std::ptr::null_mut(),
                lpServiceProc: None,
            },
        ];
        if unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) } == 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(())
    }
}

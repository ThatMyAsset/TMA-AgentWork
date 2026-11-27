use super::{development_mode, health_report, wide, INSTALL_DIR};
use crate::validation::{self, Configuration, Operation};
use std::ffi::c_void;
use std::path::Path;
use std::ptr::{null, null_mut};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_CANCELLED, HWND, LPARAM, LRESULT, RECT, WPARAM,
};
use windows_sys::Win32::Graphics::Gdi::*;
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::SystemServices::SS_LEFTNOWORDWRAP;
use windows_sys::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject, INFINITE};
use windows_sys::Win32::UI::Controls::{
    InitCommonControlsEx, BST_CHECKED, ICC_PROGRESS_CLASS, INITCOMMONCONTROLSEX, PBM_SETPOS,
    PBS_SMOOTH,
};
use windows_sys::Win32::UI::HiDpi::{
    AdjustWindowRectExForDpi, GetDpiForSystem, GetDpiForWindow, SetProcessDpiAwarenessContext,
    DPI_AWARENESS_CONTEXT_SYSTEM_AWARE,
};
use windows_sys::Win32::UI::Input::KeyboardAndMouse::EnableWindow;
use windows_sys::Win32::UI::Shell::{
    IsUserAnAdmin, ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::*;

const CLASS: &str = "ThatMyAssets.Agent.Setup";
const TITLE: &str = "ThatMyAssets Agent setup";
const ID_INSTALL: usize = 101;
const ID_REPAIR: usize = 102;
const ID_UNINSTALL: usize = 103;
const ID_URL: usize = 110;
const ID_CODE: usize = 111;
const ID_CHROME: usize = 112;
const ID_EDGE: usize = 113;
const ID_PURGE: usize = 120;
const ID_DEVELOPMENT: usize = 126;
const ID_START: usize = 121;
const ID_CLOSE: usize = 122;
const ID_HEALTH: usize = 123;
const ID_PROGRESS: usize = 124;
const ID_STATUS: usize = 125;
const WM_COMPLETE: u32 = WM_APP + 1;
const BACKGROUND: u32 = 0x00f8_f6f3;
const SURFACE: u32 = 0x00ff_ffff;
const BORDER: u32 = 0x00e4_deda;
const HEADER: u32 = 0x0034_231b;
const INK: u32 = 0x002b_201b;
const MUTED: u32 = 0x006b_625c;

#[derive(Clone)]
enum Field {
    Action(usize),
    Edit(usize),
    Button(usize),
    Purge,
    Development,
    Progress,
    Label,
    Status,
}

struct Window {
    hwnd: HWND,
    fields: Vec<(Field, HWND)>,
    font: HFONT,
    label_font: HFONT,
    title_font: HFONT,
    background: HBRUSH,
    surface: HBRUSH,
    dpi: u32,
    busy: bool,
    events: Arc<Mutex<Receiver<Event>>>,
}

enum Event {
    Progress(u32, String),
    Finished(String, String),
}

pub fn run() -> anyhow::Result<()> {
    unsafe {
        let controls = INITCOMMONCONTROLSEX {
            dwSize: size_of::<INITCOMMONCONTROLSEX>() as u32,
            dwICC: ICC_PROGRESS_CLASS,
        };
        InitCommonControlsEx(&controls);
        SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_SYSTEM_AWARE);
    }
    let dpi = unsafe { GetDpiForSystem().max(96) };
    let scale = |value: i32| value * dpi as i32 / 96;
    let instance = unsafe { GetModuleHandleW(null()) };
    let class = wide(CLASS);
    let background = unsafe { CreateSolidBrush(BACKGROUND) };
    let icon = unsafe { LoadIconW(null_mut(), IDI_APPLICATION) };
    let window_class = WNDCLASSEXW {
        cbSize: size_of::<WNDCLASSEXW>() as u32,
        style: CS_HREDRAW | CS_VREDRAW,
        lpfnWndProc: Some(window_proc),
        cbClsExtra: 0,
        cbWndExtra: 0,
        hInstance: instance,
        hIcon: icon,
        hCursor: unsafe { LoadCursorW(null_mut(), IDC_ARROW) },
        hbrBackground: background,
        lpszMenuName: null(),
        lpszClassName: class.as_ptr(),
        hIconSm: icon,
    };
    if unsafe { RegisterClassExW(&window_class) } == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let style = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX;
    let mut bounds = RECT {
        left: 0,
        top: 0,
        right: scale(840),
        bottom: scale(680),
    };
    unsafe {
        AdjustWindowRectExForDpi(&mut bounds, style, 0, 0, dpi);
    }
    let work_area = {
        let mut area: RECT = unsafe { std::mem::zeroed() };
        unsafe {
            SystemParametersInfoW(SPI_GETWORKAREA, 0, &mut area as *mut RECT as *mut c_void, 0);
        }
        area
    };
    let screen_width = work_area.right - work_area.left;
    let screen_height = work_area.bottom - work_area.top;
    let width = (bounds.right - bounds.left).min(screen_width);
    let height = (bounds.bottom - bounds.top).min(screen_height);
    let x = work_area.left + (screen_width - width) / 2;
    let y = work_area.top + ((screen_height - height) / 2).max(0);
    let hwnd = unsafe {
        CreateWindowExW(
            0,
            class.as_ptr(),
            wide(TITLE).as_ptr(),
            style,
            x,
            y,
            width,
            height,
            null_mut(),
            null_mut(),
            instance,
            null(),
        )
    };
    if hwnd.is_null() {
        return Err(std::io::Error::last_os_error().into());
    }
    unsafe {
        ShowWindow(hwnd, SW_SHOW);
        UpdateWindow(hwnd);
        let mut message: MSG = std::mem::zeroed();
        while GetMessageW(&mut message, null_mut(), 0, 0) > 0 {
            if IsDialogMessageW(hwnd, &message) == 0 {
                TranslateMessage(&message);
                DispatchMessageW(&message);
            }
        }
        DeleteObject(background);
    }
    Ok(())
}

impl Window {
    fn scale(&self, value: i32) -> i32 {
        value * self.dpi as i32 / 96
    }

    fn field(&self, id: usize) -> HWND {
        self.fields
            .iter()
            .find_map(|(field, hwnd)| match field {
                Field::Action(value) | Field::Edit(value) | Field::Button(value)
                    if *value == id =>
                {
                    Some(*hwnd)
                }
                Field::Purge if id == ID_PURGE => Some(*hwnd),
                Field::Development if id == ID_DEVELOPMENT => Some(*hwnd),
                Field::Progress if id == ID_PROGRESS => Some(*hwnd),
                Field::Status if id == ID_STATUS => Some(*hwnd),
                _ => None,
            })
            .unwrap_or(null_mut())
    }

    fn text(&self, id: usize) -> String {
        let hwnd = self.field(id);
        let length = unsafe { GetWindowTextLengthW(hwnd) };
        let mut buffer = vec![0_u16; length as usize + 1];
        unsafe {
            GetWindowTextW(hwnd, buffer.as_mut_ptr(), buffer.len() as i32);
        }
        String::from_utf16_lossy(&buffer[..length as usize])
    }

    fn set_text(&self, id: usize, value: &str) {
        unsafe {
            SetWindowTextW(self.field(id), wide(value).as_ptr());
        }
    }

    fn operation(&self) -> Operation {
        if unsafe { SendMessageW(self.field(ID_REPAIR), BM_GETCHECK, 0, 0) } == BST_CHECKED as isize
        {
            Operation::Repair
        } else if unsafe { SendMessageW(self.field(ID_UNINSTALL), BM_GETCHECK, 0, 0) }
            == BST_CHECKED as isize
        {
            Operation::Uninstall { purge: false }
        } else {
            Operation::Install
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn control(
        &mut self,
        class: &str,
        text: &str,
        style: u32,
        ex_style: u32,
        x: i32,
        y: i32,
        width: i32,
        height: i32,
        field: Field,
    ) -> anyhow::Result<HWND> {
        let id = match field {
            Field::Action(id) | Field::Edit(id) | Field::Button(id) => id,
            Field::Progress => ID_PROGRESS,
            Field::Status => ID_STATUS,
            Field::Purge => ID_PURGE,
            Field::Development => ID_DEVELOPMENT,
            Field::Label => 0,
        };
        let hwnd = unsafe {
            CreateWindowExW(
                ex_style,
                wide(class).as_ptr(),
                wide(text).as_ptr(),
                WS_CHILD | WS_VISIBLE | style,
                self.scale(x),
                self.scale(y),
                self.scale(width),
                self.scale(height),
                self.hwnd,
                id as *mut c_void,
                null_mut(),
                null(),
            )
        };
        if hwnd.is_null() {
            return Err(std::io::Error::last_os_error().into());
        }
        unsafe {
            SendMessageW(hwnd, WM_SETFONT, self.font as usize, 1);
        }
        self.fields.push((field, hwnd));
        Ok(hwnd)
    }

    fn initialize(&mut self) -> anyhow::Result<()> {
        self.control(
            "STATIC",
            "01  Choose an action",
            0,
            0,
            32,
            112,
            400,
            20,
            Field::Label,
        )?;
        for (id, label, x) in [
            (ID_INSTALL, "Install agent", 32),
            (ID_REPAIR, "Repair / upgrade", 284),
            (ID_UNINSTALL, "Uninstall", 536),
        ] {
            self.control(
                "BUTTON",
                label,
                BS_AUTORADIOBUTTON as u32
                    | WS_TABSTOP
                    | if id == ID_INSTALL { WS_GROUP } else { 0 },
                0,
                x,
                139,
                232,
                30,
                Field::Action(id),
            )?;
        }
        unsafe {
            SendMessageW(self.field(ID_INSTALL), BM_SETCHECK, BST_CHECKED as usize, 0);
        }

        self.control(
            "STATIC",
            "02  Connect your endpoint",
            0,
            0,
            32,
            190,
            400,
            20,
            Field::Label,
        )?;
        let url_label = self.control(
            "STATIC",
            "Control-plane URL",
            0,
            0,
            32,
            220,
            376,
            18,
            Field::Label,
        )?;
        unsafe {
            SendMessageW(url_label, WM_SETFONT, self.label_font as usize, 1);
        }
        self.control(
            "EDIT",
            "",
            ES_AUTOHSCROLL as u32 | WS_TABSTOP | WS_GROUP,
            WS_EX_CLIENTEDGE,
            32,
            242,
            776,
            30,
            Field::Edit(ID_URL),
        )?;
        let code_label = self.control(
            "STATIC",
            "One-time pairing code",
            0,
            0,
            32,
            283,
            376,
            18,
            Field::Label,
        )?;
        unsafe {
            SendMessageW(code_label, WM_SETFONT, self.label_font as usize, 1);
        }
        self.control(
            "EDIT",
            "",
            (ES_AUTOHSCROLL | ES_PASSWORD) as u32 | WS_TABSTOP,
            WS_EX_CLIENTEDGE,
            32,
            305,
            776,
            30,
            Field::Edit(ID_CODE),
        )?;
        for (id, label, x) in [
            (ID_CHROME, "Chrome extension ID", 32),
            (ID_EDGE, "Edge extension ID (optional)", 420),
        ] {
            let label_hwnd = self.control("STATIC", label, 0, 0, x, 346, 376, 18, Field::Label)?;
            unsafe {
                SendMessageW(label_hwnd, WM_SETFONT, self.label_font as usize, 1);
            }
            self.control(
                "EDIT",
                "",
                ES_AUTOHSCROLL as u32 | WS_TABSTOP,
                WS_EX_CLIENTEDGE,
                x,
                368,
                388,
                30,
                Field::Edit(id),
            )?;
        }
        self.control(
            "BUTTON",
            "Development mode — allow direct HTTP to a lab Control Plane",
            BS_AUTOCHECKBOX as u32 | WS_TABSTOP | WS_GROUP,
            0,
            32,
            410,
            776,
            26,
            Field::Development,
        )?;
        if development_mode() {
            unsafe {
                SendMessageW(
                    self.field(ID_DEVELOPMENT),
                    BM_SETCHECK,
                    BST_CHECKED as usize,
                    0,
                );
            }
        }
        self.control(
            "BUTTON",
            "Also permanently erase local events, enrollment and policy (purge)",
            BS_AUTOCHECKBOX as u32 | WS_TABSTOP,
            0,
            32,
            440,
            776,
            26,
            Field::Purge,
        )?;

        self.control(
            "STATIC",
            "03  Setup and health",
            0,
            0,
            32,
            480,
            400,
            20,
            Field::Label,
        )?;
        self.control(
            "STATIC",
            "",
            SS_LEFTNOWORDWRAP,
            0,
            32,
            509,
            776,
            44,
            Field::Status,
        )?;
        self.control(
            "msctls_progress32",
            "",
            PBS_SMOOTH,
            0,
            32,
            562,
            776,
            8,
            Field::Progress,
        )?;

        self.control(
            "BUTTON",
            "Recheck health",
            WS_TABSTOP | WS_GROUP,
            0,
            456,
            592,
            144,
            36,
            Field::Button(ID_HEALTH),
        )?;
        self.control(
            "BUTTON",
            "Close",
            WS_TABSTOP,
            0,
            612,
            592,
            84,
            36,
            Field::Button(ID_CLOSE),
        )?;
        self.control(
            "BUTTON",
            "Install agent",
            BS_DEFPUSHBUTTON as u32 | WS_TABSTOP,
            0,
            682,
            592,
            126,
            36,
            Field::Button(ID_START),
        )?;

        for (id, variable) in [
            (ID_URL, "TMA_CONTROL_PLANE_URL"),
            (ID_CODE, "TMA_PAIRING_CODE"),
            (ID_CHROME, "TMA_CHROME_EXTENSION_ID"),
            (ID_EDGE, "TMA_EDGE_EXTENSION_ID"),
        ] {
            if let Ok(value) = std::env::var(variable) {
                self.set_text(id, &value);
            }
        }
        let action = if Path::new(INSTALL_DIR).join("tma-agent.exe").is_file() {
            ID_REPAIR
        } else {
            ID_INSTALL
        };
        unsafe {
            SendMessageW(self.field(action), BM_SETCHECK, BST_CHECKED as usize, 0);
        }
        self.update_mode();
        Ok(())
    }

    fn update_mode(&mut self) {
        let operation = self.operation();
        let configuration = operation.needs_configuration();
        for id in [ID_URL, ID_CODE, ID_CHROME, ID_EDGE] {
            unsafe {
                EnableWindow(self.field(id), (configuration && !self.busy).into());
            }
        }
        for id in [
            ID_INSTALL,
            ID_REPAIR,
            ID_UNINSTALL,
            ID_START,
            ID_HEALTH,
            ID_PURGE,
            ID_DEVELOPMENT,
        ] {
            unsafe {
                EnableWindow(self.field(id), (!self.busy).into());
            }
        }
        unsafe {
            ShowWindow(
                self.field(ID_PURGE),
                if configuration { SW_HIDE } else { SW_SHOW },
            );
            ShowWindow(
                self.field(ID_DEVELOPMENT),
                if configuration { SW_SHOW } else { SW_HIDE },
            );
        }
        self.set_text(
            ID_START,
            if self.busy {
                "Working…"
            } else {
                operation.verb()
            },
        );
        if !self.busy {
            self.set_text(ID_STATUS, match operation {
                Operation::Install => "Installs the service and browser relay. Protection begins only after verified enrollment and health.",
                Operation::Repair => "Preserves enrollment, queued events and IPC credential. Blank fields keep existing configuration.",
                Operation::Uninstall { .. } => "Removes service and binaries. Local events and enrollment remain unless purge is selected.",
            });
        }
    }

    fn start(&mut self) {
        let operation = self.operation();
        let purge = unsafe { SendMessageW(self.field(ID_PURGE), BM_GETCHECK, 0, 0) }
            == BST_CHECKED as isize;
        let operation = if matches!(operation, Operation::Uninstall { .. }) {
            Operation::Uninstall { purge }
        } else {
            operation
        };
        let development = unsafe { SendMessageW(self.field(ID_DEVELOPMENT), BM_GETCHECK, 0, 0) }
            == BST_CHECKED as isize;
        let configuration = if operation.needs_configuration() {
            let (url, code, chrome, edge) = (
                self.text(ID_URL),
                self.text(ID_CODE),
                self.text(ID_CHROME),
                self.text(ID_EDGE),
            );
            let result = if matches!(operation, Operation::Repair) {
                validation::validate_repair_configuration(&url, &code, &chrome, &edge, development)
            } else {
                validation::validate_configuration(&url, &code, &chrome, &edge, development)
            };
            match result {
                Ok(configuration) => Some(configuration),
                Err(error) => {
                    self.error(&error);
                    return;
                }
            }
        } else {
            None
        };
        let warning = if purge {
            "PERMANENT DATA DELETION\n\nPurge permanently erases queued events, device enrollment, pairing data and local policy. This cannot be undone.\n\nContinue with purge uninstall?"
        } else {
            "Administrator approval may be requested. Continue?"
        };
        let flags = MB_YESNO
            | if purge {
                MB_ICONWARNING | MB_DEFBUTTON2
            } else {
                MB_ICONQUESTION
            };
        if unsafe {
            MessageBoxW(
                self.hwnd,
                wide(warning).as_ptr(),
                wide(TITLE).as_ptr(),
                flags,
            )
        } != IDYES
        {
            return;
        }
        match self.launch(operation, configuration.as_ref()) {
            Ok(receiver) => {
                self.events = Arc::new(Mutex::new(receiver));
                self.busy = true;
                self.set_text(
                    ID_STATUS,
                    "Waiting for administrator approval and setup progress…",
                );
                unsafe {
                    SendMessageW(self.field(ID_PROGRESS), PBM_SETPOS, 0, 0);
                }
                self.update_mode();
            }
            Err(error) => self.error(&format!("Could not start elevated setup.\n\n{error}")),
        }
    }

    fn launch(
        &mut self,
        operation: Operation,
        configuration: Option<&Configuration>,
    ) -> anyhow::Result<Receiver<Event>> {
        let report = std::env::temp_dir().join(format!("tma-setup-{}.log", std::process::id()));
        std::fs::write(&report, [])?;
        if let Some(configuration) = configuration {
            for (variable, value) in [
                ("TMA_CONTROL_PLANE_URL", &configuration.control_plane_url),
                ("TMA_PAIRING_CODE", &configuration.pairing_code),
                (
                    "TMA_CHROME_EXTENSION_ID",
                    &configuration.chrome_extension_id,
                ),
            ] {
                if !value.is_empty() {
                    std::env::set_var(variable, value);
                }
            }
            if let Some(edge) = &configuration.edge_extension_id {
                std::env::set_var("TMA_EDGE_EXTENSION_ID", edge);
            }
        }
        let mut parameters = format!("--worker {} \"{}\"", operation.argument(), report.display());
        if matches!(operation, Operation::Uninstall { purge: true }) {
            parameters.push_str(" --purge");
        }
        if let Some(configuration) = configuration {
            parameters.push_str(if configuration.development {
                " --development"
            } else {
                " --production"
            });
        }
        let executable = std::env::current_exe()?;
        let executable_wide = wide(executable.as_os_str());
        let parameters_wide = wide(parameters);
        let verb = if unsafe { IsUserAnAdmin() } != 0 {
            Vec::new()
        } else {
            wide("runas")
        };
        let mut info = SHELLEXECUTEINFOW {
            cbSize: size_of::<SHELLEXECUTEINFOW>() as u32,
            fMask: SEE_MASK_NOCLOSEPROCESS,
            hwnd: self.hwnd,
            lpVerb: if verb.is_empty() {
                null()
            } else {
                verb.as_ptr()
            },
            lpFile: executable_wide.as_ptr(),
            lpParameters: parameters_wide.as_ptr(),
            lpDirectory: null(),
            nShow: SW_HIDE,
            ..unsafe { std::mem::zeroed() }
        };
        let launched = unsafe { ShellExecuteExW(&mut info) } != 0;
        let error = if launched {
            0
        } else {
            unsafe { GetLastError() }
        };
        for variable in [
            "TMA_CONTROL_PLANE_URL",
            "TMA_PAIRING_CODE",
            "TMA_CHROME_EXTENSION_ID",
            "TMA_EDGE_EXTENSION_ID",
        ] {
            std::env::remove_var(variable);
        }
        if !launched {
            if error == ERROR_CANCELLED {
                anyhow::bail!("Administrator approval was cancelled; no changes were made");
            }
            return Err(std::io::Error::from_raw_os_error(error as i32).into());
        }
        let (sender, receiver) = mpsc::channel();
        let hwnd = self.hwnd as usize;
        let process = info.hProcess as usize;
        std::thread::spawn(move || {
            let process = process as *mut c_void;
            let send = |event| {
                let _ = sender.send(event);
                unsafe {
                    PostMessageW(hwnd as HWND, WM_COMPLETE, 0, 0);
                }
            };
            if unsafe { WaitForSingleObject(process, INFINITE) } != 0 {
                send(Event::Finished(
                    "error".into(),
                    "Could not wait for elevated setup process".into(),
                ));
                unsafe {
                    CloseHandle(process);
                }
                return;
            }
            let mut exit_code = 1;
            unsafe {
                GetExitCodeProcess(process, &mut exit_code);
                CloseHandle(process);
            }
            let mut result = None;
            match std::fs::read_to_string(&report) {
                Ok(log) => {
                    for line in log.lines() {
                        let parts: Vec<_> = line.splitn(3, '|').collect();
                        if parts.len() != 3 {
                            continue;
                        }
                        match parts[0] {
                            "progress" => send(Event::Progress(
                                parts[1].parse().unwrap_or(0),
                                parts[2].to_owned(),
                            )),
                            "result" => result = Some((parts[1].to_owned(), parts[2].to_owned())),
                            _ => {}
                        }
                    }
                }
                Err(error) if exit_code == 0 => {
                    result = Some((
                        "error".into(),
                        format!("Setup progress report could not be read: {error}"),
                    ))
                }
                Err(_) => {}
            }
            let _ = std::fs::remove_file(report);
            if let Some((status, detail)) = result {
                send(Event::Finished(status, detail));
            } else {
                send(Event::Finished(
                    "error".into(),
                    if exit_code == 0 {
                        "Setup finished without a verifiable result. Run tma-doctor status before retrying.".into()
                    } else {
                        "Elevated setup stopped before reporting a result. Review service permissions and try again.".into()
                    },
                ));
            }
        });
        Ok(receiver)
    }

    fn health(&mut self) {
        let (sender, receiver) = mpsc::channel();
        self.events = Arc::new(Mutex::new(receiver));
        self.busy = true;
        self.update_mode();
        self.set_text(
            ID_STATUS,
            "Querying installed service through authenticated local IPC…",
        );
        let hwnd = self.hwnd as usize;
        std::thread::spawn(move || {
            let (status, detail) = health_report(Path::new(INSTALL_DIR));
            let _ = sender.send(Event::Finished(status, detail));
            unsafe {
                PostMessageW(hwnd as HWND, WM_COMPLETE, 0, 0);
            }
        });
    }

    fn drain_events(&mut self) {
        loop {
            let event = self
                .events
                .lock()
                .ok()
                .and_then(|receiver| receiver.try_recv().ok());
            match event {
                Some(Event::Progress(percent, detail)) => {
                    self.set_text(ID_STATUS, &detail);
                    unsafe {
                        SendMessageW(self.field(ID_PROGRESS), PBM_SETPOS, percent as usize, 0);
                    }
                }
                Some(Event::Finished(status, detail)) => {
                    self.busy = false;
                    unsafe {
                        SendMessageW(
                            self.field(ID_PROGRESS),
                            PBM_SETPOS,
                            if matches!(status.as_str(), "error" | "unavailable") {
                                0
                            } else {
                                100
                            },
                            0,
                        );
                    }
                    self.update_mode();
                    self.set_text(ID_STATUS, &detail);
                    if status == "error" {
                        self.error(&detail);
                    }
                    break;
                }
                None => break,
            }
        }
    }

    fn error(&self, detail: &str) {
        unsafe {
            MessageBoxW(
                self.hwnd,
                wide(detail).as_ptr(),
                wide(TITLE).as_ptr(),
                MB_OK | MB_ICONERROR,
            );
        }
    }

    fn paint(&self) {
        let mut paint: PAINTSTRUCT = unsafe { std::mem::zeroed() };
        let dc = unsafe { BeginPaint(self.hwnd, &mut paint) };
        let mut client: RECT = unsafe { std::mem::zeroed() };
        unsafe {
            GetClientRect(self.hwnd, &mut client);
            FillRect(dc, &client, self.background);
            let header = RECT {
                left: 0,
                top: 0,
                right: client.right,
                bottom: self.scale(90),
            };
            let brush = CreateSolidBrush(HEADER);
            FillRect(dc, &header, brush);
            DeleteObject(brush);
            for (top, bottom) in [(99, 180), (179, 446), (444, 554)] {
                let card = RECT {
                    left: self.scale(24),
                    top: self.scale(top),
                    right: self.scale(816),
                    bottom: self.scale(bottom),
                };
                FillRect(dc, &card, self.surface);
                let border = CreateSolidBrush(BORDER);
                FrameRect(dc, &card, border);
                DeleteObject(border);
            }
            SetBkMode(dc, TRANSPARENT as i32);
            SetTextColor(dc, 0x00ff_ffff);
            SelectObject(dc, self.title_font);
            let mut title = RECT {
                left: self.scale(32),
                top: self.scale(17),
                right: self.scale(800),
                bottom: self.scale(47),
            };
            DrawTextW(
                dc,
                wide("ThatMyAssets Agent").as_ptr(),
                -1,
                &mut title,
                DT_LEFT | DT_SINGLELINE | DT_VCENTER,
            );
            SelectObject(dc, self.font);
            SetTextColor(dc, 0x00e5_d8c9);
            let mut subtitle = RECT {
                left: self.scale(32),
                top: self.scale(51),
                right: self.scale(808),
                bottom: self.scale(75),
            };
            DrawTextW(
                dc,
                wide("Set up Windows endpoint protection and browser connections").as_ptr(),
                -1,
                &mut subtitle,
                DT_LEFT | DT_SINGLELINE,
            );
            EndPaint(self.hwnd, &paint);
        }
    }
}

fn make_font(dpi: u32, points: i32, weight: i32) -> HFONT {
    unsafe {
        CreateFontW(
            -(dpi as i32 * points / 96),
            0,
            0,
            0,
            weight,
            0,
            0,
            0,
            DEFAULT_CHARSET as u32,
            OUT_DEFAULT_PRECIS as u32,
            CLIP_DEFAULT_PRECIS as u32,
            CLEARTYPE_QUALITY as u32,
            DEFAULT_PITCH as u32,
            wide("Segoe UI").as_ptr(),
        )
    }
}

unsafe extern "system" fn window_proc(
    hwnd: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    if message == WM_NCCREATE {
        let dpi = GetDpiForWindow(hwnd).max(96);
        let (_sender, receiver) = mpsc::channel();
        let state = Box::new(Window {
            hwnd,
            fields: Vec::new(),
            font: make_font(dpi, 16, FW_NORMAL as i32),
            label_font: make_font(dpi, 16, FW_SEMIBOLD as i32),
            title_font: make_font(dpi, 24, FW_SEMIBOLD as i32),
            background: CreateSolidBrush(BACKGROUND),
            surface: CreateSolidBrush(SURFACE),
            dpi,
            busy: false,
            events: Arc::new(Mutex::new(receiver)),
        });
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, Box::into_raw(state) as isize);
    }
    let pointer = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut Window;
    if pointer.is_null() {
        return DefWindowProcW(hwnd, message, wparam, lparam);
    }
    let state = &mut *pointer;
    match message {
        WM_CREATE => {
            if let Err(error) = state.initialize() {
                state.error(&format!("Could not create setup controls: {error}"));
                return -1;
            }
            0
        }
        WM_COMMAND => {
            match wparam & 0xffff {
                ID_INSTALL | ID_REPAIR | ID_UNINSTALL => state.update_mode(),
                ID_START => state.start(),
                ID_HEALTH => state.health(),
                ID_CLOSE if !state.busy => {
                    DestroyWindow(hwnd);
                }
                _ => {}
            }
            0
        }
        WM_COMPLETE => {
            state.drain_events();
            0
        }
        WM_CTLCOLORSTATIC => {
            SetBkMode(wparam as HDC, TRANSPARENT as i32);
            SetTextColor(
                wparam as HDC,
                if lparam as HWND == state.field(ID_STATUS) {
                    MUTED
                } else {
                    INK
                },
            );
            state.surface as LRESULT
        }
        WM_CTLCOLOREDIT | WM_CTLCOLORBTN => {
            SetBkColor(wparam as HDC, SURFACE);
            SetTextColor(wparam as HDC, INK);
            state.surface as LRESULT
        }
        WM_ERASEBKGND => 1,
        WM_PAINT => {
            state.paint();
            0
        }
        WM_CLOSE => {
            if state.busy {
                MessageBoxW(
                    hwnd,
                    wide("Setup is still running. Wait for completion before closing.").as_ptr(),
                    wide(TITLE).as_ptr(),
                    MB_OK | MB_ICONINFORMATION,
                );
            } else {
                DestroyWindow(hwnd);
            }
            0
        }
        WM_DESTROY => {
            DeleteObject(state.font);
            DeleteObject(state.label_font);
            DeleteObject(state.title_font);
            DeleteObject(state.background);
            DeleteObject(state.surface);
            PostQuitMessage(0);
            0
        }
        WM_NCDESTROY => {
            drop(Box::from_raw(pointer));
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
            DefWindowProcW(hwnd, message, wparam, lparam)
        }
        _ => DefWindowProcW(hwnd, message, wparam, lparam),
    }
}

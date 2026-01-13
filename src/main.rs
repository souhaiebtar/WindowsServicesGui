#![windows_subsystem = "windows"]

use std::ffi::OsStr;
use std::iter::once;
use std::os::windows::ffi::OsStrExt;

use eframe::{egui, App};
use fuzzy_matcher::skim::SkimMatcherV2;
use fuzzy_matcher::FuzzyMatcher;
use windows::core::{HRESULT, PCWSTR, PWSTR};
use windows::Win32::Foundation::{ERROR_MORE_DATA, HANDLE};
use windows::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY, SC_HANDLE};
use windows::Win32::System::Services::*;
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::Win32::UI::Shell::ShellExecuteW;
use windows::Win32::UI::WindowsAndMessaging::SW_SHOW;

#[derive(Clone, Debug)]
struct ServiceInfo {
    name: String,
    display_name: String,
    status: String,
    start_type: String,
    process_id: u32,
}

fn wide_null(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(once(0)).collect()
}

fn pwstr_to_string(ptr: PWSTR) -> String {
    if ptr.is_null() {
        return String::new();
    }
    unsafe {
        let mut len = 0usize;
        while *ptr.0.add(len) != 0 {
            len += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(ptr.0, len))
    }
}

fn state_to_string(state: SERVICE_STATUS_CURRENT_STATE) -> &'static str {
    match state {
        SERVICE_CONTINUE_PENDING => "Continue pending",
        SERVICE_PAUSE_PENDING => "Pause pending",
        SERVICE_PAUSED => "Paused",
        SERVICE_RUNNING => "Running",
        SERVICE_START_PENDING => "Start pending",
        SERVICE_STOP_PENDING => "Stop pending",
        SERVICE_STOPPED => "Stopped",
        _ => "Unknown",
    }
}

fn start_type_to_string(kind: SERVICE_START_TYPE) -> &'static str {
    match kind {
        SERVICE_BOOT_START => "Boot",
        SERVICE_SYSTEM_START => "System",
        SERVICE_AUTO_START => "Automatic",
        SERVICE_DEMAND_START => "Manual",
        SERVICE_DISABLED => "Disabled",
        _ => "Unknown",
    }
}

fn is_elevated() -> bool {
    unsafe {
        let mut token: HANDLE = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION::default();
        let mut ret_len = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut _),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut ret_len,
        );
        ok.is_ok() && elevation.TokenIsElevated != 0
    }
}

fn relaunch_as_admin() -> bool {
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(_) => return false,
    };
    let path: Vec<u16> = wide_null(exe.to_string_lossy().as_ref());
    let verb: Vec<u16> = wide_null("runas");
    let result = unsafe { ShellExecuteW(None, PCWSTR(verb.as_ptr()), PCWSTR(path.as_ptr()), None, None, SW_SHOW) };
    result.0 as isize > 32
}

fn ensure_admin() {
    if is_elevated() {
        return;
    }
    if relaunch_as_admin() {
        std::process::exit(0);
    }
}

fn open_scm() -> windows::core::Result<SC_HANDLE> {
    unsafe { OpenSCManagerW(None, None, SC_MANAGER_ALL_ACCESS) }
}

fn query_start_type(scm: SC_HANDLE, name: &str) -> windows::core::Result<SERVICE_START_TYPE> {
    let name_w = wide_null(name);
    let svc = unsafe { OpenServiceW(scm, PCWSTR(name_w.as_ptr()), SERVICE_QUERY_CONFIG) }?;
    let mut bytes_needed = 0u32;
    unsafe {
        let _ = QueryServiceConfigW(svc, None, 0, &mut bytes_needed);
    }
    if bytes_needed == 0 {
        unsafe { let _ = CloseServiceHandle(svc); };
        return Err(windows::core::Error::from_win32());
    }

    let mut buffer = vec![0u8; bytes_needed as usize];
    let cfg_ptr = buffer.as_mut_ptr() as *mut QUERY_SERVICE_CONFIGW;
    let result = unsafe { QueryServiceConfigW(svc, Some(cfg_ptr), bytes_needed, &mut bytes_needed) };
    let start_type = match result {
        Ok(_) => unsafe { (*cfg_ptr).dwStartType },
        Err(e) => {
            unsafe { let _ = CloseServiceHandle(svc); };
            return Err(e);
        }
    };
    unsafe { let _ = CloseServiceHandle(svc); };
    Ok(start_type)
}

fn fetch_services() -> Result<Vec<ServiceInfo>, String> {
    let scm = open_scm().map_err(|e| format!("OpenSCManager failed: {e}"))?;
    let mut bytes_needed = 0u32;
    let mut services_returned = 0u32;
    let mut resume_handle = 0u32;
    let mut buffer: Vec<u8> = Vec::new();

    loop {
        let services_slice = if buffer.is_empty() {
            None
        } else {
            Some(buffer.as_mut_slice())
        };

        match unsafe {
            EnumServicesStatusExW(
                scm,
                SC_ENUM_PROCESS_INFO,
                SERVICE_WIN32,
                SERVICE_STATE_ALL,
                services_slice,
                &mut bytes_needed,
                &mut services_returned,
                Some(&mut resume_handle),
                None,
            )
        } {
            Ok(()) => break,
            Err(e) => {
                if e.code() == HRESULT::from_win32(ERROR_MORE_DATA.0) {
                    buffer.resize(bytes_needed as usize, 0);
                    continue;
                } else {
                    unsafe { let _ = CloseServiceHandle(scm); };
                    return Err(format!("Failed to enumerate services: {e}"));
                }
            }
        }
    }

    let mut services = Vec::with_capacity(services_returned as usize);
    let slice = unsafe {
        std::slice::from_raw_parts(
            buffer.as_ptr() as *const ENUM_SERVICE_STATUS_PROCESSW,
            services_returned as usize,
        )
    };

    for entry in slice {
        let name = pwstr_to_string(entry.lpServiceName);
        let display = pwstr_to_string(entry.lpDisplayName);
        let status = state_to_string(entry.ServiceStatusProcess.dwCurrentState).to_string();
        let start_type = query_start_type(scm, &name)
            .map(start_type_to_string)
            .unwrap_or("Unknown")
            .to_string();
        services.push(ServiceInfo {
            name,
            display_name: display,
            status,
            start_type,
            process_id: entry.ServiceStatusProcess.dwProcessId,
        });
    }

    unsafe { let _ = CloseServiceHandle(scm); };
    Ok(services)
}

fn stop_service(name: &str) -> Result<(), String> {
    let scm = open_scm().map_err(|e| format!("OpenSCManager failed: {e}"))?;
    let name_w = wide_null(name);
    let svc = unsafe {
        OpenServiceW(
            scm,
            PCWSTR(name_w.as_ptr()),
            SERVICE_STOP | SERVICE_QUERY_STATUS,
        )
    }
    .map_err(|e| format!("OpenService failed: {e}"))?;

    let mut status = SERVICE_STATUS::default();
    let result = unsafe { ControlService(svc, SERVICE_CONTROL_STOP, &mut status) };

    unsafe {
        let _ = CloseServiceHandle(svc);
        let _ = CloseServiceHandle(scm);
    }

    match result {
        Ok(_) => Ok(()),
        Err(e) => Err(format!("ControlService failed: {e}")),
    }
}

fn start_service(name: &str) -> Result<(), String> {
    let scm = open_scm().map_err(|e| format!("OpenSCManager failed: {e}"))?;
    let name_w = wide_null(name);
    let svc = unsafe { OpenServiceW(scm, PCWSTR(name_w.as_ptr()), SERVICE_START) }
        .map_err(|e| format!("OpenService failed: {e}"))?;

    let result = unsafe { StartServiceW(svc, None) };

    unsafe {
        let _ = CloseServiceHandle(svc);
        let _ = CloseServiceHandle(scm);
    }

    match result {
        Ok(_) => Ok(()),
        Err(e) => Err(format!("StartService failed: {e}")),
    }
}

fn enable_service(name: &str) -> Result<(), String> {
    let scm = open_scm().map_err(|e| format!("OpenSCManager failed: {e}"))?;
    let name_w = wide_null(name);
    let svc = unsafe { OpenServiceW(scm, PCWSTR(name_w.as_ptr()), SERVICE_CHANGE_CONFIG) }
        .map_err(|e| format!("OpenService failed: {e}"))?;

    let result = unsafe {
        ChangeServiceConfigW(
            svc,
            ENUM_SERVICE_TYPE(SERVICE_NO_CHANGE),
            SERVICE_DEMAND_START,
            SERVICE_ERROR(SERVICE_NO_CHANGE),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
    };

    unsafe {
        let _ = CloseServiceHandle(svc);
        let _ = CloseServiceHandle(scm);
    }

    match result {
        Ok(_) => Ok(()),
        Err(e) => Err(format!("ChangeServiceConfig failed: {e}")),
    }
}

fn disable_service(name: &str) -> Result<(), String> {
    let scm = open_scm().map_err(|e| format!("OpenSCManager failed: {e}"))?;
    let name_w = wide_null(name);
    let svc = unsafe { OpenServiceW(scm, PCWSTR(name_w.as_ptr()), SERVICE_CHANGE_CONFIG) }
        .map_err(|e| format!("OpenService failed: {e}"))?;

    let result = unsafe {
        ChangeServiceConfigW(
            svc,
            ENUM_SERVICE_TYPE(SERVICE_NO_CHANGE),
            SERVICE_DISABLED,
            SERVICE_ERROR(SERVICE_NO_CHANGE),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
    };

    unsafe {
        let _ = CloseServiceHandle(svc);
        let _ = CloseServiceHandle(scm);
    }

    match result {
        Ok(_) => Ok(()),
        Err(e) => Err(format!("ChangeServiceConfig failed: {e}")),
    }
}

struct ServiceApp {
    services: Vec<ServiceInfo>,
    status_message: String,
    search_query: String,
    show_running: bool,
    show_automatic: bool,
    show_disabled: bool,
}

impl ServiceApp {
    fn new() -> Self {
        let mut app = Self {
            services: Vec::new(),
            status_message: String::from("Loading services..."),
            search_query: String::new(),
            show_running: false,
            show_automatic: false,
            show_disabled: false,
        };
        app.refresh();
        app
    }

    fn refresh(&mut self) {
        match fetch_services() {
            Ok(list) => {
                self.status_message = format!("Loaded {} services", list.len());
                self.services = list;
            }
            Err(e) => {
                self.status_message = format!("Failed to load services: {e}");
            }
        }
    }

    fn filtered_services(&self) -> Vec<ServiceInfo> {
        let matcher = SkimMatcherV2::default();
        let query = self.search_query.trim();
        self
            .services
            .iter()
            .cloned()
            .filter(|svc| {
                if self.show_running && svc.status != "Running" {
                    return false;
                }
                if self.show_automatic && svc.start_type != "Automatic" {
                    return false;
                }
                if self.show_disabled && svc.start_type != "Disabled" {
                    return false;
                }
                if query.is_empty() {
                    return true;
                }
                matcher.fuzzy_match(&svc.display_name, query).is_some()
                    || matcher.fuzzy_match(&svc.name, query).is_some()
            })
            .collect()
    }
}

impl App for ServiceApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::TopBottomPanel::top("top_bar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                if ui.button("Refresh").clicked() {
                    self.refresh();
                }
                if ui.button("Quit").clicked() {
                    std::process::exit(0);
                }
                ui.label(&self.status_message);
            });
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Windows Services");
            ui.separator();

            ui.horizontal(|ui| {
                ui.label("Search:");
                ui.text_edit_singleline(&mut self.search_query);
                ui.toggle_value(&mut self.show_running, "Running");
                ui.toggle_value(&mut self.show_automatic, "Automatic");
                ui.toggle_value(&mut self.show_disabled, "Disabled");
            });
            ui.separator();

            egui::ScrollArea::vertical().show(ui, |ui| {
                let services_snapshot = self.filtered_services();
                for svc in services_snapshot {
                    ui.horizontal(|ui| {
                        let name_text = format!("{} ({})", svc.display_name, svc.name);
                        let name_response = ui
                            .add(egui::Label::new(name_text.clone()).sense(egui::Sense::click()));
                        if name_response.secondary_clicked() {
                            ui.output_mut(|o| o.copied_text = name_text.clone());
                            self.status_message = format!("Copied service: {}", name_text);
                        }
                        ui.label(format!("Status: {}", svc.status));
                        ui.label(format!("Start: {}", svc.start_type));
                        if svc.process_id != 0 {
                            ui.label(format!("PID: {}", svc.process_id));
                        }
                        if svc.status != "Running" {
                            if ui.button("Start").clicked() {
                                if svc.start_type == "Disabled" {
                                    match enable_service(&svc.name) {
                                        Ok(_) => self.status_message = format!("Enabled {}", svc.name),
                                        Err(e) => {
                                            self.status_message = e;
                                            return;
                                        }
                                    }
                                }
                                match start_service(&svc.name) {
                                    Ok(_) => self.status_message = format!("Started {}", svc.name),
                                    Err(e) => self.status_message = e,
                                }
                                self.refresh();
                            }
                        }
                        if ui.button("Stop").clicked() {
                            match stop_service(&svc.name) {
                                Ok(_) => self.status_message = format!("Stopped {}", svc.name),
                                Err(e) => self.status_message = e,
                            }
                            self.refresh();
                        }
                        if ui.button("Disable").clicked() {
                            match disable_service(&svc.name) {
                                Ok(_) => self.status_message = format!("Disabled {}", svc.name),
                                Err(e) => self.status_message = e,
                            }
                            self.refresh();
                        }
                    });
                    ui.separator();
                }
            });
        });
    }
}

fn main() -> eframe::Result<()> {
    ensure_admin();
    let options = eframe::NativeOptions::default();
    eframe::run_native(
        "Windows Service Manager",
        options,
        Box::new(|_| Ok(Box::new(ServiceApp::new()))),
    )
}

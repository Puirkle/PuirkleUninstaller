//! Services and scheduled tasks through their Windows APIs (Service Control Manager and the Task
//! Scheduler COM interface) instead of `sc.exe` and `schtasks.exe`, which security products such
//! as 360 treat as suspicious when a program starts them hidden.

use crate::util::wide;
use std::path::Path;
use std::ptr::null;
use windows_sys::Win32::System::Services::{
    CloseServiceHandle, ControlService, DeleteService, OpenSCManagerW, OpenServiceW, QueryServiceStatus, SC_MANAGER_CONNECT,
    SERVICE_CONTROL_STOP, SERVICE_QUERY_STATUS, SERVICE_STATUS, SERVICE_STOP, SERVICE_STOPPED,
};

/// Standard DELETE access right.
const DELETE: u32 = 0x0001_0000;
const ERROR_ACCESS_DENIED: u32 = 5;
const ERROR_SERVICE_DOES_NOT_EXIST: u32 = 1060;
const ERROR_SERVICE_MARKED_FOR_DELETE: u32 = 1072;

/// Opens service `name` with `access`, runs `f`, and closes the handles.
fn with_service<T>(name: &str, access: u32, f: impl FnOnce(*mut core::ffi::c_void) -> T) -> Result<T, u32> {
    unsafe {
        let scm = OpenSCManagerW(null(), null(), SC_MANAGER_CONNECT);
        if scm.is_null() {
            return Err(windows_sys::Win32::Foundation::GetLastError());
        }
        let svc = OpenServiceW(scm, wide(name).as_ptr(), access);
        let r = if svc.is_null() {
            Err(windows_sys::Win32::Foundation::GetLastError())
        } else {
            let r = f(svc);
            CloseServiceHandle(svc);
            Ok(r)
        };
        CloseServiceHandle(scm);
        r
    }
}

/// Asks a service to stop and waits up to 5 seconds for it. True once it's stopped.
pub fn stop_service(name: &str) -> bool {
    with_service(name, SERVICE_STOP | SERVICE_QUERY_STATUS, |svc| unsafe {
        let mut status: SERVICE_STATUS = std::mem::zeroed();
        ControlService(svc, SERVICE_CONTROL_STOP, &mut status);
        for _ in 0..25 {
            if QueryServiceStatus(svc, &mut status) == 0 || status.dwCurrentState == SERVICE_STOPPED {
                return status.dwCurrentState == SERVICE_STOPPED;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        false
    })
    .unwrap_or(false)
}

/// Removes a service from Windows (it disappears once it has stopped).
pub fn delete_service(name: &str) -> Result<(), String> {
    let r = with_service(name, DELETE, |svc| unsafe {
        if DeleteService(svc) != 0 { Ok(()) } else { Err(windows_sys::Win32::Foundation::GetLastError()) }
    })
    .and_then(|r| r);
    match r {
        Ok(()) | Err(ERROR_SERVICE_MARKED_FOR_DELETE) | Err(ERROR_SERVICE_DOES_NOT_EXIST) => Ok(()),
        Err(ERROR_ACCESS_DENIED) => Err("Access denied. Restart PuirkleUninstaller as administrator to remove services.".into()),
        Err(code) => Err(format!("Could not delete the service (error {code}).")),
    }
}

/// Runs `f` with a connected Task Scheduler.
fn with_scheduler<T>(
    f: impl FnOnce(&windows::Win32::System::TaskScheduler::ITaskService) -> windows::core::Result<T>,
) -> Result<T, String> {
    use windows::Win32::System::Com::{CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED};
    use windows::Win32::System::TaskScheduler::{ITaskService, TaskScheduler};
    use windows::Win32::System::Variant::VARIANT;
    unsafe {
        // Fails harmlessly if this thread already uses COM in another mode; COM still works then.
        let init = CoInitializeEx(None, COINIT_MULTITHREADED);
        let r = (|| {
            let svc: ITaskService = CoCreateInstance(&TaskScheduler, None, CLSCTX_INPROC_SERVER)?;
            let none = VARIANT::default();
            svc.Connect(&none, &none, &none, &none)?;
            f(&svc)
        })();
        if init.is_ok() {
            CoUninitialize();
        }
        r.map_err(|e| e.message())
    }
}

/// Deletes the scheduled task `name` (its full path, e.g. `\Vendor\Updater`).
pub fn delete_task(name: &str) -> Result<(), String> {
    use windows::core::BSTR;
    with_scheduler(|s| unsafe { s.GetFolder(&BSTR::from("\\"))?.DeleteTask(&BSTR::from(name), 0) })
}

/// Re-creates the scheduled task `name` from its saved XML definition.
pub fn register_task(name: &str, xml_file: &Path) -> Result<(), String> {
    use windows::core::BSTR;
    use windows::Win32::System::TaskScheduler::{TASK_CREATE_OR_UPDATE, TASK_LOGON_NONE};
    use windows::Win32::System::Variant::VARIANT;
    let xml = read_text(xml_file)?;
    with_scheduler(|s| unsafe {
        let none = VARIANT::default();
        // TASK_LOGON_NONE: run as the account the XML's <Principal> names, as it was before.
        s.GetFolder(&BSTR::from("\\"))?
            .RegisterTask(&BSTR::from(name), &BSTR::from(xml), TASK_CREATE_OR_UPDATE.0, &none, &none, TASK_LOGON_NONE, &none)
            .map(|_| ())
    })
}

/// Task XML files are UTF-16 with a byte-order mark; accept UTF-8 too.
fn read_text(file: &Path) -> Result<String, String> {
    let bytes = std::fs::read(file).map_err(|e| e.to_string())?;
    Ok(if bytes.starts_with(&[0xFF, 0xFE]) {
        let units: Vec<u16> = bytes[2..].chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        String::from_utf16_lossy(&units)
    } else {
        String::from_utf8_lossy(bytes.strip_prefix(&[0xEF, 0xBB, 0xBF][..]).unwrap_or(&bytes)).into_owned()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Creates a throwaway task for the current user, deletes it, and re-creates it from its saved
    /// XML, like a cleanup and its undo. Touches only the task `\PuirkleUninstallerTaskTest`.
    /// `cargo test task_round_trip -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn task_round_trip() {
        let name = r"\PuirkleUninstallerTaskTest";
        let xml = r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>PuirkleUninstaller self-test; safe to delete</Description></RegistrationInfo>
  <Triggers><TimeTrigger><StartBoundary>2099-01-01T00:00:00</StartBoundary><Enabled>false</Enabled></TimeTrigger></Triggers>
  <Settings><Enabled>false</Enabled></Settings>
  <Actions><Exec><Command>notepad.exe</Command></Exec></Actions>
</Task>"#;
        let file = std::env::temp_dir().join("puirkle-task-test.xml");
        std::fs::write(&file, xml).unwrap();
        register_task(name, &file).expect("create test task");
        let on_disk = std::path::PathBuf::from(std::env::var("windir").unwrap()).join(r"System32\Tasks\PuirkleUninstallerTaskTest");
        assert!(on_disk.exists());
        delete_task(name).expect("delete");
        assert!(!on_disk.exists());
        register_task(name, &file).expect("restore");
        assert!(on_disk.exists());
        delete_task(name).unwrap();
        let _ = std::fs::remove_file(&file);
        println!("task round trip OK");
    }
}

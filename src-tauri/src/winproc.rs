//! Win32 process helpers: elevation, launching uninstallers and waiting on their whole process tree.

use crate::util::{from_wide, wide};
use std::collections::HashSet;
use std::ffi::c_void;
use std::mem::{size_of, zeroed};
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, ERROR_CANCELLED, HANDLE, INVALID_HANDLE_VALUE, WAIT_TIMEOUT};
use windows_sys::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetExitCodeProcess, GetProcessId, OpenProcess, OpenProcessToken, QueryFullProcessImageNameW,
    TerminateProcess, WaitForSingleObject, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE,
};
use windows_sys::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};
use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

/// Set by the UI's "Stop waiting" button.
pub static CANCEL_WAIT: AtomicBool = AtomicBool::new(false);

/// Processes an uninstaller commonly opens at the end (feedback pages) that we must not wait for.
const IGNORED_CHILDREN: &[&str] = &[
    "chrome.exe", "msedge.exe", "firefox.exe", "opera.exe", "brave.exe", "iexplore.exe", "vivaldi.exe",
    "explorer.exe", "conhost.exe", "werfault.exe",
];

pub struct ProcInfo {
    pub pid: u32,
    pub parent: u32,
    pub name: String,
}

pub fn snapshot() -> Vec<ProcInfo> {
    let mut out = Vec::new();
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap == INVALID_HANDLE_VALUE {
            return out;
        }
        let mut e: PROCESSENTRY32W = zeroed();
        e.dwSize = size_of::<PROCESSENTRY32W>() as u32;
        if Process32FirstW(snap, &mut e) != 0 {
            loop {
                out.push(ProcInfo { pid: e.th32ProcessID, parent: e.th32ParentProcessID, name: from_wide(&e.szExeFile) });
                if Process32NextW(snap, &mut e) == 0 {
                    break;
                }
            }
        }
        CloseHandle(snap);
    }
    out
}

pub fn image_path(pid: u32) -> Option<String> {
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h.is_null() {
            return None;
        }
        let mut buf = [0u16; 1024];
        let mut len = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(h, 0, buf.as_mut_ptr(), &mut len);
        CloseHandle(h);
        (ok != 0).then(|| String::from_utf16_lossy(&buf[..len as usize]))
    }
}

fn terminate(pid: u32) -> bool {
    unsafe {
        let h = OpenProcess(PROCESS_TERMINATE, 0, pid);
        if h.is_null() {
            return false;
        }
        let ok = TerminateProcess(h, 1) != 0;
        CloseHandle(h);
        ok
    }
}

/// Kills every process whose executable lives under one of `dirs` (lowercase paths).
pub fn kill_in_dirs(dirs: &[String]) -> Vec<String> {
    if dirs.is_empty() {
        return Vec::new();
    }
    let me = std::process::id();
    let mut killed = Vec::new();
    for p in snapshot() {
        if p.pid == me || p.pid <= 4 {
            continue;
        }
        let Some(path) = image_path(p.pid) else { continue };
        let lp = path.to_lowercase();
        // `dirs` may also hold a single-file app's exe path, which matches exactly.
        if dirs.iter().any(|d| lp == *d || lp.starts_with(&format!("{d}\\"))) && terminate(p.pid) {
            killed.push(path);
        }
    }
    killed
}

pub fn is_elevated() -> bool {
    unsafe {
        let mut token: HANDLE = null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut elev: TOKEN_ELEVATION = zeroed();
        let mut ret = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            &mut elev as *mut _ as *mut c_void,
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut ret,
        );
        CloseHandle(token);
        ok != 0 && elev.TokenIsElevated != 0
    }
}

fn exec_info(verb: &[u16], file: &[u16], params: &[u16], mask: u32) -> SHELLEXECUTEINFOW {
    let mut sei: SHELLEXECUTEINFOW = unsafe { zeroed() };
    sei.cbSize = size_of::<SHELLEXECUTEINFOW>() as u32;
    sei.fMask = mask;
    sei.lpVerb = if verb.len() > 1 { verb.as_ptr() } else { null() };
    sei.lpFile = file.as_ptr();
    sei.lpParameters = if params.len() > 1 { params.as_ptr() } else { null() };
    sei.nShow = SW_SHOWNORMAL;
    sei
}

fn launch_error() -> String {
    let err = unsafe { GetLastError() };
    if err == ERROR_CANCELLED {
        "The administrator prompt was cancelled.".into()
    } else {
        format!("Windows could not start it (error {err}).")
    }
}

/// Fire-and-forget ShellExecute (handles UAC prompts).
pub fn shell_execute(verb: Option<&str>, file: &str, params: &str) -> Result<(), String> {
    let (v, f, p) = (wide(verb.unwrap_or("")), wide(file), wide(params));
    let mut sei = exec_info(&v, &f, &p, SEE_MASK_NOASYNC);
    if unsafe { ShellExecuteExW(&mut sei) } == 0 {
        return Err(launch_error());
    }
    Ok(())
}

/// Starts this exe again as administrator, passing on our own arguments (e.g. `--unlock <path>`).
pub fn relaunch_elevated() -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let mut params = String::from("--elevated");
    for a in std::env::args().skip(1) {
        params.push_str(&format!(" \"{}\"", a.trim_end_matches('\\').replace('"', "")));
    }
    shell_execute(Some("runas"), &exe.to_string_lossy(), &params)
}

/// Under `tauri dev` the UI is served by the CLI on 127.0.0.1, which stops when this window
/// closes, so relaunching just the exe would show a dead page. Restart the whole dev command
/// in an elevated terminal instead.
pub fn relaunch_dev_elevated() -> Result<(), String> {
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let project = manifest.parent().unwrap_or(manifest);
    let params = format!(
        "/k \"cd /d \"{}\" && set \"PATH=%USERPROFILE%\\.cargo\\bin;%PATH%\" && npm run dev\"",
        project.display()
    );
    shell_execute(Some("runas"), "cmd.exe", &params)
}

/// Adds descendants of tracked processes to `tracked`; returns how many are still running.
fn track(tracked: &mut HashSet<u32>, root: u32) -> usize {
    let procs = snapshot();
    let mut changed = true;
    while changed {
        changed = false;
        for p in &procs {
            if tracked.contains(&p.parent) && !tracked.contains(&p.pid) {
                tracked.insert(p.pid);
                changed = true;
            }
        }
    }
    procs
        .iter()
        .filter(|p| p.pid != root && tracked.contains(&p.pid))
        .filter(|p| !IGNORED_CHILDREN.contains(&p.name.to_lowercase().as_str()))
        .count()
}

/// Launches `file` through ShellExecuteEx (so UAC elevation works) and waits until it and every
/// process it spawned have exited. Many uninstallers (NSIS, Inno Setup) copy themselves to %TEMP%
/// and exit immediately, so waiting on the first process alone is not enough.
pub fn run_and_wait(file: &str, params: &str) -> Result<u32, String> {
    CANCEL_WAIT.store(false, Ordering::SeqCst);
    let (v, f, p) = (wide(""), wide(file), wide(params));
    let mut sei = exec_info(&v, &f, &p, SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC);
    if unsafe { ShellExecuteExW(&mut sei) } == 0 {
        return Err(format!("Could not start the uninstaller: {}", launch_error()));
    }
    if sei.hProcess.is_null() {
        return Ok(0);
    }
    let root = unsafe { GetProcessId(sei.hProcess) };
    let mut tracked: HashSet<u32> = HashSet::from([root]);
    loop {
        let r = unsafe { WaitForSingleObject(sei.hProcess, 400) };
        track(&mut tracked, root);
        if r != WAIT_TIMEOUT || CANCEL_WAIT.load(Ordering::SeqCst) {
            break;
        }
    }
    let mut code = 0u32;
    unsafe {
        GetExitCodeProcess(sei.hProcess, &mut code);
        CloseHandle(sei.hProcess);
    }
    while !CANCEL_WAIT.load(Ordering::SeqCst) && track(&mut tracked, root) > 0 {
        std::thread::sleep(Duration::from_millis(500));
    }
    Ok(code)
}

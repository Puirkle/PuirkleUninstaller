//! Unlocking and force-deleting files and folders for the storage analyzer.
//!
//! Programs that hold a file open are found with Windows' Restart Manager and closed the same way
//! Windows Update closes them before replacing files. We never inject into other processes or
//! close their handles behind their back, which can crash them and looks like malware to antivirus.
//! Deletion uses backup/restore rights, so permissions and the read-only flag don't stop it, and
//! anything still in use (such as a loaded registry hive) is deleted when Windows restarts.

use crate::util::{from_wide, wide};
use serde::Serialize;
use std::mem::{size_of, zeroed};
use std::path::Path;
use std::ptr::{null, null_mut};
use windows_sys::core::PCWSTR;
use windows_sys::Win32::Foundation::{CloseHandle, ERROR_MORE_DATA, ERROR_SUCCESS, HANDLE, INVALID_HANDLE_VALUE, LUID};
use windows_sys::Win32::Security::{
    AdjustTokenPrivileges, LookupPrivilegeValueW, LUID_AND_ATTRIBUTES, SE_BACKUP_NAME, SE_PRIVILEGE_ENABLED, SE_RESTORE_NAME,
    SE_TAKE_OWNERSHIP_NAME, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, DeleteFileW, FileDispositionInfoEx, MoveFileExW, RemoveDirectoryW, SetFileAttributesW, SetFileInformationByHandle,
    DELETE, FILE_ATTRIBUTE_NORMAL, FILE_DISPOSITION_FLAG_DELETE, FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE,
    FILE_DISPOSITION_FLAG_POSIX_SEMANTICS, FILE_DISPOSITION_INFO_EX, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, MOVEFILE_DELAY_UNTIL_REBOOT, OPEN_EXISTING,
};
use windows_sys::Win32::System::RestartManager::{
    RmCritical, RmEndSession, RmExplorer, RmForceShutdown, RmGetList, RmRegisterResources, RmRestart, RmService, RmShutdown,
    RmStartSession, CCH_RM_SESSION_KEY, RM_PROCESS_INFO,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// More files than this in one folder are checked for locks only in part (Restart Manager slows down).
const MAX_FILES: usize = 20_000;

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Locker {
    pub pid: u32,
    pub name: String,
    /// "app", "service", "explorer" or "critical" (part of Windows; can't be closed).
    pub kind: String,
}

#[derive(Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ForceResult {
    pub deleted_bytes: u64,
    /// Items that are still in use and will be deleted when Windows restarts.
    pub pending: usize,
    /// Items that couldn't be deleted or scheduled.
    pub failed: Vec<String>,
    /// Programs that were closed to unlock the files.
    pub closed: Vec<String>,
}

/// A Restart Manager session, ended when dropped.
struct Session(u32);

impl Session {
    fn start() -> Result<Self, String> {
        let mut handle = 0u32;
        let mut key = [0u16; CCH_RM_SESSION_KEY as usize + 1];
        let r = unsafe { RmStartSession(&mut handle, 0, key.as_mut_ptr()) };
        if r != ERROR_SUCCESS {
            return Err(format!("Windows couldn't check which programs use it (error {r})."));
        }
        Ok(Session(handle))
    }

    fn for_path(path: &Path) -> Result<Self, String> {
        let session = Self::start()?;
        let files = files_under(path);
        for chunk in files.chunks(500) {
            let w: Vec<Vec<u16>> = chunk.iter().map(|f| wide(f)).collect();
            let ptrs: Vec<PCWSTR> = w.iter().map(|v| v.as_ptr()).collect();
            let r = unsafe { RmRegisterResources(session.0, ptrs.len() as u32, ptrs.as_ptr(), 0, null(), 0, null()) };
            if r != ERROR_SUCCESS {
                return Err(format!("Windows couldn't check which programs use it (error {r})."));
            }
        }
        Ok(session)
    }

    fn list(&self) -> Vec<RM_PROCESS_INFO> {
        let mut needed = 0u32;
        for _ in 0..5 {
            let mut buf: Vec<RM_PROCESS_INFO> = vec![unsafe { zeroed() }; needed as usize];
            let mut count = needed;
            let mut reasons = 0u32;
            let r = unsafe { RmGetList(self.0, &mut needed, &mut count, buf.as_mut_ptr(), &mut reasons) };
            if r == ERROR_SUCCESS {
                buf.truncate(count as usize);
                return buf;
            }
            if r != ERROR_MORE_DATA {
                break;
            }
        }
        Vec::new()
    }

    /// Asks the programs using the files to close, and ends them if they don't respond. Returns
    /// their names and the session that closed them (for `restart`). Windows' critical processes
    /// and PuirkleUninstaller itself are never touched: a second session registers only the
    /// programs we chose, and services by name, so a shared service host isn't ended with them.
    fn shut_down(&self) -> (Vec<String>, Option<Session>) {
        let mut names = Vec::new();
        let mut procs = Vec::new();
        let mut services: Vec<Vec<u16>> = Vec::new();
        for info in self.list() {
            let l = locker(&info);
            if l.kind == "critical" {
                continue;
            }
            if info.ApplicationType == RmService && info.strServiceShortName[0] != 0 {
                services.push(wide(&from_wide(&info.strServiceShortName)));
            } else {
                procs.push(info.Process);
            }
            names.push(l.name);
        }
        if names.is_empty() {
            return (names, None);
        }
        let Ok(chosen) = Session::start() else { return (Vec::new(), None) };
        let svc_ptrs: Vec<PCWSTR> = services.iter().map(|s| s.as_ptr()).collect();
        let r = unsafe {
            RmRegisterResources(chosen.0, 0, null(), procs.len() as u32, procs.as_ptr(), svc_ptrs.len() as u32, svc_ptrs.as_ptr())
        };
        if r != ERROR_SUCCESS {
            return (Vec::new(), None);
        }
        unsafe { RmShutdown(chosen.0, RmForceShutdown as u32, None) };
        (names, Some(chosen))
    }

    /// Starts again what `shut_down` closed and can restart itself, such as File Explorer.
    fn restart(&self) {
        unsafe { RmRestart(self.0, 0, None) };
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        unsafe { RmEndSession(self.0) };
    }
}

/// Every file at or under `path` (Restart Manager tracks files, not folders).
fn files_under(path: &Path) -> Vec<String> {
    if path.is_file() {
        return vec![path.to_string_lossy().into_owned()];
    }
    walkdir::WalkDir::new(path)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file())
        .take(MAX_FILES)
        .map(|e| e.path().to_string_lossy().into_owned())
        .collect()
}

fn locker(i: &RM_PROCESS_INFO) -> Locker {
    let kind = [(RmCritical, "critical"), (RmService, "service"), (RmExplorer, "explorer")]
        .iter()
        .find(|(t, _)| *t == i.ApplicationType)
        .map_or("app", |(_, k)| k);
    let mut name = from_wide(&i.strAppName);
    if name.is_empty() {
        name = from_wide(&i.strServiceShortName);
    }
    let critical = kind == "critical" || i.Process.dwProcessId == std::process::id();
    Locker { pid: i.Process.dwProcessId, name, kind: if critical { "critical" } else { kind }.into() }
}

fn refuse_protected(path: &str) -> Result<(), String> {
    if crate::leftovers::is_protected_path(path) {
        return Err("That's a protected Windows or user folder, so PuirkleUninstaller won't touch it.".into());
    }
    if !Path::new(path).exists() {
        return Err(format!("{path} no longer exists."));
    }
    Ok(())
}

/// The programs that have files at or under `path` open.
pub fn lockers(path: &str) -> Result<Vec<Locker>, String> {
    refuse_protected(path)?;
    let session = Session::for_path(Path::new(path))?;
    let mut out: Vec<Locker> = session.list().iter().map(locker).collect();
    out.sort_by_key(|l| l.pid);
    out.dedup_by_key(|l| l.pid);
    Ok(out)
}

/// Closes the programs using `path` so it can be moved, renamed or deleted. Returns their names.
pub fn unlock(path: &str) -> Result<Vec<String>, String> {
    refuse_protected(path)?;
    let session = Session::for_path(Path::new(path))?;
    let explorer_was_closed = session.list().iter().any(|i| i.ApplicationType == RmExplorer);
    let (closed, _) = session.shut_down();
    // The files stay unlocked for the user to deal with, so only the Windows shell comes back.
    if explorer_was_closed && !crate::winproc::snapshot().iter().any(|p| p.name.eq_ignore_ascii_case("explorer.exe")) {
        let _ = std::process::Command::new("explorer.exe").spawn();
    }
    Ok(closed)
}

/// Permanently deletes `path`: closes the programs using it, deletes everything it can right away,
/// and schedules what is still in use for deletion at the next restart.
pub fn force_delete(path: &str) -> Result<ForceResult, String> {
    refuse_protected(path)?;
    let root = Path::new(path);
    let mut result = ForceResult::default();
    let mut closer = None;
    if let Ok(s) = Session::for_path(root) {
        (result.closed, closer) = s.shut_down();
    }
    enable_privileges();

    let entries: Vec<walkdir::DirEntry> = walkdir::WalkDir::new(root).contents_first(true).into_iter().filter_map(Result::ok).collect();
    for e in entries {
        let p = e.path();
        let is_dir = e.file_type().is_dir();
        let size = if is_dir { 0 } else { e.metadata().map(|m| m.len()).unwrap_or(0) };
        if delete_now(p, is_dir) {
            result.deleted_bytes += size;
        } else if schedule(p) {
            result.pending += 1;
        } else {
            result.failed.push(p.to_string_lossy().into_owned());
        }
    }
    if let Some(s) = &closer {
        s.restart();
    }
    if result.pending == 0 && result.failed.is_empty() {
        crate::storage::forget(path, result.deleted_bytes);
    }
    Ok(result)
}

/// Deletes one file or empty folder, ignoring permissions (backup/restore rights), the read-only
/// flag, and other programs' handles that allow deletion (POSIX semantics).
fn delete_now(p: &Path, is_dir: bool) -> bool {
    let w = wide(&p.to_string_lossy());
    unsafe {
        let h: HANDLE = CreateFileW(
            w.as_ptr(),
            DELETE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        );
        if h != INVALID_HANDLE_VALUE {
            let info = FILE_DISPOSITION_INFO_EX {
                Flags: FILE_DISPOSITION_FLAG_DELETE | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS | FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE,
            };
            let ok = SetFileInformationByHandle(h, FileDispositionInfoEx, &info as *const _ as *const _, size_of::<FILE_DISPOSITION_INFO_EX>() as u32) != 0;
            CloseHandle(h);
            if ok {
                return true;
            }
        }
        // FAT/exFAT drives and older Windows don't support the extended delete.
        SetFileAttributesW(w.as_ptr(), FILE_ATTRIBUTE_NORMAL);
        if is_dir { RemoveDirectoryW(w.as_ptr()) != 0 } else { DeleteFileW(w.as_ptr()) != 0 }
    }
}

/// Marks `p` for deletion when Windows next starts (needs administrator rights).
fn schedule(p: &Path) -> bool {
    let w = wide(&p.to_string_lossy());
    unsafe { MoveFileExW(w.as_ptr(), null(), MOVEFILE_DELAY_UNTIL_REBOOT) != 0 }
}

/// Turns on the backup, restore and take-ownership rights an administrator has but doesn't use by
/// default. Does nothing when not elevated.
pub fn enable_privileges() {
    unsafe {
        let mut token: HANDLE = null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &mut token) == 0 {
            return;
        }
        for name in [SE_BACKUP_NAME, SE_RESTORE_NAME, SE_TAKE_OWNERSHIP_NAME] {
            let mut luid: LUID = zeroed();
            if LookupPrivilegeValueW(null(), name, &mut luid) == 0 {
                continue;
            }
            let tp = TOKEN_PRIVILEGES { PrivilegeCount: 1, Privileges: [LUID_AND_ATTRIBUTES { Luid: luid, Attributes: SE_PRIVILEGE_ENABLED }] };
            AdjustTokenPrivileges(token, 0, &tp, 0, null_mut(), null_mut());
        }
        CloseHandle(token);
    }
}

// ---------------------------------------------------------------------------------------------
// "Unlock with PuirkleUninstaller" in File Explorer's right-click menu (opt-in, current user only).
// On Windows 11 it sits under "Show more options", like other classic menu entries.

/// Where the menu entry lives for files and for folders. The installer's uninstall step deletes
/// the same keys (see installer-hooks.nsh).
const MENU_KEYS: &[&str] = &[r"Software\Classes\*\shell\PuirkleUnlock", r"Software\Classes\Directory\shell\PuirkleUnlock"];

/// The file or folder the app was started for from that menu (`--unlock <path>`).
static TARGET: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

/// Remembers `--unlock <path>` from the command line.
pub fn take_args() {
    let args: Vec<String> = std::env::args().collect();
    if let Some(i) = args.iter().position(|a| a == "--unlock") {
        *TARGET.lock().unwrap() = args.get(i + 1).cloned();
    }
}

/// The path the app was started to unlock, once.
pub fn take_target() -> Option<String> {
    TARGET.lock().unwrap().take()
}

fn menu_command() -> Option<String> {
    let exe = std::env::current_exe().ok()?;
    Some(format!("\"{}\" --unlock \"%1\"", exe.display()))
}

/// True when the menu entry is there and starts this copy of the app.
pub fn explorer_menu_enabled() -> bool {
    let hkcu = winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER);
    let Some(want) = menu_command() else { return false };
    MENU_KEYS.iter().all(|k| {
        hkcu.open_subkey(format!(r"{k}\command")).and_then(|c| c.get_value::<String, _>("")).is_ok_and(|v| v == want)
    })
}

pub fn set_explorer_menu(on: bool) -> Result<(), String> {
    let hkcu = winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER);
    for k in MENU_KEYS {
        if !on {
            match hkcu.delete_subkey_all(k) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e.to_string()),
                _ => continue,
            }
        }
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        let (key, _) = hkcu.create_subkey(k).map_err(|e| e.to_string())?;
        key.set_value("", &"Unlock with PuirkleUninstaller").map_err(|e| e.to_string())?;
        key.set_value("Icon", &format!("\"{}\",0", exe.display())).map_err(|e| e.to_string())?;
        let (cmd, _) = key.create_subkey("command").map_err(|e| e.to_string())?;
        cmd.set_value("", &menu_command().unwrap_or_default()).map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// After an update moved the exe, points an existing menu entry at the new one.
pub fn refresh_explorer_menu() {
    let hkcu = winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER);
    if hkcu.open_subkey(MENU_KEYS[0]).is_ok() && !explorer_menu_enabled() {
        let _ = set_explorer_menu(true);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A file held open without delete sharing is reported, and force delete removes a read-only tree.
    #[test]
    fn finds_lockers_and_force_deletes() {
        let dir = std::env::temp_dir().join(format!("puirkle-unlock-test-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        let f = dir.join("sub").join("locked.txt");
        std::fs::write(&f, b"hello").unwrap();
        std::fs::write(dir.join("ro.txt"), b"x").unwrap();
        let mut perm = std::fs::metadata(dir.join("ro.txt")).unwrap().permissions();
        perm.set_readonly(true);
        std::fs::set_permissions(dir.join("ro.txt"), perm).unwrap();

        let held = std::fs::File::open(&f).unwrap();
        let found = lockers(&dir.to_string_lossy()).unwrap();
        assert!(found.iter().any(|l| l.pid == std::process::id()), "our own process should be listed");
        assert!(found.iter().all(|l| l.pid != std::process::id() || l.kind == "critical"), "we must never close ourselves");
        drop(held);

        let r = force_delete(&dir.to_string_lossy()).unwrap();
        assert!(r.failed.is_empty() && r.pending == 0, "failed: {:?}", r.failed);
        assert!(!dir.exists());
    }

    /// Adds the File Explorer menu entry, checks it, and removes it again (touches HKCU):
    /// `cargo test explorer_menu_roundtrip -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn explorer_menu_roundtrip() {
        let was_on = winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER).open_subkey(MENU_KEYS[0]).is_ok();
        set_explorer_menu(true).unwrap();
        assert!(explorer_menu_enabled());
        let cmd: String = winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER)
            .open_subkey(format!(r"{}\command", MENU_KEYS[1]))
            .unwrap()
            .get_value("")
            .unwrap();
        println!("folder command: {cmd}");
        set_explorer_menu(false).unwrap();
        assert!(!explorer_menu_enabled());
        assert!(winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER).open_subkey(MENU_KEYS[0]).is_err());
        if was_on {
            set_explorer_menu(true).unwrap();
        }
    }

    /// `PUIRKLE_UNLOCK=<path> cargo test unlock_dry_run -- --ignored --nocapture` lists what locks
    /// a path; add `PUIRKLE_FORCE=1` to force-delete it (closes those programs).
    #[test]
    #[ignore]
    fn unlock_dry_run() {
        let path = std::env::var("PUIRKLE_UNLOCK").expect("set PUIRKLE_UNLOCK");
        for l in lockers(&path).unwrap() {
            println!("locked by {:>6}  {:<10} {}", l.pid, l.kind, l.name);
        }
        if std::env::var("PUIRKLE_FORCE").is_ok() {
            let r = force_delete(&path).unwrap();
            println!("closed {:?}; deleted {} bytes; {} pending; failed {:?}", r.closed, r.deleted_bytes, r.pending, r.failed);
        }
    }
}

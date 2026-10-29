//! Deletes the leftovers the user selected. Registry data is backed up first; files go to the
//! Recycle Bin when possible; locked files are scheduled for deletion on reboot. Everything that
//! can be undone is recorded in the session's manifest (see `rollback`).

use crate::leftovers::Leftover;
use crate::rollback::{self, Manifest, RegEntry, TaskEntry};
use crate::util::{env_dir, hidden, wide};
use crate::{reg, winproc};
use serde::Serialize;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::ptr::null;
use windows_sys::Win32::Storage::FileSystem::{MoveFileExW, SetFileAttributesW, FILE_ATTRIBUTE_NORMAL, MOVEFILE_DELAY_UNTIL_REBOOT};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ItemResult {
    pub id: String,
    pub ok: bool,
    pub message: Option<String>,
    pub pending_reboot: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Report {
    pub results: Vec<ItemResult>,
    pub backup_dir: Option<String>,
    /// Backup session that can be rolled back, if anything undoable was removed.
    pub session_id: Option<String>,
    pub freed_bytes: u64,
    pub closed_processes: Vec<String>,
}

pub fn backup_root() -> PathBuf {
    env_dir("LOCALAPPDATA").unwrap_or_else(std::env::temp_dir).join(r"PuirkleUninstaller\Backups")
}

struct Backup {
    dir: PathBuf,
    count: usize,
    exported: HashSet<String>,
    manifest: Manifest,
}

impl Backup {
    /// Exports `key` to a .reg file (once per key) and returns the file name.
    fn export(&mut self, key: &str) -> Result<String, String> {
        let name = format!("{:03}.reg", self.count + 1);
        if !self.exported.insert(key.to_lowercase()) {
            return Ok(String::new());
        }
        std::fs::create_dir_all(&self.dir).map_err(|e| format!("Could not create the backup folder: {e}"))?;
        let ok = hidden("reg.exe").arg("export").arg(key).arg(self.dir.join(&name)).arg("/y").status().is_ok_and(|s| s.success());
        if ok {
            self.count += 1;
            Ok(name)
        } else {
            Err("Could not back up this registry key, so it was left untouched.".into())
        }
    }

    fn file_slot(&mut self, ext: &str) -> Result<(String, PathBuf), String> {
        std::fs::create_dir_all(&self.dir).map_err(|e| format!("Could not create the backup folder: {e}"))?;
        self.count += 1;
        let name = format!("{:03}.{ext}", self.count);
        let path = self.dir.join(&name);
        Ok((name, path))
    }

    fn has_undo(&self) -> bool {
        let m = &self.manifest;
        !(m.registry.is_empty() && m.tasks.is_empty() && m.files.is_empty())
    }
}

fn result(id: &str, r: Result<bool, String>) -> ItemResult {
    match r {
        Ok(pending) => ItemResult {
            id: id.into(),
            ok: true,
            message: pending.then(|| "In use; it will be deleted when Windows restarts.".into()),
            pending_reboot: pending,
        },
        Err(e) => ItemResult { id: id.into(), ok: false, message: Some(e), pending_reboot: false },
    }
}

fn access_hint(e: std::io::Error) -> String {
    if e.kind() == std::io::ErrorKind::PermissionDenied {
        "Access denied. Restart PuirkleUninstaller as administrator and try again.".into()
    } else {
        e.to_string()
    }
}

pub fn delete(items: Vec<Leftover>, recycle: bool, program: String) -> Report {
    let now = chrono::Local::now();
    let id = now.format("%Y-%m-%d_%H-%M-%S").to_string();
    let mut backup = Backup {
        dir: backup_root().join(&id),
        count: 0,
        exported: HashSet::new(),
        manifest: Manifest { program, created_at: now.format("%Y-%m-%d %H:%M:%S").to_string(), ..Default::default() },
    };
    let mut results = Vec::new();

    // Anything still running from a folder we are about to delete would keep files locked.
    let folders: Vec<String> = items
        .iter()
        .filter(|i| i.kind == "folder" || (i.kind == "file" && i.path.to_lowercase().ends_with(".exe")))
        .map(|i| i.path.to_lowercase())
        .collect();
    let closed_processes = winproc::kill_in_dirs(&folders);

    for it in items.iter().filter(|i| i.kind == "service") {
        results.push(result(&it.id, delete_service(it, &mut backup)));
    }
    for it in items.iter().filter(|i| i.kind == "task") {
        results.push(result(&it.id, delete_task(it, &mut backup)));
    }
    for it in items.iter().filter(|i| i.kind == "regvalue") {
        results.push(result(&it.id, delete_value(it, &mut backup)));
    }
    let mut keys: Vec<&Leftover> = items.iter().filter(|i| i.kind == "regkey").collect();
    keys.sort_by_key(|k| std::cmp::Reverse(k.path.len()));
    for it in keys {
        results.push(result(&it.id, delete_key(&it.path, &mut backup)));
    }
    let mut freed = 0;
    for it in items.iter().filter(|i| matches!(i.kind.as_str(), "folder" | "file" | "shortcut")) {
        let r = delete_path(Path::new(&it.path), recycle);
        if let Ok(removed) = &r {
            freed += it.size_bytes;
            crate::storage::forget(&it.path, it.size_bytes);
            if *removed == Removed::Recycled {
                backup.manifest.files.push(it.path.clone());
            }
        }
        results.push(result(&it.id, r.map(|removed| removed == Removed::Pending)));
    }

    let session_id = (backup.has_undo() && rollback::save(&backup.dir, &backup.manifest).is_ok()).then_some(id);
    Report {
        results,
        backup_dir: (backup.count > 0 || session_id.is_some()).then(|| backup.dir.to_string_lossy().into_owned()),
        session_id,
        freed_bytes: freed,
        closed_processes,
    }
}

fn delete_service(it: &Leftover, backup: &mut Backup) -> Result<bool, String> {
    let name = it.name.as_deref().ok_or("Missing service name.")?;
    if !reg::exists(&it.path) {
        return Ok(false);
    }
    let file = backup.export(&it.path)?;
    let _ = hidden("sc.exe").args(["stop", name]).status();
    std::thread::sleep(std::time::Duration::from_millis(800));
    let out = hidden("sc.exe").args(["delete", name]).output().map_err(|e| e.to_string())?;
    let r = if out.status.success() {
        Ok(false)
    } else {
        // Fall back to removing the service key directly; Windows drops it on the next restart.
        let (root, sub) = reg::split(&it.path);
        reg::hive(root).delete_subkey_all(sub).map(|_| true).map_err(|_| {
            let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if text.contains("5:") || text.to_lowercase().contains("access") {
                "Access denied. Restart PuirkleUninstaller as administrator to remove services.".into()
            } else {
                format!("Could not delete the service: {text}")
            }
        })
    };
    if r.is_ok() && !file.is_empty() {
        backup.manifest.registry.push(RegEntry::key(&it.path, file));
    }
    r
}

fn delete_task(it: &Leftover, backup: &mut Backup) -> Result<bool, String> {
    let name = it.name.as_deref().ok_or("Missing task name.")?;
    // Keep the task definition so it can be re-created on rollback.
    let saved = match std::fs::read(&it.path) {
        Ok(xml) => {
            let (file, path) = backup.file_slot("xml")?;
            std::fs::write(&path, xml).ok().map(|_| file)
        }
        Err(_) => None,
    };
    let out = hidden("schtasks.exe").args(["/Delete", "/TN", name, "/F"]).output().map_err(|e| e.to_string())?;
    let r = if out.status.success() || !Path::new(&it.path).exists() {
        Ok(false)
    } else {
        std::fs::remove_file(&it.path).map(|_| false).map_err(access_hint)
    };
    if let (Ok(_), Some(file)) = (&r, saved) {
        backup.manifest.tasks.push(TaskEntry { name: name.into(), file });
    }
    r
}

fn delete_value(it: &Leftover, backup: &mut Backup) -> Result<bool, String> {
    let value = it.value_name.as_deref().ok_or("Missing value name.")?;
    let (root, sub) = reg::split(&it.path);
    let Ok(key) = reg::hive(root).open_subkey_with_flags(sub, winreg::enums::KEY_SET_VALUE | winreg::enums::KEY_QUERY_VALUE) else {
        if reg::exists(&it.path) {
            return Err("Access denied. Restart PuirkleUninstaller as administrator and try again.".into());
        }
        return Ok(false);
    };
    let Ok(raw) = key.get_raw_value(value) else { return Ok(false) };
    backup.export(&it.path)?;
    key.delete_value(value).map_err(access_hint)?;
    backup.manifest.registry.push(RegEntry::value(&it.path, value, &raw));
    Ok(false)
}

fn delete_key(path: &str, backup: &mut Backup) -> Result<bool, String> {
    if !reg::exists(path) {
        return Ok(false);
    }
    let file = backup.export(path)?;
    let (root, sub) = reg::split(path);
    reg::hive(root).delete_subkey_all(sub).map_err(access_hint)?;
    if !file.is_empty() {
        backup.manifest.registry.push(RegEntry::key(path, file));
    }
    Ok(false)
}

#[derive(PartialEq)]
enum Removed {
    Recycled,
    Deleted,
    Pending,
}

fn delete_path(p: &Path, recycle: bool) -> Result<Removed, String> {
    if !p.exists() {
        return Ok(Removed::Deleted);
    }
    if recycle && trash::delete(p).is_ok() {
        return Ok(Removed::Recycled);
    }
    let attempt = |p: &Path| if p.is_dir() { std::fs::remove_dir_all(p) } else { std::fs::remove_file(p) };
    if attempt(p).is_ok() {
        return Ok(Removed::Deleted);
    }
    clear_readonly(p);
    match attempt(p) {
        Ok(()) => Ok(Removed::Deleted),
        Err(_) if !p.exists() => Ok(Removed::Deleted),
        Err(e) => {
            if schedule_on_reboot(p) {
                Ok(Removed::Pending)
            } else {
                Err(access_hint(e))
            }
        }
    }
}

fn clear_readonly(p: &Path) {
    for e in walkdir::WalkDir::new(p).into_iter().filter_map(Result::ok) {
        let w = wide(&e.path().to_string_lossy());
        unsafe { SetFileAttributesW(w.as_ptr(), FILE_ATTRIBUTE_NORMAL) };
    }
}

/// Marks whatever is left under `p` for deletion at the next boot (needs administrator rights).
fn schedule_on_reboot(p: &Path) -> bool {
    let mut all_ok = true;
    for e in walkdir::WalkDir::new(p).contents_first(true).into_iter().filter_map(Result::ok) {
        let w = wide(&e.path().to_string_lossy());
        all_ok &= unsafe { MoveFileExW(w.as_ptr(), null(), MOVEFILE_DELAY_UNTIL_REBOOT) } != 0;
    }
    all_ok
}

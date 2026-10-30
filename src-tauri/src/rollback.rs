//! Rollback of cleanups. Each cleanup session writes a manifest next to its backups listing what
//! was removed: registry keys (JSON trees, or .reg exports from older versions; see `regbackup`),
//! registry values (exact data), scheduled tasks
//! (their XML) and files moved to the Recycle Bin. Restoring puts all of it back.

use crate::regbackup::reg_type;
use crate::{cleanup, reg};
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use winreg::RegValue;

const MANIFEST: &str = "manifest.json";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Manifest {
    pub program: String,
    pub created_at: String,
    #[serde(default)]
    pub registry: Vec<RegEntry>,
    #[serde(default)]
    pub tasks: Vec<TaskEntry>,
    /// Paths moved to the Recycle Bin.
    #[serde(default)]
    pub files: Vec<String>,
    #[serde(default)]
    pub restored_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegEntry {
    /// "key" (restored from `file`), "value" (restored from `vtype` + `data`)
    pub kind: String,
    pub path: String,
    #[serde(default)]
    pub file: Option<String>,
    #[serde(default)]
    pub value_name: Option<String>,
    #[serde(default)]
    pub vtype: Option<u32>,
    /// base64 of the raw value bytes
    #[serde(default)]
    pub data: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskEntry {
    pub name: String,
    pub file: String,
}

impl RegEntry {
    pub fn key(path: &str, file: String) -> Self {
        RegEntry { kind: "key".into(), path: path.into(), file: Some(file), value_name: None, vtype: None, data: None }
    }

    pub fn value(path: &str, name: &str, v: &RegValue) -> Self {
        RegEntry {
            kind: "value".into(),
            path: path.into(),
            file: None,
            value_name: Some(name.into()),
            vtype: Some(v.vtype.clone() as u32),
            data: Some(base64::engine::general_purpose::STANDARD.encode(&v.bytes)),
        }
    }
}

/// A cleanup session as shown in the Backups list.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Session {
    pub id: String,
    pub path: String,
    pub program: String,
    pub created_at: String,
    pub registry_count: usize,
    pub task_count: usize,
    pub file_count: usize,
    pub restored_at: Option<String>,
    /// First few things it removed, for display.
    pub preview: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RestoreReport {
    pub restored: usize,
    pub failed: Vec<String>,
}

pub fn save(dir: &Path, m: &Manifest) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let json = serde_json::to_string_pretty(m).map_err(|e| e.to_string())?;
    std::fs::write(dir.join(MANIFEST), json).map_err(|e| e.to_string())
}

fn load(dir: &Path) -> Option<Manifest> {
    if let Ok(text) = std::fs::read_to_string(dir.join(MANIFEST)) {
        return serde_json::from_str(&text).ok();
    }
    // Backups made before manifests existed: just the .reg exports.
    let mut regs: Vec<PathBuf> = std::fs::read_dir(dir)
        .ok()?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x.eq_ignore_ascii_case("reg")))
        .collect();
    if regs.is_empty() {
        return None;
    }
    regs.sort();
    let registry = regs
        .iter()
        .map(|p| RegEntry::key(&reg_file_key(p).unwrap_or_default(), p.file_name().unwrap().to_string_lossy().into_owned()))
        .collect();
    Some(Manifest {
        program: "Earlier cleanup".into(),
        created_at: dir.file_name().map(|n| n.to_string_lossy().replacen('_', " ", 1).replace('-', ":")).unwrap_or_default(),
        registry,
        ..Default::default()
    })
}

/// First key named in a .reg export (UTF-16 text), e.g. "HKEY_CURRENT_USER\Software\Foo".
fn reg_file_key(path: &Path) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    let units: Vec<u16> = bytes.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    let text = String::from_utf16_lossy(&units);
    let line = text.lines().find(|l| l.starts_with('['))?;
    Some(line.trim_matches(['[', ']', '\r']).to_string())
}

pub fn list() -> Vec<Session> {
    let root = cleanup::backup_root();
    let Ok(rd) = std::fs::read_dir(&root) else { return Vec::new() };
    let mut sessions: Vec<Session> = rd
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .filter_map(|e| {
            let m = load(&e.path())?;
            let mut preview: Vec<String> = m.files.iter().cloned().collect();
            preview.extend(m.tasks.iter().map(|t| format!("Task {}", t.name)));
            preview.extend(m.registry.iter().map(|r| match &r.value_name {
                Some(v) => format!("{}  →  {v}", r.path),
                None => r.path.clone(),
            }));
            preview.truncate(6);
            Some(Session {
                id: e.file_name().to_string_lossy().into_owned(),
                path: e.path().to_string_lossy().into_owned(),
                program: m.program,
                created_at: m.created_at,
                registry_count: m.registry.len(),
                task_count: m.tasks.len(),
                file_count: m.files.len(),
                restored_at: m.restored_at,
                preview,
            })
        })
        .collect();
    sessions.sort_by(|a, b| b.id.cmp(&a.id)); // folder names are timestamps
    sessions
}

fn session_dir(id: &str) -> Result<PathBuf, String> {
    if id.is_empty() || id.contains(['\\', '/', ':']) || id.contains("..") {
        return Err("Invalid backup id.".into());
    }
    let dir = cleanup::backup_root().join(id);
    if dir.is_dir() {
        Ok(dir)
    } else {
        Err("That backup no longer exists.".into())
    }
}

pub fn restore(id: &str) -> Result<RestoreReport, String> {
    let dir = session_dir(id)?;
    let mut m = load(&dir).ok_or("This backup has nothing to restore.")?;
    let mut restored = 0;
    let mut failed = Vec::new();

    // Registry keys first, then values (a value may live in a key that was removed too).
    for e in m.registry.iter().filter(|e| e.kind == "key") {
        let Some(file) = &e.file else { continue };
        match crate::regbackup::restore(&dir.join(file)) {
            Ok(()) => restored += 1,
            Err(err) => failed.push(format!("{}: {err}", e.path)),
        }
    }
    for e in m.registry.iter().filter(|e| e.kind == "value") {
        let (Some(name), Some(vtype), Some(data)) = (&e.value_name, e.vtype, &e.data) else { continue };
        let bytes = base64::engine::general_purpose::STANDARD.decode(data).unwrap_or_default();
        let (root, sub) = reg::split(&e.path);
        let r = reg::hive(root)
            .create_subkey(sub)
            .and_then(|(key, _)| key.set_raw_value(name, &RegValue { bytes, vtype: reg_type(vtype) }));
        match r {
            Ok(()) => restored += 1,
            Err(err) => failed.push(format!("{} → {name}: {err}", e.path)),
        }
    }
    for t in &m.tasks {
        match crate::sysitems::register_task(&t.name, &dir.join(&t.file)) {
            Ok(()) => restored += 1,
            Err(err) => failed.push(format!("Task {}: {err}", t.name)),
        }
    }
    if !m.files.is_empty() {
        let (n, errs) = restore_files(&m.files);
        restored += n;
        failed.extend(errs);
    }

    m.restored_at = Some(chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string());
    let _ = save(&dir, &m);
    Ok(RestoreReport { restored, failed })
}

/// Moves files and folders back out of the Recycle Bin to where they were.
fn restore_files(paths: &[String]) -> (usize, Vec<String>) {
    let items = match trash::os_limited::list() {
        Ok(items) => items,
        Err(e) => return (0, vec![format!("Could not read the Recycle Bin: {e}")]),
    };
    let mut picked = Vec::new();
    let mut failed = Vec::new();
    for p in paths {
        let want = p.to_lowercase();
        if Path::new(p).exists() {
            failed.push(format!("{p}: something already exists there, so it was left in the Recycle Bin"));
            continue;
        }
        let best = items
            .iter()
            .filter(|it| it.original_parent.join(PathBuf::from(&it.name)).to_string_lossy().to_lowercase() == want)
            .max_by_key(|it| it.time_deleted);
        match best {
            Some(it) => picked.push(it.clone()),
            None => failed.push(format!("{p}: not in the Recycle Bin any more (it may have been emptied)")),
        }
    }
    let n = picked.len();
    if n == 0 {
        return (0, failed);
    }
    match trash::os_limited::restore_all(picked) {
        Ok(()) => (n, failed),
        Err(e) => {
            failed.push(format!("Restoring from the Recycle Bin failed: {e}"));
            (0, failed)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::leftovers::Leftover;

    fn item(kind: &str, path: &str, value: Option<&str>) -> Leftover {
        Leftover {
            id: format!("{kind}|{path}|{}", value.unwrap_or("")),
            kind: kind.into(),
            path: path.into(),
            value_name: value.map(Into::into),
            name: None,
            size_bytes: 0,
            confidence: "high".into(),
            reason: "test".into(),
        }
    }

    /// Removes throwaway test data through the real cleanup code, then rolls it back.
    /// Touches only HKCU\Software\PuirkleUninstallerRollbackTest and a temp folder.
    /// `cargo test rollback_round_trip -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn rollback_round_trip() {
        let hkcu = winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER);
        let (k, _) = hkcu.create_subkey(r"Software\PuirkleUninstallerRollbackTest\Settings").unwrap();
        k.set_value("Theme", &"dark").unwrap();
        k.set_value("Launches", &42u32).unwrap();
        let (run, _) = hkcu.create_subkey(r"Software\PuirkleUninstallerRollbackTest\Run").unwrap();
        run.set_value("Tray", &r#""C:\Test\tray.exe" --min"#).unwrap();
        let dir = std::env::temp_dir().join("PuirkleRollbackTest");
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::write(dir.join("sub").join("save.dat"), b"precious").unwrap();

        let items = vec![
            item("regkey", r"HKCU\Software\PuirkleUninstallerRollbackTest\Settings", None),
            item("regvalue", r"HKCU\Software\PuirkleUninstallerRollbackTest\Run", Some("Tray")),
            item("folder", &dir.to_string_lossy(), None),
        ];
        let report = crate::cleanup::delete(items, true, "Rollback self-test".into());
        assert!(report.results.iter().all(|r| r.ok), "cleanup failed");
        assert!(hkcu.open_subkey(r"Software\PuirkleUninstallerRollbackTest\Settings").is_err());
        assert!(run.get_raw_value("Tray").is_err());
        assert!(!dir.exists());
        let id = report.session_id.expect("session recorded");
        println!("removed; session {id}");

        let r = super::restore(&id).unwrap();
        println!("restored {} item(s), failed: {:?}", r.restored, r.failed);
        let k = hkcu.open_subkey(r"Software\PuirkleUninstallerRollbackTest\Settings").expect("key restored");
        assert_eq!(k.get_value::<String, _>("Theme").unwrap(), "dark");
        assert_eq!(k.get_value::<u32, _>("Launches").unwrap(), 42);
        assert_eq!(run.get_value::<String, _>("Tray").unwrap(), r#""C:\Test\tray.exe" --min"#);
        assert_eq!(std::fs::read(dir.join("sub").join("save.dat")).unwrap(), b"precious");
        assert!(super::list().iter().any(|s| s.id == id && s.restored_at.is_some()));

        // Clean up the test data and its backup.
        hkcu.delete_subkey_all(r"Software\PuirkleUninstallerRollbackTest").unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        super::delete(&id).unwrap();
        println!("round trip OK");
    }
}

/// Deletes a backup permanently (the user confirmed in the UI).
pub fn delete(id: &str) -> Result<(), String> {
    let dir = session_dir(id)?;
    std::fs::remove_dir_all(dir).map_err(|e| e.to_string())
}

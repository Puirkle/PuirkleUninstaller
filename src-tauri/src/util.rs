use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// A `Command` that never flashes a console window.
pub fn hidden(program: &str) -> Command {
    let mut c = Command::new(program);
    c.creation_flags(CREATE_NO_WINDOW);
    c
}

/// Runs a PowerShell script via -EncodedCommand so quoting never gets in the way.
pub fn powershell(script: &str) -> Result<String, String> {
    use base64::Engine;
    let utf16: Vec<u8> = script.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    let encoded = base64::engine::general_purpose::STANDARD.encode(utf16);
    let out = hidden("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", &encoded])
        .output()
        .map_err(|e| format!("Could not start PowerShell: {e}"))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
        Err(if err.is_empty() { "PowerShell command failed.".into() } else { err })
    }
}

pub fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

pub fn from_wide(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

/// Lowercase alphanumerics only: "Notepad++ (x64)" -> "notepadx64".
pub fn normalize(s: &str) -> String {
    s.chars().filter(|c| c.is_alphanumeric()).flat_map(char::to_lowercase).collect()
}

/// Roots of all local fixed disks, e.g. `C:\`, `D:\`.
pub fn fixed_drives() -> Vec<PathBuf> {
    const DRIVE_FIXED: u32 = 3;
    let mask = unsafe { windows_sys::Win32::Storage::FileSystem::GetLogicalDrives() };
    (0..26u8)
        .filter(|i| mask & (1 << i) != 0)
        .map(|i| format!("{}:\\", (b'A' + i) as char))
        .filter(|root| unsafe { windows_sys::Win32::Storage::FileSystem::GetDriveTypeW(wide(root).as_ptr()) } == DRIVE_FIXED)
        .map(PathBuf::from)
        .collect()
}

pub fn env_dir(var: &str) -> Option<PathBuf> {
    std::env::var_os(var).map(PathBuf::from).filter(|p| p.is_dir())
}

/// Expands `%VAR%` references; unknown variables are left untouched.
pub fn expand_env(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(start) = rest.find('%') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        match after.find('%') {
            Some(end) => {
                let var = &after[..end];
                match std::env::var(var) {
                    Ok(v) if !var.is_empty() => out.push_str(&v),
                    _ => {
                        out.push('%');
                        out.push_str(var);
                        out.push('%');
                    }
                }
                rest = &after[end + 1..];
            }
            None => {
                out.push_str(&rest[start..]);
                rest = "";
            }
        }
    }
    out.push_str(rest);
    out
}

/// Strips quotes, whitespace and trailing separators, and expands environment variables.
pub fn clean_path(s: &str) -> String {
    let e = expand_env(s.trim().trim_matches('"').trim()).replace('/', "\\");
    let t = e.trim_end_matches('\\');
    if t.len() == 2 && t.ends_with(':') {
        format!("{t}\\")
    } else {
        t.to_string()
    }
}

pub fn lower_path(p: &str) -> String {
    clean_path(p).to_lowercase()
}

/// True if `text` (lowercase) mentions `dir` (lowercase) as a whole path, i.e. the match
/// is followed by a separator, quote, delimiter or the end of the text.
pub fn mentions_path(text: &str, dir: &str) -> bool {
    if dir.is_empty() {
        return false;
    }
    let mut from = 0;
    while let Some(i) = text[from..].find(dir) {
        let end = from + i + dir.len();
        match text[end..].chars().next() {
            None | Some('\\' | '"' | ' ' | ',' | ';' | '|' | '\0') => return true,
            _ => {}
        }
        from = end;
    }
    false
}

pub fn dir_size(p: &Path) -> u64 {
    if p.is_file() {
        return p.metadata().map(|m| m.len()).unwrap_or(0);
    }
    // Instant when the drive was scanned (at startup); waits for a scan that's still running.
    if let Some(size) = crate::storage::cached_size(&p.to_string_lossy()) {
        return size;
    }
    walkdir::WalkDir::new(p)
        .follow_links(false)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file())
        .filter_map(|e| e.metadata().ok())
        .map(|m| m.len())
        .sum()
}

/// Opens Explorer with the item selected (or the folder opened).
pub fn reveal(path: &str) -> Result<(), String> {
    let p = Path::new(path);
    let mut cmd = Command::new("explorer.exe");
    if p.is_dir() {
        cmd.arg(path);
    } else if p.exists() {
        cmd.raw_arg(format!("/select,\"{path}\""));
    } else {
        return Err(format!("{path} no longer exists."));
    }
    cmd.spawn().map(|_| ()).map_err(|e| e.to_string())
}

/// Opens regedit at `key` (e.g. `HKLM\SOFTWARE\Foo`) by seeding its LastKey setting.
pub fn open_regedit(key: &str) -> Result<(), String> {
    let (root, rest) = key.split_once('\\').unwrap_or((key, ""));
    let long = match root {
        "HKLM" => "HKEY_LOCAL_MACHINE",
        "HKCU" => "HKEY_CURRENT_USER",
        "HKCR" => "HKEY_CLASSES_ROOT",
        "HKU" => "HKEY_USERS",
        other => other,
    };
    let target = if rest.is_empty() { format!("Computer\\{long}") } else { format!("Computer\\{long}\\{rest}") };
    let hkcu = winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER);
    let (applet, _) = hkcu
        .create_subkey(r"Software\Microsoft\Windows\CurrentVersion\Applets\Regedit")
        .map_err(|e| e.to_string())?;
    applet.set_value("LastKey", &target).map_err(|e| e.to_string())?;
    // -m allows a second instance, so it navigates even if regedit is already open.
    crate::winproc::shell_execute(None, "regedit.exe", "-m")
}

pub fn date_from_system_time(t: std::time::SystemTime) -> String {
    chrono::DateTime::<chrono::Local>::from(t).format("%Y-%m-%d").to_string()
}

//! Finds software that is on disk but not registered with Windows: portable apps, unpacked or
//! copied games, Steam library games, leftovers of programs whose uninstall entry is gone.
//! Looks at every fixed drive: drive roots, Program Files folders, game containers and Steam libraries.

use crate::leftovers;
use crate::programs::{self, Program};
use crate::util::{date_from_system_time, fixed_drives, from_wide, normalize, wide};
use std::ffi::c_void;
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::ptr::null_mut;
use windows_sys::Win32::Storage::FileSystem::{GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW};

/// Folders that are never programs, wherever they appear.
const SKIP_NAMES: &[&str] = &[
    "windows", "program files", "program files (x86)", "programdata", "users", "perflogs", "recovery",
    "system volume information", "windowsapps", "wpsystem", "xboxgames", "msdownld.tmp", "config.msi", "intel",
    "amd", "nvidia", "inetpub", "esd", "temp", "tmp", "onedrivetemp", "documents and settings", "boot", "msocache",
    "drivers", "$recycle.bin", "$windows.~ws", "$windows.~bt", "$getcurrent", "$sysreset", "$winreagent",
];

/// Windows components that live in Program Files without an uninstall entry.
const SKIP_IN_PROGRAM_FILES: &[&str] = &[
    "common files", "internet explorer", "reference assemblies", "msbuild", "uninstall information",
    "modifiablewindowsapps", "dotnet", "iis", "iis express", "package cache", "windowspowershell", "windows nt",
    "microsoft.net", "msecache", "installshield installation information",
];

/// Executables that are never the program's main executable.
const NOT_MAIN_EXE: &[&str] = &[
    "unins", "uninst", "setup", "install", "crash", "vcredist", "vc_redist", "dxsetup", "dxwebsetup", "dotnet",
    "unitycrashhandler", "update", "updater", "helper", "notification_helper", "cefsharp", "redist", "oalinst",
    "physx", "ue4prereq", "ueprereq", "easyanticheat", "be_service", "battleye", "7z", "elevate", "cmd",
];

/// Subfolders whose executables are installers or runtimes, not the program.
const REDIST_DIRS: &[&str] = &["_commonredist", "redist", "redistributables", "__installer", "directx", "vcredist", "support", "prereq", "prerequisites", "installers"];

/// Markers of a source-code checkout or build output rather than an installed program.
const SOURCE_MARKERS: &[&str] = &[
    ".git", "cargo.toml", "package.json", "pom.xml", "build.gradle", "cmakelists.txt", "pyproject.toml", ".vscode",
    "node_modules", "go.mod", "makefile", ".idea", "cachedir.tag", ".rustc_info.json",
];

/// Folders that hold user files or downloads, not installed programs.
const USER_FOLDERS: &[&str] = &["download", "downloads", "restore", "backup", "backups", "debug", "release", "target", "obj", "build"];

/// Folder names that just group other programs (always look inside).
const CONTAINER_NAMES: &[&str] = &[
    "games", "game", "apps", "programs", "tools", "software", "output", "portable", "portableapps", "emulators", "mods",
];

/// Subfolder names that are parts of one program, so a folder holding them is that program,
/// not a container of several programs.
const PART_NAMES: &[&str] = &[
    "launcher", "client", "bin", "bin64", "binaries", "game", "app", "data", "engine", "tools", "update", "updater",
    "x64", "x86", "win64", "win32", "common", "support", "plugins", "server", "runtime", "jre", "java", "lib",
    "services", "service", "drivers", "driver",
];

/// Executable names that mark an installer rather than the program (matched anywhere in the name).
const INSTALLER_WORDS: &[&str] = &["setup", "installer", "uninst", "unins", "vcredist", "redist"];

struct Finder<'a> {
    registered_dirs: &'a [String],
    /// Keywords of registered programs, to avoid listing them twice when their folder isn't recorded.
    registered_names: &'a std::collections::HashSet<String>,
    found: Vec<Program>,
}

pub fn discover() -> Vec<Program> {
    let registered = programs::list_win32();
    let registered_dirs = leftovers::all_program_dirs(&registered);
    let registered_names: std::collections::HashSet<String> = registered.iter().flat_map(leftovers::program_keywords).collect();
    // One thread per drive: hard disks are slow to list and independent of each other.
    let mut found: Vec<Program> = std::thread::scope(|s| {
        let handles: Vec<_> = fixed_drives()
            .into_iter()
            .map(|drive| {
                let (dirs, names) = (&registered_dirs, &registered_names);
                s.spawn(move || {
                    let mut f = Finder { registered_dirs: dirs, registered_names: names, found: Vec::new() };
                    f.scan_drive(&drive);
                    f.found
                })
            })
            .collect();
        handles.into_iter().flat_map(|h| h.join().unwrap_or_default()).collect()
    });
    found.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    found
}

fn leaf(p: &Path) -> String {
    p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()
}

/// Real (non-hidden, non-system, non-junction) subfolders.
fn child_dirs(dir: &Path) -> Vec<PathBuf> {
    let Ok(rd) = std::fs::read_dir(dir) else { return Vec::new() };
    rd.filter_map(Result::ok)
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .filter(|e| e.metadata().is_ok_and(|m| m.file_attributes() & 0x6 == 0)) // HIDDEN | SYSTEM
        .map(|e| e.path())
        .collect()
}

fn steam_common(dir: &Path) -> Option<PathBuf> {
    let common = dir.join(r"steamapps\common");
    common.is_dir().then_some(common)
}

fn looks_like_source(dir: &Path) -> bool {
    let Ok(rd) = std::fs::read_dir(dir) else { return false };
    rd.filter_map(Result::ok).any(|e| {
        let n = e.file_name().to_string_lossy().to_lowercase();
        SOURCE_MARKERS.contains(&n.as_str()) || n.ends_with(".sln") || n.ends_with(".csproj")
    })
}

impl Finder<'_> {
    fn scan_drive(&mut self, drive: &Path) {
        for pf in ["Program Files", "Program Files (x86)"] {
            for dir in child_dirs(&drive.join(pf)) {
                let name = leaf(&dir).to_lowercase();
                if SKIP_IN_PROGRAM_FILES.contains(&name.as_str()) || name.starts_with("windows") || name.starts_with("microsoft") {
                    continue;
                }
                self.consider(&dir, true);
            }
        }
        for dir in child_dirs(drive) {
            self.consider(&dir, true);
        }
    }

    fn consider(&mut self, dir: &Path, can_descend: bool) {
        let name = leaf(dir);
        let lname = name.to_lowercase();
        if SKIP_NAMES.contains(&lname.as_str())
            || USER_FOLDERS.contains(&lname.as_str())
            || REDIST_DIRS.contains(&lname.as_str())
            || lname.starts_with('$')
            || lname.starts_with('_')
            || lname.starts_with("found.")
            || lname.starts_with("recovery_")
        {
            return;
        }
        if let Some(common) = steam_common(dir) {
            // A Steam install or library: every game folder in it is a program.
            for game in child_dirs(&common) {
                self.consider(&game, false);
            }
            return;
        }
        let l = dir.to_string_lossy().to_lowercase();
        let in_steam_library = l.contains(r"\steamapps\common\");
        if self.registered_dirs.iter().any(|r| *r == l || leftovers::inside_other(&l, r)) {
            return; // already listed as an installed program
        }
        if looks_like_source(dir) {
            return;
        }
        let holds_registered = self.registered_dirs.iter().any(|r| r.starts_with(&format!("{l}\\")));
        let top_exe = main_exe(dir, 1);
        let norm = normalize(&name);
        if !holds_registered && top_exe.is_none() && can_descend {
            // D:\Games, C:\Program Files\Blackmagic Design…: several programs side by side.
            let with_exe: Vec<PathBuf> = child_dirs(dir)
                .into_iter()
                .filter(|c| {
                    let n = leaf(c).to_lowercase();
                    !n.starts_with('_') && !REDIST_DIRS.contains(&n.as_str())
                })
                .filter(|c| main_exe(c, 2).is_some())
                .collect();
            let parts_of_one = with_exe.iter().any(|c| PART_NAMES.contains(&normalize(&leaf(c)).as_str()));
            // A publisher folder holding a single program (Blackmagic Design\DaVinci Resolve) is named
            // after that program; several programs side by side make it a container.
            let is_container = CONTAINER_NAMES.contains(&norm.as_str()) || (!with_exe.is_empty() && !parts_of_one);
            if is_container {
                for child in with_exe {
                    self.consider(&child, false);
                }
                return;
            }
        }
        if !holds_registered {
            if let Some(exe) = top_exe.or_else(|| main_exe(dir, 2)) {
                if !in_steam_library && self.is_registered_name(&norm, &exe) {
                    return; // a registered program whose uninstall entry doesn't record its folder
                }
                self.found.push(make_program(dir, &exe, in_steam_library));
                return;
            }
        }
        if can_descend {
            for child in child_dirs(dir) {
                self.consider(&child, false);
            }
        }
    }

    fn is_registered_name(&self, folder: &str, exe: &Path) -> bool {
        let stem = normalize(&exe.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default());
        (folder.len() >= 4 && self.registered_names.contains(folder)) || (stem.len() >= 4 && self.registered_names.contains(&stem))
    }
}

/// The folder's main executable within `depth` levels: named like the folder if possible,
/// near the top, the biggest.
fn main_exe(dir: &Path, depth: usize) -> Option<PathBuf> {
    let folder = normalize(&leaf(dir));
    let mut best: Option<(u32, u64, PathBuf)> = None;
    let walker = walkdir::WalkDir::new(dir).max_depth(depth).into_iter().filter_entry(|e| {
        e.depth() == 0 || !e.file_type().is_dir() || !REDIST_DIRS.contains(&e.file_name().to_string_lossy().to_lowercase().as_str())
    });
    for e in walker.filter_map(Result::ok) {
        if !e.file_type().is_file() {
            continue;
        }
        let path = e.path();
        if !path.extension().is_some_and(|x| x.eq_ignore_ascii_case("exe")) {
            continue;
        }
        let stem = normalize(&path.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default());
        if stem.is_empty() || NOT_MAIN_EXE.iter().any(|n| stem.starts_with(n)) || INSTALLER_WORDS.iter().any(|w| stem.contains(w)) {
            continue;
        }
        let size = e.metadata().map(|m| m.len()).unwrap_or(0);
        if size < 20 * 1024 {
            continue; // stubs and tiny tools
        }
        let name_score = if stem == folder {
            3
        } else if stem.len() >= 3 && (folder.contains(&stem) || stem.contains(&folder)) {
            2
        } else {
            0
        };
        let score = name_score * 2 + if e.depth() == 1 { 1 } else { 0 };
        let better = match &best {
            None => true,
            Some((s, sz, _)) => score > *s || (score == *s && size > *sz),
        };
        if better {
            best = Some((score, size, path.to_path_buf()));
        }
    }
    best.map(|(_, _, p)| p)
}

fn make_program(dir: &Path, exe: &Path, steam: bool) -> Program {
    let path = dir.to_string_lossy().into_owned();
    let (company, version) = version_info(&exe.to_string_lossy());
    let install_date = std::fs::metadata(dir).ok().and_then(|m| m.created().or_else(|_| m.modified()).ok()).map(date_from_system_time);
    Program {
        id: format!("dir:{path}"),
        kind: "portable".into(),
        name: leaf(dir),
        version,
        publisher: company,
        install_location: Some(path),
        install_date,
        size_bytes: None,
        uninstall_string: None,
        quiet_uninstall_string: None,
        icon_path: Some(exe.to_string_lossy().into_owned()),
        product_code: None,
        registry_key: None,
        scope: "machine".into(),
        arch: if steam { "Steam library".into() } else { String::new() },
        system_component: false,
        package_full_name: None,
        package_family_name: None,
    }
}

/// CompanyName and ProductVersion from an executable's version resource.
fn version_info(path: &str) -> (Option<String>, Option<String>) {
    let w = wide(path);
    let mut handle = 0u32;
    let size = unsafe { GetFileVersionInfoSizeW(w.as_ptr(), &mut handle) };
    if size == 0 {
        return (None, None);
    }
    let mut buf = vec![0u8; size as usize];
    if unsafe { GetFileVersionInfoW(w.as_ptr(), 0, size, buf.as_mut_ptr() as *mut c_void) } == 0 {
        return (None, None);
    }
    let mut langs: Vec<String> = Vec::new();
    let mut ptr: *mut c_void = null_mut();
    let mut len = 0u32;
    let translation = wide(r"\VarFileInfo\Translation");
    if unsafe { VerQueryValueW(buf.as_ptr() as *const c_void, translation.as_ptr(), &mut ptr, &mut len) } != 0 && len >= 4 {
        let pairs = unsafe { std::slice::from_raw_parts(ptr as *const u16, (len / 2) as usize) };
        langs.extend(pairs.chunks_exact(2).map(|c| format!("{:04x}{:04x}", c[0], c[1])));
    }
    langs.extend(["040904b0".to_string(), "040904e4".to_string(), "000004b0".to_string()]);
    let get = |key: &str| langs.iter().find_map(|lang| query(&buf, lang, key));
    let company = get("CompanyName");
    let version = get("ProductVersion").or_else(|| get("FileVersion")).map(|v| v.replace(", ", "."));
    (company, version)
}

#[cfg(test)]
mod tests {
    /// Read-only: `cargo test discover_dry_run -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn discover_dry_run() {
        let t = std::time::Instant::now();
        let found = super::discover();
        for p in &found {
            println!("{:<45} {:<28} {:<16} {}", p.name, p.publisher.as_deref().unwrap_or("-"), p.arch, p.icon_path.as_deref().unwrap_or("-"));
        }
        println!("{} programs found in {} ms", found.len(), t.elapsed().as_millis());
    }
}

fn query(buf: &[u8], lang: &str, key: &str) -> Option<String> {
    let sub = wide(&format!(r"\StringFileInfo\{lang}\{key}"));
    let mut ptr: *mut c_void = null_mut();
    let mut len = 0u32;
    if unsafe { VerQueryValueW(buf.as_ptr() as *const c_void, sub.as_ptr(), &mut ptr, &mut len) } == 0 || len == 0 || ptr.is_null() {
        return None;
    }
    let s = unsafe { std::slice::from_raw_parts(ptr as *const u16, len as usize) };
    Some(from_wide(s).trim().to_string()).filter(|s| !s.is_empty())
}

//! Finds software that is on disk but not registered with Windows: portable apps, unpacked or
//! copied games, Steam library games, leftovers of programs whose uninstall entry is gone.
//! Looks at every fixed drive: drive roots, Program Files folders, game containers and Steam libraries.

use crate::leftovers;
use crate::programs::{self, Program};
use crate::util::{date_from_system_time, fixed_drives, from_wide, normalize, wide};
use std::collections::HashMap;
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
    let registered = programs::list_win32(false);
    let registered_dirs = leftovers::all_program_dirs(&registered);
    let registered_names: std::collections::HashSet<String> = registered.iter().flat_map(leftovers::program_keywords).collect();
    // One thread per drive (hard disks are slow to list and independent of each other), plus one
    // for the user's own folders.
    let mut found: Vec<Program> = std::thread::scope(|s| {
        let (dirs, names) = (&registered_dirs, &registered_names);
        let mut handles: Vec<_> = fixed_drives()
            .into_iter()
            .map(|drive| {
                s.spawn(move || {
                    let mut f = Finder { registered_dirs: dirs, registered_names: names, found: Vec::new() };
                    f.scan_drive(&drive);
                    f.found
                })
            })
            .collect();
        handles.push(s.spawn(move || {
            let mut f = Finder { registered_dirs: dirs, registered_names: names, found: Vec::new() };
            for folder in user_folders() {
                f.scan_user_folder(&folder);
            }
            f.found
        }));
        handles.into_iter().flat_map(|h| h.join().unwrap_or_default()).collect()
    });
    // The same exe can be reached twice (e.g. a Desktop that lives on a drive root).
    let mut seen = std::collections::HashSet::new();
    found.retain(|p| seen.insert(p.id.to_lowercase()));
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

/// Game titles from Steam's `appmanifest_*.acf` files: install folder (lowercase) -> name.
/// Games Steam has uninstalled no longer have a manifest.
fn steam_titles(steamapps: &Path) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let Ok(rd) = std::fs::read_dir(steamapps) else { return out };
    for e in rd.filter_map(Result::ok) {
        let n = e.file_name().to_string_lossy().to_lowercase();
        if !(n.starts_with("appmanifest_") && n.ends_with(".acf")) {
            continue;
        }
        let text = std::fs::read_to_string(e.path()).unwrap_or_default();
        let field = |key: &str| {
            text.lines()
                .find(|l| l.trim_start().to_lowercase().starts_with(&format!("\"{key}\"")))
                .and_then(|l| l.split('"').nth(3))
                .map(str::to_string)
        };
        if let (Some(dir), Some(name)) = (field("installdir"), field("name")) {
            out.insert(dir.to_lowercase(), name);
        }
    }
    out
}

/// Traces a game or program install leaves even when its executables are gone. Only strong,
/// specific markers count, so folders of saves, plugins or personal files are never listed.
fn has_install_traces(dir: &Path) -> bool {
    let Ok(rd) = std::fs::read_dir(dir) else { return false };
    rd.filter_map(Result::ok).any(|e| {
        let n = e.file_name().to_string_lossy().to_lowercase();
        let is_dir = e.file_type().is_ok_and(|t| t.is_dir());
        n == "steam_appid.txt"
            || (is_dir && matches!(n.as_str(), ".egstore" | "_retail_" | "_classic_" | "_ptr_" | "engine"))
            || (is_dir && n.ends_with("_data") && dir.join("UnityPlayer.dll").is_file())
    })
}

/// True if `exe` is named after the folder `folder_norm` (normalized): one name contains the
/// other, or they share a distinctive start ("xamppcontrol" / "xampp2").
fn named_after(folder_norm: &str, exe: &Path) -> bool {
    let stem = normalize(&exe.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default());
    if stem.len() < 3 || folder_norm.is_empty() {
        return false;
    }
    let shared = stem.chars().zip(folder_norm.chars()).take_while(|(a, b)| a == b).count();
    folder_norm.contains(&stem) || stem.contains(folder_norm) || shared >= 4
}

/// Executables can sit deep inside a game (e.g. `Base\Binaries\Win64\Game.exe`). A deeper
/// search only accepts an exe named after the folder, or a real program of at least 1 MB.
fn deep_exe(dir: &Path) -> Option<PathBuf> {
    let folder = normalize(&leaf(dir));
    main_exe(dir, 4).filter(|p| named_after(&folder, p) || std::fs::metadata(p).map(|m| m.len()).unwrap_or(0) >= 1024 * 1024)
}

/// Repacks often wrap a game in folders holding nothing but the next folder (plus readmes, links
/// or a `_Redist` folder): `Game\Game\Game\Game.exe`. Returns the innermost real folder.
fn unwrap_folders(dir: &Path) -> PathBuf {
    let mut cur = dir.to_path_buf();
    for _ in 0..4 {
        let subs: Vec<PathBuf> = child_dirs(&cur)
            .into_iter()
            .filter(|c| {
                let n = leaf(c).to_lowercase();
                !n.starts_with('_') && !REDIST_DIRS.contains(&n.as_str())
            })
            .collect();
        if subs.len() != 1 || main_exe(&cur, 1).is_some() {
            break;
        }
        cur = subs.into_iter().next().unwrap();
    }
    cur
}

/// A Ren'Py game: `renpy` and `game` folders side by side (here or one level down). Some come
/// without a Windows launcher exe, but they're still games taking up space.
fn is_renpy(dir: &Path) -> bool {
    let has = |d: &Path| d.join("renpy").is_dir() && d.join("game").is_dir();
    has(dir) || child_dirs(dir).iter().any(|c| has(c))
}

fn looks_like_source(dir: &Path) -> bool {
    let Ok(rd) = std::fs::read_dir(dir) else { return false };
    let names: Vec<String> = rd.filter_map(Result::ok).map(|e| e.file_name().to_string_lossy().to_lowercase()).collect();
    // NW.js / Electron apps and RPG Maker games ship a package.json next to their .exe, so that
    // file alone only means "code project" when there's no program beside it.
    let has_exe = names.iter().any(|n| n.ends_with(".exe"));
    names.iter().any(|n| {
        (SOURCE_MARKERS.contains(&n.as_str()) && (n != "package.json" || !has_exe)) || n.ends_with(".sln") || n.ends_with(".csproj")
    })
}

/// A folder of code projects (e.g. Documents\Code): most of its subfolders are checkouts. One
/// odd subfolder (a game shipping a package.json) doesn't make a folder of games a projects folder.
fn holds_projects(dir: &Path) -> bool {
    let children = child_dirs(dir);
    let projects = children.iter().filter(|c| looks_like_source(c)).count();
    projects >= 2 && projects * 2 >= children.len()
}

/// True for setup programs: installer frameworks leave a fingerprint in the first part of the
/// file (NSIS, Inno Setup, InstallShield, WiX Burn), and many installers describe themselves as
/// "Setup"/"Installer" in their version information.
fn is_installer(exe: &Path) -> bool {
    const MARKERS: &[&[u8]] = &[b"Nullsoft.NSIS", b"NullsoftInst", b"JR.Inno.Setup", b"Inno Setup", b"InstallShield", b".wixburn", b"WixBundle", b"7zS.sfx"];
    if let Ok(mut f) = std::fs::File::open(exe) {
        use std::io::Read;
        let mut head = vec![0u8; 2 * 1024 * 1024];
        let n = f.read(&mut head).unwrap_or(0);
        let head = &head[..n];
        if MARKERS.iter().any(|m| head.windows(m.len()).any(|w| w == *m)) {
            return true;
        }
    }
    let path = exe.to_string_lossy();
    let w = wide(&path);
    let mut handle = 0u32;
    let size = unsafe { GetFileVersionInfoSizeW(w.as_ptr(), &mut handle) };
    if size == 0 {
        return false;
    }
    let mut buf = vec![0u8; size as usize];
    if unsafe { GetFileVersionInfoW(w.as_ptr(), 0, size, buf.as_mut_ptr() as *mut c_void) } == 0 {
        return false;
    }
    // "Setup" in the description, or "setup"/"install" in the file's original name. (A tool can
    // describe itself as an "installer" of something else, e.g. UNetbootin, so that word alone
    // in the description doesn't count.)
    ["040904b0", "040904e4", "000004b0"].iter().any(|lang| {
        let has = |key: &str, words: &[&str]| query(&buf, lang, key).is_some_and(|v| words.iter().any(|w| v.to_lowercase().contains(w)));
        has("FileDescription", &["setup"]) || has("InternalName", &["setup"]) || has("OriginalFilename", &["setup", "install"])
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
        self.loose_exes(drive);
    }

    /// Desktop, Downloads, Documents: single-file apps lying there, and unzipped portable app
    /// folders. Only one level deep — these folders are the user's own space.
    fn scan_user_folder(&mut self, folder: &Path) {
        self.loose_exes(folder);
        for dir in child_dirs(folder) {
            self.consider(&dir, false);
        }
    }

    /// Standalone portable apps: an .exe sitting on its own (not installers).
    fn loose_exes(&mut self, folder: &Path) {
        let Ok(rd) = std::fs::read_dir(folder) else { return };
        for e in rd.filter_map(Result::ok) {
            let path = e.path();
            if !e.file_type().is_ok_and(|t| t.is_file()) || !path.extension().is_some_and(|x| x.eq_ignore_ascii_case("exe")) {
                continue;
            }
            let stem = normalize(&path.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default());
            if stem.len() < 2 || NOT_MAIN_EXE.iter().any(|n| stem.starts_with(n)) || INSTALLER_WORDS.iter().any(|w| stem.contains(w)) {
                continue;
            }
            if e.metadata().map(|m| m.len()).unwrap_or(0) < 100 * 1024 {
                continue;
            }
            if is_installer(&path) {
                continue; // a downloaded setup file, not an app
            }
            self.found.push(make_exe_program(&path));
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
            // A Steam install or library: every game folder in it is listed, including folders a
            // game left behind after it was uninstalled.
            let titles = common.parent().map(steam_titles).unwrap_or_default();
            for game in child_dirs(&common) {
                self.consider_steam_game(&game, &titles);
            }
            return;
        }
        let l = dir.to_string_lossy().to_lowercase();
        if self.registered_dirs.iter().any(|r| *r == l || leftovers::inside_other(&l, r)) {
            return; // already listed as an installed program
        }
        if looks_like_source(dir) || holds_projects(dir) {
            return;
        }
        let holds_registered = self.registered_dirs.iter().any(|r| r.starts_with(&format!("{l}\\")));
        let top_exe = main_exe(dir, 1);
        let norm = normalize(&name);
        // A program's own main exe is named after it ("Photoshop.exe" in "Adobe Photoshop",
        // "xampp-control.exe" in "xampp2").
        let top_is_the_program = top_exe.as_ref().is_some_and(|e| named_after(&norm, e));
        if !holds_registered && can_descend && !top_is_the_program {
            let with_exe: Vec<PathBuf> = child_dirs(dir)
                .into_iter()
                .filter(|c| {
                    let n = leaf(c).to_lowercase();
                    !n.starts_with('_') && !REDIST_DIRS.contains(&n.as_str())
                })
                .filter(|c| main_exe(c, 2).is_some())
                .collect();
            let parts_of_one = with_exe.iter().any(|c| PART_NAMES.contains(&normalize(&leaf(c)).as_str()));
            let programs_inside: Vec<PathBuf> =
                with_exe.iter().filter(|c| !PART_NAMES.contains(&normalize(&leaf(c)).as_str())).cloned().collect();
            let is_container = if top_exe.is_none() {
                // D:\Games, C:\Program Files\Blackmagic Design…: programs side by side. A publisher
                // folder holding a single program is named after that program.
                CONTAINER_NAMES.contains(&norm.as_str()) || (!with_exe.is_empty() && !parts_of_one)
            } else {
                // A collection with a shared launcher on top (e.g. a folder of games plus a
                // "Launcher.exe"): several subfolders that are each a self-contained program, with
                // an exe named after that subfolder. Parts of one program (xampp's apache, mysql…)
                // mostly aren't.
                let self_contained = programs_inside
                    .iter()
                    .filter(|c| main_exe(c, 2).is_some_and(|e| named_after(&normalize(&leaf(c)), &e)))
                    .count();
                programs_inside.len() >= 3 && self_contained * 10 >= programs_inside.len() * 6
            };
            if is_container {
                let children = if top_exe.is_none() {
                    with_exe
                } else {
                    // In a collection, check every subfolder: some games keep their exe deeper, and
                    // some are leftovers whose files are already gone.
                    child_dirs(dir)
                        .into_iter()
                        .filter(|c| {
                            let n = leaf(c).to_lowercase();
                            !n.starts_with('_') && !REDIST_DIRS.contains(&n.as_str()) && !PART_NAMES.contains(&normalize(&n).as_str())
                        })
                        .collect()
                };
                for child in children {
                    self.consider(&child, false);
                }
                return;
            }
        }
        if !holds_registered {
            let inner = unwrap_folders(dir);
            let found_exe = top_exe
                .or_else(|| main_exe(dir, 2))
                .or_else(|| deep_exe(dir))
                .or_else(|| (inner != dir).then(|| main_exe(&inner, 2)).flatten());
            if let Some(exe) = found_exe {
                if self.is_registered_name(&norm, &exe) {
                    return; // a registered program whose uninstall entry doesn't record its folder
                }
                self.found.push(make_program(dir, Some(&exe), None, ""));
                return;
            }
            if is_renpy(dir) || is_renpy(&inner) {
                self.found.push(make_program(dir, None, None, "Ren'Py game"));
                return;
            }
            if has_install_traces(dir) {
                // The program is gone but its folder (and often gigabytes of data) is still here.
                self.found.push(make_program(dir, None, None, "Leftover folder"));
                return;
            }
        }
        if can_descend {
            for child in child_dirs(dir) {
                self.consider(&child, false);
            }
        }
    }

    fn consider_steam_game(&mut self, dir: &Path, titles: &HashMap<String, String>) {
        let lname = leaf(dir).to_lowercase();
        if lname == "steamworks shared" {
            return; // runtimes Steam installs for games, not a game
        }
        let l = dir.to_string_lossy().to_lowercase();
        if self.registered_dirs.iter().any(|r| *r == l) {
            return; // the game has its own uninstall entry, so it's already listed
        }
        let title = titles.get(&lname).cloned();
        match main_exe(dir, 2).or_else(|| deep_exe(dir)) {
            Some(exe) => self.found.push(make_program(dir, Some(&exe), title, "Steam library")),
            // No game files left: Steam uninstalled it, or Windows was reinstalled and the
            // library kept only saves, logs and workshop data.
            None => self.found.push(make_program(dir, None, title, "Steam library · leftover")),
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

/// The current user's Desktop, Downloads and Documents (wherever they really are, e.g. OneDrive).
fn user_folders() -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Some(key) = crate::reg::open(r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders") {
        // Downloads has no friendly value name, only its known-folder GUID.
        for name in ["Desktop", "Personal", "{374DE290-123F-4565-9164-39C4925E467B}"] {
            if let Some(p) = crate::reg::string(&key, name) {
                v.push(PathBuf::from(crate::util::expand_env(&p)));
            }
        }
    }
    if let Some(home) = std::env::var_os("USERPROFILE").map(PathBuf::from) {
        v.extend([home.join("Desktop"), home.join("Downloads"), home.join("Documents")]);
    }
    let mut seen = std::collections::HashSet::new();
    v.retain(|p| p.is_dir() && seen.insert(p.to_string_lossy().to_lowercase()));
    v
}

/// A single-file portable app. Its "install location" is the exe itself.
fn make_exe_program(exe: &Path) -> Program {
    let path = exe.to_string_lossy().into_owned();
    let VersionInfo { company, version, .. } = version_info(&path);
    let install_date = std::fs::metadata(exe).ok().and_then(|m| m.created().or_else(|_| m.modified()).ok()).map(date_from_system_time);
    Program {
        id: format!("dir:{path}"),
        kind: "portable".into(),
        name: exe.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_else(|| path.clone()),
        version,
        publisher: company,
        install_location: Some(path.clone()),
        install_date,
        size_bytes: std::fs::metadata(exe).ok().map(|m| m.len()),
        uninstall_string: None,
        quiet_uninstall_string: None,
        icon_path: Some(path),
        product_code: None,
        registry_key: None,
        scope: "machine".into(),
        users: Vec::new(),
        arch: "Portable app".into(),
        system_component: false,
        package_full_name: None,
        package_family_name: None,
    }
}

/// `label` ends up in `arch`, which the UI shows as the program's type ("Steam library",
/// "Leftover folder", …).
fn make_program(dir: &Path, exe: Option<&Path>, title: Option<String>, label: &str) -> Program {
    let path = dir.to_string_lossy().into_owned();
    let info = exe.map(|e| version_info(&e.to_string_lossy())).unwrap_or_default();
    let install_date = std::fs::metadata(dir).ok().and_then(|m| m.created().or_else(|_| m.modified()).ok()).map(date_from_system_time);
    // A folder called "Install" or "App" says nothing: use the name the program gives itself.
    let folder = leaf(dir);
    let name = title.unwrap_or_else(|| {
        if generic_folder_name(&folder) {
            info.product.clone().or_else(|| exe.and_then(|e| e.file_stem()).map(|s| s.to_string_lossy().into_owned())).unwrap_or(folder)
        } else {
            folder
        }
    });
    let (company, version) = (info.company, info.version);
    Program {
        id: format!("dir:{path}"),
        kind: "portable".into(),
        name,
        version,
        publisher: company,
        install_location: Some(path),
        install_date,
        size_bytes: None,
        uninstall_string: None,
        quiet_uninstall_string: None,
        icon_path: exe.map(|e| e.to_string_lossy().into_owned()),
        product_code: None,
        registry_key: None,
        scope: "machine".into(),
        users: Vec::new(),
        arch: label.into(),
        system_component: false,
        package_full_name: None,
        package_family_name: None,
    }
}

/// Folder names that don't identify a program ("Install", "New folder (2)", "1.2.3"…).
fn generic_folder_name(name: &str) -> bool {
    const GENERIC: &[&str] = &[
        "install", "installer", "setup", "app", "apps", "game", "games", "bin", "bin64", "program", "programs",
        "launcher", "client", "newfolder", "portable", "software", "tools", "release", "main", "files", "data", "x64",
        "x86", "win64", "win32", "build", "dist", "output", "extracted", "unzipped", "download", "downloads",
    ];
    let n = normalize(name);
    let base = n.trim_end_matches(|c: char| c.is_ascii_digit());
    GENERIC.contains(&n.as_str()) || GENERIC.contains(&base) || n.chars().all(|c| c.is_ascii_digit())
}

#[derive(Default)]
struct VersionInfo {
    company: Option<String>,
    version: Option<String>,
    /// ProductName, or FileDescription when there's no product name.
    product: Option<String>,
}

/// CompanyName, ProductVersion and product name from an executable's version resource.
fn version_info(path: &str) -> VersionInfo {
    let w = wide(path);
    let mut handle = 0u32;
    let size = unsafe { GetFileVersionInfoSizeW(w.as_ptr(), &mut handle) };
    if size == 0 {
        return VersionInfo::default();
    }
    let mut buf = vec![0u8; size as usize];
    if unsafe { GetFileVersionInfoW(w.as_ptr(), 0, size, buf.as_mut_ptr() as *mut c_void) } == 0 {
        return VersionInfo::default();
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
    // The description is often the more specific name ("Minecraft Launcher" vs "Minecraft").
    let (product, description) = (get("ProductName"), get("FileDescription"));
    let product = match (product, description) {
        (Some(p), Some(d)) if d.len() > p.len() && d.to_lowercase().contains(&p.to_lowercase()) => Some(d),
        (Some(p), _) => Some(p),
        (None, d) => d,
    };
    VersionInfo {
        company: get("CompanyName"),
        version: get("ProductVersion").or_else(|| get("FileVersion")).map(|v| v.replace(", ", ".")),
        product: product.filter(|p| p.len() >= 2),
    }
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
            println!("{:<45} {:<28} {:<24} {}", p.name, p.publisher.as_deref().unwrap_or("-"), p.arch, p.install_location.as_deref().unwrap_or("-"));
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

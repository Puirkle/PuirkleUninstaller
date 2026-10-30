//! Leftover detection: finds files, folders, shortcuts, registry keys/values, services and
//! scheduled tasks that belong to a program.
//!
//! Two kinds of evidence are used:
//! * **Path evidence** (high confidence): the item points into the program's install folder.
//! * **Name evidence** (high/medium): the item is named after the program, or sits in a folder
//!   named after its publisher.
//!
//! Safety rules: system and user-profile folders are never reported, nothing that belongs to
//! another installed program (shares its install folder, or its name) is reported as safe.

use crate::programs::{self, Program};
use crate::reg;
use crate::uninstall::split_command;
use crate::util::{clean_path, dir_size, env_dir, expand_env, fixed_drives, lower_path, mentions_path, normalize};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Leftover {
    pub id: String,
    /// folder | file | shortcut | regkey | regvalue | service | task
    pub kind: String,
    /// File-system path, registry key path, or task file path.
    pub path: String,
    pub value_name: Option<String>,
    /// Service name or scheduled-task name.
    pub name: Option<String>,
    pub size_bytes: u64,
    /// high | medium | low
    pub confidence: String,
    pub reason: String,
}

/// Words that are never distinctive enough to identify a program.
const GENERIC: &[&str] = &[
    "app", "apps", "application", "applications", "bin", "cache", "caches", "common", "commonfiles", "config", "data",
    "default", "driver", "drivers", "files", "install", "installer", "launcher", "local", "locallow", "microsoft",
    "windows", "program", "programs", "programfiles", "programdata", "roaming", "runtime", "service", "services",
    "setup", "shared", "software", "system", "temp", "tmp", "tools", "tool", "uninstall", "update", "updater",
    "updates", "user", "users", "x64", "x86", "amd64", "arm64", "packages", "package", "plugins", "logs", "log",
    "crashdumps", "crashpad", "desktop", "documents", "downloads", "start", "startmenu", "settings", "client", "free",
    "pro", "the", "for", "and", "edition", "version", "bit", "64bit", "32bit", "helper", "manager", "studio", "online",
    "cloud", "classes", "policies", "inc", "corp", "corporation", "ltd", "llc", "gmbh",
];

/// Executable names that say nothing about which program they belong to.
const GENERIC_EXE: &[&str] = &[
    "uninstall", "uninst", "uninstaller", "setup", "install", "installer", "update", "updater", "launcher", "app",
    "main", "start", "run", "helper", "maintenancetool", "au", "icon", "appicon", "program", "msiexec", "rundll32",
    "cmd", "explorer",
];

/// Top-level registry Software keys we never descend into.
const SKIP_REG: &[&str] = &[
    "microsoft", "classes", "policies", "wow6432node", "clients", "registeredapplications", "odbc", "windows",
    "partner", "defaultuserenvironment",
];

const PUBLISHER_SUFFIXES: &[&str] = &[
    "inc", "ltd", "llc", "corp", "corporation", "co", "gmbh", "limited", "ag", "sa", "srl", "bv", "pty", "plc",
    "the", "software", "technologies", "technology", "company", "sro", "ab", "oy", "as", "kg",
];

pub fn scan(p: &Program, force: bool) -> Vec<Leftover> {
    let mut c = Ctx::new(p, &universe());
    c.scan_install_dirs();
    c.scan_filesystem();
    c.scan_steam_manifests();
    c.scan_shortcuts();
    c.scan_tasks();
    c.scan_software_keys();
    c.scan_uninstall_entry(p, force);
    c.scan_msi(p);
    c.scan_app_paths();
    c.scan_run_keys();
    c.scan_services();
    c.scan_classes();
    c.scan_firewall();
    c.scan_traces();
    if p.kind == "store" {
        c.scan_appx(p);
    }
    c.finish()
}

/// The program's install folders, filtered for safety. Used by force removal to kill processes.
pub fn install_dirs(p: &Program) -> Vec<String> {
    Ctx::new(p, &universe()).dirs
}

/// Distinctive names of a program (normalized), e.g. "googlechrome", "chrome".
pub fn program_keywords(p: &Program) -> Vec<String> {
    keywords(p).0
}

/// Install folders (lowercase) of all the given programs.
pub fn all_program_dirs(ps: &[Program]) -> Vec<String> {
    let known = known_folders();
    ps.iter().flat_map(|p| candidate_dirs(p, &known)).map(|(l, _)| l).collect()
}

/// Names of services whose binary lives in one of `dirs`.
pub fn services_in(dirs: &[String]) -> Vec<String> {
    let Some(key) = reg::open(r"HKLM\SYSTEM\CurrentControlSet\Services") else { return Vec::new() };
    reg::subkeys(&key)
        .into_iter()
        .filter(|name| {
            key.open_subkey(name)
                .ok()
                .and_then(|k| reg::string(&k, "ImagePath"))
                .map(|img| expand_env(&img).to_lowercase())
                .is_some_and(|img| dirs.iter().any(|d| mentions_path(&img, d)))
        })
        .collect()
}

/// Every registered program plus what the scanner needs to know about each (install folders,
/// names, publishers), worked out once and shared by all scans for a couple of minutes instead
/// of being recomputed for every program.
pub struct Universe {
    all: Vec<Program>,
    names: Vec<String>,
    dirs: Vec<Vec<String>>,
    kw: Vec<(Vec<String>, Vec<String>)>,
    pubs: Vec<Vec<String>>,
    known: Vec<String>,
}

static UNIVERSE: std::sync::Mutex<Option<(std::time::Instant, std::sync::Arc<Universe>)>> = std::sync::Mutex::new(None);

fn universe() -> std::sync::Arc<Universe> {
    let mut g = UNIVERSE.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((at, u)) = g.as_ref() {
        if at.elapsed() < std::time::Duration::from_secs(120) {
            return u.clone();
        }
    }
    let all = programs::list_win32(false);
    let known = known_folders();
    let u = std::sync::Arc::new(Universe {
        names: all.iter().map(|o| normalize(&o.name)).collect(),
        dirs: all.iter().map(|o| candidate_dirs(o, &known).into_iter().map(|(l, _)| l).collect()).collect(),
        kw: all.iter().map(keywords).collect(),
        pubs: all.iter().map(|o| publisher_tokens(o.publisher.as_deref())).collect(),
        known,
        all,
    });
    *g = Some((std::time::Instant::now(), u.clone()));
    u
}

/// Forget the shared program data after something was installed or removed.
pub fn invalidate() {
    if let Ok(mut g) = UNIVERSE.lock() {
        *g = None;
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FolderUsage {
    pub path: String,
    pub size_bytes: u64,
    /// "program" (install folder) or "data" (settings, caches, saves, instances…)
    pub kind: String,
    pub confidence: String,
}

/// Real disk usage of a program: its install folder plus every data folder it owns.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Footprint {
    pub id: String,
    /// Install + data folders we are confident about.
    pub total_bytes: u64,
    pub program_bytes: u64,
    pub data_bytes: u64,
    /// Folders that probably belong to the program but are not counted in the total.
    pub uncertain_bytes: u64,
    pub folders: Vec<FolderUsage>,
}

/// Footprints of several programs at once, measured in parallel.
pub fn footprints(targets: &[Program]) -> Vec<Footprint> {
    let u = universe();
    std::thread::scope(|s| {
        let handles: Vec<_> = targets.iter().map(|p| s.spawn(|| footprint(p, &u))).collect();
        handles.into_iter().filter_map(|h| h.join().ok()).collect()
    })
}

fn footprint(p: &Program, u: &Universe) -> Footprint {
    let mut c = Ctx::new(p, u);
    c.scan_install_dirs();
    c.scan_filesystem();
    if p.kind == "store" {
        c.scan_appx(p);
    }
    let dirs = c.dirs.clone();
    let mut folders: Vec<FolderUsage> = c
        .finish()
        .into_iter()
        .filter(|it| matches!(it.kind.as_str(), "folder" | "file") && it.confidence != "low")
        .map(|it| {
            let l = it.path.to_lowercase();
            let is_program = dirs.iter().any(|d| l == *d || l.starts_with(&format!("{d}\\")));
            FolderUsage { path: it.path, size_bytes: it.size_bytes, kind: if is_program { "program" } else { "data" }.into(), confidence: it.confidence }
        })
        .collect();
    // Store apps live under WindowsApps, which the leftover scan never reports.
    if p.kind == "store" {
        if let Some(loc) = &p.install_location {
            folders.push(FolderUsage { path: loc.clone(), size_bytes: dir_size(Path::new(loc)), kind: "program".into(), confidence: "high".into() });
        }
    }
    folders.sort_by(|a, b| b.size_bytes.cmp(&a.size_bytes));
    let sum = |f: &dyn Fn(&FolderUsage) -> bool| folders.iter().filter(|x| f(x)).map(|x| x.size_bytes).sum::<u64>();
    let program_bytes = sum(&|x| x.confidence == "high" && x.kind == "program");
    let data_bytes = sum(&|x| x.confidence == "high" && x.kind == "data");
    let uncertain_bytes = sum(&|x| x.confidence != "high");
    Footprint { id: p.id.clone(), total_bytes: program_bytes + data_bytes, program_bytes, data_bytes, uncertain_bytes, folders }
}

// ---------------------------------------------------------------------------------------------
// Keyword & path derivation

fn strip_brackets(s: &str) -> String {
    let mut out = String::new();
    let mut depth = 0i32;
    for c in s.chars() {
        match c {
            '(' | '[' => depth += 1,
            ')' | ']' => depth = (depth - 1).max(0),
            _ if depth == 0 => out.push(c),
            _ => {}
        }
    }
    out
}

fn is_version(t: &str) -> bool {
    let t = t.trim_start_matches(['v', 'V']);
    t.chars().any(|c| c.is_ascii_digit()) && t.chars().all(|c| c.is_ascii_digit() || c == '.')
}

fn is_arch(t: &str) -> bool {
    matches!(t.to_lowercase().as_str(), "x64" | "x86" | "64-bit" | "32-bit" | "amd64" | "arm64" | "win64" | "win32" | "-")
}

fn push_kw(v: &mut Vec<String>, s: String) {
    if s.len() >= 3 && !GENERIC.contains(&s.as_str()) && !s.chars().all(|c| c.is_ascii_digit()) && !v.contains(&s) {
        v.push(s);
    }
}

fn publisher_tokens(publisher: Option<&str>) -> Vec<String> {
    let Some(p) = publisher else { return Vec::new() };
    let tokens: Vec<String> = strip_brackets(p)
        .split(|c: char| c.is_whitespace() || c == ',')
        .map(normalize)
        .filter(|t| !t.is_empty() && !PUBLISHER_SUFFIXES.contains(&t.as_str()))
        .collect();
    let mut out = Vec::new();
    push_kw(&mut out, tokens.concat());
    if let Some(first) = tokens.first() {
        if first.len() >= 4 {
            push_kw(&mut out, first.clone());
        }
    }
    out
}

fn exe_stem(path: &str) -> Option<String> {
    let stem = Path::new(path).file_stem()?.to_string_lossy().to_lowercase();
    let n = normalize(&stem);
    (!GENERIC_EXE.contains(&n.as_str()) && !n.starts_with("unins")).then_some(n)
}

/// (strong keywords, weak keywords). Strong exact matches are high confidence; weak ones medium.
fn keywords(p: &Program) -> (Vec<String>, Vec<String>) {
    let mut strong = Vec::new();
    let mut weak = Vec::new();
    let pubs = publisher_tokens(p.publisher.as_deref());
    let cleaned = strip_brackets(&p.name);
    let tokens: Vec<&str> =
        cleaned.split(|c: char| c.is_whitespace() || c == ',' || c == '_' || c == '-').filter(|t| !t.is_empty()).collect();
    let core: Vec<&str> = tokens.iter().copied().filter(|t| !is_version(t) && !is_arch(t)).collect();
    push_kw(&mut strong, normalize(&core.concat()));
    push_kw(&mut strong, normalize(&tokens.concat()));
    if core.len() > 1 {
        let first = normalize(core[0]);
        if pubs.contains(&first) {
            push_kw(&mut strong, normalize(&core[1..].concat()));
        } else if first.len() >= 4 {
            push_kw(&mut weak, first);
        }
    }
    if let Some(loc) = &p.install_location {
        let path = Path::new(loc);
        // For a single-file app the "location" is its exe: use the name without ".exe".
        let leaf = if path.extension().is_some_and(|x| x.eq_ignore_ascii_case("exe")) { path.file_stem() } else { path.file_name() };
        if let Some(leaf) = leaf {
            push_kw(&mut strong, normalize(&leaf.to_string_lossy()));
        }
    }
    if let Some(icon) = &p.icon_path {
        let (path, _) = crate::icons::parse_icon_spec(icon);
        let lower = path.to_lowercase();
        if lower.ends_with(".exe") && !lower.contains(r"\windows\installer\") {
            if let Some(s) = exe_stem(&path) {
                push_kw(&mut strong, s);
            }
        }
    }
    if let Some(family) = &p.package_family_name {
        push_kw(&mut strong, normalize(family));
        if let Some(name) = family.split('_').next() {
            push_kw(&mut strong, normalize(name));
        }
    }
    weak.retain(|w| !strong.contains(w));
    (strong, weak)
}

fn known_folders() -> Vec<String> {
    let mut v: Vec<PathBuf> = [
        "SystemDrive", "ProgramFiles", "ProgramFiles(x86)", "ProgramW6432", "CommonProgramFiles",
        "CommonProgramFiles(x86)", "CommonProgramW6432", "ProgramData", "ALLUSERSPROFILE", "PUBLIC", "USERPROFILE",
        "APPDATA", "LOCALAPPDATA", "TEMP", "TMP", "OneDrive", "SystemRoot", "windir",
    ]
    .iter()
    .filter_map(|var| std::env::var_os(var).map(PathBuf::from))
    .collect();
    if let Some(home) = env_dir("USERPROFILE") {
        for sub in ["Desktop", "Documents", "Downloads", "Music", "Pictures", "Videos", r"AppData\LocalLow", "Saved Games", "Favorites", "Contacts", "Links", "Searches"] {
            v.push(home.join(sub));
        }
        if let Some(parent) = home.parent() {
            v.push(parent.to_path_buf());
        }
    }
    if let Some(local) = env_dir("LOCALAPPDATA") {
        v.extend([local.join("Programs"), local.join("Packages"), local.join("Microsoft"), local.join("Temp")]);
    }
    if let Some(roaming) = env_dir("APPDATA") {
        v.extend([roaming.join(r"Microsoft\Windows\Start Menu\Programs\Startup"), roaming.join("Microsoft")]);
    }
    if let Some(pd) = env_dir("ProgramData") {
        v.extend([pd.join(r"Microsoft\Windows\Start Menu\Programs\Startup"), pd.join("Package Cache"), pd.join("Microsoft")]);
    }
    if let Some(public) = env_dir("PUBLIC") {
        v.extend([public.join("Desktop"), public.join("Documents")]);
    }
    if let Some(pf) = env_dir("ProgramFiles") {
        v.extend([pf.join("WindowsApps"), pf.join("Common Files"), pf.join("Windows Defender"), pf.join("Microsoft")]);
    }
    if let Some(desktop) = desktop_dir() {
        v.push(desktop);
    }
    v.iter().map(|p| lower_path(&p.to_string_lossy())).filter(|p| !p.is_empty()).collect()
}

fn desktop_dir() -> Option<PathBuf> {
    let key = reg::open(r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")?;
    reg::string(&key, "Desktop").map(|d| PathBuf::from(expand_env(&d)))
}

/// `is_protected` for any path, e.g. one the storage analyzer is asked to delete.
pub fn is_protected_path(path: &str) -> bool {
    is_protected(&lower_path(path), &known_folders())
}

/// A path we must never delete: drive roots, Windows, store packages, user/system known folders
/// and every ancestor of one.
fn is_protected(lp: &str, known: &[String]) -> bool {
    if lp.len() <= 3 || !lp.contains('\\') {
        return true;
    }
    let windir = std::env::var("windir").unwrap_or_else(|_| r"C:\Windows".into()).to_lowercase();
    if lp == windir || lp.starts_with(&format!("{windir}\\")) || lp.contains(r"\windowsapps\") {
        return true;
    }
    known.iter().any(|k| k == lp || k.starts_with(&format!("{lp}\\")))
}

/// Folders a program was installed into, derived from InstallLocation, its icon and its uninstaller.
/// Returns (lowercase path for matching, path as registered).
fn candidate_dirs(p: &Program, known: &[String]) -> Vec<(String, String)> {
    let mut raw: Vec<String> = Vec::new();
    if p.kind == "store" {
        if let (Some(local), Some(fam)) = (env_dir("LOCALAPPDATA"), &p.package_family_name) {
            raw.push(local.join("Packages").join(fam).to_string_lossy().into_owned());
        }
    } else if let Some(loc) = &p.install_location {
        raw.push(loc.clone());
    }
    if let Some(icon) = &p.icon_path {
        let (path, _) = crate::icons::parse_icon_spec(icon);
        if let Some(parent) = Path::new(&path).parent() {
            raw.push(parent.to_string_lossy().into_owned());
        }
    }
    if let Some(u) = &p.uninstall_string {
        let (exe, _) = split_command(u);
        if exe.contains('\\') && !exe.to_lowercase().contains("msiexec") {
            if let Some(parent) = Path::new(&exe).parent() {
                let mut dir = parent.to_path_buf();
                let leaf = normalize(&dir.file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or_default());
                if matches!(leaf.as_str(), "uninstall" | "uninst" | "uninstaller" | "uninstallers") {
                    if let Some(gp) = dir.parent() {
                        dir = gp.to_path_buf();
                    }
                }
                raw.push(dir.to_string_lossy().into_owned());
            }
        }
    }
    let (strong, weak) = keywords(p);
    let mut out: Vec<(String, String)> = Vec::new();
    for r in raw {
        let lp = lower_path(&r);
        if lp.is_empty() || is_protected(&lp, known) || out.iter().any(|(l, _)| *l == lp) {
            continue;
        }
        // A shallow folder (e.g. D:\Games) only counts when it is named after the program.
        let depth = lp.matches('\\').count();
        let leaf = normalize(lp.rsplit('\\').next().unwrap_or(""));
        let named = strong.iter().chain(weak.iter()).any(|k| leaf == *k || (k.len() >= 4 && (leaf.contains(k.as_str()) || k.contains(leaf.as_str()))));
        if depth >= 3 || named {
            out.push((lp, clean_path(&r)));
        }
    }
    out
}

// ---------------------------------------------------------------------------------------------

/// Vendors whose programs leave folders that aren't named after any one program, such as 360's
/// C:\360SANDBOX. `terms` are matched inside the normalized name or publisher.
struct Family {
    vendor: &'static str,
    terms: &'static [&'static str],
    /// Normalized folder/key name prefixes this vendor's programs create.
    prefixes: &'static [&'static str],
}

const FAMILIES: &[Family] = &[Family {
    vendor: "360",
    terms: &["360totalsecurity", "360safe", "qihoo", "360securitycenter", "360安全"],
    prefixes: &["360sandbox", "360safe", "360totalsecurity", "360securitycenter", "360tsdownload", "360download", "360quarant", "360安全"],
}];

fn family_of(p: &Program) -> Option<&'static Family> {
    let text = format!("{} {}", normalize(&p.name), p.publisher.as_deref().map(normalize).unwrap_or_default());
    FAMILIES.iter().find(|f| f.terms.iter().any(|t| text.contains(t)))
}

/// The vendor family `p` belongs to, by vendor name.
pub fn family_vendor(p: &Program) -> Option<&'static str> {
    family_of(p).map(|f| f.vendor)
}

/// The vendor whose programs create a folder called `name`, e.g. "360" for "360SANDBOX".
pub fn family_folder(name: &str) -> Option<&'static str> {
    let n = normalize(name);
    FAMILIES.iter().find(|f| f.prefixes.iter().any(|x| n.starts_with(x))).map(|f| f.vendor)
}

struct Ctx {
    /// The vendor family of the program, and whether another installed program belongs to it too.
    family: Option<(&'static Family, bool)>,
    kw: Vec<String>,
    weak: Vec<String>,
    pubs: Vec<String>,
    /// Install folders, lowercase.
    dirs: Vec<String>,
    /// Lowercase install folder -> its real spelling, for display.
    dir_names: HashMap<String, String>,
    known: Vec<String>,
    foreign_kw: HashSet<String>,
    foreign_weak: HashSet<String>,
    foreign_dirs: Vec<String>,
    foreign_pubs: HashSet<String>,
    items: Vec<Leftover>,
}

/// `path` lies inside another program's folder `other` (both lowercase). Games in a Steam library
/// inside Steam's own folder are programs of their own, not part of Steam.
pub fn inside_other(path: &str, other: &str) -> bool {
    path.starts_with(&format!("{other}\\")) && !path[other.len()..].contains(r"\steamapps\common\")
}

fn rank(conf: &str) -> u8 {
    match conf {
        "high" => 3,
        "medium" => 2,
        _ => 1,
    }
}

impl Ctx {
    /// Context for `p`, against every other registered program in `u`.
    fn new(p: &Program, u: &Universe) -> Self {
        let (kw, weak) = keywords(p);
        let me = normalize(&p.name);
        let core = kw.first().cloned().unwrap_or_else(|| me.clone());
        let mut foreign_dirs: Vec<String> = Vec::new();
        let mut foreign_kw = HashSet::new();
        let mut foreign_weak = HashSet::new();
        let mut foreign_pubs = HashSet::new();
        for (i, o) in u.all.iter().enumerate() {
            if o.id == p.id || u.names[i] == me {
                continue;
            }
            // Hidden components of the same bundle (e.g. "Python 3.13 Core Interpreter") are part of it.
            if o.system_component && o.publisher == p.publisher && u.names[i].starts_with(&core) {
                continue;
            }
            foreign_dirs.extend(u.dirs[i].iter().cloned());
            foreign_kw.extend(u.kw[i].0.iter().cloned());
            foreign_weak.extend(u.kw[i].1.iter().cloned());
            foreign_pubs.extend(u.pubs[i].iter().cloned());
        }
        // A folder shared with another registered program is ambiguous: leave it alone.
        let mut dir_names = HashMap::new();
        let dirs = candidate_dirs(p, &u.known)
            .into_iter()
            .filter(|(l, _)| !foreign_dirs.contains(l))
            .map(|(l, original)| {
                dir_names.insert(l.clone(), original);
                l
            })
            .collect();
        let family = family_of(p).map(|f| {
            let shared = u.all.iter().any(|o| o.id != p.id && !o.system_component && family_of(o).is_some_and(|g| std::ptr::eq(f, g)));
            (f, shared)
        });
        Ctx {
            family,
            kw,
            weak,
            pubs: publisher_tokens(p.publisher.as_deref()),
            dirs,
            dir_names,
            known: u.known.clone(),
            foreign_kw,
            foreign_weak,
            foreign_dirs,
            foreign_pubs,
            items: Vec::new(),
        }
    }

    /// Name evidence. Returns (confidence, reason).
    fn match_name(&self, raw: &str) -> Option<(&'static str, String)> {
        let n = normalize(raw);
        if n.len() < 3 || GENERIC.contains(&n.as_str()) {
            return None;
        }
        if let Some(k) = self.kw.iter().find(|k| **k == n) {
            if self.foreign_kw.contains(&n) {
                return Some(("low", "Named after the program, but another installed program uses this name too".into()));
            }
            return Some((if k.len() >= 4 { "high" } else { "medium" }, "Named after the program".into()));
        }
        // Reverse-DNS app identifiers used by Tauri/Electron/.NET apps, e.g. "com.vendor.product".
        let segments: Vec<&str> = raw.split('.').collect();
        if segments.len() >= 3 && segments.iter().all(|s| !s.is_empty() && !s.contains(' ')) {
            let last = normalize(segments[segments.len() - 1]);
            let owned_by_other = self.foreign_kw.contains(&last) || self.foreign_weak.contains(&last);
            if last.len() >= 4 && !owned_by_other {
                if self.kw.contains(&last) {
                    return Some(("high", "App identifier named after the program".into()));
                }
                if self.weak.contains(&last) {
                    return Some(("medium", "App identifier named after part of the program's name".into()));
                }
            }
        }
        let (matched_len, reason) = if let Some(k) = self.kw.iter().filter(|k| k.len() >= 5 && n.starts_with(k.as_str())).max_by_key(|k| k.len()) {
            (k.len(), "Name starts with the program's name")
        } else if self.weak.contains(&n) {
            (n.len(), "Named after part of the program's name")
        } else if let Some((f, shared)) = self.family.filter(|(f, _)| f.prefixes.iter().any(|x| n.starts_with(x))) {
            return Some(if shared {
                ("low", format!("Made by {} programs, and another {} program is still installed", f.vendor, f.vendor))
            } else {
                ("medium", format!("Made by {} programs", f.vendor))
            });
        } else {
            return None;
        };
        // A looser match loses to another program whose name fits this item better,
        // e.g. "Chrome Remote Desktop" when uninstalling "Google Chrome".
        let collides = self
            .foreign_kw
            .iter()
            .chain(self.foreign_weak.iter())
            .any(|f| *f == n || (f.len() > matched_len && f.len() >= 5 && (n.starts_with(f.as_str()) || f.starts_with(n.as_str()))));
        if collides {
            return Some(("low", format!("{reason}, but it looks like it belongs to another installed program")));
        }
        Some(("medium", reason.into()))
    }

    /// Treats a folder found by name in Program Files as an install folder, so shortcuts,
    /// services and registry entries pointing into it count as path evidence.
    fn promote(&mut self, path: &Path) {
        let original = path.to_string_lossy().into_owned();
        let l = original.to_lowercase();
        let foreign = self.foreign_dirs.iter().any(|f| *f == l || f.starts_with(&format!("{l}\\")) || inside_other(&l, f));
        if !self.dirs.contains(&l) && !foreign && !is_protected(&l, &self.known) {
            self.dirs.push(l.clone());
            self.dir_names.insert(l, original);
        }
    }

    fn is_publisher(&self, raw: &str) -> bool {
        let n = normalize(raw);
        !n.is_empty() && self.pubs.contains(&n)
    }

    /// Path evidence: `text` (lowercase) points into one of our install folders and not into a
    /// more specific folder owned by another program.
    fn text_hit(&self, text: &str) -> bool {
        self.dirs.iter().any(|d| {
            mentions_path(text, d)
                && !self.foreign_dirs.iter().any(|f| f.len() > d.len() && f.starts_with(d.as_str()) && mentions_path(text, f))
        })
    }

    fn file_hit(&self, path: &Path) -> bool {
        if self.dirs.is_empty() {
            return false;
        }
        let Ok(bytes) = std::fs::read(path) else { return false };
        if bytes.len() > 4 * 1024 * 1024 {
            return false;
        }
        let ansi = String::from_utf8_lossy(&bytes).to_lowercase();
        if self.text_hit(&ansi) {
            return true;
        }
        let units: Vec<u16> = bytes.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        self.text_hit(&String::from_utf16_lossy(&units).to_lowercase())
    }

    fn push(&mut self, kind: &str, path: String, value_name: Option<String>, name: Option<String>, conf: &str, reason: String) {
        let id = format!("{kind}|{path}|{}", value_name.as_deref().unwrap_or(""));
        self.items.push(Leftover { id, kind: kind.into(), path, value_name, name, size_bytes: 0, confidence: conf.into(), reason });
    }

    fn add_path(&mut self, kind: &str, path: &Path, conf: &str, reason: String) {
        let s = path.to_string_lossy().into_owned();
        let l = s.to_lowercase();
        if is_protected(&l, &self.known) {
            return;
        }
        // Never touch another program's folder, its parent, or anything inside it.
        let belongs_to_other = self.foreign_dirs.iter().any(|f| *f == l || f.starts_with(&format!("{l}\\")) || inside_other(&l, f));
        if belongs_to_other {
            return;
        }
        self.push(kind, s, None, None, conf, reason);
    }

    fn add_key(&mut self, key: &str, conf: &str, reason: impl Into<String>) {
        self.push("regkey", key.to_string(), None, None, conf, reason.into());
    }

    fn add_value(&mut self, key: &str, value: &str, conf: &str, reason: impl Into<String>) {
        self.push("regvalue", key.to_string(), Some(value.to_string()), None, conf, reason.into());
    }

    // ---- file system -----------------------------------------------------------------------

    fn scan_install_dirs(&mut self) {
        for d in self.dirs.clone() {
            let p = PathBuf::from(self.dir_names.get(&d).unwrap_or(&d));
            if p.is_dir() {
                self.add_path("folder", &p, "high", "Installation folder".into());
            } else if p.is_file() {
                // A single-file portable app: the exe is the whole program.
                self.add_path("file", &p, "high", "The program's executable".into());
            }
        }
    }

    fn scan_filesystem(&mut self) {
        let mut roots: Vec<PathBuf> = [
            "ProgramFiles", "ProgramFiles(x86)", "ProgramW6432", "CommonProgramFiles", "CommonProgramFiles(x86)",
            "ProgramData", "APPDATA", "LOCALAPPDATA",
        ]
        .iter()
        .filter_map(|v| env_dir(v))
        .collect();
        if let Some(local) = env_dir("LOCALAPPDATA") {
            roots.push(local.join("Programs"));
        }
        if let Some(home) = env_dir("USERPROFILE") {
            roots.push(home.join(r"AppData\LocalLow"));
            roots.push(home.join("Documents"));
            roots.push(home.join("Saved Games"));
        }
        // Every fixed drive: its Program Files folders, and its root (where people put games and tools).
        let drives = fixed_drives();
        for d in &drives {
            roots.push(d.join("Program Files"));
            roots.push(d.join("Program Files (x86)"));
            roots.push(d.clone());
        }
        let mut seen = HashSet::new();
        roots.retain(|r| r.is_dir() && seen.insert(r.to_string_lossy().to_lowercase()));
        let program_roots: HashSet<String> = ["ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"]
            .iter()
            .filter_map(|v| env_dir(v))
            .chain(env_dir("LOCALAPPDATA").map(|l| l.join("Programs")))
            .chain(drives.iter().flat_map(|d| [d.join("Program Files"), d.join("Program Files (x86)")]))
            .map(|p| p.to_string_lossy().to_lowercase())
            .collect();
        let drive_roots: HashSet<String> = drives.iter().map(|d| d.to_string_lossy().to_lowercase()).collect();

        for root in roots {
            let root_l = root.to_string_lossy().to_lowercase();
            let is_program_root = program_roots.contains(&root_l);
            let is_drive_root = drive_roots.contains(&root_l);
            let Ok(rd) = std::fs::read_dir(&root) else { continue };
            for e in rd.flatten() {
                if !e.file_type().is_ok_and(|t| t.is_dir()) {
                    continue; // also skips junctions/symlinks
                }
                let name = e.file_name().to_string_lossy().into_owned();
                if let Some((conf, why)) = self.match_name(&name) {
                    if is_drive_root {
                        // A folder at a drive root may just as well be the user's own files.
                        let conf = if conf == "high" { "medium" } else { conf };
                        self.add_path("folder", &e.path(), conf, format!("{why}, at the root of a drive (could be your own files)"));
                        continue;
                    }
                    if conf == "high" && is_program_root {
                        self.promote(&e.path());
                    }
                    self.add_path("folder", &e.path(), conf, why);
                } else if self.is_publisher(&name) && !is_drive_root {
                    self.scan_publisher_dir(&e.path(), &name, is_program_root);
                }
            }
        }
    }

    /// Steam keeps an appmanifest_<id>.acf per game; without it removed Steam still thinks the game is installed.
    fn scan_steam_manifests(&mut self) {
        for d in self.dirs.clone() {
            let Some(idx) = d.find(r"\steamapps\common\") else { continue };
            let steamapps = PathBuf::from(&self.dir_names.get(&d).unwrap_or(&d)[..idx + r"\steamapps".len()]);
            let game = d[idx + r"\steamapps\common\".len()..].split('\\').next().unwrap_or("").to_string();
            let Ok(rd) = std::fs::read_dir(&steamapps) else { continue };
            for e in rd.filter_map(Result::ok) {
                let n = e.file_name().to_string_lossy().to_lowercase();
                if !(n.starts_with("appmanifest_") && n.ends_with(".acf")) {
                    continue;
                }
                let text = std::fs::read_to_string(e.path()).unwrap_or_default().to_lowercase();
                let installdir = text
                    .lines()
                    .find(|l| l.trim_start().starts_with("\"installdir\""))
                    .and_then(|l| l.split('"').nth(3))
                    .unwrap_or("");
                if !game.is_empty() && installdir == game {
                    self.push("file", e.path().to_string_lossy().into_owned(), None, None, "high", "Steam's install record for this game".into());
                }
            }
        }
    }

    fn scan_publisher_dir(&mut self, dir: &Path, publisher: &str, is_program_root: bool) {
        let Ok(rd) = std::fs::read_dir(dir) else { return };
        let children: Vec<(String, PathBuf, bool)> = rd
            .flatten()
            .map(|e| (e.file_name().to_string_lossy().into_owned(), e.path(), e.file_type().is_ok_and(|t| t.is_dir())))
            .collect();
        let mut matched = 0;
        let mut all_high = true;
        for (name, path, is_dir) in &children {
            let stem = Path::new(name).file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
            if let Some((conf, why)) = self.match_name(if *is_dir { name } else { &stem }) {
                matched += 1;
                all_high &= conf == "high";
                if conf == "high" && *is_dir && is_program_root {
                    self.promote(path);
                }
                self.add_path(if *is_dir { "folder" } else { "file" }, path, conf, format!("{why} (in the {publisher} folder)"));
            }
        }
        let alone = !self.foreign_pubs.contains(&normalize(publisher));
        if children.is_empty() {
            self.add_path("folder", dir, "medium", "Empty folder named after the publisher".into());
        } else if matched == children.len() {
            let conf = if all_high && alone { "high" } else { "medium" };
            self.add_path("folder", dir, conf, "Publisher folder that only contains this program's data".into());
        } else if matched == 0 && alone {
            self.add_path("folder", dir, "medium", "Named after the publisher; no other programs from this publisher are installed".into());
        }
    }

    fn scan_shortcuts(&mut self) {
        let mut roots: Vec<(PathBuf, usize)> = Vec::new();
        if let Some(roaming) = env_dir("APPDATA") {
            roots.push((roaming.join(r"Microsoft\Windows\Start Menu\Programs"), 3));
            roots.push((roaming.join(r"Microsoft\Internet Explorer\Quick Launch"), 4));
        }
        if let Some(pd) = env_dir("ProgramData") {
            roots.push((pd.join(r"Microsoft\Windows\Start Menu\Programs"), 3));
        }
        if let Some(public) = env_dir("PUBLIC") {
            roots.push((public.join("Desktop"), 1));
        }
        if let Some(d) = desktop_dir().or_else(|| env_dir("USERPROFILE").map(|h| h.join("Desktop"))) {
            roots.push((d, 1));
        }
        for (root, depth) in roots {
            let is_start_menu = root.to_string_lossy().to_lowercase().ends_with(r"start menu\programs");
            for e in walkdir::WalkDir::new(&root).min_depth(1).max_depth(depth).into_iter().filter_map(Result::ok) {
                let name = e.file_name().to_string_lossy().into_owned();
                if e.file_type().is_dir() {
                    if is_start_menu && e.depth() == 1 {
                        if let Some((conf, why)) = self.match_name(&name) {
                            self.add_path("folder", e.path(), conf, format!("Start Menu folder: {why}"));
                        }
                    }
                    continue;
                }
                let lower = name.to_lowercase();
                if !(lower.ends_with(".lnk") || lower.ends_with(".url")) {
                    continue;
                }
                if self.file_hit(e.path()) {
                    self.add_path("shortcut", e.path(), "high", "Shortcut to the program".into());
                } else if let Some((conf, _)) = self.match_name(&name[..name.len() - 4]) {
                    // Without install-path evidence a same-named shortcut is only a medium guess,
                    // unless we have no install path at all and its target is gone.
                    let conf = if conf == "high" && self.dirs.is_empty() { "high" } else { "medium" };
                    self.add_path("shortcut", e.path(), conf, "Shortcut named after the program".into());
                }
            }
        }
    }

    fn scan_tasks(&mut self) {
        let Some(windir) = env_dir("windir") else { return };
        let root = windir.join(r"System32\Tasks");
        for e in walkdir::WalkDir::new(&root).min_depth(1).into_iter().filter_map(Result::ok) {
            if !e.file_type().is_file() {
                continue;
            }
            let rel = e.path().strip_prefix(&root).map(|r| format!("\\{}", r.to_string_lossy())).unwrap_or_default();
            if rel.to_lowercase().starts_with(r"\microsoft\") {
                continue;
            }
            let file_name = e.file_name().to_string_lossy().into_owned();
            let (conf, reason) = if self.file_hit(e.path()) {
                ("high", "Scheduled task runs a program from the install folder".to_string())
            } else if self.match_name(&file_name).is_some_and(|(c, _)| c == "high") {
                ("medium", "Scheduled task named after the program".to_string())
            } else {
                continue;
            };
            self.push("task", e.path().to_string_lossy().into_owned(), None, Some(rel), conf, reason);
        }
    }

    fn scan_appx(&mut self, p: &Program) {
        let (Some(local), Some(fam)) = (env_dir("LOCALAPPDATA"), &p.package_family_name) else { return };
        let data = local.join("Packages").join(fam);
        if data.is_dir() {
            self.add_path("folder", &data, "high", "App data folder of the Store app".into());
        }
    }

    // ---- registry --------------------------------------------------------------------------

    fn scan_software_keys(&mut self) {
        let bases = [("HKCU", "Software"), ("HKLM", "SOFTWARE"), ("HKLM", r"SOFTWARE\WOW6432Node"), ("HKCU", r"Software\WOW6432Node")];
        for (root, base) in bases {
            let base_path = format!("{root}\\{base}");
            let Some(key) = reg::open(&base_path) else { continue };
            for name in reg::subkeys(&key) {
                if SKIP_REG.contains(&normalize(&name).as_str()) {
                    continue;
                }
                let full = format!("{base_path}\\{name}");
                if let Some((conf, why)) = self.match_name(&name) {
                    self.add_key(&full, conf, format!("Settings key: {why}"));
                    continue;
                }
                if !self.is_publisher(&name) {
                    continue;
                }
                let Ok(pk) = key.open_subkey(&name) else { continue };
                let children = reg::subkeys(&pk);
                let has_values = pk.enum_values().next().is_some();
                let mut matched = 0;
                for c in &children {
                    if let Some((conf, why)) = self.match_name(c) {
                        matched += 1;
                        self.add_key(&format!("{full}\\{c}"), conf, format!("Settings key: {why} (under {name})"));
                    }
                }
                let alone = !self.foreign_pubs.contains(&normalize(&name));
                if !has_values && matched == children.len() {
                    self.add_key(&full, if alone { "high" } else { "medium" }, "Publisher key that only holds this program's settings");
                } else if matched == 0 && alone {
                    self.add_key(&full, "medium", "Publisher key; no other programs from this publisher are installed");
                }
            }
        }
    }

    fn scan_uninstall_entry(&mut self, p: &Program, force: bool) {
        if let Some(k) = &p.registry_key {
            if reg::exists(k) {
                let why = if force { "Programs & Features entry" } else { "Programs & Features entry left behind" };
                self.add_key(k, "high", why);
            }
        }
    }

    fn scan_msi(&mut self, p: &Program) {
        let Some(code) = &p.product_code else { return };
        let packed = pack_guid(code);
        for k in [
            format!(r"HKLM\SOFTWARE\Classes\Installer\Products\{packed}"),
            format!(r"HKLM\SOFTWARE\Classes\Installer\Features\{packed}"),
            format!(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\{packed}"),
            format!(r"HKCU\Software\Microsoft\Installer\Products\{packed}"),
            format!(r"HKCU\Software\Microsoft\Installer\Features\{packed}"),
        ] {
            if reg::exists(&k) {
                self.add_key(&k, "high", "Windows Installer registration");
            }
        }
    }

    fn scan_app_paths(&mut self) {
        for base in [
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths",
            r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\App Paths",
        ] {
            let Some(key) = reg::open(base) else { continue };
            for name in reg::subkeys(&key) {
                let Ok(sub) = key.open_subkey(&name) else { continue };
                if self.text_hit(&reg::all_text(&sub)) {
                    self.add_key(&format!("{base}\\{name}"), "high", "Registers the program's executable");
                }
            }
        }
    }

    fn scan_run_keys(&mut self) {
        const RUN: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
        const RUN_ONCE: &str = r"Software\Microsoft\Windows\CurrentVersion\RunOnce";
        const APPROVED: &str = r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved";
        let keys = [
            format!(r"HKCU\{RUN}"),
            format!(r"HKCU\{RUN_ONCE}"),
            format!(r"HKLM\{RUN}"),
            format!(r"HKLM\{RUN_ONCE}"),
            r"HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run".to_string(),
            r"HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce".to_string(),
        ];
        let mut flagged: Vec<String> = Vec::new();
        for k in &keys {
            let Some(key) = reg::open(k) else { continue };
            for (vname, val) in key.enum_values().filter_map(Result::ok) {
                let Some(data) = reg::text(&val) else { continue };
                let lower = expand_env(&data).to_lowercase();
                if self.text_hit(&lower) {
                    self.add_value(k, &vname, "high", "Starts automatically with Windows");
                    flagged.push(vname);
                } else if self.match_name(&vname).is_some_and(|(c, _)| c == "high") {
                    let (exe, _) = split_command(&data);
                    if exe.contains('\\') && !Path::new(&exe).exists() {
                        self.add_value(k, &vname, "medium", "Startup entry named after the program; its target no longer exists");
                        flagged.push(vname);
                    }
                }
            }
        }
        for root in ["HKCU", "HKLM"] {
            for sub in ["Run", "Run32"] {
                let k = format!(r"{root}\{APPROVED}\{sub}");
                let Some(key) = reg::open(&k) else { continue };
                for v in &flagged {
                    if key.get_raw_value(v).is_ok() {
                        self.add_value(&k, v, "high", "Startup approval setting for a removed startup entry");
                    }
                }
            }
        }
    }

    fn scan_services(&mut self) {
        let base = r"HKLM\SYSTEM\CurrentControlSet\Services";
        for name in services_in(&self.dirs) {
            self.push("service", format!("{base}\\{name}"), None, Some(name), "high", "Windows service runs from the install folder".into());
        }
    }

    fn scan_classes(&mut self) {
        let roots = [r"HKLM\SOFTWARE\Classes", r"HKCU\Software\Classes", r"HKLM\SOFTWARE\Classes\WOW6432Node"];
        let mut clsids: HashSet<String> = HashSet::new();
        for base in roots {
            // COM servers
            let clsid_base = format!("{base}\\CLSID");
            if let Some(ck) = reg::open(&clsid_base) {
                for id in reg::subkeys(&ck) {
                    let Ok(sub) = ck.open_subkey(&id) else { continue };
                    let mut t = String::new();
                    for s in ["InprocServer32", "LocalServer32", "InprocHandler32"] {
                        if let Some(v) = reg::default_of(&sub, s) {
                            t.push_str(&v);
                            t.push(' ');
                        }
                    }
                    if !t.is_empty() && self.text_hit(&expand_env(&t).to_lowercase()) {
                        clsids.insert(id.to_lowercase());
                        self.add_key(&format!("{clsid_base}\\{id}"), "high", "COM component from the install folder");
                    }
                }
            }
            let Some(bk) = reg::open(base) else { continue };
            // ProgIDs / URL protocols
            for name in reg::subkeys(&bk) {
                if name.starts_with('.')
                    || ["clsid", "interface", "typelib", "installer", "wow6432node", "*", "directory", "folder", "drive", "allfilesystemobjects", "local settings", "appid", "applications"]
                        .contains(&name.to_lowercase().as_str())
                {
                    continue;
                }
                let Ok(sub) = bk.open_subkey(&name) else { continue };
                let t = [reg::default_of(&sub, r"shell\open\command"), reg::default_of(&sub, "DefaultIcon")]
                    .into_iter()
                    .flatten()
                    .collect::<Vec<_>>()
                    .join(" ");
                if !t.is_empty() && self.text_hit(&expand_env(&t).to_lowercase()) {
                    self.add_key(&format!("{base}\\{name}"), "high", "File type or link protocol handled by the program");
                }
            }
            if let Ok(apps) = bk.open_subkey("Applications") {
                for name in reg::subkeys(&apps) {
                    let Ok(sub) = apps.open_subkey(&name) else { continue };
                    if reg::default_of(&sub, r"shell\open\command").is_some_and(|t| self.text_hit(&expand_env(&t).to_lowercase())) {
                        self.add_key(&format!("{base}\\Applications\\{name}"), "high", "\"Open with\" registration");
                    }
                }
            }
            // Explorer context-menu verbs
            for target in ["*", "Directory", r"Directory\Background", "Folder", "Drive", "AllFilesystemObjects"] {
                let shell_path = format!("{base}\\{target}\\shell");
                let Some(shell) = reg::open(&shell_path) else { continue };
                for verb in reg::subkeys(&shell) {
                    let Ok(vk) = shell.open_subkey(&verb) else { continue };
                    let t = format!("{} {}", reg::default_of(&vk, "command").unwrap_or_default(), reg::string(&vk, "Icon").unwrap_or_default());
                    if self.text_hit(&expand_env(&t).to_lowercase()) {
                        self.add_key(&format!("{shell_path}\\{verb}"), "high", "Explorer context-menu entry");
                    }
                }
            }
        }
        if clsids.is_empty() {
            return;
        }
        // Shell extension handlers that point at the COM components found above.
        for base in roots {
            for target in ["*", "Directory", r"Directory\Background", "Folder", "Drive", "AllFilesystemObjects"] {
                for kind in ["ContextMenuHandlers", "DragDropHandlers", "PropertySheetHandlers", "CopyHookHandlers"] {
                    let path = format!("{base}\\{target}\\shellex\\{kind}");
                    let Some(k) = reg::open(&path) else { continue };
                    for h in reg::subkeys(&k) {
                        let val = k.open_subkey(&h).ok().and_then(|s| reg::string(&s, "")).unwrap_or_default().to_lowercase();
                        if clsids.contains(&val) || clsids.contains(&h.to_lowercase()) {
                            self.add_key(&format!("{path}\\{h}"), "high", "Shell extension registration");
                        }
                    }
                }
            }
        }
    }

    fn scan_firewall(&mut self) {
        let k = r"HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules";
        let Some(key) = reg::open(k) else { return };
        for (vname, val) in key.enum_values().filter_map(Result::ok) {
            let Some(data) = reg::text(&val) else { continue };
            if self.text_hit(&expand_env(&data).to_lowercase()) {
                let rule = data.split('|').find_map(|s| s.strip_prefix("Name=")).unwrap_or("").to_string();
                let why = if rule.is_empty() || rule.starts_with('@') { "Firewall rule".to_string() } else { format!("Firewall rule \"{rule}\"") };
                self.add_value(k, &vname, "high", why);
            }
        }
    }

    /// Windows keeps value names that are full paths to programs it has seen.
    fn scan_traces(&mut self) {
        let keys = [
            (r"HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache", "Explorer name cache entry"),
            (r"HKCU\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store", "Compatibility Assistant record"),
            (r"HKCU\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers", "Compatibility setting"),
            (r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers", "Compatibility setting"),
            (r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\Folders", "Windows Installer folder record"),
            (r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SharedDLLs", "Shared DLL reference"),
            (r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\SharedDLLs", "Shared DLL reference"),
        ];
        for (k, why) in keys {
            let Some(key) = reg::open(k) else { continue };
            let names: Vec<String> = key.enum_values().filter_map(Result::ok).map(|(n, _)| n).collect();
            for n in names {
                if self.text_hit(&n.to_lowercase()) {
                    self.add_value(k, &n, "high", why);
                }
            }
        }
    }

    // ---- results ---------------------------------------------------------------------------

    fn finish(self) -> Vec<Leftover> {
        fn container_key(it: &Leftover) -> String {
            match it.kind.as_str() {
                "regkey" | "service" => format!("reg:{}", it.path.to_lowercase()),
                "regvalue" => format!("reg:{}\\\u{1}{}", it.path.to_lowercase(), it.value_name.as_deref().unwrap_or("").to_lowercase()),
                "task" => format!("task:{}", it.path.to_lowercase()),
                _ => format!("fs:{}", it.path.to_lowercase()),
            }
        }
        let mut items = self.items;
        items.sort_by(|a, b| {
            container_key(a).len().cmp(&container_key(b).len()).then(rank(&b.confidence).cmp(&rank(&a.confidence)))
        });
        let mut kept: Vec<(String, Leftover)> = Vec::new();
        for it in items {
            let ck = container_key(&it);
            let covered = kept.iter().any(|(k, parent)| {
                *k == ck
                    || (matches!(parent.kind.as_str(), "folder" | "regkey" | "service")
                        && ck.starts_with(&format!("{k}\\"))
                        && rank(&parent.confidence) >= rank(&it.confidence))
            });
            if !covered {
                kept.push((ck, it));
            }
        }
        let mut out: Vec<Leftover> = kept.into_iter().map(|(_, it)| it).collect();
        for it in out.iter_mut() {
            if matches!(it.kind.as_str(), "folder" | "file" | "shortcut") {
                it.size_bytes = dir_size(Path::new(&it.path));
            }
        }
        out.sort_by(|a, b| a.kind.cmp(&b.kind).then(rank(&b.confidence).cmp(&rank(&a.confidence))).then(a.path.cmp(&b.path)));
        out
    }
}

/// MSI "packed" GUID used under Installer\Products.
pub fn pack_guid(code: &str) -> String {
    let g: Vec<char> = code.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if g.len() != 32 {
        return String::new();
    }
    let mut out = String::new();
    out.extend(g[0..8].iter().rev());
    out.extend(g[8..12].iter().rev());
    out.extend(g[12..16].iter().rev());
    for pair in g[16..32].chunks(2) {
        out.push(pair[1]);
        out.push(pair[0]);
    }
    out.to_uppercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packs_msi_guid() {
        assert_eq!(pack_guid("{23170F69-40C1-2702-2301-000001000000}"), "96F071321C0420723210000010000000");
    }

    #[test]
    fn derives_keywords() {
        let mut p = programs::list_win32(false).into_iter().next().expect("at least one program");
        p.name = "Mozilla Firefox (x64 en-US)".into();
        p.publisher = Some("Mozilla".into());
        p.install_location = Some(r"C:\Program Files\Mozilla Firefox".into());
        p.icon_path = Some(r"C:\Program Files\Mozilla Firefox\firefox.exe,0".into());
        let (strong, _) = keywords(&p);
        assert!(strong.contains(&"mozillafirefox".to_string()));
        assert!(strong.contains(&"firefox".to_string()));
        assert!(!strong.contains(&"mozilla".to_string()));
    }

    #[test]
    fn vendor_family_folders() {
        let base = programs::list_win32(false).into_iter().next().expect("at least one program");
        let named = |name: &str, publisher: &str| {
            let mut p = base.clone();
            (p.id, p.name, p.publisher, p.install_location, p.icon_path) =
                (format!("test:{name}"), name.into(), Some(publisher.into()), None, None);
            p
        };
        let u = universe();
        let ts = Ctx::new(&named("360 Total Security", "360 Security Center"), &u);
        assert!(ts.match_name("360SANDBOX").is_some_and(|(c, _)| c != "high"));
        assert!(ts.match_name("360Safe").is_some());
        let cleanpro = Ctx::new(&named("CleanPro", "www.360totalsecurity.com"), &u);
        assert!(cleanpro.match_name("360SANDBOX").is_some());
        let norton = Ctx::new(&named("Norton 360", "Gen Digital Inc."), &u);
        assert!(norton.match_name("360SANDBOX").is_none());
        assert_eq!(family_folder("360SANDBOX"), Some("360"));
        assert_eq!(family_folder("360Zip Projects"), None);
    }

    #[test]
    fn path_mentions_need_a_boundary() {
        assert!(mentions_path(r#""c:\program files\foo\foo.exe" -x"#, r"c:\program files\foo"));
        assert!(!mentions_path(r"c:\program files\foobar\x.exe", r"c:\program files\foo"));
    }

    /// Times each phase of the software scan: `cargo test scan_timing -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn scan_timing() {
        let t = std::time::Instant::now();
        let win32 = programs::list_win32(false);
        println!("registry programs: {:>4} in {:>6} ms", win32.len(), t.elapsed().as_millis());
        let t = std::time::Instant::now();
        let store = programs::list_store();
        println!("store apps:        {:>4} in {:>6} ms", store.len(), t.elapsed().as_millis());
        let t = std::time::Instant::now();
        let found = crate::discover::discover();
        println!("found on drives:   {:>4} in {:>6} ms", found.len(), t.elapsed().as_millis());
        let targets: Vec<Program> = win32.iter().filter(|p| !p.system_component).take(20).cloned().collect();
        let t = std::time::Instant::now();
        let u = universe();
        println!("shared program data (once): {} ms", t.elapsed().as_millis());
        let t = std::time::Instant::now();
        for p in &targets {
            let _ = Ctx::new(p, &u);
        }
        println!("footprint setup x{}: {} ms total", targets.len(), t.elapsed().as_millis());
        let t = std::time::Instant::now();
        let fps = footprints(&targets);
        println!("footprints x{} (parallel): {} ms total ({} GB)", fps.len(), t.elapsed().as_millis(), fps.iter().map(|f| f.total_bytes).sum::<u64>() >> 30);
    }

    /// `PUIRKLE_SCAN=<name filter> cargo test footprint -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn footprint_dry_run() {
        let filter = std::env::var("PUIRKLE_SCAN").unwrap_or_default().to_lowercase();
        let targets: Vec<Program> = programs::list_all(false, false).into_iter().filter(|p| !p.system_component && p.name.to_lowercase().contains(&filter)).collect();
        for f in footprints(&targets) {
            println!("{}  total {} MB (program {} MB, data {} MB, uncertain {} MB)", f.id, f.total_bytes >> 20, f.program_bytes >> 20, f.data_bytes >> 20, f.uncertain_bytes >> 20);
            for u in &f.folders {
                println!("    {:<8} {:<6} {:>8} MB  {}", u.kind, u.confidence, u.size_bytes >> 20, u.path);
            }
        }
    }

    /// Read-only scan of installed programs; deletes nothing.
    /// `PUIRKLE_SCAN=<name filter> cargo test dry_run -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn dry_run() {
        let filter = std::env::var("PUIRKLE_SCAN").unwrap_or_default().to_lowercase();
        let verbose = !filter.is_empty();
        for p in programs::list_all(true, false).iter().filter(|p| !p.system_component && p.name.to_lowercase().contains(&filter)) {
            let t = std::time::Instant::now();
            let items = scan(p, true);
            let n = |c: &str| items.iter().filter(|i| i.confidence == c).count();
            println!("{:<55} high {:>3}  medium {:>3}  low {:>3}  {:>5} ms", p.name, n("high"), n("medium"), n("low"), t.elapsed().as_millis());
            if verbose {
                for i in &items {
                    println!("    [{:<6}] {:<8} {}{}  -- {}", i.confidence, i.kind, i.path, i.value_name.as_deref().map(|v| format!(" -> {v}")).unwrap_or_default(), i.reason);
                }
            }
        }
    }
}

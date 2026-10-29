//! Storage analyzer: what is taking up space on a drive or in a folder.
//!
//! One scan walks the whole tree (several threads, one per top-level folder) and keeps folder
//! sizes in memory, so drilling down in the UI is instant. Junctions and symlinks are not
//! followed (no double counting) and cloud placeholders (OneDrive "online-only" files) count as 0,
//! since they don't use the disk.

use crate::util::wide;
use serde::Serialize;
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;

/// Files at least this big are listed one by one; smaller ones are summed per folder.
const BIG_FILE: u64 = 1024 * 1024;
/// Per-folder cap on individually listed files (the rest join the "other files" total).
const MAX_FILES_PER_DIR: usize = 300;
const TOP_FILES: usize = 300;
const FILE_ATTRIBUTE_RECALL_ON_OPEN: u32 = 0x0004_0000;
const FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS: u32 = 0x0040_0000;

#[derive(Default)]
struct Node {
    size: u64,
    files: u64,
    dirs: Vec<String>,
    big_files: Vec<(String, u64)>,
    other_files: u64,
    other_bytes: u64,
}

struct Tree {
    root: String,
    nodes: HashMap<String, Node>,
    top: Vec<(u64, String)>,
}

static TREE: Mutex<Option<Tree>> = Mutex::new(None);
static CANCEL: AtomicBool = AtomicBool::new(false);
static FILES: AtomicU64 = AtomicU64::new(0);
static BYTES: AtomicU64 = AtomicU64::new(0);
static ERRORS: AtomicU64 = AtomicU64::new(0);
static CURRENT: Mutex<String> = Mutex::new(String::new());

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Drive {
    pub root: String,
    pub total_bytes: u64,
    pub free_bytes: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Summary {
    pub root: String,
    pub total_bytes: u64,
    pub files: u64,
    pub unreadable: u64,
    pub cancelled: bool,
    pub millis: u128,
    /// "fast" (read the NTFS file table) or "walk" (opened every folder)
    pub method: String,
    /// Why the fast method wasn't used, if it wasn't.
    pub fast_unavailable: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Progress {
    pub files: u64,
    pub bytes: u64,
    pub current: String,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Entry {
    pub path: String,
    pub name: String,
    /// "dir", "file" or "other" (the summed small files of a folder)
    pub kind: String,
    pub size_bytes: u64,
    pub files: u64,
}

pub fn drives() -> Vec<Drive> {
    crate::util::fixed_drives()
        .into_iter()
        .map(|d| {
            let root = d.to_string_lossy().into_owned();
            let (mut avail, mut total, mut free) = (0u64, 0u64, 0u64);
            let w = wide(&root);
            unsafe { windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW(w.as_ptr(), &mut avail, &mut total, &mut free) };
            Drive { root, total_bytes: total, free_bytes: free }
        })
        .filter(|d| d.total_bytes > 0)
        .collect()
}

pub fn progress() -> Progress {
    Progress {
        files: FILES.load(Ordering::Relaxed),
        bytes: BYTES.load(Ordering::Relaxed),
        current: CURRENT.lock().map(|c| c.clone()).unwrap_or_default(),
    }
}

pub fn cancel() {
    CANCEL.store(true, Ordering::SeqCst);
}

/// One thread's results while walking part of the tree.
#[derive(Default)]
struct Partial {
    nodes: HashMap<String, Node>,
    top: BinaryHeap<Reverse<(u64, String)>>,
}

impl Partial {
    fn note_top(&mut self, size: u64, path: &str) {
        if self.top.len() < TOP_FILES {
            self.top.push(Reverse((size, path.to_string())));
        } else if self.top.peek().is_some_and(|Reverse((s, _))| size > *s) {
            self.top.pop();
            self.top.push(Reverse((size, path.to_string())));
        }
    }

    /// Walks `dir` recursively; returns (bytes, files) under it.
    fn walk(&mut self, dir: &Path) -> (u64, u64) {
        if CANCEL.load(Ordering::Relaxed) {
            return (0, 0);
        }
        let key = dir.to_string_lossy().into_owned();
        if let Ok(mut c) = CURRENT.lock() {
            c.clone_from(&key);
        }
        let mut node = Node::default();
        let Ok(rd) = std::fs::read_dir(dir) else {
            ERRORS.fetch_add(1, Ordering::Relaxed);
            self.nodes.insert(key, node);
            return (0, 0);
        };
        let mut subdirs = Vec::new();
        for e in rd.filter_map(Result::ok) {
            let Ok(ft) = e.file_type() else { continue };
            if ft.is_symlink() {
                continue; // junctions/symlinks: the target is counted where it really lives
            }
            if ft.is_dir() {
                subdirs.push(e.path());
                continue;
            }
            let Ok(meta) = e.metadata() else { continue };
            let attrs = meta.file_attributes();
            let size = if attrs & (FILE_ATTRIBUTE_RECALL_ON_OPEN | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS) != 0 { 0 } else { meta.len() };
            node.size += size;
            node.files += 1;
            FILES.fetch_add(1, Ordering::Relaxed);
            BYTES.fetch_add(size, Ordering::Relaxed);
            let path = e.path().to_string_lossy().into_owned();
            if size >= BIG_FILE && node.big_files.len() < MAX_FILES_PER_DIR {
                self.note_top(size, &path);
                node.big_files.push((path, size));
            } else {
                if size >= BIG_FILE {
                    self.note_top(size, &path);
                }
                node.other_files += 1;
                node.other_bytes += size;
            }
        }
        for sub in subdirs {
            let (bytes, files) = self.walk(&sub);
            node.size += bytes;
            node.files += files;
            node.dirs.push(sub.to_string_lossy().into_owned());
        }
        let result = (node.size, node.files);
        self.nodes.insert(key, node);
        result
    }
}

/// Scans `root` (a drive like `D:\` or any folder) and keeps the result for drilling down.
/// Whole NTFS drives are read straight from the file table when possible (seconds instead of
/// minutes); anything else is walked folder by folder.
pub fn scan(root: &str) -> Result<Summary, String> {
    let root_path = PathBuf::from(root);
    if !root_path.is_dir() {
        return Err(format!("{root} isn't a folder that can be read."));
    }
    let started = std::time::Instant::now();
    CANCEL.store(false, Ordering::SeqCst);
    FILES.store(0, Ordering::SeqCst);
    BYTES.store(0, Ordering::SeqCst);
    ERRORS.store(0, Ordering::SeqCst);

    let is_drive = root.len() == 3 && root.ends_with(":\\");
    let fast_unavailable = if is_drive {
        match scan_fast(root, started) {
            Ok(summary) => return Ok(summary),
            Err(why) => Some(why),
        }
    } else {
        Some("Fast scanning works on whole drives.".into())
    };
    let mut summary = scan_walk(root, &root_path, started)?;
    summary.fast_unavailable = fast_unavailable;
    Ok(summary)
}

/// Builds the tree from the NTFS file table.
fn scan_fast(root: &str, started: std::time::Instant) -> Result<Summary, String> {
    let vol = crate::mft::read_volume(root, |done, total| {
        FILES.store(done as u64, Ordering::Relaxed);
        if let Ok(mut c) = CURRENT.lock() {
            *c = format!("Reading the drive's file table… {}%", done * 100 / total.max(1));
        }
    })?;
    let n = vol.in_use.len();
    let root_rec = crate::mft::Volume::ROOT;

    // Which records hang off the root folder (deleted or orphaned ones don't).
    let mut state = vec![0u8; n]; // 0 = unknown, 1 = reachable, 2 = not
    state[root_rec] = 1;
    let mut chain = Vec::new();
    for i in 0..n {
        let mut cur = i;
        chain.clear();
        let verdict = loop {
            if state[cur] != 0 {
                break state[cur];
            }
            if !vol.in_use[cur] || chain.len() > 1024 {
                break 2;
            }
            chain.push(cur);
            let p = vol.parent[cur] as usize;
            if p >= n || p == cur {
                break 2;
            }
            cur = p;
        };
        for &c in &chain {
            state[c] = verdict;
        }
    }

    // Folder totals: add every file's size to each folder above it.
    let mut total = vec![0u64; n];
    let mut count = vec![0u64; n];
    let mut kids: HashMap<usize, Vec<usize>> = HashMap::new();
    for i in 0..n {
        if i == root_rec || state[i] != 1 {
            continue;
        }
        kids.entry(vol.parent[i] as usize).or_default().push(i);
        if vol.is_dir[i] {
            continue;
        }
        let size = vol.size[i];
        let mut cur = vol.parent[i] as usize;
        let mut guard = 0;
        loop {
            total[cur] += size;
            count[cur] += 1;
            if cur == root_rec || guard > 1024 {
                break;
            }
            cur = vol.parent[cur] as usize;
            guard += 1;
        }
    }

    // Folder paths, built top-down from the root.
    let mut paths: HashMap<usize, String> = HashMap::new();
    paths.insert(root_rec, root.to_string());
    let mut queue = vec![root_rec];
    let mut nodes: HashMap<String, Node> = HashMap::new();
    let mut top: BinaryHeap<Reverse<(u64, String)>> = BinaryHeap::new();
    while let Some(d) = queue.pop() {
        let dpath = paths[&d].clone();
        let mut node = Node { size: total[d], files: count[d], ..Default::default() };
        let mut files: Vec<(u64, String)> = Vec::new();
        for &c in kids.get(&d).map(Vec::as_slice).unwrap_or(&[]) {
            let Some(name) = vol.name[c].as_deref() else { continue };
            let cpath = if dpath.ends_with('\\') { format!("{dpath}{name}") } else { format!("{dpath}\\{name}") };
            if vol.is_dir[c] {
                node.dirs.push(cpath.clone());
                paths.insert(c, cpath);
                queue.push(c);
            } else if vol.size[c] >= BIG_FILE {
                files.push((vol.size[c], cpath));
            } else {
                node.other_files += 1;
                node.other_bytes += vol.size[c];
            }
        }
        files.sort_by(|a, b| b.0.cmp(&a.0));
        for (i, (size, path)) in files.into_iter().enumerate() {
            if top.len() < TOP_FILES {
                top.push(Reverse((size, path.clone())));
            } else if top.peek().is_some_and(|Reverse((s, _))| size > *s) {
                top.pop();
                top.push(Reverse((size, path.clone())));
            }
            if i < MAX_FILES_PER_DIR {
                node.big_files.push((path, size));
            } else {
                node.other_files += 1;
                node.other_bytes += size;
            }
        }
        nodes.insert(dpath, node);
    }
    let mut top: Vec<(u64, String)> = top.into_iter().map(|Reverse(x)| x).collect();
    top.sort_by(|a, b| b.0.cmp(&a.0));
    BYTES.store(total[root_rec], Ordering::Relaxed);

    let summary = Summary {
        root: root.to_string(),
        total_bytes: total[root_rec],
        files: count[root_rec],
        unreadable: 0,
        cancelled: false,
        millis: started.elapsed().as_millis(),
        method: "fast".into(),
        fast_unavailable: None,
    };
    if let Ok(mut t) = TREE.lock() {
        *t = Some(Tree { root: root.to_string(), nodes, top });
    }
    if let Ok(mut c) = CURRENT.lock() {
        c.clear();
    }
    Ok(summary)
}

/// Builds the tree by opening every folder (works everywhere, but slow on big drives).
fn scan_walk(root: &str, root_path: &Path, started: std::time::Instant) -> Result<Summary, String> {
    let root_path = root_path.to_path_buf();

    // Files directly in the root, then one thread per top-level folder.
    let mut root_part = Partial::default();
    let mut root_node = Node::default();
    let mut top_dirs = Vec::new();
    match std::fs::read_dir(&root_path) {
        Ok(rd) => {
            for e in rd.filter_map(Result::ok) {
                let Ok(ft) = e.file_type() else { continue };
                if ft.is_symlink() {
                    continue;
                }
                if ft.is_dir() {
                    top_dirs.push(e.path());
                } else if let Ok(meta) = e.metadata() {
                    let size = meta.len();
                    root_node.size += size;
                    root_node.files += 1;
                    let path = e.path().to_string_lossy().into_owned();
                    if size >= BIG_FILE {
                        root_part.note_top(size, &path);
                        root_node.big_files.push((path, size));
                    } else {
                        root_node.other_files += 1;
                        root_node.other_bytes += size;
                    }
                }
            }
        }
        Err(e) => return Err(format!("Couldn't read {root}: {e}")),
    }

    let parts: Vec<(PathBuf, (u64, u64), Partial)> = std::thread::scope(|s| {
        let handles: Vec<_> = top_dirs
            .into_iter()
            .map(|d| {
                s.spawn(move || {
                    let mut p = Partial::default();
                    let totals = p.walk(&d);
                    (d, totals, p)
                })
            })
            .collect();
        handles.into_iter().filter_map(|h| h.join().ok()).collect()
    });

    let mut nodes: HashMap<String, Node> = HashMap::new();
    let mut top: Vec<(u64, String)> = root_part.top.into_iter().map(|Reverse(x)| x).collect();
    for (dir, (bytes, files), part) in parts {
        root_node.size += bytes;
        root_node.files += files;
        root_node.dirs.push(dir.to_string_lossy().into_owned());
        nodes.extend(part.nodes);
        top.extend(part.top.into_iter().map(|Reverse(x)| x));
    }
    top.sort_by(|a, b| b.0.cmp(&a.0));
    top.truncate(TOP_FILES);
    let summary = Summary {
        root: root.to_string(),
        total_bytes: root_node.size,
        files: root_node.files,
        unreadable: ERRORS.load(Ordering::Relaxed),
        cancelled: CANCEL.load(Ordering::SeqCst),
        millis: started.elapsed().as_millis(),
        method: "walk".into(),
        fast_unavailable: None,
    };
    nodes.insert(root.to_string(), root_node);
    if let Ok(mut t) = TREE.lock() {
        *t = Some(Tree { root: root.to_string(), nodes, top });
    }
    if let Ok(mut c) = CURRENT.lock() {
        c.clear();
    }
    Ok(summary)
}

#[cfg(test)]
mod tests {
    /// Read-only: `PUIRKLE_ROOT=D:\ cargo test storage_dry_run -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn storage_dry_run() {
        let root = std::env::var("PUIRKLE_ROOT").unwrap_or_else(|_| r"D:\".into());
        let s = super::scan(&root).unwrap();
        println!(
            "{}: {} GB in {} files, {} unreadable folders, {} ms, method={} {}",
            s.root,
            s.total_bytes >> 30,
            s.files,
            s.unreadable,
            s.millis,
            s.method,
            s.fast_unavailable.unwrap_or_default()
        );
        for e in super::children(&root).unwrap().iter().take(12) {
            println!("  {:<6} {:>8} MB  {}", e.kind, e.size_bytes >> 20, e.name);
        }
        println!("largest files:");
        for e in super::top_files(5) {
            println!("  {:>8} MB  {}", e.size_bytes >> 20, e.path);
        }
    }
}

fn leaf(path: &str) -> String {
    Path::new(path).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| path.to_string())
}

/// Folders and big files directly inside `path`, largest first, plus one "other files" entry.
pub fn children(path: &str) -> Result<Vec<Entry>, String> {
    let guard = TREE.lock().map_err(|e| e.to_string())?;
    let tree = guard.as_ref().ok_or("Scan a drive first.")?;
    let node = tree.nodes.get(path).ok_or("That folder isn't part of the last scan.")?;
    let mut out: Vec<Entry> = node
        .dirs
        .iter()
        .filter_map(|d| tree.nodes.get(d).map(|n| Entry { path: d.clone(), name: leaf(d), kind: "dir".into(), size_bytes: n.size, files: n.files }))
        .collect();
    out.extend(node.big_files.iter().map(|(p, s)| Entry { path: p.clone(), name: leaf(p), kind: "file".into(), size_bytes: *s, files: 1 }));
    if node.other_files > 0 {
        out.push(Entry {
            path: format!("{path}\u{1}other"),
            name: format!("{} smaller file{}", node.other_files, if node.other_files == 1 { "" } else { "s" }),
            kind: "other".into(),
            size_bytes: node.other_bytes,
            files: node.other_files,
        });
    }
    out.sort_by(|a, b| b.size_bytes.cmp(&a.size_bytes));
    Ok(out)
}

/// The biggest files anywhere in the last scan.
pub fn top_files(limit: usize) -> Vec<Entry> {
    let Ok(guard) = TREE.lock() else { return Vec::new() };
    let Some(tree) = guard.as_ref() else { return Vec::new() };
    tree.top
        .iter()
        .take(limit)
        .map(|(s, p)| Entry { path: p.clone(), name: leaf(p), kind: "file".into(), size_bytes: *s, files: 1 })
        .collect()
}

/// Moves a file or folder to the Recycle Bin and updates the scan's sizes. Refuses Windows,
/// Program Files, user folders, drive roots and other protected places.
pub fn recycle(path: &str) -> Result<u64, String> {
    if crate::leftovers::is_protected_path(path) {
        return Err("That's a protected Windows or user folder, so PuirkleUninstaller won't delete it.".into());
    }
    let p = Path::new(path);
    if !p.exists() {
        return Err(format!("{path} no longer exists."));
    }
    let size = {
        let guard = TREE.lock().map_err(|e| e.to_string())?;
        guard
            .as_ref()
            .and_then(|t| t.nodes.get(path).map(|n| n.size).or_else(|| t.top.iter().find(|(_, f)| f == path).map(|(s, _)| *s)))
            .unwrap_or_else(|| crate::util::dir_size(p))
    };
    trash::delete(p).map_err(|e| format!("Couldn't move it to the Recycle Bin: {e}"))?;

    // Update the in-memory tree so the view stays right without a rescan.
    if let Ok(mut guard) = TREE.lock() {
        if let Some(tree) = guard.as_mut() {
            tree.nodes.remove(path);
            tree.top.retain(|(_, f)| !(f == path || f.starts_with(&format!("{path}\\"))));
            let mut cur = p.parent();
            let mut first = true;
            while let Some(parent) = cur {
                let key = parent.to_string_lossy().into_owned();
                let Some(node) = tree.nodes.get_mut(&key) else { break };
                node.size = node.size.saturating_sub(size);
                if first {
                    node.dirs.retain(|d| d != path);
                    node.big_files.retain(|(f, _)| f != path);
                    first = false;
                }
                if key == tree.root {
                    break;
                }
                cur = parent.parent();
            }
        }
    }
    Ok(size)
}

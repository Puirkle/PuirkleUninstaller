//! Storage analyzer: what is taking up space on a drive or in a folder.
//!
//! A scan keeps every folder's size in memory, so drilling down in the UI is instant. NTFS drives
//! are read straight from their file table (see `mft`); anything else is walked folder by folder.
//! At startup every drive is scanned in the background, and those results double as instant
//! folder sizes for the program list (`cached_size`).
//!
//! Junctions and symlinks are not followed (no double counting); cloud placeholders (OneDrive
//! "online-only" files) count as 0, since they don't use the disk.

use crate::util::wide;
use serde::Serialize;
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

/// Files at least this big are listed one by one; smaller ones are summed per folder.
const BIG_FILE: u64 = 1024 * 1024;
/// Per-folder cap on individually listed files (the rest join the "other files" total).
const MAX_FILES_PER_DIR: usize = 300;
const TOP_FILES: usize = 300;
const FILE_ATTRIBUTE_RECALL_ON_OPEN: u32 = 0x0004_0000;
const FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS: u32 = 0x0040_0000;

#[derive(Default)]
struct Node {
    /// The folder's path as it's spelled on disk.
    path: String,
    size: u64,
    files: u64,
    /// Subfolders, as spelled on disk.
    dirs: Vec<String>,
    big_files: Vec<(String, u64)>,
    other_files: u64,
    other_bytes: u64,
}

struct Tree {
    root: String,
    /// Keyed by lowercase path, so lookups match however a path is capitalised.
    nodes: HashMap<String, Node>,
    top: Vec<(u64, String)>,
    summary: Summary,
    index: Index,
}

/// Compact list of every file and folder (for instant search): names live in one arena string,
/// and each entry points at its parent folder's path in `dirs`.
#[derive(Default)]
struct Index {
    names: String,
    entries: Vec<IndexEntry>,
    dirs: Vec<String>,
}

#[derive(Clone, Copy)]
struct IndexEntry {
    size: u64,
    name_at: u32,
    parent: u32,
    name_len: u16,
    is_dir: bool,
    /// Removed by a delete since the scan.
    gone: bool,
}

impl Index {
    fn add_dir(&mut self, path: &str) -> u32 {
        self.dirs.push(path.to_string());
        (self.dirs.len() - 1) as u32
    }

    fn add(&mut self, name: &str, parent: u32, size: u64, is_dir: bool) {
        let name_at = self.names.len() as u32;
        let name = if name.len() > u16::MAX as usize { &name[..u16::MAX as usize] } else { name };
        self.names.push_str(name);
        self.entries.push(IndexEntry { size, name_at, parent, name_len: name.len() as u16, is_dir, gone: false });
    }

    fn name(&self, e: &IndexEntry) -> &str {
        &self.names[e.name_at as usize..e.name_at as usize + e.name_len as usize]
    }

    fn path(&self, e: &IndexEntry) -> String {
        let dir = &self.dirs[e.parent as usize];
        if dir.ends_with('\\') { format!("{dir}{}", self.name(e)) } else { format!("{dir}\\{}", self.name(e)) }
    }

    /// Appends another thread's index, re-pointing its entries.
    fn merge(&mut self, other: Index) {
        let (dir_base, name_base) = (self.dirs.len() as u32, self.names.len() as u32);
        self.dirs.extend(other.dirs);
        self.names.push_str(&other.names);
        self.entries.extend(other.entries.into_iter().map(|mut e| {
            e.parent += dir_base;
            e.name_at += name_base;
            e
        }));
    }
}

#[derive(Clone, Copy, PartialEq)]
enum State {
    Scanning,
    Done,
    Failed,
}

/// Finished scans, keyed by lowercase root ("d:\").
static TREES: Mutex<Option<HashMap<String, Tree>>> = Mutex::new(None);
/// Scan state per lowercase root, with a condvar to wait for a running scan.
static STATES: Mutex<Option<HashMap<String, State>>> = Mutex::new(None);
static STATE_CHANGED: Condvar = Condvar::new();

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
    /// "scanning", "done", "failed" or "" (not scanned)
    pub state: String,
}

#[derive(Serialize, Clone)]
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
    /// When the scan finished (local time, HH:MM).
    pub scanned_at: String,
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

fn key(path: &str) -> String {
    path.to_lowercase()
}

fn set_state(root: &str, s: State) {
    let mut g = STATES.lock().unwrap_or_else(|e| e.into_inner());
    g.get_or_insert_with(HashMap::new).insert(key(root), s);
    STATE_CHANGED.notify_all();
}

fn state_of(root: &str) -> Option<State> {
    STATES.lock().ok()?.as_ref()?.get(&key(root)).copied()
}

fn store(tree: Tree) {
    let mut g = TREES.lock().unwrap_or_else(|e| e.into_inner());
    g.get_or_insert_with(HashMap::new).insert(key(&tree.root), tree);
}

pub fn drives() -> Vec<Drive> {
    crate::util::fixed_drives()
        .into_iter()
        .map(|d| {
            let root = d.to_string_lossy().into_owned();
            let (mut avail, mut total, mut free) = (0u64, 0u64, 0u64);
            let w = wide(&root);
            unsafe { windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW(w.as_ptr(), &mut avail, &mut total, &mut free) };
            let state = match state_of(&root) {
                Some(State::Scanning) => "scanning",
                Some(State::Done) => "done",
                Some(State::Failed) => "failed",
                None => "",
            };
            Drive { root, total_bytes: total, free_bytes: free, state: state.into() }
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

/// The last finished scan of `root`, if any.
pub fn summary(root: &str) -> Option<Summary> {
    TREES.lock().ok()?.as_ref()?.get(&key(root)).map(|t| t.summary.clone())
}

/// Scans every fixed drive in parallel using the fast NTFS method only (it needs administrator
/// rights; drives where it isn't possible are skipped rather than walked, which would take
/// minutes and slow everything else down).
pub fn scan_all_fast() -> Vec<Summary> {
    let drives: Vec<String> = crate::util::fixed_drives().into_iter().map(|d| d.to_string_lossy().into_owned()).collect();
    for d in &drives {
        set_state(d, State::Scanning);
    }
    std::thread::scope(|s| {
        let handles: Vec<_> = drives
            .iter()
            .map(|d| {
                s.spawn(move || {
                    let started = Instant::now();
                    match scan_fast(d, started) {
                        Ok(summary) => {
                            set_state(d, State::Done);
                            Some(summary)
                        }
                        Err(_) => {
                            set_state(d, State::Failed);
                            None
                        }
                    }
                })
            })
            .collect();
        handles.into_iter().filter_map(|h| h.join().ok().flatten()).collect()
    })
}

/// Size of folder `path` from a drive scan: instant once that drive is scanned. If its drive is
/// being scanned right now, waits for that scan (up to two minutes) instead of reading the disk
/// a second time. `None` when no scan covers it.
pub fn cached_size(path: &str) -> Option<u64> {
    let lower = key(path.trim_end_matches('\\'));
    let drive = lower.get(..3).filter(|d| d.ends_with(":\\"))?.to_string();
    {
        let mut g = STATES.lock().ok()?;
        let deadline = Instant::now() + Duration::from_secs(120);
        while g.as_ref().and_then(|m| m.get(&drive)) == Some(&State::Scanning) {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return None;
            }
            g = STATE_CHANGED.wait_timeout(g, left).ok()?.0;
        }
    }
    let trees = TREES.lock().ok()?;
    let tree = trees.as_ref()?.get(&drive)?;
    let lookup = if lower.len() < 3 { drive.clone() } else if lower.len() == 2 { format!("{lower}\\") } else { lower };
    tree.nodes.get(&lookup).map(|n| n.size)
}

/// One thread's results while walking part of the tree.
#[derive(Default)]
struct Partial {
    nodes: HashMap<String, Node>,
    top: BinaryHeap<Reverse<(u64, String)>>,
    index: Index,
}

fn note_top(top: &mut BinaryHeap<Reverse<(u64, String)>>, size: u64, path: &str) {
    if top.len() < TOP_FILES {
        top.push(Reverse((size, path.to_string())));
    } else if top.peek().is_some_and(|Reverse((s, _))| size > *s) {
        top.pop();
        top.push(Reverse((size, path.to_string())));
    }
}

impl Partial {
    /// Walks `dir` recursively; returns (bytes, files) under it.
    fn walk(&mut self, dir: &Path) -> (u64, u64) {
        let path = dir.to_string_lossy().into_owned();
        if CANCEL.load(Ordering::Relaxed) {
            return (0, 0);
        }
        if let Ok(mut c) = CURRENT.lock() {
            c.clone_from(&path);
        }
        let mut node = Node { path: path.clone(), ..Default::default() };
        let me = self.index.add_dir(&path);
        let Ok(rd) = std::fs::read_dir(dir) else {
            ERRORS.fetch_add(1, Ordering::Relaxed);
            self.nodes.insert(key(&path), node);
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
            self.index.add(&e.file_name().to_string_lossy(), me, size, false);
            let fpath = e.path().to_string_lossy().into_owned();
            if size >= BIG_FILE {
                note_top(&mut self.top, size, &fpath);
            }
            if size >= BIG_FILE && node.big_files.len() < MAX_FILES_PER_DIR {
                node.big_files.push((fpath, size));
            } else {
                node.other_files += 1;
                node.other_bytes += size;
            }
        }
        for sub in subdirs {
            let (bytes, files) = self.walk(&sub);
            node.size += bytes;
            node.files += files;
            self.index.add(&leaf(&sub.to_string_lossy()), me, bytes, true);
            node.dirs.push(sub.to_string_lossy().into_owned());
        }
        let result = (node.size, node.files);
        self.nodes.insert(key(&path), node);
        result
    }
}

fn now_hhmm() -> String {
    chrono::Local::now().format("%H:%M").to_string()
}

/// Scans `root` (a drive like `D:\` or any folder) on request and keeps the result. Whole NTFS
/// drives are read from the file table when possible (seconds); anything else is walked.
pub fn scan(root: &str) -> Result<Summary, String> {
    let root_path = PathBuf::from(root);
    if !root_path.is_dir() {
        return Err(format!("{root} isn't a folder that can be read."));
    }
    let started = Instant::now();
    CANCEL.store(false, Ordering::SeqCst);
    FILES.store(0, Ordering::SeqCst);
    BYTES.store(0, Ordering::SeqCst);
    ERRORS.store(0, Ordering::SeqCst);

    let is_drive = root.len() == 3 && root.ends_with(":\\");
    if is_drive {
        set_state(root, State::Scanning);
    }
    let fast = if is_drive { scan_fast(root, started) } else { Err("Fast scanning works on whole drives.".into()) };
    let result = match fast {
        Ok(summary) => Ok(summary),
        Err(why) => scan_walk(root, &root_path, started, Some(why)),
    };
    if is_drive {
        set_state(root, if result.is_ok() { State::Done } else { State::Failed });
    }
    result
}

/// Builds the tree from the NTFS file table.
fn scan_fast(root: &str, started: Instant) -> Result<Summary, String> {
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

    // Folder nodes and the search index, built top-down from the root.
    let mut index = Index::default();
    let mut dir_idx: HashMap<usize, u32> = HashMap::new();
    dir_idx.insert(root_rec, index.add_dir(root));
    let mut queue = vec![root_rec];
    let mut nodes: HashMap<String, Node> = HashMap::new();
    let mut top: BinaryHeap<Reverse<(u64, String)>> = BinaryHeap::new();
    while let Some(d) = queue.pop() {
        let didx = dir_idx[&d];
        let dpath = index.dirs[didx as usize].clone();
        let mut node = Node { path: dpath.clone(), size: total[d], files: count[d], ..Default::default() };
        let mut files: Vec<(u64, String)> = Vec::new();
        for &c in kids.get(&d).map(Vec::as_slice).unwrap_or(&[]) {
            let Some(name) = vol.name[c].as_deref() else { continue };
            let cpath = if dpath.ends_with('\\') { format!("{dpath}{name}") } else { format!("{dpath}\\{name}") };
            if vol.is_dir[c] {
                index.add(name, didx, total[c], true);
                dir_idx.insert(c, index.add_dir(&cpath));
                node.dirs.push(cpath);
                queue.push(c);
            } else {
                index.add(name, didx, vol.size[c], false);
                if vol.size[c] >= BIG_FILE {
                    files.push((vol.size[c], cpath));
                } else {
                    node.other_files += 1;
                    node.other_bytes += vol.size[c];
                }
            }
        }
        files.sort_by(|a, b| b.0.cmp(&a.0));
        for (i, (size, path)) in files.into_iter().enumerate() {
            note_top(&mut top, size, &path);
            if i < MAX_FILES_PER_DIR {
                node.big_files.push((path, size));
            } else {
                node.other_files += 1;
                node.other_bytes += size;
            }
        }
        nodes.insert(key(&dpath), node);
    }
    let mut top: Vec<(u64, String)> = top.into_iter().map(|Reverse(x)| x).collect();
    top.sort_by(|a, b| b.0.cmp(&a.0));

    let summary = Summary {
        root: root.to_string(),
        total_bytes: total[root_rec],
        files: count[root_rec],
        unreadable: 0,
        cancelled: false,
        millis: started.elapsed().as_millis(),
        method: "fast".into(),
        fast_unavailable: None,
        scanned_at: now_hhmm(),
    };
    store(Tree { root: root.to_string(), nodes, top, summary: summary.clone(), index });
    if let Ok(mut c) = CURRENT.lock() {
        c.clear();
    }
    Ok(summary)
}

/// Builds the tree by opening every folder (works everywhere, but slow on big drives).
fn scan_walk(root: &str, root_path: &Path, started: Instant, fast_unavailable: Option<String>) -> Result<Summary, String> {
    // Files directly in the root, then one thread per top-level folder.
    let mut root_top = BinaryHeap::new();
    let mut root_node = Node { path: root.to_string(), ..Default::default() };
    let mut index = Index::default();
    let root_idx = index.add_dir(root);
    let mut top_dirs = Vec::new();
    let rd = std::fs::read_dir(root_path).map_err(|e| format!("Couldn't read {root}: {e}"))?;
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
            index.add(&e.file_name().to_string_lossy(), root_idx, size, false);
            let path = e.path().to_string_lossy().into_owned();
            if size >= BIG_FILE {
                note_top(&mut root_top, size, &path);
                root_node.big_files.push((path, size));
            } else {
                root_node.other_files += 1;
                root_node.other_bytes += size;
            }
        }
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
    let mut top: Vec<(u64, String)> = root_top.into_iter().map(|Reverse(x)| x).collect();
    for (dir, (bytes, files), part) in parts {
        root_node.size += bytes;
        root_node.files += files;
        index.add(&leaf(&dir.to_string_lossy()), root_idx, bytes, true);
        root_node.dirs.push(dir.to_string_lossy().into_owned());
        nodes.extend(part.nodes);
        top.extend(part.top.into_iter().map(|Reverse(x)| x));
        index.merge(part.index);
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
        fast_unavailable,
        scanned_at: now_hhmm(),
    };
    nodes.insert(key(root), root_node);
    store(Tree { root: root.to_string(), nodes, top, summary: summary.clone(), index });
    if let Ok(mut c) = CURRENT.lock() {
        c.clear();
    }
    Ok(summary)
}

fn leaf(path: &str) -> String {
    Path::new(path).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| path.to_string())
}

/// Runs `f` on the scan that contains `path` (the one with the longest matching root).
fn with_tree<T>(path: &str, f: impl FnOnce(&mut Tree) -> T) -> Option<T> {
    let mut g = TREES.lock().ok()?;
    let trees = g.as_mut()?;
    let lower = key(path);
    let root = trees.keys().filter(|r| lower.starts_with(r.as_str())).max_by_key(|r| r.len())?.clone();
    trees.get_mut(&root).map(f)
}

/// Folders and big files directly inside `path`, largest first, plus one "other files" entry.
pub fn children(path: &str) -> Result<Vec<Entry>, String> {
    with_tree(path, |tree| {
        let node = tree.nodes.get(&key(path)).ok_or("That folder isn't part of the last scan.")?;
        let mut out: Vec<Entry> = node
            .dirs
            .iter()
            .filter_map(|d| {
                tree.nodes.get(&key(d)).map(|n| Entry { path: n.path.clone(), name: leaf(d), kind: "dir".into(), size_bytes: n.size, files: n.files })
            })
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
    })
    .unwrap_or_else(|| Err("Scan this drive first.".into()))
}

/// The biggest files anywhere in the scan of `root`.
pub fn top_files(root: &str, limit: usize) -> Vec<Entry> {
    with_tree(root, |tree| {
        tree.top
            .iter()
            .take(limit)
            .map(|(s, p)| Entry { path: p.clone(), name: leaf(p), kind: "file".into(), size_bytes: *s, files: 1 })
            .collect()
    })
    .unwrap_or_default()
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchResult {
    pub items: Vec<Entry>,
    /// How many matched in total (only the biggest `limit` are returned).
    pub total: usize,
    /// How many files and folders were searched.
    pub searched: usize,
    pub millis: u128,
}

/// One search term: plain text matches anywhere in the name; `*` and `?` are wildcards over the
/// whole name (`*.iso`).
fn term_matches(term: &str, name: &str) -> bool {
    if term.contains(['*', '?']) {
        wildcard(term.as_bytes(), name.as_bytes())
    } else {
        name.contains(term)
    }
}

fn wildcard(p: &[u8], s: &[u8]) -> bool {
    let (mut pi, mut si, mut star, mut mark) = (0, 0, None, 0);
    while si < s.len() {
        if pi < p.len() && (p[pi] == b'?' || p[pi] == s[si]) {
            pi += 1;
            si += 1;
        } else if pi < p.len() && p[pi] == b'*' {
            star = Some(pi);
            mark = si;
            pi += 1;
        } else if let Some(st) = star {
            pi = st + 1;
            mark += 1;
            si = mark;
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|&c| c == b'*')
}

/// Instant search over every file and folder in the scans (all drives, or just `root`), like
/// Everything: all words must match the name (case-insensitive). Results are the biggest matches.
pub fn search(query: &str, kind: &str, root: Option<&str>, limit: usize) -> SearchResult {
    let started = Instant::now();
    let terms: Vec<String> = query.split_whitespace().map(|t| t.to_lowercase()).collect();
    let mut best: BinaryHeap<Reverse<(u64, usize, usize)>> = BinaryHeap::new(); // (size, tree, entry)
    let (mut total, mut searched) = (0usize, 0usize);
    let Ok(g) = TREES.lock() else { return SearchResult { items: Vec::new(), total: 0, searched: 0, millis: 0 } };
    let trees: Vec<&Tree> = g
        .as_ref()
        .map(|m| m.values().filter(|t| root.is_none_or(|r| key(&t.root) == key(r))).collect())
        .unwrap_or_default();
    // Split every scan into chunks and search them on all CPU cores at once.
    let threads = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4).clamp(1, 16);
    let terms = &terms;
    let partials: Vec<(BinaryHeap<Reverse<(u64, usize, usize)>>, usize, usize)> = std::thread::scope(|s| {
        let mut handles = Vec::new();
        for (ti, tree) in trees.iter().enumerate() {
            let entries = &tree.index.entries;
            let chunk = (entries.len() / threads).max(20_000);
            for (ci, slice) in entries.chunks(chunk).enumerate() {
                let index = &tree.index;
                handles.push(s.spawn(move || {
                    let mut heap: BinaryHeap<Reverse<(u64, usize, usize)>> = BinaryHeap::new();
                    let (mut total, mut searched) = (0usize, 0usize);
                    let mut lower = String::new();
                    for (j, e) in slice.iter().enumerate() {
                        if e.gone || (kind == "files" && e.is_dir) || (kind == "folders" && !e.is_dir) {
                            continue;
                        }
                        searched += 1;
                        if !terms.is_empty() {
                            // Case-insensitive: lowercase into a reused buffer (no allocation).
                            lower.clear();
                            lower.push_str(index.name(e));
                            lower.make_ascii_lowercase();
                            if !terms.iter().all(|t| term_matches(t, &lower)) {
                                continue;
                            }
                        }
                        total += 1;
                        let item = (e.size, ti, ci * chunk + j);
                        if heap.len() < limit {
                            heap.push(Reverse(item));
                        } else if heap.peek().is_some_and(|Reverse((s, _, _))| e.size > *s) {
                            heap.pop();
                            heap.push(Reverse(item));
                        }
                    }
                    (heap, total, searched)
                }));
            }
        }
        handles.into_iter().filter_map(|h| h.join().ok()).collect()
    });
    for (heap, t, s) in partials {
        total += t;
        searched += s;
        for Reverse(item) in heap {
            if best.len() < limit {
                best.push(Reverse(item));
            } else if best.peek().is_some_and(|Reverse((s, _, _))| item.0 > *s) {
                best.pop();
                best.push(Reverse(item));
            }
        }
    }
    let mut hits: Vec<(u64, usize, usize)> = best.into_iter().map(|Reverse(x)| x).collect();
    hits.sort_by(|a, b| b.0.cmp(&a.0));
    let items = hits
        .into_iter()
        .map(|(size, ti, ei)| {
            let idx = &trees[ti].index;
            let e = &idx.entries[ei];
            Entry { path: idx.path(e), name: idx.name(e).to_string(), kind: if e.is_dir { "dir" } else { "file" }.into(), size_bytes: size, files: 0 }
        })
        .collect();
    SearchResult { items, total, searched, millis: started.elapsed().as_millis() }
}

/// The folders where space really sits, across a whole scan: folders whose size isn't mostly
/// one subfolder (so `C:\Users` is skipped when `C:\Users\Name` holds most of it).
pub fn largest_folders(root: &str, limit: usize) -> Vec<Entry> {
    with_tree(root, |tree| {
        let mut out: Vec<Entry> = tree
            .nodes
            .values()
            .filter(|n| key(&n.path) != key(&tree.root) && n.size > 0)
            .filter(|n| {
                let biggest_child = n.dirs.iter().filter_map(|d| tree.nodes.get(&key(d))).map(|c| c.size).max().unwrap_or(0);
                biggest_child * 10 < n.size * 6
            })
            .map(|n| Entry { path: n.path.clone(), name: leaf(&n.path), kind: "dir".into(), size_bytes: n.size, files: n.files })
            .collect();
        out.sort_by(|a, b| b.size_bytes.cmp(&a.size_bytes));
        out.truncate(limit);
        out
    })
    .unwrap_or_default()
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
    let lower = key(path);
    let known = with_tree(path, |t| t.nodes.get(&lower).map(|n| n.size).or_else(|| t.top.iter().find(|(_, f)| key(f) == lower).map(|(s, _)| *s))).flatten();
    // Look the size up before touching the tree lock again (dir_size may consult the scans).
    let size = known.unwrap_or_else(|| if p.is_file() { p.metadata().map(|m| m.len()).unwrap_or(0) } else { crate::util::dir_size(p) });
    trash::delete(p).map_err(|e| format!("Couldn't move it to the Recycle Bin: {e}"))?;
    forget(path, size);
    Ok(size)
}

/// Removes `path` (`size` bytes) from the scans after it was deleted, so totals stay right.
pub fn forget(path: &str, size: u64) {
    let lower = key(path);
    with_tree(path, |tree| {
        let prefix = format!("{lower}\\");
        tree.nodes.retain(|k, _| *k != lower && !k.starts_with(&prefix));
        tree.top.retain(|(_, f)| {
            let f = key(f);
            f != lower && !f.starts_with(&prefix)
        });
        let mut cur = Path::new(path).parent();
        let mut first = true;
        while let Some(parent) = cur {
            let Some(node) = tree.nodes.get_mut(&key(&parent.to_string_lossy())) else { break };
            node.size = node.size.saturating_sub(size);
            if first {
                node.dirs.retain(|d| key(d) != lower);
                node.big_files.retain(|(f, _)| key(f) != lower);
                first = false;
            }
            if key(&node.path) == key(&tree.root) {
                break;
            }
            cur = parent.parent();
        }
        tree.summary.total_bytes = tree.summary.total_bytes.saturating_sub(size);
        // Hide it (and anything inside it) from search.
        let idx = &mut tree.index;
        let gone_dirs: std::collections::HashSet<u32> = idx
            .dirs
            .iter()
            .enumerate()
            .filter(|(_, d)| {
                let d = key(d);
                d == lower || d.starts_with(&prefix)
            })
            .map(|(i, _)| i as u32)
            .collect();
        let entries = std::mem::take(&mut idx.entries);
        idx.entries = entries
            .into_iter()
            .map(|mut e| {
                if gone_dirs.contains(&e.parent) || key(&idx.path(&e)) == lower {
                    e.gone = true;
                }
                e
            })
            .collect();
    });
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
        for e in super::top_files(&root, 5) {
            println!("  {:>8} MB  {}", e.size_bytes >> 20, e.path);
        }
    }

    /// Elevated: scan every drive at once, then time program-folder size lookups against it.
    /// `cargo test --release startup_scan -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn startup_scan() {
        let t = std::time::Instant::now();
        let all = super::scan_all_fast();
        for s in &all {
            println!("{}: {} GB, {} files, {} ms", s.root, s.total_bytes >> 30, s.files, s.millis);
        }
        println!("all drives in parallel: {} ms", t.elapsed().as_millis());
        let programs = crate::programs::list_win32(false);
        let t = std::time::Instant::now();
        let hits = programs.iter().filter_map(|p| p.install_location.as_deref()).filter_map(super::cached_size).count();
        println!("{hits} program folder sizes looked up in {} µs", t.elapsed().as_micros());
        for (q, kind) in [("mp4", "files"), ("*.iso", "files"), ("steam", "folders"), ("2026 mp4", "all")] {
            let r = super::search(q, kind, None, 500);
            let first = r.items.first().map(|e| format!("{} ({} MB)", e.path, e.size_bytes >> 20)).unwrap_or_default();
            println!("search {q:?} [{kind}]: {} matches of {} in {} ms; biggest: {first}", r.total, r.searched, r.millis);
        }
        let t = std::time::Instant::now();
        let largest = super::largest_folders(r"C:\", 5);
        println!("largest folders on C: in {} ms:", t.elapsed().as_millis());
        for e in largest {
            println!("  {:>8} MB  {}", e.size_bytes >> 20, e.path);
        }
    }
}

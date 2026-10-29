//! Storage analyzer: what is taking up space on a drive or in a folder.
//!
//! A scan keeps every file and folder of a drive in memory, compactly: one 24-byte record per
//! file or folder, one 32-byte record per folder, and all names in a single buffer. Full paths
//! are rebuilt from parent links only when shown. That one structure serves browsing, the
//! largest-folders list, Everything-style search and instant folder sizes for the program list.
//!
//! NTFS drives are read straight from their file table (see `mft`); anything else is walked
//! folder by folder. At startup every drive is scanned in the background (`scan_all_fast`).
//! Junctions and symlinks are not followed (no double counting); cloud placeholders (OneDrive
//! "online-only" files) count as 0, since they don't use the disk.

use crate::util::wide;
use serde::Serialize;
use std::cmp::Reverse;
use std::collections::hash_map::DefaultHasher;
use std::collections::{BinaryHeap, HashMap};
use std::hash::Hasher;
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

/// Files at least this big compete for the drive's "largest files" list.
const BIG_FILE: u64 = 1024 * 1024;
/// A folder lists every file, biggest first, up to this many (the rest are summed in one row).
const MAX_FILES_PER_DIR: usize = 1000;
const TOP_FILES: usize = 300;
const NONE: u32 = u32::MAX;
const FILE_ATTRIBUTE_RECALL_ON_OPEN: u32 = 0x0004_0000;
const FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS: u32 = 0x0040_0000;

/// A file or folder. Each folder's children are stored next to each other.
#[derive(Clone, Copy)]
struct Rec {
    size: u64,
    name_at: u32,
    /// The folder it's in.
    parent: u32,
    /// For a folder, its id in `dirs`; NONE for files.
    dir: u32,
    name_len: u16,
    gone: bool,
}

#[derive(Clone, Copy)]
struct Dir {
    /// Its own record (NONE for the scan's root).
    rec: u32,
    parent: u32,
    size: u64,
    files: u64,
    /// Its children: recs[start..start + len].
    start: u32,
    len: u32,
}

impl Default for Dir {
    fn default() -> Self {
        Dir { rec: NONE, parent: NONE, size: 0, files: 0, start: 0, len: 0 }
    }
}

/// Collects records while scanning; several threads build their own and merge.
#[derive(Default)]
struct Builder {
    names: String,
    recs: Vec<Rec>,
    dirs: Vec<Dir>,
    /// (hash of the lowercase path, folder id), for finding folders by path.
    hashes: Vec<(u64, u32)>,
    /// Biggest files as (size, rec).
    top: BinaryHeap<Reverse<(u64, u32)>>,
}

impl Builder {
    fn add_dir(&mut self, parent: u32, path: &str) -> u32 {
        let id = self.dirs.len() as u32;
        self.dirs.push(Dir { parent, ..Default::default() });
        self.hashes.push((hash_path(path), id));
        id
    }

    fn add_rec(&mut self, name: &str, parent: u32, size: u64, dir: u32) -> u32 {
        let name = if name.len() > u16::MAX as usize { &name[..u16::MAX as usize] } else { name };
        let id = self.recs.len() as u32;
        self.recs.push(Rec { size, name_at: self.names.len() as u32, parent, dir, name_len: name.len() as u16, gone: false });
        self.names.push_str(name);
        if dir != NONE {
            self.dirs[dir as usize].rec = id;
        } else if size >= BIG_FILE {
            if self.top.len() < TOP_FILES {
                self.top.push(Reverse((size, id)));
            } else if self.top.peek().is_some_and(|Reverse((s, _))| size > *s) {
                self.top.pop();
                self.top.push(Reverse((size, id)));
            }
        }
        id
    }

    /// Appends another builder (from another thread), re-pointing its ids. Returns the id its
    /// first folder got here.
    fn merge(&mut self, other: Builder) -> u32 {
        let (dir_off, rec_off, name_off) = (self.dirs.len() as u32, self.recs.len() as u32, self.names.len() as u32);
        let shift = |v: u32, off: u32| if v == NONE { NONE } else { v + off };
        self.names.push_str(&other.names);
        self.recs.extend(other.recs.into_iter().map(|mut r| {
            r.name_at += name_off;
            r.parent = shift(r.parent, dir_off);
            r.dir = shift(r.dir, dir_off);
            r
        }));
        self.dirs.extend(other.dirs.into_iter().map(|mut d| {
            d.rec = shift(d.rec, rec_off);
            d.parent = shift(d.parent, dir_off);
            d.start += rec_off;
            d
        }));
        self.hashes.extend(other.hashes.into_iter().map(|(h, id)| (h, id + dir_off)));
        for Reverse((size, rec)) in other.top {
            self.top.push(Reverse((size, rec + rec_off)));
            if self.top.len() > TOP_FILES {
                self.top.pop();
            }
        }
        dir_off
    }

    /// Records children recs[start..] as the contents of folder `dir`.
    fn close_dir(&mut self, dir: u32, start: u32, size: u64, files: u64) {
        let d = &mut self.dirs[dir as usize];
        d.start = start;
        d.len = self.recs.len() as u32 - start;
        d.size = size;
        d.files = files;
    }
}

struct Tree {
    root: String,
    names: String,
    recs: Vec<Rec>,
    dirs: Vec<Dir>,
    /// Hash of a folder's lowercase path -> folder id (collisions probe to the next slot).
    lookup: HashMap<u64, u32>,
    top: Vec<u32>,
    summary: Summary,
}

/// Normalizes a path for lookups: lowercase ASCII, no trailing backslash except on a drive root.
fn norm_path(path: &str) -> String {
    let mut p = path.trim().replace('/', "\\");
    if p.len() == 2 && p.ends_with(':') {
        p.push('\\');
    }
    while p.len() > 3 && p.ends_with('\\') {
        p.pop();
    }
    p.make_ascii_lowercase();
    p
}

fn hash_path(path: &str) -> u64 {
    let mut h = DefaultHasher::new();
    h.write(norm_path(path).as_bytes());
    h.finish()
}

fn join(dir: &str, name: &str) -> String {
    if dir.ends_with('\\') { format!("{dir}{name}") } else { format!("{dir}\\{name}") }
}

impl Tree {
    fn from_builder(root: &str, b: Builder, summary: Summary) -> Tree {
        let mut lookup = HashMap::with_capacity(b.hashes.len());
        for (h, id) in b.hashes {
            let mut k = h;
            while lookup.contains_key(&k) {
                k = k.wrapping_add(1);
            }
            lookup.insert(k, id);
        }
        let mut top: Vec<(u64, u32)> = b.top.into_iter().map(|Reverse(x)| x).collect();
        top.sort_by(|a, b| b.0.cmp(&a.0));
        let mut t = Tree {
            root: root.to_string(),
            names: b.names,
            recs: b.recs,
            dirs: b.dirs,
            lookup,
            top: top.into_iter().map(|(_, r)| r).collect(),
            summary,
        };
        t.names.shrink_to_fit();
        t.recs.shrink_to_fit();
        t.dirs.shrink_to_fit();
        t
    }

    fn name(&self, r: &Rec) -> &str {
        &self.names[r.name_at as usize..r.name_at as usize + r.name_len as usize]
    }

    fn dir_path(&self, mut id: u32) -> String {
        let mut parts = Vec::new();
        while id != 0 && id != NONE && parts.len() < 1024 {
            let d = &self.dirs[id as usize];
            parts.push(self.name(&self.recs[d.rec as usize]));
            id = d.parent;
        }
        let mut path = self.root.clone();
        for (i, part) in parts.iter().rev().enumerate() {
            if i > 0 || !path.ends_with('\\') {
                path.push('\\');
            }
            path.push_str(part);
        }
        path
    }

    fn rec_path(&self, rec: u32) -> String {
        let r = &self.recs[rec as usize];
        join(&self.dir_path(r.parent), self.name(r))
    }

    fn find_dir(&self, path: &str) -> Option<u32> {
        let want = norm_path(path);
        let mut k = hash_path(path);
        for _ in 0..64 {
            let id = *self.lookup.get(&k)?;
            if norm_path(&self.dir_path(id)) == want {
                return Some(id);
            }
            k = k.wrapping_add(1);
        }
        None
    }

    /// The record of a file or folder by path.
    fn find_rec(&self, path: &str) -> Option<u32> {
        if let Some(id) = self.find_dir(path) {
            return Some(self.dirs[id as usize].rec).filter(|&r| r != NONE);
        }
        let p = Path::new(path);
        let parent = self.find_dir(&p.parent()?.to_string_lossy())?;
        let name = p.file_name()?.to_string_lossy();
        let d = &self.dirs[parent as usize];
        (d.start..d.start + d.len).find(|&r| self.name(&self.recs[r as usize]).eq_ignore_ascii_case(&name))
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

/// Runs `f` on the scan that contains `path` (the one with the longest matching root).
fn with_tree<T>(path: &str, f: impl FnOnce(&mut Tree) -> T) -> Option<T> {
    let mut g = TREES.lock().ok()?;
    let trees = g.as_mut()?;
    let lower = key(path);
    let root = trees.keys().filter(|r| lower.starts_with(r.as_str()) || lower == r.trim_end_matches('\\')).max_by_key(|r| r.len())?.clone();
    trees.get_mut(&root).map(f)
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
                s.spawn(move || match scan_fast(d, Instant::now()) {
                    Ok(summary) => {
                        set_state(d, State::Done);
                        Some(summary)
                    }
                    Err(_) => {
                        set_state(d, State::Failed);
                        None
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
    let lower = norm_path(path);
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
    tree.find_dir(path).map(|id| tree.dirs[id as usize].size)
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

    // Children of each record as one flat array (offsets per parent), and folder totals.
    let mut offsets = vec![0u32; n + 1];
    for i in 0..n {
        if i != root_rec && state[i] == 1 {
            offsets[vol.parent[i] as usize + 1] += 1;
        }
    }
    for i in 0..n {
        offsets[i + 1] += offsets[i];
    }
    let mut kids = vec![0u32; offsets[n] as usize];
    let mut fill = offsets.clone();
    let mut total = vec![0u64; n];
    let mut count = vec![0u64; n];
    for i in 0..n {
        if i == root_rec || state[i] != 1 {
            continue;
        }
        let p = vol.parent[i] as usize;
        kids[fill[p] as usize] = i as u32;
        fill[p] += 1;
        if vol.is_dir[i] {
            continue;
        }
        let size = vol.size[i];
        let mut cur = p;
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
    drop(fill);
    drop(state);

    // Folder by folder from the root, children stored together.
    let mut b = Builder::default();
    let root_id = b.add_dir(NONE, root);
    let mut queue: Vec<(usize, u32, String)> = vec![(root_rec, root_id, root.to_string())];
    while let Some((d, did, dpath)) = queue.pop() {
        let start = b.recs.len() as u32;
        for &c in &kids[offsets[d] as usize..offsets[d + 1] as usize] {
            let c = c as usize;
            let Some(name) = vol.name(c) else { continue };
            if vol.is_dir[c] {
                let cpath = join(&dpath, name);
                let cid = b.add_dir(did, &cpath);
                b.add_rec(name, did, total[c], cid);
                queue.push((c, cid, cpath));
            } else {
                b.add_rec(name, did, vol.size[c], NONE);
            }
        }
        b.close_dir(did, start, total[d], count[d]);
    }

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
    drop(vol);
    store(Tree::from_builder(root, b, summary.clone()));
    if let Ok(mut c) = CURRENT.lock() {
        c.clear();
    }
    Ok(summary)
}

/// Walks `dir` recursively into `b`; returns (folder id, bytes, files).
fn walk(b: &mut Builder, dir: &Path, parent: u32) -> (u32, u64, u64) {
    let path = dir.to_string_lossy().into_owned();
    let id = b.add_dir(parent, &path);
    if CANCEL.load(Ordering::Relaxed) {
        b.close_dir(id, b.recs.len() as u32, 0, 0);
        return (id, 0, 0);
    }
    if let Ok(mut c) = CURRENT.lock() {
        c.clone_from(&path);
    }
    let Ok(rd) = std::fs::read_dir(dir) else {
        ERRORS.fetch_add(1, Ordering::Relaxed);
        b.close_dir(id, b.recs.len() as u32, 0, 0);
        return (id, 0, 0);
    };
    let (mut files, mut subdirs) = (Vec::new(), Vec::new());
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
        FILES.fetch_add(1, Ordering::Relaxed);
        BYTES.fetch_add(size, Ordering::Relaxed);
        files.push((e.file_name().to_string_lossy().into_owned(), size));
    }
    let (mut bytes, mut count) = (files.iter().map(|f| f.1).sum::<u64>(), files.len() as u64);
    let mut subs = Vec::new();
    for sub in subdirs {
        let (cid, sb, sc) = walk(b, &sub, id);
        bytes += sb;
        count += sc;
        subs.push((sub.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default(), cid, sb));
    }
    let start = b.recs.len() as u32;
    for (name, size) in files {
        b.add_rec(&name, id, size, NONE);
    }
    for (name, cid, size) in subs {
        b.add_rec(&name, id, size, cid);
    }
    b.close_dir(id, start, bytes, count);
    (id, bytes, count)
}

/// Builds the tree by opening every folder (works everywhere, but slow on big drives). One
/// thread per top-level folder.
fn scan_walk(root: &str, root_path: &Path, started: Instant, fast_unavailable: Option<String>) -> Result<Summary, String> {
    let mut root_files = Vec::new();
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
            root_files.push((e.file_name().to_string_lossy().into_owned(), meta.len()));
        }
    }
    let parts: Vec<(String, u64, u64, Builder)> = std::thread::scope(|s| {
        let handles: Vec<_> = top_dirs
            .into_iter()
            .map(|d| {
                s.spawn(move || {
                    let mut b = Builder::default();
                    let (_, bytes, count) = walk(&mut b, &d, NONE);
                    (d.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default(), bytes, count, b)
                })
            })
            .collect();
        handles.into_iter().filter_map(|h| h.join().ok()).collect()
    });

    let mut b = Builder::default();
    let root_id = b.add_dir(NONE, root);
    let (mut bytes, mut count) = (root_files.iter().map(|f| f.1).sum::<u64>(), root_files.len() as u64);
    let mut tops = Vec::new();
    for (name, sb, sc, part) in parts {
        let first = b.merge(part);
        b.dirs[first as usize].parent = root_id;
        bytes += sb;
        count += sc;
        tops.push((name, first, sb));
    }
    // The root's own children go together, after everything else.
    let start = b.recs.len() as u32;
    for (name, size) in root_files {
        b.add_rec(&name, root_id, size, NONE);
    }
    for (name, id, size) in tops {
        b.add_rec(&name, root_id, size, id);
    }
    b.close_dir(root_id, start, bytes, count);

    let summary = Summary {
        root: root.to_string(),
        total_bytes: bytes,
        files: count,
        unreadable: ERRORS.load(Ordering::Relaxed),
        cancelled: CANCEL.load(Ordering::SeqCst),
        millis: started.elapsed().as_millis(),
        method: "walk".into(),
        fast_unavailable,
        scanned_at: now_hhmm(),
    };
    store(Tree::from_builder(root, b, summary.clone()));
    if let Ok(mut c) = CURRENT.lock() {
        c.clear();
    }
    Ok(summary)
}

/// Folders and big files directly inside `path`, largest first, plus one "smaller files" entry.
pub fn children(path: &str) -> Result<Vec<Entry>, String> {
    with_tree(path, |tree| {
        let id = tree.find_dir(path).ok_or("That folder isn't part of the last scan.")?;
        let d = tree.dirs[id as usize];
        let dpath = tree.dir_path(id);
        let mut out = Vec::new();
        let mut files: Vec<(u64, &str)> = Vec::new();
        for r in &tree.recs[d.start as usize..(d.start + d.len) as usize] {
            if r.gone {
                continue;
            }
            let name = tree.name(r);
            if r.dir != NONE {
                let sub = &tree.dirs[r.dir as usize];
                out.push(Entry { path: join(&dpath, name), name: name.to_string(), kind: "dir".into(), size_bytes: sub.size, files: sub.files });
            } else {
                files.push((r.size, name));
            }
        }
        files.sort_by(|a, b| b.0.cmp(&a.0));
        let (mut other_files, mut other_bytes) = (0u64, 0u64);
        for (i, (size, name)) in files.into_iter().enumerate() {
            if i < MAX_FILES_PER_DIR {
                out.push(Entry { path: join(&dpath, name), name: name.to_string(), kind: "file".into(), size_bytes: size, files: 1 });
            } else {
                other_files += 1;
                other_bytes += size;
            }
        }
        if other_files > 0 {
            out.push(Entry {
                path: format!("{dpath}\u{1}other"),
                name: format!("{other_files} more file{}", if other_files == 1 { "" } else { "s" }),
                kind: "other".into(),
                size_bytes: other_bytes,
                files: other_files,
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
            .filter(|&&r| !tree.recs[r as usize].gone)
            .take(limit)
            .map(|&r| {
                let rec = &tree.recs[r as usize];
                Entry { path: tree.rec_path(r), name: tree.name(rec).to_string(), kind: "file".into(), size_bytes: rec.size, files: 1 }
            })
            .collect()
    })
    .unwrap_or_default()
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
    let Ok(g) = TREES.lock() else { return SearchResult { items: Vec::new(), total: 0, searched: 0, millis: 0 } };
    let trees: Vec<&Tree> = g
        .as_ref()
        .map(|m| m.values().filter(|t| root.is_none_or(|r| key(&t.root) == key(r))).collect())
        .unwrap_or_default();

    // Split every scan into chunks and search them on all CPU cores at once.
    let threads = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4).clamp(1, 16);
    let terms = &terms;
    type Hit = (u64, usize, u32); // (size, tree, rec)
    let partials: Vec<(BinaryHeap<Reverse<Hit>>, usize, usize)> = std::thread::scope(|s| {
        let mut handles = Vec::new();
        for (ti, tree) in trees.iter().enumerate() {
            let chunk = (tree.recs.len() / threads).max(20_000);
            for (ci, slice) in tree.recs.chunks(chunk).enumerate() {
                handles.push(s.spawn(move || {
                    let mut heap: BinaryHeap<Reverse<Hit>> = BinaryHeap::new();
                    let (mut total, mut searched) = (0usize, 0usize);
                    let mut lower = String::new();
                    for (j, r) in slice.iter().enumerate() {
                        let is_dir = r.dir != NONE;
                        if r.gone || (kind == "files" && is_dir) || (kind == "folders" && !is_dir) {
                            continue;
                        }
                        searched += 1;
                        if !terms.is_empty() {
                            // Case-insensitive: lowercase into a reused buffer (no allocation).
                            lower.clear();
                            lower.push_str(tree.name(r));
                            lower.make_ascii_lowercase();
                            if !terms.iter().all(|t| term_matches(t, &lower)) {
                                continue;
                            }
                        }
                        total += 1;
                        let hit = (r.size, ti, (ci * chunk + j) as u32);
                        if heap.len() < limit {
                            heap.push(Reverse(hit));
                        } else if heap.peek().is_some_and(|Reverse((s, _, _))| r.size > *s) {
                            heap.pop();
                            heap.push(Reverse(hit));
                        }
                    }
                    (heap, total, searched)
                }));
            }
        }
        handles.into_iter().filter_map(|h| h.join().ok()).collect()
    });
    let (mut total, mut searched) = (0usize, 0usize);
    let mut hits: Vec<Hit> = Vec::new();
    for (heap, t, s) in partials {
        total += t;
        searched += s;
        hits.extend(heap.into_iter().map(|Reverse(h)| h));
    }
    hits.sort_by(|a, b| b.0.cmp(&a.0));
    hits.truncate(limit);
    let items = hits
        .into_iter()
        .map(|(size, ti, r)| {
            let tree = trees[ti];
            let rec = &tree.recs[r as usize];
            let is_dir = rec.dir != NONE;
            let files = if is_dir { tree.dirs[rec.dir as usize].files } else { 0 };
            Entry { path: tree.rec_path(r), name: tree.name(rec).to_string(), kind: if is_dir { "dir" } else { "file" }.into(), size_bytes: size, files }
        })
        .collect();
    SearchResult { items, total, searched, millis: started.elapsed().as_millis() }
}

/// The folders where space really sits, across a whole scan: folders whose size isn't mostly
/// one subfolder (so `C:\Users` is skipped when `C:\Users\Name` holds most of it).
pub fn largest_folders(root: &str, limit: usize) -> Vec<Entry> {
    with_tree(root, |tree| {
        let mut picked: Vec<(u64, u32)> = Vec::new();
        for (id, d) in tree.dirs.iter().enumerate().skip(1) {
            if d.size == 0 || (d.rec != NONE && tree.recs[d.rec as usize].gone) {
                continue;
            }
            let biggest_child = tree.recs[d.start as usize..(d.start + d.len) as usize]
                .iter()
                .filter(|r| r.dir != NONE && !r.gone)
                .map(|r| tree.dirs[r.dir as usize].size)
                .max()
                .unwrap_or(0);
            if biggest_child * 10 < d.size * 6 {
                picked.push((d.size, id as u32));
            }
        }
        picked.sort_by(|a, b| b.0.cmp(&a.0));
        picked.truncate(limit);
        picked
            .into_iter()
            .map(|(size, id)| {
                let path = tree.dir_path(id);
                let name = Path::new(&path).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| path.clone());
                Entry { path, name, kind: "dir".into(), size_bytes: size, files: tree.dirs[id as usize].files }
            })
            .collect()
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
    let known = with_tree(path, |t| {
        t.find_rec(path).map(|r| {
            let rec = &t.recs[r as usize];
            if rec.dir != NONE { t.dirs[rec.dir as usize].size } else { rec.size }
        })
    })
    .flatten();
    let size = known.unwrap_or_else(|| if p.is_file() { p.metadata().map(|m| m.len()).unwrap_or(0) } else { crate::util::dir_size(p) });
    trash::delete(p).map_err(|e| format!("Couldn't move it to the Recycle Bin: {e}"))?;
    forget(path, size);
    Ok(size)
}

/// Removes `path` (`size` bytes) from the scans after it was deleted, so totals and search stay right.
pub fn forget(path: &str, size: u64) {
    with_tree(path, |tree| {
        let Some(r) = tree.find_rec(path) else { return };
        tree.recs[r as usize].gone = true;
        // Everything inside a deleted folder is gone too.
        let mut stack: Vec<u32> = vec![tree.recs[r as usize].dir].into_iter().filter(|&d| d != NONE).collect();
        while let Some(d) = stack.pop() {
            let dir = tree.dirs[d as usize];
            for rr in dir.start..dir.start + dir.len {
                let rec = &mut tree.recs[rr as usize];
                rec.gone = true;
                if rec.dir != NONE {
                    stack.push(rec.dir);
                }
            }
        }
        // Folders above it shrink.
        let mut d = tree.recs[r as usize].parent;
        while d != NONE {
            let dir = &mut tree.dirs[d as usize];
            dir.size = dir.size.saturating_sub(size);
            let (rec, parent) = (dir.rec, dir.parent);
            if rec != NONE {
                tree.recs[rec as usize].size = tree.recs[rec as usize].size.saturating_sub(size);
            }
            d = parent;
        }
        tree.summary.total_bytes = tree.summary.total_bytes.saturating_sub(size);
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

    /// Elevated: scan every drive at once, then time program-folder size lookups and search
    /// against it, and report this process's memory.
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
        let kids = super::children(r"C:\Users").unwrap_or_default();
        println!("C:\\Users children: {}", kids.iter().map(|e| format!("{} {} MB", e.name, e.size_bytes >> 20)).collect::<Vec<_>>().join(", "));
        let mut counters: windows_sys::Win32::System::ProcessStatus::PROCESS_MEMORY_COUNTERS = unsafe { std::mem::zeroed() };
        counters.cb = std::mem::size_of_val(&counters) as u32;
        unsafe {
            windows_sys::Win32::System::ProcessStatus::GetProcessMemoryInfo(
                windows_sys::Win32::System::Threading::GetCurrentProcess(),
                &mut counters,
                counters.cb,
            )
        };
        println!("memory: working set {} MB, peak {} MB, committed {} MB", counters.WorkingSetSize >> 20, counters.PeakWorkingSetSize >> 20, counters.PagefileUsage >> 20);
    }
}

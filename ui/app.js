'use strict';

const { invoke } = window.__TAURI__.core;

const state = {
  programs: [],
  view: 'all',
  hideComponents: true,
  sort: { key: 'name', dir: 1 },
  search: '',
  selectedId: null,
  icons: new Map(),
  /** id -> Footprint (real disk usage incl. data folders), or null if it couldn't be measured */
  footprints: new Map(),
  fpGen: 0,
  loadGen: 0,
  discovering: false,
  allUsers: false,
  /** drive: "" or "C:"; user: "" (everyone), an account name, or SHARED (machine-wide only) */
  filter: { drive: '', user: '' },
  elevated: false,
  busy: false,
  loading: true,
};

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

function fmtSize(b) {
  if (b == null) return '';
  if (b < 1024) return `${b} B`;
  const units = ['KB', 'MB', 'GB', 'TB'];
  let v = b / 1024, i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return `${v >= 100 || i === 0 ? Math.round(v) : v.toFixed(1)} ${units[i]}`;
}

function fmtDate(d) {
  if (!d) return '';
  const dt = new Date(`${d}T00:00:00`);
  return isNaN(dt) ? d : dt.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
}

const daysAgo = (d) => (d ? (Date.now() - new Date(`${d}T00:00:00`).getTime()) / 86400000 : Infinity);

// ---------------------------------------------------------------------------------------------
// Data

// ---------------------------------------------------------------------------------------------
// Drive and user filters

const SHARED = '__shared';

/** Drive a program is installed on ("C:"), from its folder, icon or uninstaller path. */
function programDrive(p) {
  for (const s of [p.installLocation, p.iconPath, p.uninstallString]) {
    const m = String(s || '').replace(/^"/, '').match(/^([A-Za-z]):\\/);
    if (m) return `${m[1].toUpperCase()}:`;
  }
  return '';
}

/** Per-user programs list their accounts; machine-wide and found-on-drive ones are shared. */
const isShared = (p) => !(p.users && p.users.length);

function passesFilters(p) {
  const { drive, user } = state.filter;
  if (drive && programDrive(p) !== drive) return false;
  if (user === SHARED) return isShared(p);
  // An account can use its own installs plus everything shared.
  if (user && !isShared(p) && !p.users.includes(user)) return false;
  return true;
}

/** Fills the drive and user dropdowns from the programs that are actually listed. */
function renderFilters() {
  const drives = [...new Set(state.programs.map(programDrive).filter(Boolean))].sort();
  const users = [...new Set(state.programs.flatMap((p) => p.users || []))].sort((a, b) => a.localeCompare(b));
  if (state.filter.drive && !drives.includes(state.filter.drive)) state.filter.drive = '';
  if (state.filter.user && state.filter.user !== SHARED && !users.includes(state.filter.user)) state.filter.user = '';
  const opt = (value, label, selected) => `<option value="${esc(value)}"${selected ? ' selected' : ''}>${esc(label)}</option>`;
  $('#filter-drive').innerHTML = opt('', 'All drives', !state.filter.drive)
    + drives.map((d) => opt(d, `Drive ${d}`, state.filter.drive === d)).join('');
  $('#filter-user').innerHTML = opt('', 'All users', !state.filter.user)
    + users.map((u) => opt(u, u, state.filter.user === u)).join('')
    + opt(SHARED, 'Shared (machine-wide)', state.filter.user === SHARED);
  $('#filter-drive').classList.toggle('active', !!state.filter.drive);
  $('#filter-user').classList.toggle('active', !!state.filter.user);
}

/** Real size (install + data folders) once measured, otherwise the installer's estimate. */
const sizeOf = (p) => state.footprints.get(p.id)?.totalBytes || p.sizeBytes;

/** Windows' own parts: hidden system components and the Store apps Windows ships with. */
const MICROSOFT = /^microsoft( corporation)?$|^microsoft windows$/i;
const isWindowsComponent = (p) => p.systemComponent || (p.kind === 'store' && MICROSOFT.test((p.publisher || '').trim()));

const VIEWS = {
  all: (p) => !(state.hideComponents && isWindowsComponent(p)),
  apps: (p) => p.kind === 'win32' && !p.systemComponent,
  store: (p) => p.kind === 'store',
  found: (p) => p.kind === 'portable',
  recent: (p) => !p.systemComponent && daysAgo(p.installDate) <= 30,
  large: (p) => !p.systemComponent && (sizeOf(p) ?? 0) > 0,
  system: (p) => p.kind === 'win32' && p.systemComponent,
  storage: () => false, // the Storage tool replaces the program list
};

const VIEW_SORT = { recent: { key: 'date', dir: -1 }, large: { key: 'size', dir: -1 } };

function visiblePrograms() {
  const q = state.search.trim().toLowerCase();
  const { key, dir } = state.sort;
  const val = {
    name: (p) => p.name.toLowerCase(),
    publisher: (p) => (p.publisher || '￿').toLowerCase(),
    size: (p) => sizeOf(p) ?? -1,
    date: (p) => p.installDate || '',
    version: (p) => p.version || '',
  }[key];
  return state.programs
    .filter(VIEWS[state.view])
    .filter(passesFilters)
    .filter((p) => !q || p.name.toLowerCase().includes(q) || (p.publisher || '').toLowerCase().includes(q))
    .sort((a, b) => {
      const x = val(a), y = val(b);
      const c = typeof x === 'number' ? x - y : String(x).localeCompare(String(y), undefined, { numeric: true });
      return c * dir || a.name.localeCompare(b.name);
    });
}

async function loadPrograms() {
  const gen = ++state.loadGen;
  state.loading = true;
  renderList();
  try {
    // Desktop programs come straight from the registry (milliseconds); Store apps and programs
    // found on the drives join as they arrive.
    state.programs = await invoke('list_programs', { includeStore: false, allUsers: state.allUsers });
  } catch (e) {
    toast(`Could not read installed programs: ${e}`, 'error');
  }
  state.loading = false;
  if (state.selectedId && !state.programs.some((p) => p.id === state.selectedId) && !state.selectedId.startsWith('dir:')) state.selectedId = null;
  renderAll();
  loadIcons();
  computeFootprints();
  loadStoreApps(gen);
  discoverPrograms(gen);
}

/** Adds Microsoft Store apps (listing them takes PowerShell a second or two). */
async function loadStoreApps(gen) {
  let store = [];
  try {
    store = await invoke('list_store_programs');
  } catch { /* the rest of the list still works */ }
  if (gen !== state.loadGen) return;
  addPrograms(store);
}

/** Merges newly found programs into the list and refreshes what depends on it. */
function addPrograms(more) {
  const ids = new Set(state.programs.map((p) => p.id));
  state.programs.push(...more.filter((p) => !ids.has(p.id)));
  renderAll();
  loadIcons();
  computeFootprints();
}

/** Adds programs found on the drives that Windows doesn't list (portable apps, copied games…). */
async function discoverPrograms(gen) {
  state.discovering = true;
  renderCounts();
  if (state.view === 'found') renderList();
  let found = [];
  try {
    found = await invoke('discover_programs');
  } catch (e) {
    toast(`Couldn't search your drives: ${e}`, 'error');
  }
  if (gen !== state.loadGen) return; // a newer refresh replaced the list meanwhile
  state.discovering = false;
  addPrograms(found);
  if (state.selectedId && !state.programs.some((p) => p.id === state.selectedId)) state.selectedId = null;
}

// Real disk usage is measured in the background, a batch of programs at a time (in parallel on
// the backend), visible ones first. Sizes come from the startup drive scan when it's done.
const fpPending = new Set();
const FP_BATCH = 8;

async function fetchFootprints(batch) {
  batch = batch.filter((p) => !state.footprints.has(p.id) && !fpPending.has(p.id));
  if (!batch.length) return;
  batch.forEach((p) => fpPending.add(p.id));
  let results = [];
  try {
    results = await invoke('program_footprints', { programs: batch });
  } catch { /* each one falls back to the installer's estimate */ }
  const byId = new Map(results.map((fp) => [fp.id, fp]));
  for (const p of batch) {
    state.footprints.set(p.id, byId.get(p.id) || null);
    fpPending.delete(p.id);
    const cell = $(`#rows .row[data-id="${CSS.escape(p.id)}"] .size`);
    if (cell) cell.innerHTML = sizeCell(p);
  }
  renderStatus();
  if (batch.some((p) => p.id === state.selectedId)) renderDetails();
  if (sortsBySize() && batch.some((p) => visiblePrograms().some((x) => x.id === p.id))) scheduleResort();
}

/** One program, ahead of the queue (e.g. the one just selected). */
const fetchFootprint = (p) => fetchFootprints([p]);

// When the list is ordered by size, keep that order right while real sizes stream in.
const sortsBySize = () => state.sort.key === 'size' || state.view === 'large';
let resortTimer = null;

function scheduleResort() {
  const viewDone = !visiblePrograms().some((x) => !x.systemComponent && !state.footprints.has(x.id));
  if (viewDone) {
    // Every program in this view has its real size: put them in final order now.
    clearTimeout(resortTimer);
    resortTimer = null;
    resortList();
  } else if (!resortTimer) {
    // Still measuring: re-sort at most every 1.5 s so rows don't jump on every update.
    resortTimer = setTimeout(() => {
      resortTimer = null;
      if (sortsBySize()) resortList();
    }, 1500);
  }
}

/** Re-renders the list in sort order, keeping the scroll position (selection is kept by id). */
function resortList() {
  const rows = $('#rows');
  const top = rows.scrollTop;
  renderList();
  rows.scrollTop = top;
}

async function computeFootprints() {
  const gen = ++state.fpGen;
  while (gen === state.fpGen) {
    const seen = new Set();
    const next = visiblePrograms().concat(state.programs)
      .filter((p) => !p.systemComponent && !state.footprints.has(p.id) && !fpPending.has(p.id) && !seen.has(p.id) && seen.add(p.id))
      .slice(0, FP_BATCH);
    if (!next.length) break;
    await fetchFootprints(next);
  }
  if (gen === state.fpGen) {
    renderCounts();
    if (sortsBySize()) resortList();
  }
}

const SPINNER = '<i class="mini-spin" aria-hidden="true"></i>';

function sizeCell(p) {
  const fp = state.footprints.get(p.id);
  if (fp && fp.totalBytes > 0) return fmtSize(fp.totalBytes);
  const estimate = p.sizeBytes == null ? '' : fmtSize(p.sizeBytes);
  // Measured nothing on disk (trust the installer), or never measured (system components).
  if (state.footprints.has(p.id) || p.systemComponent) return estimate;
  return `<span class="measuring" title="Measuring the real size, including data folders…">${SPINNER}<span class="est">${estimate}</span></span>`;
}

function renderStatus() {
  if (state.loading) return;
  const list = visiblePrograms();
  const total = list.reduce((s, p) => s + (sizeOf(p) || 0), 0);
  const measuring = state.programs.some((p) => !p.systemComponent && !state.footprints.has(p.id));
  $('#statusbar').innerHTML = `${list.length} program${list.length === 1 ? '' : 's'}${total ? ` · ${fmtSize(total)} total` : ''}${
    measuring ? ` · <span class="measuring">${SPINNER}measuring sizes…</span>` : ''}`;
}

async function loadIcons() {
  const pending = [...new Set(state.programs.map((p) => p.iconPath).filter(Boolean))].filter((p) => !state.icons.has(p));
  // Visible programs first so the screen fills in quickly.
  const visible = new Set(visiblePrograms().map((p) => p.iconPath));
  pending.sort((a, b) => visible.has(b) - visible.has(a));
  for (let i = 0; i < pending.length; i += 24) {
    const chunk = pending.slice(i, i + 24);
    let res = {};
    try { res = await invoke('get_icons', { paths: chunk }); } catch { /* keep letter avatars */ }
    chunk.forEach((p) => state.icons.set(p, res[p] || null));
    paintIcons();
  }
}

function iconHtml(p, large = false) {
  const src = p.iconPath && state.icons.get(p.iconPath);
  const cls = `ico${large ? ' lg' : ''}`;
  if (src) return `<span class="${cls}" data-icon-for="${esc(p.id)}"><img src="${src}" alt="" draggable="false"></span>`;
  const letter = (p.name.match(/[A-Za-z0-9]/) || ['?'])[0].toUpperCase();
  return `<span class="${cls} letter" data-icon-for="${esc(p.id)}">${esc(letter)}</span>`;
}

function paintIcons() {
  const byId = new Map(state.programs.map((p) => [p.id, p]));
  $$('[data-icon-for].letter').forEach((el) => {
    const p = byId.get(el.dataset.iconFor);
    const src = p && p.iconPath && state.icons.get(p.iconPath);
    if (src) {
      el.classList.remove('letter');
      el.innerHTML = `<img src="${src}" alt="" draggable="false">`;
    }
  });
}

// ---------------------------------------------------------------------------------------------
// Rendering

function renderAll() {
  renderFilters();
  renderCounts();
  renderList();
  renderDetails();
}

function renderCounts() {
  for (const [view, fn] of Object.entries(VIEWS)) {
    const el = $(`[data-count="${view}"]`);
    if (el) el.textContent = state.loading || (view === 'found' && state.discovering) ? '…' : state.programs.filter((p) => fn(p) && passesFilters(p)).length;
  }
}

function renderList() {
  $$('#list-head button').forEach((b) => {
    b.classList.toggle('sorted', b.dataset.sort === state.sort.key);
    b.classList.toggle('desc', b.dataset.sort === state.sort.key && state.sort.dir < 0);
  });
  const rows = $('#rows');
  if (state.loading) {
    rows.innerHTML = Array.from({ length: 10 }, (_, i) =>
      `<div class="skeleton"><i></i><i style="width:${30 + ((i * 37) % 30)}%"></i></div>`).join('');
    $('#statusbar').textContent = 'Reading installed programs…';
    return;
  }
  const list = visiblePrograms();
  if (!list.length && state.view === 'found' && state.discovering) {
    rows.innerHTML = '<div class="empty"><div class="spinner" style="margin:0 auto 12px"></div><strong>Searching your drives</strong>Looking for programs Windows doesn\'t list on every drive…</div>';
  } else if (!list.length) {
    const filtered = state.filter.drive || state.filter.user;
    rows.innerHTML = `<div class="empty"><strong>${state.search || filtered ? 'No matches' : 'Nothing here'}</strong>${
      state.search ? `No program matches “${esc(state.search)}”.`
        : filtered ? 'No programs here match the drive or user filter.'
          : 'This list is empty.'}</div>`;
  } else {
    rows.innerHTML = list.map((p) => `
      <div class="row${p.id === state.selectedId ? ' sel' : ''}" data-id="${esc(p.id)}">
        <div class="name">${iconHtml(p)}<span>${esc(p.name)}</span>${rowTag(p)}</div>
        <div class="pub">${esc(p.publisher || '')}</div>
        <div class="size">${sizeCell(p)}</div>
        <div class="date">${esc(fmtDate(p.installDate))}</div>
        <div class="ver">${esc(p.version || '')}</div>
      </div>`).join('');
  }
  renderStatus();
}

const driveOf = (p) => (p.installLocation || '').slice(0, 2).toUpperCase();
const isLeftover = (p) => p.kind === 'portable' && /leftover/i.test(p.arch || '');
/** A portable app that is a single .exe file rather than a folder. */
const isSingleFile = (p) => p.kind === 'portable' && /\.exe$/i.test(p.installLocation || '');

function rowTag(p) {
  if (p.kind === 'win32' && p.scope === 'user') {
    // In all-users mode, name the account(s) instead of a generic USER tag.
    if (state.allUsers && p.users && p.users.length) {
      const label = p.users.length > 1 ? `${p.users.length} users` : p.users[0];
      return `<em class="tag" title="Installed for: ${esc(p.users.join(', '))}">${esc(label)}</em>`;
    }
    return '<em class="tag" title="Installed for the current user only">USER</em>';
  }
  if (p.kind !== 'portable') return '';
  const steam = (p.arch || '').startsWith('Steam library') ? '<em class="tag" title="In a Steam library">STEAM</em>' : '';
  const leftover = isLeftover(p) ? '<em class="tag tag-warn" title="The program itself is gone; only its folder and data are left">LEFTOVER</em>' : '';
  const exe = isSingleFile(p) ? '<em class="tag" title="A portable app that is a single .exe file">EXE</em>' : '';
  return `<em class="tag" title="Found on drive ${esc(driveOf(p))}; not registered with Windows">${esc(driveOf(p))}</em>${steam}${exe}${leftover}`;
}

function selected() {
  return state.programs.find((p) => p.id === state.selectedId) || null;
}

function select(id, scroll = false) {
  state.selectedId = id;
  $$('#rows .row').forEach((r) => r.classList.toggle('sel', r.dataset.id === id));
  if (scroll) $(`#rows .row[data-id="${CSS.escape(id)}"]`)?.scrollIntoView({ block: 'nearest' });
  renderDetails();
  const p = selected();
  if (p) fetchFootprint(p); // jump the queue for the program being looked at
}

/** "C:\Users\me\AppData\Roaming\Foo" -> "~\AppData\Roaming\Foo" */
function shortPath(path) {
  const m = path.match(/^[A-Za-z]:\\Users\\[^\\]+(\\.*)$/);
  return m ? `~${m[1]}` : path;
}

function usageHtml(p) {
  const fp = state.footprints.get(p.id);
  if (!fp || !fp.folders.length) return '';
  const total = fp.totalBytes || 1;
  const rows = fp.folders.map((f) => `
    <a class="usage-row" data-act="open-path" data-path="${esc(f.path)}" title="${esc(f.path)}">
      <span class="dot ${f.confidence === 'high' ? f.kind : 'maybe'}"></span>
      <span class="usage-path"><bdi>${esc(shortPath(f.path))}</bdi></span>
      <span class="usage-size">${fmtSize(f.sizeBytes)}</span>
    </a>`).join('');
  return `
    <div class="d-section">Disk usage</div>
    <div class="usage">
      <div class="usage-bar">
        <span class="program" style="width:${(fp.programBytes / total) * 100}%"></span>
        <span class="data" style="width:${(fp.dataBytes / total) * 100}%"></span>
      </div>
      <div class="usage-legend">
        <span><i class="dot program"></i>Program ${fmtSize(fp.programBytes) || '0 B'}</span>
        <span><i class="dot data"></i>Data ${fmtSize(fp.dataBytes) || '0 B'}</span>
      </div>
      ${rows}
      ${fp.uncertainBytes ? `<p class="usage-note"><i class="dot maybe"></i>${fmtSize(fp.uncertainBytes)} more in folders that may belong to it (not counted).</p>` : ''}
    </div>`;
}

function renderDetails() {
  const el = $('#details');
  if (state.view === 'storage') return renderStorageDetails(el);
  const p = selected();
  if (!p) {
    el.className = 'details blank';
    el.innerHTML = `<div><svg viewBox="0 0 24 24"><rect x="3" y="4" width="18" height="16" rx="2.5"/><path d="M3 9h18M8 14h8"/></svg>
      <div>Select a program to see its details.</div></div>`;
    return;
  }
  el.className = 'details';
  const portable = p.kind === 'portable';
  const type = p.kind === 'store' ? 'Microsoft Store app'
    : portable ? `Not registered with Windows${p.arch ? ` · ${p.arch}` : ''}`
    : `${p.productCode ? 'Windows Installer (MSI)' : 'Desktop app'}${p.arch ? ` · ${p.arch}` : ''}`;
  // A program found on disk may still ship its own uninstaller; then it gets both buttons.
  const actions = portable && !p.uninstallString
    ? `<button class="btn danger" data-act="force" ${state.busy ? 'disabled' : ''} title="Delete its folder and leftovers after you review them">
        <svg viewBox="0 0 24 24"><path d="M13 3L5 13h6l-1 8 8-10h-6z"/></svg>Force Removal</button>
      <button class="btn ghost" data-act="open-folder">
        <svg viewBox="0 0 24 24"><path d="M3.5 7a2 2 0 0 1 2-2h4l2 2h7a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2h-13a2 2 0 0 1-2-2z"/></svg>Open folder</button>`
    : `<button class="btn primary" data-act="uninstall" ${state.busy ? 'disabled' : ''}>
        <svg viewBox="0 0 24 24"><path d="M4 7h16M10 11v6M14 11v6M6 7l1 12a2 2 0 0 0 2 2h6a2 2 0 0 0 2-2l1-12M9 7V4h6v3"/></svg>Uninstall</button>
      <button class="btn danger-ghost" data-act="force" ${state.busy ? 'disabled' : ''} title="Remove everything without running the program's own uninstaller">
        <svg viewBox="0 0 24 24"><path d="M13 3L5 13h6l-1 8 8-10h-6z"/></svg>Force Removal</button>`;
  const note = portable && isLeftover(p)
    ? `<div class="note">Leftover on drive ${esc(driveOf(p))} — the program's files are gone, but its folder is still here${
        (p.arch || '').startsWith('Steam library') ? ' in your Steam library (often saves, logs or workshop downloads after an uninstall or a Windows reinstall)' : ''}. Remove deletes it after you review it.</div>`
    : portable && isSingleFile(p)
    ? `<div class="note">A portable app: this single .exe is the whole program, so there's no uninstaller. Force Removal deletes the file and any settings it left behind, after you review them.</div>`
    : portable && p.uninstallString
    ? `<div class="note">Found on drive ${esc(driveOf(p))}. It isn't in Windows' list of installed programs, but it has its own uninstaller: Uninstall runs it, then looks for leftovers. If that doesn't work, use Force Removal.</div>`
    : portable
    ? `<div class="note">Found on drive ${esc(driveOf(p))}. It isn't in Windows' list of installed programs and has no uninstaller. Force Removal deletes its folder and any leftovers you approve.${
        (p.arch || '').startsWith('Steam library') ? ' Uninstalling it from Steam also works; Force Removal also deletes Steam\'s install record.' : ''}</div>`
    : p.kind === 'win32' && !p.uninstallString && !p.productCode ? '<div class="note">No uninstaller is registered for this program. Use Force Removal to remove its files and registry entries.</div>' : '';
  const prop = (label, value, cls = '') => (value ? `<dt>${label}</dt><dd class="${cls}">${value}</dd>` : '');
  const cmd = p.uninstallString || (p.productCode ? `msiexec /x ${p.productCode}` : '');
  const fp = state.footprints.get(p.id);
  const size = !state.footprints.has(p.id) ? `<span class="measuring">${SPINNER}Measuring…</span>` : fmtSize(sizeOf(p));
  el.innerHTML = `
    <div class="d-head">${iconHtml(p, true)}<div><h2>${esc(p.name)}</h2><p>${esc(p.publisher || 'Unknown publisher')}</p></div></div>
    <div class="d-actions">${actions}</div>
    <dl class="d-props">
      ${prop('Version', esc(p.version))}
      ${prop('Size', size)}
      ${prop('Reported', fp && fp.totalBytes > 0 && p.sizeBytes != null ?`<span class="muted" title="Size the installer registered; excludes data created later">${fmtSize(p.sizeBytes)} by the installer</span>` : '')}
      ${prop('Installed', esc(fmtDate(p.installDate)))}
      ${prop('Type', esc(type))}
      ${portable ? '' : prop('Scope', p.scope === 'user' ? 'Per user' : 'All users (machine-wide)')}
      ${p.users && p.users.length ? prop('Account', esc(p.users.join(', '))) : ''}
      ${prop('Location', p.installLocation ? `<a data-act="open-folder">${esc(p.installLocation)}</a>` : '')}
      ${prop('Registry', p.registryKey ? `<a data-act="open-reg">${esc(p.registryKey)}</a>` : '')}
      ${prop('Package', esc(p.packageFullName), 'mono')}
      ${prop('Uninstaller', esc(cmd), 'mono')}
    </dl>
    ${note}
    ${usageHtml(p)}
  `;
}

function renderAdmin() {
  const el = $('#admin');
  if (state.elevated) {
    el.className = 'admin yes';
    el.textContent = 'Running as administrator';
  } else {
    el.className = 'admin no';
    el.innerHTML = `<strong>Limited mode</strong>Some leftovers in system locations can't be removed without administrator rights.
      <button class="btn ghost small" id="btn-elevate">Restart as administrator</button>`;
  }
}

// ---------------------------------------------------------------------------------------------
// Modals, progress & toasts

let modalResolve = null;
let modalCancelValue = null;

function openModal(html, { wide = false, cancelValue = null } = {}) {
  const ov = $('#overlay');
  ov.innerHTML = `<div class="modal${wide ? ' wide' : ''}" role="dialog" aria-modal="true">${html}</div>`;
  ov.hidden = false;
  modalCancelValue = cancelValue;
  return new Promise((resolve) => { modalResolve = resolve; });
}

function closeModal(value) {
  const ov = $('#overlay');
  ov.hidden = true;
  ov.innerHTML = '';
  const r = modalResolve;
  modalResolve = null;
  if (r) r(value);
}

/** Simple dialog. `actions` are [{label, value, cls}]; the last one is the default button. */
function dialog({ title, subtitle = '', body = '', actions, checks = [], focus = actions.length - 1 }) {
  const checksHtml = checks.map((c) => `
    <label class="check"><input type="checkbox" data-check="${c.id}" ${c.checked ? 'checked' : ''}>
      <span>${esc(c.label)}${c.hint ? `<small>${esc(c.hint)}</small>` : ''}</span></label>`).join('');
  const html = `
    <div class="modal-head"><h3>${esc(title)}</h3>${subtitle ? `<p>${esc(subtitle)}</p>` : ''}</div>
    <div class="modal-body">${body}${checksHtml}</div>
    <div class="modal-foot"><span class="spacer"></span>${actions.map((a, i) =>
      `<button class="btn ${a.cls || 'ghost'}" data-value="${i}">${esc(a.label)}</button>`).join('')}</div>`;
  const p = openModal(html, { cancelValue: -1 });
  $$('#overlay [data-value]').forEach((b) => b.addEventListener('click', () => {
    const values = Object.fromEntries($$('#overlay [data-check]').map((c) => [c.dataset.check, c.checked]));
    closeModal({ index: Number(b.dataset.value), values });
  }));
  $(`#overlay .modal-foot [data-value="${focus}"]`)?.focus();
  return p.then((r) => (r === -1 || r == null ? { index: -1, values: {} } : { ...r, value: actions[r.index]?.value }));
}

function showProgress(title, text = '', stop = null) {
  openModal(`<div class="progress"><div class="spinner"></div><h3>${esc(title)}</h3>${text ? `<p>${esc(text)}</p>` : ''}
    ${stop ? `<button class="btn ghost small" id="btn-stop" style="margin-top:8px">${esc(stop.label)}</button>` : ''}</div>`);
  if (stop) $('#btn-stop').addEventListener('click', (e) => { e.target.disabled = true; stop.onClick(); });
}

function hideProgress() {
  if (!$('#overlay').hidden) closeModal(null);
}

function toast(msg, type = '') {
  const t = document.createElement('div');
  t.className = `toast ${type}`;
  t.textContent = msg;
  $('#toasts').appendChild(t);
  setTimeout(() => t.remove(), type === 'error' ? 7000 : 4200);
}

// ---------------------------------------------------------------------------------------------
// Uninstall flows

function setBusy(b) {
  state.busy = b;
  renderDetails();
}

async function uninstall(p) {
  if (state.busy) return;
  if (p.kind === 'portable' && !p.uninstallString) return forceRemove(p);
  if (!(await stubbornGate(p))) return;
  const isStore = p.kind === 'store';
  const r = await dialog({
    title: `Uninstall ${p.name}?`,
    subtitle: isStore ? 'The app and its data will be removed for your account.' : 'PuirkleUninstaller runs the program\'s own uninstaller, then looks for anything it left behind.',
    checks: [
      ...(isStore ? [] : [{ id: 'quiet', label: 'Quiet mode', hint: 'Skip the uninstaller\'s prompts when it supports it.', checked: false }]),
      { id: 'scan', label: 'Scan for leftovers afterwards', hint: 'Files, folders, registry entries, services and scheduled tasks.', checked: true },
    ],
    actions: [{ label: 'Cancel' }, { label: 'Uninstall', cls: 'primary', value: 'go' }],
  });
  if (r.value !== 'go') return;

  setBusy(true);
  try {
    showProgress(`Uninstalling ${p.name}`, isStore ? 'Removing the app package…' : 'Complete the steps in the uninstaller window. PuirkleUninstaller waits until it closes.',
      isStore ? null : { label: 'Stop waiting', onClick: () => invoke('stop_waiting') });
    let outcome;
    try {
      outcome = await invoke('run_uninstaller', { program: p, quiet: !!r.values.quiet });
    } catch (e) {
      hideProgress();
      const f = await dialog({
        title: 'The uninstaller could not run',
        body: `<div class="pre">${esc(e)}</div><p style="margin-top:12px">Force Removal skips the program's uninstaller and removes its files and registry entries directly.</p>`,
        actions: [{ label: 'Close' }, { label: 'Force Removal', cls: 'danger', value: 'force' }],
      });
      if (f.value === 'force') await forceRemove(p, true);
      return;
    }
    hideProgress();

    if (outcome.stillInstalled) {
      const f = await dialog({
        title: `${p.name} is still installed`,
        body: `<p>${esc(outcome.message)}</p><p>If the uninstaller is broken, Force Removal can remove the program instead.</p>`,
        actions: [{ label: 'Close' }, { label: 'Scan for leftovers', value: 'scan' }, { label: 'Force Removal', cls: 'danger', value: 'force' }],
      });
      if (f.value === 'force') await forceRemove(p, true);
      else if (f.value === 'scan') await scanAndClean(p, false);
      return;
    }
    toast(outcome.message, 'success');
    if (r.values.scan) await scanAndClean(p, false);
  } finally {
    setBusy(false);
    await loadPrograms();
  }
}

/**
 * Self-protected security products (antivirus like 360) block normal uninstalls on purpose.
 * Rather than fight that, show the vendor's official remover and the Safe Mode route. Returns
 * true to carry on with the normal uninstall anyway, false to stop here.
 */
async function stubbornGate(p) {
  let info;
  try { info = await invoke('check_stubborn', { program: p }); } catch { return true; }
  if (!info) return true;
  const actions = [{ label: 'Cancel' }];
  if (info.removerUrl) actions.push({ label: `Open ${info.vendor} tool`, value: 'remover' });
  actions.push({ label: 'Try anyway', cls: 'danger', value: 'go' });
  const r = await dialog({
    title: `${p.name} protects itself`,
    body: `<p>${esc(info.note)}</p>
      <p style="margin-top:10px">PuirkleUninstaller won't disable its protection for you — that's what the official tool and Safe Mode are for. You can still try a normal uninstall.</p>`,
    actions,
  });
  if (r.value === 'remover') {
    invoke('open_url', { url: info.removerUrl }).catch((e) => toast(String(e), 'error'));
    return false;
  }
  return r.value === 'go';
}

async function forceRemove(p, skipConfirm = false) {
  if (state.busy && !skipConfirm) return;
  if (!skipConfirm && p.kind !== 'portable' && !(await stubbornGate(p))) return;
  if (!skipConfirm && p.kind === 'portable') {
    const r = await dialog({
      title: `Force removal of ${p.name}`,
      body: `<p>This program isn't registered with Windows, so there's no uninstaller to run. PuirkleUninstaller closes it, then lists its folder and anything else it left on your PC.</p>
        <div class="pre">${esc(p.installLocation)}</div>
        <p style="margin-top:10px">You'll review everything before anything is deleted.</p>`,
      actions: [{ label: 'Cancel' }, { label: 'Scan', cls: 'danger', value: 'go' }],
    });
    if (r.value !== 'go') return;
  } else if (!skipConfirm) {
    const r = await dialog({
      title: `Force removal of ${p.name}`,
      body: `<p>Force Removal doesn't run the program's uninstaller. It closes the program, then finds and deletes its files, folders, registry entries, services and scheduled tasks.</p>
        <p>Use it when the regular uninstaller is missing, broken or refuses to run. You'll review everything before anything is deleted.</p>`,
      actions: [{ label: 'Cancel' }, { label: 'Scan', cls: 'danger', value: 'go' }],
    });
    if (r.value !== 'go') return;
  }
  setBusy(true);
  try {
    showProgress('Preparing force removal', 'Closing running processes and stopping services…');
    const actions = await invoke('prepare_force_removal', { program: p }).catch(() => []);
    if (actions.length) toast(actions.slice(0, 3).join(' · ') + (actions.length > 3 ? ` (+${actions.length - 3} more)` : ''));
    await scanAndClean(p, true);
  } finally {
    setBusy(false);
    await loadPrograms();
  }
}

async function scanAndClean(p, force) {
  showProgress('Scanning for leftovers', 'Checking folders, shortcuts, the registry, services and scheduled tasks…');
  let items;
  try {
    items = await invoke('scan_leftovers', { program: p, force });
  } catch (e) {
    hideProgress();
    toast(`Scan failed: ${e}`, 'error');
    return;
  }
  hideProgress();
  if (!items.length) {
    await dialog({
      title: 'No leftovers found',
      body: `<p>${esc(p.name)} left nothing behind that PuirkleUninstaller could detect.</p>`,
      actions: [{ label: 'Done', cls: 'primary' }],
    });
    return;
  }
  const choice = await leftoversDialog(p, items, force);
  if (!choice || !choice.items.length) return;

  showProgress('Removing leftovers', `Deleting ${choice.items.length} item${choice.items.length === 1 ? '' : 's'}. Registry entries are backed up first.`);
  let report;
  try {
    report = await invoke('delete_leftovers', { items: choice.items, recycle: choice.recycle, programName: p.name });
  } catch (e) {
    hideProgress();
    toast(`Removal failed: ${e}`, 'error');
    return;
  }
  hideProgress();
  await showReport(report, choice.items, choice.recycle);
}

// ---------------------------------------------------------------------------------------------
// Leftover review

const KIND_ICONS = {
  folder: '<svg viewBox="0 0 24 24"><path d="M3.5 7a2 2 0 0 1 2-2h4l2 2h7a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2h-13a2 2 0 0 1-2-2z"/></svg>',
  file: '<svg viewBox="0 0 24 24"><path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5"/></svg>',
  shortcut: '<svg viewBox="0 0 24 24"><rect x="3.5" y="3.5" width="17" height="17" rx="3"/><path d="M10 14l5-5M10 9h5v5"/></svg>',
  regkey: '<svg viewBox="0 0 24 24"><path d="M12 3l8 4.5v9L12 21l-8-4.5v-9z"/><path d="M12 12l8-4.5M12 12v9M12 12L4 7.5"/></svg>',
  regvalue: '<svg viewBox="0 0 24 24"><path d="M5 6h14M5 12h14M5 18h9"/></svg>',
  service: '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="3"/><path d="M12 2.5v3M12 18.5v3M4.2 6.5l2.6 1.5M17.2 16l2.6 1.5M4.2 17.5l2.6-1.5M17.2 8l2.6-1.5"/></svg>',
  task: '<svg viewBox="0 0 24 24"><rect x="3.5" y="5" width="17" height="15" rx="2.5"/><path d="M3.5 10h17M8 3v4M16 3v4"/></svg>',
};

const GROUPS = [
  { title: 'Files & folders', kinds: ['folder', 'file'] },
  { title: 'Shortcuts', kinds: ['shortcut'] },
  { title: 'Registry', kinds: ['regkey', 'regvalue'] },
  { title: 'Services & scheduled tasks', kinds: ['service', 'task'] },
];

/** Leftover kinds that can be opened for a look before deciding, with the button's tooltip. */
const OPENABLE = {
  folder: 'Open this folder in Explorer',
  file: 'Show this file in Explorer',
  shortcut: 'Show this shortcut in Explorer',
  task: 'Show this task file in Explorer',
  regkey: 'Open this key in Registry Editor',
  regvalue: 'Open this key in Registry Editor',
};
const ICON_OPEN = '<svg viewBox="0 0 24 24"><path d="M14 4h6v6M20 4l-8.5 8.5"/><path d="M18 14v4a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4"/></svg>';

const BADGE = { high: 'Safe', medium: 'Check', low: 'Shared?' };
const BADGE_TIP = {
  high: 'Clearly belongs to this program',
  medium: 'Probably belongs to this program; check before deleting',
  low: 'Might be shared with another program',
};

function displayPath(it) {
  if (it.kind === 'regvalue') return `${it.path}  →  ${it.valueName}`;
  if (it.kind === 'task') return `Task ${it.name}`;
  if (it.kind === 'service') return `Service “${it.name}”  ·  ${it.path}`;
  return it.path;
}

/** One review row per item, except many values under the same key collapse into one row. */
function reviewRows(list) {
  const rows = [];
  const buckets = new Map();
  for (const it of list) {
    if (it.kind !== 'regvalue') { rows.push([it]); continue; }
    const k = `${it.path}|${it.reason}|${it.confidence}`;
    if (!buckets.has(k)) { buckets.set(k, []); rows.push(buckets.get(k)); }
    buckets.get(k).push(it);
  }
  return rows.flatMap((r) => (r.length > 3 ? [r] : r.map((it) => [it])));
}

function leftoversDialog(p, items, force) {
  const checked = new Set(items.filter((i) => i.confidence === 'high').map((i) => i.id));
  const totalSize = items.reduce((s, i) => s + (i.sizeBytes || 0), 0);
  const rows = [];

  const groupsHtml = GROUPS.map((g, gi) => {
    const list = items.filter((i) => g.kinds.includes(i.kind));
    if (!list.length) return '';
    return `<section class="lo-group" data-group="${gi}">
      <h4><input type="checkbox" data-group-check="${gi}">${g.title} <span>${list.length}</span></h4>
      ${reviewRows(list).map((row) => {
        const it = row[0];
        const label = row.length > 1 ? `${it.path}  →  ${row.length} values` : displayPath(it);
        const tip = row.length > 1 ? row.map((r) => r.valueName).slice(0, 40).join('\n') + (row.length > 40 ? '\n…' : '') : label;
        rows.push(row);
        return `
        <label class="lo-item" title="${esc(tip)}">
          <input type="checkbox" data-row="${rows.length - 1}">
          ${KIND_ICONS[it.kind] || ''}
          <span class="lo-path"><bdi>${esc(label)}</bdi></span>
          <span class="lo-size">${it.sizeBytes ? fmtSize(it.sizeBytes) : ''}</span>
          <span class="badge ${it.confidence}" title="${BADGE_TIP[it.confidence]}">${BADGE[it.confidence]}</span>
          ${OPENABLE[it.kind] ? `<button class="icon-btn lo-open" data-open-row="${rows.length - 1}" title="${OPENABLE[it.kind]}">${ICON_OPEN}</button>` : '<span></span>'}
          <span class="lo-reason">${esc(it.reason)}</span>
        </label>`;
      }).join('')}
    </section>`;
  }).join('');

  const html = `
    <div class="modal-head">
      <h3>${force ? 'Force removal' : 'Leftovers'} · ${esc(p.name)}</h3>
      <p>Found ${items.length} item${items.length === 1 ? '' : 's'}${totalSize ? ` taking ${fmtSize(totalSize)}` : ''}. Items marked Safe are selected; review the rest before removing them.</p>
    </div>
    <div class="lo-tools">
      Select:
      <button class="chip" data-select="high">Safe only</button>
      <button class="chip" data-select="all">All</button>
      <button class="chip" data-select="none">None</button>
      <span class="legend"><span class="badge high">Safe</span><span class="badge medium">Check</span><span class="badge low">Shared?</span></span>
    </div>
    <div class="lo-body">${groupsHtml}</div>
    <div class="modal-foot">
      <label class="check" style="padding:0"><input type="checkbox" id="lo-recycle" checked><span>Move files to the Recycle Bin</span></label>
      <span class="spacer"></span>
      <span class="lo-summary" id="lo-summary"></span>
      <button class="btn ghost" data-lo="cancel">Cancel</button>
      <button class="btn danger" data-lo="remove">Remove selected</button>
    </div>`;
  const promise = openModal(html, { wide: true, cancelValue: null });

  const ov = $('#overlay');
  const sync = () => {
    GROUPS.forEach((g, gi) => {
      const box = $(`[data-group-check="${gi}"]`, ov);
      if (!box) return;
      const ids = items.filter((i) => g.kinds.includes(i.kind)).map((i) => i.id);
      const n = ids.filter((id) => checked.has(id)).length;
      box.checked = n === ids.length;
      box.indeterminate = n > 0 && n < ids.length;
    });
    $$('[data-row]', ov).forEach((c) => {
      const row = rows[Number(c.dataset.row)];
      const n = row.filter((it) => checked.has(it.id)).length;
      c.checked = n === row.length;
      c.indeterminate = n > 0 && n < row.length;
    });
    const sel = items.filter((i) => checked.has(i.id));
    const size = sel.reduce((s, i) => s + (i.sizeBytes || 0), 0);
    $('#lo-summary', ov).textContent = `${sel.length} selected${size ? ` · ${fmtSize(size)}` : ''}`;
    $('[data-lo="remove"]', ov).disabled = sel.length === 0;
  };

  $('.modal', ov).addEventListener('change', (e) => {
    const t = e.target;
    if (t.dataset.row != null) rows[Number(t.dataset.row)].forEach((it) => (t.checked ? checked.add(it.id) : checked.delete(it.id)));
    if (t.dataset.groupCheck != null) {
      const g = GROUPS[Number(t.dataset.groupCheck)];
      items.filter((i) => g.kinds.includes(i.kind)).forEach((i) => (t.checked ? checked.add(i.id) : checked.delete(i.id)));
    }
    sync();
  });
  // Open a leftover to check it, without toggling its checkbox (the button sits inside the label).
  $('.lo-body', ov).addEventListener('click', (e) => {
    const b = e.target.closest('[data-open-row]');
    if (!b) return;
    e.preventDefault();
    const it = rows[Number(b.dataset.openRow)][0];
    const call = it.kind === 'regkey' || it.kind === 'regvalue' ? invoke('open_registry_key', { key: it.path }) : invoke('open_path', { path: it.path });
    call.catch((err) => toast(String(err), 'error'));
  });
  $$('[data-select]', ov).forEach((b) => b.addEventListener('click', () => {
    checked.clear();
    items.forEach((i) => {
      if (b.dataset.select === 'all' || (b.dataset.select === 'high' && i.confidence === 'high')) checked.add(i.id);
    });
    sync();
  }));
  $('[data-lo="cancel"]', ov).addEventListener('click', () => closeModal(null));
  $('[data-lo="remove"]', ov).addEventListener('click', () => {
    const recycle = $('#lo-recycle', ov).checked;
    closeModal({ items: items.filter((it) => checked.has(it.id)), recycle });
  });
  sync();
  return promise;
}

async function showReport(report, items, recycle) {
  const byId = new Map(items.map((i) => [i.id, i]));
  const ok = report.results.filter((r) => r.ok);
  const failed = report.results.filter((r) => !r.ok);
  const pending = report.results.filter((r) => r.pendingReboot);
  const failList = failed.map((r) => {
    const it = byId.get(r.id);
    return `<div><code>${esc(it ? displayPath(it) : r.id)}</code><br>${esc(r.message || 'Failed')}</div>`;
  }).join('');
  const body = `
    <div class="stat-row">
      <div class="stat"><b>${ok.length}</b><span>removed</span></div>
      <div class="stat"><b>${fmtSize(report.freedBytes) || '0 B'}</b><span>${recycle ? 'moved to Recycle Bin' : 'freed'}</span></div>
      <div class="stat"><b>${failed.length}</b><span>failed</span></div>
    </div>
    ${pending.length ? `<p>${pending.length} item${pending.length === 1 ? ' is' : 's are'} in use and will be deleted when Windows restarts.</p>` : ''}
    ${report.closedProcesses.length ? `<p>Closed ${report.closedProcesses.length} running process${report.closedProcesses.length === 1 ? '' : 'es'} first.</p>` : ''}
    ${report.sessionId ? '<p>Everything removed was backed up. Use Undo now, or later from Backups &amp; Restore in the sidebar.</p>' : ''}
    ${failed.length ? `<div class="result-list">${failList}</div>` : ''}
    ${failed.length && !state.elevated ? '<p style="margin-top:12px">Restarting as administrator usually fixes "Access denied" errors.</p>' : ''}`;
  const actions = [];
  if (report.sessionId) actions.push({ label: 'Undo', value: 'undo' });
  actions.push({ label: 'Done', cls: 'primary', value: 'done' });
  const r = await dialog({ title: failed.length ? 'Cleanup finished with some errors' : 'Cleanup complete', body, actions });
  if (r.value === 'undo') await restoreSession(report.sessionId);
}

// ---------------------------------------------------------------------------------------------
// Backups & rollback

function sessionSummary(s) {
  const parts = [];
  if (s.registryCount) parts.push(`${s.registryCount} registry entr${s.registryCount === 1 ? 'y' : 'ies'}`);
  if (s.taskCount) parts.push(`${s.taskCount} scheduled task${s.taskCount === 1 ? '' : 's'}`);
  if (s.fileCount) parts.push(`${s.fileCount} item${s.fileCount === 1 ? '' : 's'} in the Recycle Bin`);
  return parts.join(' · ') || 'Nothing to restore';
}

function backupsModal(sessions) {
  const list = sessions.length
    ? sessions.map((s, i) => `
      <div class="bk">
        <div class="bk-main">
          <div class="bk-title"><strong>${esc(s.program)}</strong>${s.restoredAt ? `<span class="badge high" title="Restored ${esc(s.restoredAt)}">Restored</span>` : ''}</div>
          <div class="bk-meta">${esc(s.createdAt)} · ${esc(sessionSummary(s))}</div>
          <ul class="bk-preview">${s.preview.map((x) => `<li title="${esc(x)}"><bdi>${esc(x)}</bdi></li>`).join('')}</ul>
        </div>
        <div class="bk-actions">
          <button class="btn primary small" data-bk="restore" data-i="${i}">Restore</button>
          <button class="btn ghost small" data-bk="open" data-i="${i}">Folder</button>
          <button class="btn ghost small" data-bk="delete" data-i="${i}">Delete</button>
        </div>
      </div>`).join('')
    : '<div class="empty" style="padding:40px 10px"><strong>No backups yet</strong>A backup is saved every time you remove leftovers.</div>';
  const promise = openModal(`
    <div class="modal-head"><h3>Backups &amp; Restore</h3>
      <p>Every cleanup saves what it removed. Restore puts back its registry entries, scheduled tasks and Recycle Bin files.</p></div>
    <div class="modal-body bk-list">${list}</div>
    <div class="modal-foot"><span class="spacer"></span><button class="btn primary" data-bk="close">Done</button></div>`, { wide: false, cancelValue: null });
  const ov = $('#overlay');
  $('.modal', ov).classList.add('mid');
  $$('[data-bk]', ov).forEach((b) => b.addEventListener('click', () => {
    const s = sessions[Number(b.dataset.i)];
    if (b.dataset.bk === 'open') {
      invoke('open_path', { path: s.path }).catch((e) => toast(String(e), 'error'));
      return;
    }
    closeModal(b.dataset.bk === 'close' ? null : { type: b.dataset.bk, session: s });
  }));
  return promise;
}

async function showBackups() {
  for (;;) {
    let sessions = [];
    try { sessions = await invoke('list_backups'); } catch (e) { toast(String(e), 'error'); return; }
    const action = await backupsModal(sessions);
    if (!action) return;
    if (action.type === 'restore') {
      await restoreSession(action.session.id, action.session);
    } else if (action.type === 'delete') {
      const r = await dialog({
        title: 'Delete this backup?',
        body: `<p>The backup of <strong>${esc(action.session.program)}</strong> (${esc(action.session.createdAt)}) will be deleted. You won't be able to restore it afterwards. Files in the Recycle Bin stay there.</p>`,
        actions: [{ label: 'Cancel' }, { label: 'Delete backup', cls: 'danger', value: 'go' }],
      });
      if (r.value === 'go') await invoke('delete_backup', { id: action.session.id }).catch((e) => toast(String(e), 'error'));
    }
  }
}

async function restoreSession(id, session = null) {
  if (!session) {
    session = (await invoke('list_backups').catch(() => [])).find((s) => s.id === id);
    if (!session) { toast('That backup no longer exists.', 'error'); return; }
  }
  const again = session.restoredAt ? `<p>It was already restored on ${esc(session.restoredAt)}; restoring again rewrites the same entries.</p>` : '';
  const r = await dialog({
    title: `Restore ${session.program}?`,
    body: `<p>This puts back what the cleanup on ${esc(session.createdAt)} removed: ${esc(sessionSummary(session))}.</p>${again}
      ${state.elevated ? '' : '<p>Some system registry entries can only be restored as administrator.</p>'}`,
    actions: [{ label: 'Cancel' }, { label: 'Restore', cls: 'primary', value: 'go' }],
  });
  if (r.value !== 'go') return;
  showProgress('Restoring', 'Re-importing registry entries, re-creating tasks and moving files back from the Recycle Bin…');
  let report;
  try {
    report = await invoke('restore_backup', { id });
  } catch (e) {
    hideProgress();
    toast(`Restore failed: ${e}`, 'error');
    return;
  }
  hideProgress();
  await dialog({
    title: report.failed.length ? 'Restored with some problems' : 'Restore complete',
    body: `<div class="stat-row"><div class="stat"><b>${report.restored}</b><span>restored</span></div><div class="stat"><b>${report.failed.length}</b><span>failed</span></div></div>
      ${report.failed.length ? `<div class="result-list">${report.failed.map((f) => `<div><code>${esc(f)}</code></div>`).join('')}</div>` : ''}
      <p style="margin-top:12px">Programs whose uninstall entry came back show up in the list again after this refresh.</p>`,
    actions: [{ label: 'Done', cls: 'primary' }],
  });
  loadPrograms();
}

// ---------------------------------------------------------------------------------------------
// Storage analyzer

/**
 * mode: "browse" (a folder and what's in it), "largest" (biggest subfolders on the drive) or
 * "search" (matches across every scanned drive).
 */
const storage = {
  drives: null, scanning: null, summary: null, path: null, entries: [], top: [], timer: null,
  mode: 'browse', query: '', kind: 'all', results: null, autoScan: false, searchSeq: 0,
};

const ICON_FOLDER = '<svg viewBox="0 0 24 24"><path d="M3.5 7a2 2 0 0 1 2-2h4l2 2h7a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2h-13a2 2 0 0 1-2-2z"/></svg>';
const ICON_FILE = '<svg viewBox="0 0 24 24"><path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5"/></svg>';
const ICON_TRASH = '<svg viewBox="0 0 24 24"><path d="M4 7h16M10 11v6M14 11v6M6 7l1 12a2 2 0 0 0 2 2h6a2 2 0 0 0 2-2l1-12M9 7V4h6v3"/></svg>';
const ICON_UNLOCK = '<svg viewBox="0 0 24 24"><rect x="4.5" y="10.5" width="15" height="10" rx="2"/><path d="M8 10.5V7a4 4 0 0 1 7.6-1.7"/></svg>';
const ICON_BOLT = '<svg viewBox="0 0 24 24"><path d="M13 3L5 13h6l-1 8 8-10h-6z"/></svg>';

/** Shows the Storage view instead of the program list. */
function applyViewMode() {
  const isStorage = state.view === 'storage';
  $('.toolbar').hidden = isStorage;
  $('#list').hidden = isStorage;
  $('#statusbar').hidden = isStorage;
  $('#storage').hidden = !isStorage;
  if (isStorage) showStorage();
  renderDetails();
}

/**
 * Startup: read every drive's file table in the background (administrator only; seconds per
 * drive). Program sizes and the Storage view both use the result.
 */
async function autoScanDrives() {
  if (!state.elevated) return;
  storage.autoScan = true;
  const poll = setInterval(refreshDrives, 1000);
  refreshDrives();
  try {
    await invoke('storage_scan_all');
  } catch { /* drives that can't be read fast just stay unscanned */ }
  clearInterval(poll);
  storage.autoScan = false;
  await refreshDrives();
  // Open the system drive's results if the Storage view is waiting for something to show.
  if (!storage.summary && storage.drives?.length) {
    const first = storage.drives.find((d) => d.state === 'done');
    if (first) await openDrive(first.root, false);
  }
}

async function refreshDrives() {
  storage.drives = await invoke('storage_drives').catch(() => storage.drives || []);
  if (state.view === 'storage') renderStorage();
}

async function showStorage() {
  if (!storage.drives) await refreshDrives();
  if (!storage.summary && !storage.scanning) {
    const done = (storage.drives || []).find((d) => d.state === 'done');
    if (done) await openDrive(done.root, false);
  }
  renderStorage();
}

/** Shows a drive: instantly from an earlier scan, otherwise scans it now. */
async function openDrive(root, rescan) {
  const cached = rescan ? null : await invoke('storage_summary', { root }).catch(() => null);
  if (!cached) return startStorageScan(root);
  storage.summary = cached;
  storage.mode = storage.query ? 'search' : 'browse';
  storage.top = await invoke('storage_top_files', { root, limit: 40 }).catch(() => []);
  await loadStorageFolder(root);
  renderDetails();
}

function driveCard(d) {
  const used = d.totalBytes - d.freeBytes;
  const pct = d.totalBytes ? Math.round((used / d.totalBytes) * 100) : 0;
  const active = storage.summary && storage.summary.root === d.root;
  const status = d.state === 'scanning' ? `<span class="st-drive-state">${SPINNER}Scanning…</span>`
    : d.state === 'done' ? '<span class="st-drive-state ok">Scanned</span>' : '';
  return `<button class="st-drive${active ? ' active' : ''}" data-drive="${esc(d.root)}" ${storage.scanning || d.state === 'scanning' ? 'disabled' : ''}>
    <span class="st-drive-name">${esc(d.root.replace('\\', ''))}</span>
    <span class="st-drive-bar"><i style="width:${pct}%"></i></span>
    <span class="st-drive-meta">${fmtSize(used)} used of ${fmtSize(d.totalBytes)} · ${fmtSize(d.freeBytes)} free ${status}</span>
  </button>`;
}

/** One row of a folder listing or of a flat result list (which also shows each item's path). */
function storageRow(e, i, total, withPath, showPct = true) {
  const pct = total ? (e.sizeBytes / total) * 100 : 0;
  return `
    <div class="st-row${e.kind === 'dir' ? ' dir' : ''}${withPath ? ' flat' : ''}" data-i="${i}" title="${esc(e.kind === 'other' ? e.name : e.path)}">
      <span class="st-ico">${e.kind === 'dir' ? ICON_FOLDER : ICON_FILE}</span>
      <span class="st-name">${esc(e.name)}${withPath ? `<small><bdi>${esc(e.path.slice(0, Math.max(0, e.path.length - e.name.length - 1)))}</bdi></small>` : ''}</span>
      <span class="st-bar"><i style="width:${Math.max(0.5, Math.min(100, pct))}%"></i></span>
      <span class="st-size">${fmtSize(e.sizeBytes) || '0 B'}</span>
      <span class="st-pct">${total && showPct ? `${pct.toFixed(1)}%` : ''}</span>
      <span class="st-actions">${e.kind === 'other' ? '' : `
        <button class="icon-btn" data-st="open" data-i="${i}" title="Show in Explorer">${ICON_FOLDER}</button>
        <button class="icon-btn danger" data-st="recycle" data-i="${i}" title="Move to Recycle Bin">${ICON_TRASH}</button>`}
      </span>
    </div>`;
}

/** The rows the list is showing right now (folder contents, largest folders or search hits). */
const storageRows = () => (storage.mode === 'browse' ? storage.entries : storage.results?.items || []);

function renderStorage() {
  $('#st-drives').innerHTML = (storage.drives || []).map(driveCard).join('');
  $$('#st-kind button').forEach((b) => b.classList.toggle('on', b.dataset.kind === storage.kind));
  const head = $('#st-head');
  const list = $('#st-list');

  if (storage.scanning) {
    head.innerHTML = '';
    list.innerHTML = `<div class="st-scanning"><div class="spinner"></div>
      <strong>Scanning ${esc(storage.scanning)}</strong><span id="st-progress">Starting…</span>
      <button class="btn ghost small" id="st-stop">Stop</button></div>`;
    return;
  }

  if (storage.mode === 'search') {
    const r = storage.results;
    head.innerHTML = r
      ? `<div class="st-summary">${r.total.toLocaleString()} match${r.total === 1 ? '' : 'es'} in ${r.searched.toLocaleString()} ${storage.kind === 'all' ? 'files and folders' : storage.kind}
          · ${r.millis} ms${r.total > r.items.length ? ` · showing the ${r.items.length} biggest` : ''}</div>`
      : '<div class="st-summary">Searching…</div>';
    const scanned = (storage.drives || []).some((d) => d.state === 'done');
    // Bars compare results with the biggest one (they come from anywhere, so no % of a parent).
    const biggest = r && r.items.length ? r.items[0].sizeBytes : 0;
    list.innerHTML = r && r.items.length ? r.items.map((e, i) => storageRow(e, i, biggest, true, false)).join('')
      : `<div class="empty"><strong>${r ? 'No matches' : 'Searching…'}</strong>${scanned ? 'Search looks at every drive that has been scanned.' : 'Scan a drive first; search covers every scanned drive.'}</div>`;
    return;
  }

  if (!storage.summary) {
    head.innerHTML = '';
    const scanningNow = (storage.drives || []).some((d) => d.state === 'scanning');
    list.innerHTML = scanningNow
      ? `<div class="st-scanning"><div class="spinner"></div><strong>Reading your drives' file tables</strong><span>This takes a few seconds per drive.</span></div>`
      : `<div class="empty"><strong>Pick a drive to scan</strong>See which folders and files take up the most space.
        ${state.elevated ? 'NTFS drives are read straight from the file table, so even big drives take seconds.' : 'Restart as administrator for fast scanning (seconds instead of minutes).'}</div>`;
    return;
  }

  const s = storage.summary;
  const method = s.method === 'fast'
    ? `read the file table in ${(s.millis / 1000).toFixed(1)} s`
    : `scanned folder by folder in ${(s.millis / 1000).toFixed(0)} s${s.fastUnavailable ? ` · <span title="${esc(s.fastUnavailable)}">fast scan unavailable</span>` : ''}`;
  const tools = `<div class="st-tools">
      <button class="chip${storage.mode === 'largest' ? ' on' : ''}" id="st-largest" title="The folders where space really sits, at any depth">Largest folders</button>
      ${storage.mode === 'browse' ? `<button class="chip" id="st-open-here" title="Open this folder in File Explorer">Open in Explorer</button>
      <button class="chip" id="st-copy-here" title="Copy this folder's path">Copy path</button>` : ''}
      <button class="chip" id="st-goto" title="Type or paste a folder path to jump to it">Go to path…</button>
      <button class="chip" id="st-rescan" title="Scan ${esc(s.root.replace('\\', ''))} again">Rescan</button></div>`;

  if (storage.mode === 'largest') {
    head.innerHTML = `<div class="st-headline"><div class="crumbs"><button class="crumb" data-path="${esc(s.root)}">${esc(s.root.replace('\\', ''))}</button>
      <span class="crumb-sep">›</span><span class="crumb">Largest folders</span></div>${tools}</div>
      <div class="st-summary">Folders at any depth, skipping ones that only hold one big subfolder · scanned at ${esc(s.scannedAt)}</div>`;
    const items = storage.results?.items || [];
    list.innerHTML = items.length ? items.map((e, i) => storageRow(e, i, s.totalBytes, true)).join('') : '<div class="empty"><strong>Nothing to show</strong></div>';
    return;
  }

  // Browse: breadcrumb from the drive down to the folder being viewed.
  const rel = storage.path.slice(s.root.length).split('\\').filter(Boolean);
  let acc = s.root;
  const crumbs = [`<button class="crumb" data-path="${esc(s.root)}">${esc(s.root.replace('\\', ''))}</button>`];
  for (const part of rel) {
    acc = acc.endsWith('\\') ? acc + part : `${acc}\\${part}`;
    crumbs.push(`<span class="crumb-sep">›</span><button class="crumb" data-path="${esc(acc)}">${esc(part)}</button>`);
  }
  head.innerHTML = `<div class="st-headline"><div class="crumbs">${crumbs.join('')}</div>${tools}</div>
    <div class="st-summary">${fmtSize(s.totalBytes)} in ${s.files.toLocaleString()} files · ${method} · scanned at ${esc(s.scannedAt)}${s.cancelled ? ' · stopped early' : ''}</div>`;
  const total = storage.entries.reduce((n, e) => n + e.sizeBytes, 0) || 1;
  list.innerHTML = storage.entries.length ? storage.entries.map((e, i) => storageRow(e, i, total, false)).join('')
    : '<div class="empty"><strong>Empty folder</strong>Nothing here.</div>';
}

async function startStorageScan(root) {
  storage.scanning = root;
  storage.summary = null;
  storage.mode = 'browse';
  renderStorage();
  renderDetails();
  storage.timer = setInterval(async () => {
    const p = await invoke('storage_progress').catch(() => null);
    const el = $('#st-progress');
    if (p && el) el.textContent = p.current.startsWith('Reading') ? p.current : `${p.files.toLocaleString()} files · ${fmtSize(p.bytes) || '0 B'}`;
  }, 400);
  try {
    storage.summary = await invoke('storage_scan', { root });
    storage.top = await invoke('storage_top_files', { root, limit: 40 });
    storage.scanning = null;
    await loadStorageFolder(storage.summary.root);
  } catch (e) {
    toast(`Scan failed: ${e}`, 'error');
  } finally {
    clearInterval(storage.timer);
    storage.scanning = null;
    await refreshDrives();
    if (state.view === 'storage') { renderStorage(); renderDetails(); }
  }
}

async function loadStorageFolder(path) {
  storage.entries = await invoke('storage_children', { path });
  storage.path = path;
  if (!storage.query) storage.mode = 'browse';
  renderStorage();
  $('#st-list').scrollTop = 0;
}

// --- Path actions: Explorer, clipboard, go to path, right-click menu ---

const revealPath = (path) => invoke('open_path', { path }).catch((e) => toast(String(e), 'error'));

async function copyPath(path) {
  try {
    await navigator.clipboard.writeText(path);
    toast('Path copied.');
  } catch {
    toast(path); // clipboard blocked: at least show it so it can be selected
  }
}

/** Replaces the breadcrumb with a path box; Enter jumps to that folder (in any scanned drive). */
function promptGoTo() {
  const crumbs = $('#st-head .crumbs');
  if (!crumbs) return;
  crumbs.innerHTML = `<input class="st-goto" id="st-goto-input" spellcheck="false" placeholder="e.g. D:\\SteamLibrary\\steamapps" value="${esc(storage.path || '')}">`;
  const input = $('#st-goto-input');
  input.focus();
  input.select();
  input.addEventListener('keydown', async (e) => {
    if (e.key === 'Escape') { e.stopPropagation(); renderStorage(); }
    if (e.key !== 'Enter') return;
    const raw = input.value.trim().replace(/^"|"$/g, '').replace(/\//g, '\\');
    if (!/^[a-z]:/i.test(raw)) return toast('Enter a full path, like D:\\Games.', 'error');
    const path = raw.length === 2 ? `${raw}\\` : raw;
    try {
      await browseTo(path);
    } catch {
      // A file, or something the scan doesn't know: open its folder instead if possible.
      const parent = path.slice(0, path.lastIndexOf('\\')) || path;
      try { await browseTo(parent.length === 2 ? `${parent}\\` : parent); } catch (err) {
        toast(`${err}`.includes('Scan') || `${err}`.includes('null') ? 'Scan that drive first.' : String(err), 'error');
      }
    }
  });
}

let ctxEl = null;
function closeContextMenu() {
  ctxEl?.remove();
  ctxEl = null;
}

/** Right-click menu for a file or folder row. */
function openContextMenu(x, y, entry) {
  closeContextMenu();
  const isDir = entry.kind === 'dir';
  const items = [
    isDir ? ['browse', 'Open', ICON_FOLDER] : ['reveal', 'Show in File Explorer', ICON_FOLDER],
    isDir ? ['reveal', 'Open in File Explorer', ICON_FOLDER] : null,
    ['copy', 'Copy path', '<svg viewBox="0 0 24 24"><rect x="8" y="8" width="12" height="12" rx="2"/><path d="M16 8V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h2"/></svg>'],
    ['sep'],
    ['unlock', 'Unlock…', ICON_UNLOCK],
    ['recycle', 'Move to Recycle Bin', ICON_TRASH, 'danger'],
    ['force', 'Force delete…', ICON_BOLT, 'danger'],
  ].filter(Boolean);
  ctxEl = document.createElement('div');
  ctxEl.className = 'ctx';
  ctxEl.innerHTML = `<div class="ctx-title" title="${esc(entry.path)}"><bdi>${esc(entry.path)}</bdi></div>` + items.map(([act, label, icon, cls]) => act === 'sep'
    ? '<div class="ctx-sep"></div>'
    : `<button class="ctx-item ${cls || ''}" data-ctx="${act}">${icon}<span>${label}</span></button>`).join('');
  document.body.appendChild(ctxEl);
  const r = ctxEl.getBoundingClientRect();
  ctxEl.style.left = `${Math.min(x, innerWidth - r.width - 8)}px`;
  ctxEl.style.top = `${Math.min(y, innerHeight - r.height - 8)}px`;
  ctxEl.addEventListener('click', (e) => {
    const act = e.target.closest('[data-ctx]')?.dataset.ctx;
    if (!act) return;
    closeContextMenu();
    if (act === 'browse') (storage.mode === 'browse' ? loadStorageFolder(entry.path) : browseTo(entry.path)).catch((err) => toast(String(err), 'error'));
    if (act === 'reveal') revealPath(entry.path);
    if (act === 'copy') copyPath(entry.path);
    if (act === 'recycle') recycleStorageEntry(entry);
    if (act === 'unlock') unlockStorageEntry(entry);
    if (act === 'force') forceDeleteStorageEntry(entry);
  });
}

/** Jumps from a search hit or a "largest folders" row to that folder's contents. */
async function browseTo(path) {
  const root = path.slice(0, 3);
  if (!storage.summary || storage.summary.root.toLowerCase() !== root.toLowerCase()) {
    const summary = await invoke('storage_summary', { root });
    if (!summary) throw new Error('Scan that drive first.');
    storage.summary = summary;
    storage.top = await invoke('storage_top_files', { root, limit: 40 }).catch(() => []);
    renderDetails();
  }
  storage.query = '';
  $('#st-q').value = '';
  storage.mode = 'browse';
  await loadStorageFolder(path);
}

async function showLargestFolders() {
  if (!storage.summary) return;
  storage.query = '';
  $('#st-q').value = '';
  storage.mode = 'largest';
  storage.results = { items: await invoke('storage_largest_folders', { root: storage.summary.root, limit: 300 }) };
  renderStorage();
  $('#st-list').scrollTop = 0;
}

/** Everything-style search across every scanned drive (debounced; stale answers are dropped). */
async function runStorageSearch() {
  const q = storage.query.trim();
  if (!q) {
    storage.mode = 'browse';
    storage.results = null;
    renderStorage();
    return;
  }
  storage.mode = 'search';
  const seq = ++storage.searchSeq;
  const result = await invoke('storage_search', { query: q, kind: storage.kind, root: null, limit: 500 }).catch((e) => {
    toast(String(e), 'error');
    return null;
  });
  if (seq !== storage.searchSeq) return;
  storage.results = result;
  renderStorage();
  $('#st-list').scrollTop = 0;
}

async function recycleStorageEntry(e) {
  const r = await dialog({
    title: `Move ${e.name} to the Recycle Bin?`,
    body: `<div class="pre">${esc(e.path)}</div><p style="margin-top:10px">This frees about <strong>${fmtSize(e.sizeBytes)}</strong>. You can restore it from the Recycle Bin.
      If it belongs to an installed program, uninstalling the program is the cleaner way.</p>`,
    actions: [{ label: 'Cancel' }, { label: 'Move to Recycle Bin', cls: 'danger', value: 'go' }],
  });
  if (r.value !== 'go') return;
  showProgress('Moving to the Recycle Bin', e.path);
  try {
    const freed = await invoke('storage_recycle', { path: e.path });
    hideProgress();
    toast(`Moved ${e.name} to the Recycle Bin (${fmtSize(freed)}).`, 'success');
    await refreshAfterStorageDelete(freed);
  } catch (err) {
    hideProgress();
    // Usually something has it open, or its permissions don't allow it: offer the stronger way.
    const again = await dialog({
      title: `Couldn't move ${e.name} to the Recycle Bin`,
      body: `<p>${esc(String(err))}</p><p>Force delete closes the programs using it and deletes it permanently. Anything Windows itself keeps in use is deleted when you restart.</p>`,
      actions: [{ label: 'Cancel' }, { label: 'Force delete…', cls: 'danger', value: 'force' }],
    });
    if (again.value === 'force') forceDeleteStorageEntry(e);
  }
}

/** Updates the list, totals and largest files after something was deleted. */
async function refreshAfterStorageDelete(freed) {
  if (!storage.summary) return; // e.g. started from File Explorer's menu: no drive is open
  storage.summary.totalBytes -= freed;
  if (storage.mode === 'search') await runStorageSearch();
  else if (storage.mode === 'largest') await showLargestFolders();
  else await loadStorageFolder(storage.path);
  if (storage.summary) storage.top = await invoke('storage_top_files', { root: storage.summary.root, limit: 40 });
  renderDetails();
}

const LOCKER_KIND = { app: '', service: 'Service', explorer: 'File Explorer, restarts by itself', critical: 'Part of Windows, can\'t be closed' };

function lockerList(lockers) {
  return `<ul class="lockers">${lockers.map((l) => `<li><strong>${esc(l.name || `Process ${l.pid}`)}</strong>
    <small>PID ${l.pid}${LOCKER_KIND[l.kind] ? ` · ${LOCKER_KIND[l.kind]}` : ''}</small></li>`).join('')}</ul>`;
}

/** Shows which programs have a file or folder open, and closes them on request (like IObit Unlocker). */
async function unlockStorageEntry(e) {
  showProgress('Checking which programs use it', e.path);
  let lockers;
  try {
    lockers = await invoke('storage_lockers', { path: e.path });
  } catch (err) {
    hideProgress();
    toast(String(err), 'error');
    return;
  }
  hideProgress();
  const closable = lockers.filter((l) => l.kind !== 'critical');
  if (!closable.length) {
    const r = await dialog({
      title: lockers.length ? `Only Windows is using ${e.name}` : `Nothing is using ${e.name}`,
      body: `<div class="pre">${esc(e.path)}</div>${lockers.length ? lockerList(lockers) : ''}
        <p style="margin-top:10px">${lockers.length ? 'Windows itself keeps it open, so it can only be removed when Windows restarts.' : 'No program has it open.'}
        If Windows still won't let you delete it, its permissions are in the way: Force delete handles that too.</p>`,
      actions: [{ label: 'Close' }, { label: 'Force delete…', cls: 'danger', value: 'force' }],
    });
    if (r.value === 'force') forceDeleteStorageEntry(e);
    return;
  }
  const r = await dialog({
    title: `${closable.length} program${closable.length === 1 ? ' is' : 's are'} using ${e.name}`,
    body: `<div class="pre">${esc(e.path)}</div>${lockerList(lockers)}
      <p style="margin-top:10px">Closing them unlocks it. Save your work in them first: programs that don't respond are ended.</p>`,
    actions: [{ label: 'Cancel' }, { label: 'Close and force delete…', cls: 'ghost', value: 'force' }, { label: 'Close programs', cls: 'danger', value: 'go' }],
  });
  if (r.value === 'force') return forceDeleteStorageEntry(e, lockers);
  if (r.value !== 'go') return;
  showProgress('Closing programs', closable.map((l) => l.name).join(', '));
  try {
    const closed = await invoke('storage_unlock', { path: e.path });
    hideProgress();
    toast(closed.length ? `Unlocked ${e.name}: closed ${closed.join(', ')}.` : `${e.name} is not in use anymore.`, 'success');
  } catch (err) {
    hideProgress();
    toast(String(err), 'error');
  }
}

/** Permanently deletes a file or folder: unlocks it, ignores permissions and read-only flags, and
 *  leaves what Windows keeps in use for the next restart. */
async function forceDeleteStorageEntry(e, known = null) {
  let lockers = known;
  if (!lockers) {
    showProgress('Checking which programs use it', e.path);
    lockers = await invoke('storage_lockers', { path: e.path }).catch(() => []);
    hideProgress();
  }
  const closable = lockers.filter((l) => l.kind !== 'critical');
  const r = await dialog({
    title: `Permanently delete ${e.name}?`,
    body: `<div class="pre">${esc(e.path)}</div>
      <p style="margin-top:10px">This frees about <strong>${fmtSize(e.sizeBytes)}</strong>. It does <strong>not</strong> go to the Recycle Bin and can't be undone.
      If it belongs to an installed program, uninstalling the program is the cleaner way.</p>
      ${closable.length ? `<p>These programs will be closed first:</p>${lockerList(closable)}` : ''}`,
    actions: [{ label: 'Cancel' }, { label: 'Delete permanently', cls: 'danger', value: 'go' }],
    focus: 0, // can't be undone: Enter must not delete
  });
  if (r.value !== 'go') return;
  showProgress('Force deleting', e.path);
  try {
    const res = await invoke('storage_force_delete', { path: e.path });
    hideProgress();
    const closed = res.closed || [];
    if (!res.pending && !res.failed.length) {
      toast(`Deleted ${e.name} (${fmtSize(res.deletedBytes)})${closed.length ? `, after closing ${closed.join(', ')}` : ''}.`, 'success');
    } else {
      await dialog({
        title: res.failed.length ? `${e.name} was only partly deleted` : `${e.name} will be finished when you restart`,
        body: `<p>Deleted ${fmtSize(res.deletedBytes)} now.</p>
          ${res.pending ? `<p>${res.pending} item${res.pending === 1 ? ' is' : 's are'} still in use by Windows and will be deleted when you restart the PC.</p>` : ''}
          ${res.failed.length ? `<p>${res.failed.length} item${res.failed.length === 1 ? '' : 's'} couldn't be deleted${state.elevated ? '' : '. Restart PuirkleUninstaller as administrator and try again'}:</p>
            <div class="pre">${res.failed.slice(0, 20).map(esc).join('\n')}${res.failed.length > 20 ? '\n…' : ''}</div>` : ''}`,
        actions: [{ label: 'OK', cls: 'primary' }],
      });
    }
    await refreshAfterStorageDelete(res.deletedBytes);
  } catch (err) {
    hideProgress();
    toast(String(err), 'error');
  }
}

function renderStorageDetails(el) {
  el.className = 'details';
  if (!storage.summary || !storage.top.length) {
    el.innerHTML = `<div class="d-section">Largest files</div><p class="muted" style="margin:0">${
      storage.scanning || storage.autoScan ? 'Scanning…' : 'Scan a drive to see its largest files.'}</p>`;
    return;
  }
  el.innerHTML = `<div class="d-section">Largest files on ${esc(storage.summary.root.replace('\\', ''))}</div>
    <div class="usage">${storage.top.map((f, i) => `
      <a class="usage-row" data-top="${i}" title="${esc(f.path)}">
        <span class="st-ico">${ICON_FILE}</span>
        <span class="usage-path"><bdi>${esc(shortPath(f.path))}</bdi></span>
        <span class="usage-size">${fmtSize(f.sizeBytes)}</span>
      </a>`).join('')}</div>
    <p class="muted" style="font-size:11.5px">Click a file to show it in Explorer.</p>`;
}
// ---------------------------------------------------------------------------------------------
// Updates (GitHub releases)

const REPO = 'Puirkle/PuirkleUninstaller';

/** True if version `a` ("1.2.10") is newer than `b`. */
function isNewer(a, b) {
  const pa = String(a).split(/[.-]/).map((x) => parseInt(x, 10) || 0);
  const pb = String(b).split(/[.-]/).map((x) => parseInt(x, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    if ((pa[i] || 0) !== (pb[i] || 0)) return (pa[i] || 0) > (pb[i] || 0);
  }
  return false;
}

async function checkForUpdates(manual = false) {
  const btn = $('#btn-check-update');
  if (manual) { btn.disabled = true; btn.textContent = 'Checking…'; }
  try {
    if (!state.version) state.version = await window.__TAURI__.app.getVersion();
    $('#version').textContent = `v${state.version}`;
    const r = await fetch(`https://api.github.com/repos/${REPO}/releases/latest`, { headers: { Accept: 'application/vnd.github+json' } });
    if (r.status === 404) {
      if (manual) toast('No releases have been published yet.');
      return;
    }
    if (!r.ok) throw new Error(`GitHub answered ${r.status}`);
    const rel = await r.json();
    const latest = String(rel.tag_name || '').replace(/^v/i, '');
    if (latest && isNewer(latest, state.version)) {
      const asset = (rel.assets || []).find((a) => /-setup\.exe$/i.test(a.name));
      state.update = { version: latest, page: rel.html_url, url: asset?.browser_download_url || null, notes: rel.body || '' };
      renderUpdate();
      if (manual) showUpdateDialog();
    } else if (manual) {
      toast(`You're up to date (v${state.version}).`, 'success');
    }
  } catch (e) {
    if (manual) toast(`Couldn't check for updates: ${e.message || e}`, 'error');
  } finally {
    if (manual) { btn.disabled = false; btn.textContent = 'Check for updates'; }
  }
}

function renderUpdate() {
  const el = $('#update');
  if (!state.update) { el.hidden = true; return; }
  el.hidden = false;
  el.innerHTML = `<strong>Update available</strong>Version ${esc(state.update.version)} is out. You have ${esc(state.version)}.
    <button class="btn primary small" id="btn-update">See update</button>`;
}

async function showUpdateDialog() {
  const u = state.update;
  if (!u) return;
  const notes = u.notes.trim() ? `<div class="pre update-notes">${esc(u.notes.trim().slice(0, 2500))}</div>` : '';
  const actions = [{ label: 'Later' }, { label: "What's new", value: 'page' }];
  if (u.url) actions.push({ label: 'Update now', cls: 'primary', value: 'install' });
  const r = await dialog({
    title: `PuirkleUninstaller ${u.version} is available`,
    subtitle: `You have version ${state.version}.`,
    body: `${notes}<p style="margin-top:10px">${u.url ? 'Update now downloads the installer from GitHub, closes PuirkleUninstaller and starts the installer.' : 'Download it from the release page.'}</p>`,
    actions,
  });
  if (r.value === 'page') invoke('open_url', { url: u.page }).catch((e) => toast(String(e), 'error'));
  if (r.value === 'install') {
    showProgress(`Downloading ${u.version}`, 'Getting the installer from GitHub. PuirkleUninstaller will close and the installer will start.');
    try {
      await invoke('install_update', { url: u.url });
    } catch (e) {
      hideProgress();
      toast(String(e), 'error');
    }
  }
}

// ---------------------------------------------------------------------------------------------
// Events

function moveSelection(delta) {
  const list = visiblePrograms();
  if (!list.length) return;
  const i = list.findIndex((p) => p.id === state.selectedId);
  const next = list[Math.max(0, Math.min(list.length - 1, i < 0 ? 0 : i + delta))];
  select(next.id, true);
}

function bindEvents() {
  $('#nav').addEventListener('click', (e) => {
    const b = e.target.closest('.nav-item');
    if (!b) return;
    $$('.nav-item').forEach((n) => n.classList.toggle('active', n === b));
    state.view = b.dataset.view;
    state.sort = { ...(VIEW_SORT[state.view] || { key: 'name', dir: 1 }) };
    renderList();
    applyViewMode();
  });

  $('#storage').addEventListener('click', (e) => {
    const fail = (err) => toast(String(err), 'error');
    const drive = e.target.closest('[data-drive]');
    if (drive && !storage.scanning) {
      storage.query = '';
      $('#st-q').value = '';
      return openDrive(drive.dataset.drive, false).catch(fail);
    }
    if (e.target.closest('#st-stop')) {
      e.target.closest('#st-stop').disabled = true;
      return invoke('storage_cancel');
    }
    if (e.target.closest('#st-rescan') && storage.summary) return openDrive(storage.summary.root, true).catch(fail);
    if (e.target.closest('#st-open-here') && storage.path) return revealPath(storage.path);
    if (e.target.closest('#st-copy-here') && storage.path) return copyPath(storage.path);
    if (e.target.closest('#st-goto')) return promptGoTo();
    if (e.target.closest('#st-largest')) return showLargestFolders().catch(fail);
    const kind = e.target.closest('#st-kind [data-kind]');
    if (kind) {
      storage.kind = kind.dataset.kind;
      $$('#st-kind button').forEach((b) => b.classList.toggle('on', b === kind));
      if (storage.query.trim()) runStorageSearch();
      return;
    }
    const crumb = e.target.closest('button.crumb');
    if (crumb) {
      storage.mode = 'browse';
      return loadStorageFolder(crumb.dataset.path).catch(fail);
    }
    const act = e.target.closest('[data-st]');
    if (act) {
      const entry = storageRows()[Number(act.dataset.i)];
      if (act.dataset.st === 'open') invoke('open_path', { path: entry.path }).catch(fail);
      if (act.dataset.st === 'recycle') recycleStorageEntry(entry);
      return;
    }
    const row = e.target.closest('.st-row.dir');
    if (!row) return;
    const entry = storageRows()[Number(row.dataset.i)];
    // In search results and "largest folders", a folder opens in the normal folder view.
    (storage.mode === 'browse' ? loadStorageFolder(entry.path) : browseTo(entry.path)).catch(fail);
  });

  // Right-click a row (or a largest file on the right) for open / show / copy / delete.
  $('#storage').addEventListener('contextmenu', (e) => {
    const row = e.target.closest('.st-row');
    if (!row) return;
    const entry = storageRows()[Number(row.dataset.i)];
    if (!entry || entry.kind === 'other') return;
    e.preventDefault();
    openContextMenu(e.clientX, e.clientY, entry);
  });
  $('#details').addEventListener('contextmenu', (e) => {
    const top = e.target.closest('[data-top]');
    if (!top || state.view !== 'storage') return;
    e.preventDefault();
    openContextMenu(e.clientX, e.clientY, storage.top[Number(top.dataset.top)]);
  });
  document.addEventListener('click', (e) => { if (ctxEl && !ctxEl.contains(e.target)) closeContextMenu(); });
  document.addEventListener('scroll', closeContextMenu, true);
  window.addEventListener('blur', closeContextMenu);

  let storageSearchTimer;
  $('#st-q').addEventListener('input', (e) => {
    clearTimeout(storageSearchTimer);
    storage.query = e.target.value;
    storageSearchTimer = setTimeout(runStorageSearch, 150);
  });

  $('#list-head').addEventListener('click', (e) => {
    const b = e.target.closest('button[data-sort]');
    if (!b) return;
    const key = b.dataset.sort;
    state.sort = state.sort.key === key ? { key, dir: -state.sort.dir } : { key, dir: key === 'size' || key === 'date' ? -1 : 1 };
    renderList();
  });

  const rows = $('#rows');
  rows.addEventListener('click', (e) => {
    const r = e.target.closest('.row');
    if (r) select(r.dataset.id);
  });
  rows.addEventListener('dblclick', (e) => {
    const r = e.target.closest('.row');
    const p = r && state.programs.find((x) => x.id === r.dataset.id);
    if (p) uninstall(p);
  });

  let searchTimer;
  $('#search').addEventListener('input', (e) => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => { state.search = e.target.value; renderList(); }, 80);
  });

  $('#details').addEventListener('click', (e) => {
    const top = e.target.closest('[data-top]');
    if (top && state.view === 'storage') {
      invoke('open_path', { path: storage.top[Number(top.dataset.top)].path }).catch((err) => toast(String(err), 'error'));
      return;
    }
    const act = e.target.closest('[data-act]')?.dataset.act;
    const p = selected();
    if (!act || !p) return;
    if (act === 'uninstall') uninstall(p);
    if (act === 'force') forceRemove(p);
    if (act === 'open-folder') invoke('open_path', { path: p.installLocation }).catch((err) => toast(String(err), 'error'));
    if (act === 'open-path') {
      const path = e.target.closest('[data-path]').dataset.path;
      invoke('open_path', { path }).catch((err) => toast(String(err), 'error'));
    }
    if (act === 'open-reg') invoke('open_registry_key', { key: p.registryKey }).catch((err) => toast(String(err), 'error'));
  });

  $('#btn-refresh').addEventListener('click', () => {
    if (state.busy) return;
    state.footprints.clear();
    loadPrograms();
  });
  $('#btn-backups').addEventListener('click', () => { if (!state.busy) showBackups(); });
  $('#hide-components').addEventListener('change', (e) => {
    state.hideComponents = e.target.checked;
    try { localStorage.setItem('hideComponents', e.target.checked ? '1' : '0'); } catch { /* not persisted */ }
    renderCounts();
    renderList();
  });

  for (const [id, key] of [['#filter-drive', 'drive'], ['#filter-user', 'user']]) {
    $(id).addEventListener('change', (e) => {
      state.filter[key] = e.target.value;
      e.target.classList.toggle('active', !!e.target.value);
      renderCounts();
      renderList();
    });
  }

  $('#explorer-menu').addEventListener('change', async (e) => {
    const on = e.target.checked;
    try {
      await invoke('set_explorer_menu', { enabled: on });
      toast(on ? 'Right-click a file or folder in File Explorer and choose "Unlock with PuirkleUninstaller" (Windows 11: Show more options).' : 'Removed from File Explorer\'s menu.', 'success');
    } catch (err) {
      e.target.checked = !on;
      toast(String(err), 'error');
    }
  });
  $('#allusers').addEventListener('change', (e) => {
    if (state.busy) { e.target.checked = state.allUsers; return; }
    if (e.target.checked && !state.elevated) {
      toast('Restart as administrator to read other accounts.', 'error');
      e.target.checked = false;
      return;
    }
    state.allUsers = e.target.checked;
    state.footprints.clear();
    loadPrograms();
  });

  $('#btn-check-update').addEventListener('click', () => checkForUpdates(true));
  $('#update').addEventListener('click', (e) => {
    if (e.target.id === 'btn-update') showUpdateDialog();
  });
  $('#admin').addEventListener('click', (e) => {
    if (e.target.id === 'btn-elevate') invoke('relaunch_as_admin').catch((err) => toast(String(err), 'error'));
  });

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && ctxEl) {
      closeContextMenu();
      return;
    }
    const modalOpen = !$('#overlay').hidden;
    if (e.key === 'Escape' && modalOpen && modalResolve && modalCancelValue !== undefined && !$('#overlay .progress')) {
      closeModal(modalCancelValue);
      return;
    }
    if (modalOpen) return;
    if (state.view === 'storage') {
      // Backspace goes up one folder; the program-list shortcuts don't apply here.
      if ((e.ctrlKey && e.key.toLowerCase() === 'f') || (e.key === '/' && document.activeElement !== $('#st-q'))) {
        e.preventDefault();
        $('#st-q').focus();
        $('#st-q').select();
        return;
      }
      if (e.key === 'Escape' && document.activeElement === $('#st-q')) {
        $('#st-q').value = '';
        storage.query = '';
        runStorageSearch();
        return;
      }
      if (document.activeElement === $('#st-q')) return;
      if (e.key === 'Backspace' && storage.mode === 'browse' && storage.summary && storage.path !== storage.summary.root) {
        const up = storage.path.slice(0, storage.path.lastIndexOf('\\')) || storage.summary.root;
        loadStorageFolder(up.length < storage.summary.root.length ? storage.summary.root : up).catch(() => {});
      }
      return;
    }
    if ((e.ctrlKey && e.key.toLowerCase() === 'f') || (e.key === '/' && document.activeElement !== $('#search'))) {
      e.preventDefault();
      $('#search').focus();
      $('#search').select();
    } else if (e.key === 'F5') {
      e.preventDefault();
      if (!state.busy) loadPrograms();
    } else if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault();
      moveSelection(e.key === 'ArrowDown' ? 1 : -1);
    } else if ((e.key === 'Delete' || e.key === 'Enter') && document.activeElement !== $('#search')) {
      const p = selected();
      if (p) { e.preventDefault(); e.shiftKey ? forceRemove(p) : uninstall(p); }
    } else if (e.key === 'Escape' && document.activeElement === $('#search')) {
      $('#search').value = '';
      state.search = '';
      renderList();
      $('#rows').focus();
    }
  });

  // Block the webview's own context menu and reload shortcut; this is a desktop tool.
  document.addEventListener('contextmenu', (e) => {
    if (!e.target.closest('input, .pre, dd, h2')) e.preventDefault();
  });
}

async function init() {
  try { state.hideComponents = localStorage.getItem('hideComponents') !== '0'; } catch { /* default: hide */ }
  $('#hide-components').checked = state.hideComponents;
  bindEvents();
  renderDetails();
  try { state.elevated = await invoke('is_elevated'); } catch { state.elevated = false; }
  renderAdmin();
  $('#explorer-menu').checked = await invoke('explorer_menu_enabled').catch(() => false);
  // Started from "Unlock with PuirkleUninstaller" in File Explorer: go straight to that, and skip
  // reading every drive (the user came for one file).
  const target = await invoke('unlock_target').catch(() => null);
  if (target) {
    unlockStorageEntry(target);
  } else {
    setTimeout(() => checkForUpdates(false), 2500); // quietly, once the list is on screen
    // Read every drive's file table alongside the program scan: program sizes and the Storage
    // view come from it.
    autoScanDrives();
  }
  await loadPrograms();
}

init();

// cloud-serv PWA — vanilla JS, same-origin with the API.
// Security note: every piece of server/user data is inserted via textContent or
// element properties — never innerHTML — so filenames can never inject HTML.

const API = ""; // same origin
const TOKEN_KEY = "cs_token";
let token = localStorage.getItem(TOKEN_KEY) || "";
let mode = "login"; // or "register"

const $ = (id) => document.getElementById(id);

// ---- tiny helpers ----
function authHeaders(extra = {}) {
  return token ? { Authorization: "Bearer " + token, ...extra } : extra;
}

async function api(path, opts = {}) {
  const res = await fetch(API + path, opts);
  let body = null;
  try { body = await res.json(); } catch { /* non-JSON (e.g. a download) */ }
  return { ok: res.ok, status: res.status, body };
}

function fmtSize(n) {
  if (n < 1024) return n + " B";
  const u = ["KB", "MB", "GB", "TB"];
  let i = -1;
  do { n /= 1024; i++; } while (n >= 1024 && i < u.length - 1);
  return n.toFixed(n < 10 ? 1 : 0) + " " + u[i];
}

function fmtDate(s) {
  // server sends "YYYY-MM-DD HH:MM:SS" (UTC)
  const d = new Date((s || "").replace(" ", "T") + "Z");
  return isNaN(d) ? s : d.toLocaleString();
}

// Filenames are stored URI-encoded (keeps the X-Filename header ASCII-safe and
// injection-free); decode only for display.
function decodeName(name) {
  try { return decodeURIComponent(name); } catch { return name; }
}

function iconFor(mime) {
  if (!mime) return "📄";
  if (mime.startsWith("image/")) return "🖼️";
  if (mime.startsWith("video/")) return "🎬";
  if (mime.startsWith("audio/")) return "🎵";
  if (mime.includes("pdf")) return "📕";
  if (mime.startsWith("text/")) return "📝";
  if (mime.includes("zip") || mime.includes("tar") || mime.includes("compressed")) return "🗜️";
  return "📄";
}

let toastTimer;
function toast(msg) {
  const t = $("toast");
  t.textContent = msg;
  t.classList.remove("hidden");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.add("hidden"), 2600);
}

// ---- view switching ----
function showAuth() {
  $("app-view").classList.add("hidden");
  $("auth-view").classList.remove("hidden");
}
function showApp(user) {
  $("auth-view").classList.add("hidden");
  $("app-view").classList.remove("hidden");
  $("who").textContent = user ? (user.displayName || user.email) : "";
  switchTab("files"); // always land on Files
  loadFs(0);
}

// ---- auth ----
function setMode(m) {
  mode = m;
  const login = m === "login";
  $("tab-login").classList.toggle("active", login);
  $("tab-register").classList.toggle("active", !login);
  $("name-row").classList.toggle("hidden", login);
  $("auth-submit").textContent = login ? "Log in" : "Create account";
  $("password").setAttribute("autocomplete", login ? "current-password" : "new-password");
  $("auth-error").textContent = "";
}

async function onAuthSubmit(e) {
  e.preventDefault();
  $("auth-error").textContent = "";
  const email = $("email").value.trim();
  const password = $("password").value;
  const displayName = $("display-name").value.trim();
  const btn = $("auth-submit");
  btn.disabled = true;

  const path = mode === "login" ? "/api/auth/login" : "/api/auth/register";
  const payload = mode === "login"
    ? { email, password }
    : { email, password, displayName };

  const { ok, body } = await api(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  btn.disabled = false;

  if (!ok || !body || !body.token) {
    $("auth-error").textContent = prettyError(body) || "Something went wrong.";
    return;
  }
  token = body.token;
  localStorage.setItem(TOKEN_KEY, token);
  $("password").value = "";
  showApp(body.user);
}

function prettyError(body) {
  const e = body && body.error;
  const map = {
    "invalid credentials": "Wrong email or password.",
    "email already registered": "That email is already registered.",
    "invalid email": "Please enter a valid email.",
    "password must be at least 8 characters": "Password must be at least 8 characters.",
    "unauthorized": "Session expired — please log in again.",
  };
  return map[e] || e || "";
}

async function logout() {
  await api("/api/auth/logout", { method: "POST", headers: authHeaders() });
  token = "";
  localStorage.removeItem(TOKEN_KEY);
  showAuth();
}

// ---- files ----
// ---- file manager (folders) ----
let currentFolder = 0; // 0 = root
let curFolders = [], curFiles = [];
let resultsMode = false; // true when showing category/search results
let selectMode = false;  // multi-select
const selFiles = new Set(), selFolders = new Set();
let viewMode = localStorage.getItem("cs_view") || "list";   // list | grid
let sortBy = localStorage.getItem("cs_sortby") || "name";   // name | date | size
let sortDir = localStorage.getItem("cs_sortdir") || "asc";  // asc | desc

// Row/tile activation: in select mode toggle selection, else open.
function rowActivate(li, kind, item) {
  if (selectMode) { toggleSelect(kind, item.id); li.classList.toggle("selected"); return; }
  if (kind === "folder") loadFs(item.id);
  else if (isPreviewable(item.mime)) openPreview(item);
  else openActions("file", item);
}
function isSelected(kind, id) { return (kind === "folder" ? selFolders : selFiles).has(id); }
function toggleSelect(kind, id) {
  const set = kind === "folder" ? selFolders : selFiles;
  set.has(id) ? set.delete(id) : set.add(id);
  updateSelectBar();
}
function enterSelect() { selectMode = true; selFiles.clear(); selFolders.clear(); renderFs(); updateSelectBar(); }
function exitSelect() { selectMode = false; selFiles.clear(); selFolders.clear(); renderFs(); updateSelectBar(); }
function updateSelectBar() {
  const n = selFiles.size + selFolders.size;
  $("select-bar").classList.toggle("hidden", !selectMode);
  $("select-count").textContent = n + " selected";
  $("sel-move").disabled = n === 0;
  $("sel-delete").disabled = n === 0;
  const btn = $("select-btn"); if (btn) btn.classList.toggle("active", selectMode);
}

async function loadFs(folderId) {
  currentFolder = folderId;
  resultsMode = false;
  const si = $("search-input"); if (si) si.value = "";
  const { ok, status, body } = await api("/api/fs?folder=" + folderId, { headers: authHeaders() });
  if (status === 401) { sessionExpired(); return; }
  if (!ok || !body) { toast("Could not load folder."); return; }
  renderBreadcrumbs($("breadcrumbs"), body.breadcrumbs || [], (id) => loadFs(id));
  curFolders = body.folders || [];
  curFiles = body.files || [];
  renderFs();
  updateHome();
}

// Storage chip + category row are only shown at the root, in normal (non-results) mode.
function updateHome() {
  const atRoot = currentFolder === 0 && !resultsMode;
  $("home-extras").classList.toggle("hidden", !atRoot);
  $("dropzone").classList.toggle("hidden", resultsMode);
  if (atRoot) loadUsage();
}

async function loadUsage() {
  const { ok, body } = await api("/api/usage", { headers: authHeaders() });
  const el = $("storage-chip");
  if (ok && body) {
    el.textContent = `🗄 ${fmtSize(body.used || 0)} used · ${body.files || 0} file${body.files === 1 ? "" : "s"}`;
  }
}

const CATEGORY_TITLE = { image: "Images", video: "Videos", audio: "Audio", document: "Documents" };
async function openCategory(cat) {
  const { ok, status, body } = await api("/api/search?category=" + encodeURIComponent(cat), { headers: authHeaders() });
  if (status === 401) { sessionExpired(); return; }
  if (!ok || !body) { toast("Could not load."); return; }
  resultsMode = true;
  curFolders = [];
  curFiles = body.files || [];
  renderResultsHeader(CATEGORY_TITLE[cat] || "Results");
  renderFs();
  updateHome();
}

function renderResultsHeader(title) {
  const el = $("breadcrumbs");
  el.textContent = "";
  const home = document.createElement("button");
  home.className = "crumb"; home.type = "button"; home.textContent = "🏠";
  home.addEventListener("click", () => loadFs(currentFolder));
  const sep = document.createElement("span"); sep.className = "crumb-sep"; sep.textContent = "›";
  const t = document.createElement("span"); t.className = "crumb-current"; t.textContent = title;
  el.append(home, sep, t);
}

function sortItems(items, isFile) {
  const dir = sortDir === "asc" ? 1 : -1;
  return [...items].sort((a, b) => {
    let r;
    if (sortBy === "size" && isFile) r = (a.size || 0) - (b.size || 0);
    else if (sortBy === "date") r = (a.createdAt || "").localeCompare(b.createdAt || "");
    else r = decodeName(a.name).localeCompare(decodeName(b.name), undefined, { sensitivity: "base", numeric: true });
    return r * dir;
  });
}

// Renders the current folder contents in the active view + sort (no refetch).
function renderFs() {
  const list = $("fs-list");
  list.className = viewMode === "grid" ? "fs-grid" : "fs-list";
  list.textContent = "";
  const folders = sortItems(curFolders, false);
  const files = sortItems(curFiles, true);
  $("fs-empty").classList.toggle("hidden", folders.length + files.length > 0);
  if (viewMode === "grid") {
    for (const f of folders) list.appendChild(gridCell("folder", f));
    for (const f of files) list.appendChild(gridCell("file", f));
  } else {
    for (const f of folders) list.appendChild(folderRow(f));
    for (const f of files) list.appendChild(fileRow(f));
  }
  refreshControls();
}

function toggleView() {
  viewMode = viewMode === "list" ? "grid" : "list";
  localStorage.setItem("cs_view", viewMode);
  renderFs();
}

const SORT_LABEL = { name: "Name", date: "Date", size: "Size" };
function refreshControls() {
  const v = $("view-toggle"); if (v) v.textContent = viewMode === "grid" ? "☰ List" : "▦ Grid";
  const s = $("sort-btn"); if (s) s.textContent = "↕ " + SORT_LABEL[sortBy] + (sortDir === "asc" ? " ↑" : " ↓");
}

function openSort() {
  const list = $("sort-list");
  list.textContent = "";
  const add = (by, label) => {
    const b = document.createElement("button");
    b.className = "action-item" + (sortBy === by ? " current" : "");
    b.type = "button";
    b.textContent = label + (sortBy === by ? (sortDir === "asc" ? "  ↑" : "  ↓") : "");
    b.addEventListener("click", () => {
      if (sortBy === by) sortDir = sortDir === "asc" ? "desc" : "asc";
      else { sortBy = by; sortDir = by === "date" || by === "size" ? "desc" : "asc"; }
      localStorage.setItem("cs_sortby", sortBy);
      localStorage.setItem("cs_sortdir", sortDir);
      closeSort();
      renderFs();
    });
    list.appendChild(b);
  };
  add("name", "Name");
  add("date", "Date");
  add("size", "Size");
  $("sort-modal").classList.remove("hidden");
}
function closeSort() { $("sort-modal").classList.add("hidden"); }

// A grid tile: thumbnail (image) or type icon, name, and a "•••" menu.
function gridCell(kind, item) {
  const li = document.createElement("li");
  li.className = "grid-cell";
  const thumb = document.createElement("div");
  thumb.className = "thumb";
  if (kind === "folder") {
    thumb.classList.add("is-folder"); thumb.textContent = "📁";
  } else if ((item.mime || "").startsWith("image/")) {
    const img = document.createElement("img");
    img.loading = "lazy"; img.alt = ""; img.src = API + "/api/files/" + item.id + "/content";
    thumb.appendChild(img);
  } else {
    thumb.classList.add("is-type"); thumb.textContent = iconFor(item.mime);
    if ((item.mime || "").startsWith("video/")) {
      const p = document.createElement("span"); p.className = "play-badge"; p.textContent = "▶";
      thumb.appendChild(p);
    }
  }
  const name = document.createElement("div");
  name.className = "grid-name";
  name.textContent = kind === "folder" ? item.name : decodeName(item.name);
  name.title = name.textContent;
  const menu = menuButton(kind, item); menu.classList.add("grid-menu");
  li.append(thumb, name, menu);
  if (selectMode) li.classList.add("selecting");
  if (isSelected(kind, item.id)) li.classList.add("selected");
  li.addEventListener("click", (e) => {
    if (e.target.closest(".menu-btn")) return;
    rowActivate(li, kind, item);
  });
  return li;
}

function renderBreadcrumbs(el, crumbs, onNav) {
  el.textContent = "";
  const home = document.createElement("button");
  home.className = "crumb"; home.type = "button"; home.textContent = "🏠";
  home.addEventListener("click", () => onNav(0));
  el.appendChild(home);
  for (const c of crumbs) {
    const sep = document.createElement("span");
    sep.className = "crumb-sep"; sep.textContent = "›";
    el.appendChild(sep);
    const b = document.createElement("button");
    b.className = "crumb"; b.type = "button";
    b.textContent = c.name; // textContent — safe
    b.addEventListener("click", () => onNav(c.id));
    el.appendChild(b);
  }
}

// A single "•••" actions button (bullets render everywhere, unlike glyph icons).
function menuButton(kind, item) {
  const b = document.createElement("button");
  b.className = "btn ghost small menu-btn"; b.type = "button";
  b.textContent = "•••"; b.setAttribute("aria-label", "Actions");
  b.addEventListener("click", (e) => { e.stopPropagation(); openActions(kind, item); });
  return b;
}

function rowShell(kind, item, icText) {
  const li = document.createElement("li");
  li.className = "fs-item";
  if (selectMode) li.classList.add("selecting");
  if (isSelected(kind, item.id)) li.classList.add("selected");
  const check = document.createElement("div");
  check.className = "row-check"; check.textContent = "✓";
  const ic = document.createElement("div");
  ic.className = "file-ic"; ic.textContent = icText;
  const meta = document.createElement("div");
  meta.className = "file-meta clickable";
  li.append(check, ic, meta);
  li.addEventListener("click", (e) => {
    if (e.target.closest(".menu-btn")) return;
    rowActivate(li, kind, item);
  });
  return { li, meta };
}

function folderRow(f) {
  const { li, meta } = rowShell("folder", f, "📁");
  const name = document.createElement("div");
  name.className = "file-name"; name.textContent = f.name; name.title = f.name;
  const sub = document.createElement("div");
  sub.className = "file-sub"; sub.textContent = "Folder";
  meta.append(name, sub);
  const actions = document.createElement("div");
  actions.className = "file-actions"; actions.append(menuButton("folder", f));
  li.append(actions);
  return li;
}

function fileRow(f) {
  const { li, meta } = rowShell("file", f, iconFor(f.mime));
  const name = document.createElement("div");
  name.className = "file-name"; name.textContent = decodeName(f.name); name.title = decodeName(f.name);
  const sub = document.createElement("div");
  sub.className = "file-sub"; sub.textContent = `${fmtSize(f.size)} · ${fmtDate(f.createdAt)}`;
  meta.append(name, sub);
  const actions = document.createElement("div");
  actions.className = "file-actions"; actions.append(menuButton("file", f));
  li.append(actions);
  return li;
}

// ---- per-item action sheet ----
function openActions(kind, item) {
  const list = $("action-list");
  list.textContent = "";
  $("action-title").textContent = kind === "folder" ? item.name : decodeName(item.name);
  const add = (label, fn, danger) => {
    const b = document.createElement("button");
    b.className = "action-item" + (danger ? " danger" : "");
    b.type = "button"; b.textContent = label;
    b.addEventListener("click", () => { closeActions(); fn(); });
    list.appendChild(b);
  };
  if (kind === "folder") {
    add("Open", () => loadFs(item.id));
    add("Rename", () => renameFolder(item));
    add("Move", () => openMove("folder", item));
    add("Delete", () => deleteFolder(item), true);
  } else {
    if (isPreviewable(item.mime)) add("Open / preview", () => openPreview(item));
    add("Download", () => downloadFile(item));
    add("Rename", () => renameFileItem(item));
    add("Move", () => openMove("file", item));
    add("Delete", () => deleteFile(item), true);
  }
  $("action-modal").classList.remove("hidden");
}
function closeActions() { $("action-modal").classList.add("hidden"); }

async function downloadFile(f) {
  const res = await fetch(API + "/api/files/" + f.id, { headers: authHeaders() });
  if (!res.ok) { toast("Download failed."); return; }
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = decodeName(f.name);
  document.body.appendChild(a); a.click(); a.remove();
  URL.revokeObjectURL(url);
}

async function deleteFile(f) {
  if (!confirm(`Delete "${decodeName(f.name)}"?`)) return;
  const { ok } = await api("/api/files/" + f.id, { method: "DELETE", headers: authHeaders() });
  if (!ok) { toast("Delete failed."); return; }
  loadFs(currentFolder);
}

// ---- folder + file operations ----
async function newFolder() {
  const name = prompt("New folder name:");
  if (name == null || !name.trim()) return;
  const { ok, body } = await api("/api/folders", {
    method: "POST",
    headers: authHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify({ parentId: currentFolder, name: name.trim() }),
  });
  if (!ok) { toast(prettyError(body) || "Could not create folder"); return; }
  loadFs(currentFolder);
}

async function renameFolder(f) {
  const name = prompt("Rename folder:", f.name);
  if (name == null || !name.trim() || name.trim() === f.name) return;
  const { ok } = await api("/api/folders/" + f.id, {
    method: "PATCH",
    headers: authHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify({ name: name.trim() }),
  });
  if (!ok) { toast("Rename failed"); return; }
  loadFs(currentFolder);
}

async function deleteFolder(f) {
  if (!confirm(`Delete folder "${f.name}" and everything inside it?`)) return;
  const { ok } = await api("/api/folders/" + f.id, { method: "DELETE", headers: authHeaders() });
  if (!ok) { toast("Delete failed"); return; }
  loadFs(currentFolder);
}

async function renameFileItem(f) {
  const cur = decodeName(f.name);
  const name = prompt("Rename file:", cur);
  if (name == null || !name.trim() || name.trim() === cur) return;
  const { ok } = await api("/api/files/" + f.id, {
    method: "PATCH",
    headers: authHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify({ name: name.trim() }),
  });
  if (!ok) { toast("Rename failed"); return; }
  loadFs(currentFolder);
}

// ---- move modal (folder picker) — handles single item or a batch ----
let moveTarget = null;       // { kind:"file"|"folder", item } OR { kind:"batch", files, folders }
let moveCurrentFolder = 0;

function openMove(kind, item) {
  moveTarget = { kind, item };
  moveCurrentFolder = 0;
  $("move-modal").classList.remove("hidden");
  loadMoveFs(0);
}
function openMoveBatch() {
  if (!(selFiles.size + selFolders.size)) return;
  moveTarget = { kind: "batch", files: [...selFiles], folders: [...selFolders] };
  moveCurrentFolder = 0;
  $("move-modal").classList.remove("hidden");
  loadMoveFs(0);
}
function closeMove() { $("move-modal").classList.add("hidden"); moveTarget = null; }

// Folders we must not show as a destination (can't move a folder into itself).
function moveSkipSet() {
  if (!moveTarget) return new Set();
  if (moveTarget.kind === "folder") return new Set([moveTarget.item.id]);
  if (moveTarget.kind === "batch") return new Set(moveTarget.folders);
  return new Set();
}

async function loadMoveFs(folderId) {
  moveCurrentFolder = folderId;
  const { ok, body } = await api("/api/fs?folder=" + folderId, { headers: authHeaders() });
  if (!ok || !body) { toast("Could not load folders."); return; }
  renderBreadcrumbs($("move-breadcrumbs"), body.breadcrumbs || [], (id) => loadMoveFs(id));
  const list = $("move-list");
  list.textContent = "";
  const skip = moveSkipSet();
  const subs = (body.folders || []).filter((f) => !skip.has(f.id));
  if (!subs.length) {
    const p = document.createElement("li");
    p.className = "muted move-empty"; p.textContent = "No subfolders here.";
    list.appendChild(p);
  }
  for (const f of subs) {
    const li = document.createElement("li");
    li.className = "fs-item clickable";
    const ic = document.createElement("div"); ic.className = "file-ic"; ic.textContent = "📁";
    const meta = document.createElement("div"); meta.className = "file-meta";
    const name = document.createElement("div"); name.className = "file-name"; name.textContent = f.name;
    meta.append(name);
    li.append(ic, meta);
    li.addEventListener("click", () => loadMoveFs(f.id));
    list.appendChild(li);
  }
}

async function doMove() {
  if (!moveTarget) return;
  const dest = moveCurrentFolder;
  const isBatch = moveTarget.kind === "batch";
  const patchFile = (id) => api("/api/files/" + id, {
    method: "PATCH", headers: authHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify({ folderId: dest }),
  });
  const patchFolder = (id) => api("/api/folders/" + id, {
    method: "PATCH", headers: authHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify({ parentId: dest }),
  });

  const ops = [];
  if (moveTarget.kind === "file") ops.push(patchFile(moveTarget.item.id));
  else if (moveTarget.kind === "folder") ops.push(patchFolder(moveTarget.item.id));
  else { moveTarget.files.forEach((id) => ops.push(patchFile(id))); moveTarget.folders.forEach((id) => ops.push(patchFolder(id))); }

  const results = await Promise.all(ops);
  const failed = results.filter((r) => !r.ok).length;
  closeMove();
  if (isBatch) exitSelect();
  if (failed) toast(failed + " couldn't be moved");
  loadFs(currentFolder);
}

// ---- search ----
let searchTimer;
function onSearchInput(e) {
  const q = e.target.value.trim();
  clearTimeout(searchTimer);
  if (!q) { loadFs(currentFolder); return; }
  searchTimer = setTimeout(() => doSearch(q), 300);
}
async function doSearch(q) {
  const { ok, status, body } = await api("/api/search?q=" + encodeURIComponent(q), { headers: authHeaders() });
  if (status === 401) { sessionExpired(); return; }
  if (!ok || !body) return;
  resultsMode = true;
  curFolders = body.folders || [];
  curFiles = body.files || [];
  renderResultsHeader('“' + q + '”');
  renderFs();
  updateHome();
}

// ---- batch delete ----
async function batchDelete() {
  const n = selFiles.size + selFolders.size;
  if (!n) return;
  if (!confirm(`Delete ${n} item${n === 1 ? "" : "s"}? Folders delete everything inside.`)) return;
  const ops = [];
  selFiles.forEach((id) => ops.push(api("/api/files/" + id, { method: "DELETE", headers: authHeaders() })));
  selFolders.forEach((id) => ops.push(api("/api/folders/" + id, { method: "DELETE", headers: authHeaders() })));
  const results = await Promise.all(ops);
  const failed = results.filter((r) => !r.ok).length;
  exitSelect();
  if (failed) toast(failed + " couldn't be deleted");
  loadFs(currentFolder);
}

// ---- preview / playback ----
function isPreviewable(mime) { return /^(image|video|audio)\//.test(mime || ""); }

// Opens media inline using the content endpoint. The <img>/<video>/<audio> src
// authenticates via the session cookie (no Authorization header possible), and
// video/audio stream with Range so they seek without downloading the whole file.
function openPreview(file) {
  const modal = $("preview-modal");
  const c = $("preview-content");
  c.textContent = "";
  const src = API + "/api/files/" + file.id + "/content";
  const mime = file.mime || "";
  let el;
  if (mime.startsWith("image/")) { el = document.createElement("img"); el.src = src; }
  else if (mime.startsWith("video/")) { el = document.createElement("video"); el.src = src; el.controls = true; el.autoplay = true; el.playsInline = true; }
  else if (mime.startsWith("audio/")) { el = document.createElement("audio"); el.src = src; el.controls = true; el.autoplay = true; }
  else return;
  el.className = "preview-media";
  const cap = document.createElement("div");
  cap.className = "preview-cap";
  cap.textContent = decodeName(file.name); // textContent — safe
  c.append(el, cap);
  modal.classList.remove("hidden");
}

function closePreview() {
  $("preview-content").textContent = ""; // detaching stops video/audio playback
  $("preview-modal").classList.add("hidden");
}

// ---- upload ----
const UPLOAD_CONCURRENCY = 3;              // parallel uploads; keeps us under the rate limit
const UPLOAD_MAX_ATTEMPTS = 6;             // retries on 429 before giving up
const CHUNK_THRESHOLD = 8 * 1024 * 1024;   // files larger than this upload in chunks
const CHUNK_SIZE = 5 * 1024 * 1024;        // per-chunk size (< server MAX_BODY_SIZE)

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
function sessionExpired() { token = ""; localStorage.removeItem(TOKEN_KEY); showAuth(); }

// Dispatch: small files go in one request, big files stream in chunks.
async function uploadOne(file, state) {
  return file.size > CHUNK_THRESHOLD ? uploadChunked(file, state) : uploadDirect(file, state);
}

// Small file: single POST, retrying with backoff if rate-limited (429).
async function uploadDirect(file, state) {
  for (let attempt = 1; attempt <= UPLOAD_MAX_ATTEMPTS; attempt++) {
    let res;
    try {
      res = await fetch(API + "/api/files", {
        method: "POST",
        headers: authHeaders({
          "X-Filename": encodeURIComponent(file.name), // ASCII-safe header
          "X-Folder": String(currentFolder),
          "Content-Type": file.type || "application/octet-stream",
        }),
        body: file,
      });
    } catch { state.textContent = "Network error"; return false; }

    // Always drain the response body, even on success — if we drop it unread,
    // Chrome cancels the stream and resets the connection mid-write, which makes
    // the server log an EPIPE ("Writing stopped premature") for every upload.
    if (res.ok) { await res.json().catch(() => {}); return true; }
    if (res.status === 429 && attempt < UPLOAD_MAX_ATTEMPTS) {
      state.textContent = `Waiting… (busy, retry ${attempt})`;
      await sleep(Math.min(500 * attempt, 3000));
      continue;
    }
    if (res.status === 401) { sessionExpired(); return false; }
    let body = null;
    try { body = await res.json(); } catch { /* ignore */ }
    state.textContent = prettyError(body) || `Failed (${res.status})`;
    return false;
  }
  return false;
}

// Large file: init -> PUT sequential chunks (resumable) -> complete.
async function uploadChunked(file, state) {
  state.textContent = "Starting…";
  let initRes;
  try {
    initRes = await fetch(API + "/api/uploads/init", {
      method: "POST",
      headers: authHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify({ name: file.name, mime: file.type || "application/octet-stream", size: file.size, folderId: currentFolder }),
    });
  } catch { state.textContent = "Network error"; return false; }
  if (initRes.status === 401) { sessionExpired(); return false; }
  if (!initRes.ok) {
    let b = null; try { b = await initRes.json(); } catch {}
    state.textContent = prettyError(b) || "Upload init failed";
    return false;
  }
  const { uploadId } = await initRes.json();
  const abort = () => fetch(API + "/api/uploads/" + uploadId, { method: "DELETE", headers: authHeaders() }).catch(() => {});

  let offset = 0;
  while (offset < file.size) {
    const chunk = file.slice(offset, Math.min(offset + CHUNK_SIZE, file.size));
    let done = false;
    for (let attempt = 1; attempt <= UPLOAD_MAX_ATTEMPTS; attempt++) {
      let res;
      try {
        res = await fetch(API + "/api/uploads/" + uploadId, {
          method: "PUT",
          headers: authHeaders({ "X-Offset": String(offset), "Content-Type": "application/octet-stream" }),
          body: chunk,
        });
      } catch { state.textContent = "Network error"; abort(); return false; }

      if (res.ok) { offset = (await res.json()).received; done = true; break; }
      if (res.status === 429 && attempt < UPLOAD_MAX_ATTEMPTS) { await sleep(Math.min(500 * attempt, 3000)); continue; }
      if (res.status === 409) { // offset drifted — resync to what the server has
        try { const j = await res.json(); if (typeof j.received === "number") { offset = j.received; done = true; break; } } catch {}
      }
      if (res.status === 401) { sessionExpired(); return false; }
      let b = null; try { b = await res.json(); } catch {}
      state.textContent = prettyError(b) || `Failed (${res.status})`;
      abort();
      return false;
    }
    if (!done) { abort(); return false; }
    state.textContent = "Uploading… " + Math.floor((offset / file.size) * 100) + "%";
  }

  const comp = await fetch(API + "/api/uploads/" + uploadId + "/complete", { method: "POST", headers: authHeaders() });
  if (!comp.ok) {
    let b = null; try { b = await comp.json(); } catch {}
    state.textContent = prettyError(b) || "Finalize failed";
    return false;
  }
  await comp.json().catch(() => {}); // drain the body (avoid EPIPE, see uploadDirect)
  return true;
}

async function uploadFiles(fileList) {
  const files = Array.from(fileList);
  if (!files.length) return;
  const box = $("uploads");

  // Build a row per file up front so progress is visible immediately.
  const jobs = files.map((file) => {
    const row = document.createElement("div");
    row.className = "upload-row";
    const label = document.createElement("span");
    label.textContent = file.name; // textContent — safe
    const state = document.createElement("span");
    state.textContent = "Queued…";
    row.append(label, state);
    box.appendChild(row);
    return { file, row, state };
  });

  // Worker pool: at most UPLOAD_CONCURRENCY uploads in flight at once.
  let next = 0;
  async function worker() {
    while (next < jobs.length) {
      const j = jobs[next++];
      j.state.textContent = "Uploading…";
      const ok = await uploadOne(j.file, j.state);
      if (ok) {
        j.state.textContent = "Done ✔";
        setTimeout(() => j.row.remove(), 1500);
      } else {
        j.row.classList.add("err");
      }
    }
  }
  await Promise.all(
    Array.from({ length: Math.min(UPLOAD_CONCURRENCY, jobs.length) }, worker)
  );
  loadFs(currentFolder);
}

// ---- drag & drop (folder-aware) ----
// Read every entry from a directory reader (it returns results in batches).
function readAllEntries(reader) {
  return new Promise((resolve) => {
    const all = [];
    const pump = () => reader.readEntries((batch) => {
      if (!batch.length) return resolve(all);
      all.push(...batch);
      pump();
    }, () => resolve(all));
    pump();
  });
}

// Recursively collect File objects from a dropped file/folder entry.
async function collectEntry(entry, out) {
  if (entry.isFile) {
    try { out.push(await new Promise((res, rej) => entry.file(res, rej))); } catch { /* skip */ }
  } else if (entry.isDirectory) {
    const entries = await readAllEntries(entry.createReader());
    for (const e of entries) await collectEntry(e, out);
  }
}

function wireDropzone() {
  const dz = $("dropzone");
  ["dragenter", "dragover"].forEach((ev) =>
    dz.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.add("drag"); }));
  ["dragleave", "drop"].forEach((ev) =>
    dz.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.remove("drag"); }));
  dz.addEventListener("drop", async (e) => {
    const dt = e.dataTransfer;
    if (!dt) return;
    // Prefer entries (handles dropped folders); fall back to a flat file list.
    const entries = dt.items
      ? Array.from(dt.items).map((it) => it.webkitGetAsEntry && it.webkitGetAsEntry()).filter(Boolean)
      : [];
    if (entries.length) {
      const files = [];
      for (const entry of entries) await collectEntry(entry, files);
      if (files.length) uploadFiles(files);
      else toast("Nothing to upload.");
    } else if (dt.files && dt.files.length) {
      uploadFiles(dt.files);
    }
  });
}

// ---- notes ----
let editingNoteId = null;

function switchTab(tab) {
  const files = tab === "files";
  $("nav-files").classList.toggle("active", files);
  $("nav-notes").classList.toggle("active", !files);
  $("files-tab").classList.toggle("hidden", !files);
  $("notes-tab").classList.toggle("hidden", files);
  if (!files) { showNotesList(); loadNotes(); }
}

function showNotesList() {
  $("note-editor").classList.add("hidden");
  $("notes-list-view").classList.remove("hidden");
}
function showNoteEditor() {
  $("notes-list-view").classList.add("hidden");
  $("note-editor").classList.remove("hidden");
  $("note-status").textContent = "";
}

async function loadNotes() {
  const { ok, status, body } = await api("/api/notes", { headers: authHeaders() });
  if (status === 401) { token = ""; localStorage.removeItem(TOKEN_KEY); showAuth(); return; }
  if (!ok || !body) { toast("Could not load notes."); return; }
  const list = $("note-list");
  list.textContent = "";
  const notes = body.notes || [];
  $("notes-empty").classList.toggle("hidden", notes.length > 0);
  for (const n of notes) list.appendChild(noteCard(n));
}

function noteCard(n) {
  const li = document.createElement("li");
  li.className = "note-card";
  const t = document.createElement("div");
  t.className = "note-t";
  t.textContent = n.title && n.title.trim() ? n.title : "Untitled"; // textContent — safe
  const d = document.createElement("div");
  d.className = "note-d";
  d.textContent = "Edited " + fmtDate(n.updatedAt);
  li.append(t, d);
  li.addEventListener("click", () => openNote(n.id));
  return li;
}

async function openNote(id) {
  const { ok, body } = await api("/api/notes/" + id, { headers: authHeaders() });
  if (!ok || !body || !body.note) { toast("Could not open note."); return; }
  editingNoteId = body.note.id;
  $("note-title").value = body.note.title || ""; // .value — safe, never parsed as HTML
  $("note-body").value = body.note.body || "";
  $("note-delete").classList.remove("hidden");
  showNoteEditor();
}

function newNote() {
  editingNoteId = null;
  $("note-title").value = "";
  $("note-body").value = "";
  $("note-delete").classList.add("hidden");
  showNoteEditor();
  $("note-title").focus();
}

async function saveNote() {
  const payload = JSON.stringify({ title: $("note-title").value, body: $("note-body").value });
  const path = editingNoteId ? "/api/notes/" + editingNoteId : "/api/notes";
  const { ok, body } = await api(path, {
    method: editingNoteId ? "PUT" : "POST",
    headers: authHeaders({ "Content-Type": "application/json" }),
    body: payload,
  });
  if (!ok || !body || !body.note) {
    $("note-status").textContent = prettyError(body) || "Save failed";
    return;
  }
  editingNoteId = body.note.id;
  $("note-delete").classList.remove("hidden");
  $("note-status").textContent = "Saved ✔";
}

async function deleteCurrentNote() {
  if (!editingNoteId) { showNotesList(); return; }
  if (!confirm("Delete this note?")) return;
  const { ok } = await api("/api/notes/" + editingNoteId, { method: "DELETE", headers: authHeaders() });
  if (!ok) { toast("Delete failed."); return; }
  editingNoteId = null;
  showNotesList();
  loadNotes();
}

// ---- boot ----
async function boot() {
  $("tab-login").addEventListener("click", () => setMode("login"));
  $("tab-register").addEventListener("click", () => setMode("register"));
  $("auth-form").addEventListener("submit", onAuthSubmit);
  $("logout").addEventListener("click", logout);
  $("new-folder").addEventListener("click", newFolder);
  $("pick").addEventListener("click", () => $("file-input").click());
  $("file-input").addEventListener("change", (e) => uploadFiles(e.target.files));
  $("view-toggle").addEventListener("click", toggleView);
  $("sort-btn").addEventListener("click", openSort);
  $("select-btn").addEventListener("click", () => (selectMode ? exitSelect() : enterSelect()));
  $("search-input").addEventListener("input", onSearchInput);
  document.querySelectorAll(".cat").forEach((b) => b.addEventListener("click", () => openCategory(b.dataset.cat)));

  // selection bar
  $("sel-move").addEventListener("click", openMoveBatch);
  $("sel-delete").addEventListener("click", batchDelete);
  $("sel-cancel").addEventListener("click", exitSelect);
  $("sort-close").addEventListener("click", closeSort);
  $("sort-modal").addEventListener("click", (e) => { if (e.target.id === "sort-modal") closeSort(); });
  wireDropzone();

  // move modal
  $("move-close").addEventListener("click", closeMove);
  $("move-here").addEventListener("click", doMove);
  $("move-modal").addEventListener("click", (e) => { if (e.target.id === "move-modal") closeMove(); });

  // action sheet
  $("action-close").addEventListener("click", closeActions);
  $("action-modal").addEventListener("click", (e) => { if (e.target.id === "action-modal") closeActions(); });

  // notes
  $("nav-files").addEventListener("click", () => switchTab("files"));
  $("nav-notes").addEventListener("click", () => switchTab("notes"));
  $("new-note").addEventListener("click", newNote);
  $("note-back").addEventListener("click", () => { showNotesList(); loadNotes(); });
  $("note-save").addEventListener("click", saveNote);
  $("note-delete").addEventListener("click", deleteCurrentNote);

  // preview modal
  $("preview-close").addEventListener("click", closePreview);
  $("preview-modal").addEventListener("click", (e) => { if (e.target.id === "preview-modal") closePreview(); });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") { closePreview(); closeMove(); closeActions(); closeSort(); } });

  setMode("login");

  if (token) {
    const { ok, body } = await api("/api/auth/me", { headers: authHeaders() });
    if (ok && body && body.user) { showApp(body.user); return; }
    token = ""; localStorage.removeItem(TOKEN_KEY);
  }
  showAuth();
}

boot();

if ("serviceWorker" in navigator) {
  window.addEventListener("load", () => navigator.serviceWorker.register("/sw.js").catch(() => {}));
}

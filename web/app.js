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
function initials(s) {
  const parts = (s || "?").trim().split(/[\s@._-]+/).filter(Boolean);
  return ((parts[0]?.[0] || "?") + (parts[1]?.[0] || "")).toUpperCase();
}
function showApp(user) {
  $("auth-view").classList.add("hidden");
  $("app-view").classList.remove("hidden");
  const label = user ? (user.displayName || user.email) : "";
  $("who").textContent = label;
  const av = $("avatar"); if (av) { av.textContent = initials(label); av.title = label; }
  loadFs(0); // land on Files
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

// ==== E2E crypto (WebCrypto) ====
// Zero-knowledge: the password derives keys in the browser. The server only ever
// sees an AUTH key (for login) and wrapped key material it cannot open.
const te = new TextEncoder();
const PBKDF2_ITERS = 310000;

function toHex(buf) { return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join(""); }
function fromHex(s) { const a = new Uint8Array(s.length / 2); for (let i = 0; i < a.length; i++) a[i] = parseInt(s.substr(i * 2, 2), 16); return a; }
function toB64(buf) { let s = ""; const a = new Uint8Array(buf); for (let i = 0; i < a.length; i++) s += String.fromCharCode(a[i]); return btoa(s); }
function fromB64(s) { const bin = atob(s); const a = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) a[i] = bin.charCodeAt(i); return a; }
function randBytes(n) { return crypto.getRandomValues(new Uint8Array(n)); }

// Derive an AUTH key (sent to the server) + a KEK (stays in the browser).
async function deriveKeys(password, saltHex) {
  const base = await crypto.subtle.importKey("raw", te.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = new Uint8Array(await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: fromHex(saltHex), iterations: PBKDF2_ITERS, hash: "SHA-256" }, base, 512));
  const kek = await crypto.subtle.importKey("raw", bits.slice(32, 64), { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
  return { authKeyB64: toB64(bits.slice(0, 32)), kek };
}
function importAes(raw) { return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]); }
async function wrapBytes(raw, key) {
  const iv = randBytes(12);
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, raw);
  return toB64(iv) + "." + toB64(new Uint8Array(ct));
}
async function unwrapBytes(wrapped, key) {
  const [iv, ct] = wrapped.split(".");
  return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: fromB64(iv) }, key, fromB64(ct)));
}

// ---- content encryption (chunked AES-256-GCM, STREAM-style) ----
// Each frame on the wire/disk is [nonce(12) ‖ ciphertext ‖ tag(16)]; full frames
// hold ENC_CHUNK plaintext bytes, so decryption can seek by fixed frame size.
// The frame index + a final-frame flag are bound into the GCM AAD, so an
// untrusted server cannot reorder, drop (truncate), duplicate, or splice frames
// without the tag check failing on decrypt.
const ENC_CHUNK = 1024 * 1024;
const ENC_OVERHEAD = 12 + 16;
function concatBytes(list) { const n = list.reduce((s, c) => s + c.length, 0); const o = new Uint8Array(n); let p = 0; for (const c of list) { o.set(c, p); p += c.length; } return o; }
// AAD = big-endian uint32 frame index ‖ final-flag byte.
function frameAad(index, isFinal) {
  return new Uint8Array([(index >>> 24) & 0xff, (index >>> 16) & 0xff, (index >>> 8) & 0xff, index & 0xff, isFinal ? 1 : 0]);
}
async function encryptChunk(fileKey, slice, index, isFinal) {
  const nonce = randBytes(12);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: frameAad(index, isFinal) }, fileKey, slice));
  const frame = new Uint8Array(12 + ct.length); frame.set(nonce, 0); frame.set(ct, 12);
  return frame;
}
async function decryptFrame(fileKey, frame, index, isFinal) {
  return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: frame.subarray(0, 12), additionalData: frameAad(index, isFinal) }, fileKey, frame.subarray(12)));
}
async function encryptContent(fileKey, plain) {
  const frames = [];
  const total = Math.max(1, Math.ceil(plain.length / ENC_CHUNK)); // 0-byte file => one empty final frame
  let off = 0, i = 0;
  do {
    frames.push(await encryptChunk(fileKey, plain.subarray(off, Math.min(off + ENC_CHUNK, plain.length)), i, i === total - 1));
    off += ENC_CHUNK; i++;
  } while (off < plain.length);
  return concatBytes(frames);
}
async function decryptContent(fileKey, cipher) {
  if (cipher.length === 0) throw new Error("empty ciphertext"); // a real file has >= 1 frame
  const FRAME = ENC_CHUNK + ENC_OVERHEAD; const parts = [];
  let i = 0;
  for (let off = 0; off < cipher.length; i++) {
    const len = Math.min(FRAME, cipher.length - off);
    const isFinal = off + len >= cipher.length; // last frame by position
    parts.push(await decryptFrame(fileKey, cipher.subarray(off, off + len), i, isFinal));
    off += len;
  }
  return concatBytes(parts);
}

// Per-file content keys, wrapped by the user's DEK.
function dekKey() { return importAes(DEK_RAW); }
async function newFileKey() { const raw = randBytes(32); return { raw, key: await importAes(raw) }; }
async function wrapFileKey(raw) { return wrapBytes(raw, await dekKey()); }
async function unwrapFileKey(wrapped) { return importAes(await unwrapBytes(wrapped, await dekKey())); }

// ---- E2E upload/download plumbing ----
// Encrypt a File for upload. Returns the ciphertext bytes, the per-file key
// wrapped by the DEK, and the plaintext size (stored server-side for display).
// Throws if the DEK is missing — we never silently store plaintext.
async function encryptFileForUpload(file) {
  const plain = new Uint8Array(await file.arrayBuffer());
  const { raw, key } = await newFileKey();
  const cipher = await encryptContent(key, plain);
  const wrappedKey = await wrapFileKey(raw);
  const encName = await encryptName(file.name);
  return { cipher, wrappedKey, plainSize: plain.length, encName };
}

// Fetch a file's stored content and return its plaintext bytes. A file with no
// wrappedKey is a legacy plaintext blob and is returned as-is.
async function fetchPlaintext(item) {
  const res = await fetch(API + "/api/files/" + item.id + "/content", { headers: authHeaders() });
  if (!res.ok) throw new Error("fetch " + res.status);
  const cipher = new Uint8Array(await res.arrayBuffer());
  if (!item.wrappedKey) return cipher;
  const key = await unwrapFileKey(item.wrappedKey);
  return decryptContent(key, cipher);
}

// A blob: URL of a file's decrypted content. Caller revokes it when done.
async function objectUrlFor(item) {
  const bytes = await fetchPlaintext(item);
  return URL.createObjectURL(new Blob([bytes], { type: item.mime || "application/octet-stream" }));
}

// ---- E2E name encryption ----
// Display names are encrypted under the DEK (like content keys), so the server
// only ever stores opaque blobs. Empty encName = legacy plaintext (see dispName).
const _nameDec = new TextDecoder();
async function encryptName(name) { return wrapBytes(new TextEncoder().encode(name), await dekKey()); }
async function decryptName(enc) { return _nameDec.decode(await unwrapBytes(enc, await dekKey())); }
// Decrypt encName -> item._name for every item in a listing, before it renders.
async function hydrateNames(...lists) {
  for (const items of lists) {
    if (!Array.isArray(items)) continue;
    for (const it of items) {
      if (it && it.encName) {
        try { it._name = await decryptName(it.encName); }
        catch { it._name = "🔒 locked"; }
      }
    }
  }
}
// The name to show: decrypted plaintext for E2E items, else the legacy name.
function dispName(item) {
  if (!item) return "";
  if (item.encName) return item._name != null ? item._name : "🔒 locked";
  return decodeName(item.name);
}

// The Data Encryption Key lives in memory + sessionStorage (per-tab, cleared on close).
let DEK_RAW = null;
function setDEK(raw) { DEK_RAW = raw; try { sessionStorage.setItem("cs_dek", toB64(raw)); } catch {} }
function clearDEK() { DEK_RAW = null; try { sessionStorage.removeItem("cs_dek"); } catch {} }
function restoreDEK() { if (!DEK_RAW) { const s = sessionStorage.getItem("cs_dek"); if (s) DEK_RAW = fromB64(s); } return !!DEK_RAW; }

async function e2eRegister(email, password, displayName) {
  const saltHex = toHex(randBytes(16));
  const { authKeyB64, kek } = await deriveKeys(password, saltHex);
  const dekRaw = randBytes(32);
  const wrappedDek = await wrapBytes(dekRaw, kek);
  const recRaw = randBytes(32);
  const wrappedDekRecovery = await wrapBytes(dekRaw, await importAes(recRaw));
  const { ok, body } = await api("/api/auth/register", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password: authKeyB64, displayName, salt: saltHex, wrappedDek, wrappedDekRecovery }),
  });
  if (!ok || !body || !body.token) return { ok: false, body };
  setDEK(dekRaw);
  return { ok: true, token: body.token, user: body.user, recoveryKey: "csr_" + toB64(recRaw) };
}

async function e2eLogin(email, password) {
  const s = await api("/api/auth/salt?email=" + encodeURIComponent(email), {});
  const saltHex = (s.ok && s.body && s.body.salt) ? s.body.salt : toHex(randBytes(16));
  const { authKeyB64, kek } = await deriveKeys(password, saltHex);
  const { ok, body } = await api("/api/auth/login", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password: authKeyB64 }),
  });
  if (!ok || !body || !body.token) return { ok: false, body };
  try { setDEK(await unwrapBytes(body.wrappedDek, kek)); }
  catch { return { ok: false, body: { error: "invalid credentials" } }; }
  return { ok: true, token: body.token, user: body.user };
}

async function onAuthSubmit(e) {
  e.preventDefault();
  $("auth-error").textContent = "";
  const email = $("email").value.trim();
  const password = $("password").value;
  const displayName = $("display-name").value.trim();
  const btn = $("auth-submit");
  btn.disabled = true; btn.textContent = mode === "login" ? "Unlocking…" : "Creating…";

  let r;
  try {
    r = mode === "login" ? await e2eLogin(email, password) : await e2eRegister(email, password, displayName);
  } catch (err) { r = { ok: false, body: { error: err.message } }; }
  btn.disabled = false; setMode(mode);

  if (!r.ok) { $("auth-error").textContent = prettyError(r.body) || "Something went wrong."; return; }
  token = r.token;
  localStorage.setItem(TOKEN_KEY, token);
  $("password").value = "";
  if (mode === "register" && r.recoveryKey) showRecoveryKey(r.recoveryKey, r.user);
  else showApp(r.user);
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

// One-time recovery key screen shown after registration.
function showRecoveryKey(key, user) {
  $("recovery-key").textContent = key;
  $("recovery-modal").classList.remove("hidden");
  $("recovery-download").onclick = () => {
    const blob = new Blob(
      ["cloud-serv recovery key for " + (user?.email || "") + "\n\n" + key +
       "\n\nKeep this safe. It is the ONLY way to recover your account if you forget your password.\n"],
      { type: "text/plain" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob); a.download = "cloud-serv-recovery-key.txt";
    document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(a.href);
  };
  $("recovery-continue").onclick = () => { $("recovery-modal").classList.add("hidden"); showApp(user); };
}

async function logout() {
  await api("/api/auth/logout", { method: "POST", headers: authHeaders() });
  token = "";
  localStorage.removeItem(TOKEN_KEY);
  clearDEK();
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
  setActiveNav("files");
  showFilesTab();
  closeSidebar();
  const si = $("search-input"); if (si) si.value = "";
  const { ok, status, body } = await api("/api/fs?folder=" + folderId, { headers: authHeaders() });
  if (status === 401) { sessionExpired(); return; }
  if (!ok || !body) { toast("Could not load folder."); return; }
  curFolders = body.folders || [];
  curFiles = body.files || [];
  await hydrateNames(curFolders, curFiles, body.breadcrumbs || []);
  renderBreadcrumbs($("breadcrumbs"), body.breadcrumbs || [], (id) => loadFs(id));
  renderFs();
  updateHome();
  loadUsage(); // sidebar storage chip stays current
}

// Category row is only shown at the root, in normal (non-results) mode.
function updateHome() {
  const atRoot = currentFolder === 0 && !resultsMode;
  $("home-extras").classList.toggle("hidden", !atRoot);
  $("dropzone").classList.toggle("hidden", resultsMode);
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
  setActiveNav("files");
  showFilesTab();
  curFolders = [];
  curFiles = body.files || [];
  await hydrateNames(curFiles);
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
    else r = dispName(a).localeCompare(dispName(b), undefined, { sensitivity: "base", numeric: true });
    return r * dir;
  });
}

// A "Folders" / "Files" section divider (Android/Drive style, folder-first).
function sectionLabel(text, count, grid) {
  const li = document.createElement("li");
  li.className = "section-label" + (grid ? " grid-span" : "");
  li.textContent = count != null ? `${text} · ${count}` : text;
  return li;
}

// Renders the current folder contents in the active view + sort (no refetch).
// Folder-first: folders are grouped under a "Folders" header, then "Files".
function renderFs() {
  const list = $("fs-list");
  const grid = viewMode === "grid";
  list.className = grid ? "fs-grid" : "fs-list";
  list.textContent = "";
  const folders = sortItems(curFolders, false);
  const files = sortItems(curFiles, true);
  $("fs-empty").classList.toggle("hidden", folders.length + files.length > 0);

  if (!grid && (folders.length + files.length)) list.appendChild(listHeader());

  if (folders.length) {
    list.appendChild(sectionLabel("Folders", folders.length, grid));
    for (const f of folders) list.appendChild(grid ? gridCell("folder", f) : folderRow(f));
  }
  if (files.length) {
    list.appendChild(sectionLabel("Files", files.length, grid));
    for (const f of files) list.appendChild(grid ? gridCell("file", f) : fileRow(f));
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
    img.loading = "lazy"; img.alt = "";
    if (item.wrappedKey) {
      // E2E: fetch + decrypt, then swap in a blob URL (revoked once decoded).
      objectUrlFor(item)
        .then((u) => { img.src = u; img.addEventListener("load", () => URL.revokeObjectURL(u), { once: true }); })
        .catch(() => {});
    } else {
      img.src = API + "/api/files/" + item.id + "/content"; // legacy plaintext
    }
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
  name.textContent = dispName(item);
  name.title = name.textContent;
  if (item.starred) {
    const star = document.createElement("span");
    star.className = "grid-star"; star.textContent = "★";
    thumb.appendChild(star);
  }
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
    b.textContent = dispName(c); // textContent — safe
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

function cell(cls, text) {
  const d = document.createElement("div");
  d.className = "cell " + cls;
  if (text != null) d.textContent = text;
  return d;
}

// Drive-style list row: [name (icon+name+star)] [modified] [size] [menu].
// On mobile the modified/size columns collapse into a sub-line under the name.
function listRow(kind, item, icText, displayName, modified, size) {
  const li = document.createElement("li");
  li.className = "fs-item";
  if (selectMode) li.classList.add("selecting");
  if (isSelected(kind, item.id)) li.classList.add("selected");

  const nameCell = document.createElement("div");
  nameCell.className = "cell cell-name clickable";
  const check = document.createElement("div"); check.className = "row-check"; check.textContent = "✓";
  const ic = document.createElement("div"); ic.className = "file-ic"; ic.textContent = icText;
  const wrap = document.createElement("div"); wrap.className = "name-wrap";
  const name = document.createElement("div"); name.className = "file-name"; name.textContent = displayName; name.title = displayName;
  const sub = document.createElement("div"); sub.className = "file-sub mobile-only";
  sub.textContent = kind === "folder" ? "Folder" : `${size} · ${modified}`;
  wrap.append(name, sub);
  nameCell.append(check, ic, wrap);
  if (item.starred) { const s = document.createElement("span"); s.className = "star-mark"; s.textContent = "★"; s.title = "Starred"; nameCell.append(s); }

  const menuCell = document.createElement("div"); menuCell.className = "cell cell-menu";
  menuCell.append(menuButton(kind, item));

  li.append(nameCell, cell("cell-mod", modified), cell("cell-size", kind === "folder" ? "—" : size), menuCell);
  li.addEventListener("click", (e) => {
    if (e.target.closest(".menu-btn")) return;
    rowActivate(li, kind, item);
  });
  return li;
}

function folderRow(f) { return listRow("folder", f, "📁", dispName(f), fmtDate(f.createdAt), "—"); }
function fileRow(f) {
  return listRow("file", f, iconFor(f.mime), dispName(f), fmtDate(f.createdAt), fmtSize(f.size));
}

// Sortable column header for list view.
function listHeader() {
  const li = document.createElement("li");
  li.className = "fs-head";
  const col = (by, label, cls) => {
    const d = document.createElement("div");
    d.className = "cell " + cls + " sortable";
    d.textContent = label + (sortBy === by ? (sortDir === "asc" ? " ↑" : " ↓") : "");
    d.addEventListener("click", () => setSort(by));
    return d;
  };
  li.append(col("name", "Name", "cell-name"), col("date", "Modified", "cell-mod"),
            col("size", "Size", "cell-size"), cell("cell-menu", ""));
  return li;
}

function setSort(by) {
  if (sortBy === by) sortDir = sortDir === "asc" ? "desc" : "asc";
  else { sortBy = by; sortDir = (by === "date" || by === "size") ? "desc" : "asc"; }
  localStorage.setItem("cs_sortby", sortBy);
  localStorage.setItem("cs_sortdir", sortDir);
  renderFs();
}

// ---- per-item action sheet ----
function openActions(kind, item) {
  const list = $("action-list");
  list.textContent = "";
  $("action-title").textContent = dispName(item);
  const add = (label, fn, danger) => {
    const b = document.createElement("button");
    b.className = "action-item" + (danger ? " danger" : "");
    b.type = "button"; b.textContent = label;
    b.addEventListener("click", () => { closeActions(); fn(); });
    list.appendChild(b);
  };
  if (kind === "folder") {
    add("Open", () => loadFs(item.id));
    add(item.starred ? "★ Unstar" : "☆ Star", () => toggleStar("folder", item));
    add("Rename", () => renameFolder(item));
    add("Move", () => openMove("folder", item));
    add("Delete", () => deleteFolder(item), true);
  } else {
    if (isPreviewable(item.mime)) add("Open / preview", () => openPreview(item));
    add(item.starred ? "★ Unstar" : "☆ Star", () => toggleStar("file", item));
    add("Download", () => downloadFile(item));
    add("Rename", () => renameFileItem(item));
    add("Move", () => openMove("file", item));
    add("Delete", () => deleteFile(item), true);
  }
  $("action-modal").classList.remove("hidden");
}
function closeActions() { $("action-modal").classList.add("hidden"); }

async function toggleStar(kind, item) {
  const path = (kind === "folder" ? "/api/folders/" : "/api/files/") + item.id;
  const { ok } = await api(path, {
    method: "PATCH", headers: authHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify({ starred: !item.starred }),
  });
  if (!ok) { toast("Couldn't update star"); return; }
  refreshCurrentView();
}

// Reload whatever view is active (folder, recent, or starred).
function refreshCurrentView() {
  if ($("nav-starred").classList.contains("active")) loadView("starred");
  else if ($("nav-recent").classList.contains("active")) loadView("recent");
  else loadFs(currentFolder);
}

// ---- New menu ----
function openNewMenu() { $("new-modal").classList.remove("hidden"); }
function closeNewMenu() { $("new-modal").classList.add("hidden"); }

async function downloadFile(f) {
  let bytes;
  try { bytes = await fetchPlaintext(f); }
  catch { toast("Download failed."); return; }
  const url = URL.createObjectURL(new Blob([bytes], { type: f.mime || "application/octet-stream" }));
  const a = document.createElement("a");
  a.href = url; a.download = dispName(f);
  document.body.appendChild(a); a.click(); a.remove();
  URL.revokeObjectURL(url);
}

async function deleteFile(f) {
  if (!confirm(`Delete "${dispName(f)}"?`)) return;
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
    body: JSON.stringify({ parentId: currentFolder, encName: await encryptName(name.trim()) }),
  });
  if (!ok) { toast(prettyError(body) || "Could not create folder"); return; }
  loadFs(currentFolder);
}

async function renameFolder(f) {
  const cur = dispName(f);
  const name = prompt("Rename folder:", cur);
  if (name == null || !name.trim() || name.trim() === cur) return;
  const { ok } = await api("/api/folders/" + f.id, {
    method: "PATCH",
    headers: authHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify({ encName: await encryptName(name.trim()) }),
  });
  if (!ok) { toast("Rename failed"); return; }
  loadFs(currentFolder);
}

async function deleteFolder(f) {
  if (!confirm(`Delete folder "${dispName(f)}" and everything inside it?`)) return;
  const { ok } = await api("/api/folders/" + f.id, { method: "DELETE", headers: authHeaders() });
  if (!ok) { toast("Delete failed"); return; }
  loadFs(currentFolder);
}

async function renameFileItem(f) {
  const cur = dispName(f);
  const name = prompt("Rename file:", cur);
  if (name == null || !name.trim() || name.trim() === cur) return;
  const { ok } = await api("/api/files/" + f.id, {
    method: "PATCH",
    headers: authHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify({ encName: await encryptName(name.trim()) }),
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
  await hydrateNames(body.folders || [], body.breadcrumbs || []);
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
    const name = document.createElement("div"); name.className = "file-name"; name.textContent = dispName(f);
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
  setActiveNav("files");
  showFilesTab();
  curFolders = body.folders || [];
  curFiles = body.files || [];
  await hydrateNames(curFolders, curFiles);
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
let previewObjectUrl = null; // revoked when the preview closes

async function openPreview(file) {
  const modal = $("preview-modal");
  const c = $("preview-content");
  const mime = file.mime || "";
  let el;
  if (mime.startsWith("image/")) el = document.createElement("img");
  else if (mime.startsWith("video/")) { el = document.createElement("video"); el.controls = true; el.autoplay = true; el.playsInline = true; }
  else if (mime.startsWith("audio/")) { el = document.createElement("audio"); el.controls = true; el.autoplay = true; }
  else return;

  c.textContent = "Loading…";
  modal.classList.remove("hidden");

  // E2E: fetch + decrypt into a blob URL (download-then-play). Video/audio load
  // the whole file into memory for now; streamed decrypt is a later phase.
  let url;
  try { url = await objectUrlFor(file); }
  catch { c.textContent = "Preview failed."; return; }
  if (modal.classList.contains("hidden")) { URL.revokeObjectURL(url); return; } // closed while loading

  if (previewObjectUrl) URL.revokeObjectURL(previewObjectUrl);
  previewObjectUrl = url;
  el.src = url;
  el.className = "preview-media";
  const cap = document.createElement("div");
  cap.className = "preview-cap";
  cap.textContent = dispName(file); // textContent — safe
  c.textContent = "";
  c.append(el, cap);
}

function closePreview() {
  $("preview-content").textContent = ""; // detaching stops video/audio playback
  $("preview-modal").classList.add("hidden");
  if (previewObjectUrl) { URL.revokeObjectURL(previewObjectUrl); previewObjectUrl = null; }
}

// ---- upload ----
const UPLOAD_CONCURRENCY = 3;              // parallel uploads; keeps us under the rate limit
const UPLOAD_MAX_ATTEMPTS = 6;             // retries on 429 before giving up
const CHUNK_THRESHOLD = 8 * 1024 * 1024;   // files larger than this upload in chunks
const CHUNK_SIZE = 5 * 1024 * 1024;        // per-chunk size (< server MAX_BODY_SIZE)

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
function sessionExpired() { token = ""; localStorage.removeItem(TOKEN_KEY); clearDEK(); showAuth(); }

// Dispatch: small files go in one request, big files stream in chunks.
async function uploadOne(file, state, folderId) {
  return file.size > CHUNK_THRESHOLD ? uploadChunked(file, state, folderId) : uploadDirect(file, state, folderId);
}

// Small file: encrypt client-side, then single POST, retrying with backoff if
// rate-limited (429).
async function uploadDirect(file, state, folderId) {
  let enc;
  try { enc = await encryptFileForUpload(file); }
  catch { state.textContent = "Encryption failed"; return false; }

  for (let attempt = 1; attempt <= UPLOAD_MAX_ATTEMPTS; attempt++) {
    let res;
    try {
      res = await fetch(API + "/api/files", {
        method: "POST",
        headers: authHeaders({
          "X-Enc-Name": enc.encName, // encrypted filename (opaque to the server)
          "X-Folder": String(folderId),
          "X-Wrapped-Key": enc.wrappedKey,
          "X-Plain-Size": String(enc.plainSize),
          "Content-Type": file.type || "application/octet-stream",
        }),
        body: enc.cipher,
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

// Large file: encrypt client-side, then init -> PUT sequential ciphertext
// chunks (resumable) -> complete. We encrypt the whole file up front (memory-
// bound; streaming encrypt is a later optimization); wire chunks are just
// slices of the ciphertext, so resume/offset logic is unchanged.
async function uploadChunked(file, state, folderId) {
  state.textContent = "Encrypting…";
  let enc;
  try { enc = await encryptFileForUpload(file); }
  catch { state.textContent = "Encryption failed"; return false; }
  const cipher = enc.cipher;
  const total = cipher.length;

  state.textContent = "Starting…";
  let initRes;
  try {
    initRes = await fetch(API + "/api/uploads/init", {
      method: "POST",
      headers: authHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify({
        encName: enc.encName, mime: file.type || "application/octet-stream",
        size: total, folderId,
        wrappedKey: enc.wrappedKey, plainSize: enc.plainSize,
      }),
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
  while (offset < total) {
    const chunk = cipher.subarray(offset, Math.min(offset + CHUNK_SIZE, total));
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
    state.textContent = "Uploading… " + Math.floor((offset / total) * 100) + "%";
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

// A fixed, always-visible overall upload progress bar.
function makeUploadProgress(total) {
  const bar = document.createElement("div");
  bar.className = "upload-progress";
  const label = document.createElement("div"); label.className = "up-label";
  const track = document.createElement("div"); track.className = "up-track";
  const fill = document.createElement("div"); fill.className = "up-fill";
  track.append(fill);
  bar.append(label, track);
  $("app-view").appendChild(bar);
  return {
    update(done, failed) {
      fill.style.width = Math.round((done / total) * 100) + "%";
      label.textContent = `Uploading… ${done}/${total}` + (failed ? ` · ${failed} failed` : "");
    },
    finish(done, failed) {
      fill.style.width = "100%";
      bar.classList.toggle("err", failed > 0);
      label.textContent = failed
        ? `Uploaded ${done - failed}/${done} · ${failed} failed`
        : `Uploaded ${done} file${done === 1 ? "" : "s"} ✔`;
      setTimeout(() => bar.remove(), failed ? 6000 : 2500);
    },
  };
}

// Worker pool over jobs of { file, folderId, label }.
async function runUploads(jobs) {
  if (!jobs.length) return;
  const box = $("uploads");
  const total = jobs.length;
  const showRows = total <= 8; // per-file rows only for small batches
  let done = 0, failed = 0;
  const progress = makeUploadProgress(total);
  progress.update(0, 0);

  const rows = jobs.map((j) => {
    if (!showRows) return { ...j, row: null, state: {} };
    const row = document.createElement("div");
    row.className = "upload-row";
    const label = document.createElement("span");
    label.textContent = j.label; // textContent — safe
    const state = document.createElement("span");
    state.textContent = "Queued…";
    row.append(label, state);
    box.appendChild(row);
    return { ...j, row, state };
  });

  let next = 0;
  async function worker() {
    while (next < rows.length) {
      const j = rows[next++];
      if (j.row) j.state.textContent = "Uploading…";
      const ok = await uploadOne(j.file, j.state, j.folderId);
      if (ok) { if (j.row) { j.state.textContent = "Done ✔"; setTimeout(() => j.row.remove(), 1500); } }
      else {
        failed++;
        if (j.row) j.row.classList.add("err");
        else { const r = document.createElement("div"); r.className = "upload-row err"; r.textContent = "✗ " + j.label; box.appendChild(r); }
      }
      done++;
      progress.update(done, failed);
    }
  }
  await Promise.all(Array.from({ length: Math.min(UPLOAD_CONCURRENCY, rows.length) }, worker));
  progress.finish(done, failed);
  loadFs(currentFolder);
}

// Flat upload: everything into the current folder.
async function uploadFiles(fileList) {
  const files = Array.from(fileList);
  if (!files.length) return;
  await runUploads(files.map((f) => ({ file: f, folderId: currentFolder, label: f.name })));
}

// Recreate the folder hierarchy for {file, path} items under the current folder.
// Returns Map(dirPath -> folderId); "" maps to the current folder.
async function ensureFolders(items) {
  const pathToId = new Map([["", currentFolder]]);
  const dirs = new Set();
  for (const it of items) {
    if (!it.path) continue;
    const parts = it.path.split("/");
    for (let i = 1; i <= parts.length; i++) dirs.add(parts.slice(0, i).join("/"));
  }
  // shallowest first so each folder's parent already exists
  const ordered = [...dirs].sort((a, b) => a.split("/").length - b.split("/").length || a.localeCompare(b));
  for (const dir of ordered) {
    const parts = dir.split("/");
    const name = parts[parts.length - 1];
    const parentId = pathToId.get(parts.slice(0, -1).join("/")) ?? currentFolder;
    const { ok, body } = await api("/api/folders", {
      method: "POST", headers: authHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify({ parentId, encName: await encryptName(name) }),
    });
    pathToId.set(dir, ok && body && body.folder ? body.folder.id : parentId);
  }
  return pathToId;
}

// Upload {file, path} items, preserving the folder tree.
async function uploadItems(items) {
  if (!items.length) { toast("Nothing to upload."); return; }
  const box = $("uploads");
  const prep = document.createElement("div");
  prep.className = "upload-row";
  prep.textContent = `Creating folders for ${items.length} file${items.length === 1 ? "" : "s"}…`;
  box.appendChild(prep);
  const pathToId = await ensureFolders(items);
  prep.remove();
  const jobs = items.map((it) => ({
    file: it.file,
    folderId: pathToId.get(it.path) ?? currentFolder,
    label: (it.path ? it.path + "/" : "") + it.file.name,
  }));
  await runUploads(jobs);
}

// From a <input webkitdirectory> selection: paths come from webkitRelativePath.
function uploadFromDirInput(fileList) {
  const items = Array.from(fileList).map((f) => {
    const rel = f.webkitRelativePath || f.name;
    const parts = rel.split("/"); parts.pop(); // drop the filename
    return { file: f, path: parts.join("/") };
  });
  uploadItems(items);
}

// ---- drag & drop (folder-tree aware) ----
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

// Recursively collect {file, path} from a dropped file/folder entry, where
// `path` is the directory chain (so the tree is recreated on upload).
async function collectEntry(entry, out, prefix = "") {
  if (entry.isFile) {
    try { out.push({ file: await new Promise((res, rej) => entry.file(res, rej)), path: prefix }); } catch { /* skip */ }
  } else if (entry.isDirectory) {
    const entries = await readAllEntries(entry.createReader());
    const sub = prefix ? prefix + "/" + entry.name : entry.name;
    for (const e of entries) await collectEntry(e, out, sub);
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
    // Prefer entries (handles dropped folders + nesting); fall back to flat files.
    const entries = dt.items
      ? Array.from(dt.items).map((it) => it.webkitGetAsEntry && it.webkitGetAsEntry()).filter(Boolean)
      : [];
    if (entries.length) {
      const items = [];
      for (const entry of entries) await collectEntry(entry, items);
      uploadItems(items);
    } else if (dt.files && dt.files.length) {
      uploadFiles(dt.files);
    }
  });
}

// ---- notes ----
let editingNoteId = null;

// ---- sidebar navigation ----
function setActiveNav(nav) {
  ["files", "recent", "starred", "notes"].forEach((n) => {
    const el = $("nav-" + n); if (el) el.classList.toggle("active", n === nav);
  });
}
function showFilesTab() { $("files-tab").classList.remove("hidden"); $("notes-tab").classList.add("hidden"); }

function goNotes() {
  setActiveNav("notes");
  $("files-tab").classList.add("hidden");
  $("notes-tab").classList.remove("hidden");
  showNotesList(); loadNotes();
  closeSidebar();
}

// Recent / Starred views (files-tab, results mode).
async function loadView(kind) {
  setActiveNav(kind);
  showFilesTab();
  closeSidebar();
  const path = kind === "recent" ? "/api/recent" : "/api/starred";
  const { ok, status, body } = await api(path, { headers: authHeaders() });
  if (status === 401) { sessionExpired(); return; }
  if (!ok || !body) { toast("Could not load."); return; }
  resultsMode = true;
  curFolders = body.folders || [];
  curFiles = body.files || [];
  await hydrateNames(curFolders, curFiles);
  renderResultsHeader(kind === "recent" ? "🕓 Recent" : "⭐ Starred");
  renderFs();
  updateHome();
}

// Back-compat shim (used by showApp / helpers).
function switchTab(tab) { tab === "notes" ? goNotes() : loadFs(0); }

// ---- sidebar (mobile drawer) ----
function openSidebar() { $("sidebar").classList.add("open"); $("sidebar-backdrop").classList.remove("hidden"); }
function closeSidebar() { $("sidebar").classList.remove("open"); $("sidebar-backdrop").classList.add("hidden"); }

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
  $("file-input").addEventListener("change", (e) => { uploadFiles(e.target.files); e.target.value = ""; });
  $("folder-input").addEventListener("change", (e) => { uploadFromDirInput(e.target.files); e.target.value = ""; });
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

  // sidebar / nav
  $("menu-btn").addEventListener("click", openSidebar);
  $("sidebar-backdrop").addEventListener("click", closeSidebar);
  $("nav-files").addEventListener("click", () => loadFs(0));
  $("nav-recent").addEventListener("click", () => loadView("recent"));
  $("nav-starred").addEventListener("click", () => loadView("starred"));
  $("nav-notes").addEventListener("click", goNotes);

  // New menu
  $("new-btn").addEventListener("click", openNewMenu);
  $("new-close").addEventListener("click", closeNewMenu);
  $("new-modal").addEventListener("click", (e) => { if (e.target.id === "new-modal") closeNewMenu(); });
  $("new-folder-item").addEventListener("click", () => { closeNewMenu(); newFolder(); });
  $("new-upload-item").addEventListener("click", () => { closeNewMenu(); $("file-input").click(); });
  $("new-uploadfolder-item").addEventListener("click", () => { closeNewMenu(); $("folder-input").click(); });

  $("new-note").addEventListener("click", newNote);
  $("note-back").addEventListener("click", () => { showNotesList(); loadNotes(); });
  $("note-save").addEventListener("click", saveNote);
  $("note-delete").addEventListener("click", deleteCurrentNote);

  // preview modal
  $("preview-close").addEventListener("click", closePreview);
  $("preview-modal").addEventListener("click", (e) => { if (e.target.id === "preview-modal") closePreview(); });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") { closePreview(); closeMove(); closeActions(); closeSort(); closeNewMenu(); } });

  setMode("login");

  // Need both a session token AND the decryption key (per-tab). Reopening the app
  // in a fresh tab clears the key, so you log in again to re-derive it.
  if (token && restoreDEK()) {
    const { ok, body } = await api("/api/auth/me", { headers: authHeaders() });
    if (ok && body && body.user) { showApp(body.user); return; }
    token = ""; localStorage.removeItem(TOKEN_KEY); clearDEK();
  }
  showAuth();
}

boot();

if ("serviceWorker" in navigator) {
  window.addEventListener("load", () => navigator.serviceWorker.register("/sw.js").catch(() => {}));
}

// cloud-serv PWA — vanilla JS, same-origin with the API.
// Security note: every piece of server/user data is inserted via textContent or
// element properties — never innerHTML — so filenames can never inject HTML.

const API = ""; // same origin
// Auth is the HttpOnly session cookie only; no token is kept in JS or localStorage.
try { localStorage.removeItem("cs_token"); } catch { /* ignore */ }
let mode = "login"; // or "register"

const $ = (id) => document.getElementById(id);

// ---- tiny helpers ----
function authHeaders(extra = {}) {
  return extra; // session cookie is sent automatically (same-origin)
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

function extOf(name) { const i = (name || "").lastIndexOf("."); return i > 0 ? name.slice(i + 1).toLowerCase() : ""; }

// Text-ish extensions we can preview as plain text.
const TEXT_EXT = new Set(["txt", "md", "markdown", "log", "json", "csv", "xml", "yml", "yaml",
  "js", "ts", "jsx", "tsx", "py", "c", "cpp", "cc", "h", "hpp", "html", "css", "sh", "ino",
  "kt", "java", "go", "rs", "rb", "php", "sql", "toml", "ini", "conf"]);
const ARCHIVE_EXT = new Set(["zip", "tar", "gz", "tgz", "rar", "7z", "xz", "bz2"]);

// A type icon from mime + filename (mime is often generic, so fall back to ext).
// A short uppercase file-type badge (rendered by .is-type / .file-ic in
// style.css) — no emoji, just text, so it's a plain fixed label like any
// other UI string rather than a pictograph that varies by platform/font.
function iconFor(mime, name) {
  const m = mime || "";
  if (m.startsWith("image/")) return "IMG";
  if (m.startsWith("video/")) return "VID";
  if (m.startsWith("audio/")) return "AUD";
  const e = extOf(name);
  if (m.includes("pdf") || e === "pdf") return "PDF";
  if (m.includes("zip") || m.includes("compressed") || m.includes("tar") || ARCHIVE_EXT.has(e)) return "ZIP";
  if (["doc", "docx", "odt", "rtf"].includes(e)) return "DOC";
  if (["xls", "xlsx", "ods", "csv"].includes(e) || m.includes("spreadsheet")) return "XLS";
  if (["ppt", "pptx", "odp"].includes(e) || m.includes("presentation")) return "PPT";
  if (["js", "ts", "jsx", "tsx", "py", "c", "cpp", "cc", "h", "hpp", "java", "rs", "go", "rb",
       "php", "sh", "html", "css", "xml", "yml", "yaml", "ino", "kt", "swift", "sql"].includes(e) ||
      m.includes("json") || e === "json") return "DEV";
  if (m.startsWith("text/") || TEXT_EXT.has(e)) return "TXT";
  return "FILE";
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
// Per-account "Encrypt my files" switch (server-stored, default off). Only affects NEW
// uploads, folders and renames of plain items; existing encrypted items stay encrypted
// and still open, because every item is decrypted (or not) on its own.
let ENCRYPT_FILES = false;
async function loadPrefs() {
  const { ok, body } = await api("/api/auth/me", { headers: authHeaders() });
  if (ok && body && typeof body.encryptFiles === "boolean") ENCRYPT_FILES = body.encryptFiles;
  const t = $("enc-toggle"); if (t) t.checked = ENCRYPT_FILES;
}
async function setEncryptPref(on) {
  if (on && !confirm("Encrypt new uploads?\n\nEncrypted files can only be opened with your password or recovery key. If you lose both, those files are gone for good, and server backups can't read them.")) {
    $("enc-toggle").checked = false; return;
  }
  const { ok } = await api("/api/auth/me/prefs", {
    method: "PATCH", headers: authHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify({ encryptFiles: !!on }),
  });
  if (!ok) { $("enc-toggle").checked = ENCRYPT_FILES; toast("Couldn't save the setting"); return; }
  ENCRYPT_FILES = !!on;
  toast(on ? "New uploads will be encrypted" : "New uploads will be stored as normal files");
}
// Name payload for a new item or a rename: encrypted only if the switch is on (new items)
// or the item itself is already encrypted (renames keep its form).
async function namePayload(name, item) {
  const enc = item ? !!item.encName : ENCRYPT_FILES;
  return enc ? { encName: await encryptName(name) } : { name };
}

function showApp(user) {
  $("auth-view").classList.add("hidden");
  $("app-view").classList.remove("hidden");
  const label = user ? (user.displayName || user.email) : "";
  $("who").textContent = label;
  const av = $("avatar"); if (av) { av.textContent = initials(label); av.title = label; }
  loadPrefs();
  loadFs(0); // land on Files
}

// ---- auth ----
function setMode(m) {
  mode = m;
  const login = m === "login";
  $("tab-login").classList.toggle("active", login);
  $("tab-register").classList.toggle("active", !login);
  $("name-row").classList.toggle("hidden", login);
  $("invite-row").classList.toggle("hidden", login);
  $("invite-code").required = !login;
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
  const encMime = await encryptName(file.type || "application/octet-stream");
  return { cipher, wrappedKey, plainSize: plain.length, encName, encMime };
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

// ---- E2E thumbnails (lazy, bounded, cached) ----
// The server can't thumbnail encrypted blobs, so the client fetches + decrypts
// each image itself. To keep that affordable we (1) only start when a tile
// scrolls near the viewport, (2) cap concurrency, (3) downscale to a small
// cached data URL so memory stays low and re-renders are instant.
const THUMB_MAX = 256;               // longest edge, px
const THUMB_CONCURRENCY = 4;
const thumbCache = new Map();        // fileId -> small data URL
let thumbQueue = [];
let thumbActive = 0;

function clearThumbCache() { thumbCache.clear(); thumbQueue = []; }

async function makeThumb(item) {
  const bytes = await fetchPlaintext(item);
  // Decode the bytes directly (no <img> blob: URL, so CSP img-src stays strict).
  const bmp = await createImageBitmap(new Blob([bytes], { type: item.mime || "image/*" }));
  try {
    const scale = Math.min(1, THUMB_MAX / Math.max(bmp.width, bmp.height, 1));
    const w = Math.max(1, Math.round(bmp.width * scale));
    const h = Math.max(1, Math.round(bmp.height * scale));
    const canvas = document.createElement("canvas"); canvas.width = w; canvas.height = h;
    canvas.getContext("2d").drawImage(bmp, 0, 0, w, h);
    return canvas.toDataURL("image/jpeg", 0.8); // small data: URL (allowed by CSP)
  } finally {
    bmp.close(); // free the full-size decoded image; keep only the small thumb
  }
}

function pumpThumbs() {
  while (thumbActive < THUMB_CONCURRENCY && thumbQueue.length) {
    const { item, imgEl } = thumbQueue.shift();
    if (!imgEl.isConnected) continue; // tile scrolled away / re-rendered
    thumbActive++;
    makeThumb(item)
      .then((dataUrl) => { thumbCache.set(item.id, dataUrl); if (imgEl.isConnected) imgEl.src = dataUrl; })
      .catch(() => {})
      .finally(() => { thumbActive--; pumpThumbs(); });
  }
}

const thumbObserver = ("IntersectionObserver" in window)
  ? new IntersectionObserver((entries) => {
      for (const e of entries) {
        if (!e.isIntersecting) continue;
        const imgEl = e.target;
        thumbObserver.unobserve(imgEl);
        const item = imgEl._thumbItem;
        if (thumbCache.has(item.id)) { imgEl.src = thumbCache.get(item.id); continue; }
        thumbQueue.push({ item, imgEl });
        pumpThumbs();
      }
    }, { rootMargin: "300px" })
  : null;

// Attach an E2E image tile: use the cache, else lazy-load when it nears view.
function loadThumb(imgEl, item) {
  if (thumbCache.has(item.id)) { imgEl.src = thumbCache.get(item.id); return; }
  imgEl._thumbItem = item;
  if (thumbObserver) thumbObserver.observe(imgEl);
  else { thumbQueue.push({ item, imgEl }); pumpThumbs(); } // no IO: just bound concurrency
}

// ---- E2E name encryption ----
// Display names are encrypted under the DEK (like content keys), so the server
// only ever stores opaque blobs. Empty encName = legacy plaintext (see dispName).
const _nameDec = new TextDecoder();
async function encryptName(name) { return wrapBytes(new TextEncoder().encode(name), await dekKey()); }
async function decryptName(enc) { return _nameDec.decode(await unwrapBytes(enc, await dekKey())); }
// Decrypt encrypted metadata (name, mime) for every item in a listing, before
// it renders: encName -> item._name, encMime -> item.mime (overwriting the
// server's generic placeholder).
async function hydrateNames(...lists) {
  for (const items of lists) {
    if (!Array.isArray(items)) continue;
    for (const it of items) {
      if (!it) continue;
      if (it.encName) {
        try { it._name = await decryptName(it.encName); }
        catch { it._name = "Locked"; }
      }
      if (it.encMime) {
        try { it.mime = await decryptName(it.encMime); }
        catch { /* keep the server placeholder */ }
      }
    }
  }
}
// The name to show: decrypted plaintext for E2E items, else the legacy name.
function dispName(item) {
  if (!item) return "";
  if (item.encName) return item._name != null ? item._name : "Locked";
  return decodeName(item.name);
}

// The Data Encryption Key lives in memory + sessionStorage (per-tab, cleared on close).
let DEK_RAW = null;
function setDEK(raw) { DEK_RAW = raw; try { sessionStorage.setItem("cs_dek", toB64(raw)); } catch {} }
function clearDEK() { DEK_RAW = null; try { sessionStorage.removeItem("cs_dek"); } catch {} clearThumbCache(); }
function restoreDEK() { if (!DEK_RAW) { const s = sessionStorage.getItem("cs_dek"); if (s) DEK_RAW = fromB64(s); } return !!DEK_RAW; }

async function e2eRegister(email, password, displayName, inviteCode) {
  const saltHex = toHex(randBytes(16));
  const { authKeyB64, kek } = await deriveKeys(password, saltHex);
  const dekRaw = randBytes(32);
  const wrappedDek = await wrapBytes(dekRaw, kek);
  const recRaw = randBytes(32);
  const wrappedDekRecovery = await wrapBytes(dekRaw, await importAes(recRaw));
  const { ok, body } = await api("/api/auth/register", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password: authKeyB64, displayName, inviteCode, salt: saltHex, wrappedDek, wrappedDekRecovery }),
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
    r = mode === "login" ? await e2eLogin(email, password) : await e2eRegister(email, password, displayName, $("invite-code").value.trim());
  } catch (err) { r = { ok: false, body: { error: err.message } }; }
  btn.disabled = false; setMode(mode);

  if (!r.ok) { $("auth-error").textContent = prettyError(r.body) || "Something went wrong."; return; }
  $("password").value = "";
  if (mode === "register" && r.recoveryKey) showRecoveryKey(r.recoveryKey, r.user);
  else showApp(r.user);
}

function prettyError(body) {
  // A removed/suspended account gets a full explanation, not a one-liner.
  if (body && body.code === "data_removed") {
    return [body.notice || "Your data has been temporarily removed. To get it back, please appeal.",
            body.reason ? "Reason: " + body.reason : "",
            body.appealContact ? "Appeal: " + body.appealContact : ""].filter(Boolean).join(" ");
  }
  if (body && body.code === "suspended") {
    return "This account has been suspended." + (body.appealContact ? " To appeal: " + body.appealContact : "");
  }
  const e = body && body.error;
  const map = {
    "invalid credentials": "Wrong email or password.",
    "registration is not open": "Registration failed — check the invite code, or registration is closed.",
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
  else openPreview(item); // handles media/pdf/text inline, else a download card
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
    el.textContent = `${fmtSize(body.used || 0)} used · ${body.files || 0} file${body.files === 1 ? "" : "s"}`;
  }
}

const CATEGORY_TITLE = { image: "Images", video: "Videos", audio: "Audio", document: "Documents" };
// Same buckets the server uses (database.cpp searchFiles), but computed client-side
// against the DECRYPTED mime. The server's own category filter only ever sees the
// placeholder mime for E2E files (real mime is encrypted in enc_mime, database.cpp's
// column stores 'application/octet-stream'), so every E2E image/video/audio matched
// its "document" clause instead — nothing was ever actually filtered by real type.
function categoryOf(mime) {
  const m = mime || "";
  if (m.startsWith("image/")) return "image";
  if (m.startsWith("video/")) return "video";
  if (m.startsWith("audio/")) return "audio";
  if (m.startsWith("text/") || m.startsWith("application/")) return "document";
  return "other";
}
async function openCategory(cat) {
  // No category/q param: the server applies no mime filter (E2E's placeholder mime
  // would defeat it anyway) and just returns every file, up to its existing 500 cap.
  const { ok, status, body } = await api("/api/search", { headers: authHeaders() });
  if (status === 401) { sessionExpired(); return; }
  if (!ok || !body) { toast("Could not load."); return; }
  resultsMode = true;
  setActiveNav("files");
  showFilesTab();
  curFolders = [];
  const all = body.files || [];
  await hydrateNames(all);
  curFiles = all.filter((f) => categoryOf(f.mime) === cat);
  renderResultsHeader(CATEGORY_TITLE[cat] || "Results");
  renderFs();
  updateHome();
}

function renderResultsHeader(title) {
  const el = $("breadcrumbs");
  el.textContent = "";
  const home = document.createElement("button");
  home.className = "crumb"; home.type = "button"; home.textContent = "Home";
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
  // Drop observations/queue for the tiles we're about to remove (cache persists).
  if (thumbObserver) thumbObserver.disconnect();
  thumbQueue = [];
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
  const v = $("view-toggle"); if (v) v.textContent = viewMode === "grid" ? "List view" : "Grid view";
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
    thumb.classList.add("is-folder"); thumb.textContent = "DIR";
  } else if ((item.mime || "").startsWith("image/")) {
    const img = document.createElement("img");
    img.loading = "lazy"; img.alt = "";
    if (item.wrappedKey) {
      loadThumb(img, item); // E2E: lazy decrypt + downscale + cache
    } else {
      img.src = API + "/api/files/" + item.id + "/content"; // legacy plaintext
    }
    thumb.appendChild(img);
  } else {
    thumb.classList.add("is-type"); thumb.textContent = iconFor(item.mime, dispName(item));
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
  home.className = "crumb"; home.type = "button"; home.textContent = "Home";
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

function folderRow(f) { return listRow("folder", f, "DIR", dispName(f), fmtDate(f.createdAt), "—"); }
function fileRow(f) {
  return listRow("file", f, iconFor(f.mime, dispName(f)), dispName(f), fmtDate(f.createdAt), fmtSize(f.size));
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
    add("Open", () => openPreview(item));
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
    body: JSON.stringify({ parentId: currentFolder, ...(await namePayload(name.trim())) }),
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
    body: JSON.stringify(await namePayload(name.trim(), f)),
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
    body: JSON.stringify(await namePayload(name.trim(), f)),
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
    const ic = document.createElement("div"); ic.className = "file-ic"; ic.textContent = "DIR";
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
// What kind of inline preview a file supports (mime is often generic, so also
// look at the extension).
function previewKind(mime, name) {
  const m = mime || "", e = extOf(name);
  if (m.startsWith("image/")) return "image";
  if (m.startsWith("video/")) return "video";
  if (m.startsWith("audio/")) return "audio";
  if (m.includes("pdf") || e === "pdf") return "pdf";
  if (m.startsWith("text/") || TEXT_EXT.has(e)) return "text";
  return "other"; // no inline preview — show a download card
}

let previewObjectUrl = null; // revoked when the preview closes

function previewCaption(name) {
  const cap = document.createElement("div");
  cap.className = "preview-cap";
  cap.textContent = name; // textContent — safe
  return cap;
}

// Info card for types we can't render inline: big icon, name, size, Download.
function previewCard(file, name) {
  const card = document.createElement("div"); card.className = "preview-card";
  const ic = document.createElement("div"); ic.className = "preview-card-icon"; ic.textContent = iconFor(file.mime, name);
  const nm = document.createElement("div"); nm.className = "preview-card-name"; nm.textContent = name;
  const meta = document.createElement("div"); meta.className = "preview-card-meta";
  meta.textContent = "No preview available · " + fmtSize(file.size || 0);
  const btn = document.createElement("button"); btn.className = "btn primary preview-card-btn";
  btn.textContent = "Download";
  btn.onclick = () => downloadFile(file);
  card.append(ic, nm, meta, btn);
  return card;
}

async function openPreview(file) {
  const modal = $("preview-modal");
  const c = $("preview-content");
  const name = dispName(file);
  const kind = previewKind(file.mime, name);

  c.textContent = "Loading…";
  modal.classList.remove("hidden");

  // Non-renderable types: no fetch, just the download card.
  if (kind === "other") { c.textContent = ""; c.append(previewCard(file, name)); return; }

  // Everything else needs the decrypted bytes (download-then-view).
  let bytes;
  try { bytes = await fetchPlaintext(file); }
  catch { c.textContent = "Preview failed."; return; }
  if (modal.classList.contains("hidden")) return; // closed while loading

  if (kind === "text") {
    const text = new TextDecoder().decode(bytes.subarray(0, 512 * 1024)); // cap huge files
    const pre = document.createElement("pre"); pre.className = "preview-text"; pre.textContent = text;
    c.textContent = ""; c.append(pre, previewCaption(name));
    return;
  }

  const url = URL.createObjectURL(new Blob([bytes], { type: file.mime || "application/octet-stream" }));
  if (previewObjectUrl) URL.revokeObjectURL(previewObjectUrl);
  previewObjectUrl = url;
  let el;
  if (kind === "image") { el = document.createElement("img"); el.className = "preview-media"; el.src = url; }
  else if (kind === "video") { el = document.createElement("video"); el.className = "preview-media"; el.controls = true; el.autoplay = true; el.playsInline = true; el.src = url; }
  else if (kind === "audio") { el = document.createElement("audio"); el.className = "preview-media"; el.controls = true; el.autoplay = true; el.src = url; }
  else if (kind === "pdf") { el = document.createElement("iframe"); el.className = "preview-pdf"; el.src = url; }
  c.textContent = ""; c.append(el, previewCaption(name));
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
function sessionExpired() { clearDEK(); showAuth(); }

// Dispatch: small files go in one request, big files stream in chunks.
async function uploadOne(file, state, folderId) {
  return file.size > CHUNK_THRESHOLD ? uploadChunked(file, state, folderId) : uploadDirect(file, state, folderId);
}

// Small file: encrypt client-side, then single POST, retrying with backoff if
// rate-limited (429).
async function uploadDirect(file, state, folderId) {
  let enc;
  if (ENCRYPT_FILES) {
    try { enc = await encryptFileForUpload(file); }
    catch { state.textContent = "Encryption failed"; return false; }
  }

  for (let attempt = 1; attempt <= UPLOAD_MAX_ATTEMPTS; attempt++) {
    let res;
    try {
      res = await fetch(API + "/api/files", {
        method: "POST",
        headers: authHeaders(enc ? {
          "X-Enc-Name": enc.encName, // encrypted filename (opaque to the server)
          "X-Enc-Mime": enc.encMime, // encrypted mime type (opaque to the server)
          "X-Folder": String(folderId),
          "X-Wrapped-Key": enc.wrappedKey,
          "X-Plain-Size": String(enc.plainSize),
          "Content-Type": "application/octet-stream",
        } : {
          "X-Filename": encodeURIComponent(file.name), // plain file: real name + type, stored as-is
          "X-Folder": String(folderId),
          "Content-Type": file.type || "application/octet-stream",
        }),
        body: enc ? enc.cipher : file,
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
  let enc = null, cipher = null, total;
  if (ENCRYPT_FILES) {
    state.textContent = "Encrypting…";
    try { enc = await encryptFileForUpload(file); }
    catch { state.textContent = "Encryption failed"; return false; }
    cipher = enc.cipher; total = cipher.length;
  } else {
    total = file.size; // plain file: chunks are read straight from disk, never all in memory
  }

  state.textContent = "Starting…";
  let initRes;
  try {
    initRes = await fetch(API + "/api/uploads/init", {
      method: "POST",
      headers: authHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify(enc ? {
        encName: enc.encName, encMime: enc.encMime,
        size: total, folderId,
        wrappedKey: enc.wrappedKey, plainSize: enc.plainSize,
      } : {
        name: file.name, mime: file.type || "application/octet-stream", size: total, folderId,
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
    const chunk = enc ? cipher.subarray(offset, Math.min(offset + CHUNK_SIZE, total))
                      : file.slice(offset, Math.min(offset + CHUNK_SIZE, total));
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
        : `Uploaded ${done} file${done === 1 ? "" : "s"}`;
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
      if (ok) { if (j.row) { j.state.textContent = "Done"; setTimeout(() => j.row.remove(), 1500); } }
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
      body: JSON.stringify({ parentId, ...(await namePayload(name)) }),
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
  renderResultsHeader(kind === "recent" ? "Recent" : "Starred");
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

// Notes are end-to-end encrypted like file names: encTitle/encBody hold "iv.ct"
// ciphertext under the DEK and the server keeps the plaintext columns blank. A
// note with no encTitle is a legacy plaintext note (migrated below).
async function hydrateNote(n) {
  if (n.encTitle) {
    try { n._title = await decryptName(n.encTitle); } catch { n._title = "Locked"; n._locked = true; }
  } else {
    n._title = n.title || "";
  }
  if (n.encBody) {
    try { n._body = await decryptName(n.encBody); } catch { n._body = ""; n._locked = true; }
  } else if (n.body !== undefined) {
    n._body = n.body || "";
  }
}

let notesMigrating = false;
// One-time, silent: re-encrypt any plaintext notes left over from before notes
// were encrypted. Oldest first and with preserveUpdatedAt so the list order and
// "Edited" times don't change. A failure leaves that note as-is for next time.
async function migrateLegacyNotes(notes) {
  if (notesMigrating) return;
  const legacy = notes.filter((n) => !n.encTitle).reverse();
  if (!legacy.length) return;
  notesMigrating = true;
  try {
    for (const n of legacy) {
      const full = await api("/api/notes/" + n.id, { headers: authHeaders() });
      if (!full.ok || !full.body || !full.body.note || full.body.note.encTitle) continue;
      const note = full.body.note;
      const payload = JSON.stringify({
        encTitle: await encryptName(note.title || ""),
        encBody: await encryptName(note.body || ""),
        preserveUpdatedAt: true,
      });
      await api("/api/notes/" + n.id, {
        method: "PUT", headers: authHeaders({ "Content-Type": "application/json" }), body: payload,
      });
    }
  } catch { /* leave the rest for the next load */ }
  finally { notesMigrating = false; }
}

async function loadNotes() {
  const { ok, status, body } = await api("/api/notes", { headers: authHeaders() });
  if (status === 401) { showAuth(); return; }
  if (!ok || !body) { toast("Could not load notes."); return; }
  const list = $("note-list");
  list.textContent = "";
  const notes = body.notes || [];
  for (const n of notes) await hydrateNote(n);
  $("notes-empty").classList.toggle("hidden", notes.length > 0);
  for (const n of notes) list.appendChild(noteCard(n));
  migrateLegacyNotes(notes);   // background; doesn't block rendering
}

function noteCard(n) {
  const li = document.createElement("li");
  li.className = "note-card";
  const t = document.createElement("div");
  t.className = "note-t";
  t.textContent = n._title && n._title.trim() ? n._title : "Untitled"; // textContent — safe
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
  await hydrateNote(body.note);
  // Never open a note we couldn't decrypt: saving it would overwrite the real
  // ciphertext with an empty one.
  if (body.note._locked) { toast("This note can't be decrypted with your current key."); return; }
  editingNoteId = body.note.id;
  $("note-title").value = body.note._title || ""; // .value — safe, never parsed as HTML
  $("note-body").value = body.note._body || "";
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
  let payload;
  try {
    payload = JSON.stringify({
      encTitle: await encryptName($("note-title").value),
      encBody: await encryptName($("note-body").value),
    });
  } catch { $("note-status").textContent = "Save failed: encryption key unavailable"; return; }
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
  $("note-status").textContent = "Saved";
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
  $("enc-toggle").addEventListener("change", (e) => setEncryptPref(e.target.checked));
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

  // Need both a valid session cookie AND the decryption key (per-tab). Reopening the app
  // in a fresh tab clears the key, so you log in again to re-derive it.
  if (restoreDEK()) {
    const { ok, body } = await api("/api/auth/me", { headers: authHeaders() });
    if (ok && body && body.user) { showApp(body.user); return; }
    clearDEK();
  }
  showAuth();
}

boot();

if ("serviceWorker" in navigator) {
  window.addEventListener("load", () => navigator.serviceWorker.register("/sw.js").catch(() => {}));
}

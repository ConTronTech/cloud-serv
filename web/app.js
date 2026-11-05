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
  if (on && !DEK_RAW) { $("enc-toggle").checked = false; toast("Unlock encryption on this device first (banner at the top)"); return; }
  if (on && !confirm("Encrypt new uploads?\n\nEncrypted files can only be opened on your trusted devices, or with your password or recovery key. Lose all of those and the files are gone for good, and server backups can't read them.")) {
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
  refreshMe().then(async () => {
    if (DEK_RAW && trustThisBrowser()) { try { await enrollThisDevice(uidNow()); } catch {} }
    checkPendingDevices();
  });
  if (!pendingPoll) pendingPoll = setInterval(checkPendingDevices, 30000);
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
  stopApprovalPoll(); if (pendingPoll) { clearInterval(pendingPoll); pendingPoll = null; }
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
  li.addEventListener("contextmenu", (e) => itemContextMenu(e, kind, item));
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
  li.addEventListener("contextmenu", (e) => itemContextMenu(e, kind, item));
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
// One list of actions per item, used by both the ••• sheet and the right-click menu.
function itemActions(kind, item) {
  if (kind === "folder") return [
    { label: "Open", fn: () => loadFs(item.id) },
    { label: item.starred ? "★ Unstar" : "☆ Star", fn: () => toggleStar("folder", item) },
    { label: "Rename", fn: () => renameFolder(item) },
    { label: "Move", fn: () => openMove("folder", item) },
    "-",
    { label: "Delete", fn: () => deleteFolder(item), danger: true },
  ];
  return [
    { label: "Open", fn: () => openPreview(item) },
    { label: "Download", fn: () => downloadFile(item) },
    { label: item.starred ? "★ Unstar" : "☆ Star", fn: () => toggleStar("file", item) },
    { label: "Rename", fn: () => renameFileItem(item) },
    { label: "Move", fn: () => openMove("file", item) },
    "-",
    { label: "Delete", fn: () => deleteFile(item), danger: true },
  ];
}

function openActions(kind, item) {
  const list = $("action-list");
  list.textContent = "";
  $("action-title").textContent = dispName(item);
  for (const a of itemActions(kind, item)) {
    if (a === "-") continue;
    const b = document.createElement("button");
    b.className = "action-item" + (a.danger ? " danger" : "");
    b.type = "button"; b.textContent = a.label;
    b.addEventListener("click", () => { closeActions(); a.fn(); });
    list.appendChild(b);
  }
  $("action-modal").classList.remove("hidden");
}

function selCount() { return selFolders.size + selFiles.size; }

// ---- right-click (context) menu ----
let ctxEl = null;
function closeCtx() { if (ctxEl) { ctxEl.remove(); ctxEl = null; } }
function openCtx(e, actions, title) {
  e.preventDefault(); e.stopPropagation();
  closeCtx();
  const m = document.createElement("div");
  m.className = "ctx-menu"; m.setAttribute("role", "menu");
  if (title) { const t = document.createElement("div"); t.className = "ctx-title"; t.textContent = title; m.appendChild(t); }
  for (const a of actions) {
    if (a === "-") { const hr = document.createElement("div"); hr.className = "ctx-sep"; m.appendChild(hr); continue; }
    const b = document.createElement("button");
    b.type = "button"; b.className = "ctx-item" + (a.danger ? " danger" : ""); b.setAttribute("role", "menuitem");
    b.textContent = a.label;
    b.addEventListener("click", (ev) => { ev.stopPropagation(); closeCtx(); a.fn(); });
    m.appendChild(b);
  }
  document.body.appendChild(m);
  const r = m.getBoundingClientRect();
  m.style.left = Math.max(6, Math.min(e.clientX, window.innerWidth - r.width - 6)) + "px";
  m.style.top = Math.max(6, Math.min(e.clientY, window.innerHeight - r.height - 6)) + "px";
  ctxEl = m;
  const first = m.querySelector(".ctx-item"); if (first) first.focus({ preventScroll: true });
}
// Right-click on an item. If it is part of a multi-selection, act on the whole selection.
function itemContextMenu(e, kind, item) {
  if (selectMode && isSelected(kind, item.id) && selCount() > 1) {
    openCtx(e, [
      { label: `Move ${selCount()} items`, fn: () => $("sel-move").click() },
      "-",
      { label: `Delete ${selCount()} items`, fn: () => $("sel-delete").click(), danger: true },
    ], `${selCount()} selected`);
    return;
  }
  openCtx(e, itemActions(kind, item), dispName(item));
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
  refreshCurrentView();
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

// Media opens in a card: header (name, size, position, prev/next, download, close) and a
// bounded media area, so it never takes over the whole screen. Plain (unencrypted) video,
// audio and images stream straight from the server with seeking; encrypted ones are
// decrypted in the browser first.
let previewList = [], previewIndex = -1;
function previewable(f) { return previewKind(f.mime, dispName(f)) !== "other"; }

async function openPreview(file) {
  previewList = sortItems(curFiles, true).filter(previewable);
  previewIndex = previewList.findIndex((f) => f.id === file.id);
  if (previewIndex < 0) { previewList = [file]; previewIndex = 0; }
  await renderPreview(previewList[previewIndex]);
}

function previewStep(d) {
  if (previewList.length < 2 || $("preview-modal").classList.contains("hidden")) return;
  previewIndex = (previewIndex + d + previewList.length) % previewList.length;
  renderPreview(previewList[previewIndex]);
}

function pvButton(label, title, fn, cls) {
  const b = document.createElement("button");
  b.type = "button"; b.className = "pv-btn" + (cls ? " " + cls : ""); b.textContent = label; b.title = title;
  b.setAttribute("aria-label", title); b.addEventListener("click", fn);
  return b;
}

async function renderPreview(file) {
  const modal = $("preview-modal");
  const c = $("preview-content");
  const name = dispName(file);
  const kind = previewKind(file.mime, name);
  if (previewObjectUrl) { URL.revokeObjectURL(previewObjectUrl); previewObjectUrl = null; }

  const card = document.createElement("div"); card.className = "pv-card pv-" + kind;
  const head = document.createElement("div"); head.className = "pv-head";
  const titles = document.createElement("div"); titles.className = "pv-titles";
  const t = document.createElement("div"); t.className = "pv-title"; t.textContent = name; t.title = name;
  const meta = document.createElement("div"); meta.className = "pv-meta";
  meta.textContent = fmtSize(file.size || 0) + (previewList.length > 1 ? `  ·  ${previewIndex + 1} of ${previewList.length}` : "") +
                     (file.wrappedKey ? "  ·  encrypted" : "");
  titles.append(t, meta);
  const actions = document.createElement("div"); actions.className = "pv-actions";
  if (previewList.length > 1) actions.append(pvButton("‹", "Previous (←)", () => previewStep(-1)), pvButton("›", "Next (→)", () => previewStep(1)));
  actions.append(pvButton("⤓", "Download", () => downloadFile(file)), pvButton("✕", "Close (Esc)", closePreview, "pv-close"));
  head.append(titles, actions);
  const body = document.createElement("div"); body.className = "pv-body"; body.textContent = "Loading…";
  card.append(head, body);
  c.textContent = ""; c.append(card);
  modal.classList.remove("hidden");

  if (kind === "other") { body.textContent = ""; body.append(previewCard(file, name)); return; }

  let src;
  const streamable = !file.wrappedKey && (kind === "video" || kind === "audio" || kind === "image");
  if (streamable) {
    src = API + "/api/files/" + file.id + "/content"; // session cookie authenticates; Range for seeking
  } else {
    let bytes;
    try { bytes = await fetchPlaintext(file); }
    catch { body.textContent = "Preview failed."; return; }
    if (modal.classList.contains("hidden") || previewList[previewIndex] !== file) return; // closed or moved on
    if (kind === "text") {
      const pre = document.createElement("pre"); pre.className = "preview-text";
      pre.textContent = new TextDecoder().decode(bytes.subarray(0, 512 * 1024)); // cap huge files
      body.textContent = ""; body.append(pre); return;
    }
    src = URL.createObjectURL(new Blob([bytes], { type: file.mime || "application/octet-stream" }));
    previewObjectUrl = src;
  }
  let el;
  if (kind === "image") { el = document.createElement("img"); el.className = "pv-media"; el.alt = name; el.src = src; }
  else if (kind === "video") { el = document.createElement("video"); el.className = "pv-media"; el.controls = true; el.autoplay = true; el.playsInline = true; el.preload = "metadata"; el.src = src; }
  else if (kind === "audio") {
    el = document.createElement("div"); el.className = "pv-audio";
    const ic = document.createElement("div"); ic.className = "pv-audio-icon"; ic.textContent = "♪";
    const au = document.createElement("audio"); au.controls = true; au.autoplay = true; au.src = src;
    el.append(ic, au);
  }
  else if (kind === "pdf") { el = document.createElement("iframe"); el.className = "pv-pdf"; el.title = name; el.src = src; }
  body.textContent = ""; body.append(el);
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
  if (ENCRYPT_FILES && !DEK_RAW) { state.textContent = "Locked: unlock this device to upload encrypted"; return false; }
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
  if (ENCRYPT_FILES && !DEK_RAW) { state.textContent = "Locked: unlock this device to upload encrypted"; return false; }
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
  ["files", "recent", "starred", "notes", "settings"].forEach((n) => {
    const el = $("nav-" + n); if (el) el.classList.toggle("active", n === nav);
  });
}
function showFilesTab() { $("files-tab").classList.remove("hidden"); $("notes-tab").classList.add("hidden"); $("settings-tab").classList.add("hidden"); }

function goNotes() {
  setActiveNav("notes");
  $("files-tab").classList.add("hidden");
  $("settings-tab").classList.add("hidden");
  $("notes-tab").classList.remove("hidden");
  showNotesList(); loadNotes();
  closeSidebar();
}

// ---- Sign in with authentik (SSO) + "locked" mode ----
// A session can exist without the encryption key on this device (SSO login, or a new tab).
// Plain files work normally; encrypted items stay locked until the key is unlocked here.
let SSO = { enabled: false, label: "SSO" };
const SSO_ERRORS = {
  "not-allowed": "Your account isn't allowed to use cloud-serv. Ask the owner to add you to the right group.",
  "email-in-use": "An account with that email already exists. Log in with your password, then link it under Settings > Sign-in methods.",
  "linked-elsewhere": "That identity is already linked to a different account.",
  "expired": "The sign-in took too long or was already used. Please try again.",
  "cancelled": "Sign-in was cancelled.",
  "idp-unreachable": "Couldn't reach the sign-in provider. Try again shortly.",
  "not-signed-in": "Log in first, then link the account from Settings.",
  "no-email": "The sign-in provider didn't share an email address.",
  "account-suspended": "This account is suspended.",
};
async function loadSsoConfig() {
  const { ok, body } = await api("/api/auth/oidc/config");
  if (ok && body) SSO = { enabled: !!body.enabled, label: body.label || "SSO" };
  $("sso-row").classList.toggle("hidden", !SSO.enabled);
  $("sso-btn-label").textContent = "Sign in with " + SSO.label;
}
function hashParam() { return decodeURIComponent((location.hash || "").replace(/^#/, "")); }
function clearHash() { history.replaceState(null, "", location.pathname + location.search); }

// ======================= Trusted devices =======================
// Each browser makes its own ECDH P-256 key pair. The private key is created
// non-extractable and kept in this browser's IndexedDB, so it never leaves the device.
// The server stores the DEK sealed to each approved device: ECDH(ephemeral, device) ->
// HKDF-SHA256 -> AES-GCM. A trusted device unlocks with no password at all.
const DEV_DB = "cloud-serv-device", DEV_STORE = "kv", SEAL_AAD = te.encode("cloud-serv-device-v1");
function idbOpen() {
  return new Promise((res, rej) => {
    const r = indexedDB.open(DEV_DB, 1);
    r.onupgradeneeded = () => r.result.createObjectStore(DEV_STORE);
    r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error);
  });
}
async function idbDo(mode, fn) {
  const db = await idbOpen();
  return new Promise((res, rej) => {
    const st = db.transaction(DEV_STORE, mode).objectStore(DEV_STORE);
    const req = fn(st); req.onsuccess = () => res(req.result); req.onerror = () => rej(req.error);
  });
}
const devKey = (uid) => "dev:" + uid;
async function devGet(uid) { try { return await idbDo("readonly", (s) => s.get(devKey(uid))); } catch { return null; } }
async function devPut(uid, v) { return idbDo("readwrite", (s) => s.put(v, devKey(uid))); }
async function devForget(uid) { try { await idbDo("readwrite", (s) => s.delete(devKey(uid))); } catch {} }

async function deviceRecord(uid) {
  let rec = await devGet(uid);
  if (rec && rec.priv && rec.pubB64) return rec;
  const kp = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
  rec = { priv: kp.privateKey, pubB64: toB64(await crypto.subtle.exportKey("spki", kp.publicKey)), deviceId: null };
  await devPut(uid, rec);
  return rec;
}
async function sealKey(bits, salt) {
  const base = await crypto.subtle.importKey("raw", bits, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt, info: te.encode("cloud-serv device wrap v1") },
    base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}
async function sealForDevice(pubB64, dek) {
  const pub = await crypto.subtle.importKey("spki", fromB64(pubB64), { name: "ECDH", namedCurve: "P-256" }, false, []);
  const eph = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "ECDH", public: pub }, eph.privateKey, 256);
  const epk = new Uint8Array(await crypto.subtle.exportKey("spki", eph.publicKey));
  const iv = randBytes(12);
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: SEAL_AAD }, await sealKey(bits, epk), dek);
  return "v1." + toB64(epk) + "." + toB64(iv) + "." + toB64(ct);
}
async function openSealed(blob, priv) {
  const [v, e, iv, ct] = String(blob).split(".");
  if (v !== "v1" || !e || !iv || !ct) throw new Error("bad sealed key");
  const epkRaw = fromB64(e);
  const epk = await crypto.subtle.importKey("spki", epkRaw, { name: "ECDH", namedCurve: "P-256" }, false, []);
  const bits = await crypto.subtle.deriveBits({ name: "ECDH", public: epk }, priv, 256);
  return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: fromB64(iv), additionalData: SEAL_AAD },
    await sealKey(bits, epkRaw), fromB64(ct)));
}
// 6-digit code both screens show, so an approval can't be swapped for someone else's device.
async function deviceCode(pubB64) {
  const h = new Uint8Array(await crypto.subtle.digest("SHA-256", fromB64(pubB64)));
  const n = ((h[0] << 24) >>> 0) + (h[1] << 16) + (h[2] << 8) + h[3];
  const s = String(n % 1000000).padStart(6, "0");
  return s.slice(0, 3) + " " + s.slice(3);
}
function deviceName() {
  const ua = navigator.userAgent;
  const br = /Edg\//.test(ua) ? "Edge" : /OPR\//.test(ua) ? "Opera" : /Firefox\//.test(ua) ? "Firefox" : /Chrome\//.test(ua) ? "Chrome" : /Safari\//.test(ua) ? "Safari" : "Browser";
  const os = /Android/.test(ua) ? "Android" : /iPhone|iPad/.test(ua) ? "iOS" : /Windows/.test(ua) ? "Windows" : /Mac OS/.test(ua) ? "macOS" : /Linux/.test(ua) ? "Linux" : "device";
  return br + " on " + os;
}
function trustThisBrowser() { try { return localStorage.getItem("cs_trust") !== "0"; } catch { return true; } }

// Try to unlock with this device's own key. -> "ok" | "pending" | "none"
async function tryDeviceUnlock(uid) {
  const rec = await devGet(uid);
  if (!rec || !rec.deviceId || !rec.priv) return "none";
  const { ok, status, body } = await api("/api/devices/" + rec.deviceId + "/key", { headers: authHeaders() });
  if (status === 404) { rec.deviceId = null; await devPut(uid, rec); return "none"; }   // revoked
  if (!ok || !body) return "none";
  if (body.status !== "approved") return "pending";
  try { setDEK(await openSealed(body.wrappedDek, rec.priv)); return "ok"; }
  catch { return "none"; }
}
// Register this browser as trusted (needs the key unlocked here).
async function enrollThisDevice(uid) {
  if (!DEK_RAW || !uid) return false;
  const rec = await deviceRecord(uid);
  if (rec.deviceId) {
    const r = await api("/api/devices/" + rec.deviceId + "/key", { headers: authHeaders() });
    if (r.ok && r.body && r.body.status === "approved") return true;
    if (r.ok && r.body && r.body.status === "pending") {   // finish our own pending request
      const a = await api("/api/devices/" + rec.deviceId + "/approve", { method: "POST",
        headers: authHeaders({ "Content-Type": "application/json" }), body: JSON.stringify({ wrappedDek: await sealForDevice(rec.pubB64, DEK_RAW) }) });
      return a.ok;
    }
  }
  const { ok, body } = await api("/api/devices", { method: "POST", headers: authHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify({ name: deviceName(), publicKey: rec.pubB64, wrappedDek: await sealForDevice(rec.pubB64, DEK_RAW) }) });
  if (!ok || !body || !body.device) return false;
  rec.deviceId = body.device.id; await devPut(uid, rec);
  return true;
}

// ---- lock banner: every way to unlock this device ----
let LOCK_STATE = "unlocked";   // unlocked | locked | pending | nokeys
let approvalPoll = null;
function uidNow() { return ME && ME.user ? ME.user.id : null; }
function lockButton(label, fn, primary) {
  const b = document.createElement("button"); b.type = "button";
  b.className = "btn small " + (primary ? "primary" : "ghost"); b.textContent = label; b.addEventListener("click", fn);
  return b;
}
async function updateLockBanner() {
  const b = $("lock-banner"); if (!b) return;
  const hasPw = !!(ME && ME.wrappedDek), hasRec = !!(ME && ME.wrappedDekRecovery);
  if (DEK_RAW) LOCK_STATE = "unlocked";
  else if (!hasPw && !hasRec) LOCK_STATE = "nokeys";
  else if (LOCK_STATE !== "pending") LOCK_STATE = "locked";
  b.classList.toggle("hidden", LOCK_STATE === "unlocked");
  const acts = $("lock-actions"); acts.textContent = "";
  $("lock-form").classList.add("hidden");
  if (LOCK_STATE === "nokeys") {
    $("lock-text").textContent = "Encryption isn't set up on this account yet. Plain files work normally; notes and encrypted uploads need it.";
    acts.append(lockButton("Set up encryption", setupEncryption, true));
  } else if (LOCK_STATE === "pending") {
    const rec = await devGet(uidNow());
    const code = rec ? await deviceCode(rec.pubB64) : "";
    $("lock-text").textContent = `Waiting for approval. On a device that's already signed in, open Settings → Devices and approve code ${code}.`;
    acts.append(lockButton("Use something else", () => { LOCK_STATE = "locked"; stopApprovalPoll(); updateLockBanner(); }));
  } else if (LOCK_STATE === "locked") {
    $("lock-text").textContent = "Notes and encrypted files are locked on this device.";
    acts.append(lockButton("Approve from another device", requestApproval, true));
    if (hasPw) acts.append(lockButton("Use password", () => showLockForm("password")));
    if (hasRec) acts.append(lockButton("Use recovery key", () => showLockForm("recovery")));
  }
}
function showLockForm(mode) {
  const f = $("lock-form"); f.dataset.mode = mode; f.classList.remove("hidden");
  const i = $("lock-pw"); i.value = "";
  i.type = mode === "password" ? "password" : "text";
  i.placeholder = mode === "password" ? "Your password" : "csr_… recovery key";
  i.autocomplete = mode === "password" ? "current-password" : "off";
  i.focus();
}
async function afterUnlock(msg) {
  clearThumbCache(); stopApprovalPoll();
  if (trustThisBrowser()) { try { await enrollThisDevice(uidNow()); } catch {} }
  LOCK_STATE = "unlocked"; updateLockBanner(); toast(msg);
  refreshCurrentView(); checkPendingDevices();
}
async function unlockWithPassword(e) {
  e.preventDefault();
  const mode = $("lock-form").dataset.mode || "password";
  const val = $("lock-pw").value.trim();
  const me = ME || (await api("/api/auth/me", { headers: authHeaders() })).body;
  try {
    if (mode === "recovery") {
      if (!val.startsWith("csr_") || !me.wrappedDekRecovery) throw new Error("bad");
      setDEK(await unwrapBytes(me.wrappedDekRecovery, await importAes(fromB64(val.slice(4)))));
    } else {
      const { kek } = await deriveKeys($("lock-pw").value, me.salt);
      setDEK(await unwrapBytes(me.wrappedDek, kek));
    }
  } catch { toast(mode === "recovery" ? "That recovery key didn't work" : "That password didn't unlock it"); return; }
  $("lock-pw").value = "";
  afterUnlock("Unlocked" + (trustThisBrowser() ? " · this device is now trusted" : ""));
}
async function requestApproval() {
  const uid = uidNow(); if (!uid) return;
  const rec = await deviceRecord(uid);
  let fresh = !rec.deviceId;
  if (rec.deviceId) {
    const r = await api("/api/devices/" + rec.deviceId + "/key", { headers: authHeaders() });
    if (!r.ok) fresh = true;
  }
  if (fresh) {
    const { ok, body } = await api("/api/devices", { method: "POST", headers: authHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify({ name: deviceName(), publicKey: rec.pubB64 }) });
    if (!ok || !body || !body.device) { toast(prettyError(body) || "Couldn't send the request"); return; }
    rec.deviceId = body.device.id; await devPut(uid, rec);
  }
  LOCK_STATE = "pending"; updateLockBanner();
  stopApprovalPoll();
  approvalPoll = setInterval(async () => {
    const s = await tryDeviceUnlock(uid);
    if (s === "ok") afterUnlock("Approved · unlocked on this device");
    else if (s === "none") { stopApprovalPoll(); LOCK_STATE = "locked"; updateLockBanner(); toast("The request was declined"); }
  }, 4000);
}
function stopApprovalPoll() { if (approvalPoll) { clearInterval(approvalPoll); approvalPoll = null; } }

// First-time setup for accounts with no keys (e.g. created through SSO): a new random
// data key + a recovery key, this device trusted, recovery key shown once.
async function setupEncryption() {
  if (!confirm("Set up encryption?\n\nYou'll get a recovery key next. Save it somewhere safe: with no password on this account, it's your only way back in if you lose all your trusted devices.")) return;
  const dek = randBytes(32), recRaw = randBytes(32);
  const wrappedDekRecovery = await wrapBytes(dek, await importAes(recRaw));
  const { ok, body } = await api("/api/keys/init", { method: "POST", headers: authHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify({ wrappedDekRecovery }) });
  if (!ok) { toast(prettyError(body) || "Couldn't set up encryption"); return; }
  setDEK(dek);
  await refreshMe();
  try { await enrollThisDevice(uidNow()); } catch {}
  LOCK_STATE = "unlocked"; updateLockBanner();
  showRecoveryKey("csr_" + toB64(recRaw), ME && ME.user);
}

// Unlocked devices get told when another device is waiting for approval.
let pendingPoll = null;
async function checkPendingDevices() {
  if (!DEK_RAW) { $("review-banner").classList.add("hidden"); return; }
  const { ok, body } = await api("/api/devices", { headers: authHeaders() });
  const n = ok && body ? (body.devices || []).filter((d) => d.status === "pending").length : 0;
  $("review-banner").classList.toggle("hidden", n === 0);
  $("review-text").textContent = n === 1 ? "A new device is asking for access to your encrypted files." : `${n} new devices are asking for access.`;
}

// Settings > Devices
async function loadDevices() {
  const list = $("dev-list"); list.textContent = "";
  const { ok, body } = await api("/api/devices", { headers: authHeaders() });
  if (!ok || !body) return;
  const mine = await devGet(uidNow());
  const devs = body.devices || [];
  $("dev-empty").classList.toggle("hidden", devs.length > 0);
  for (const d of devs) {
    const code = await deviceCode(d.publicKey);
    const li = document.createElement("li"); li.className = "key-row" + (d.status === "pending" ? " dev-pending" : "");
    const info = document.createElement("div"); info.className = "key-info";
    const nm = document.createElement("div"); nm.className = "key-name";
    nm.textContent = d.name + (mine && mine.deviceId === d.id ? "  (this device)" : "");
    const sub = document.createElement("div"); sub.className = "key-sub";
    sub.textContent = (d.status === "pending" ? "Waiting · code " + code : "Trusted") +
      (d.createdAt ? " · added " + fmtDate(d.createdAt) : "") + (d.lastUsedAt ? " · used " + fmtDate(d.lastUsedAt) : "") +
      (d.createdIp ? " · from " + d.createdIp : "");
    info.append(nm, sub);
    li.append(info);
    if (d.status === "pending") {
      const ap = document.createElement("button"); ap.type = "button"; ap.className = "btn primary small"; ap.textContent = "Approve";
      ap.addEventListener("click", async () => {
        if (!DEK_RAW) { toast("Unlock this device first"); return; }
        if (!confirm(`Approve "${d.name}"?\n\nOnly continue if the other device shows this code:\n\n        ${code}\n\nIt will be able to open your notes and encrypted files.`)) return;
        const r = await api("/api/devices/" + d.id + "/approve", { method: "POST", headers: authHeaders({ "Content-Type": "application/json" }),
          body: JSON.stringify({ wrappedDek: await sealForDevice(d.publicKey, DEK_RAW) }) });
        if (!r.ok) { toast(prettyError(r.body) || "Couldn't approve"); return; }
        toast("Approved"); loadDevices(); checkPendingDevices();
      });
      li.append(ap);
    }
    const rm = document.createElement("button"); rm.type = "button"; rm.className = "btn ghost small";
    const isMe = mine && mine.deviceId === d.id;
    rm.textContent = d.status === "pending" ? "Deny" : isMe ? "Forget" : "Revoke";
    rm.addEventListener("click", async () => {
      const q = isMe ? "Forget this device? You'll need to unlock it again next time." :
        d.status === "pending" ? `Deny "${d.name}"?` : `Revoke "${d.name}"? It loses access to encrypted items (anything it already opened stays on it).`;
      if (!confirm(q)) return;
      const r = await api("/api/devices/" + d.id, { method: "DELETE", headers: authHeaders() });
      if (!r.ok) { toast("Couldn't remove it"); return; }
      if (isMe) { await devForget(uidNow()); clearDEK(); LOCK_STATE = "locked"; updateLockBanner(); }
      loadDevices(); checkPendingDevices();
    });
    li.append(rm);
    list.appendChild(li);
  }
}

async function refreshMe() {
  const { ok, body } = await api("/api/auth/me", { headers: authHeaders() });
  if (ok && body) ME = body;
  updateLockBanner();
  return ok ? body : null;
}

// Settings > Sign-in methods
async function loadIdentities() {
  const box = $("ids-list"); box.textContent = "";
  const { ok, body } = await api("/api/auth/identities", { headers: authHeaders() });
  if (!ok || !body) return;
  $("ids-card").classList.toggle("hidden", !body.ssoEnabled && !(body.identities || []).length);
  $("ids-link").textContent = "Link " + (body.label || "SSO");
  $("ids-password").textContent = body.localLogin ? "Email + password: on" : "Email + password: not set (this account signs in with " + (body.label || "SSO") + ")";
  for (const i of body.identities || []) {
    const li = document.createElement("li"); li.className = "key-row";
    const info = document.createElement("div"); info.className = "key-info";
    const nm = document.createElement("div"); nm.className = "key-name"; nm.textContent = i.provider + (i.email ? " · " + i.email : "");
    const sub = document.createElement("div"); sub.className = "key-sub"; sub.textContent = i.createdAt ? "linked " + fmtDate(i.createdAt) : "";
    info.append(nm, sub);
    const rm = document.createElement("button"); rm.type = "button"; rm.className = "btn ghost small"; rm.textContent = "Unlink";
    rm.addEventListener("click", async () => {
      if (!confirm(`Unlink ${i.provider}? You won't be able to sign in with it until you link it again.`)) return;
      const r = await api("/api/auth/identities/" + i.id, { method: "DELETE", headers: authHeaders() });
      if (!r.ok) { toast(prettyError(r.body) || "Couldn't unlink"); return; }
      loadIdentities();
    });
    li.append(info, rm); box.appendChild(li);
  }
}

// ---- Settings ----
let ME = null;
function goSettings() {
  setActiveNav("settings");
  $("files-tab").classList.add("hidden"); $("notes-tab").classList.add("hidden");
  $("settings-tab").classList.remove("hidden");
  closeSidebar();
  loadSettings();
}
function setStatus(id, msg, bad) { const el = $(id); el.textContent = msg || ""; el.classList.toggle("bad", !!bad); }

async function loadSettings() {
  const { ok, body } = await api("/api/auth/me", { headers: authHeaders() });
  if (!ok || !body) { toast("Couldn't load settings"); return; }
  ME = body;
  const u = body.user || {};
  $("set-email").textContent = u.email || "";
  $("set-role").textContent = u.role === "admin" ? "Admin" : "User";
  $("set-name").value = u.displayName || "";
  $("set-storage").textContent = $("storage-chip").textContent || "—";
  if (typeof body.encryptFiles === "boolean") { ENCRYPT_FILES = body.encryptFiles; $("enc-toggle").checked = ENCRYPT_FILES; }
  updateLockBanner();
  loadApiKeys();
  loadIdentities();
  loadDevices();
}

async function saveDisplayName(e) {
  e.preventDefault();
  const name = $("set-name").value.trim();
  if (!name) { setStatus("set-name-status", "Name can't be empty", true); return; }
  const { ok, body } = await api("/api/auth/me/prefs", {
    method: "PATCH", headers: authHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify({ displayName: name }),
  });
  if (!ok) { setStatus("set-name-status", prettyError(body) || "Couldn't save", true); return; }
  setStatus("set-name-status", "Saved");
  $("who").textContent = name;
  const av = $("avatar"); if (av) { av.textContent = initials(name); av.title = name; }
}

// Password change keeps every file and note readable: the data key (DEK) never changes,
// it is only re-wrapped under the new password. The recovery key keeps working too.
async function changePassword(e) {
  e.preventDefault();
  const cur = $("pw-current").value, next = $("pw-new").value, conf = $("pw-confirm").value;
  if (next.length < 8) { setStatus("pw-status", "New password must be at least 8 characters", true); return; }
  if (next !== conf) { setStatus("pw-status", "New passwords don't match", true); return; }
  setStatus("pw-status", "Checking…");
  const me = ME || (await api("/api/auth/me", { headers: authHeaders() })).body;
  if (!me || !me.salt || !me.wrappedDek) { setStatus("pw-status", "Couldn't load your keys", true); return; }
  let oldAuth, dek;
  try {
    const old = await deriveKeys(cur, me.salt);
    oldAuth = old.authKeyB64;
    dek = await unwrapBytes(me.wrappedDek, old.kek);   // proves the current password locally
  } catch { setStatus("pw-status", "Current password is wrong", true); return; }
  setStatus("pw-status", "Re-wrapping your key…");
  const saltHex = toHex(randBytes(16));
  const fresh = await deriveKeys(next, saltHex);
  const wrappedDek = await wrapBytes(dek, fresh.kek);
  const { ok, body } = await api("/api/auth/password", {
    method: "POST", headers: authHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify({ currentPassword: oldAuth, newPassword: fresh.authKeyB64, salt: saltHex, wrappedDek }),
  });
  if (!ok) { setStatus("pw-status", prettyError(body) || "Couldn't change password", true); return; }
  ["pw-current", "pw-new", "pw-confirm"].forEach((id) => { $(id).value = ""; });
  const n = body && body.otherSessionsSignedOut;
  setStatus("pw-status", "Password changed" + (n > 0 ? ` · signed out ${n} other device${n === 1 ? "" : "s"}` : ""));
  ME = null;
}

async function loadApiKeys() {
  const list = $("key-list"); list.textContent = "";
  const { ok, body } = await api("/api/auth/api-keys", { headers: authHeaders() });
  const keys = (ok && body && body.keys) || [];
  $("key-empty").classList.toggle("hidden", keys.length > 0);
  for (const k of keys) {
    const li = document.createElement("li"); li.className = "key-row";
    const info = document.createElement("div"); info.className = "key-info";
    const nm = document.createElement("div"); nm.className = "key-name"; nm.textContent = k.name || "Unnamed key";
    const sub = document.createElement("div"); sub.className = "key-sub";
    sub.textContent = (k.prefix ? k.prefix + "…" : "") + (k.createdAt ? "  ·  created " + fmtDate(k.createdAt) : "") +
                      (k.lastUsedAt ? "  ·  last used " + fmtDate(k.lastUsedAt) : "");
    info.append(nm, sub);
    const rm = document.createElement("button"); rm.type = "button"; rm.className = "btn ghost small"; rm.textContent = "Revoke";
    rm.addEventListener("click", async () => {
      if (!confirm(`Revoke "${k.name || k.prefix}"? Anything using it stops working.`)) return;
      const r = await api("/api/auth/api-keys/" + k.id, { method: "DELETE", headers: authHeaders() });
      if (!r.ok) { toast("Couldn't revoke"); return; }
      loadApiKeys();
    });
    li.append(info, rm); list.appendChild(li);
  }
}

async function createApiKey(e) {
  e.preventDefault();
  const name = $("key-name").value.trim() || "API key";
  const { ok, body } = await api("/api/auth/api-keys", {
    method: "POST", headers: authHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify({ name }),
  });
  if (!ok || !body || !body.key) { toast(prettyError(body) || "Couldn't create key"); return; }
  $("key-name").value = "";
  $("key-new-value").textContent = body.key;
  $("key-new").classList.remove("hidden");
  loadApiKeys();
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
  if (notesMigrating || !DEK_RAW) return;   // needs the key on this device
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
  $("nav-settings").addEventListener("click", goSettings);
  $("set-name-form").addEventListener("submit", saveDisplayName);
  $("pw-form").addEventListener("submit", changePassword);
  $("key-form").addEventListener("submit", createApiKey);
  $("key-copy").addEventListener("click", async () => {
    try { await navigator.clipboard.writeText($("key-new-value").textContent); toast("Copied"); }
    catch { toast("Copy failed: select it and copy manually"); }
  });
  $("key-done").addEventListener("click", () => { $("key-new").classList.add("hidden"); $("key-new-value").textContent = ""; });
  // Right-click on empty space in the file area
  $("files-tab").addEventListener("contextmenu", (e) => {
    if (e.target.closest(".fs-item, .grid-cell, input, textarea")) return;
    openCtx(e, [
      { label: "New folder", fn: () => newFolder() },
      { label: "Upload files", fn: () => $("file-input").click() },
      { label: "Upload folder", fn: () => $("folder-input").click() },
      "-",
      { label: "Refresh", fn: () => refreshCurrentView() },
    ]);
  });
  document.addEventListener("click", closeCtx);
  window.addEventListener("resize", closeCtx);
  document.addEventListener("scroll", closeCtx, true);
  document.addEventListener("keydown", (e) => {
    if ($("preview-modal").classList.contains("hidden")) return;
    if (e.key === "ArrowLeft") previewStep(-1);
    if (e.key === "ArrowRight") previewStep(1);
  });


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
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") { closeCtx(); closePreview(); closeMove(); closeActions(); closeSort(); closeNewMenu(); } });

  setMode("login");

  $("lock-form").addEventListener("submit", unlockWithPassword);
  $("review-btn").addEventListener("click", () => goSettings());
  $("trust-device").checked = trustThisBrowser();
  $("trust-device").addEventListener("change", (e) => { try { localStorage.setItem("cs_trust", e.target.checked ? "1" : "0"); } catch {} });
  $("sso-btn").addEventListener("click", () => { location.href = "/api/auth/oidc/start"; });
  $("ids-link").addEventListener("click", () => { location.href = "/api/auth/oidc/start?mode=link"; });
  await loadSsoConfig();

  // Coming back from the sign-in provider?
  const h = hashParam();
  if (h.startsWith("sso-error=")) {
    clearHash();
    const code = h.slice(10);
    $("auth-error").textContent = SSO_ERRORS[code] || ("Sign-in failed (" + code + ")");
  }
  const cameFromSso = h === "sso" || h === "sso-linked";
  if (cameFromSso) clearHash();

  // A valid session is enough to open the app. The encryption key is per device/tab:
  // without it, plain files work and encrypted items stay locked until unlocked.
  restoreDEK();
  const { ok, body } = await api("/api/auth/me", { headers: authHeaders() });
  if (ok && body && body.user) {
    ME = body;
    if (!DEK_RAW) {
      const s = await tryDeviceUnlock(body.user.id);
      if (s === "pending") { LOCK_STATE = "pending"; setTimeout(() => requestApproval(), 0); }
    }
    showApp(body.user);
    if (h === "sso-linked") { goSettings(); toast(SSO.label + " linked to your account"); }
    return;
  }
  clearDEK();
  showAuth();
}

boot();

if ("serviceWorker" in navigator) {
  window.addEventListener("load", () => navigator.serviceWorker.register("/sw.js").catch(() => {}));
}

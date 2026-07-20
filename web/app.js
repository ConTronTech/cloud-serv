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
  loadFiles();
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
async function loadFiles() {
  const { ok, status, body } = await api("/api/files", { headers: authHeaders() });
  if (status === 401) { token = ""; localStorage.removeItem(TOKEN_KEY); showAuth(); return; }
  if (!ok || !body) { toast("Could not load files."); return; }

  const list = $("file-list");
  list.textContent = "";
  const files = body.files || [];
  $("empty").classList.toggle("hidden", files.length > 0);

  for (const f of files) list.appendChild(fileRow(f));
}

function fileRow(f) {
  const li = document.createElement("li");
  li.className = "file-item";

  const ic = document.createElement("div");
  ic.className = "file-ic";
  ic.textContent = iconFor(f.mime);

  const meta = document.createElement("div");
  meta.className = "file-meta";
  const name = document.createElement("div");
  name.className = "file-name";
  name.textContent = decodeName(f.name); // XSS-safe: textContent
  name.title = decodeName(f.name);
  if (isPreviewable(f.mime)) {
    name.classList.add("clickable");
    name.addEventListener("click", () => openPreview(f));
  }
  const sub = document.createElement("div");
  sub.className = "file-sub";
  sub.textContent = `${fmtSize(f.size)} · ${fmtDate(f.createdAt)}`;
  meta.append(name, sub);

  const actions = document.createElement("div");
  actions.className = "file-actions";

  if (isPreviewable(f.mime)) {
    const pv = document.createElement("button");
    pv.className = "btn ghost small";
    pv.type = "button";
    pv.innerHTML = "▶ <span>Open</span>";
    pv.addEventListener("click", () => openPreview(f));
    actions.append(pv);
  }

  const dl = document.createElement("button");
  dl.className = "btn ghost small";
  dl.type = "button";
  dl.innerHTML = "⬇ <span>Download</span>";
  dl.addEventListener("click", () => downloadFile(f));

  const del = document.createElement("button");
  del.className = "btn ghost small";
  del.type = "button";
  del.innerHTML = "🗑 <span>Delete</span>";
  del.addEventListener("click", () => deleteFile(f));

  actions.append(dl, del);
  li.append(ic, meta, actions);
  return li;
}

async function downloadFile(f) {
  const res = await fetch(API + "/api/files/" + f.id, { headers: authHeaders() });
  if (!res.ok) { toast("Download failed."); return; }
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = decodeName(f.name); // client controls the saved filename
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

async function deleteFile(f) {
  if (!confirm(`Delete "${decodeName(f.name)}"?`)) return;
  const { ok } = await api("/api/files/" + f.id, { method: "DELETE", headers: authHeaders() });
  if (!ok) { toast("Delete failed."); return; }
  toast("Deleted.");
  loadFiles();
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
          "Content-Type": file.type || "application/octet-stream",
        }),
        body: file,
      });
    } catch { state.textContent = "Network error"; return false; }

    if (res.ok) return true;
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
      body: JSON.stringify({ name: file.name, mime: file.type || "application/octet-stream", size: file.size }),
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
  loadFiles();
}

// ---- drag & drop ----
function wireDropzone() {
  const dz = $("dropzone");
  ["dragenter", "dragover"].forEach((ev) =>
    dz.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.add("drag"); }));
  ["dragleave", "drop"].forEach((ev) =>
    dz.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.remove("drag"); }));
  dz.addEventListener("drop", (e) => {
    if (e.dataTransfer && e.dataTransfer.files) uploadFiles(e.dataTransfer.files);
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
  $("refresh").addEventListener("click", loadFiles);
  $("pick").addEventListener("click", () => $("file-input").click());
  $("file-input").addEventListener("change", (e) => uploadFiles(e.target.files));
  wireDropzone();

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
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") closePreview(); });

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

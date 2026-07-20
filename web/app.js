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
  const sub = document.createElement("div");
  sub.className = "file-sub";
  sub.textContent = `${fmtSize(f.size)} · ${fmtDate(f.createdAt)}`;
  meta.append(name, sub);

  const actions = document.createElement("div");
  actions.className = "file-actions";

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

// ---- upload ----
async function uploadFiles(fileList) {
  const files = Array.from(fileList);
  if (!files.length) return;
  const box = $("uploads");

  for (const file of files) {
    const row = document.createElement("div");
    row.className = "upload-row";
    const label = document.createElement("span");
    label.textContent = file.name; // textContent — safe
    const state = document.createElement("span");
    state.textContent = "Uploading…";
    row.append(label, state);
    box.appendChild(row);

    const { ok, body } = await api("/api/files", {
      method: "POST",
      headers: authHeaders({
        "X-Filename": encodeURIComponent(file.name), // ASCII-safe header
        "Content-Type": file.type || "application/octet-stream",
      }),
      body: file,
    });

    if (ok) {
      state.textContent = "Done ✔";
      setTimeout(() => row.remove(), 1500);
    } else {
      row.classList.add("err");
      state.textContent = prettyError(body) || "Failed";
    }
  }
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

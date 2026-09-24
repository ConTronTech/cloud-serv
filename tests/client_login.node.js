"use strict";
// Proves an account created by `cloud_serv admin create-admin` is a REAL account:
// the browser's own, unmodified web/app.js can sign in to it with just the password,
// the recovery key unwraps to the very same data key, and the account is an admin.
// Cookies are kept in a jar like a browser (no token shortcut).
//
//   node tests/client_login.node.js <api-base-url> <email> <password> <recovery-key-file> <wrappedDekRecovery>
const vm = require("vm");
const fs = require("fs");
const path = require("path");
const crypto = globalThis.crypto || require("crypto").webcrypto;

const [BASE, EMAIL, PASSWORD, RECFILE, WRAPPED_REC] = process.argv.slice(2);
const te = new TextEncoder(), td = new TextDecoder();
const toB64 = (u) => Buffer.from(u).toString("base64");
const fromB64 = (s) => new Uint8Array(Buffer.from(s, "base64"));

let PASS = 0, FAIL = 0;
const ok = (m) => { console.log("  PASS: " + m); PASS++; };
const bad = (m) => { console.log("  FAIL: " + m); FAIL++; };
const check = (c, m) => (c ? ok(m) : bad(m));
const importAes = (raw) => crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
async function unwrap(w, rawKey) {
  const [iv, ct] = w.split(".");
  return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: fromB64(iv) }, await importAes(rawKey), fromB64(ct)));
}

async function main() {
  console.log("== CLI-created admin vs the real browser client ==");
  const jar = new Map();                                   // a browser's cookie jar
  const cookieHeader = () => [...jar].map(([k, v]) => k + "=" + v).join("; ");
  const jarFetch = async (u, o = {}) => {
    const res = await fetch(BASE + u, { ...o, headers: { ...(o.headers || {}), cookie: cookieHeader() } });
    for (const c of (res.headers.getSetCookie ? res.headers.getSetCookie() : [])) {
      const [kv] = c.split(";"); const i = kv.indexOf("=");
      jar.set(kv.slice(0, i), kv.slice(i + 1));
    }
    return res;
  };

  const els = {};
  const makeEl = () => new Proxy({ classList: { add() {}, remove() {}, toggle() {}, contains: () => false },
    style: {}, dataset: {}, children: [], value: "", textContent: "" }, {
    get(t, k) { return k in t ? t[k] : () => makeEl(); }, set(t, k, v) { t[k] = v; return true; } });
  const store = () => { const m = new Map(); return { getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: (k) => m.delete(k) }; };
  const ctx = vm.createContext({
    document: { getElementById: (id) => (els[id] ||= makeEl()), createElement: () => makeEl(), querySelectorAll: () => [], addEventListener() {}, body: makeEl() },
    window: { addEventListener() {} }, navigator: {}, localStorage: store(), sessionStorage: store(),
    fetch: jarFetch, crypto, TextEncoder, TextDecoder, atob, btoa, URL, console, setTimeout, clearTimeout,
    confirm: () => true, alert() {}, Uint8Array, Promise, JSON, Math, Date, Map, Set, Array, Object, String, Number, structuredClone,
  });
  process.on("unhandledRejection", () => {});
  vm.runInContext(fs.readFileSync(path.join(__dirname, "..", "web", "app.js"), "utf8"), ctx, { filename: "app.js" });
  await new Promise((r) => setTimeout(r, 50));
  const run = (c) => vm.runInContext(c, ctx);
  ctx.__email = EMAIL; ctx.__pw = PASSWORD; ctx.__bad = PASSWORD + "x";

  // A wrong password must fail (and must not leave a session behind).
  const wrong = await run("e2eLogin(__email, __bad)");
  check(wrong.ok === false, "the real client is refused with a wrong password");
  check(jar.size === 0, "a refused login sets no cookie");

  // The real login: derives the key in the browser, unwraps the DEK the CLI wrapped.
  const good = await run("e2eLogin(__email, __pw)");
  check(good.ok === true, "the real app.js signs in to the CLI-created account with just the password");
  const dek = new Uint8Array(run("Array.from(DEK_RAW)"));
  check(dek.length === 32, "the browser recovered a 32-byte data key (so the CLI's KDF + wrap match the browser's)");
  check(jar.has("session"), "a session cookie was issued");

  // It is an admin, through the ordinary session cookie.
  const me = await (await jarFetch("/api/auth/me")).json();
  check(me.user && me.user.email === EMAIL.toLowerCase() && me.user.role === "admin" && me.user.status === "active",
        "/api/auth/me shows an active admin");
  const list = await jarFetch("/api/admin/users");
  check(list.status === 200 && (await list.json()).users.some((u) => u.email === EMAIL.toLowerCase()), "the admin API accepts it");

  // The recovery key unwraps to the SAME data key the password path produced.
  const rec = fs.readFileSync(RECFILE, "utf8").trim();
  check(/^csr_[A-Za-z0-9+/]{43}=$/.test(rec), "recovery key has the documented format (csr_ + base64 of 32 bytes)");
  const recRaw = fromB64(rec.slice(4));
  check(recRaw.length === 32, "recovery key decodes to 32 bytes");
  let viaRecovery = null;
  try { viaRecovery = await unwrap(WRAPPED_REC, recRaw); } catch { /* fall through */ }
  check(viaRecovery && Buffer.from(viaRecovery).equals(Buffer.from(dek)), "the recovery key unwraps to the SAME data key as the password");

  // End to end: data written through the real app is readable with the recovered key.
  run("newNote()");
  els["note-title"].value = "written by the browser";
  els["note-body"].value = "CLI-ACCOUNT-BODY-MARKER";
  await run("saveNote()");
  const notes = (await (await jarFetch("/api/notes")).json()).notes;
  const full = (await (await jarFetch("/api/notes/" + notes[0].id)).json()).note;
  const body = viaRecovery ? td.decode(await unwrap(full.encBody, viaRecovery)) : "";
  check(full.title === "" && full.body === "" && body === "CLI-ACCOUNT-BODY-MARKER",
        "a note saved via the real app decrypts with the RECOVERY-derived key");

  // Registration is closed, yet this account exists: no invite code was ever needed.
  const reg = await fetch(BASE + "/api/auth/register", { method: "POST", body: JSON.stringify({ email: "new@e.cc", password: "x".repeat(20) }) });
  check(reg.status === 403, "self-registration is still closed (no invite code configured)");

  console.log("\nRESULTS: " + PASS + " passed, " + FAIL + " failed");
  process.exit(FAIL === 0 ? 0 : 1);
}
main().catch((e) => { console.error(e); process.exit(1); });

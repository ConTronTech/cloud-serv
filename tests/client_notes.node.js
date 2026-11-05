"use strict";
// Drives the REAL, unmodified web/app.js (loaded into a VM with DOM stubs) against
// the REAL server with REAL WebCrypto, to test the browser's note code: encrypt on
// save, decrypt on open, and the silent migration of legacy plaintext notes.
//
//   node tests/client_notes.node.js <api-base-url> <storage-dir>
const vm = require("vm");
const fs = require("fs");
const path = require("path");
const crypto = globalThis.crypto || require("crypto").webcrypto;

const BASE = process.argv[2];
const STORAGE = process.argv[3];
const te = new TextEncoder();
const td = new TextDecoder();
const toB64 = (u) => Buffer.from(u).toString("base64");
const fromB64 = (s) => new Uint8Array(Buffer.from(s, "base64"));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

let PASS = 0, FAIL = 0;
const ok = (m) => { console.log("  PASS: " + m); PASS++; };
const bad = (m) => { console.log("  FAIL: " + m); FAIL++; };
const check = (cond, m) => (cond ? ok(m) : bad(m));

// Independent decrypt (does NOT go through app.js) so the test isn't circular.
const importAes = (raw) => crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
async function wrap(text, dek) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, await importAes(dek), te.encode(text)));
  return toB64(iv) + "." + toB64(ct);
}
async function unwrap(w, dek) {
  const [iv, ct] = w.split(".");
  return td.decode(await crypto.subtle.decrypt({ name: "AES-GCM", iv: fromB64(iv) }, await importAes(dek), fromB64(ct)));
}

async function main() {
  console.log("== client note code (real app.js, real server, real crypto) ==");

  // ---- account + a DEK the "browser" holds ----
  let r = await fetch(BASE + "/api/auth/register", { method: "POST", body: JSON.stringify({
    email: "cn@e.cc", password: "client-notes-authkey", inviteCode: "test-invite",
    salt: "00112233445566778899aabbccddeeff", wrappedDek: "x.y", wrappedDekRecovery: "x.y" }) });
  const token = (await r.json()).token;
  const H = { authorization: "Bearer " + token, "content-type": "application/json" };
  const api = async (m, p, body) => (await fetch(BASE + p, { method: m, headers: H, body: body ? JSON.stringify(body) : undefined }));
  const getNotes = async () => (await (await api("GET", "/api/notes")).json()).notes;
  const getNote = async (id) => (await (await api("GET", "/api/notes/" + id)).json()).note;

  // ---- load the real app.js into a VM ----
  const els = {};
  const makeEl = () => new Proxy({ classList: { add() {}, remove() {}, toggle() {}, contains: () => false },
    style: {}, dataset: {}, children: [], value: "", textContent: "" }, {
    get(t, k) { return k in t ? t[k] : () => makeEl(); }, set(t, k, v) { t[k] = v; return true; } });
  const noopStore = () => { const m = new Map(); return { getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: (k) => m.delete(k) }; };
  const toasts = [];
  const ctx = vm.createContext({
    document: { getElementById: (id) => (els[id] ||= makeEl()), createElement: () => makeEl(), createDocumentFragment: () => makeEl(),
      querySelectorAll: () => [], addEventListener() {}, body: makeEl() },
    window: { addEventListener() {} }, navigator: {}, localStorage: noopStore(), sessionStorage: noopStore(),
    fetch: (u, o = {}) => fetch(BASE + u, { ...o, headers: { ...(o.headers || {}), authorization: "Bearer " + token } }),
    crypto, TextEncoder, TextDecoder, atob, btoa, URL, console, setTimeout, clearTimeout,
    confirm: () => true, alert() {}, Uint8Array, Promise, JSON, Math, Date, Map, Set, Array, Object, String, Number,
    IntersectionObserver: undefined, structuredClone,
  });
  process.on("unhandledRejection", () => {});   // boot() touches UI we don't model
  const src = fs.readFileSync(path.join(__dirname, "..", "web", "app.js"), "utf8");
  vm.runInContext(src, ctx, { filename: "app.js" });
  await sleep(50);
  const run = (code) => vm.runInContext(code, ctx);
  run("toast = function (m) { __toasts.push(m); }");
  ctx.__toasts = toasts;

  // The browser's DEK (set through the app's own function, then read back for our checks).
  run("setDEK(crypto.getRandomValues(new Uint8Array(32)))");
  const dek = new Uint8Array(run("Array.from(DEK_RAW)"));
  check(dek.length === 32, "app.js holds a 32-byte DEK");

  // ---- seed: 3 legacy plaintext notes (distinct timestamps) + 1 already encrypted ----
  const seeds = [
    { title: "Groceries", body: "milk, eggs, LEGACY-SECRET-AAA" },
    { title: "Passwords hint", body: "the one about the dog LEGACY-SECRET-BBB" },
    { title: "", body: "untitled body LEGACY-SECRET-CCC" },
  ];
  const ids = [];
  for (const s of seeds) {
    const j = await (await api("POST", "/api/notes", s)).json();
    ids.push(j.note.id);
    await sleep(1150);   // updated_at has 1-second resolution
  }
  const encId = (await (await api("POST", "/api/notes", { encTitle: await wrap("Already secret", dek), encBody: await wrap("ENC-ONLY-BODY", dek) })).json()).note.id;
  const before = await getNotes();
  const beforeOrder = before.map((n) => n.id);
  const beforeTimes = Object.fromEntries(before.map((n) => [n.id, n.updatedAt]));
  check(before.filter((n) => !n.encTitle).length === 3, "seeded 3 legacy plaintext notes");
  check(new Set(before.map((n) => n.updatedAt)).size === 4, "seeded notes have distinct timestamps");

  // ---- the real loadNotes(): renders, then migrates in the background ----
  await run("loadNotes()");
  for (let i = 0; i < 40; i++) {
    const n = await getNotes();
    if (n.every((x) => x.encTitle)) break;
    await sleep(250);
  }
  const after = await getNotes();
  check(after.every((n) => n.encTitle), "every legacy note was migrated to ciphertext");
  const full = await Promise.all(after.map((n) => getNote(n.id)));
  check(full.every((n) => n.title === "" && n.body === ""), "server now holds no plaintext title/body for any note");

  // Content survived exactly.
  const byId = Object.fromEntries(full.map((n) => [n.id, n]));
  for (let i = 0; i < seeds.length; i++) {
    const n = byId[ids[i]];
    const t = await unwrap(n.encTitle, dek), b = await unwrap(n.encBody, dek);
    check(t === seeds[i].title && b === seeds[i].body, "migrated note " + (i + 1) + " decrypts to its exact original title+body");
  }
  const e = byId[encId];
  check((await unwrap(e.encBody, dek)) === "ENC-ONLY-BODY", "the already-encrypted note was left untouched");

  // Order + timestamps preserved (migration must not reshuffle the list).
  check(JSON.stringify(after.map((n) => n.id)) === JSON.stringify(beforeOrder), "list order unchanged by migration");
  check(after.every((n) => n.updatedAt === beforeTimes[n.id]), "every note's updatedAt unchanged by migration");

  const dbDir = path.dirname(STORAGE);

  // ---- the real openNote(): decrypts into the editor fields ----
  await run("openNote(" + ids[0] + ")");
  check(els["note-title"].value === "Groceries", "openNote() puts the decrypted title in the editor");
  check(els["note-body"].value === "milk, eggs, LEGACY-SECRET-AAA", "openNote() puts the decrypted body in the editor");
  check(run("editingNoteId") === ids[0], "openNote() sets the note being edited");

  // ---- the real saveNote(): encrypts before sending ----
  els["note-title"].value = "Groceries v2";
  els["note-body"].value = "NEW-PLAINTEXT-MARKER-QQQ";
  await run("saveNote()");
  const saved = await getNote(ids[0]);
  check(saved.title === "" && saved.body === "" && saved.encTitle && saved.encBody, "saveNote() sends ciphertext only (server has no plaintext)");
  check((await unwrap(saved.encTitle, dek)) === "Groceries v2" && (await unwrap(saved.encBody, dek)) === "NEW-PLAINTEXT-MARKER-QQQ",
        "saved note decrypts to what was typed");
  check(saved.updatedAt !== beforeTimes[ids[0]], "a real edit still updates the edit time");
  const dbNow = fs.readdirSync(dbDir).filter((f) => f.startsWith("cloud.db")).map((f) => fs.readFileSync(path.join(dbDir, f)));
  check(!dbNow.some((b) => b.includes(Buffer.from("NEW-PLAINTEXT-MARKER-QQQ"))), "the newly typed text never reached the database in plaintext");

  // ---- a brand-new note through the real newNote()/saveNote() ----
  run("newNote()");
  els["note-title"].value = "Fresh";
  els["note-body"].value = "FRESH-BODY-MARKER-ZZZ";
  await run("saveNote()");
  const newId = run("editingNoteId");
  const fresh = await getNote(newId);
  check(fresh && fresh.title === "" && fresh.encTitle && (await unwrap(fresh.encBody, dek)) === "FRESH-BODY-MARKER-ZZZ", "a new note is created encrypted");
  const dbNow2 = fs.readdirSync(dbDir).filter((f) => f.startsWith("cloud.db")).map((f) => fs.readFileSync(path.join(dbDir, f)));
  check(!dbNow2.some((b) => b.includes(Buffer.from("FRESH-BODY-MARKER-ZZZ"))), "the new note's text never reached the database in plaintext");

  // ---- safety: a note this key can't decrypt must NOT be opened (and so can't be overwritten) ----
  const otherDek = crypto.getRandomValues(new Uint8Array(32));
  const lockedId = (await (await api("POST", "/api/notes", { encTitle: await wrap("theirs", otherDek), encBody: await wrap("THEIR-BODY", otherDek) })).json()).note.id;
  const lockedBefore = await getNote(lockedId);
  run("editingNoteId = null");
  toasts.length = 0;
  await run("openNote(" + lockedId + ")");
  check(run("editingNoteId") === null, "a note that can't be decrypted is NOT opened for editing");
  check(toasts.some((t) => /can't be decrypted/.test(t)), "the user is told why it can't be opened");
  const lockedAfter = await getNote(lockedId);
  check(lockedAfter.encBody === lockedBefore.encBody && lockedAfter.encTitle === lockedBefore.encTitle, "the undecryptable note's ciphertext is untouched");

  // ---- idempotence: a second load migrates nothing and changes nothing ----
  const snap = JSON.stringify((await getNotes()).map((n) => [n.id, n.updatedAt, n.encTitle]));
  await run("loadNotes()");
  await sleep(600);
  check(JSON.stringify((await getNotes()).map((n) => [n.id, n.updatedAt, n.encTitle])) === snap, "reloading the notes tab changes nothing");

  // ---- the list titles the app renders come from decryption ----
  const listed = (await getNotes()).find((n) => n.id === ids[1]);
  const hydrated = await (async () => { const o = { encTitle: listed.encTitle }; await run("hydrateNote").call(null, o); return o._title; })();
  check(hydrated === "Passwords hint", "hydrateNote() decrypts a list title");

  console.log("\nRESULTS: " + PASS + " passed, " + FAIL + " failed");
  process.exit(FAIL === 0 ? 0 : 1);
}
main().catch((e) => { console.error(e); process.exit(1); });

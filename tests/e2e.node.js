"use strict";
// End-to-end zero-knowledge check. Drives the real HTTP API the way the browser
// client does: derive keys from a password, register with a client-generated
// salt + wrapped DEK, encrypt a file client-side, upload the ciphertext, then
// confirm (a) the plaintext never lands on disk, (b) the stored blob is exactly
// our ciphertext, and (c) download + decrypt reproduces the original.
//
//   node tests/e2e.node.js <api-base-url> <storage-dir>
const crypto = globalThis.crypto || require("crypto").webcrypto;
const fs = require("fs");
const path = require("path");

const API = process.argv[2];
const STORAGE = process.argv[3];

const te = new TextEncoder();
const PBKDF2_ITERS = 310000;
const toB64 = (u) => Buffer.from(u).toString("base64");
const fromB64 = (s) => new Uint8Array(Buffer.from(s, "base64"));
const toHex = (u) => Buffer.from(u).toString("hex");
const fromHex = (h) => new Uint8Array(Buffer.from(h, "hex"));
const rand = (n) => crypto.getRandomValues(new Uint8Array(n));

async function deriveKeys(password, saltHex) {
  const base = await crypto.subtle.importKey("raw", te.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = new Uint8Array(await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: fromHex(saltHex), iterations: PBKDF2_ITERS, hash: "SHA-256" }, base, 512));
  const authKeyB64 = toB64(bits.slice(0, 32));
  const kek = await crypto.subtle.importKey("raw", bits.slice(32, 64), { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
  return { authKeyB64, kek };
}
const importAes = (raw) => crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
async function wrapBytes(raw, key) { const iv = rand(12); const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, raw)); return toB64(iv) + "." + toB64(ct); }
async function unwrapBytes(w, key) { const [iv, ct] = w.split("."); return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: fromB64(iv) }, key, fromB64(ct))); }

const ENC_CHUNK = 1024 * 1024;
function concatBytes(list) { const n = list.reduce((s, c) => s + c.length, 0); const o = new Uint8Array(n); let p = 0; for (const c of list) { o.set(c, p); p += c.length; } return o; }
function frameAad(index, isFinal) {
  return new Uint8Array([(index >>> 24) & 0xff, (index >>> 16) & 0xff, (index >>> 8) & 0xff, index & 0xff, isFinal ? 1 : 0]);
}
async function encryptContent(fileKey, plain) {
  const frames = [];
  const total = Math.max(1, Math.ceil(plain.length / ENC_CHUNK));
  let off = 0, i = 0;
  do {
    const slice = plain.subarray(off, Math.min(off + ENC_CHUNK, plain.length));
    const nonce = rand(12);
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: frameAad(i, i === total - 1) }, fileKey, slice));
    const fr = new Uint8Array(12 + ct.length); fr.set(nonce, 0); fr.set(ct, 12); frames.push(fr);
    off += ENC_CHUNK; i++;
  } while (off < plain.length);
  return concatBytes(frames);
}
async function decryptContent(fileKey, cipher) {
  if (cipher.length === 0) throw new Error("empty ciphertext");
  const FRAME = ENC_CHUNK + 28; const parts = [];
  let i = 0;
  for (let off = 0; off < cipher.length; i++) {
    const len = Math.min(FRAME, cipher.length - off);
    const isFinal = off + len >= cipher.length;
    const fr = cipher.subarray(off, off + len);
    parts.push(new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: fr.subarray(0, 12), additionalData: frameAad(i, isFinal) }, fileKey, fr.subarray(12))));
    off += len;
  }
  return concatBytes(parts);
}

let PASS = 0, FAIL = 0;
const ok = (d) => { console.log("  PASS: " + d); PASS++; };
const bad = (d) => { console.log("  FAIL: " + d); FAIL++; };
function walk(d) { const out = []; for (const e of fs.readdirSync(d, { withFileTypes: true })) { const p = path.join(d, e.name); e.isDirectory() ? out.push(...walk(p)) : out.push(p); } return out; }

async function main() {
  console.log("== E2E zero-knowledge round-trip ==");
  const email = "e2e_" + Date.now() + "@t.io";
  const password = "CorrectHorse9";
  const saltHex = toHex(rand(16));
  const { authKeyB64, kek } = await deriveKeys(password, saltHex);

  // DEK wrapped by the password-KEK and by a recovery key — exactly what the
  // client uploads at registration. The server never sees the password or DEK.
  const dek = rand(32);
  const wrappedDek = await wrapBytes(dek, kek);
  const wrappedDekRecovery = await wrapBytes(dek, await importAes(rand(32)));

  let r = await fetch(API + "/api/auth/register", {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ email, password: authKeyB64, displayName: "e2e", inviteCode: "test-invite", salt: saltHex, wrappedDek, wrappedDekRecovery }),
  });
  r.ok ? ok("register (auth key, not password)") : bad("register " + r.status);

  r = await fetch(API + "/api/auth/login", {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ email, password: authKeyB64 }),
  });
  const lj = await r.json();
  const token = lj.token;
  token ? ok("login returns session token") : bad("login " + r.status);
  lj.wrappedDek === wrappedDek ? ok("server round-trips wrappedDek untouched") : bad("wrappedDek mismatch");
  const auth = { authorization: "Bearer " + token };

  // Encrypt a file client-side (name AND contents) and upload the ciphertext.
  const marker = "TOP-SECRET-PLAINTEXT-MARKER";
  const nameMarker = "MY-PRIVATE-FILENAME-2026.txt";
  const plaintext = te.encode(marker + " " + "x".repeat(5000));
  const dekKey = await importAes(dek);
  const fileRaw = rand(32);
  const cipher = await encryptContent(await importAes(fileRaw), plaintext);
  const wrappedKey = await wrapBytes(fileRaw, dekKey);
  const encName = await wrapBytes(te.encode(nameMarker), dekKey);
  const mimeMarker = "application/x-my-secret-type";
  const encMime = await wrapBytes(te.encode(mimeMarker), dekKey);
  r = await fetch(API + "/api/files", {
    method: "POST",
    headers: { ...auth, "X-Enc-Name": encName, "X-Enc-Mime": encMime, "X-Folder": "0", "X-Wrapped-Key": wrappedKey, "X-Plain-Size": String(plaintext.length), "content-type": "application/octet-stream" },
    body: cipher,
  });
  const uj = await r.json();
  uj.id ? ok("upload encrypted file (encrypted name+mime)") : bad("upload " + r.status);
  uj.size === plaintext.length ? ok("stored display size = plaintext size") : bad("size " + uj.size);
  uj.name === "" ? ok("server stores blank plaintext name") : bad("plaintext name stored: " + JSON.stringify(uj.name));
  uj.mime === "application/octet-stream" ? ok("server stores generic mime placeholder") : bad("real mime stored: " + JSON.stringify(uj.mime));

  // Create a folder with an encrypted name too.
  const folderNameMarker = "PRIVATE-FOLDER-NAME";
  const folderEnc = await wrapBytes(te.encode(folderNameMarker), dekKey);
  r = await fetch(API + "/api/folders", {
    method: "POST", headers: { ...auth, "content-type": "application/json" },
    body: JSON.stringify({ parentId: 0, encName: folderEnc }),
  });
  (await r.json()).folder ? ok("create folder with encrypted name") : bad("folder create " + r.status);

  // On disk: no plaintext contents, and the blob is byte-for-byte our ciphertext.
  const disk = walk(STORAGE).map((f) => fs.readFileSync(f));
  disk.some((b) => b.includes(Buffer.from(marker))) ? bad("PLAINTEXT CONTENT LEAKED TO DISK") : ok("no plaintext content on disk");
  disk.some((b) => b.equals(Buffer.from(cipher))) ? ok("on-disk blob is the ciphertext") : bad("ciphertext not found on disk");

  // In the database file (incl. WAL): the filename / folder name must not appear.
  const dbDir = path.dirname(STORAGE);
  const dbBlobs = fs.readdirSync(dbDir).filter((f) => f.startsWith("cloud.db")).map((f) => fs.readFileSync(path.join(dbDir, f)));
  const nameLeaked = dbBlobs.some((b) => b.includes(Buffer.from(nameMarker)) || b.includes(Buffer.from(folderNameMarker)));
  nameLeaked ? bad("PLAINTEXT NAME LEAKED TO DATABASE") : ok("no plaintext name in the database");
  const mimeLeaked = dbBlobs.some((b) => b.includes(Buffer.from(mimeMarker)));
  mimeLeaked ? bad("PLAINTEXT MIME LEAKED TO DATABASE") : ok("no plaintext mime in the database");

  // The listing exposes wrappedKey + encName so the client can decrypt both.
  r = await fetch(API + "/api/files", { headers: auth });
  const listed = (await r.json()).files.find((f) => f.id === uj.id);
  listed && listed.wrappedKey === wrappedKey ? ok("listing returns wrappedKey") : bad("wrappedKey not in listing");
  const backName = listed && listed.encName ? new TextDecoder().decode(await unwrapBytes(listed.encName, dekKey)) : "";
  backName === nameMarker ? ok("encName decrypts to original filename") : bad("name decrypt mismatch: " + backName);
  const backMime = listed && listed.encMime ? new TextDecoder().decode(await unwrapBytes(listed.encMime, dekKey)) : "";
  backMime === mimeMarker ? ok("encMime decrypts to original mime") : bad("mime decrypt mismatch: " + backMime);

  // Download + decrypt with the key recovered via the DEK → original bytes.
  r = await fetch(API + "/api/files/" + uj.id + "/content", { headers: auth });
  const dl = new Uint8Array(await r.arrayBuffer());
  const recovered = await decryptContent(await importAes(await unwrapBytes(listed.wrappedKey, dekKey)), dl);
  Buffer.from(recovered).equals(Buffer.from(plaintext)) ? ok("download decrypts to original") : bad("decrypt mismatch");

  console.log("\nRESULTS: " + PASS + " passed, " + FAIL + " failed");
  process.exit(FAIL === 0 ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(1); });

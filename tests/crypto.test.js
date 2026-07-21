// Verifies the browser E2E crypto (same functions as web/app.js) in Node WebCrypto.
const crypto = globalThis.crypto || require("crypto").webcrypto;
const te = new TextEncoder();
const PBKDF2_ITERS = 310000;
const toHex = (b) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, "0")).join("");
const fromHex = (s) => { const a = new Uint8Array(s.length / 2); for (let i = 0; i < a.length; i++) a[i] = parseInt(s.substr(i*2,2),16); return a; };
const toB64 = (b) => Buffer.from(new Uint8Array(b)).toString("base64");
const fromB64 = (s) => new Uint8Array(Buffer.from(s, "base64"));
const rand = (n) => crypto.getRandomValues(new Uint8Array(n));
// getRandomValues caps at 64KB/call — fill larger buffers in blocks (test helper only).
function bigBytes(n) { const a = new Uint8Array(n); for (let i = 0; i < n; i += 65536) crypto.getRandomValues(a.subarray(i, Math.min(i + 65536, n))); return a; }

async function deriveKeys(password, saltHex) {
  const base = await crypto.subtle.importKey("raw", te.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = new Uint8Array(await crypto.subtle.deriveBits({ name: "PBKDF2", salt: fromHex(saltHex), iterations: PBKDF2_ITERS, hash: "SHA-256" }, base, 512));
  const kek = await crypto.subtle.importKey("raw", bits.slice(32, 64), { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
  return { authKeyB64: toB64(bits.slice(0, 32)), kek };
}
const importAes = (raw) => crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
async function wrapBytes(raw, key) { const iv = rand(12); const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, raw); return toB64(iv) + "." + toB64(new Uint8Array(ct)); }
async function unwrapBytes(w, key) { const [iv, ct] = w.split("."); return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: fromB64(iv) }, key, fromB64(ct))); }

// ---- content encryption (chunked AES-256-GCM), identical to web/app.js ----
const ENC_CHUNK = 1024 * 1024;   // plaintext bytes per chunk
const ENC_OVERHEAD = 12 + 16;    // nonce + GCM tag
function concatBytes(list) { const n = list.reduce((s, c) => s + c.length, 0); const o = new Uint8Array(n); let p = 0; for (const c of list) { o.set(c, p); p += c.length; } return o; }
// AAD binds each frame to its position + final-flag (STREAM construction) so a
// server cannot reorder/truncate/duplicate frames without failing the tag check.
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
    const frame = new Uint8Array(12 + ct.length); frame.set(nonce, 0); frame.set(ct, 12);
    frames.push(frame); off += ENC_CHUNK; i++;
  } while (off < plain.length);
  return concatBytes(frames);
}
async function decryptContent(fileKey, cipher) {
  if (cipher.length === 0) throw new Error("empty ciphertext");
  const FRAME = ENC_CHUNK + ENC_OVERHEAD;
  const parts = [];
  let i = 0;
  for (let off = 0; off < cipher.length; i++) {
    const len = Math.min(FRAME, cipher.length - off);
    const isFinal = off + len >= cipher.length;
    const nonce = cipher.subarray(off, off + 12);
    const ctTag = cipher.subarray(off + 12, off + len);
    parts.push(new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: nonce, additionalData: frameAad(i, isFinal) }, fileKey, ctTag)));
    off += len;
  }
  return concatBytes(parts);
}

let pass = 0, fail = 0;
const ok = (name, cond) => { console.log((cond ? "  PASS: " : "  FAIL: ") + name); cond ? pass++ : fail++; };

(async () => {
  // Register-time derivation
  const saltHex = toHex(rand(16));
  const { authKeyB64, kek } = await deriveKeys("CorrectHorse9", saltHex);
  ok("authKey is 32 bytes b64", fromB64(authKeyB64).length === 32);

  const dek = rand(32);
  const wrappedDek = await wrapBytes(dek, kek);

  // Recovery key
  const recRaw = rand(32);
  const wrappedRec = await wrapBytes(dek, await importAes(recRaw));

  // Login with CORRECT password -> same salt+password -> same KEK -> unwraps DEK
  const login = await deriveKeys("CorrectHorse9", saltHex);
  ok("correct password derives same authKey", login.authKeyB64 === authKeyB64);
  const dekBack = await unwrapBytes(wrappedDek, login.kek);
  ok("correct password unwraps the DEK", toB64(dekBack) === toB64(dek));

  // WRONG password -> different KEK -> unwrap must fail (GCM auth)
  const wrong = await deriveKeys("WrongPassword1", saltHex);
  ok("wrong password derives different authKey", wrong.authKeyB64 !== authKeyB64);
  let unwrapFailed = false;
  try { await unwrapBytes(wrappedDek, wrong.kek); } catch { unwrapFailed = true; }
  ok("wrong password cannot unwrap DEK", unwrapFailed);

  // Recovery key unwraps the DEK
  const recBack = await unwrapBytes(wrappedRec, await importAes(recRaw));
  ok("recovery key unwraps the DEK", toB64(recBack) === toB64(dek));

  // Tamper detection: flip a byte in ciphertext -> GCM rejects
  const parts = wrappedDek.split(".");
  const ctB = fromB64(parts[1]); ctB[0] ^= 1;
  let tamperFailed = false;
  try { await unwrapBytes(parts[0] + "." + toB64(ctB), kek); } catch { tamperFailed = true; }
  ok("tampered ciphertext is rejected (GCM)", tamperFailed);

  // ---- content encryption round-trips ----
  const fileKey = await importAes(rand(32));
  for (const size of [0, 1, 100, ENC_CHUNK, ENC_CHUNK + 1, ENC_CHUNK * 2 + 12345]) {
    const plain = bigBytes(size);
    const cipher = await encryptContent(fileKey, plain);
    const back = await decryptContent(fileKey, cipher);
    const same = back.length === plain.length && Buffer.compare(Buffer.from(back), Buffer.from(plain)) === 0;
    ok(`content round-trip @ ${size} bytes (cipher=${cipher.length})`, same);
  }
  // wrong file key can't decrypt content
  {
    const plain = bigBytes(2048);
    const cipher = await encryptContent(fileKey, plain);
    let failed = false;
    try { await decryptContent(await importAes(rand(32)), cipher); } catch { failed = true; }
    ok("content: wrong key rejected (GCM)", failed);
  }
  // tampered content chunk rejected
  {
    const plain = bigBytes(4096);
    const cipher = await encryptContent(fileKey, plain);
    cipher[20] ^= 1;
    let failed = false;
    try { await decryptContent(fileKey, cipher); } catch { failed = true; }
    ok("content: tampered chunk rejected (GCM)", failed);
  }

  // ---- untrusted-server frame integrity (STREAM AAD) ----
  // These simulate a malicious server rearranging the ciphertext a user's own
  // key can otherwise "validly" decrypt frame-by-frame.
  const FRAME = ENC_CHUNK + ENC_OVERHEAD;
  // reordered frames rejected (swap frame 0 and frame 1 of a 3-frame file)
  {
    const cipher = await encryptContent(fileKey, bigBytes(ENC_CHUNK * 2 + 500));
    const swapped = new Uint8Array(cipher);
    swapped.set(cipher.subarray(FRAME, 2 * FRAME), 0);
    swapped.set(cipher.subarray(0, FRAME), FRAME);
    let failed = false;
    try { await decryptContent(fileKey, swapped); } catch { failed = true; }
    ok("content: reordered frames rejected (AAD index)", failed);
  }
  // truncated file rejected (drop the final frame of a 2-frame file)
  {
    const cipher = await encryptContent(fileKey, bigBytes(ENC_CHUNK + 500));
    const truncated = cipher.subarray(0, FRAME); // keep only frame 0
    let failed = false;
    try { await decryptContent(fileKey, truncated); } catch { failed = true; }
    ok("content: truncated file rejected (AAD final-flag)", failed);
  }
  // duplicated final frame (append) rejected
  {
    const cipher = await encryptContent(fileKey, bigBytes(ENC_CHUNK + 500));
    const appended = concatBytes([cipher, cipher.subarray(FRAME)]); // repeat last frame
    let failed = false;
    try { await decryptContent(fileKey, appended); } catch { failed = true; }
    ok("content: appended/duplicated frame rejected (AAD)", failed);
  }

  console.log(`\nRESULTS: ${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
})();

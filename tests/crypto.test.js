// Verifies the browser E2E crypto (same functions as web/app.js) in Node WebCrypto.
const crypto = globalThis.crypto || require("crypto").webcrypto;
const te = new TextEncoder();
const PBKDF2_ITERS = 310000;
const toHex = (b) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, "0")).join("");
const fromHex = (s) => { const a = new Uint8Array(s.length / 2); for (let i = 0; i < a.length; i++) a[i] = parseInt(s.substr(i*2,2),16); return a; };
const toB64 = (b) => Buffer.from(new Uint8Array(b)).toString("base64");
const fromB64 = (s) => new Uint8Array(Buffer.from(s, "base64"));
const rand = (n) => crypto.getRandomValues(new Uint8Array(n));

async function deriveKeys(password, saltHex) {
  const base = await crypto.subtle.importKey("raw", te.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = new Uint8Array(await crypto.subtle.deriveBits({ name: "PBKDF2", salt: fromHex(saltHex), iterations: PBKDF2_ITERS, hash: "SHA-256" }, base, 512));
  const kek = await crypto.subtle.importKey("raw", bits.slice(32, 64), { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
  return { authKeyB64: toB64(bits.slice(0, 32)), kek };
}
const importAes = (raw) => crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
async function wrapBytes(raw, key) { const iv = rand(12); const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, raw); return toB64(iv) + "." + toB64(new Uint8Array(ct)); }
async function unwrapBytes(w, key) { const [iv, ct] = w.split("."); return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: fromB64(iv) }, key, fromB64(ct))); }

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

  console.log(`\nRESULTS: ${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
})();

# cloud-serv — Client Crypto & API Spec (v1)

Implementation-grade reference for building a **second client** (Android/Kotlin) that
interoperates byte-for-byte with the web client and the server. If a value here disagrees with
the code, the code (`web/app.js`, `src/routes/*`) wins — but they are meant to match, and the
test suite (`tests/crypto.test.js`, `tests/e2e.node.js`) pins these exact bytes.

Threat model and rationale live in [SECURITY.md](SECURITY.md). Short version: the **server is
untrusted**; it must never see the password, the data key, contents, names, or types.

---

## 0. Primitives & encodings

| Thing | Value |
|-------|-------|
| Hash / PRF | SHA-256 |
| Password KDF | PBKDF2-HMAC-SHA256, **310000** iterations |
| Bulk cipher | AES-256-GCM, 96-bit (12-byte) nonce, 128-bit (16-byte) tag |
| Random | CSPRNG for every nonce/key/salt |
| `hex` | lowercase, no prefix |
| `b64` | **standard** Base64 (alphabet `A–Z a–z 0–9 + /`, `=` padding). Not URL-safe. |
| GCM output order | `ciphertext ‖ tag` (tag appended) — matches WebCrypto and Java `AES/GCM/NoPadding` |

**Wrap format** (used for every wrapped key and every encrypted metadata string):

```
wrap(keyBytes, plaintextBytes):
    iv = random 12 bytes
    ct_and_tag = AES-256-GCM(key=keyBytes, iv=iv, aad=∅).encrypt(plaintextBytes)
    return b64(iv) + "." + b64(ct_and_tag)        # a single ASCII string with one '.'
unwrap(keyBytes, "b64iv.b64ct"):  # inverse; GCM tag failure => reject
```

---

## 1. Key hierarchy

```
password ─PBKDF2-HMAC-SHA256(salt=16B, 310000)→ 512 bits
                                                 ├ bits[0:32]  = AUTH key  → b64 → sent to server as "password"
                                                 └ bits[32:64] = KEK (AES-256 key, stays on client)

DEK          = random 32 bytes                      # the data key; everything below is under it
recoveryKey  = random 32 bytes                      # shown once as "csr_" + b64(recoveryKey)
wrappedDek           = wrap(KEK, DEK)               # unlock with password
wrappedDekRecovery   = wrap(recoveryKey, DEK)       # unlock without password

perFileKey   = random 32 bytes                      # one per file
wrappedKey   = wrap(DEK, perFileKey)                # stored/served per file
encName      = wrap(DEK, utf8(filename))            # per file AND per folder
encMime      = wrap(DEK, utf8(mimeType))            # per file
```

- `salt` is client-generated: `hex(random 16 bytes)`.
- The AUTH key is what the server password-hashes; it never sees the password or the KEK.
- The recovery key string is `"csr_" + b64(recoveryKey)`; to use it, strip `csr_`, Base64-decode
  to 32 bytes, and `unwrap(recoveryKey, wrappedDekRecovery)`.

---

## 2. Content encryption (chunked AES-256-GCM, STREAM construction)

Plaintext is split into **1 MiB** (`ENC_CHUNK = 1048576`) frames. Each frame on the wire/disk is:

```
frame = nonce(12) ‖ ciphertext ‖ tag(16)
full-frame size = 12 + 1048576 + 16 = 1048604 bytes ; the last frame is shorter
```

Each frame's **AAD binds its position**, so an untrusted server can't reorder/truncate/duplicate:

```
frameAad(index, isFinal) = bigEndianUint32(index) ‖ (isFinal ? 0x01 : 0x00)   # 5 bytes
```

**Encrypt** (`total = max(1, ceil(len/ENC_CHUNK))`, so a 0-byte file has one empty final frame):

```
for i in 0 .. total-1:
    slice   = plaintext[i*ENC_CHUNK : min((i+1)*ENC_CHUNK, len)]
    nonce   = random 12 bytes
    ct_tag  = AES-256-GCM(perFileKey, nonce, aad=frameAad(i, i==total-1)).encrypt(slice)
    emit nonce ‖ ct_tag
```

**Decrypt** walks fixed `1048604`-byte frames (last is the remainder); `isFinal` = "this frame
ends the ciphertext". Any GCM failure (wrong key, tamper, reorder, truncation) must abort.

The whole ciphertext blob is what gets uploaded and what the server stores/serves.

---

## 3. Server-visible vs. encrypted

| Field | On server | Notes |
|-------|-----------|-------|
| file/folder name | `encName` blob; plaintext column blanked | length ≈ leaks name length |
| mime type | `encMime` blob; plaintext stored as `application/octet-stream` | |
| contents | ciphertext blob on disk | |
| per-file key | `wrappedKey` blob | |
| **plaintext size** | integer, cleartext (for display / progress) | |
| folder tree, timestamps, counts | cleartext | structural metadata |

---

## 4. HTTP API

Base URL is the server origin. **Auth:** send `Authorization: Bearer <token>` (session) or
`X-API-Key: csk_...` on every request. Native clients set these on media/content requests too
(the browser-only session cookie is not needed). No `Origin`/`Referer` ⇒ the CSRF check is
skipped, so native requests pass.

### 4.1 Pre-login salt
`GET /api/auth/salt?email=<email>` → `{ "salt": "<hex>" }`
Returns the user's real salt, or an unpredictable per-install decoy for unknown emails
(indistinguishable — do not rely on it to detect registration).

### 4.2 Register
`POST /api/auth/register`
```json
{ "email": "...", "password": "<b64 AUTH key>", "displayName": "...",
  "salt": "<hex>", "wrappedDek": "iv.ct", "wrappedDekRecovery": "iv.ct" }
```
→ `{ "token": "<session>", "user": {...} }`. Show the recovery key (`csr_...`) **once**.

### 4.3 Login
`POST /api/auth/login` with `{ "email": "...", "password": "<b64 AUTH key>" }`
→ `{ "token": "...", "salt": "<hex>", "wrappedDek": "iv.ct", "user": {...} }`
Flow: `GET /salt` → `deriveKeys` → login → `unwrap(KEK, wrappedDek)` = DEK.

### 4.4 Upload — small file (single request)
`POST /api/files`, body = **ciphertext**, headers:
```
X-Enc-Name:   <encName blob>
X-Enc-Mime:   <encMime blob>
X-Wrapped-Key:<wrappedKey blob>
X-Plain-Size: <plaintext byte length>
X-Folder:     <folderId, 0 = root>
Content-Type: application/octet-stream
```
→ `{ "id": N, "encName": "...", "encMime": "...", "size": <plainSize>, ... }`

### 4.5 Upload — large file (resumable)
1. `POST /api/uploads/init`
   `{ "encName","encMime","wrappedKey","plainSize", "size": <ciphertext length>, "folderId" }`
   → `{ "uploadId": "..." }`
2. `PUT /api/uploads/<uploadId>` with header `X-Offset: <bytes so far>`, body = next ciphertext
   slice (send in order; a 409 returns the server's `received` to resync).
3. `POST /api/uploads/<uploadId>/complete` → `{ "file": {...} }`.
Encrypt the whole file first, then upload the ciphertext in slices (framing is independent of
slice boundaries).

### 4.6 List / browse
`GET /api/fs?folder=<id>` → `{ folder, breadcrumbs[], folders[], files[] }`.
Each **file**: `{ id, folderId, size (plaintext), createdAt, starred, wrappedKey, encName, encMime, mime("application/octet-stream"), name("") }`.
Each **folder**: `{ id, parentId, name(""), createdAt, starred, encName }`.
Client decrypts `encName`→name, `encMime`→mime before display.
Also: `GET /api/starred`, `/api/recent`, `/api/usage`, `/api/search?q=&category=` (server search
is name-blind for E2E items — do it client-side).

### 4.7 Download / preview
`GET /api/files/<id>/content` → the ciphertext blob (supports `Range`, but E2E clients fetch the
whole blob, then `decryptContent(unwrap(DEK, wrappedKey), blob)`). `GET /api/files/<id>` is the
attachment variant. Build the local file/blob with the **decrypted** mime.

### 4.8 Mutations
`PATCH /api/files/<id>` / `PATCH /api/folders/<id>` accept `{ "encName": "..." }` (rename),
`{ "folderId" | "parentId": N }` (move), `{ "starred": bool }`.
`POST /api/folders` `{ "parentId", "encName" }`. `DELETE` on either.

---

## 5. Conformance

A new client is correct when, against a throwaway server, it can: register → log in → upload a
file → and have `tests/e2e.node.js`-style checks pass (no plaintext content/name/mime on disk or
in the DB; download decrypts to the original). Reuse the frame/AAD vectors in
`tests/crypto.test.js` as known-answer tests.

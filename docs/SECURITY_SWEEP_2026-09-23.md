# cloud-serv — Security Sweep (2026-09-23)

Full-codebase read-only security review, run as three parallel audits (auth/crypto/middleware;
DB layer + route authorization; storage/uploads/web client) and consolidated here. Nothing in
the repo was modified to produce this document — every item below is a finding to triage, not
a fix already applied.

**Scope:** all of `src/`, `include/`, `web/`, `schema.sql`, `config.env`. Reviewers also
cross-checked `SECURITY.md` and `CRYPTO_SPEC.md` and were told not to re-report the residual
risks already documented there (file substitution by a malicious server, offline password
attack via a captured AUTH key, plaintext metadata, DEK in `sessionStorage`, and
`RATE_LIMIT_ENABLED=false`/no-TLS-yet — all still true and still open).

**Result:** no SQL injection and no cross-user IDOR/missing-`user_id`-scoping was found
anywhere (every id-taking query was checked — see the "Verified safe" sections). No XSS sink
exists in the web client (`innerHTML`/`eval`/etc. all absent; verified by grep + read).
Password hashing, session/API-key storage, CSRF matching, and the crypto engine all check out
against their design. The real issues are two DoS-shaped gaps (rate-limiter identity spoofing,
no upload quota/expiry), a cluster of upload-race data-corruption bugs, and defense-in-depth
gaps consistent with what `SECURITY.md` already scopes as accepted risk.

---

## Findings by severity

### High

| # | Where | Title |
|---|-------|-------|
| H1 | `src/security/rate_limiter.cpp:134-154` | X-Forwarded-For parsed from the wrong end — client controls its own rate-limit identity behind the documented reverse-proxy setup |
| H2 | `src/routes/uploads.cpp:84-103`, `src/db/database.cpp` (no `upload_sessions` purge) | No per-user upload quota; upload sessions never expire; disk fills with unlimited/never-reclaimed 5 GB claims |

### Medium

| # | Where | Title |
|---|-------|-------|
| M1 | `src/routes/uploads.cpp:124-145` | Chunk append not atomic with the offset check — concurrent PUTs desync blob vs. DB `received`, bricking the upload |
| M2 | `src/routes/uploads.cpp:156-170` | Concurrent `/complete` can create two file rows sharing one blob; deleting either destroys the other's data |
| M3 | `src/db/database.cpp:971,980-988` | `deleteFolderRecursive` ignores per-statement SQL errors and reads stale `sqlite3_changes` — a partial failure can still commit and unlink blobs for rows that survived |
| M4 | `src/db/database.cpp:117-131,143-158` + routes | Orphaned file/upload rows can point at a folder deleted out from under them (no FK on `folder_id`, no atomic re-check) |
| M5 | `src/db/database.cpp:999-1010,918-926` | Unbounded folder nesting depth; `folderPath`/`moveFolder` open one DB connection per level, `moveFolder` holds the **global exclusive lock** for the whole walk — cross-user DoS on a deep tree |
| M6 | `src/routes/auth.cpp:97-126`, `config.env:30` | No per-account login throttling; with the limiter off (current config) or bypassed (H1) there's unlimited online guessing / PBKDF2 CPU exhaustion |
| M7 | `src/routes/auth.cpp:61` | `/api/auth/register` returns `409` for a taken email, defeating the anti-enumeration decoy-salt design elsewhere in the same flow |
| M8 | `src/routes/auth.cpp:75,124,149` | Session cookie is never sent with `Secure` (the flag exists, is just never passed `true`) |
| M9 | `web/app.js:7,371`; `web/app.js:318-322` | Session token duplicated into `localStorage` (redundant — the HttpOnly cookie already authenticates the browser client) **and** the raw DEK sits in `sessionStorage` as extractable bytes — both are XSS-exfiltratable, widening the blast radius of any future script-injection bug beyond what `SECURITY.md`'s "DEK in sessionStorage" risk already accepts |
| M10 | `src/routes/auth.cpp:154-174` | Any authenticated principal, **including an API key**, can mint further API keys — a leaked automation key can outlive its own revocation via child keys it created |
| M11 | `web/app.js:212,312-315` | Client treats a missing `wrappedKey`/`encName` from the server as "legacy plaintext" and renders it — a malicious server can forge file content/name for any item with no cryptographic detection (violates the "untrusted server" threat model in `CRYPTO_SPEC.md`) |
| M12 | `web/app.js:131-139`; `CRYPTO_SPEC.md` §0 | Wrapped file keys and encrypted name/mime have no AAD binding them to a file id — a malicious server can swap a `wrappedKey`/`encName`/`encMime` between two of the user's own files and both still decrypt "successfully" |

### Low

| # | Where | Title |
|---|-------|-------|
| L1 | `src/db/database.cpp:408-426` | An invalid `X-API-Key` takes the global exclusive DB lock + opens a fresh RW connection before rejecting it — amplifies H1/M6 |
| L2 | `src/routes/auth.cpp:47-66` | Open registration with no length/format validation on `displayName`/`salt`/`wrappedDek*`; 256 MB body cap applies even to unauthenticated auth routes |
| L3 | `src/http/middleware.cpp:36,104,139` | If `CORS_ORIGINS=*` is ever set, the server reflects any `Origin` with `Allow-Credentials: true` (classic reflected-wildcard bug); no `Vary: Origin` |
| L4 | `src/http/middleware.cpp:41` | CORS preflight omits `Authorization` from `Access-Control-Allow-Headers`, so cross-origin Bearer auth can't actually work against the documented Vite dev origin |
| L5 | `src/http/middleware.cpp:88-119` | CSRF authority check ignores scheme (`http://` passes for an `https://` deployment); requests with neither `Origin` nor `Referer` skip the check and rely solely on `SameSite=Strict` |
| L6 | `src/routes/auth.cpp:84`, `src/db/database.cpp:320-321` | `serverSecret()` fails open to `""` on a DB error, making the anti-enumeration decoy salt attacker-computable again |
| L7 | `src/routes/auth.cpp:108-112` | Two small timing side channels: lazy-initialized dummy hash makes the *first* unknown-email login measurably slower; malformed stored hashes short-circuit `verifyPassword` |
| L8 | `src/security/rate_limiter.cpp:66-76,164-180,79` | Violation counter never decays (post-ban re-offense is instant); a banned bucket can be cleaned up (and the ban lifted) by the idle sweep; `enabled_` read outside its mutex (data race); banned requests log at `warn` every time (flood) |
| L9 | `src/http/middleware.cpp:110-111,153-155` | Logs record the full request URL (including `?email=...` on `/salt`) and the raw, attacker-controlled XFF/Origin/Referer strings verbatim |
| L10 | `src/routes/auth.cpp:129-139` | `/api/auth/me` returns `salt`+`wrappedDek` to **any** valid credential, including an API key — a leaked automation key yields offline password-attack material even though it can't decrypt anything itself |
| L11 | `src/routes/files.cpp:170-172`, `src/routes/uploads.cpp:93` | Client-controlled `X-Plain-Size`/`plainSize` is unbounded/unsigned-unchecked; two adversarial values can make SQLite's `SUM()` overflow and `usage()` silently return `{0,0}` |
| L12 | `src/routes/files.cpp:234,247-268` | Range/`Content-Range` math is computed from the plaintext `size` field, not the real on-disk (ciphertext) size — can truncate the GCM tag on an E2E file's final bytes |
| L13 | `src/routes/fs.cpp:119-134,212-227` | Folder/file `PATCH` applies rename (or star) before validating the move, so a bad move can leave the rename committed under a `400` response |
| L14 | `src/routes/files.cpp:276-281`, `src/routes/fs.cpp:149`, `src/routes/uploads.cpp:183-184` | File delete ignores the DB delete's return value before unlinking the blob, and ignores blob-unlink failures — can produce a dangling row or a leaked blob with no reconciliation |
| L15 | `src/routes/notes.cpp`, `src/routes/fs.cpp`, `src/db/database.cpp` | No per-user cap on notes/folders/files, and most list endpoints (`listNotes`, `listFiles`, `listFolders`, starred) return every row with no pagination |
| L16 | `schema.sql` vs `src/db/database.cpp:73-164` | `schema.sql` is badly drifted — missing `folders`/`notes`/`upload_sessions`/`app_meta` tables entirely, missing all E2E columns on `users`/`files`, and a weaker index than the one the code actually creates; anyone seeding a DB from the documented `sqlite3 data/cloud.db < schema.sql` gets a worse index forever (`IF NOT EXISTS` never upgrades it) |
| L17 | `web/app.js:92-101,966-973,1024,1031` | Blob-URL PDF preview `<iframe>` has no `sandbox` attribute, and its branch is selected by `mime.includes("pdf")` rather than an exact match |
| L18 | `src/http/middleware.cpp:176-181` | CSP comment is stale (claims `'unsafe-inline'` is needed for scripts; it isn't and isn't set); missing `base-uri 'self'`, `form-action 'self'`, `object-src 'none'` |
| L19 | `src/storage/file_store.cpp:36-38` | `FileStore::pathFor` is public and doesn't call the hex-key guard itself — safe today only because every caller's key originates from a server-written DB row |
| L20 | `src/storage/file_store.cpp:44,50,65` | Blob files/directories are created under the process umask (typically 0644/0755) with no `O_NOFOLLOW` — any other local account on the host can read ciphertext blobs |
| L21 | `web/sw.js:26-46` | Service worker caches any same-origin 200 GET response cache-first (not just the shell list), so an `app.js` security fix isn't seen until the *second* load after deploy |
| L22 | `src/routes/static_files.cpp:20-43` | The catch-all static route serves any file dropped into `web/`, relying on Crow's own path sanitizing rather than an explicit allowlist |
| L23 | `src/routes/uploads.cpp:92-93`, `src/routes/files.cpp:169` | `wrappedKey`/`X-Wrapped-Key` has no format/length validation, unlike `encName`/`encMime` which do |

### Informational

- `src/routes/auth.cpp:60-66` — `setUserKeys`'s return value is discarded and it isn't in the same transaction as `createUser`; a failure leaves an account with blank key material that can't recover.
- `SECURITY.md:19` says the server stores `scrypt(AUTH key)`; the code (`src/security/crypto.cpp`) uses PBKDF2-HMAC-SHA256, 200k iterations. `include/db/models.h:17`'s comment has the same "scrypt" drift. Low consequence (input is already a 256-bit derived key, not the raw password) but worth fixing the docs.
- `SECURITY.md:82` still lists file **mime type** as plaintext-visible-to-server; that was closed in Phase 3.5 (`enc_mime`, commit `73835bb`) — the doc needs a pass.
- `src/db/database.cpp:637,641-645` — E2E files have blank `name`/generic `mime`, so server-side name search and mime-based categories never match them (functional, not a vulnerability — tracked as ROADMAP Phase 3).
- No `UNIQUE(user_id, parent_id, name)` on folders/files — duplicate names are allowed (UX, not security).
- `src/db/database.cpp:919` — the 100000-step cycle-detection guard in `moveFolder` fails **open** (allows the move) if it's ever exhausted; currently unreachable since cycles can't otherwise be created.
- Route params like file/folder/note id are Crow `<int>` (32-bit) while DB ids are `int64_t`; ids above `2^31-1` are simply unreachable, not exploitable.
- `src/routes/files.cpp:151` — a malformed `X-Folder` header silently uploads to root instead of erroring.
- `src/routes/uploads.cpp:128-130` — `X-Offset` parsing accepts trailing garbage (`"12abc"` parses as `12`); harmless since the value must equal `received` anyway.

---

## Detail: the two High findings

### H1 — Rate limiter's XFF parsing hands the client its own identity

`src/security/rate_limiter.cpp:134-154` walks `X-Forwarded-For` left-to-right and takes the
first entry that isn't a trusted proxy, on the theory that "the leftmost non-trusted IP is the
real client." That's only true if the proxy **replaces** the header. The standard nginx
directive (`proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for`) **appends** instead,
so a client-supplied prefix survives and the real peer address ends up on the right.

Behind the exact reverse-proxy setup `SECURITY.md`/`ROADMAP.md` describe as the pre-exposure
plan (nginx on `127.0.0.1`, which is in `TRUSTED_PROXIES`), an attacker who sends
`X-Forwarded-For: 10.<rand>.<rand>.<rand>` gets a fresh rate-limit bucket on every request —
per-IP throttling, ban thresholds, and (once added) per-account login throttling are all
bypassed. The same trick lets an attacker frame a victim's real IP for a ban.

**Fix:** walk the header **right-to-left**, skipping trusted-proxy hops, and take the first
address that isn't one of them (i.e., the rightmost untrusted hop). Validate each token as an
IP literal before trusting it, and normalize IPv6 loopback forms (`::1`) so they match
`127.0.0.1` in `TRUSTED_PROXIES` — today they silently don't, which fails the *other* direction
(disables proxy handling entirely on an IPv6 stack).

### H2 — No upload quota; sessions never expire

`POST /api/uploads/init` (`src/routes/uploads.cpp:84-103`) accepts any authenticated (or
freshly self-registered, since registration is open) request declaring up to `MAX_FILE_MB`
(5 GB by default) per session, with no limit on how many sessions a user can have open and no
check against actual free disk or a per-account quota. Nothing in `src/db/database.cpp` or the
maintenance loop (`src/main.cpp:167-186`, which only purges expired *login* sessions) ever
sweeps abandoned `upload_sessions` rows or their blobs. A `size:0` session streams unbounded up
to `maxFileBytes` with the declared-size check skipped entirely.

**Fix:** enforce a per-user quota (sum of `usage()` + all open sessions' declared sizes) at
`init` and on every chunk append; cap concurrent open sessions per user; require `size > 0`;
add a TTL sweep to the maintenance thread that deletes the row and blob for sessions idle past
some threshold (e.g. 24h).

---

## Detail: the upload-race cluster (M1, M2 / H2's neighbors)

Two reviewers independently found the same root cause from different files, which is worth
calling out because it means both the server route and the client's retry behavior need to
change together:

- **M1 (`uploads.cpp:124-145`):** `PUT /api/uploads/<id>` reads `received`, compares to
  `X-Offset`, appends, and writes back the new `received` — as three separate, unlocked steps.
  Two concurrent PUTs at the same offset (a client retry racing the original request, which the
  existing 429-backoff/retry logic in `web/app.js` can trigger) both pass the check and both
  append, leaving the on-disk blob larger than what `received` records. `/complete` then fails
  `409 size mismatch` permanently, and the client's own offset-resync logic (reading the now
  wrong `received`) makes it worse instead of repairing it.
- **M2 (`uploads.cpp:156-170`):** the same non-atomicity applies to `/complete`: two concurrent
  completions of one session both insert a `files` row pointing at the same `storage_key`
  before either one deletes the upload session. Deleting either resulting file row unlinks the
  blob and corrupts the other.

**Fix (both):** serialize state changes per upload id (an in-process mutex keyed by upload id,
or a DB compare-and-swap — `UPDATE upload_sessions SET received=?new WHERE id=? AND
received=?old` performed before the append/completion, checking `changes()==1`); switch the
blob write from append-mode to an explicit-offset write (`pwrite`) so a duplicate PUT is
idempotent instead of additive; add a `UNIQUE(storage_key)` constraint on `files` so a
duplicate-completion race fails loudly (`SQLITE_CONSTRAINT`) instead of silently succeeding
twice.

---

## Verified safe (coverage, not just problems)

**Injection.** Every query in `src/db/database.cpp` is parameterized (`sqlite3_prepare_v2` +
bound `?`); the only dynamically assembled SQL (`searchFiles`, `renameFile`/`renameFolder`)
selects between hard-coded literal fragments, never user-controlled column/table/order names.
`LIKE` search terms are escaped (`likeTerm`, `ESCAPE '\'`) and length-capped.

**Cross-user authorization (IDOR).** Every id-taking query for files, folders, notes, upload
sessions, and API keys was checked and is scoped `WHERE id = ? AND user_id = ?` (or the
equivalent recursive-CTE `user_id` filter for folder trees). Every route handler authenticates
first and only ever uses the authenticated user id, never a client-supplied one. Cross-tenant
ids return a uniform 404 — no oracle for "not yours" vs. "doesn't exist."

**Path traversal.** File/folder display names are never used as filesystem paths — blobs use
server-generated 128-bit random hex keys, and `FileStore::isSafeKey` enforces a hex-only,
length-bounded key on every write path (`write`/`append`/`sizeOf`/`remove`). Client-supplied
names are validated for length, control characters (including a decoded `%00`), and path
separators before use as metadata.

**Auth core.** Passwords are PBKDF2-HMAC-SHA256 with a random per-user salt and a fail-closed
RNG (throws rather than emitting a zero buffer). Password-hash comparison is genuinely
constant-time (`constantTimeEquals`, full-length XOR accumulation). Sessions and API keys are
stored **only** as SHA-256 of a 256-bit-entropy server-minted token — no session fixation (the
server never accepts a client-supplied token), and no cross-user fallthrough between
`X-API-Key` → `Bearer` → cookie precedence.

**CSRF.** The authority check is a genuine exact match (`authorityOf` extracts and lowercases
`host[:port]`, compared with `==`), not the substring/`find()` bug this class of check is
usually vulnerable to — subdomain-suffix and prefix spoofing (`victimhost.attacker.com`,
`host.evil`) are both correctly rejected, and a missing/scheme-less `Origin` fails closed.

**Crypto client.** `web/app.js`'s implementation matches `CRYPTO_SPEC.md`: PBKDF2 310k
iterations split into AUTH key/KEK, AES-256-GCM with the documented `iv.ct` wrap format, and
the STREAM-style 1 MiB frame chunking with the frame index + final-flag bound into the AAD —
confirmed to reject reordering, truncation, and duplication. The DEK is never sent to the
server, and the KEK is imported as a non-extractable `CryptoKey`.

**No client-side injection sink.** A grep of `web/app.js` and `web/index.html` for
`innerHTML`/`outerHTML`/`insertAdjacentHTML`/`document.write`/`eval(`/`new Function(`/`srcdoc`
turned up nothing but a comment. All dynamic content (names, mime, previews, toasts, errors)
goes through `textContent` or element properties; decrypted bytes only ever become a `Blob`
URL, a re-encoded thumbnail data URL, or `<pre>.textContent`.

**Chunked-upload bounds** (independent of the race findings above): offsets must exactly equal
`received` (no sparse/out-of-order writes), the running total is clamped against both
`maxFileBytes` and the declared `size`, and `/complete` cross-checks on-disk size against both.

**Service worker.** Ignores every non-GET request and everything under `/api/`, so no
authenticated or cross-user response is ever cached; navigations are network-first; the cache
is explicitly versioned with old caches deleted on activate.

---

## Suggested remediation order

1. **H1** — fix XFF parsing direction (cheap, closes a real bypass of every rate limit).
2. **H2, M1, M2** — upload quota/expiry + atomic session state changes (closes real
   data-corruption and disk-exhaustion paths, all self-inflicted-but-real today).
3. **M11, M12** — bind wrapped keys/metadata to a file id in the AAD; stop treating a missing
   `wrappedKey` as "legacy plaintext" by default. This is a `CRYPTO_SPEC.md` version bump and
   needs a migration plan, but it's the one gap that actually breaks the "untrusted server"
   promise the spec makes.
4. **M3, M4, M5** — harden `deleteFolderRecursive`'s error handling, guard against
   folder-delete races, and cap folder nesting depth (the last one is also a cross-user DoS via
   the global exclusive lock).
5. **M6–M10** — auth/session hardening batch: per-account login throttling, fix `/register`
   enumeration, set `Secure` on the cookie, drop the redundant `localStorage` token, restrict
   API-key management to session auth.
6. Everything else in **Low**/**Informational** is cheap, mostly independent hardening —
   good candidates for a single cleanup pass (CSP directives, `schema.sql` regeneration,
   `pathFor` guard, iframe sandbox, static-route allowlist, doc drift).

---

## Method note

Three read-only reviews ran in parallel against this checkout, each restricted to a
non-overlapping file scope, and were told to explicitly document what they verified as
correct/safe (not just problems) and to cross-check `SECURITY.md`/`CRYPTO_SPEC.md` so already
-accepted residual risks weren't re-reported as new findings. No file was modified and no code
was executed as part of the review. This document is the consolidation of those three reports;
none of the fixes above have been applied yet.

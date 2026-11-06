// /api/events: who may connect, and who hears what.  node tests/events.node.js <base-http-url> <adminTok> <userTok> <apiKey>
const [BASE, TA, TU, KEY] = process.argv.slice(2);
const WS = BASE.replace(/^http/, "ws") + "/api/events";
const host = new URL(BASE).host;
let PASS = 0, FAIL = 0;
const ok = (c, m) => { if (c) { console.log("  PASS: " + m); PASS++; } else { console.log("  FAIL: " + m); FAIL++; } };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
function open(headers) {
  return new Promise((res) => {
    const ws = new WebSocket(WS, { headers });
    const got = [];
    ws.onmessage = (m) => got.push(JSON.parse(m.data).type);
    ws.onopen = () => res({ ws, got, open: true });
    ws.onerror = () => res({ ws, got, open: false });
  });
}
const post = (path, tok, body) => fetch(BASE + path, { method: "POST", headers: tok ? { authorization: "Bearer " + tok } : {}, body: JSON.stringify(body) }).then((r) => r.json().catch(() => ({})));
(async () => {
  ok(!(await open({})).open, "no session -> refused");
  ok(!(await open({ "X-API-Key": KEY })).open, "API key -> refused");
  ok(!(await open({ Cookie: "session=" + TA, Origin: "https://evil.example" })).open, "foreign Origin -> refused");
  const admin = await open({ Cookie: "session=" + TA, Origin: "http://" + host });
  const user = await open({ Cookie: "session=" + TU, Origin: "http://" + host });
  ok(admin.open && user.open, "admin and user connect (same-origin)");
  await post("/api/auth/register", null, { email: "evreq@e.cc", password: "supersecret" });   // a sign-up request
  await post("/api/admin/invites", TA, {});
  await post("/api/devices", TU, { name: "x", publicKey: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAAAA" });
  await sleep(500);
  ok(admin.got.includes("requests"), "admin hears 'requests'");
  ok(admin.got.includes("invites"), "admin hears 'invites'");
  ok(!user.got.includes("requests") && !user.got.includes("invites"), "normal user hears no admin events");
  ok(user.got.includes("devices"), "user hears their own 'devices'");
  ok(!admin.got.includes("devices"), "admin doesn't hear another user's devices");
  // everything else that changes reaches the owner's other tabs/devices
  const user2 = await open({ Cookie: "session=" + TU, Origin: "http://" + host });
  user.got.length = 0; admin.got.length = 0;
  const H = { authorization: "Bearer " + TU };
  await fetch(BASE + "/api/files", { method: "POST", headers: { ...H, "X-Filename": "e.txt" }, body: "x" });
  await fetch(BASE + "/api/folders", { method: "POST", headers: H, body: JSON.stringify({ parentId: 0, name: "d" }) });
  await fetch(BASE + "/api/notes", { method: "POST", headers: H, body: JSON.stringify({ title: "t", body: "b" }) });
  await fetch(BASE + "/api/auth/me/prefs", { method: "PATCH", headers: H, body: JSON.stringify({ displayName: "New" }) });
  const uid = (await (await fetch(BASE + "/api/auth/me", { headers: H })).json()).user.id;
  await fetch(BASE + "/api/admin/users/" + uid, { method: "PATCH", headers: { authorization: "Bearer " + TA }, body: JSON.stringify({ storageQuotaBytes: 5000000 }) });
  await sleep(500);
  for (const t of ["files", "notes", "me", "account"]) ok(user.got.includes(t) && user2.got.includes(t), `both of the user's tabs hear '${t}'`);
  ok(!admin.got.includes("files") && !admin.got.includes("notes"), "admin doesn't hear the user's files/notes");
  user2.ws.close();
  admin.ws.close(); user.ws.close();
  console.log(`\nRESULTS: ${PASS} passed, ${FAIL} failed`);
  process.exit(FAIL ? 1 : 0);
})();

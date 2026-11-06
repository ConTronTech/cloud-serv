// "updating" event reaches every signed-in tab.  node tests/update_notice.node.js <base> <tok> <stagedDir>
const fs = require("fs");
const [BASE, TOK, STAGED] = process.argv.slice(2);
const host = new URL(BASE).host;
(async () => {
  const ws = new WebSocket(BASE.replace(/^http/, "ws") + "/api/events", { headers: { Cookie: "session=" + TOK, Origin: "http://" + host } });
  const got = [];
  ws.onmessage = (m) => got.push(JSON.parse(m.data).type);
  await new Promise((r) => { ws.onopen = r; ws.onerror = r; });
  fs.mkdirSync(STAGED);
  await new Promise((r) => setTimeout(r, 3500));
  ws.close();
  process.exit(got.filter((t) => t === "updating").length === 1 ? 0 : 1);
})();

// cloud-serv service worker — caches the app shell so the PWA installs and the
// UI loads offline. API responses are never cached (always fresh + auth-scoped).

const CACHE = "cloud-serv-shell-v43";
const SHELL = [
  "/",
  "/index.html",
  "/style.css",
  "/app.js",
  "/favicon.svg",
  "/manifest.webmanifest",
];

// Shell files whose content changes on every deploy: always prefer a fresh
// fetch so a code (or security) fix is visible on the very next load, not the
// one after — cache is only the offline fallback here, refreshed on every hit.
// Assets that essentially never change (icon, manifest) stay cache-first below.
const NETWORK_FIRST = new Set(["/", "/index.html", "/style.css", "/app.js"]);

self.addEventListener("install", (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(SHELL)).then(() => self.skipWaiting()));
});

self.addEventListener("activate", (e) => {
  e.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k)))
    ).then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", (e) => {
  const req = e.request;
  const url = new URL(req.url);

  // Never touch the API or non-GET: go straight to the network.
  if (req.method !== "GET" || url.pathname.startsWith("/api/")) return;

  // Navigations + the live shell files: network-first. Only fall back to the
  // cache when the fetch itself fails (offline), and refresh the cache on
  // every successful fetch so the fallback doesn't go stale either.
  if (req.mode === "navigate" || NETWORK_FIRST.has(url.pathname)) {
    e.respondWith(
      fetch(req)
        .then((res) => {
          if (res.ok && url.origin === self.location.origin) {
            const copy = res.clone();
            caches.open(CACHE).then((c) => c.put(req, copy));
          }
          return res;
        })
        .catch(() => caches.match(req.mode === "navigate" ? "/index.html" : req))
    );
    return;
  }

  // Remaining static assets: cache-first, update cache in the background.
  e.respondWith(
    caches.match(req).then((hit) => {
      const net = fetch(req).then((res) => {
        if (res.ok && url.origin === self.location.origin) {
          const copy = res.clone();
          caches.open(CACHE).then((c) => c.put(req, copy));
        }
        return res;
      }).catch(() => hit);
      return hit || net;
    })
  );
});

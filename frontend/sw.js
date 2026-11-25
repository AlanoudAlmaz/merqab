// MIRGAB service worker: offline app shell, Web Push, notification taps.
// App files are fetched network-first (so updates show immediately) and fall back to the cache offline.
// API calls are never cached: analysis results and personal data stay out of the cache.
const CACHE = "mirqab-shell-v27";
const SHELL = ["/", "/index.html", "/css/app.css", "/js/app.js", "/js/core.js", "/manifest.webmanifest",
  "/assets/logo-mark.png", "/assets/logo-small.png", "/assets/falcon.png", "/assets/icons/icon-192.png", "/i18n/ar.json", "/i18n/en.json"];

self.addEventListener("install", (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(SHELL)).catch(() => {}).then(() => self.skipWaiting()));
});
self.addEventListener("activate", (e) => {
  e.waitUntil(caches.keys().then((ks) => Promise.all(ks.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
    .then(() => self.clients.claim()));
});
self.addEventListener("fetch", (e) => {
  const u = new URL(e.request.url);
  if (e.request.method !== "GET" || u.origin !== location.origin || u.pathname.startsWith("/api/")) return;
  e.respondWith(fetch(e.request).then((r) => {
    if (r.ok && r.type === "basic") { const copy = r.clone(); caches.open(CACHE).then((c) => c.put(e.request, copy)); }
    return r;
  }).catch(() => caches.match(e.request).then((r) => r || caches.match("/index.html"))));
});

self.addEventListener("push", (e) => {
  let d = {};
  try { d = e.data ? e.data.json() : {}; } catch { d = { title: "MIRGAB", body: e.data ? e.data.text() : "" }; }
  const title = String(d.title || "MIRGAB").slice(0, 120);
  const url = typeof d.url === "string" && d.url.startsWith("/") && !d.url.startsWith("//") ? d.url : "/#/shield";
  e.waitUntil(Promise.all([
    self.registration.showNotification(title, {
      body: String(d.body || "").slice(0, 300), icon: "/assets/icons/icon-192.png", badge: "/assets/icons/icon-192.png",
      tag: d.tag || "mirqab", renotify: true, data: { url, kind: d.kind || "alert", ts: d.ts || new Date().toISOString() },
    }),
    // tell open MIRGAB windows so the dashboard updates live
    self.clients.matchAll({ type: "window", includeUncontrolled: true })
      .then((cs) => cs.forEach((c) => c.postMessage({ type: "mirqab-push", title, body: d.body, kind: d.kind, url, ts: d.ts }))),
  ]));
});

self.addEventListener("notificationclick", (e) => {
  e.notification.close();
  const url = e.notification.data?.url || "/#/shield";
  e.waitUntil(self.clients.matchAll({ type: "window", includeUncontrolled: true }).then((cs) => {
    for (const c of cs) { if ("focus" in c) { c.navigate?.(url); return c.focus(); } }
    return self.clients.openWindow(url);
  }));
});

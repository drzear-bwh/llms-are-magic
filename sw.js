// Precache the whole show so it keeps working if the hotel Wi-Fi drops.
// Bump VERSION on every deploy so phones pick up the new files. Precaching
// bypasses the HTTP cache so a redeploy can't store stale copies.
const VERSION = "lam-v55";
const FILES = ["./","index.html","unlock.js","site.bin","css/style.css","media/tophat.svg","vendor/fonts/instrument-sans.woff2","vendor/fonts/jetbrains-mono.woff2"];

self.addEventListener("install", (e) => {
  e.waitUntil(caches.open(VERSION).then((c) => c.addAll(FILES.map((f) => new Request(f, { cache: "reload" })))).then(() => self.skipWaiting()));
});

self.addEventListener("activate", (e) => {
  e.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== VERSION).map((k) => caches.delete(k))))
      .then(() => self.clients.claim()),
  );
});

self.addEventListener("fetch", (e) => {
  if (e.request.method !== "GET" || new URL(e.request.url).origin !== location.origin) return;
  e.respondWith(caches.match(e.request, { ignoreSearch: true }).then((hit) => hit || fetch(e.request)));
});

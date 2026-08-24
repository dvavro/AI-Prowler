// AI-Prowler Remote PWA Service Worker
// Network-first strategy: always fetch fresh HTML from server.
// Only cache static assets (icons, manifest) — never index.html.

// CACHE's value is a placeholder — the server (ai_prowler_mcp.py's
// _patch_sw_cache_version(), 2026-08-24) replaces it at serve time with a
// content hash covering this file, index.html, and manifest.json, so any
// change to any of the three automatically produces a new value here.
// There's nothing to hand-bump anymore; editing this string has no effect.
const CACHE = 'auto';
const STATIC_ASSETS = ['/remote/manifest.json', '/remote/icon-192.png'];

self.addEventListener('install', e => {
  // Skip waiting so new SW activates immediately
  self.skipWaiting();
  e.waitUntil(
    caches.open(CACHE).then(c => c.addAll(STATIC_ASSETS).catch(() => {}))
  );
});

self.addEventListener('activate', e => {
  // Delete ALL old caches so stale index.html is gone
  e.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))
    ).then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);

  // NEVER cache index.html or the remote root — always go to network
  if (url.pathname === '/remote/' || url.pathname === '/remote/index.html') {
    e.respondWith(fetch(e.request).catch(() => caches.match(e.request)));
    return;
  }

  // Static assets: cache-first
  if (STATIC_ASSETS.some(a => url.pathname === a)) {
    e.respondWith(
      caches.match(e.request).then(cached => cached || fetch(e.request))
    );
    return;
  }

  // /remote-api and all other dynamic requests: network-only (never cached)
  // remote-api calls must always be fresh — no stale tool responses
  e.respondWith(fetch(e.request));
});

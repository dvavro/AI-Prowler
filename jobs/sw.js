// CACHE's value is a placeholder — the server (ai_prowler_mcp.py's
// _patch_sw_cache_version(), 2026-08-24) replaces it at serve time with a
// content hash covering this file, index.html, and manifest.json, so any
// change to any of the three automatically produces a new value here.
// There's nothing to hand-bump anymore; editing this string has no effect.
const CACHE = 'auto';
const OFFLINE_ASSETS = ['/jobs/', '/jobs/index.html', '/jobs/manifest.json'];

self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(OFFLINE_ASSETS)));
  self.skipWaiting();
});

self.addEventListener('activate', e => {
  e.waitUntil(caches.keys().then(keys =>
    Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))
  ));
  self.clients.claim();
});

// Found 2026-08-23: this used to be cache-first for everything except
// /mcp and anthropic requests — which meant /jobs/index.html itself (the
// app's own code, listed in OFFLINE_ASSETS) was served from whatever got
// cached at install time, forever, regardless of what actually changed on
// the server. A deployed code fix could sit invisible to an already-
// installed PWA indefinitely; only a hard refresh / cleared site data (or
// bumping CACHE, which forces a fresh install+activate) would ever pick
// it up. /pwa-api — the endpoint that actually fetches live spreadsheet
// data — wasn't covered by the "always fetch fresh" condition either.
//
// Now: network-first for everything. Every request tries the network
// first so code and data updates are picked up immediately; only on a
// genuine network failure (offline) does it fall back to whatever's in
// cache, so the app still works offline, it just isn't stale-by-default
// online.
self.addEventListener('fetch', e => {
  e.respondWith(
    fetch(e.request).then(function(res) {
      var resClone = res.clone();
      caches.open(CACHE).then(function(c) { c.put(e.request, resClone); }).catch(function(){});
      return res;
    }).catch(function() {
      return caches.match(e.request).then(function(cached) {
        if (cached) return cached;
        if (e.request.url.includes('/mcp') || e.request.url.includes('anthropic') || e.request.url.includes('/pwa-api')) {
          return new Response(
            JSON.stringify({ error: 'Offline — no network connection' }),
            { headers: { 'Content-Type': 'application/json' } }
          );
        }
        return new Response('Offline', { status: 503 });
      });
    })
  );
});

// CACHE_NAME is a placeholder — the server (ai_prowler_mcp.py's
// _patch_sw_cache_version()) replaces it at serve time with a content hash
// covering this file, index.html, and manifest.json. Any change to any of
// the three automatically produces a new cache key. Nothing to hand-bump.
// HR PWA mirrors jobs/sw.js exactly — same network-first strategy, same
// offline fallback shape, different mount point (/hr/) and cache prefix (hr-).
const CACHE = 'hr-auto';
const CACHE_NAME = 'hr-auto';
const OFFLINE_ASSETS = ['/hr/', '/hr/index.html', '/hr/manifest.json'];

self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE_NAME).then(c => c.addAll(OFFLINE_ASSETS)));
  self.skipWaiting();
});

self.addEventListener('activate', e => {
  e.waitUntil(caches.keys().then(keys =>
    Promise.all(keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k)))
  ));
  self.clients.claim();
});

// Network-first: always try the network so code and data updates are picked
// up immediately. Only fall back to cache on genuine network failure so the
// app remains usable offline without being stale-by-default online.
// Offline task completions are queued in localStorage and synced on reconnect.
self.addEventListener('fetch', e => {
  // Only handle GET requests — POST/PUT/PATCH/DELETE go straight to network
  if (e.request.method !== 'GET') return;
  e.respondWith(
    fetch(e.request).then(function(res) {
      var resClone = res.clone();
      caches.open(CACHE_NAME).then(function(c) { c.put(e.request, resClone); }).catch(function(){});
      return res;
    }).catch(function() {
      return caches.match(e.request).then(function(cached) {
        if (cached) return cached;
        if (
          e.request.url.includes('/mcp') ||
          e.request.url.includes('anthropic') ||
          e.request.url.includes('/hr-api')
        ) {
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

// Push notification handler — deep-links to the specific task's detail sheet
// when the notification is tapped (C-HR-PWA-06).
self.addEventListener('notificationclick', e => {
  e.notification.close();
  var taskId = e.notification.data && e.notification.data.task_id;
  var url = taskId ? '/hr/?task=' + taskId : '/hr/';
  e.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then(function(clients) {
      for (var i = 0; i < clients.length; i++) {
        if (clients[i].url.startsWith(self.location.origin + '/hr/') && 'focus' in clients[i]) {
          clients[i].focus();
          clients[i].postMessage({ type: 'OPEN_TASK', task_id: taskId });
          return;
        }
      }
      return self.clients.openWindow(url);
    })
  );
});

// Service-worker update banner: mirrors jobs/sw.js — broadcasts
// 'SW_UPDATE_AVAILABLE' to all controlled clients when a new version is
// waiting, so index.html can show the update-available banner.
self.addEventListener('message', e => {
  if (e.data && e.data.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }
});

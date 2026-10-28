// AI-Prowler Service Desk service worker.
// CACHE's value is a placeholder - the server (ai_prowler_mcp.py's
// _patch_sw_cache_version) replaces it at serve time with a content hash of
// this folder's files, so every deploy installs fresh. Network-first for the
// app shell; /desk-api (ticket data, attachments) is NEVER cached, so a
// signed-out phone keeps no customer data and nothing shown is ever stale.
const CACHE = 'auto';
const OFFLINE_ASSETS = ['/desk/', '/desk/index.html', '/desk/manifest.json'];

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

self.addEventListener('fetch', e => {
  const url = e.request.url;
  if (url.includes('/desk-api') || url.includes('/pwa-') || e.request.method !== 'GET') {
    return;   // straight to the network, never cached
  }
  e.respondWith(
    fetch(e.request).then(res => {
      const copy = res.clone();
      caches.open(CACHE).then(c => c.put(e.request, copy)).catch(() => {});
      return res;
    }).catch(() => caches.match(e.request).then(c => c || new Response('Offline', { status: 503 })))
  );
});

// Web push (alerts) - shown even when the app is closed.
self.addEventListener('push', e => {
  let d = {};
  try { d = e.data ? e.data.json() : {}; } catch (_) { d = { title: 'Service Desk', body: e.data && e.data.text() }; }
  e.waitUntil(self.registration.showNotification(d.title || 'Service Desk', {
    body: d.body || '', tag: d.ticket_id || 'desk', data: { url: d.url || '/desk/' },
    icon: '/desk/icon-192.png', badge: '/desk/icon-192.png'
  }));
});

self.addEventListener('notificationclick', e => {
  e.notification.close();
  const target = (e.notification.data && e.notification.data.url) || '/desk/';
  e.waitUntil(clients.matchAll({ type: 'window', includeUncontrolled: true }).then(list => {
    for (const c of list) { if (c.url.includes('/desk/')) { c.navigate(target); return c.focus(); } }
    return clients.openWindow(target);
  }));
});

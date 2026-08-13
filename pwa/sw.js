const CACHE = 'aiprowler-v1';
const OFFLINE_ASSETS = ['/pwa/', '/pwa/index.html', '/pwa/manifest.json'];

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
  if (e.request.url.includes('/mcp') || e.request.url.includes('anthropic')) {
    e.respondWith(fetch(e.request).catch(() => new Response(
      JSON.stringify({ error: 'Offline — no network connection' }),
      { headers: { 'Content-Type': 'application/json' } }
    )));
  } else {
    e.respondWith(
      caches.match(e.request).then(cached => cached || fetch(e.request))
    );
  }
});

// Build service worker — caches the app shell for offline use
const CACHE_NAME = 'build-shell-1';
const APP_SHELL = [
  './',
  './index.html',
  './manifest.json',
  './icon.svg',
  'https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js'
];

self.addEventListener('install', e => {
  e.waitUntil(
    caches.open(CACHE_NAME).then(c => c.addAll(APP_SHELL.map(u => new Request(u, {cache: 'reload'}))))
      .then(() => self.skipWaiting())
      .catch(err => console.error('SW install failed', err))
  );
});

self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k)))
    ).then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);
  // Don't intercept USDA API requests — they need fresh data
  if (url.hostname === 'api.nal.usda.gov') return;
  // Cache-first for app shell, network fallback
  e.respondWith(
    caches.match(e.request).then(cached => {
      if (cached) return cached;
      return fetch(e.request).then(resp => {
        // Cache new GETs from our own origin or known CDNs
        if (e.request.method === 'GET' && (url.origin === location.origin || url.hostname.includes('jsdelivr'))) {
          const clone = resp.clone();
          caches.open(CACHE_NAME).then(c => c.put(e.request, clone));
        }
        return resp;
      }).catch(() => {
        // Offline fallback: try to return the main page for navigation requests
        if (e.request.mode === 'navigate') return caches.match('./index.html');
      });
    })
  );
});

// ===== Push notification handlers =====
self.addEventListener('push', event => {
  let data = {title: 'Build', body: 'Notification', icon: './icon-192.png'};
  try {
    if (event.data) data = {...data, ...event.data.json()};
  } catch (e) {
    if (event.data) data.body = event.data.text();
  }
  const opts = {
    body: data.body,
    icon: data.icon || './icon-192.png',
    badge: data.badge || './icon-192.png',
    tag: data.tag || 'build-default',
    data: {url: data.url || './', ...data.data},
    requireInteraction: !!data.requireInteraction,
    vibrate: data.vibrate || [80, 40, 80]
  };
  event.waitUntil(self.registration.showNotification(data.title, opts));
});

self.addEventListener('notificationclick', event => {
  event.notification.close();
  const targetUrl = event.notification.data?.url || './';
  event.waitUntil(
    self.clients.matchAll({type: 'window', includeUncontrolled: true}).then(clients => {
      // Focus existing window if any
      for (const client of clients) {
        if ('focus' in client) {
          client.focus();
          if (targetUrl && targetUrl !== './' && 'navigate' in client) client.navigate(targetUrl);
          return;
        }
      }
      // Otherwise open new
      if (self.clients.openWindow) return self.clients.openWindow(targetUrl);
    })
  );
});

// Re-subscribe automatically if the browser rotates the subscription
self.addEventListener('pushsubscriptionchange', event => {
  event.waitUntil(
    self.registration.pushManager.subscribe({userVisibleOnly: true, applicationServerKey: event.oldSubscription?.options?.applicationServerKey})
      .then(sub => {
        // Notify any open clients so they can re-register with the backend
        return self.clients.matchAll().then(clients => {
          for (const c of clients) c.postMessage({type: 'pushsubscriptionchange', subscription: sub.toJSON()});
        });
      })
  );
});

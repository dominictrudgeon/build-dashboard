// Build service worker — caches the app shell for offline use
const CACHE_NAME = 'build-shell-2';
const APP_SHELL = [
  './',
  './index.html',
  './manifest.json',
  './icon.svg',
  './icon-192.png',
  './icon-512.png',
  'https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js'
];
 
self.addEventListener('install', e => {
  e.waitUntil(
    caches.open(CACHE_NAME).then(async cache => {
      // Fetch each URL manually with redirect:'follow' so we cache the final, non-redirected response.
      // This prevents iOS Safari's "response has redirections" error.
      for (const url of APP_SHELL) {
        try {
          const resp = await fetch(url, {cache: 'reload', redirect: 'follow'});
          if (resp.ok && !resp.redirected) {
            await cache.put(url, resp);
          } else if (resp.ok && resp.redirected) {
            // Re-fetch the final URL and cache under both keys
            const clean = await fetch(resp.url, {cache: 'reload'});
            if (clean.ok) await cache.put(url, clean);
          }
        } catch (err) {
          console.warn('SW pre-cache failed for', url, err.message);
        }
      }
    })
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
  // Don't intercept USDA API or any non-GET requests — they need direct network
  if (url.hostname === 'api.nal.usda.gov') return;
  if (e.request.method !== 'GET') return;
  // Don't intercept worker API calls (sync, push subscribe, etc) — must hit network
  if (url.hostname.includes('workers.dev')) return;
 
  e.respondWith(
    caches.match(e.request).then(cached => {
      if (cached) return cached;
      return fetch(e.request, {redirect: 'follow'}).then(async resp => {
        // If the response is a redirect, follow it and return the clean version
        // (don't return redirected responses from a SW — iOS rejects them)
        if (resp.redirected) {
          const clean = await fetch(resp.url);
          // Cache the clean response under the original request URL
          if (clean.ok && (url.origin === location.origin || url.hostname.includes('jsdelivr'))) {
            const cloneForCache = clean.clone();
            caches.open(CACHE_NAME).then(c => c.put(e.request, cloneForCache));
          }
          return clean;
        }
        // Normal non-redirected response — cache + return
        if (resp.ok && (url.origin === location.origin || url.hostname.includes('jsdelivr'))) {
          const clone = resp.clone();
          caches.open(CACHE_NAME).then(c => c.put(e.request, clone));
        }
        return resp;
      }).catch(() => {
        // Offline fallback for navigation
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

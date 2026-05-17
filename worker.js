// =============================================================================
// Build — push notification Cloudflare Worker
//
// Provides:
//   POST /subscribe       store push subscription + reminder preferences
//   POST /preferences     update preferences only
//   POST /unsubscribe     delete subscription
//   POST /test            send a test notification to the caller's subscription
//   GET  /vapid-public    return VAPID public key (for fallback / debug)
//   (cron) "*/15 * * * *" scan subscriptions and send due reminders
//
// Storage: Cloudflare KV namespace bound as `SUBSCRIPTIONS`
// Secrets:  VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY, VAPID_SUBJECT (e.g. mailto:you@example.com)
//
// CORS: allows the app's origin (set via APP_ORIGIN env var).
// =============================================================================

// ---- CORS helpers ----
function corsHeaders(req, env) {
  const origin = req.headers.get('Origin') || '';
  const allowed = (env.APP_ORIGIN || '').split(',').map(s => s.trim()).filter(Boolean);
  const allowOrigin = allowed.includes(origin) || allowed.includes('*') ? origin : (allowed[0] || '*');
  return {
    'Access-Control-Allow-Origin': allowOrigin,
    'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Max-Age': '86400',
    'Vary': 'Origin'
  };
}
function json(body, status, req, env) {
  return new Response(JSON.stringify(body), {
    status: status || 200,
    headers: {'Content-Type': 'application/json', ...corsHeaders(req, env)}
  });
}

// ---- Base64 url helpers ----
function b64urlToBytes(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function bytesToB64url(bytes) {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function strToBytes(s) { return new TextEncoder().encode(s); }
function concatBytes(...arrs) {
  let total = 0;
  for (const a of arrs) total += a.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrs) { out.set(a, off); off += a.length; }
  return out;
}

// ---- VAPID JWT (ES256) ----
async function importVapidPrivate(b64) {
  // Private key is 32 bytes, but JWK import wants both d, x, y
  // We accept either raw 32-byte private key or full JWK JSON
  if (b64.startsWith('{')) {
    return crypto.subtle.importKey('jwk', JSON.parse(b64), {name: 'ECDSA', namedCurve: 'P-256'}, false, ['sign']);
  }
  // Raw 32-byte → reconstruct via importing pkcs8? We'd need the public key too.
  // For simplicity, require JWK format. Throw helpful error if raw is provided.
  throw new Error('VAPID_PRIVATE_KEY must be JWK JSON format. Run scripts/gen-vapid.mjs to generate.');
}

async function vapidJWT(endpoint, env) {
  const url = new URL(endpoint);
  const aud = `${url.protocol}//${url.host}`;
  const header = {typ: 'JWT', alg: 'ES256'};
  const payload = {
    aud,
    exp: Math.floor(Date.now() / 1000) + 12 * 3600, // 12h
    sub: env.VAPID_SUBJECT || 'mailto:nobody@example.com'
  };
  const headerB64 = bytesToB64url(strToBytes(JSON.stringify(header)));
  const payloadB64 = bytesToB64url(strToBytes(JSON.stringify(payload)));
  const signingInput = `${headerB64}.${payloadB64}`;
  const privKey = await importVapidPrivate(env.VAPID_PRIVATE_KEY);
  const sigBuf = await crypto.subtle.sign({name: 'ECDSA', hash: 'SHA-256'}, privKey, strToBytes(signingInput));
  const sig = new Uint8Array(sigBuf);
  return `${signingInput}.${bytesToB64url(sig)}`;
}

// ---- Web push payload encryption (RFC 8291, aes128gcm content encoding) ----
// Steps:
//   1. Generate ephemeral ECDH P-256 keypair (server)
//   2. ECDH(server_priv, ua_pub) → IKM
//   3. PRK_key = HKDF-Extract(auth_secret, IKM); info = "WebPush: info\0" || ua_pub || server_pub
//   4. IKM_2 = HKDF-Expand(PRK_key, info, 32)
//   5. CEK = HKDF-Expand(IKM_2, "Content-Encoding: aes128gcm\0", 16) using random salt
//   6. NONCE = HKDF-Expand(IKM_2, "Content-Encoding: nonce\0", 12)
//   7. Encrypt payload+\x02 with AES-128-GCM(CEK, NONCE)
//   8. Body = salt(16) || rs(4) || idlen(1) || keyid(idlen) || ciphertext
async function hkdfExpand(prk, info, length) {
  const baseKey = await crypto.subtle.importKey('raw', prk, 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    {name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info},
    baseKey, length * 8
  );
  return new Uint8Array(bits);
}
async function hkdfExtract(salt, ikm) {
  // HMAC-SHA256(salt, ikm)
  const key = await crypto.subtle.importKey('raw', salt, {name: 'HMAC', hash: 'SHA-256'}, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, ikm);
  return new Uint8Array(sig);
}

async function encryptPayload(payloadBytes, subscription) {
  const uaPublic = b64urlToBytes(subscription.keys.p256dh);
  const authSecret = b64urlToBytes(subscription.keys.auth);

  // Ephemeral ECDH keypair
  const ephKeyPair = await crypto.subtle.generateKey(
    {name: 'ECDH', namedCurve: 'P-256'}, true, ['deriveBits']
  );
  // Export server public as raw (65 bytes uncompressed point: 0x04 || X || Y)
  const serverPublicRaw = new Uint8Array(await crypto.subtle.exportKey('raw', ephKeyPair.publicKey));

  // Import UA public key
  const uaPubKey = await crypto.subtle.importKey(
    'raw', uaPublic, {name: 'ECDH', namedCurve: 'P-256'}, false, []
  );
  // ECDH shared secret
  const ikm = new Uint8Array(await crypto.subtle.deriveBits(
    {name: 'ECDH', public: uaPubKey}, ephKeyPair.privateKey, 256
  ));

  // PRK_key = HMAC-SHA256(auth_secret, ikm)
  const prkKey = await hkdfExtract(authSecret, ikm);
  // info1 = "WebPush: info\x00" || ua_public || server_public
  const info1 = concatBytes(strToBytes('WebPush: info\0'), uaPublic, serverPublicRaw);
  const ikm2 = await hkdfExpand(prkKey, info1, 32);

  // Random salt (16 bytes)
  const salt = crypto.getRandomValues(new Uint8Array(16));
  // PRK = HMAC-SHA256(salt, ikm2)
  const prk = await hkdfExtract(salt, ikm2);

  // CEK = HKDF-Expand(prk, "Content-Encoding: aes128gcm\0", 16)
  const cek = await hkdfExpand(prk, strToBytes('Content-Encoding: aes128gcm\0'), 16);
  // NONCE = HKDF-Expand(prk, "Content-Encoding: nonce\0", 12)
  const nonce = await hkdfExpand(prk, strToBytes('Content-Encoding: nonce\0'), 12);

  // Plaintext: payload || 0x02 (delimiter, no padding)
  const plaintext = concatBytes(payloadBytes, new Uint8Array([0x02]));
  // Encrypt
  const aesKey = await crypto.subtle.importKey('raw', cek, 'AES-GCM', false, ['encrypt']);
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
    {name: 'AES-GCM', iv: nonce}, aesKey, plaintext
  ));

  // Body framing: salt(16) || rs(4, BE uint32) || idlen(1) || keyid(idlen) || ciphertext
  const rs = new Uint8Array(4);
  // Record size = 4096 (just a recommendation; needs > body size)
  rs[0] = 0; rs[1] = 0; rs[2] = 0x10; rs[3] = 0x00; // 4096
  const idlen = new Uint8Array([serverPublicRaw.length]); // 65
  const body = concatBytes(salt, rs, idlen, serverPublicRaw, ciphertext);
  return body;
}

// ---- Send one push ----
async function sendPush(subscription, payload, env) {
  const payloadBytes = strToBytes(typeof payload === 'string' ? payload : JSON.stringify(payload));
  const body = await encryptPayload(payloadBytes, subscription);
  const jwt = await vapidJWT(subscription.endpoint, env);
  const headers = {
    'Authorization': `vapid t=${jwt}, k=${env.VAPID_PUBLIC_KEY}`,
    'Content-Encoding': 'aes128gcm',
    'Content-Type': 'application/octet-stream',
    'TTL': '86400',
    'Urgency': 'normal'
  };
  const resp = await fetch(subscription.endpoint, {method: 'POST', headers, body});
  return resp;
}

// ---- Reminder scheduling ----
// Each subscription stores: {endpoint, keys, prefs: {tz, morning, prePm, preAm, postWorkout, evening}}
// Cron tick: figure out user-local time from prefs.tz, fire any reminder whose minute matches.
function userLocalMinute(now, tzOffsetMin) {
  // tzOffsetMin = minutes offset from UTC (e.g. -300 for EST)
  const local = new Date(now.getTime() + tzOffsetMin * 60 * 1000);
  return {hours: local.getUTCHours(), minutes: local.getUTCMinutes(), day: local.getUTCDay()};
}
function isWithinWindow(target, now, windowMin) {
  // target = {h, m}, now = {hours, minutes}
  const tMin = target.h * 60 + target.m;
  const nMin = now.hours * 60 + now.minutes;
  return Math.abs(tMin - nMin) <= windowMin;
}

async function scanAndSendReminders(env) {
  // List all subscription keys
  const list = await env.SUBSCRIPTIONS.list({prefix: 'sub:'});
  const now = new Date();
  let sent = 0, failed = 0;
  for (const key of list.keys) {
    const raw = await env.SUBSCRIPTIONS.get(key.name);
    if (!raw) continue;
    let entry;
    try { entry = JSON.parse(raw); } catch { continue; }
    const prefs = entry.prefs || {};
    if (!prefs.enabled) continue;
    const tz = prefs.tz || 0;
    const local = userLocalMinute(now, tz);
    const reminders = [];
    // Morning check-in
    if (prefs.morning?.enabled && isWithinWindow(prefs.morning, local, 5)) {
      reminders.push({
        title: '☀️ Morning check-in',
        body: 'Log HRV, RHR, sleep + sliders to get your daily prescription.',
        tag: 'morning', url: './'
      });
    }
    // Pre-AM workout (90 min before amSessionTime)
    if (prefs.preAm?.enabled && isWithinWindow(prefs.preAm, local, 5)) {
      reminders.push({
        title: '🍌 Pre-workout fuel',
        body: prefs.preAm.body || 'AM session in ~90 min — fuel up. Open Build for today\'s carb target.',
        tag: 'preAm', url: './'
      });
    }
    // Pre-PM workout
    if (prefs.prePm?.enabled && isWithinWindow(prefs.prePm, local, 5)) {
      reminders.push({
        title: '🍌 Pre-workout fuel',
        body: prefs.prePm.body || 'PM session in ~90 min — fuel up. Open Build for today\'s target.',
        tag: 'prePm', url: './'
      });
    }
    // Post-workout
    if (prefs.postAm?.enabled && isWithinWindow(prefs.postAm, local, 5)) {
      reminders.push({title: '🥛 Recovery window open', body: 'Hit your protein + carb post-workout target within the next hour.', tag: 'postAm', url: './'});
    }
    if (prefs.postPm?.enabled && isWithinWindow(prefs.postPm, local, 5)) {
      reminders.push({title: '🥛 Recovery window open', body: 'Hit your protein + carb post-workout target within the next hour.', tag: 'postPm', url: './'});
    }
    // Evening macro check
    if (prefs.evening?.enabled && isWithinWindow(prefs.evening, local, 5)) {
      reminders.push({title: '🌙 Evening review', body: 'Quick check: macros, hydration, tomorrow\'s session prep.', tag: 'evening', url: './'});
    }

    // Send each
    for (const r of reminders) {
      try {
        const resp = await sendPush({endpoint: entry.endpoint, keys: entry.keys}, r, env);
        if (resp.status === 410 || resp.status === 404) {
          await env.SUBSCRIPTIONS.delete(key.name); // expired
        } else if (resp.ok || resp.status === 201) {
          sent++;
        } else {
          failed++;
          console.error('Push fail', resp.status, await resp.text());
        }
      } catch (e) {
        failed++;
        console.error('Push throw', e.message);
      }
    }
  }
  return {sent, failed, scanned: list.keys.length};
}

// ---- Subscription key derivation ----
async function subscriptionKey(endpoint) {
  const buf = await crypto.subtle.digest('SHA-256', strToBytes(endpoint));
  return 'sub:' + bytesToB64url(new Uint8Array(buf)).slice(0, 24);
}

// ---- Request handler ----
export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (req.method === 'OPTIONS') {
      return new Response(null, {headers: corsHeaders(req, env)});
    }

    if (req.method === 'GET' && url.pathname === '/vapid-public') {
      return json({vapidPublic: env.VAPID_PUBLIC_KEY}, 200, req, env);
    }

    if (req.method === 'POST' && url.pathname === '/subscribe') {
      const body = await req.json().catch(() => null);
      if (!body || !body.subscription?.endpoint) return json({error: 'subscription required'}, 400, req, env);
      const key = await subscriptionKey(body.subscription.endpoint);
      const entry = {
        endpoint: body.subscription.endpoint,
        keys: body.subscription.keys,
        prefs: body.prefs || {enabled: true},
        createdAt: Date.now()
      };
      await env.SUBSCRIPTIONS.put(key, JSON.stringify(entry));
      return json({ok: true, id: key}, 200, req, env);
    }

    if (req.method === 'POST' && url.pathname === '/preferences') {
      const body = await req.json().catch(() => null);
      if (!body?.endpoint || !body?.prefs) return json({error: 'endpoint+prefs required'}, 400, req, env);
      const key = await subscriptionKey(body.endpoint);
      const raw = await env.SUBSCRIPTIONS.get(key);
      if (!raw) return json({error: 'not subscribed'}, 404, req, env);
      const entry = JSON.parse(raw);
      entry.prefs = body.prefs;
      await env.SUBSCRIPTIONS.put(key, JSON.stringify(entry));
      return json({ok: true}, 200, req, env);
    }

    if ((req.method === 'POST' || req.method === 'DELETE') && url.pathname === '/unsubscribe') {
      const body = await req.json().catch(() => null);
      if (!body?.endpoint) return json({error: 'endpoint required'}, 400, req, env);
      const key = await subscriptionKey(body.endpoint);
      await env.SUBSCRIPTIONS.delete(key);
      return json({ok: true}, 200, req, env);
    }

    if (req.method === 'POST' && url.pathname === '/test') {
      const body = await req.json().catch(() => null);
      if (!body?.endpoint) return json({error: 'endpoint required'}, 400, req, env);
      const key = await subscriptionKey(body.endpoint);
      const raw = await env.SUBSCRIPTIONS.get(key);
      if (!raw) return json({error: 'not subscribed'}, 404, req, env);
      const entry = JSON.parse(raw);
      try {
        const resp = await sendPush(
          {endpoint: entry.endpoint, keys: entry.keys},
          {title: '✅ Build push working', body: 'Notifications are live.', tag: 'test'},
          env
        );
        return json({ok: resp.ok || resp.status === 201, status: resp.status}, 200, req, env);
      } catch (e) {
        return json({error: e.message, stack: e.stack?.slice(0, 500)}, 500, req, env);
      }
    }

    return json({service: 'build-push', endpoints: ['/subscribe', '/preferences', '/unsubscribe', '/test', '/vapid-public']}, 200, req, env);
  },

  async scheduled(event, env, ctx) {
    ctx.waitUntil(scanAndSendReminders(env).then(r => console.log('Reminder scan', r)));
  }
};

#!/usr/bin/env node
// Generate a VAPID keypair using Node's built-in webcrypto.
// Outputs:
//   - VAPID_PUBLIC_KEY  (base64url, raw uncompressed P-256 point, 65 bytes)
//   - VAPID_PRIVATE_KEY (JWK JSON — required format for the worker)
//
// Usage:  node gen-vapid.mjs

import { webcrypto } from 'node:crypto';
const subtle = webcrypto.subtle;

function bytesToB64url(bytes) {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return Buffer.from(bin, 'binary').toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

const kp = await subtle.generateKey({name: 'ECDSA', namedCurve: 'P-256'}, true, ['sign', 'verify']);

// Export public as raw (65-byte uncompressed P-256 point)
const pubRaw = new Uint8Array(await subtle.exportKey('raw', kp.publicKey));
const pubB64url = bytesToB64url(pubRaw);

// Export private as JWK
const privJwk = await subtle.exportKey('jwk', kp.privateKey);

console.log('--- VAPID keys generated ---\n');
console.log('VAPID_PUBLIC_KEY (paste into worker secret AND into your app):');
console.log(pubB64url);
console.log('\nVAPID_PRIVATE_KEY (paste into worker secret only; keep secret):');
console.log(JSON.stringify(privJwk));
console.log('\nVAPID_SUBJECT (paste into worker secret; replace with your real email):');
console.log('mailto:you@example.com');
console.log('\n--- Setup commands ---\n');
console.log('wrangler secret put VAPID_PUBLIC_KEY    # paste public');
console.log('wrangler secret put VAPID_PRIVATE_KEY   # paste JWK JSON in one line');
console.log('wrangler secret put VAPID_SUBJECT       # paste mailto:');

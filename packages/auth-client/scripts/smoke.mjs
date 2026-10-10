import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { hasPermission, hasRole, isPlatformAdmin, verifyToken } from '../dist/index.js';

const SECRET = 'dev-secret-at-least-32-bytes-long-0000';

const b64url = (value) => Buffer.from(value).toString('base64url');

function mint(payload) {
  const header = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body = b64url(JSON.stringify(payload));
  const signature = createHmac('sha256', SECRET).update(`${header}.${body}`).digest('base64url');
  return `${header}.${body}.${signature}`;
}

const now = Math.floor(Date.now() / 1000);
const token = mint({
  sub: 'alice',
  jti: 'jti-1',
  pid: 'project-1',
  proj: 'DUKAANDAAR',
  roles: ['admin', 'user'],
  perms: ['order:read', 'project:manage'],
  platformAdmin: false,
  iat: now,
  exp: now + 3600,
});

const { claims } = await verifyToken(token, { secret: SECRET });
assert.equal(claims.sub, 'alice');
assert.equal(claims.proj, 'DUKAANDAAR');
assert.deepEqual(claims.roles, ['ADMIN', 'USER']);
assert.ok(hasRole(claims, 'admin'));
assert.ok(hasPermission(claims, 'order:read'));
assert.equal(isPlatformAdmin(claims), false);

await assert.rejects(() => verifyToken(`${token.slice(0, -2)}xx`, { secret: SECRET }), /signature/i);

const expired = mint({ sub: 'bob', roles: [], perms: [], platformAdmin: false, exp: now - 10 });
await assert.rejects(() => verifyToken(expired, { secret: SECRET }), /expired/i);

const admin = mint({ sub: 'root', roles: [], perms: [], platformAdmin: true, exp: now + 60 });
const adminVerified = await verifyToken(admin, { secret: SECRET });
assert.equal(isPlatformAdmin(adminVerified.claims), true);

console.log('auth-client smoke test: OK');

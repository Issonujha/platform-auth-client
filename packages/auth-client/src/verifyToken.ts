import { base64UrlToBytes, stringToBytes } from './base64url.js';
import { InvalidTokenError, TokenExpiredError } from './errors.js';

/** Claims minted by auth-service on a project-scoped platform token. */
export interface PlatformClaims {
  /** Username, or the service-client id for client-credentials tokens. */
  sub: string;
  /** Unique token id. */
  jti?: string;
  /** Project id the token is scoped to (absent on platform login tokens). */
  pid?: string;
  /** Project code the token is scoped to. */
  proj?: string;
  /** Project role codes (upper-cased). */
  roles: string[];
  /** Flattened permission strings. */
  perms: string[];
  /** True only for platform-level SUPER_ADMIN tokens. */
  platformAdmin: boolean;
  /** Present on client-credentials tokens. */
  clientId?: string;
  /** e.g. "client_credentials". */
  grantType?: string;
  iat?: number;
  exp?: number;
  [claim: string]: unknown;
}

export interface VerifyOptions {
  /** Shared HS256 secret (the same JWT_SECRET auth-service signs with). */
  secret: string;
  /** Clock skew tolerance in seconds (default 0). */
  leewaySeconds?: number;
  /** Override "now" in seconds since epoch (mainly for tests). */
  nowSeconds?: number;
  /** Algorithms accepted. Defaults to ["HS256"]. */
  algorithms?: string[];
  /** Inject a SubtleCrypto implementation in runtimes without a global one. */
  subtle?: SubtleCrypto;
}

export interface VerifiedToken<T extends PlatformClaims = PlatformClaims> {
  claims: T;
  header: { alg: string; typ?: string; [k: string]: unknown };
  signature: string;
}

interface RawPayload {
  [claim: string]: unknown;
}

function toStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.filter((item): item is string => typeof item === 'string');
}

function decodeSegment<T>(segment: string): T {
  try {
    const json = JSON.parse(new TextDecoder().decode(base64UrlToBytes(segment))) as T;
    if (json === null || typeof json !== 'object') {
      throw new Error('not an object');
    }
    return json;
  } catch (error) {
    throw new InvalidTokenError(`Malformed token segment: ${(error as Error).message}`);
  }
}

/**
 * Verifies an HS256 platform token's signature and expiry, then returns the
 * canonicalised claims. Signature verification uses WebCrypto; no network calls.
 */
export async function verifyToken<T extends PlatformClaims = PlatformClaims>(
  token: string,
  options: VerifyOptions,
): Promise<VerifiedToken<T>> {
  if (!token || typeof token !== 'string') {
    throw new InvalidTokenError('Token is required');
  }
  if (!options || !options.secret) {
    throw new InvalidTokenError('A shared secret is required to verify the token');
  }

  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new InvalidTokenError('Token must have three segments');
  }
  const [encodedHeader, encodedPayload, signature] = parts;

  const header = decodeSegment<{ alg: string; typ?: string }>(encodedHeader);
  const algorithms = options.algorithms ?? ['HS256'];
  if (!algorithms.includes(header.alg)) {
    throw new InvalidTokenError(`Unsupported token algorithm: ${header.alg}`);
  }

  const subtle = options.subtle ?? (globalThis as { crypto?: Crypto }).crypto?.subtle;
  if (!subtle) {
    throw new InvalidTokenError('No SubtleCrypto available; pass options.subtle');
  }

  const key = await subtle.importKey('raw', stringToBytes(options.secret), { name: 'HMAC', hash: 'SHA-256' }, false, [
    'verify',
  ]);
  const valid = await subtle.verify(
    'HMAC',
    key,
    base64UrlToBytes(signature),
    stringToBytes(`${encodedHeader}.${encodedPayload}`),
  );
  if (!valid) {
    throw new InvalidTokenError('Token signature is invalid');
  }

  const raw = decodeSegment<RawPayload>(encodedPayload);
  const now = options.nowSeconds ?? Math.floor(Date.now() / 1000);
  const leeway = options.leewaySeconds ?? 0;

  if (typeof raw.exp === 'number' && raw.exp + leeway < now) {
    throw new TokenExpiredError('Token has expired');
  }
  if (typeof raw.nbf === 'number' && raw.nbf - leeway > now) {
    throw new InvalidTokenError('Token is not yet valid');
  }

  const claims: PlatformClaims = {
    ...raw,
    sub: typeof raw.sub === 'string' ? raw.sub : '',
    roles: toStringArray(raw.roles).map((role) => role.toUpperCase()),
    perms: toStringArray(raw.perms),
    platformAdmin: raw.platformAdmin === true,
  };

  return { claims: claims as T, header, signature };
}

/** Decodes claims without verifying the signature. Never trust this for authz. */
export function decodeToken(token: string): PlatformClaims {
  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new InvalidTokenError('Token must have three segments');
  }
  const raw = decodeSegment<RawPayload>(parts[1]);
  return {
    ...raw,
    sub: typeof raw.sub === 'string' ? raw.sub : '',
    roles: toStringArray(raw.roles).map((role) => role.toUpperCase()),
    perms: toStringArray(raw.perms),
    platformAdmin: raw.platformAdmin === true,
  };
}

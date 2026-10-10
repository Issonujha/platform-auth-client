import { InvalidTokenError } from './errors.js';

/** Minimal response shape we need; keeps this package free of any HTTP client. */
export interface FetchResponseLike {
  ok: boolean;
  status: number;
  json(): Promise<unknown>;
}

/**
 * The host injects its own fetch (browser `fetch`, Node `undici`, axios wrapper, …).
 * This package never imports a network library.
 */
export type Fetcher = (
  url: string,
  init?: { method?: string; headers?: Record<string, string>; body?: string },
) => Promise<FetchResponseLike>;

/** RFC 7662-style result from auth-service `POST /auth/introspect`. */
export interface IntrospectionResult {
  active: boolean;
  subject?: string;
  clientId?: string;
  grantType?: string;
  expiresAtEpochSeconds?: number;
  projectId?: string;
  projectCode?: string;
  roles?: string[];
  permissions?: string[];
  platformAdmin?: boolean;
  reason?: string;
}

export interface IntrospectorConfig {
  /** Full URL, e.g. https://auth.example.com/auth/introspect */
  url: string;
  /** Host-supplied fetch implementation. */
  fetcher: (url: string, init?: { method?: string; headers?: Record<string, string>; body?: string }) => Promise<FetchResponseLike>;
}

/**
 * Builds an introspector that asks auth-service whether a token is still active
 * (the only way to catch centrally-revoked tokens). Networking is delegated to the
 * injected fetcher.
 */
export function createIntrospector(config: { url: string; fetcher: Fetcher }) {
  if (!config || !config.url) {
    throw new InvalidTokenError('introspection url is required');
  }
  if (!config.fetcher) {
    throw new InvalidTokenError('a fetcher is required (no HTTP client is bundled)');
  }
  return async function introspect(token: string): Promise<IntrospectionResult> {
    if (!token) {
      throw new InvalidTokenError('token is required');
    }
    const response = await config.fetcher(config.url, {
      method: 'POST',
      headers: { 'content-type': 'application/json', accept: 'application/json' },
      body: JSON.stringify({ token }),
    });
    if (!response.ok) {
      throw new InvalidTokenError(`Introspection request failed with status ${response.status}`);
    }
    return (await response.json()) as IntrospectionResult;
  };
}

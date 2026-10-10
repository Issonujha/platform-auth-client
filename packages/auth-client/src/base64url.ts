const DECODER = new TextDecoder();

/** Decodes a base64 (standard or url-safe) string into bytes, without requiring Node Buffer. */
export function base64ToBytes(input: string): Uint8Array {
  const normalized = input.replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4);

  const globalAtob = (globalThis as { atob?: (data: string) => string }).atob;
  if (typeof globalAtob === 'function') {
    const binary = globalAtob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  const BufferCtor = (globalThis as { Buffer?: { from(data: string, encoding: string): Uint8Array } }).Buffer;
  if (BufferCtor) {
    return new Uint8Array(BufferCtor.from(padded, 'base64'));
  }
  throw new Error('No base64 decoder available (need atob or Buffer)');
}

export function base64UrlToString(value: string): string {
  return new TextDecoder().decode(base64UrlToBytes(value));
}

export function base64UrlToBytes(value: string): Uint8Array {
  return base64ToBytes(value);
}

export function stringToBytes(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

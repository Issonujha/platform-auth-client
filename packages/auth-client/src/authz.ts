import type { PlatformClaims } from './verifyToken.js';

/** True if the token carries the given project role (case-insensitive). */
export function hasRole(claims: PlatformClaims, role: string): boolean {
  const target = role.toUpperCase();
  return claims.roles.some((role_) => role_ === target);
}

/** True if the token carries the exact permission string. */
export function hasPermission(claims: PlatformClaims, permission: string): boolean {
  return claims.perms.includes(permission);
}

/** True for a platform-level SUPER_ADMIN token. */
export function isPlatformAdmin(claims: PlatformClaims): boolean {
  return claims.platformAdmin === true;
}

/** True when the token is scoped to the given project code. */
export function isMemberOf(claims: PlatformClaims, projectCode: string): boolean {
  return claims.proj === projectCode;
}

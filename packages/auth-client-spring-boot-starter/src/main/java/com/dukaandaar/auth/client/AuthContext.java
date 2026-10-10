package com.dukaandaar.auth.client;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * Static helpers to read the current {@link PlatformClaims} from the SecurityContext.
 * Safe to call from controllers/services; returns null / false when unauthenticated.
 */
public final class AuthContext {

	/** Request attribute set by the filter when a presented token failed validation. */
	public static final String TOKEN_ERROR_ATTRIBUTE = "platform.auth.tokenError";

	private AuthContext() {
	}

	public static PlatformPrincipal principal() {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		if (authentication != null && authentication.getPrincipal() instanceof PlatformPrincipal principal) {
			return principal;
		}
		return null;
	}

	public static PlatformClaims claims() {
		PlatformPrincipal principal = principal();
		return principal == null ? null : principal.claims();
	}

	public static String subject() {
		PlatformClaims claims = claims();
		return claims == null ? null : claims.subject();
	}

	public static String projectCode() {
		PlatformClaims claims = claims();
		return claims == null ? null : claims.projectCode();
	}

	public static boolean hasRole(String role) {
		PlatformClaims claims = claims();
		return claims != null && claims.hasRole(role);
	}

	public static boolean hasPermission(String permission) {
		PlatformClaims claims = claims();
		return claims != null && claims.hasPermission(permission);
	}

	public static boolean isPlatformAdmin() {
		PlatformClaims claims = claims();
		return claims != null && claims.platformAdmin();
	}

	public static boolean isMemberOf(String projectCode) {
		PlatformClaims claims = claims();
		return claims != null && claims.isMemberOf(projectCode);
	}
}

package com.dukaandaar.auth.client;

import java.security.Principal;

/**
 * Authentication principal placed in the SecurityContext by {@link PlatformTokenFilter}.
 * Carries the validated {@link PlatformClaims}.
 */
public record PlatformPrincipal(PlatformClaims claims) implements Principal {

	@Override
	public String getName() {
		return claims.subject();
	}

	public String subject() {
		return claims.subject();
	}

	public String projectCode() {
		return claims.projectCode();
	}

	public boolean platformAdmin() {
		return claims.platformAdmin();
	}
}

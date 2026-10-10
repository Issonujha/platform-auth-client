package com.dukaandaar.auth.client;

import java.time.Instant;
import java.util.Set;

/**
 * Normalised claims from a Dukaandaar platform token. Roles are upper-cased; permissions
 * are the flattened {@code perms} claim. Immutable — safe to hand to request-scoped code.
 */
public record PlatformClaims(
		String subject,
		String tokenId,
		String projectId,
		String projectCode,
		Set<String> roles,
		Set<String> permissions,
		boolean platformAdmin,
		String clientId,
		String grantType,
		Instant issuedAt,
		Instant expiresAt) {

	public boolean hasRole(String role) {
		return role != null && roles.contains(role.trim().toUpperCase());
	}

	public boolean hasPermission(String permission) {
		return permission != null && permissions.contains(permission);
	}

	public boolean isMemberOf(String projectCode) {
		return projectCode != null && projectCode.equalsIgnoreCase(this.projectCode);
	}

	/** True when this token was issued via the client-credentials grant. */
	public boolean isMachine() {
		return clientId != null && !clientId.isBlank();
	}
}

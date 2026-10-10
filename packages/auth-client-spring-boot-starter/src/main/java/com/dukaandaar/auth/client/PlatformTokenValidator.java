package com.dukaandaar.auth.client;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.time.Instant;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Set;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

/**
 * Verifies HS256 platform tokens locally using the shared {@code JWT_SECRET}. No
 * network call: any service holding the secret can validate a token independently, so
 * an auth-service outage does not take consumers down.
 */
public class PlatformTokenValidator {

	private final Key signingKey;

	public PlatformTokenValidator(String secret) {
		if (secret == null || secret.getBytes(StandardCharsets.UTF_8).length < 32) {
			throw new IllegalArgumentException(
					"platform.auth.jwt-secret is required and must be at least 32 bytes (the shared JWT_SECRET).");
		}
		this.signingKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
	}

	/**
	 * Verifies the signature and expiry, then returns the canonical claims.
	 *
	 * @throws PlatformTokenException when the token is invalid or expired
	 */
	public PlatformClaims validate(String token) {
		if (token == null || token.isBlank()) {
			throw new PlatformTokenException("Token is missing");
		}
		try {
			Claims claims = Jwts.parserBuilder().setSigningKey(this.signingKey).build().parseClaimsJws(token).getBody();
			return toClaims(claims);
		} catch (JwtException | IllegalArgumentException ex) {
			throw new PlatformTokenException("Invalid platform token", ex);
		}
	}

	private PlatformClaims toClaims(Claims claims) {
		Set<String> roles = new LinkedHashSet<>();
		for (String role : toStringSet(claims.get("roles"))) {
			roles.add(role.toUpperCase());
		}
		return new PlatformClaims(claims.getSubject(), claims.getId(), claims.get("pid", String.class),
				claims.get("proj", String.class), roles, toStringSet(claims.get("perms")),
				Boolean.TRUE.equals(claims.get("platformAdmin", Boolean.class)),
				claims.get("clientId", String.class), claims.get("grantType", String.class),
				claims.getIssuedAt() == null ? null : claims.getIssuedAt().toInstant(),
				claims.getExpiration() == null ? null : claims.getExpiration().toInstant());
	}

	private Set<String> toStringSet(Object value) {
		Set<String> out = new LinkedHashSet<>();
		if (value instanceof Collection<?> collection) {
			collection.forEach(item -> {
				if (item != null) {
					out.add(item.toString());
				}
			});
		}
		return out;
	}

	/** Exposed for tests / tooling: the parsed token expiration, or null when absent. */
	public Instant expirationOf(String token) {
		return validate(token).expiresAt();
	}

	/** The signing key, for advanced use (e.g. building a matching parser). */
	Key signingKey() {
		return signingKey;
	}
}

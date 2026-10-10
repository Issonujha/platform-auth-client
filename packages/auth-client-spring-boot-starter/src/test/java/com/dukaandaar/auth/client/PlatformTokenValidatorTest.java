package com.dukaandaar.auth.client;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Date;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

class PlatformTokenValidatorTest {

	static final String SECRET = "test-secret-that-is-at-least-32-bytes-long";

	private final PlatformTokenValidator validator = new PlatformTokenValidator(SECRET);

	static String mint(Map<String, Object> claims, long ttlMillis) {
		var builder = Jwts.builder().setSubject(String.valueOf(claims.getOrDefault("sub", "alice"))).setId("jti-1")
				.setIssuedAt(new Date()).setExpiration(new Date(System.currentTimeMillis() + ttlMillis));
		claims.forEach((key, value) -> {
			if (!"sub".equals(key)) {
				builder.claim(key, value);
			}
		});
		return builder.signWith(Keys.hmacShaKeyFor(SECRET.getBytes()), SignatureAlgorithm.HS256).compact();
	}

	@Test
	void validatesProjectScopedClaims() {
		String token = mint(Map.of("pid", "p1", "proj", "DUKAANDAAR", "roles", List.of("admin", "user"), "perms",
				List.of("order:read", "project:manage")), 60_000);

		PlatformClaims claims = validator.validate(token);

		assertThat(claims.subject()).isEqualTo("alice");
		assertThat(claims.projectId()).isEqualTo("p1");
		assertThat(claims.projectCode()).isEqualTo("DUKAANDAAR");
		assertThat(claims.roles()).containsExactlyInAnyOrder("ADMIN", "USER");
		assertThat(claims.hasRole("admin")).isTrue();
		assertThat(claims.hasPermission("order:read")).isTrue();
		assertThat(claims.hasPermission("order:delete")).isFalse();
		assertThat(claims.platformAdmin()).isFalse();
		assertThat(claims.isMachine()).isFalse();
	}

	@Test
	void marksClientCredentialsTokenAsMachine() {
		String token = mint(Map.of("sub", "svc_123", "clientId", "svc_123", "grantType", "client_credentials"), 60_000);

		PlatformClaims claims = validator.validate(token);

		assertThat(claims.isMachine()).isTrue();
		assertThat(claims.clientId()).isEqualTo("svc_123");
		assertThat(claims.grantType()).isEqualTo("client_credentials");
	}

	@Test
	void flagsPlatformAdmin() {
		String token = mint(Map.of("platformAdmin", true), 60_000);
		assertThat(validator.validate(token).platformAdmin()).isTrue();
	}

	@Test
	void rejectsTamperedSignature() {
		String token = mint(Map.of("sub", "alice"), 60_000);
		String tampered = token.substring(0, token.length() - 2) + "xx";
		assertThatThrownBy(() -> validator.validate(tampered)).isInstanceOf(PlatformTokenException.class);
	}

	@Test
	void rejectsExpiredToken() {
		String token = mint(Map.of("sub", "alice"), -1_000);
		assertThatThrownBy(() -> validator.validate(token)).isInstanceOf(PlatformTokenException.class);
	}

	@Test
	void rejectsTokenSignedWithDifferentSecret() {
		String other = Jwts.builder().setSubject("mallory")
				.signWith(Keys.hmacShaKeyFor("a-different-secret-that-is-32-bytes-long!!".getBytes()),
						SignatureAlgorithm.HS256)
				.compact();
		assertThatThrownBy(() -> validator.validate(other)).isInstanceOf(PlatformTokenException.class);
	}

	@Test
	void rejectsSecretShorterThan32Bytes() {
		assertThatThrownBy(() -> new PlatformTokenValidator("too-short")).isInstanceOf(IllegalArgumentException.class);
	}
}

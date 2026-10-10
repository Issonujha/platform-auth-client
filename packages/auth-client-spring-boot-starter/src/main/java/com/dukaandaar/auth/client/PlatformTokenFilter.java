package com.dukaandaar.auth.client;

import java.io.IOException;
import java.util.LinkedHashSet;
import java.util.Set;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Validates the bearer token on each request and, on success, populates the
 * SecurityContext with a {@link PlatformPrincipal} and the token's roles/permissions.
 * No database and no network — verification is purely local HS256.
 */
public class PlatformTokenFilter extends OncePerRequestFilter {

	/** Authority granted when the token has {@code platformAdmin=true}. */
	public static final String SUPER_ADMIN_AUTHORITY = "ROLE_SUPER_ADMIN";

	private final PlatformTokenValidator validator;
	private final AuthClientProperties properties;

	public PlatformTokenFilter(PlatformTokenValidator validator, AuthClientProperties properties) {
		this.validator = validator;
		this.properties = properties;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, java.io.IOException {
		if (SecurityContextHolder.getContext().getAuthentication() == null) {
			String token = resolveToken(request);
			if (token != null) {
				try {
					PlatformClaims claims = validator.validate(token);
					var authentication = new UsernamePasswordAuthenticationToken(new PlatformPrincipal(claims), null,
							authoritiesOf(claims));
					authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
					SecurityContextHolder.getContext().setAuthentication(authentication);
				} catch (PlatformTokenException ex) {
					SecurityContextHolder.clearContext();
					request.setAttribute(AuthContext.TOKEN_ERROR_ATTRIBUTE, ex.getMessage());
				}
			}
		}
		filterChain.doFilter(request, response);
	}

	private String resolveToken(HttpServletRequest request) {
		String header = request.getHeader(properties.getHeader());
		if (header == null || header.isBlank()) {
			return null;
		}
		String prefix = properties.getPrefix();
		if (prefix == null || prefix.isEmpty()) {
			return header.trim();
		}
		return header.startsWith(prefix) ? header.substring(prefix.length()).trim() : null;
	}

	/** Maps claims to Spring authorities: {@code ROLE_<code>} for each role + raw permissions. */
	public static Set<GrantedAuthority> authoritiesOf(PlatformClaims claims) {
		Set<GrantedAuthority> authorities = new LinkedHashSet<>();
		claims.roles().forEach(role -> authorities.add(new SimpleGrantedAuthority("ROLE_" + role)));
		claims.permissions().forEach(permission -> authorities.add(new SimpleGrantedAuthority(permission)));
		if (claims.platformAdmin()) {
			authorities.add(new SimpleGrantedAuthority(SUPER_ADMIN_AUTHORITY));
		}
		return authorities;
	}
}

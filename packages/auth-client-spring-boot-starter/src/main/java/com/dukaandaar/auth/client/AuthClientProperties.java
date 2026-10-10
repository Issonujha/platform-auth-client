package com.dukaandaar.auth.client;

import org.springframework.boot.context.properties.ConfigurationProperties;

/** Configuration for the auth-client starter. */
@ConfigurationProperties(prefix = "platform.auth")
public class AuthClientProperties {

	/** Master switch for the auto-configured validator/filter. */
	private boolean enabled = true;

	/** Shared HS256 secret — must match auth-service's {@code JWT_SECRET}. */
	private String jwtSecret;

	/** Request header carrying the bearer token. */
	private String header = "Authorization";

	/** Scheme prefix expected before the token. */
	private String prefix = "Bearer ";

	public boolean isEnabled() {
		return enabled;
	}

	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}

	public String getJwtSecret() {
		return jwtSecret;
	}

	public void setJwtSecret(String jwtSecret) {
		this.jwtSecret = jwtSecret;
	}

	public String getHeader() {
		return header;
	}

	public void setHeader(String header) {
		this.header = header;
	}

	public String getPrefix() {
		return prefix;
	}

	public void setPrefix(String prefix) {
		this.prefix = prefix;
	}
}

package com.dukaandaar.auth.client;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

/**
 * Auto-configures the platform token validator, filter and SpEL authorization helper.
 * Active when {@code platform.auth.enabled} is true (default) and a
 * {@code platform.auth.jwt-secret} is present; each bean backs off if the host already
 * defines one.
 */
@AutoConfiguration
@EnableConfigurationProperties(AuthClientProperties.class)
@ConditionalOnProperty(prefix = "platform.auth", name = "enabled", havingValue = "true", matchIfMissing = true)
public class AuthClientAutoConfiguration {

	@Bean
	@ConditionalOnMissingBean
	public PlatformTokenValidator platformTokenValidator(AuthClientProperties properties) {
		return new PlatformTokenValidator(properties.getJwtSecret());
	}

	@Bean
	@ConditionalOnMissingBean
	public PlatformTokenFilter platformTokenFilter(PlatformTokenValidator validator, AuthClientProperties properties) {
		return new PlatformTokenFilter(validator, properties);
	}

	@Bean
	@ConditionalOnMissingBean
	public PlatformAuthz platformAuthz() {
		return new PlatformAuthz();
	}
}

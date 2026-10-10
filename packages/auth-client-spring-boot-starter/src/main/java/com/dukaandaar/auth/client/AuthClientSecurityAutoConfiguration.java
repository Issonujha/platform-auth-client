package com.dukaandaar.auth.client;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * Provides a minimal stateless security chain (all requests authenticated, platform
 * token filter installed) <em>only</em> when the host application does not define its
 * own {@link SecurityFilterChain}. Services with bespoke security should register
 * {@link PlatformTokenFilter} in their own chain instead.
 */
@AutoConfiguration(after = AuthClientAutoConfiguration.class)
@ConditionalOnClass(SecurityFilterChain.class)
public class AuthClientSecurityAutoConfiguration {

	@Bean
	@ConditionalOnMissingBean(SecurityFilterChain.class)
	public SecurityFilterChain platformAuthSecurityFilterChain(HttpSecurity http, PlatformTokenFilter filter)
			throws Exception {
		http.csrf(csrf -> csrf.disable())
				.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
				.authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
				.addFilterBefore(filter, UsernamePasswordAuthenticationFilter.class);
		return http.build();
	}
}

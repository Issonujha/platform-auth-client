package com.dukaandaar.auth.client;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

class PlatformTokenFilterTest {

	private final PlatformTokenValidator validator = new PlatformTokenValidator(PlatformTokenValidatorTest.SECRET);
	private final AuthClientProperties properties = new AuthClientProperties();
	private final PlatformTokenFilter filter = new PlatformTokenFilter(validator, properties);

	@AfterEach
	void clearContext() {
		SecurityContextHolder.clearContext();
	}

	@Test
	void authenticatesValidBearerToken() throws Exception {
		String token = PlatformTokenValidatorTest.mint(Map.of("pid", "p1", "proj", "DUKAANDAAR", "roles",
				List.of("admin", "user"), "perms", List.of("order:read")), 60_000);
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/orders");
		request.addHeader("Authorization", "Bearer " + token);

		filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());

		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		assertThat(authentication).isNotNull();
		assertThat(authentication.getAuthorities()).extracting("authority").contains("ROLE_ADMIN", "ROLE_USER",
				"order:read");
		assertThat(AuthContext.subject()).isEqualTo("alice");
		assertThat(AuthContext.projectCode()).isEqualTo("DUKAANDAAR");
		assertThat(AuthContext.hasPermission("order:read")).isTrue();
		assertThat(AuthContext.isMemberOf("dukaandaar")).isTrue();
	}

	@Test
	void grantsSuperAdminAuthorityToPlatformAdmins() throws Exception {
		String token = PlatformTokenValidatorTest.mint(Map.of("platformAdmin", true), 60_000);
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/projects");
		request.addHeader("Authorization", "Bearer " + token);

		filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());

		assertThat(SecurityContextHolder.getContext().getAuthentication().getAuthorities()).extracting("authority")
				.contains(PlatformTokenFilter.SUPER_ADMIN_AUTHORITY);
		assertThat(AuthContext.isPlatformAdmin()).isTrue();
	}

	@Test
	void leavesContextEmptyWhenHeaderMissing() throws Exception {
		filter.doFilter(new MockHttpServletRequest("GET", "/orders"), new MockHttpServletResponse(),
				new MockFilterChain());

		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
		assertThat(AuthContext.claims()).isNull();
	}

	@Test
	void doesNotAuthenticateInvalidToken() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/orders");
		request.addHeader("Authorization", "Bearer not-a-real-token");

		filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());

		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
		assertThat(request.getAttribute(AuthContext.TOKEN_ERROR_ATTRIBUTE)).isNotNull();
	}

	@Test
	void supportsConfigurableHeaderAndPrefix() throws Exception {
		properties.setHeader("X-Platform-Token");
		properties.setPrefix("");
		String token = PlatformTokenValidatorTest.mint(Map.of("proj", "DUKAANDAAR"), 60_000);
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/orders");
		request.addHeader("X-Platform-Token", token);

		filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());

		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
	}
}

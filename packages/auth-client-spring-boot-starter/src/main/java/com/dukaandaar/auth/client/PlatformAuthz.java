package com.dukaandaar.auth.client;

/**
 * SpEL-friendly authorization bean, usable in method security, e.g.
 * {@code @PreAuthorize("@platformAuthz.hasPermission('order:read')")} or
 * {@code @PreAuthorize("@platformAuthz.inProject(#code)")}.
 */
public class PlatformAuthz {

	public boolean hasPermission(String permission) {
		return AuthContext.hasPermission(permission);
	}

	public boolean hasRole(String role) {
		return AuthContext.hasRole(role);
	}

	public boolean inProject(String projectCode) {
		return AuthContext.isMemberOf(projectCode);
	}

	public boolean isPlatformAdmin() {
		return AuthContext.isPlatformAdmin();
	}

	public boolean hasAnyPermission(String... permissions) {
		for (String permission : permissions) {
			if (AuthContext.hasPermission(permission)) {
				return true;
			}
		}
		return false;
	}
}

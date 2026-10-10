# platform-auth-client

Consume Dukaandaar platform tokens (minted by `auth-service`) anywhere — no service-specific code.

- **`auth-client-spring-boot-starter`** (`com.dukaandaar:auth-client-spring-boot-starter`) — a
  servlet `OncePerRequestFilter` that verifies HS256 tokens locally, a `PlatformClaims` model,
  `AuthContext` helpers, and `@platformAuthz` SpEL authorization.
- **`@dukaandaar/auth-client`** — a dependency-free TS/JS verifier (WebCrypto HMAC-SHA256),
  claim helpers, and an optional introspection client that takes a host-injected `fetcher`.

## Trust model

Tokens are **verified locally** with the shared `JWT_SECRET` (HS256). No network on the hot path —
an `auth-service` outage does not take consumers down. Introspection (`/auth/introspect`) is only
for catching centrally-revoked tokens, and only where you need it.

## JVM usage

```xml
<dependency>
  <groupId>com.dukaandaar</groupId>
  <artifactId>auth-client-spring-boot-starter</artifactId>
  <version>0.1.0</version>
</dependency>
```

```yaml
platform:
  auth:
    jwt-secret: ${JWT_SECRET}   # same value as auth-service
```

If your app has no `SecurityFilterChain`, one is created (stateless, all requests authenticated).
Otherwise add the filter to your own chain:

```java
http.addFilterBefore(platformTokenFilter, UsernamePasswordAuthenticationFilter.class);
```

Read the caller inside controllers/services:

```java
PlatformClaims claims = AuthContext.claims();
if (AuthContext.hasPermission("order:read")) { ... }
```

Guard endpoints with SpEL:

```java
@PreAuthorize("@platformAuthz.hasPermission('order:read')")
@PreAuthorize("@platformAuthz.inProject(#code) or @platformAuthz.isPlatformAdmin()")
```

## TS usage

```ts
import { verifyToken, hasPermission, createIntrospector } from '@dukaandaar/auth-client';

const { claims } = await verifyToken(bearer, { secret: process.env.JWT_SECRET! });
if (!hasPermission(claims, 'order:read')) throw new Error('forbidden');

// Revocation (optional; inject your own fetch):
const introspect = createIntrospector({ url: 'https://auth.example.com/auth/introspect', fetcher: fetch });
const result = await introspect(bearer);
```

## Build

```bash
# JS package
pnpm install && pnpm -r build      # smoke: node packages/auth-client/scripts/smoke.mjs

# Java starter (independent)
mvn -f packages/auth-client-spring-boot-starter/pom.xml test
```

See `../docs/PLATFORM_PLAN.md` for how this fits the control-plane architecture.

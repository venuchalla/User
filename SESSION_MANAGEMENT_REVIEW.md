# Authentication and session hardening (work in progress)

Branch: `feature/unified-auth-session-management`. Do not merge without compiling and running integration tests.

## Implemented
- General API chain defaults to authenticated, with public sign-in/signup and CSRF bootstrap.
- JWT filter registered in Spring Security, and bearer tokens include a `sid` claim checked against an active-session registry.
- Local login saves a Spring Security context into the HTTP session.
- Public signup always assigns USER and never echoes the password.
- Browser session cookie uses existing Spring Session JDBC configuration.
- Database registry allows only the latest session ID for a principal and checks an absolute lifetime (default 8 hours).
- Session status, extension, and logout endpoints at `/auth/session`, `/auth/session/extend`, and `/auth/session/logout`.
- One-time SAML profile tickets stored in JDBC; token values are hashed at rest.
- SAML appId is checked against configured callbacks and callback RelayState is compared to the initiating session.
- CSRF enabled for the general cookie-authenticated chain; Angular must bootstrap `GET /auth/session/csrf` and send `X-XSRF-TOKEN` on state-changing requests.

## Not yet verified / blocking production
- No build or integration test has run in this environment. The project uses a custom Maven parent from GitHub Packages.
- No OAuth2/OIDC login configuration is present in the inspected backend. Do not claim OAuth2 support until a provider registration, login filter chain, success handler, and identity mapping are implemented and tested.
- SAML principals and local principals currently use different names. A unified internal user identity mapping (issuer+subject / SAML NameID to internal user ID) is required for exactly one session *per person* across methods.
- Database schema creation currently occurs in application startup. Replace it with versioned Flyway/Liquibase migrations and restrict DDL permissions in production.
- CSRF must be exercised with both frontend origins and SameSite=None cookies; browser third-party-cookie restrictions may prevent session persistence.
- The SAML security chain currently retains existing CSRF exclusions and custom logout handling; validate against ZITADEL.
- Session expiration/revocation tests, concurrent login tests, and API authorization tests are required.
- Check frontend compatibility with existing login response JWT and session cookies; Angular cross-origin requests must use `withCredentials`.
- Security hardening for logging, error handling, and callback URL validation requires a final review.

## Manual test scenarios
1. Anonymous GET protected API => 401.
2. Anonymous POST signup requesting ADMIN => registered USER only, no password in response.
3. GET CSRF token then POST local signin with token => authenticated session.
4. GET session => authenticated; POST extend => idle expiration refreshed.
5. Second login with same principal => previous cookie and previous JWT rejected.
6. Logout => cookie session invalid and JWT revoked.
7. SAML login from each configured appId => valid callback and single-use ticket; unknown appId rejected.
8. Concurrent login across two backend instances => only latest registry session authorized.
9. After absolute lifetime => session rejected regardless of activity.
10. Test CORS preflight and cookie policies from both Angular hosting origins.

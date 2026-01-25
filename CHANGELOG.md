# Changelog

All notable changes to the Secure OIDC Login plugin will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security
- **[Low]** Fixed missing `wp_unslash()` on `$_GET['page']` in admin notices check
- **[Low]** Added `autocomplete="new-password"` to client secret field when unsafe mode is enabled to reduce browser cache exposure

### Added
- New environment variable `SECURE_OIDC_STATE_TTL` (60-600 seconds, default: 300) to configure state/nonce parameter expiration

### Changed
- Enhanced README documentation for reverse proxy security considerations

## [0.6.0-beta] - 2026-01-24

### Security
- **[High]** Added IP-based rate limiting to all authentication endpoints (login, callback, discovery)
- **[High]** Migrated all HTTP requests to `wp_safe_remote_get/post` for comprehensive SSRF protection
- **[Medium]** Reduced default JWT clock skew tolerance from 5 minutes to 15 seconds

### Added
- New `OIDC_Rate_Limiter` class using WordPress transients (follows core patterns like `check_comment_flood_db()`)
- Rate limiting returns HTTP 429 (Too Many Requests) with informative error messages
- Security event logging for rate limit events (lockouts, blocked requests)
- New environment variable `SECURE_OIDC_RATE_LIMIT_ATTEMPTS` (1-100, default: 10)
- New environment variable `SECURE_OIDC_RATE_LIMIT_WINDOW` (60-3600 seconds, default: 300)
- New environment variable `SECURE_OIDC_RATE_LIMIT_LOCKOUT` (60-86400 seconds, default: 900)
- New environment variable `SECURE_OIDC_JWT_LEEWAY` (1-600 seconds, default: 15) for JWT clock skew tolerance
- New constant `SECURE_OIDC_TRUST_PROXY_HEADERS` for reverse proxy/load balancer deployments
- Reverse proxy support checks `X-Real-IP`, `X-Forwarded-For`, and `Client-IP` headers

### Changed
- Discovery endpoint now uses `wp_safe_remote_get()` with WordPress's built-in `wp_http_validate_url()` validation
- Token endpoint now uses `wp_safe_remote_post()` for SSRF protection
- JWKS endpoint now uses `wp_safe_remote_get()` for SSRF protection
- Userinfo endpoint now uses `wp_safe_remote_get()` for SSRF protection
- Removed custom DNS resolution (`gethostbyname()`) in favor of WordPress's built-in SSRF protection
- Improved error messages for SSRF-blocked requests with guidance for intranet IdPs
- Rate limits automatically clear on successful authentication

### Removed
- `SECURE_OIDC_ALLOW_LOCAL_DISCOVERY_URLS` environment variable (use `http_request_host_is_external` filter instead)

## [0.5.0-beta] - 2026-01-18

### Security
- **[Critical]** Emergency bypass now requires environment variable `SECURE_OIDC_ENABLE_EMERGENCY_BYPASS=true` to function (disabled by default)
- **[High]** Token encryption now fails authentication if encryption fails instead of degrading to plaintext storage
- **[High]** Added inline security warning when email verification is disabled in settings
- **[Medium]** Removed legacy plaintext token support - users with old tokens must re-authenticate
- **[Medium]** Added SSRF protection to discovery endpoint with URL validation
- **[Low]** Added logging for JWKS cache HMAC verification failures to detect salt rotation or tampering

### Added
- New environment variable `SECURE_OIDC_ENABLE_EMERGENCY_BYPASS` to control emergency bypass availability
- New environment variable `SECURE_OIDC_ALLOW_LOCAL_DISCOVERY_URLS` to allow internal IPs for discovery (intranet deployments)
- New environment variable `SECURE_OIDC_ALLOW_INSECURE_DISCOVERY` to allow HTTP discovery URLs (testing only)

### Changed
- Token encryption is now mandatory - authentication fails if Sodium encryption is unavailable
- Discovery endpoint now requires HTTPS by default and blocks internal/private IP addresses
- Plaintext tokens in database will now cause decryption errors (users must re-authenticate)

### Breaking Changes
- Emergency bypass (`?native=1`) is disabled by default - set `SECURE_OIDC_ENABLE_EMERGENCY_BYPASS=true` to enable
- Users with plaintext tokens stored before encryption was enabled must log in again
- Discovery endpoint blocks internal IPs and HTTP by default (use environment variables to override for intranet deployments)

## [0.4.0-beta] - 2026-01-18

### Changed
- **Cryptography improvement** - Migrated token encryption from OpenSSL to libsodium (Sodium) for better security and modern PHP integration
- Added comprehensive type declarations to all class properties and method parameters (PHP 8.1+ feature)

### Improved
- Enhanced code quality and IDE support through proper type hints

## [0.3.1-beta] - 2026-01-04

### Fixed
- Fixed blank page issue occurring after IdP redirect (#17, #19)
- Added validation of IdP response content-types before decoding JSON (#18)
- Corrected content-type header handling for PHPSTAN compliance

## [0.3.0-beta] - 2026-01-04

### Security
- **[Critical]** Token encryption - OIDC tokens (ID tokens and refresh tokens) are now encrypted at rest using AES-256-CBC encryption
- **[Critical]** Open redirect prevention - Fixed open redirect vulnerability in OIDC callback handler
- **[High]** JWKS cache poisoning mitigation - Reduced JWKS cache duration from 1 hour to 15 minutes
- **[High]** CSRF protection enhancement - Added explicit nonce validation to settings form
- **[High]** XSS prevention - Added sanitization to redirect_to parameter before validation

### Fixed
- Fixed emergency bypass (`?native=1`) not working when submitting login form via POST

### Changed
- Added GitHub Action workflow for automated PHP quality checks (PHPStan level 6, PHPCS)

## [0.2.0-beta] - 2026-01-03

### Added
- OIDC-only login mode with ability to disable native WordPress login
- Emergency bypass via `?native=1` URL parameter
- Multi-layer protection (frontend CSS + backend authentication blocking)
- Safety checks to prevent activation if OIDC not properly configured
- Admin warnings for misconfiguration

### Fixed
- Fixed error message in OIDC-only mode that created a navigation loop

## [0.1.0-beta] - 2026-01-03

### Added
- Initial beta release
- OIDC Authorization Code Flow with PKCE implementation
- Auto-discovery support for IdP endpoints
- User provisioning with configurable claim mapping
- Single logout support
- Environment variable configuration support
- Flexible email verification
- PHPStan level 6 compliance

[Unreleased]: https://github.com/notglossy/secure-oidc-login/compare/v0.6.0-beta...HEAD
[0.6.0-beta]: https://github.com/notglossy/secure-oidc-login/compare/v0.5.0-beta...v0.6.0-beta
[0.5.0-beta]: https://github.com/notglossy/secure-oidc-login/compare/v0.4.0-beta...v0.5.0-beta
[0.4.0-beta]: https://github.com/notglossy/secure-oidc-login/compare/v0.3.1-beta...v0.4.0-beta
[0.3.1-beta]: https://github.com/notglossy/secure-oidc-login/compare/v0.3.0-beta...v0.3.1-beta
[0.3.0-beta]: https://github.com/notglossy/secure-oidc-login/compare/v0.2.0-beta...v0.3.0-beta
[0.2.0-beta]: https://github.com/notglossy/secure-oidc-login/compare/v0.1.0-beta...v0.2.0-beta
[0.1.0-beta]: https://github.com/notglossy/secure-oidc-login/releases/tag/v0.1.0-beta

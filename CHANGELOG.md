# Changelog

All notable changes to the Secure OIDC Login plugin will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/notglossy/secure-oidc-login/compare/v0.5.0-beta...HEAD
[0.5.0-beta]: https://github.com/notglossy/secure-oidc-login/compare/v0.4.0-beta...v0.5.0-beta
[0.4.0-beta]: https://github.com/notglossy/secure-oidc-login/compare/v0.3.1-beta...v0.4.0-beta
[0.3.1-beta]: https://github.com/notglossy/secure-oidc-login/compare/v0.3.0-beta...v0.3.1-beta
[0.3.0-beta]: https://github.com/notglossy/secure-oidc-login/compare/v0.2.0-beta...v0.3.0-beta
[0.2.0-beta]: https://github.com/notglossy/secure-oidc-login/compare/v0.1.0-beta...v0.2.0-beta
[0.1.0-beta]: https://github.com/notglossy/secure-oidc-login/releases/tag/v0.1.0-beta

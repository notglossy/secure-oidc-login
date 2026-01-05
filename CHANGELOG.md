# Changelog

All notable changes to the Secure OIDC Login plugin will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/notglossy/secure-oidc-login/compare/v0.3.1-beta...HEAD
[0.3.1-beta]: https://github.com/notglossy/secure-oidc-login/compare/v0.3.0-beta...v0.3.1-beta
[0.3.0-beta]: https://github.com/notglossy/secure-oidc-login/compare/v0.2.0-beta...v0.3.0-beta
[0.2.0-beta]: https://github.com/notglossy/secure-oidc-login/compare/v0.1.0-beta...v0.2.0-beta
[0.1.0-beta]: https://github.com/notglossy/secure-oidc-login/releases/tag/v0.1.0-beta

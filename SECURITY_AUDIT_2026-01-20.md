# Security Audit Report: Secure OIDC Login Plugin

**Date:** January 20, 2026
**Version Audited:** 0.5.0-beta
**Auditor:** Claude (Opus 4.5)
**Severity Scale:** Critical / High / Medium / Low / Informational

---

## Executive Summary

This security audit evaluates the Secure OIDC Login WordPress plugin, which implements OpenID Connect authentication. Overall, the plugin demonstrates **strong security practices** with defense-in-depth measures. The codebase follows security best practices for OIDC implementations and WordPress plugin development.

### Key Findings Summary

| Severity | Count | Description |
|----------|-------|-------------|
| Critical | 0 | No critical vulnerabilities found |
| High | 1 | Time-of-check-time-of-use (TOCTOU) in DNS resolution for SSRF protection |
| Medium | 2 | JWT clock skew tolerance, missing rate limiting |
| Low | 3 | Information leakage in logs, algorithm compatibility concerns |
| Informational | 4 | Suggested hardening measures |

---

## Security Strengths

The plugin implements numerous security best practices:

### 1. Authentication Flow Security (Excellent)

- **PKCE Implementation** (`secure-oidc-login.php:427-429`): Correctly implements RFC 7636 with S256 challenge method
- **State Parameter** (`secure-oidc-login.php:411`): Prevents CSRF attacks during authorization
- **Nonce Validation** (`class-oidc-client.php:250-257`): Prevents token replay attacks
- **c_hash Validation** (`class-oidc-client.php:264-270`): Protects hybrid flows against token substitution

### 2. Token Security (Excellent)

- **Encrypted Token Storage** (`class-oidc-token-crypto.php`): Uses Sodium ChaCha20-Poly1305-IETF authenticated encryption
- **No Plaintext Tokens** (`class-oidc-token-crypto.php:158-164`): Plaintext tokens rejected since v0.5.0
- **Key Derivation** (`class-oidc-token-crypto.php:294-298`): Uses WordPress salts (not stored in DB)
- **Authentication Failure on Encryption Error** (`secure-oidc-login.php:546-553`): Never stores plaintext if encryption fails

### 3. JWT Verification (Excellent)

- **Signature Verification**: Uses Firebase JWT library for proper cryptographic validation
- **JWKS Cache Integrity** (`class-oidc-client.php:430-435`): HMAC-SHA256 protects against cache poisoning
- **Key Rotation Handling** (`class-oidc-client.php:325-335`): Automatic retry with fresh JWKS
- **Claim Validation**: Validates iss, aud, azp, exp, nbf per OIDC Core spec

### 4. User Security (Good)

- **Email Verification Required** (`class-oidc-user-handler.php:89-107`): Prevents account takeover via unverified emails
- **Email Domain Filtering** (`class-oidc-user-handler.php:111-130`): Multi-tenant access control
- **Strong Random Passwords** (`class-oidc-user-handler.php:216`): 32-char passwords for OIDC users
- **Rollback on Failure** (`class-oidc-user-handler.php:234-251`): Deletes user if metadata storage fails

### 5. Input Validation (Good)

- **Max Length Limits** (`class-oidc-admin.php:78-98`): Prevents DoS via large inputs
- **CSRF Protection** (`class-oidc-admin.php:421-430`): Explicit nonce verification
- **URL Sanitization**: Uses `esc_url_raw()` for all URL fields
- **Domain Validation** (`class-oidc-admin.php:537-569`): Validates domain list format

### 6. SSRF Protection (Good)

- **Private IP Blocking** (`class-oidc-rest-controller.php:234`): Blocks RFC 1918 ranges
- **HTTPS Enforcement** (`class-oidc-rest-controller.php:211-218`): Required by default
- **Localhost Blocking** (`class-oidc-rest-controller.php:243-249`): Explicit blocklist

### 7. Error Handling (Good)

- **Generic User Messages** (`class-oidc-client.php:74-85`): No information disclosure
- **Detailed Server Logging**: Enables debugging without exposing to users

---

## Vulnerabilities and Concerns

### HIGH SEVERITY

#### 1. TOCTOU Race Condition in SSRF Protection

**Location:** `class-oidc-rest-controller.php:225-240`

**Issue:** The SSRF protection performs DNS resolution to check if a hostname resolves to a private IP address. However, there's a time-of-check-time-of-use (TOCTOU) vulnerability where:

1. `gethostbyname()` resolves the hostname to a public IP (passes check)
2. Attacker's DNS responds differently on second query
3. `wp_remote_get()` resolves to a private IP (SSRF successful)

```php
// Check happens here
$ip = gethostbyname( $host );
// ... validation ...

// Actual request happens later - DNS may return different result
$response = wp_remote_get( $discovery_url, array( 'timeout' => 30 ) );
```

**Impact:** An attacker with control over DNS could bypass SSRF protections to access internal services.

**Recommendation:**
- Use `wp_http_validate_url()` which resolves and pins the IP
- Or implement DNS pinning by passing the resolved IP directly to the HTTP request

---

### MEDIUM SEVERITY

#### 2. JWT Clock Skew Tolerance May Be Too Generous

**Location:** `class-oidc-client.php:319`

**Issue:** The JWT library is configured with a 5-minute (300 seconds) clock skew tolerance:

```php
JWT::$leeway = 300; // 5 minutes clock skew tolerance
```

While this accommodates poorly synchronized servers, it extends the window for token replay attacks. A stolen token remains valid for up to 5 minutes beyond its stated expiration.

**Impact:** Extended attack window for token theft/replay.

**Recommendation:**
- Consider reducing to 60-120 seconds
- Document the trade-off for administrators
- Consider making this configurable via environment variable

---

#### 3. No Rate Limiting on Authentication Endpoints

**Location:** `secure-oidc-login.php:162-172`

**Issue:** The OIDC callback and login initiation endpoints have no rate limiting:

```php
if ( isset( $_GET['oidc_callback'] ) && $_GET['oidc_callback'] === '1' ) {
    $this->handle_callback();
}

if ( isset( $_GET['oidc_login'] ) && $_GET['oidc_login'] === '1' ) {
    $this->initiate_login();
}
```

**Impact:**
- State exhaustion attacks (filling transient table)
- Denial of service via resource exhaustion
- Potential for timing attacks

**Recommendation:**
- Implement rate limiting using transients or WordPress's built-in mechanisms
- Consider using `wp_check_limit_exceeded()` pattern
- Add IP-based throttling for failed callbacks

---

### LOW SEVERITY

#### 4. Sensitive Information in Error Logs

**Location:** Multiple files

**Issue:** While user-facing errors are generic, server logs may contain sensitive information:

```php
// class-oidc-user-handler.php:114-120
$log_msg = sprintf(
    'OIDC authentication blocked: email domain not allowed (email: %s, domain: %s, subject: %s)',
    $email,  // PII in logs
    $domain,
    $subject
);
error_log( '[Secure OIDC Login] ' . $log_msg );
```

**Impact:** Email addresses and subject identifiers in logs could be exposed if logs are compromised.

**Recommendation:**
- Hash or partially mask email addresses in logs
- Consider structured logging with configurable verbosity levels
- Document log retention policies

---

#### 5. Algorithm Confusion Potential

**Location:** `class-oidc-client.php:301-311`

**Issue:** If the JWT header doesn't specify an algorithm, the code defaults to RS256 and applies this to JWKS keys without the `alg` field:

```php
$alg = isset( $header['alg'] ) ? $header['alg'] : 'RS256';
// ...
foreach ( $jwks['keys'] as &$key ) {
    if ( ! isset( $key['alg'] ) ) {
        $key['alg'] = $alg;
    }
}
```

While this aids IdP compatibility, it trusts the JWT header to specify which algorithm to use. This could potentially be exploited if an IdP has misconfigured keys.

**Impact:** In edge cases with misconfigured IdPs, algorithm confusion attacks might be possible.

**Recommendation:**
- Add configuration option to specify expected algorithms
- Log warnings when algorithm is inferred from JWT header
- Consider validating `kty` matches expected algorithm family

---

#### 6. Emergency Bypass Documentation in UI

**Location:** `class-oidc-admin.php:293-294`

**Issue:** The emergency bypass URL (`?native=1`) is documented directly in the admin UI:

```php
'description' => __( 'Hide username/password form and block native authentication. Emergency access: add ?native=1 to login URL.', 'secure-oidc-login' ),
```

While the bypass requires `SECURE_OIDC_ENABLE_EMERGENCY_BYPASS=true`, documenting the parameter in the UI increases discoverability for attackers.

**Impact:** Attackers who see the settings page (e.g., via screenshot or shared access) learn about the bypass mechanism.

**Recommendation:**
- Document bypass mechanism only in server-side documentation/README
- Require a more complex/random bypass parameter

---

### INFORMATIONAL

#### 7. Consider Binding Transients to Session

**Location:** `secure-oidc-login.php:412-428`

The state, nonce, and code_verifier transients use random keys but aren't bound to any session identifier. While the random state provides sufficient protection, binding to a session ID or browser fingerprint would add defense-in-depth.

---

#### 8. Missing Content-Security-Policy for Admin Pages

The admin settings page doesn't set a Content-Security-Policy header. While WordPress admin has default protections, a strict CSP would prevent XSS exploitation.

---

#### 9. Consider Subresource Integrity for Dependencies

The Firebase JWT library is loaded via Composer. Consider implementing integrity verification for Composer dependencies to detect supply chain attacks.

---

#### 10. No Token Revocation Check

The plugin validates tokens at login time but doesn't check for token revocation via the IdP's introspection endpoint. This means revoked tokens may be valid for their full lifetime.

**Note:** This is common for OIDC implementations and may be acceptable depending on security requirements.

---

## Code Quality Observations

### Positive Patterns

1. **Type Declarations**: PHP 8.1+ type hints throughout
2. **Immutable Value Objects**: OIDC_Config, OIDC_Claims, etc.
3. **Single Responsibility**: Each class has clear, focused purpose
4. **Comprehensive Comments**: Security rationale documented inline
5. **WordPress Coding Standards**: Follows WPCS conventions

### Areas for Improvement

1. **Test Coverage**: Ensure security-critical paths have 100% coverage
2. **Static Analysis**: Consider adding PHPStan level 9 for stricter checks
3. **Dependency Audit**: Regular `composer audit` for known vulnerabilities

---

## Compliance Considerations

### OWASP Top 10 2021

| Category | Status | Notes |
|----------|--------|-------|
| A01:2021 – Broken Access Control | ✅ Pass | Proper capability checks |
| A02:2021 – Cryptographic Failures | ✅ Pass | Strong encryption, proper key management |
| A03:2021 – Injection | ✅ Pass | Proper sanitization/escaping |
| A04:2021 – Insecure Design | ✅ Pass | Security-first architecture |
| A05:2021 – Security Misconfiguration | ⚠️ Note | Depends on admin configuration |
| A06:2021 – Vulnerable Components | ⚠️ Note | Monitor Firebase JWT for updates |
| A07:2021 – Auth Failures | ✅ Pass | Strong OIDC implementation |
| A08:2021 – Software/Data Integrity | ✅ Pass | JWKS HMAC, encrypted storage |
| A09:2021 – Logging Failures | ⚠️ Note | PII in logs (see finding #4) |
| A10:2021 – SSRF | ⚠️ Partial | TOCTOU issue (see finding #1) |

### OIDC Core Specification Compliance

The implementation correctly follows:
- Authorization Code Flow (Section 3.1)
- Token Endpoint (Section 3.1.3)
- ID Token Validation (Section 3.1.3.7)
- UserInfo Endpoint (Section 5.3)
- PKCE (RFC 7636)

---

## Recommendations Summary

### Priority 1 (Address Before Production)

1. **Fix SSRF TOCTOU vulnerability** - Implement DNS pinning or use `wp_http_validate_url()`

### Priority 2 (Address Soon)

2. **Add rate limiting** to authentication endpoints
3. **Reduce JWT clock skew** to 60-120 seconds
4. **Mask PII in logs** or implement structured logging

### Priority 3 (Consider for Hardening)

5. **Remove bypass documentation** from admin UI
6. **Add algorithm allowlist** configuration
7. **Consider session binding** for transients
8. **Implement token revocation checks** for high-security deployments

---

## Conclusion

The Secure OIDC Login plugin demonstrates a mature understanding of OIDC security and implements defense-in-depth principles effectively. The single high-severity finding (SSRF TOCTOU) should be addressed, but overall the plugin is well-designed for security.

The development team has made thoughtful security decisions including encrypted token storage, proper JWT validation, and comprehensive input sanitization. With the recommended fixes, this plugin would be suitable for production use in security-conscious environments.

---

*This audit was conducted through static code analysis. Dynamic testing and penetration testing are recommended for comprehensive security validation.*

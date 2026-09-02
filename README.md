# Secure OIDC Login

[![CI](https://github.com/notglossy/secure-oidc-login/actions/workflows/php-quality.yml/badge.svg)](https://github.com/notglossy/secure-oidc-login/actions/workflows/php-quality.yml)
[![codecov](https://codecov.io/gh/notglossy/secure-oidc-login/branch/main/graph/badge.svg)](https://codecov.io/gh/notglossy/secure-oidc-login)
[![PHP 8.2+](https://img.shields.io/badge/PHP-8.2%2B-777BB4.svg)](https://php.net/)
[![License: GPL v2+](https://img.shields.io/badge/License-GPL%20v2%2B-blue.svg)](https://www.gnu.org/licenses/old-licenses/gpl-2.0)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/notglossy/secure-oidc-login)

A secure OpenID Connect (OIDC) authentication plugin for WordPress that allows users to authenticate using any OIDC-compliant identity provider (IdP).

## Features

- **Standard OIDC Support**: Works with any OIDC-compliant identity provider (Keycloak, Okta, Auth0, Azure AD, Google, etc.)
- **Auto-Discovery**: Automatically configure endpoints using the IdP's discovery URL
- **PKCE Support**: Implements Proof Key for Code Exchange for enhanced security
- **User Provisioning**: Automatically create WordPress users on first login
- **Claim Mapping**: Configurable mapping of OIDC claims to WordPress user fields
- **Email Domain Filtering**: Restrict authentication to specific email domains for multi-tenant scenarios
- **Single Logout**: Optional logout from IdP when logging out of WordPress
- **Secure by Default**: Uses state parameter for CSRF protection and validates all tokens
- **Rate Limiting**: IP-based rate limiting protects against brute force and DoS attacks
- **SSRF Protection**: All HTTP requests use WordPress's safe remote functions to prevent server-side request forgery

## Requirements

- WordPress 5.8 or higher
- PHP 8.1 or higher
- HTTPS enabled (required for secure authentication)
- Composer (for development and building)

## Installation

### Option 1: Install Pre-built Package

1. Download the latest release zip file
2. In WordPress admin, go to **Plugins > Add New > Upload Plugin**
3. Choose the downloaded zip file and click **Install Now**
4. Click **Activate Plugin**
5. Go to **Settings > OIDC Auth** to configure the plugin

### Option 2: Install from Source

1. Clone this repository or download the source files
2. Run `./package.sh` to build the plugin package (see Building section below)
3. Upload the generated zip file from the `build/` directory
4. Follow steps 2-5 from Option 1

### Option 3: Manual Installation

1. Download or clone the plugin source files
2. Install production dependencies: `composer install --no-dev`
3. Upload the `secure-oidc-login` folder to `/wp-content/plugins/`
4. Activate the plugin through the 'Plugins' menu in WordPress
5. Go to **Settings > OIDC Auth** to configure the plugin

## Building the Plugin

This plugin uses Composer for dependency management. To create a distributable package:

### Prerequisites

- PHP 8.1 or higher
- [Composer](https://getcomposer.org/)
- `zip` command-line utility

### Build Instructions

1. Clone or download this repository
2. Run the packaging script:
   ```bash
   ./package.sh
   ```

The script will:
- Install production dependencies via Composer
- Copy all necessary plugin files to a build directory
- Exclude development files (tests, configs, etc.)
- Create a zip file in the `build/` directory named `secure-oidc-login-{version}.zip`
- Restore development dependencies

The generated zip file is ready for distribution or installation on any WordPress site.

### What's Included in the Package

- Plugin PHP files (`secure-oidc-login.php`, `includes/`)
- Production dependencies (`vendor/` with firebase/php-jwt)
- Documentation (`README.md`)

### What's Excluded from the Package

- Development dependencies (PHPStan, PHPCS, etc.)
- Configuration files (phpstan.neon, phpcs.xml, composer.json)
- IDE settings (.vscode/, .editorconfig)
- Git repository (.git/)
- Build artifacts and cache files

## Configuration

### Identity Provider Setup

Before configuring the plugin, you need to register your WordPress site as a client/application in your identity provider:

1. **Redirect URI**: Use the callback URL shown on the plugin settings page:
   ```
   https://your-wordpress-site.com/?oidc_callback=1
   ```

2. **Grant Type**: Authorization Code

3. **Scopes**: At minimum, request `openid email profile`

### Plugin Settings

Navigate to **Settings > OIDC Auth** in your WordPress admin panel.

#### Identity Provider Settings

| Setting | Description | Required |
|---------|-------------|----------|
| Discovery URL | Your IdP's `.well-known/openid-configuration` URL. Click "Discover" to auto-populate endpoints. | No |
| Client ID | The client ID from your IdP | Yes |
| Client Secret | The client secret from your IdP (for confidential clients) | No |
| Token Endpoint Auth Method | How client credentials are sent to the token endpoint: `client_secret_basic` (Authorization header, default) or `client_secret_post` (POST body) | No |
| Authorization Endpoint | URL for the authorization endpoint | Yes |
| Token Endpoint | URL for the token endpoint | Yes |
| Userinfo Endpoint | URL for the userinfo endpoint | No |
| End Session Endpoint | URL for logout/end session | No |
| Issuer | Expected issuer value for token validation | Yes |
| Scope | OAuth scopes to request (default: `openid email profile`) | No |
| Max Authentication Age | Maximum seconds since the user last authenticated at the IdP (`max_age` request parameter). When set, the ID token `auth_time` claim is required and verified. 0 disables. | No |
| Prompt | OIDC `prompt` parameter: provider default, `login` (always re-prompt for credentials), `consent`, or `select_account` | No |

#### Login Settings

| Setting | Description |
|---------|-------------|
| Login Button Text | Text displayed on the SSO login button |
| Enable Single Logout | When enabled, logging out of WordPress also logs out of the IdP |
| Enable Back-Channel Logout | End WordPress sessions when the IdP reports a logout (OIDC Back-Channel Logout 1.0). Register `<site>/?rest_route=/secure-oidc-login/v1/backchannel-logout` (shown on the settings page) as the back-channel logout URI at your IdP. |
| Remember Users | Keep users logged in with WordPress's persistent 14-day cookie (default). Disable to use a session cookie that expires when the browser closes, aligning the WordPress session more closely with the IdP session. Also filterable via `secure_oidc_login_remember_user`. |

### Back-Channel Logout

When enabled, the IdP can terminate WordPress sessions directly (server-to-server) the moment the user's IdP session ends — logout at the IdP, an admin-forced logout, or a session timeout. Without it, WordPress sessions survive until the auth cookie expires.

The endpoint validates the signed logout token per OIDC Back-Channel Logout 1.0 §2.6 (signature against the JWKS, `iss`, `aud`, `events`, `sub`/`sid`, no `nonce`) with single-use `jti` replay protection, then destroys all WordPress sessions for the matched user and clears their stored tokens.

### Login Hints

A login link can pre-fill the IdP's identifier field by adding `login_hint` to the initiation URL:

```text
https://example.com/wp-login.php?oidc_login=1&login_hint=user@example.com
```

Developers can add IdP-specific authorization request parameters with the `secure_oidc_login_auth_params` filter; security-critical parameters (state, nonce, PKCE, redirect URI) cannot be overridden.

#### User Settings

| Setting | Description |
|---------|-------------|
| Create Users | Automatically create WordPress users for new OIDC users |
| Default Role | WordPress role assigned to new users |
| Require Verified Email | Require the identity provider to verify email addresses before linking/creating accounts. Enabled by default for security. Disable only for trusted IdPs. |
| Allowed Email Domains | Comma-separated list of allowed email domains (e.g., `example.com,subsidiary.com`). Leave empty to allow all domains. Supports wildcards like `*.example.com` for subdomains. |
| Username Claim | OIDC claim to use for WordPress username (default: `preferred_username`) |
| Email Claim | OIDC claim for email address (default: `email`) |
| First Name Claim | OIDC claim for first name (default: `given_name`) |
| Last Name Claim | OIDC claim for last name (default: `family_name`) |

### Email Domain Filtering

Email domain filtering provides an additional layer of access control for multi-tenant scenarios where multiple organizations share the same identity provider.

#### Use Cases

- **Subsidiary Control**: Allow only employees from specific subsidiaries (e.g., `example.com,subsidiary.com`)
- **Vendor Access**: Restrict vendor portal access to approved vendor domains
- **Department Isolation**: Limit access to specific departments using subdomain wildcards (e.g., `*.hr.example.com`)
- **Multi-tenant IdP**: Filter users when multiple tenants authenticate through the same IdP

#### Configuration

**Allow all domains (default):**
Leave the "Allowed Email Domains" field empty.

**Single domain:**
```
example.com
```
Only users with `@example.com` email addresses can authenticate.

**Multiple domains:**
```
example.com,subsidiary.com,partner.org
```
Users from any of these domains can authenticate.

**Wildcard subdomains:**
```
*.example.com
```
Matches both the base domain (`user@example.com`) and all subdomains (`user@dept.example.com`, `user@hr.subsidiary.example.com`, etc.).

**Mixed configuration:**
```
example.com,*.subsidiary.com,partner.org
```
Allows `@example.com`, any subdomain of `subsidiary.com`, and `@partner.org`.

#### Behavior

- **Empty configuration**: No filtering (all domains allowed)
- **Case-insensitive**: `Example.COM` and `example.com` are treated identically
- **Validation timing**: Checked after email verification but before user lookup/creation
- **Error message**: Users from blocked domains see: "Your email domain (blocked.com) is not authorized to access this site. Please contact your administrator."

#### Security Considerations

- Domain filtering is an **additional layer** beyond email verification, not a replacement
- Validation happens **server-side** and cannot be bypassed
- Wildcards only work at the **subdomain level** (`*.example.com`), not TLD level (`example.*`)
- Use the `SECURE_OIDC_ALLOWED_EMAIL_DOMAINS` environment variable to lock down domains in production without database access

### Using Environment Variables

For enhanced security in production environments, you can override sensitive settings using environment variables instead of storing them in the WordPress database. This is particularly useful for containerized deployments and follows 12-factor app methodology.

#### Supported Environment Variables

**Authentication Credentials:**
- `SECURE_OIDC_CLIENT_ID` - Overrides the Client ID setting
- `SECURE_OIDC_CLIENT_SECRET` - Overrides the Client Secret setting

**Discovery:**
- `SECURE_OIDC_DISCOVERY_URL` - Pre-populates the Discovery URL field

**OIDC Endpoints:**
- `SECURE_OIDC_AUTHORIZATION_ENDPOINT` - Overrides the Authorization Endpoint
- `SECURE_OIDC_TOKEN_ENDPOINT` - Overrides the Token Endpoint
- `SECURE_OIDC_USERINFO_ENDPOINT` - Overrides the Userinfo Endpoint
- `SECURE_OIDC_END_SESSION_ENDPOINT` - Overrides the End Session (logout) Endpoint
- `SECURE_OIDC_JWKS_URI` - Overrides the JWKS URI for token verification

**Client Authentication:**
- `SECURE_OIDC_TOKEN_ENDPOINT_AUTH_METHOD` - Overrides the token endpoint auth method (`client_secret_basic` or `client_secret_post`)

**Token Validation:**
- `SECURE_OIDC_ISSUER` - Overrides the expected Issuer value for JWT validation

**Access Control:**
- `SECURE_OIDC_ALLOWED_EMAIL_DOMAINS` - Overrides the Allowed Email Domains setting (comma-separated list)

**Rate Limiting:**
- `SECURE_OIDC_RATE_LIMIT_ATTEMPTS` - Maximum attempts before lockout (1-100, default: 10)
- `SECURE_OIDC_RATE_LIMIT_WINDOW` - Time window in seconds (60-3600, default: 300)
- `SECURE_OIDC_RATE_LIMIT_LOCKOUT` - Lockout duration in seconds (60-86400, default: 900)

**JWT Validation:**
- `SECURE_OIDC_JWT_LEEWAY` - Clock skew tolerance in seconds (1-600, default: 15)

**Authentication Flow:**
- `SECURE_OIDC_STATE_TTL` - State/nonce parameter expiration in seconds (60-600, default: 300)
- `SECURE_OIDC_HTTP_TIMEOUT` - HTTP timeout in seconds for interactive IdP requests: token exchange, JWKS fetch, userinfo, discovery (5-60, default: 15)

#### Setting Environment Variables

**On your server:**

```bash
export SECURE_OIDC_CLIENT_ID="your-client-id"
export SECURE_OIDC_CLIENT_SECRET="your-client-secret"
export SECURE_OIDC_DISCOVERY_URL="https://your-idp.com/.well-known/openid-configuration"
export SECURE_OIDC_ALLOWED_EMAIL_DOMAINS="example.com,subsidiary.com"
```

**Using .env file (with a WordPress .env loader):**

```
SECURE_OIDC_CLIENT_ID=your-client-id
SECURE_OIDC_CLIENT_SECRET=your-client-secret
SECURE_OIDC_DISCOVERY_URL=https://your-idp.com/.well-known/openid-configuration
SECURE_OIDC_ALLOWED_EMAIL_DOMAINS=example.com,subsidiary.com
```

**Using Docker (docker-compose.yml):**

```yaml
services:
  wordpress:
    environment:
      SECURE_OIDC_CLIENT_ID: "your-client-id"
      SECURE_OIDC_CLIENT_SECRET: "your-client-secret"
      SECURE_OIDC_DISCOVERY_URL: "https://your-idp.com/.well-known/openid-configuration"
      SECURE_OIDC_ALLOWED_EMAIL_DOMAINS: "example.com,subsidiary.com"
```

**Using Kubernetes ConfigMap/Secret:**

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: oidc-credentials
type: Opaque
stringData:
  SECURE_OIDC_CLIENT_ID: your-client-id
  SECURE_OIDC_CLIENT_SECRET: your-client-secret
```

#### Admin UI Behavior

When environment variables are set:

- **Client ID and Client Secret fields**: Become disabled (read-only) with a notice indicating the environment variable is in use. The database value is preserved but ignored.
- **Discovery URL field**: Pre-populated with the environment variable value but remains editable, allowing you to modify it before clicking "Discover" if needed.

#### Advantages of Using Environment Variables

- **Enhanced Security**: Secrets are not stored in the WordPress database
- **Container-Friendly**: Compatible with Docker, Kubernetes, and other containerized deployments
- **Infrastructure as Code**: Works seamlessly with secrets management systems (AWS Secrets Manager, HashiCorp Vault, etc.)
- **12-Factor Compliance**: Follows best practices for modern web applications
- **Easy Rotation**: Update credentials without modifying database or code
- **Backward Compatible**: Existing installations continue to work unchanged; removing environment variables automatically falls back to database values

### Rate Limiting

The plugin includes built-in rate limiting to protect against brute force attacks and denial of service. Rate limiting is enabled by default with sensible limits.

#### Default Configuration

| Setting | Default | Description |
|---------|---------|-------------|
| Attempts | 10 | Maximum login/callback attempts before lockout |
| Window | 5 minutes | Time window for counting attempts |
| Lockout | 15 minutes | Duration of lockout after exceeding limit |

#### Customizing Rate Limits

Configure via environment variables:

```bash
# Allow 5 attempts per 2 minutes, with 30-minute lockout
export SECURE_OIDC_RATE_LIMIT_ATTEMPTS=5
export SECURE_OIDC_RATE_LIMIT_WINDOW=120
export SECURE_OIDC_RATE_LIMIT_LOCKOUT=1800
```

#### Rate Limited Endpoints

- **Login initiation** (`?oidc_login=1`) - Prevents state exhaustion attacks
- **Callback handler** (`?oidc_callback=1`) - Prevents callback flooding
- **Discovery REST endpoint** (`/wp-json/secure-oidc-login/v1/discover`) - Prevents endpoint abuse

Rate limits are tracked per IP address and automatically clear on successful authentication.

### Reverse Proxy / Load Balancer Configuration

If your WordPress site runs behind a reverse proxy (nginx, CloudFlare, AWS ALB, etc.), you need to enable proxy header trust so rate limiting uses the correct client IP:

```php
// wp-config.php
define( 'SECURE_OIDC_TRUST_PROXY_HEADERS', true );
```

Or via environment variable:

```bash
SECURE_OIDC_TRUST_PROXY_HEADERS=true
```

When enabled, the plugin checks these headers in order:
1. `X-Real-IP`
2. `X-Forwarded-For` (first IP in the list)
3. `Client-IP`

**Security Warning:** Only enable this if your server is actually behind a trusted proxy. These headers can be spoofed by attackers if requests reach your server directly.

#### Important Security Considerations

- **Verify your proxy configuration**: Ensure your reverse proxy is stripping or overwriting client-provided `X-Forwarded-For` headers before adding the real client IP
- **Disable in development**: Leave `SECURE_OIDC_TRUST_PROXY_HEADERS` undefined (defaults to false) for local development
- **Spoofing risk**: If clients can connect directly to your WordPress server (bypassing the proxy), attackers can spoof these headers to bypass rate limiting
- **Testing**: After enabling, verify rate limiting works correctly by testing with multiple IPs behind your proxy

## Provider-Specific Configuration

### Keycloak

1. Create a new client in your Keycloak realm
2. Set **Client Protocol** to `openid-connect`
3. Set **Access Type** to `confidential` or `public`
4. Add your WordPress callback URL to **Valid Redirect URIs**
5. Discovery URL: `https://your-keycloak.com/realms/your-realm/.well-known/openid-configuration`

### Azure AD / Entra ID

1. Register a new application in Azure Portal
2. Add a Web platform with your callback URL
3. Create a client secret (for confidential clients)
4. Discovery URL: `https://login.microsoftonline.com/{tenant-id}/v2.0/.well-known/openid-configuration`

### Okta

1. Create a new OIDC Web Application
2. Set the Sign-in redirect URI to your callback URL
3. Discovery URL: `https://your-domain.okta.com/.well-known/openid-configuration`

### Auth0

1. Create a new Regular Web Application
2. Add your callback URL to Allowed Callback URLs
3. Discovery URL: `https://your-domain.auth0.com/.well-known/openid-configuration`

### Google

1. Create OAuth 2.0 credentials in Google Cloud Console
2. Add your callback URL to Authorized redirect URIs
3. Discovery URL: `https://accounts.google.com/.well-known/openid-configuration`

## Hooks and Filters

### Actions

```php
// Fired when a new user is created via OIDC
do_action('secure_oidc_login_user_created', $user_id, $claims);

// Fired when an existing user is updated via OIDC
do_action('secure_oidc_login_user_updated', $user_id, $claims);
```

### Example: Assign Role Based on Claims

```php
add_action('secure_oidc_login_user_created', function($user_id, $claims) {
    // Check for admin group in claims
    if (isset($claims['groups']) && in_array('admins', $claims['groups'])) {
        $user = get_user_by('ID', $user_id);
        $user->set_role('administrator');
    }
}, 10, 2);
```

## Security Considerations

- **Always use HTTPS** in production
- The plugin implements PKCE (Proof Key for Code Exchange) for enhanced security
- State parameter is used to prevent CSRF attacks
- JWT verification is handled by the firebase/php-jwt library
- Tokens are validated for issuer, audience, and expiration
- **Email verification** is required by default before linking/creating accounts - disable only for trusted IdPs
- Client secrets are stored in the WordPress database (consider using environment variables for sensitive deployments)
- Environment variables can be used to keep credentials out of the database entirely
- **Rate limiting** protects all authentication endpoints against brute force and DoS attacks
- **SSRF protection** via `wp_safe_remote_get/post` blocks requests to internal IPs and non-standard ports
- For intranet identity providers, use the `http_request_host_is_external` WordPress filter
- **Object-cache note:** rate limiting uses transients, which a persistent object cache (memcached, some Redis configs) may evict under memory pressure before their expiry. On cache-backed sites, rate limiting is best-effort — signature verification, nonce binding, and PKCE do not depend on it. The back-channel logout jti replay cache is stored as database options and is not affected by cache eviction.

## Troubleshooting

### Common Issues

1. **"Invalid state parameter"**: This usually means the authentication took too long (>5 minutes by default) or cookies are not being preserved. Check your browser's cookie settings. You can increase the timeout using `SECURE_OIDC_STATE_TTL` (60-600 seconds).

2. **"Token exchange failed"**: Verify your client ID and secret are correct, and that the callback URL matches exactly what's configured in your IdP.

3. **"User does not exist"**: Enable "Create Users" in the plugin settings, or manually create the user in WordPress first.

4. **"Your email domain is not authorized"**: The user's email domain is not in the allowed list. Check the "Allowed Email Domains" setting or `SECURE_OIDC_ALLOWED_EMAIL_DOMAINS` environment variable. Wildcards like `*.example.com` can be used to allow all subdomains.

5. **Login button not appearing**: Ensure Client ID and Authorization Endpoint are configured.

6. **"Too many login attempts"**: You've been rate limited. Wait for the lockout period to expire (default: 15 minutes) or adjust rate limit settings via environment variables.

7. **"Discovery URL was blocked for security reasons"**: The IdP URL points to a private IP or uses a non-standard port. For intranet IdPs, add a filter:
   ```php
   add_filter('http_request_host_is_external', function($external, $host) {
       if ($host === 'idp.internal.company.com') {
           return true;
       }
       return $external;
   }, 10, 2);
   ```

### Debug Mode

To enable debug logging, add this to your `wp-config.php`:

```php
define('WP_DEBUG', true);
define('WP_DEBUG_LOG', true);
```

Then check `/wp-content/debug.log` for OIDC-related messages.

## Dependencies

This plugin uses the following open-source libraries:

- [firebase/php-jwt](https://github.com/firebase/php-jwt) - JWT verification and validation

## License

GPL v2 or later

## Contributing

Contributions are welcome! Please submit pull requests or open issues on the project repository.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for a detailed history of changes.

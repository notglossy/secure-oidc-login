# Secure OIDC Login

A secure OpenID Connect (OIDC) authentication plugin for WordPress that allows users to authenticate using any OIDC-compliant identity provider (IdP).

## Features

- **Standard OIDC Support**: Works with any OIDC-compliant identity provider (Keycloak, Okta, Auth0, Azure AD, Google, etc.)
- **Auto-Discovery**: Automatically configure endpoints using the IdP's discovery URL
- **PKCE Support**: Implements Proof Key for Code Exchange for enhanced security
- **User Provisioning**: Automatically create WordPress users on first login
- **Claim Mapping**: Configurable mapping of OIDC claims to WordPress user fields
- **Single Logout**: Optional logout from IdP when logging out of WordPress
- **Secure by Default**: Uses state parameter for CSRF protection and validates all tokens

## Requirements

- WordPress 5.8 or higher
- PHP 7.4 or higher
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

- PHP 7.4 or higher
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
| Authorization Endpoint | URL for the authorization endpoint | Yes |
| Token Endpoint | URL for the token endpoint | Yes |
| Userinfo Endpoint | URL for the userinfo endpoint | No |
| End Session Endpoint | URL for logout/end session | No |
| Issuer | Expected issuer value for token validation | No |
| Scope | OAuth scopes to request (default: `openid email profile`) | No |

#### Login Settings

| Setting | Description |
|---------|-------------|
| Login Button Text | Text displayed on the SSO login button |
| Enable Single Logout | When enabled, logging out of WordPress also logs out of the IdP |

#### User Settings

| Setting | Description |
|---------|-------------|
| Create Users | Automatically create WordPress users for new OIDC users |
| Default Role | WordPress role assigned to new users |
| Require Verified Email | Require the identity provider to verify email addresses before linking/creating accounts. Enabled by default for security. Disable only for trusted IdPs. |
| Username Claim | OIDC claim to use for WordPress username (default: `preferred_username`) |
| Email Claim | OIDC claim for email address (default: `email`) |
| First Name Claim | OIDC claim for first name (default: `given_name`) |
| Last Name Claim | OIDC claim for last name (default: `family_name`) |

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

**Token Validation:**
- `SECURE_OIDC_ISSUER` - Overrides the expected Issuer value for JWT validation

#### Setting Environment Variables

**On your server:**

```bash
export SECURE_OIDC_CLIENT_ID="your-client-id"
export SECURE_OIDC_CLIENT_SECRET="your-client-secret"
export SECURE_OIDC_DISCOVERY_URL="https://your-idp.com/.well-known/openid-configuration"
```

**Using .env file (with a WordPress .env loader):**

```
SECURE_OIDC_CLIENT_ID=your-client-id
SECURE_OIDC_CLIENT_SECRET=your-client-secret
SECURE_OIDC_DISCOVERY_URL=https://your-idp.com/.well-known/openid-configuration
```

**Using Docker (docker-compose.yml):**

```yaml
services:
  wordpress:
    environment:
      SECURE_OIDC_CLIENT_ID: "your-client-id"
      SECURE_OIDC_CLIENT_SECRET: "your-client-secret"
      SECURE_OIDC_DISCOVERY_URL: "https://your-idp.com/.well-known/openid-configuration"
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

## Security Considerations

- **Always use HTTPS** in production
- The plugin implements PKCE (Proof Key for Code Exchange) for enhanced security
- State parameter is used to prevent CSRF attacks
- JWT verification is handled by the firebase/php-jwt library
- Tokens are validated for issuer, audience, and expiration
- **Email verification** is required by default before linking/creating accounts - disable only for trusted IdPs
- Client secrets are stored in the WordPress database (consider using environment variables for sensitive deployments)
- Environment variables can be used to keep credentials out of the database entirely

## Troubleshooting

### Common Issues

1. **"Invalid state parameter"**: This usually means the authentication took too long (>5 minutes) or cookies are not being preserved. Check your browser's cookie settings.

2. **"Token exchange failed"**: Verify your client ID and secret are correct, and that the callback URL matches exactly what's configured in your IdP.

3. **"User does not exist"**: Enable "Create Users" in the plugin settings, or manually create the user in WordPress first.

4. **Login button not appearing**: Ensure Client ID and Authorization Endpoint are configured.

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

GPL v3

## Contributing

Contributions are welcome! Please submit pull requests or open issues on the project repository.

## Changelog

### 0.1.0-beta
- Initial beta release
- OIDC authorization code flow with PKCE
- Auto-discovery support
- User provisioning and claim mapping
- Single logout support
- Environment variable support for all OIDC endpoints and credentials
- Flexible email verification with configurable requirement
- Collision-safe Composer autoloader integration
- Full PHPStan level 6 type safety compliance

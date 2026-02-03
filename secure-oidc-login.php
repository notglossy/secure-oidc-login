<?php
declare(strict_types=1);
/**
 * Plugin Name: Secure OIDC Login
 * Plugin URI: https://github.com/notglossy/secure-oidc-login
 * Description: OpenID Connect (OIDC) authentication plugin for WordPress. Allows users to authenticate using any OIDC-compliant identity provider.
 * Version: 1.1.0
 * Requires at least: 5.8
 * Tested up to: 6.7
 * Requires PHP: 8.1
 * Author: Not Glossy
 * Author URI: https://github.com/notglossy
 * License: GPL v3
 * License URI: https://www.gnu.org/licenses/gpl-3.0.en.html
 * Text Domain: secure-oidc-login
 * Domain Path: /languages
 *
 * @package Secure_OIDC_Login
 */

// Prevent direct file access
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// Plugin version constant - used for cache busting and compatibility checks
define( 'SECURE_OIDC_LOGIN_VERSION', '1.1.0' );
// Plugin directory path constant - used for including files (has trailing slash)
define( 'SECURE_OIDC_LOGIN_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
// Plugin URL constant - used for enqueueing assets (has trailing slash)
define( 'SECURE_OIDC_LOGIN_PLUGIN_URL', plugin_dir_url( __FILE__ ) );

// Load Composer dependencies if not already loaded by another plugin
if ( ! class_exists( 'Firebase\JWT\JWT' ) ) {
	$autoload_path = SECURE_OIDC_LOGIN_PLUGIN_DIR . 'vendor/autoload.php';
	if ( file_exists( $autoload_path ) ) {
		require_once $autoload_path;
	} else {
		// Composer dependencies not installed
		add_action(
			'admin_notices',
			function () {
				echo '<div class="notice notice-error"><p>';
				printf(
					/* translators: %s: plugin name */
					esc_html__( '%s: Composer dependencies are missing. Please run "composer install" in the plugin directory.', 'secure-oidc-login' ),
					'<strong>Secure OIDC Login</strong>'
				);
				echo '</p></div>';
			}
		);
		return; // Stop plugin execution
	}
}

require_once SECURE_OIDC_LOGIN_PLUGIN_DIR . 'includes/class-oidc-client.php';
require_once SECURE_OIDC_LOGIN_PLUGIN_DIR . 'includes/class-oidc-admin.php';
require_once SECURE_OIDC_LOGIN_PLUGIN_DIR . 'includes/class-oidc-user-handler.php';
require_once SECURE_OIDC_LOGIN_PLUGIN_DIR . 'includes/class-oidc-token-crypto.php';
require_once SECURE_OIDC_LOGIN_PLUGIN_DIR . 'includes/class-oidc-rest-controller.php';
require_once SECURE_OIDC_LOGIN_PLUGIN_DIR . 'includes/class-oidc-rate-limiter.php';
require_once SECURE_OIDC_LOGIN_PLUGIN_DIR . 'includes/class-oidc-token-manager.php';
require_once SECURE_OIDC_LOGIN_PLUGIN_DIR . 'includes/class-oidc-token-refresh.php';

/**
 * Main plugin class implementing OpenID Connect authentication for WordPress.
 *
 * Uses the singleton pattern to ensure only one instance exists.
 * Handles the OIDC authorization code flow with PKCE for secure authentication.
 *
 * @since 0.1.0
 */
class Secure_OIDC_Login {
	/** @var Secure_OIDC_Login|null Singleton instance */
	private static $instance = null;

	/** @var OIDC_Client Handles OIDC protocol operations */
	private $client;

	/** @var OIDC_Admin Handles admin settings UI */
	private $admin;

	/** @var OIDC_User_Handler Handles WordPress user creation/mapping */
	private $user_handler;

	/** @var OIDC_Rate_Limiter Handles rate limiting for authentication endpoints */
	private $rate_limiter;

	/** @var OIDC_Token_Manager Handles token storage and retrieval */
	private $token_manager;

	/** @var OIDC_Token_Refresh Handles automatic token refresh */
	private $token_refresh;

	/**
	 * Get the singleton instance.
	 *
	 * @return Secure_OIDC_Login
	 */
	public static function get_instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Get a plugin setting value, checking environment variables first.
	 *
	 * Environment variables take precedence over database settings for sensitive values.
	 * This allows deployments to use .env files or server configuration instead of
	 * storing secrets in the WordPress database.
	 *
	 * Supported environment variables:
	 * - SECURE_OIDC_CLIENT_ID - Overrides database client_id
	 * - SECURE_OIDC_CLIENT_SECRET - Overrides database client_secret
	 * - SECURE_OIDC_DISCOVERY_URL - Pre-populates discovery_url
	 *
	 * @since 0.1.0
	 *
	 * @param string $option_key The settings array key to retrieve (e.g., 'client_secret').
	 * @param array<string, mixed>  $options    The full options array from get_option().
	 * @param string $env_var    Optional environment variable name to check first. If empty, derives from option_key.
	 * @return string The setting value from env var or database, or empty string if not set.
	 */
	public static function get_setting( string $option_key, array $options = array(), string $env_var = '' ): string {
		// If no environment variable specified, use convention: SECURE_OIDC_{UPPERCASE_KEY}
		if ( empty( $env_var ) ) {
			$env_var = 'SECURE_OIDC_' . strtoupper( $option_key );
		}

		// Check environment variable first (takes precedence)
		$env_value = getenv( $env_var );
		if ( false !== $env_value && '' !== $env_value ) {
			return (string) $env_value;
		}

		// Fall back to database value
		$setting = (string) ( $options[ $option_key ] ?? '' );

		// Allow filtering for advanced use cases
		return apply_filters( 'secure_oidc_login_setting_' . $option_key, $setting, $option_key );
	}

	/**
	 * Initialize the plugin components and register WordPress hooks.
	 */
	private function __construct() {
		$this->client        = new OIDC_Client();
		$this->admin         = new OIDC_Admin();
		$this->user_handler  = new OIDC_User_Handler();
		$this->rate_limiter  = new OIDC_Rate_Limiter();
		$this->token_manager = new OIDC_Token_Manager();
		$this->token_refresh = new OIDC_Token_Refresh( $this->client, $this->token_manager );

		add_action( 'init', array( $this, 'init' ) );
		add_action( 'init', array( $this, 'maybe_refresh_tokens' ), 20 );
		add_action( 'rest_api_init', array( $this, 'register_rest_routes' ) );
		add_action( 'login_form', array( $this, 'add_login_button' ) );
		add_action( 'login_form', array( $this, 'add_emergency_bypass_field' ) );
		add_action( 'wp_logout', array( $this, 'handle_logout' ), 10, 1 );
		add_action( 'login_head', array( $this, 'hide_native_login_form' ) );
		add_filter( 'authenticate', array( $this, 'block_native_authentication' ), 30, 3 );
		add_filter( 'login_errors', array( $this, 'display_login_errors' ) );

		register_activation_hook( __FILE__, array( $this, 'activate' ) );
		register_deactivation_hook( __FILE__, array( $this, 'deactivate' ) );
	}

	/**
	 * Initialize plugin on WordPress init.
	 *
	 * Loads translations and handles OIDC callback/login requests.
	 */
	public function init(): void {
		load_plugin_textdomain( 'secure-oidc-login', false, dirname( plugin_basename( __FILE__ ) ) . '/languages' );

		// Handle OIDC callback from identity provider
		if ( isset( $_GET['oidc_callback'] ) && $_GET['oidc_callback'] === '1' ) {
			// Start output buffering to prevent any stray output from blocking redirects
			// The buffer will be automatically discarded when exit is called
			ob_start();
			$this->handle_callback();
		}

		// Handle OIDC login initiation from login form
		if ( isset( $_GET['oidc_login'] ) && $_GET['oidc_login'] === '1' ) {
			$this->initiate_login();
		}
	}

	/**
	 * Register REST API routes.
	 *
	 * Instantiates the REST controller and registers its routes.
	 *
	 * @since 0.6.0
	 */
	public function register_rest_routes(): void {
		$controller = new OIDC_REST_Controller();
		$controller->register_routes();
	}

	/**
	 * Add SSO login button to the WordPress login form.
	 *
	 * Only displays if OIDC is properly configured.
	 */
	public function add_login_button(): void {
		$options = get_option( 'secure_oidc_login_settings' );

		// Check for required settings, including environment variables
		$client_id              = self::get_setting( 'client_id', $options );
		$authorization_endpoint = self::get_setting( 'authorization_endpoint', $options );

		if ( empty( $client_id ) || empty( $authorization_endpoint ) ) {
			return;
		}

		// Setup login button
		$button_text = __( 'Login with SSO', 'secure-oidc-login' );
		if ( ! empty( $options['login_button_text'] ) ) {
			$button_text = $options['login_button_text'];
		}
		$login_url = add_query_arg( 'oidc_login', '1', wp_login_url() );

		// Check if native login is disabled (keep if-then for clarity)
		$disable_native = false;
		if ( ! empty( $options['disable_native_login'] ) && ! $this->is_emergency_bypass_active() ) {
			$disable_native = true;
		}

		if ( $disable_native ) {
			// OIDC-only mode: Display button prominently (replaces form fields)
			?>
			<p class="oidc-button-container" style="text-align: center;">
				<a href="<?php echo esc_url( $login_url ); ?>" class="button button-primary button-large" style="width: 100%;">
					<?php echo esc_html( $button_text ); ?>
				</a>
			</p>
			<?php
		} else {
			// Hybrid mode: Display button as alternative
			?>
			<div style="margin: 20px 0; text-align: center;">
				<p style="margin-bottom: 10px;"><?php echo esc_html__( 'Or', 'secure-oidc-login' ); ?></p>
					<a href="<?php echo esc_url( $login_url ); ?>" class="button button-primary button-large" style="width: 100%;">
						<?php echo esc_html( $button_text ); ?>
					</a>
				</p>
			</div>
			<?php
		}
	}

	/**
	 * Add hidden field to preserve emergency bypass parameter in login form.
	 *
	 * When the login page is accessed with ?native=1, this adds a hidden field
	 * to ensure the parameter is preserved when the form is submitted via POST.
	 */
	public function add_emergency_bypass_field(): void {
		if ( $this->is_emergency_bypass_active() ) {
			echo '<input type="hidden" name="native" value="1" />';
		}
	}

	/**
	 * Check if emergency bypass is active via URL parameter.
	 *
	 * SECURITY: This bypass mechanism allows administrators to regain access
	 * if OIDC configuration fails. The bypass is controlled by the environment
	 * variable SECURE_OIDC_ENABLE_EMERGENCY_BYPASS which must be set to 'true'
	 * to enable the bypass functionality. This is disabled by default.
	 *
	 * When enabled, the ?native=1 URL parameter allows native WordPress login.
	 * Checks both GET and POST parameters to handle the case where the login
	 * form is submitted (POST) after loading the page with ?native=1 (GET).
	 *
	 * @since 0.5.0 Requires SECURE_OIDC_ENABLE_EMERGENCY_BYPASS=true to function.
	 *
	 * @return bool True if emergency bypass is enabled and parameter is present.
	 */
	private function is_emergency_bypass_active(): bool {
		// SECURITY: Emergency bypass must be explicitly enabled via environment variable
		$bypass_enabled = getenv( 'SECURE_OIDC_ENABLE_EMERGENCY_BYPASS' );
		if ( false === $bypass_enabled || 'true' !== strtolower( (string) $bypass_enabled ) ) {
			return false;
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- This is a feature flag, not user input
		return ( isset( $_GET['native'] ) && $_GET['native'] === '1' ) ||
				( isset( $_POST['native'] ) && $_POST['native'] === '1' );
	}

	/**
	 * Hide the native login form when OIDC-only mode is enabled.
	 *
	 * Injects CSS to hide username/password fields unless emergency bypass is active.
	 */
	public function hide_native_login_form(): void {
		$options = get_option( 'secure_oidc_login_settings' );

		if ( empty( $options['disable_native_login'] ) ) {
			return;
		}

		if ( $this->is_emergency_bypass_active() ) {
			return;
		}

		$client_id              = self::get_setting( 'client_id', $options );
		$authorization_endpoint = self::get_setting( 'authorization_endpoint', $options );

		if ( empty( $client_id ) || empty( $authorization_endpoint ) ) {
			return;
		}

		?>
		<style type="text/css">
			/* Hide native login form fields but keep the form container */
			#loginform p:not(.oidc-button-container),
			#loginform label,
			#loginform input,
			#loginform .forgetmenot,
			#loginform .submit,
			.login form#lostpasswordform,
			.login form#registerform,
			p#nav,
			p#backtoblog {
				display: none !important;
			}

			/* Add message above the form */
			#loginform::before {
				content: "<?php echo esc_js( __( 'Single Sign-On authentication is required.', 'secure-oidc-login' ) ); ?>";
				display: block;
				text-align: center;
				margin-bottom: 20px;
				padding: 12px 20px;
				background: #f0f0f1;
				border-left: 4px solid #72aee6;
			}
		</style>
		<?php
	}

	/**
	 * Block native username/password authentication when OIDC-only mode is enabled.
	 *
	 * Filters the authenticate process to prevent password-based login unless
	 * emergency bypass is active.
	 *
	 * @param WP_User|WP_Error|null $user     User object or error.
	 * @param string                $username Username or email.
	 * @param string                $password Password.
	 * @return WP_User|WP_Error|null User object or error.
	 */
	public function block_native_authentication( $user, $username, $password ): WP_User|WP_Error|null {
		if ( empty( $username ) || empty( $password ) ) {
			return $user;
		}

		$options = get_option( 'secure_oidc_login_settings' );

		if ( empty( $options['disable_native_login'] ) ) {
			return $user;
		}

		if ( $this->is_emergency_bypass_active() ) {
			return $user;
		}

		$client_id              = self::get_setting( 'client_id', $options );
		$authorization_endpoint = self::get_setting( 'authorization_endpoint', $options );

		if ( empty( $client_id ) || empty( $authorization_endpoint ) ) {
			return $user;
		}

		return new WP_Error(
			'oidc_native_login_disabled',
			__( '<strong>ERROR</strong>: Username/password authentication is disabled. Please use the Single Sign-On button above.', 'secure-oidc-login' )
		);
	}

	/**
	 * Display OIDC-related error messages on the login page.
	 *
	 * Filters the login_errors to add OIDC authentication errors passed via
	 * the oidc_error URL parameter. This ensures users see meaningful error
	 * messages when authentication fails, rather than a blank page or silent failure.
	 *
	 * @param string $errors Existing error messages.
	 * @return string Updated error messages including OIDC errors.
	 */
	public function display_login_errors( $errors ): string {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Reading error message from URL parameter
		if ( ! empty( $_GET['oidc_error'] ) ) {
			$oidc_error = sanitize_text_field( wp_unslash( $_GET['oidc_error'] ) );
			$errors    .= '<strong>' . esc_html__( 'SSO Error', 'secure-oidc-login' ) . ':</strong> ';
			$errors    .= esc_html( $oidc_error ) . '<br />';
		}
		return $errors;
	}

	/**
	 * Initiate the OIDC authorization code flow.
	 *
	 * Generates PKCE challenge, state, and nonce parameters for security,
	 * then redirects the user to the identity provider's authorization endpoint.
	 */
	public function initiate_login(): void {
		// SECURITY: Check rate limit to prevent state exhaustion attacks
		if ( $this->rate_limiter->is_rate_limited( 'login' ) ) {
			$expiry = $this->rate_limiter->get_lockout_expiry( 'login' );
			if ( false !== $expiry ) {
				$wait_time = $expiry - time();
				$this->handle_error(
					sprintf(
						/* translators: %d: number of seconds */
						__( 'Too many login attempts. Please wait %d seconds before trying again.', 'secure-oidc-login' ),
						$wait_time
					)
				);
			} else {
				$this->handle_error( __( 'Too many login attempts. Please try again later.', 'secure-oidc-login' ) );
			}
			return;
		}

		// Record this login attempt
		$this->rate_limiter->record_attempt( 'login' );

		$options = get_option( 'secure_oidc_login_settings' );

		// Get settings with environment variable support
		$client_id              = self::get_setting( 'client_id', $options );
		$authorization_endpoint = self::get_setting( 'authorization_endpoint', $options );

		if ( empty( $client_id ) || empty( $authorization_endpoint ) ) {
			wp_die( __( 'OIDC is not properly configured.', 'secure-oidc-login' ) );
		}

		// Get state/nonce TTL from environment or use default (5 minutes)
		// Configurable via SECURE_OIDC_STATE_TTL (60-600 seconds)
		$state_ttl = $this->get_state_ttl();

		// SECURITY: State parameter prevents CSRF attacks by linking the callback
		// to this specific authorization request. Attackers cannot trick users into
		// authenticating with an attacker-controlled account (session fixation).
		$state = wp_generate_password( 32, false );
		set_transient( 'oidc_state_' . $state, true, $state_ttl );

		// SECURITY: Nonce prevents token replay attacks. The nonce is embedded in
		// the ID token by the IdP and must match our expected value. This ensures
		// the token was issued in response to our specific authentication request.
		$nonce = wp_generate_password( 32, false );
		set_transient( 'oidc_nonce_' . $state, $nonce, $state_ttl );

		// SECURITY: PKCE (Proof Key for Code Exchange) prevents authorization code
		// interception attacks. Even if an attacker intercepts the authorization code,
		// they cannot exchange it for tokens without the code_verifier (which never
		// leaves this server). This protects public clients and adds defense-in-depth
		// for confidential clients. Per RFC 7636.
		$code_verifier = $this->generate_code_verifier();
		set_transient( 'oidc_code_verifier_' . $state, $code_verifier, $state_ttl );
		$code_challenge = $this->generate_code_challenge( $code_verifier );

		$redirect_uri = $this->get_callback_url();
		$scope        = 'openid email profile';

		if ( ! empty( $options['scope'] ) ) {
			$scope = $options['scope'];
		}

		$auth_params = array(
			'response_type'         => 'code',
			'client_id'             => $client_id,
			'redirect_uri'          => $redirect_uri,
			'scope'                 => $scope,
			'state'                 => $state,
			'nonce'                 => $nonce,
			'code_challenge'        => $code_challenge,
			'code_challenge_method' => 'S256',
		);

		$auth_url = $authorization_endpoint . '?' . http_build_query( $auth_params );

		wp_redirect( $auth_url );
		exit;
	}

	/**
	 * Handle the callback from the identity provider after user authentication.
	 *
	 * Validates the state parameter, exchanges the authorization code for tokens,
	 * validates the ID token, retrieves user info, and logs the user into WordPress.
	 */
	public function handle_callback(): void {
		// SECURITY: Check rate limit to prevent callback flooding and DoS attacks
		if ( $this->rate_limiter->is_rate_limited( 'callback' ) ) {
			$expiry = $this->rate_limiter->get_lockout_expiry( 'callback' );
			if ( false !== $expiry ) {
				$wait_time = $expiry - time();
				$this->handle_error(
					sprintf(
						/* translators: %d: number of seconds */
						__( 'Too many authentication attempts. Please wait %d seconds before trying again.', 'secure-oidc-login' ),
						$wait_time
					)
				);
			} else {
				$this->handle_error( __( 'Too many authentication attempts. Please try again later.', 'secure-oidc-login' ) );
			}
			return;
		}

		// Record this callback attempt
		$this->rate_limiter->record_attempt( 'callback' );

		// Verify state to prevent CSRF
		if ( empty( $_GET['state'] ) ) {
			$this->handle_error( __( 'Missing state parameter.', 'secure-oidc-login' ) );
			return;
		}

		$state        = sanitize_text_field( $_GET['state'] );
		$stored_state = get_transient( 'oidc_state_' . $state );

		if ( ! $stored_state ) {
			$this->handle_error( __( 'Invalid or expired state parameter.', 'secure-oidc-login' ) );
			return;
		}

		delete_transient( 'oidc_state_' . $state );

		// Check for errors returned by the IdP
		if ( ! empty( $_GET['error'] ) ) {
			// Keep if-then for nested condition clarity
			if ( ! empty( $_GET['error_description'] ) ) {
				$error_description = sanitize_text_field( $_GET['error_description'] );
			} else {
				$error_description = sanitize_text_field( $_GET['error'] );
			}
			$this->handle_error( $error_description );
			return;
		}

		if ( empty( $_GET['code'] ) ) {
			$this->handle_error( __( 'Missing authorization code.', 'secure-oidc-login' ) );
			return;
		}

		$code          = sanitize_text_field( $_GET['code'] );
		$code_verifier = get_transient( 'oidc_code_verifier_' . $state );
		delete_transient( 'oidc_code_verifier_' . $state );

		// Exchange authorization code for access/ID tokens
		$tokens = $this->client->exchange_code( $code, $code_verifier );

		if ( is_wp_error( $tokens ) ) {
			$this->handle_error( $tokens->get_error_message() );
			return;
		}

		// Retrieve nonce before validation
		$nonce = get_transient( 'oidc_nonce_' . $state );

		// Validate ID token claims (issuer, audience, expiration) and nonce
		$id_token_claims = $this->client->validate_id_token( $tokens['id_token'], $nonce, $code );

		if ( is_wp_error( $id_token_claims ) ) {
			$this->handle_error( $id_token_claims->get_error_message() );
			return;
		}

		// Delete nonce to prevent replay attacks
		delete_transient( 'oidc_nonce_' . $state );

		// Fetch additional user info from userinfo endpoint
		$userinfo = $this->client->get_userinfo( $tokens['access_token'] );

		if ( is_wp_error( $userinfo ) ) {
			$this->handle_error( $userinfo->get_error_message() );
			return;
		}

		// Find existing or create new WordPress user
		$user = $this->user_handler->get_or_create_user( $id_token_claims, $userinfo );

		if ( is_wp_error( $user ) ) {
			$this->handle_error( $user->get_error_message() );
			return;
		}

		// SECURITY: Store tokens encrypted at rest to protect against database compromises.
		// JWTs contain sensitive user information and session identifiers. If the database
		// is leaked, unencrypted tokens could allow session hijacking or information disclosure.
		// We use Sodium ChaCha20-Poly1305-IETF authenticated encryption for confidentiality and integrity.
		// SECURITY: Authentication FAILS if encryption fails - we never store plaintext tokens.
		$options = get_option( 'secure_oidc_login_settings' );

		// Prepare tokens for storage - always include access_token and id_token
		$tokens_to_store = array(
			'access_token' => $tokens['access_token'],
			'id_token'     => $tokens['id_token'],
			'expires_in'   => $tokens['expires_in'] ?? 3600,
		);

		// Include refresh token if:
		// 1. Single logout is enabled (existing behavior), OR
		// 2. Auto token refresh is enabled (new M3 feature)
		if ( ! empty( $tokens['refresh_token'] ) &&
			( ! empty( $options['enable_single_logout'] ) || ! empty( $options['enable_auto_token_refresh'] ) ) ) {
			$tokens_to_store['refresh_token'] = $tokens['refresh_token'];
		}

		// Store tokens using the token manager (handles encryption)
		$store_result = $this->token_manager->store_tokens( $user->ID, $tokens_to_store );
		if ( is_wp_error( $store_result ) ) {
			// SECURITY: Fail authentication if encryption fails - never store plaintext tokens
			OIDC_Token_Crypto::log_error( 'Token storage failed: ' . $store_result->get_error_message() );
			$this->handle_error(
				__( 'Authentication failed: Unable to securely store session tokens. Please contact your administrator.', 'secure-oidc-login' )
			);
			return;
		}

		// Clear rate limits on successful authentication
		$this->rate_limiter->clear_limit( 'callback' );
		$this->rate_limiter->clear_limit( 'login' );

		// Establish WordPress session
		wp_set_current_user( $user->ID );
		wp_set_auth_cookie( $user->ID, true );
		do_action( 'wp_login', $user->user_login, $user );

		// Redirect to requested page or admin dashboard
		// Use wp_validate_redirect() to prevent open redirect vulnerabilities
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Redirect URL from OAuth callback
		$requested_redirect = ! empty( $_GET['redirect_to'] ) ? esc_url_raw( wp_unslash( $_GET['redirect_to'] ) ) : '';
		$redirect_url       = wp_validate_redirect( $requested_redirect, admin_url() );

		// Ensure redirect URL is not empty (fallback to admin if wp_validate_redirect returns empty)
		if ( empty( $redirect_url ) ) {
			$redirect_url = admin_url();
		}

		// Use wp_redirect() since we've already validated the URL with wp_validate_redirect()
		// wp_safe_redirect() can fail in some edge cases even with valid URLs
		if ( ! wp_redirect( $redirect_url ) ) {
			// Fallback: If redirect fails (headers already sent), display a link
			wp_die(
				sprintf(
					/* translators: %s: URL to redirect to */
					__( 'Authentication successful. <a href="%s">Click here to continue</a>.', 'secure-oidc-login' ),
					esc_url( $redirect_url )
				)
			);
		}
		exit;
	}

	/**
	 * Handle user logout, optionally performing single logout with the IdP.
	 *
	 * @param int|null $user_id The ID of the user logging out.
	 */
	public function handle_logout( ?int $user_id = null ): void {
		if ( null === $user_id ) {
			$user_id = get_current_user_id();
		}

		// Guard against invalid user ID
		if ( ! $user_id ) {
			return;
		}

		$options = get_option( 'secure_oidc_login_settings' );

		// Get settings with environment variable support
		$end_session_endpoint = self::get_setting( 'end_session_endpoint', $options );

		// Get ID token before clearing (needed for single logout)
		$id_token = '';
		if ( ! empty( $end_session_endpoint ) && ! empty( $options['enable_single_logout'] ) ) {
			$maybe_id_token = $this->token_manager->get_id_token( $user_id );
			if ( ! is_wp_error( $maybe_id_token ) ) {
				$id_token = $maybe_id_token;
			} else {
				OIDC_Token_Crypto::log_error( 'ID token retrieval failed during logout: ' . $maybe_id_token->get_error_message() );
			}
		}

		// Clean up all stored OIDC tokens using token manager
		$this->token_manager->clear_tokens( $user_id );

		// Redirect to IdP logout if single logout is enabled
		if ( ! empty( $id_token ) && ! empty( $end_session_endpoint ) ) {
			$logout_params = array(
				'id_token_hint'            => $id_token,
				'post_logout_redirect_uri' => home_url(),
			);

			$logout_url = $end_session_endpoint . '?' . http_build_query( $logout_params );

			wp_redirect( $logout_url );
			exit;
		}
	}

	/**
	 * Check and refresh tokens if needed for the current user.
	 *
	 * Called on init hook (priority 20) to ensure tokens are refreshed before
	 * they expire. If refresh fails and enforcement is enabled, logs out the user.
	 *
	 * @since 0.7.0
	 */
	public function maybe_refresh_tokens(): void {
		// Only process for logged-in users
		if ( ! is_user_logged_in() ) {
			return;
		}

		$options = get_option( 'secure_oidc_login_settings' );

		// Check if auto-refresh is enabled
		if ( empty( $options['enable_auto_token_refresh'] ) ) {
			return;
		}

		$user_id = get_current_user_id();
		$result  = $this->token_refresh->maybe_refresh( $user_id );

		// If refresh failed and we should enforce it, log out the user
		if ( is_wp_error( $result ) ) {
			// Log the failure
			error_log(
				sprintf(
					'[Secure OIDC Login] Token refresh failed for user %d: %s',
					$user_id,
					$result->get_error_message()
				)
			);

			// Only force logout if the token is actually expired (not just failed to refresh)
			// This prevents logout during temporary IdP issues
			if ( $this->token_manager->is_token_expired( $user_id, 0 ) ) {
				wp_logout();
				wp_safe_redirect( wp_login_url() );
				exit;
			}
		}
	}

	/**
	 * Get the OIDC callback URL for this site.
	 *
	 * @return string The callback URL to be registered with the IdP.
	 */
	public function get_callback_url(): string {
		return add_query_arg( 'oidc_callback', '1', home_url( '/' ) );
	}

	/**
	 * Get the TTL for state/nonce transients.
	 *
	 * Configurable via SECURE_OIDC_STATE_TTL environment variable.
	 * Default is 300 seconds (5 minutes). Valid range: 60-600 seconds.
	 *
	 * @since 1.0.0
	 *
	 * @return int TTL in seconds.
	 */
	private function get_state_ttl(): int {
		$env_value = getenv( 'SECURE_OIDC_STATE_TTL' );
		if ( false === $env_value || '' === $env_value ) {
			return 300; // Default: 5 minutes
		}

		$parsed = filter_var( $env_value, FILTER_VALIDATE_INT );
		if ( false === $parsed || $parsed < 60 || $parsed > 600 ) {
			error_log( "[Secure OIDC Login] Invalid SECURE_OIDC_STATE_TTL value: {$env_value}. Using default 300 seconds." );
			return 300;
		}

		return $parsed;
	}

	/**
	 * Generate a cryptographically secure PKCE code verifier.
	 *
	 * Uses base64url encoding (not standard base64) per RFC 7636 section 4.1.
	 * Base64url uses '-' and '_' instead of '+' and '/' and omits padding '='.
	 * This makes the verifier URL-safe for transmission in query parameters.
	 *
	 * @return string Base64url-encoded random string (43 characters, 256 bits of entropy).
	 */
	private function generate_code_verifier(): string {
		// Generate 32 random bytes (256 bits)
		// Base64url encode: replace +/= with -_
		return rtrim( strtr( base64_encode( random_bytes( 32 ) ), '+/', '-_' ), '=' );
	}

	/**
	 * Generate a PKCE code challenge from the verifier using SHA-256.
	 *
	 * Uses base64url encoding (not standard base64) per RFC 7636 section 4.2.
	 * The challenge is sent to the IdP during authorization, while the verifier
	 * is kept secret and sent during token exchange to prove we initiated the request.
	 *
	 * @param string $verifier The code verifier.
	 * @return string Base64url-encoded SHA-256 hash of the verifier (43 characters).
	 */
	private function generate_code_challenge( $verifier ): string {
		// SHA-256 hash the verifier (returns 32 bytes when $binary = true)
		// Base64url encode: replace +/= with -_
		return rtrim( strtr( base64_encode( hash( 'sha256', $verifier, true ) ), '+/', '-_' ), '=' );
	}

	/**
	 * Redirect to login page with an error message.
	 *
	 * @param string $message The error message to display.
	 */
	private function handle_error( string $message ): void {
		$login_url = wp_login_url();
		$login_url = add_query_arg( 'oidc_error', urlencode( $message ), $login_url );

		// Use wp_redirect() instead of wp_safe_redirect() since wp_login_url() is always safe
		if ( ! wp_redirect( $login_url ) ) {
			// Fallback: If redirect fails (headers already sent), display error with link
			wp_die(
				sprintf(
					/* translators: 1: Error message, 2: Login URL */
					__( '<strong>Authentication Error:</strong> %1$s<br><br><a href="%2$s">Return to login page</a>', 'secure-oidc-login' ),
					esc_html( $message ),
					esc_url( $login_url )
				)
			);
		}
		exit;
	}

	/**
	 * Plugin activation hook. Sets up default options.
	 */
	public function activate(): void {
		$default_options = array(
			'client_id'                      => '',
			'client_secret'                  => '',
			'authorization_endpoint'         => '',
			'token_endpoint'                 => '',
			'userinfo_endpoint'              => '',
			'end_session_endpoint'           => '',
			'jwks_uri'                       => '',
			'issuer'                         => '',
			'scope'                          => 'openid email profile',
			'login_button_text'              => 'Login with SSO',
			'enable_single_logout'           => false,
			'disable_native_login'           => false,
			'enable_auto_token_refresh'      => false,
			'token_refresh_buffer'           => 300,
			'enforce_refresh_token_rotation' => false,
			'create_users'                   => true,
			'require_verified_email'         => true,
			'default_role'                   => 'subscriber',
			'username_claim'                 => 'preferred_username',
			'email_claim'                    => 'email',
			'first_name_claim'               => 'given_name',
			'last_name_claim'                => 'family_name',
			'allowed_email_domains'          => '',
		);

		if ( ! get_option( 'secure_oidc_login_settings' ) ) {
			add_option( 'secure_oidc_login_settings', $default_options );
		}
	}

	/**
	 * Plugin deactivation hook. Cleans up OIDC-related transients.
	 */
	public function deactivate(): void {
		global $wpdb;
		$wpdb->query(
			$wpdb->prepare(
				"DELETE FROM {$wpdb->options} WHERE option_name LIKE %s OR option_name LIKE %s",
				$wpdb->esc_like( '_transient_oidc_' ) . '%',
				$wpdb->esc_like( '_transient_timeout_oidc_' ) . '%'
			)
		);
	}
}

// Initialize the plugin
Secure_OIDC_Login::get_instance();

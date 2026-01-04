<?php
/**
 * Plugin Name: Secure OIDC Login
 * Plugin URI: https://github.com/notglossy/secure-oidc-login
 * Description: OpenID Connect (OIDC) authentication plugin for WordPress. Allows users to authenticate using any OIDC-compliant identity provider.
 * Version: 0.2.0-beta
 * Requires at least: 5.8
 * Tested up to: 6.7
 * Requires PHP: 7.4
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

define( 'SECURE_OIDC_LOGIN_VERSION', '0.2.0' );
define( 'SECURE_OIDC_LOGIN_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
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
		$setting = isset( $options[ $option_key ] ) ? (string) $options[ $option_key ] : '';

		// Allow filtering for advanced use cases
		return apply_filters( 'secure_oidc_login_setting_' . $option_key, $setting, $option_key );
	}

	/**
	 * Initialize the plugin components and register WordPress hooks.
	 */
	private function __construct() {
		$this->client       = new OIDC_Client();
		$this->admin        = new OIDC_Admin();
		$this->user_handler = new OIDC_User_Handler();

		add_action( 'init', array( $this, 'init' ) );
		add_action( 'login_form', array( $this, 'add_login_button' ) );
		add_action( 'login_form', array( $this, 'add_emergency_bypass_field' ) );
		add_action( 'wp_logout', array( $this, 'handle_logout' ), 10, 1 );
		add_action( 'login_head', array( $this, 'hide_native_login_form' ) );
		add_filter( 'authenticate', array( $this, 'block_native_authentication' ), 30, 3 );

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
			$this->handle_callback();
		}

		// Handle OIDC login initiation from login form
		if ( isset( $_GET['oidc_login'] ) && $_GET['oidc_login'] === '1' ) {
			$this->initiate_login();
		}
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

		// Check if native login is disabled
		$disable_native = ! empty( $options['disable_native_login'] ) && ! $this->is_emergency_bypass_active();

		if ( $disable_native ) {
			// OIDC-only mode: Display button prominently (replaces form fields)
			echo '<p class="oidc-button-container" style="text-align: center;">';
			echo '<a href="' . esc_url( $login_url ) . '" class="button button-primary button-large" style="width: 100%;">';
			echo esc_html( $button_text );
			echo '</a>';
			echo '</p>';
		} else {
			// Hybrid mode: Display button as alternative
			echo '<div style="margin: 20px 0; text-align: center;">';
			echo '<p style="margin-bottom: 10px;">' . esc_html__( 'Or', 'secure-oidc-login' ) . '</p>';
			echo '<a href="' . esc_url( $login_url ) . '" class="button button-primary button-large" style="width: 100%;">';
			echo esc_html( $button_text );
			echo '</a>';
			echo '</div>';
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
	 * Checks both GET and POST parameters to handle the case where the login
	 * form is submitted (POST) after loading the page with ?native=1 (GET).
	 *
	 * @return bool True if emergency bypass parameter is present.
	 */
	private function is_emergency_bypass_active(): bool {
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
	 * @return WP_User|WP_Error User object or error.
	 */
	public function block_native_authentication( $user, $username, $password ) {
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
	 * Initiate the OIDC authorization code flow.
	 *
	 * Generates PKCE challenge, state, and nonce parameters for security,
	 * then redirects the user to the identity provider's authorization endpoint.
	 */
	public function initiate_login(): void {
		$options = get_option( 'secure_oidc_login_settings' );

		// Get settings with environment variable support
		$client_id              = self::get_setting( 'client_id', $options );
		$authorization_endpoint = self::get_setting( 'authorization_endpoint', $options );

		if ( empty( $client_id ) || empty( $authorization_endpoint ) ) {
			wp_die( __( 'OIDC is not properly configured.', 'secure-oidc-login' ) );
		}

		// State parameter prevents CSRF attacks
		$state = wp_generate_password( 32, false );
		set_transient( 'oidc_state_' . $state, true, 300 );

		// Nonce prevents token replay attacks
		$nonce = wp_generate_password( 32, false );
		set_transient( 'oidc_nonce_' . $state, $nonce, 300 );

		// PKCE (Proof Key for Code Exchange) prevents authorization code interception
		$code_verifier = $this->generate_code_verifier();
		set_transient( 'oidc_code_verifier_' . $state, $code_verifier, 300 );
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
			$error_description = ! empty( $_GET['error_description'] ) ? sanitize_text_field( $_GET['error_description'] ) : sanitize_text_field( $_GET['error'] );
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

		// Store tokens for single logout support (encrypt at rest)
		$options = get_option( 'secure_oidc_login_settings' );

		$id_token_to_store = $tokens['id_token'];
		$encrypted_id      = OIDC_Token_Crypto::encrypt( $id_token_to_store );
		if ( is_wp_error( $encrypted_id ) ) {
			OIDC_Token_Crypto::log_error( 'ID token encryption failed: ' . $encrypted_id->get_error_message() );
		} else {
			$id_token_to_store = $encrypted_id;
		}
		update_user_meta( $user->ID, 'oidc_id_token', $id_token_to_store );

		// Persist refresh token only when single logout is enabled
		if ( ! empty( $tokens['refresh_token'] ) && ! empty( $options['enable_single_logout'] ) ) {
			$refresh_token_to_store = $tokens['refresh_token'];
			$encrypted_refresh      = OIDC_Token_Crypto::encrypt( $refresh_token_to_store );
			if ( is_wp_error( $encrypted_refresh ) ) {
				OIDC_Token_Crypto::log_error( 'Refresh token encryption failed: ' . $encrypted_refresh->get_error_message() );
			} else {
				$refresh_token_to_store = $encrypted_refresh;
			}
			update_user_meta( $user->ID, 'oidc_refresh_token', $refresh_token_to_store );
		}

		// Establish WordPress session
		wp_set_current_user( $user->ID );
		wp_set_auth_cookie( $user->ID, true );
		do_action( 'wp_login', $user->user_login, $user );

		// Redirect to requested page or admin dashboard
		// Use wp_validate_redirect() to prevent open redirect vulnerabilities
		$requested_redirect = ! empty( $_GET['redirect_to'] ) ? $_GET['redirect_to'] : '';
		$redirect_url       = wp_validate_redirect( $requested_redirect, admin_url() );

		wp_safe_redirect( $redirect_url );
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

		if ( empty( $end_session_endpoint ) ) {
			return;
		}

		$stored_id_token = get_user_meta( $user_id, 'oidc_id_token', true );
		$id_token        = '';

		if ( ! empty( $stored_id_token ) ) {
			$maybe_decrypted = OIDC_Token_Crypto::decrypt_if_needed( $stored_id_token );
			if ( is_wp_error( $maybe_decrypted ) ) {
				OIDC_Token_Crypto::log_error( 'ID token decrypt failed during logout: ' . $maybe_decrypted->get_error_message() );
			} else {
				$id_token = $maybe_decrypted;
			}
		}

		// Clean up stored OIDC tokens
		delete_user_meta( $user_id, 'oidc_id_token' );
		delete_user_meta( $user_id, 'oidc_refresh_token' );

		// Redirect to IdP logout if single logout is enabled
		if ( ! empty( $id_token ) && ! empty( $options['enable_single_logout'] ) ) {
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
	 * Get the OIDC callback URL for this site.
	 *
	 * @return string The callback URL to be registered with the IdP.
	 */
	public function get_callback_url() {
		return add_query_arg( 'oidc_callback', '1', home_url( '/' ) );
	}

	/**
	 * Generate a cryptographically secure PKCE code verifier.
	 *
	 * @return string Base64url-encoded random string.
	 */
	private function generate_code_verifier() {
		return rtrim( strtr( base64_encode( random_bytes( 32 ) ), '+/', '-_' ), '=' );
	}

	/**
	 * Generate a PKCE code challenge from the verifier using SHA-256.
	 *
	 * @param string $verifier The code verifier.
	 * @return string Base64url-encoded SHA-256 hash of the verifier.
	 */
	private function generate_code_challenge( $verifier ) {
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
		wp_safe_redirect( $login_url );
		exit;
	}

	/**
	 * Plugin activation hook. Sets up default options.
	 */
	public function activate(): void {
		$default_options = array(
			'client_id'              => '',
			'client_secret'          => '',
			'authorization_endpoint' => '',
			'token_endpoint'         => '',
			'userinfo_endpoint'      => '',
			'end_session_endpoint'   => '',
			'jwks_uri'               => '',
			'issuer'                 => '',
			'scope'                  => 'openid email profile',
			'login_button_text'      => 'Login with SSO',
			'enable_single_logout'   => false,
			'disable_native_login'   => false,
			'create_users'           => true,
			'require_verified_email' => true,
			'default_role'           => 'subscriber',
			'username_claim'         => 'preferred_username',
			'email_claim'            => 'email',
			'first_name_claim'       => 'given_name',
			'last_name_claim'        => 'family_name',
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

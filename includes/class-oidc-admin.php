<?php
/**
 * OIDC Admin class for handling WordPress admin settings.
 *
 * @package Secure_OIDC_Login
 * @since 0.1.0
 */

// Prevent direct file access
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Handles the WordPress admin settings page for OIDC configuration.
 *
 * Provides a settings interface for configuring the identity provider,
 * login behavior, and user mapping options.
 */
class OIDC_Admin {
	/**
	 * Register WordPress hooks for admin functionality.
	 */
	public function __construct() {
		add_action( 'admin_menu', array( $this, 'add_admin_menu' ) );
		add_action( 'admin_init', array( $this, 'register_settings' ) );
		add_action( 'admin_init', array( $this, 'handle_credential_deletion' ) );
		add_action( 'admin_notices', array( $this, 'admin_notices' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_admin_scripts' ) );
	}

	/**
	 * Check if unsafe database storage mode is explicitly enabled.
	 *
	 * When SECURE_OIDC_ALLOW_UNSAFE=true is set, administrators can store
	 * client credentials in the WordPress database. This is less secure than
	 * using environment variables but may be necessary in some hosting environments.
	 *
	 * @return bool True if unsafe mode is enabled.
	 */
	private function is_unsafe_mode_enabled(): bool {
		$allow_unsafe = getenv( 'SECURE_OIDC_ALLOW_UNSAFE' );
		return false !== $allow_unsafe && 'true' === strtolower( $allow_unsafe );
	}

	/**
	 * Check if credentials are set via environment variables.
	 *
	 * @return bool True if both client_id and client_secret are set via env vars.
	 */
	private function has_env_credentials(): bool {
		$has_client_id     = false !== getenv( 'SECURE_OIDC_CLIENT_ID' ) && '' !== getenv( 'SECURE_OIDC_CLIENT_ID' );
		$has_client_secret = false !== getenv( 'SECURE_OIDC_CLIENT_SECRET' ) && '' !== getenv( 'SECURE_OIDC_CLIENT_SECRET' );
		return $has_client_id && $has_client_secret;
	}

	/**
	 * Check if credentials are stored in the database.
	 *
	 * @return bool True if client_id or client_secret exists in database options.
	 */
	private function has_database_credentials(): bool {
		$options = get_option( 'secure_oidc_login_settings', array() );
		return ( ! empty( $options['client_id'] ) || ! empty( $options['client_secret'] ) );
	}

	/**
	 * Handle credential deletion form submission.
	 *
	 * Processes the nonce-protected form for removing client credentials from database.
	 */
	public function handle_credential_deletion(): void {
		// Check if deletion was requested
		if ( ! isset( $_POST['secure_oidc_delete_credentials'] ) ) {
			return;
		}

		// Verify user capability
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		// Verify nonce
		if ( ! isset( $_POST['_wpnonce_delete_credentials'] ) ||
			! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['_wpnonce_delete_credentials'] ) ), 'secure_oidc_delete_credentials' ) ) {
			add_settings_error(
				'secure_oidc_login_settings',
				'nonce_verification_failed',
				__( 'Security verification failed. Please try again.', 'secure-oidc-login' ),
				'error'
			);
			return;
		}

		// Remove credentials from database
		$options = get_option( 'secure_oidc_login_settings', array() );
		$options['client_id']     = '';
		$options['client_secret'] = '';
		update_option( 'secure_oidc_login_settings', $options );

		add_settings_error(
			'secure_oidc_login_settings',
			'credentials_deleted',
			__( 'Client credentials have been removed from the database.', 'secure-oidc-login' ),
			'success'
		);
	}

	/**
	 * Enqueue admin scripts and styles for the settings page.
	 *
	 * @param string $hook The current admin page hook.
	 */
	public function enqueue_admin_scripts( string $hook ): void {
		// Only load on our settings page
		if ( 'settings_page_secure-oidc-login' !== $hook ) {
			return;
		}

		// Enqueue the admin settings JavaScript
		wp_enqueue_script(
			'oidc-admin-settings',
			SECURE_OIDC_LOGIN_PLUGIN_URL . 'assets/js/admin-settings.js',
			array( 'jquery' ),
			SECURE_OIDC_LOGIN_VERSION,
			true
		);

		// Pass dynamic values to JavaScript
		wp_localize_script(
			'oidc-admin-settings',
			'oidcAdminSettings',
			array(
				'restUrl'   => rest_url( 'secure-oidc-login/v1/discover' ),
				'restNonce' => wp_create_nonce( 'wp_rest' ),
				'i18n'      => array(
					'enterDiscoveryUrl'      => __( 'Please enter a discovery URL.', 'secure-oidc-login' ),
					'discovering'            => __( 'Discovering...', 'secure-oidc-login' ),
					'discover'               => __( 'Discover', 'secure-oidc-login' ),
					'discoverySuccess'       => __( 'Configuration discovered successfully!', 'secure-oidc-login' ),
					'discoveryFailed'        => __( 'Discovery failed.', 'secure-oidc-login' ),
					'discoveryRequestFailed' => __( 'Discovery request failed.', 'secure-oidc-login' ),
				),
			)
		);
	}

	/**
	 * Get maximum length limits for input fields.
	 *
	 * Defines reasonable maximum lengths for OIDC configuration fields
	 * to prevent DoS attacks via large inputs and database bloat.
	 *
	 * @return array<string, int> Field name to maximum length mapping.
	 */
	private function get_max_lengths(): array {
		return array(
			'client_id'              => 255,
			'client_secret'          => 512,
			'discovery_url'          => 2048,
			'authorization_endpoint' => 2048,
			'token_endpoint'         => 2048,
			'userinfo_endpoint'      => 2048,
			'end_session_endpoint'   => 2048,
			'jwks_uri'               => 2048,
			'issuer'                 => 512,
			'scope'                  => 512,
			'login_button_text'      => 100,
			'username_claim'         => 100,
			'email_claim'            => 100,
			'first_name_claim'       => 100,
			'last_name_claim'        => 100,
			'default_role'           => 50,
			'allowed_email_domains'  => 512,
		);
	}

	/**
	 * Add the settings page to the WordPress admin menu.
	 */
	public function add_admin_menu(): void {
		add_options_page(
			__( 'OIDC Authentication', 'secure-oidc-login' ),
			__( 'OIDC Auth', 'secure-oidc-login' ),
			'manage_options',
			'secure-oidc-login',
			array( $this, 'render_settings_page' )
		);
	}

	/**
	 * Register all settings fields and sections.
	 *
	 * Organizes settings into three sections:
	 * - Identity Provider Settings (endpoints, credentials)
	 * - Login Settings (button text, single logout)
	 * - User Settings (claim mappings, user creation)
	 */
	public function register_settings(): void {
		register_setting(
			'secure_oidc_login_settings_group',
			'secure_oidc_login_settings',
			array( $this, 'sanitize_settings' )
		);

		// === Identity Provider Settings Section ===
		add_settings_section(
			'oidc_provider_section',
			__( 'Identity Provider Settings', 'secure-oidc-login' ),
			array( $this, 'render_provider_section' ),
			'secure-oidc-login'
		);

		add_settings_field(
			'discovery_url',
			__( 'Discovery URL', 'secure-oidc-login' ),
			array( $this, 'render_discovery_field' ),
			'secure-oidc-login',
			'oidc_provider_section'
		);

		add_settings_field(
			'client_id',
			__( 'Client ID', 'secure-oidc-login' ),
			array( $this, 'render_text_field' ),
			'secure-oidc-login',
			'oidc_provider_section',
			array(
				'field'    => 'client_id',
				'required' => true,
			)
		);

		add_settings_field(
			'client_secret',
			__( 'Client Secret', 'secure-oidc-login' ),
			array( $this, 'render_password_field' ),
			'secure-oidc-login',
			'oidc_provider_section',
			array( 'field' => 'client_secret' )
		);

		add_settings_field(
			'authorization_endpoint',
			__( 'Authorization Endpoint', 'secure-oidc-login' ),
			array( $this, 'render_text_field' ),
			'secure-oidc-login',
			'oidc_provider_section',
			array(
				'field'    => 'authorization_endpoint',
				'required' => true,
				'type'     => 'url',
			)
		);

		add_settings_field(
			'token_endpoint',
			__( 'Token Endpoint', 'secure-oidc-login' ),
			array( $this, 'render_text_field' ),
			'secure-oidc-login',
			'oidc_provider_section',
			array(
				'field'    => 'token_endpoint',
				'required' => true,
				'type'     => 'url',
			)
		);

		add_settings_field(
			'userinfo_endpoint',
			__( 'Userinfo Endpoint', 'secure-oidc-login' ),
			array( $this, 'render_text_field' ),
			'secure-oidc-login',
			'oidc_provider_section',
			array(
				'field' => 'userinfo_endpoint',
				'type'  => 'url',
			)
		);

		add_settings_field(
			'end_session_endpoint',
			__( 'End Session Endpoint', 'secure-oidc-login' ),
			array( $this, 'render_text_field' ),
			'secure-oidc-login',
			'oidc_provider_section',
			array(
				'field' => 'end_session_endpoint',
				'type'  => 'url',
			)
		);

		add_settings_field(
			'jwks_uri',
			__( 'JWKS URI', 'secure-oidc-login' ),
			array( $this, 'render_text_field' ),
			'secure-oidc-login',
			'oidc_provider_section',
			array(
				'field'       => 'jwks_uri',
				'required'    => true,
				'type'        => 'url',
				'description' => __( 'URL to the JSON Web Key Set for signature verification.', 'secure-oidc-login' ),
			)
		);

		add_settings_field(
			'issuer',
			__( 'Issuer', 'secure-oidc-login' ),
			array( $this, 'render_text_field' ),
			'secure-oidc-login',
			'oidc_provider_section',
			array(
				'field' => 'issuer',
				'type'  => 'url',
			)
		);

		add_settings_field(
			'scope',
			__( 'Scope', 'secure-oidc-login' ),
			array( $this, 'render_text_field' ),
			'secure-oidc-login',
			'oidc_provider_section',
			array(
				'field'   => 'scope',
				'default' => 'openid email profile',
			)
		);

		// === Login Settings Section ===
		add_settings_section(
			'oidc_login_section',
			__( 'Login Settings', 'secure-oidc-login' ),
			array( $this, 'render_login_section' ),
			'secure-oidc-login'
		);

		add_settings_field(
			'login_button_text',
			__( 'Login Button Text', 'secure-oidc-login' ),
			array( $this, 'render_text_field' ),
			'secure-oidc-login',
			'oidc_login_section',
			array(
				'field'   => 'login_button_text',
				'default' => 'Login with SSO',
			)
		);

		add_settings_field(
			'enable_single_logout',
			__( 'Enable Single Logout', 'secure-oidc-login' ),
			array( $this, 'render_checkbox_field' ),
			'secure-oidc-login',
			'oidc_login_section',
			array(
				'field'       => 'enable_single_logout',
				'description' => __( 'Logout from identity provider when logging out of WordPress.', 'secure-oidc-login' ),
			)
		);

		add_settings_field(
			'disable_native_login',
			__( 'Disable Native Login', 'secure-oidc-login' ),
			array( $this, 'render_checkbox_field' ),
			'secure-oidc-login',
			'oidc_login_section',
			array(
				'field'       => 'disable_native_login',
				'description' => __( 'Hide username/password form and block native authentication. Emergency access: add ?native=1 to login URL.', 'secure-oidc-login' ),
			)
		);

		// === User Settings Section ===
		add_settings_section(
			'oidc_user_section',
			__( 'User Settings', 'secure-oidc-login' ),
			array( $this, 'render_user_section' ),
			'secure-oidc-login'
		);

		add_settings_field(
			'create_users',
			__( 'Create Users', 'secure-oidc-login' ),
			array( $this, 'render_checkbox_field' ),
			'secure-oidc-login',
			'oidc_user_section',
			array(
				'field'       => 'create_users',
				'description' => __( 'Automatically create WordPress users for new OIDC users.', 'secure-oidc-login' ),
			)
		);

		add_settings_field(
			'require_verified_email',
			__( 'Require Verified Email', 'secure-oidc-login' ),
			array( $this, 'render_checkbox_field' ),
			'secure-oidc-login',
			'oidc_user_section',
			array(
				'field'       => 'require_verified_email',
				'description' => __( 'Require the identity provider to verify email addresses. Disable only for trusted IdPs.', 'secure-oidc-login' ),
			)
		);

		add_settings_field(
			'default_role',
			__( 'Default Role', 'secure-oidc-login' ),
			array( $this, 'render_role_field' ),
			'secure-oidc-login',
			'oidc_user_section',
			array( 'field' => 'default_role' )
		);

		add_settings_field(
			'username_claim',
			__( 'Username Claim', 'secure-oidc-login' ),
			array( $this, 'render_text_field' ),
			'secure-oidc-login',
			'oidc_user_section',
			array(
				'field'       => 'username_claim',
				'default'     => 'preferred_username',
				'description' => __( 'OIDC claim to use for WordPress username.', 'secure-oidc-login' ),
			)
		);

		add_settings_field(
			'email_claim',
			__( 'Email Claim', 'secure-oidc-login' ),
			array( $this, 'render_text_field' ),
			'secure-oidc-login',
			'oidc_user_section',
			array(
				'field'   => 'email_claim',
				'default' => 'email',
			)
		);

		add_settings_field(
			'first_name_claim',
			__( 'First Name Claim', 'secure-oidc-login' ),
			array( $this, 'render_text_field' ),
			'secure-oidc-login',
			'oidc_user_section',
			array(
				'field'   => 'first_name_claim',
				'default' => 'given_name',
			)
		);

		add_settings_field(
			'last_name_claim',
			__( 'Last Name Claim', 'secure-oidc-login' ),
			array( $this, 'render_text_field' ),
			'secure-oidc-login',
			'oidc_user_section',
			array(
				'field'   => 'last_name_claim',
				'default' => 'family_name',
			)
		);

		add_settings_field(
			'allowed_email_domains',
			__( 'Allowed Email Domains', 'secure-oidc-login' ),
			array( $this, 'render_text_field' ),
			'secure-oidc-login',
			'oidc_user_section',
			array(
				'field'       => 'allowed_email_domains',
				'description' => __( 'Comma-separated list of allowed email domains (e.g., example.com,subsidiary.com). Leave empty to allow all domains. Supports wildcards like *.example.com for subdomains.', 'secure-oidc-login' ),
			)
		);
	}

	/**
	 * Sanitize and validate settings before saving.
	 *
	 * @param array<string, mixed> $input The raw input from the settings form.
	 * @return array<string, mixed> Sanitized settings array.
	 */
	public function sanitize_settings( array $input ): array {
		// Security check: Verify user has permission to modify settings
		if ( ! current_user_can( 'manage_options' ) ) {
			add_settings_error(
				'secure_oidc_login_settings',
				'capability_check_failed',
				__( 'You do not have permission to modify these settings.', 'secure-oidc-login' ),
				'error'
			);
			return get_option( 'secure_oidc_login_settings', array() );
		}

		// SECURITY: Verify nonce explicitly for CSRF protection
		// Prevents attackers from tricking admins into changing OIDC settings via malicious forms
		// The nonce is automatically generated by settings_fields() and must match
		if ( ! isset( $_POST['_wpnonce'] ) ||
			! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['_wpnonce'] ) ), 'secure_oidc_login_settings_group-options' ) ) {
			add_settings_error(
				'secure_oidc_login_settings',
				'nonce_verification_failed',
				__( 'Security verification failed. Please try again.', 'secure-oidc-login' ),
				'error'
			);
			return get_option( 'secure_oidc_login_settings', array() );
		}

		// Get maximum length limits for validation
		$max_lengths = $this->get_max_lengths();

		$sanitized = array();

		// Get existing settings to preserve values when validation fails
		$existing_settings = get_option( 'secure_oidc_login_settings', array() );

		// Text fields - sanitize as plain text
		$text_fields = array(
			'client_id',
			'client_secret',
			'scope',
			'login_button_text',
			'username_claim',
			'email_claim',
			'first_name_claim',
			'last_name_claim',
			'default_role',
			'issuer',
			'allowed_email_domains',
		);

		// URL fields - validate and sanitize as URLs
		$url_fields = array(
			'authorization_endpoint',
			'token_endpoint',
			'userinfo_endpoint',
			'end_session_endpoint',
			'jwks_uri',
		);

		// Boolean checkbox fields
		$checkbox_fields = array( 'enable_single_logout', 'create_users', 'require_verified_email', 'disable_native_login' );

		// Credential fields that require special security handling
		$credential_fields = array( 'client_id', 'client_secret' );

		foreach ( $text_fields as $field ) {
			$value = sanitize_text_field( $input[ $field ] ?? '' );

			// SECURITY: Block saving credentials unless unsafe mode is explicitly enabled
			// or the field is being set via environment variable
			if ( in_array( $field, $credential_fields, true ) ) {
				$env_var           = 'SECURE_OIDC_' . strtoupper( $field );
				$is_env_overridden = false !== getenv( $env_var ) && '' !== getenv( $env_var );

				// If env var is set, don't allow database storage (ignore input)
				if ( $is_env_overridden ) {
					$sanitized[ $field ] = '';
					continue;
				}

				// If unsafe mode is not enabled, preserve existing value and block new values
				if ( ! $this->is_unsafe_mode_enabled() ) {
					$sanitized[ $field ] = $existing_settings[ $field ] ?? '';
					continue;
				}
			}

			// Validate length if max length is defined for this field
			if ( isset( $max_lengths[ $field ] ) && strlen( $value ) > $max_lengths[ $field ] ) {
				add_settings_error(
					'secure_oidc_login_settings',
					$field . '_too_long',
					sprintf(
						/* translators: 1: field name, 2: maximum length */
						__( '%1$s exceeds maximum length of %2$d characters.', 'secure-oidc-login' ),
						ucwords( str_replace( '_', ' ', $field ) ),
						$max_lengths[ $field ]
					)
				);
				// Preserve the existing value if validation fails
				$sanitized[ $field ] = $existing_settings[ $field ] ?? '';
			} else {
				$sanitized[ $field ] = $value;
			}
		}

		foreach ( $url_fields as $field ) {
			$value = esc_url_raw( $input[ $field ] ?? '' );

			// Validate length if max length is defined for this field
			if ( isset( $max_lengths[ $field ] ) && strlen( $value ) > $max_lengths[ $field ] ) {
				add_settings_error(
					'secure_oidc_login_settings',
					$field . '_too_long',
					sprintf(
						/* translators: 1: field name, 2: maximum length */
						__( '%1$s exceeds maximum length of %2$d characters.', 'secure-oidc-login' ),
						ucwords( str_replace( '_', ' ', $field ) ),
						$max_lengths[ $field ]
					)
				);
				// Preserve the existing value if validation fails
				$sanitized[ $field ] = $existing_settings[ $field ] ?? '';
			} else {
				$sanitized[ $field ] = $value;
			}
		}

		foreach ( $checkbox_fields as $field ) {
			$sanitized[ $field ] = ! empty( $input[ $field ] );
		}

		// Validate allowed_email_domains format
		if ( ! empty( $sanitized['allowed_email_domains'] ) ) {
			$validation = $this->validate_domain_list( $sanitized['allowed_email_domains'] );
			if ( is_wp_error( $validation ) ) {
				add_settings_error(
					'secure_oidc_login_settings',
					'invalid_allowed_domains',
					$validation->get_error_message()
				);
				$sanitized['allowed_email_domains'] = $existing_settings['allowed_email_domains'] ?? '';
			}
		}

		return $sanitized;
	}

	/**
	 * Validate allowed email domains format.
	 *
	 * @param string $domains Comma-separated domain list.
	 * @return true|WP_Error True if valid, WP_Error otherwise.
	 */
	private function validate_domain_list( string $domains ): bool|WP_Error {
		if ( empty( trim( $domains ) ) ) {
			return true;
		}

		$domain_list = array_map( 'trim', explode( ',', $domains ) );

		foreach ( $domain_list as $domain ) {
			if ( empty( $domain ) ) {
				continue;
			}

			// Remove wildcard prefix for validation
			$domain_to_check = $domain;
			if ( strpos( $domain, '*.' ) === 0 ) {
				$domain_to_check = substr( $domain, 2 );
			}

			// Validate domain format (basic check)
			if ( ! preg_match( '/^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)*$/i', $domain_to_check ) ) {
				return new WP_Error(
					'invalid_domain_format',
					sprintf(
						/* translators: %s: invalid domain */
						__( 'Invalid domain format: %s', 'secure-oidc-login' ),
						esc_html( $domain )
					)
				);
			}
		}

		return true;
	}

	/**
	 * Render the main settings page.
	 *
	 * Displays the callback URL info box and the settings form with
	 * JavaScript for the OIDC discovery feature.
	 */
	public function render_settings_page(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		$callback_url = add_query_arg( 'oidc_callback', '1', home_url( '/' ) );
		?>
		<div class="wrap">
			<h1><?php echo esc_html( get_admin_page_title() ); ?></h1>

			<!-- Display the callback URL that needs to be registered with the IdP -->
			<div class="notice notice-info">
				<p>
					<strong><?php esc_html_e( 'Callback URL:', 'secure-oidc-login' ); ?></strong>
					<code><?php echo esc_html( $callback_url ); ?></code>
				</p>
				<p class="description"><?php esc_html_e( 'Use this URL as the redirect URI when configuring your identity provider.', 'secure-oidc-login' ); ?></p>
			</div>

			<form action="options.php" method="post">
				<?php
				settings_fields( 'secure_oidc_login_settings_group' );
				do_settings_sections( 'secure-oidc-login' );
				submit_button();
				?>
			</form>
		</div>
		<?php
	}

	/**
	 * Render the Identity Provider settings section description.
	 */
	public function render_provider_section(): void {
		echo '<p>' . __( 'Configure your OIDC identity provider settings. You can use the discovery URL to auto-populate the endpoints.', 'secure-oidc-login' ) . '</p>';
	}

	/**
	 * Render the Login settings section description.
	 */
	public function render_login_section(): void {
		echo '<p>' . __( 'Configure how the OIDC login appears and behaves.', 'secure-oidc-login' ) . '</p>';
	}

	/**
	 * Render the User settings section description.
	 */
	public function render_user_section(): void {
		echo '<p>' . __( 'Configure how OIDC users are mapped to WordPress users.', 'secure-oidc-login' ) . '</p>';
	}

	/**
	 * Render the discovery URL field with auto-discover button.
	 */
	public function render_discovery_field(): void {
		// Check for environment variable to pre-populate the field
		$env_var   = 'SECURE_OIDC_DISCOVERY_URL';
		$env_value = getenv( $env_var );
		$has_env   = false !== $env_value && '' !== $env_value;

		// Get maximum length for discovery_url field
		$max_lengths = $this->get_max_lengths();
		$maxlength   = isset( $max_lengths['discovery_url'] ) ? $max_lengths['discovery_url'] : 2048;
		?>
		<input type="url" id="discovery_url" class="regular-text" placeholder="https://your-idp.com/.well-known/openid-configuration" value="<?php echo esc_attr( $has_env ? $env_value : '' ); ?>" maxlength="<?php echo esc_attr( (string) $maxlength ); ?>">
		<button type="button" id="oidc-discover-btn" class="button"><?php esc_html_e( 'Discover', 'secure-oidc-login' ); ?></button>
		<?php if ( $has_env ) : ?>
			<p class="description" style="color: #2271b1;">
				<?php
				printf(
					/* translators: %s: environment variable name */
					esc_html__( 'Discovery URL pre-populated from %s environment variable. You can modify it before clicking Discover.', 'secure-oidc-login' ),
					esc_html( $env_var )
				);
				?>
			</p>
		<?php else : ?>
			<p class="description"><?php esc_html_e( 'Enter your identity provider\'s discovery URL to auto-populate endpoints.', 'secure-oidc-login' ); ?></p>
		<?php endif; ?>
		<?php
	}

	/**
	 * Render a text input field.
	 *
	 * @param array<string, mixed> $args Field arguments including 'field', 'type', 'required', 'default', 'description'.
	 */
	public function render_text_field( array $args ): void {
		$options = get_option( 'secure_oidc_login_settings', array() );
		$field   = $args['field'];

		// Use null coalescing for simple defaults
		$value = $options[ $field ] ?? $args['default'] ?? '';
		$type  = $args['type'] ?? 'text';

		// Add 'required' attribute if field is required
		$required = '';
		if ( ! empty( $args['required'] ) ) {
			$required = 'required';
		}

		// Get maximum length for this field (client-side validation)
		$max_lengths = $this->get_max_lengths();
		$maxlength   = '';
		if ( isset( $max_lengths[ $field ] ) ) {
			$maxlength = ' maxlength="' . esc_attr( (string) $max_lengths[ $field ] ) . '"';
		}

		// Check if this setting is overridden by environment variable
		// Environment variables take precedence over database settings (see Secure_OIDC_Login::get_setting)
		// This allows deployments to use .env files or server configuration instead of storing secrets in the database
		$env_var = 'SECURE_OIDC_' . strtoupper( $field );

		// Check if environment variable is set and non-empty
		// getenv() returns false if not set, or the string value (which could be empty)
		$is_env_overridden = false;
		if ( false !== getenv( $env_var ) && '' !== getenv( $env_var ) ) {
			$is_env_overridden = true;
		}

		// Special handling for client_id field - requires explicit opt-in for database storage
		$is_credential_field = ( 'client_id' === $field );
		$is_disabled         = $is_env_overridden;
		$description_message = '';

		if ( $is_credential_field && ! $is_env_overridden ) {
			// For client_id without env var: check if unsafe mode is enabled
			if ( ! $this->is_unsafe_mode_enabled() ) {
				$is_disabled         = true;
				$description_message = sprintf(
					/* translators: %s: environment variable name */
					__( 'Set via %s environment variable, or set SECURE_OIDC_ALLOW_UNSAFE=true to enable database storage.', 'secure-oidc-login' ),
					esc_html( $env_var )
				);
			} else {
				// Unsafe mode is enabled - show security warning
				$description_message = __( 'Warning: Storing credentials in the database is less secure than using environment variables.', 'secure-oidc-login' );
			}
		}

		printf(
			'<input type="%s" name="secure_oidc_login_settings[%s]" value="%s" class="regular-text" %s%s%s>',
			esc_attr( $type ),
			esc_attr( $field ),
			esc_attr( $value ),
			$required,
			$maxlength,
			$is_disabled ? ' disabled' : ''
		);

		if ( $is_env_overridden ) {
			printf(
				'<p class="description" style="color: #2271b1;">%s</p>',
				sprintf(
					/* translators: %s: environment variable name */
					esc_html__( 'This setting is overridden by the %s environment variable.', 'secure-oidc-login' ),
					esc_html( $env_var )
				)
			);
		} elseif ( $is_credential_field && ! empty( $description_message ) ) {
			$style = $this->is_unsafe_mode_enabled() ? 'color: #b32d2e;' : 'color: #2271b1;';
			printf( '<p class="description" style="%s">%s</p>', esc_attr( $style ), esc_html( $description_message ) );
		} elseif ( isset( $args['description'] ) ) {
			printf( '<p class="description">%s</p>', esc_html( $args['description'] ) );
		}
	}

	/**
	 * Render a password input field.
	 *
	 * @param array<string, mixed> $args Field arguments including 'field' and 'description'.
	 */
	public function render_password_field( array $args ): void {
		$options = get_option( 'secure_oidc_login_settings', array() );
		$field   = $args['field'];
		$value   = $options[ $field ] ?? '';

		// Get maximum length for this field (client-side validation)
		$max_lengths = $this->get_max_lengths();
		$maxlength   = '';
		if ( isset( $max_lengths[ $field ] ) ) {
			$maxlength = ' maxlength="' . esc_attr( (string) $max_lengths[ $field ] ) . '"';
		}

		// Check if this setting is overridden by environment variable
		// Environment variables take precedence over database settings (see Secure_OIDC_Login::get_setting)
		// This is especially useful for secrets like client_secret to avoid storing them in the database
		$env_var = 'SECURE_OIDC_' . strtoupper( $field );

		// Check if environment variable is set and non-empty
		// getenv() returns false if not set, or the string value (which could be empty)
		$is_env_overridden = false;
		if ( false !== getenv( $env_var ) && '' !== getenv( $env_var ) ) {
			$is_env_overridden = true;
		}

		// Special handling for client_secret field - requires explicit opt-in for database storage
		$is_credential_field = ( 'client_secret' === $field );
		$is_disabled         = $is_env_overridden;
		$description_message = '';

		if ( $is_credential_field && ! $is_env_overridden ) {
			// For client_secret without env var: check if unsafe mode is enabled
			if ( ! $this->is_unsafe_mode_enabled() ) {
				$is_disabled         = true;
				$description_message = sprintf(
					/* translators: %s: environment variable name */
					__( 'Set via %s environment variable, or set SECURE_OIDC_ALLOW_UNSAFE=true to enable database storage.', 'secure-oidc-login' ),
					esc_html( $env_var )
				);
			} else {
				// Unsafe mode is enabled - show security warning
				$description_message = __( 'Warning: Storing client secrets in the database is a security risk. Use environment variables in production.', 'secure-oidc-login' );
			}
		}

		printf(
			'<input type="password" name="secure_oidc_login_settings[%s]" value="%s" class="regular-text"%s%s>',
			esc_attr( $field ),
			esc_attr( $value ),
			$maxlength,
			$is_disabled ? ' disabled' : ''
		);

		if ( $is_env_overridden ) {
			printf(
				'<p class="description" style="color: #2271b1;">%s</p>',
				sprintf(
					/* translators: %s: environment variable name */
					esc_html__( 'This setting is overridden by the %s environment variable.', 'secure-oidc-login' ),
					esc_html( $env_var )
				)
			);
		} elseif ( $is_credential_field && ! empty( $description_message ) ) {
			$style = $this->is_unsafe_mode_enabled() ? 'color: #b32d2e;' : 'color: #2271b1;';
			printf( '<p class="description" style="%s">%s</p>', esc_attr( $style ), esc_html( $description_message ) );
		} elseif ( isset( $args['description'] ) ) {
			printf( '<p class="description">%s</p>', esc_html( $args['description'] ) );
		}
	}

	/**
	 * Render a checkbox field.
	 *
	 * @param array<string, mixed> $args Field arguments including 'field' and 'description'.
	 */
	public function render_checkbox_field( array $args ): void {
		$options = get_option( 'secure_oidc_login_settings', array() );
		$field   = $args['field'];
		$checked = isset( $options[ $field ] ) && $options[ $field ] ? 'checked' : '';

		// SECURITY WARNING: Show inline warning when email verification is disabled
		if ( 'require_verified_email' === $field && ! $checked ) {
			?>
			<div class="notice notice-warning inline" style="margin: 0 0 10px 0; padding: 8px 12px;">
				<strong><?php esc_html_e( 'Security Warning:', 'secure-oidc-login' ); ?></strong>
				<?php esc_html_e( 'Disabling email verification may allow account takeover attacks. Only disable if your identity provider does not support email verification claims (e.g., certain Azure AD configurations).', 'secure-oidc-login' ); ?>
			</div>
			<?php
		}

		printf(
			'<input type="checkbox" name="secure_oidc_login_settings[%s]" value="1" %s>',
			esc_attr( $field ),
			$checked
		);

		if ( isset( $args['description'] ) ) {
			printf( '<span class="description">%s</span>', esc_html( $args['description'] ) );
		}
	}

	/**
	 * Render a WordPress role dropdown field.
	 *
	 * @param array<string, mixed> $args Field arguments including 'field'.
	 */
	public function render_role_field( array $args ): void {
		$options = get_option( 'secure_oidc_login_settings', array() );
		$field   = $args['field'];
		$value   = $options[ $field ] ?? 'subscriber';

		// Build the dropdown manually to have full control over the name attribute
		$field_name = 'secure_oidc_login_settings[' . esc_attr( $field ) . ']';
		?>
		<select name="<?php echo esc_attr( $field_name ); ?>" id="<?php echo esc_attr( $field ); ?>">
			<?php wp_dropdown_roles( $value ); ?>
		</select>
		<p class="description">
			<?php esc_html_e( 'Role assigned to new users created via OIDC authentication.', 'secure-oidc-login' ); ?>
		</p>
		<?php
	}

	/**
	 * Display admin notices on the settings page.
	 *
	 * Shows a warning if required settings are not configured.
	 */
	public function admin_notices(): void {
		if ( ! isset( $_GET['page'] ) || $_GET['page'] !== 'secure-oidc-login' ) {
			return;
		}

		$options = get_option( 'secure_oidc_login_settings', array() );

		// SECURITY: Show error if credentials are stored in database
		if ( $this->has_database_credentials() ) {
			?>
			<div class="notice notice-error">
				<p>
					<strong><?php esc_html_e( 'Security Warning:', 'secure-oidc-login' ); ?></strong>
					<?php esc_html_e( 'Client credentials are stored in the database. This is a security risk. For production environments, use environment variables (SECURE_OIDC_CLIENT_ID and SECURE_OIDC_CLIENT_SECRET) and remove the stored credentials.', 'secure-oidc-login' ); ?>
				</p>
				<form method="post" action="" style="margin-top: 10px;">
					<?php wp_nonce_field( 'secure_oidc_delete_credentials', '_wpnonce_delete_credentials' ); ?>
					<input type="submit" name="secure_oidc_delete_credentials" class="button button-secondary" value="<?php esc_attr_e( 'Remove Stored Credentials', 'secure-oidc-login' ); ?>" onclick="return confirm('<?php esc_attr_e( 'Are you sure you want to remove the stored client credentials from the database? Make sure you have configured environment variables first.', 'secure-oidc-login' ); ?>');">
				</form>
			</div>
			<?php
		}

		// SECURITY: Show warning if unsafe mode is enabled
		if ( $this->is_unsafe_mode_enabled() && ! $this->has_env_credentials() ) {
			?>
			<div class="notice notice-warning">
				<p>
					<strong><?php esc_html_e( 'Unsafe Mode Active:', 'secure-oidc-login' ); ?></strong>
					<?php esc_html_e( 'SECURE_OIDC_ALLOW_UNSAFE is enabled, allowing client credentials to be stored in the database. This is not recommended for production environments. Configure SECURE_OIDC_CLIENT_ID and SECURE_OIDC_CLIENT_SECRET environment variables instead.', 'secure-oidc-login' ); ?>
				</p>
			</div>
			<?php
		}

		// Check for required settings, including environment variables
		$client_id              = Secure_OIDC_Login::get_setting( 'client_id', $options );
		$authorization_endpoint = Secure_OIDC_Login::get_setting( 'authorization_endpoint', $options );
		$token_endpoint         = Secure_OIDC_Login::get_setting( 'token_endpoint', $options );

		if ( empty( $client_id ) || empty( $authorization_endpoint ) || empty( $token_endpoint ) ) {
			?>
			<div class="notice notice-warning">
				<p>
					<?php esc_html_e( 'OIDC Authentication is not fully configured. Please fill in the required fields.', 'secure-oidc-login' ); ?>
				</p>
			</div>
			<?php
		}

		// Check if native login is disabled
		$disable_native_login = isset( $options['disable_native_login'] ) && $options['disable_native_login'];

		if ( $disable_native_login ) {
			if ( empty( $client_id ) || empty( $authorization_endpoint ) || empty( $token_endpoint ) ) {
				?>
				<div class="notice notice-error">
					<p>
						<strong><?php esc_html_e( 'WARNING:', 'secure-oidc-login' ); ?></strong>
						<?php esc_html_e( 'Native login is disabled but OIDC is not fully configured. Users may be locked out. Configure OIDC or disable "Disable Native Login" immediately.', 'secure-oidc-login' ); ?>
					</p>
				</div>
				<?php
			} else {
				?>
				<div class="notice notice-info">
					<p>
						<?php
						printf(
							/* translators: %s: emergency login URL */
							esc_html__( 'Native login is disabled. Emergency admin access: %s', 'secure-oidc-login' ),
							'<code>' . esc_html( wp_login_url() . '?native=1' ) . '</code>'
						);
						?>
					</p>
				</div>
				<?php
			}
		}

		// Show info notice if domain filtering is active
		$allowed_domains = Secure_OIDC_Login::get_setting( 'allowed_email_domains', $options );
		if ( ! empty( $allowed_domains ) ) {
			$is_env_override = ( false !== getenv( 'SECURE_OIDC_ALLOWED_EMAIL_DOMAINS' ) && '' !== getenv( 'SECURE_OIDC_ALLOWED_EMAIL_DOMAINS' ) );
			?>
			<div class="notice notice-info">
				<p>
					<strong><?php esc_html_e( 'Email Domain Filtering Active', 'secure-oidc-login' ); ?></strong>
					<?php
					printf(
						/* translators: %s: comma-separated list of domains */
						esc_html__( 'Only users with email addresses from these domains can authenticate: %s', 'secure-oidc-login' ),
						'<code>' . esc_html( $allowed_domains ) . '</code>'
					);
					?>
					<?php if ( $is_env_override ) : ?>
						<br><em><?php esc_html_e( '(Configured via SECURE_OIDC_ALLOWED_EMAIL_DOMAINS environment variable)', 'secure-oidc-login' ); ?></em>
					<?php endif; ?>
				</p>
			</div>
			<?php
		}
	}
}

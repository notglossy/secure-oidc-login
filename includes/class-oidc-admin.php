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
		add_action( 'admin_notices', array( $this, 'admin_notices' ) );
		add_action( 'wp_ajax_oidc_discover', array( $this, 'ajax_discover' ) );
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

		$sanitized = array();

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

		foreach ( $text_fields as $field ) {
			$sanitized[ $field ] = sanitize_text_field( $input[ $field ] ?? '' );
		}

		foreach ( $url_fields as $field ) {
			$sanitized[ $field ] = esc_url_raw( $input[ $field ] ?? '' );
		}

		foreach ( $checkbox_fields as $field ) {
			$sanitized[ $field ] = ! empty( $input[ $field ] );
		}

		return $sanitized;
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
					<strong><?php _e( 'Callback URL:', 'secure-oidc-login' ); ?></strong>
					<code><?php echo esc_html( $callback_url ); ?></code>
				</p>
				<p class="description"><?php _e( 'Use this URL as the redirect URI when configuring your identity provider.', 'secure-oidc-login' ); ?></p>
			</div>

			<form action="options.php" method="post">
				<?php
				settings_fields( 'secure_oidc_login_settings_group' );
				do_settings_sections( 'secure-oidc-login' );
				submit_button();
				?>
			</form>
		</div>

		<!-- JavaScript for OIDC discovery auto-population -->
		<script>
		jQuery(document).ready(function($) {
			// Handle click on "Discover" button
			$('#oidc-discover-btn').on('click', function(e) {
				e.preventDefault();
				var discoveryUrl = $('#discovery_url').val();

				// Validate that user entered a discovery URL
				if (!discoveryUrl) {
					alert('<?php _e( 'Please enter a discovery URL.', 'secure-oidc-login' ); ?>');
					return;
				}

				// Update button state to show discovery in progress
				$(this).prop('disabled', true).text('<?php _e( 'Discovering...', 'secure-oidc-login' ); ?>');

				// Fetch the OIDC discovery document from the IdP via AJAX
				// This calls ajax_discover() which fetches .well-known/openid-configuration
				$.ajax({
					url: ajaxurl,
					type: 'POST',
					data: {
						action: 'oidc_discover',
						discovery_url: discoveryUrl,
						nonce: '<?php echo wp_create_nonce( 'oidc_discover' ); ?>'
					},
					success: function(response) {
						if (response.success) {
							// Auto-populate endpoint fields from discovery document
							// Each endpoint is optional in the OIDC spec, so we check before populating
							var config = response.data;
							if (config.authorization_endpoint) {
								$('input[name="secure_oidc_login_settings[authorization_endpoint]"]').val(config.authorization_endpoint);
							}
							if (config.token_endpoint) {
								$('input[name="secure_oidc_login_settings[token_endpoint]"]').val(config.token_endpoint);
							}
							if (config.userinfo_endpoint) {
								$('input[name="secure_oidc_login_settings[userinfo_endpoint]"]').val(config.userinfo_endpoint);
							}
							if (config.end_session_endpoint) {
								$('input[name="secure_oidc_login_settings[end_session_endpoint]"]').val(config.end_session_endpoint);
							}
							if (config.jwks_uri) {
								$('input[name="secure_oidc_login_settings[jwks_uri]"]').val(config.jwks_uri);
							}
							if (config.issuer) {
								$('input[name="secure_oidc_login_settings[issuer]"]').val(config.issuer);
							}
							alert('<?php _e( 'Configuration discovered successfully!', 'secure-oidc-login' ); ?>');
						} else {
							// Discovery failed - show error message from server
							alert(response.data || '<?php _e( 'Discovery failed.', 'secure-oidc-login' ); ?>');
						}
					},
					error: function() {
						// Network error or server error
						alert('<?php _e( 'Discovery request failed.', 'secure-oidc-login' ); ?>');
					},
					complete: function() {
						// Re-enable button whether success or failure
						$('#oidc-discover-btn').prop('disabled', false).text('<?php _e( 'Discover', 'secure-oidc-login' ); ?>');
					}
				});
			});
		});
		</script>
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
		?>
		<input type="url" id="discovery_url" class="regular-text" placeholder="https://your-idp.com/.well-known/openid-configuration" value="<?php echo esc_attr( $has_env ? $env_value : '' ); ?>">
		<button type="button" id="oidc-discover-btn" class="button"><?php _e( 'Discover', 'secure-oidc-login' ); ?></button>
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
			<p class="description"><?php _e( 'Enter your identity provider\'s discovery URL to auto-populate endpoints.', 'secure-oidc-login' ); ?></p>
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

		printf(
			'<input type="%s" name="secure_oidc_login_settings[%s]" value="%s" class="regular-text" %s%s>',
			esc_attr( $type ),
			esc_attr( $field ),
			esc_attr( $value ),
			$required,
			$is_env_overridden ? ' disabled' : ''
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

		printf(
			'<input type="password" name="secure_oidc_login_settings[%s]" value="%s" class="regular-text"%s>',
			esc_attr( $field ),
			esc_attr( $value ),
			$is_env_overridden ? ' disabled' : ''
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

		echo '<select name="' . esc_attr( $field_name ) . '" id="' . esc_attr( $field ) . '">';

		wp_dropdown_roles( $value );

		echo '</select>';

		printf(
			'<p class="description">%s</p>',
			esc_html__( 'Role assigned to new users created via OIDC authentication.', 'secure-oidc-login' )
		);
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

		// Check for required settings, including environment variables
		$client_id              = Secure_OIDC_Login::get_setting( 'client_id', $options );
		$authorization_endpoint = Secure_OIDC_Login::get_setting( 'authorization_endpoint', $options );
		$token_endpoint         = Secure_OIDC_Login::get_setting( 'token_endpoint', $options );

		if ( empty( $client_id ) || empty( $authorization_endpoint ) || empty( $token_endpoint ) ) {
			echo '<div class="notice notice-warning"><p>';
			_e( 'OIDC Authentication is not fully configured. Please fill in the required fields.', 'secure-oidc-login' );
			echo '</p></div>';
		}

		// Check if native login is disabled
		$disable_native_login = isset( $options['disable_native_login'] ) && $options['disable_native_login'];

		if ( $disable_native_login ) {
			if ( empty( $client_id ) || empty( $authorization_endpoint ) || empty( $token_endpoint ) ) {
				echo '<div class="notice notice-error"><p>';
				_e( '<strong>WARNING:</strong> Native login is disabled but OIDC is not fully configured. Users may be locked out. Configure OIDC or disable "Disable Native Login" immediately.', 'secure-oidc-login' );
				echo '</p></div>';
			} else {
				echo '<div class="notice notice-info"><p>';
				printf(
					/* translators: %s: emergency login URL */
					__( 'Native login is disabled. Emergency admin access: <code>%s</code>', 'secure-oidc-login' ),
					esc_html( wp_login_url() . '?native=1' )
				);
				echo '</p></div>';
			}
		}
	}

	/**
	 * Handle AJAX request for OIDC discovery.
	 *
	 * Fetches the OpenID Provider Configuration document from the
	 * well-known endpoint and returns it as JSON.
	 */
	public function ajax_discover(): void {
		check_ajax_referer( 'oidc_discover', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( __( 'Permission denied.', 'secure-oidc-login' ) );
		}

		$discovery_url = esc_url_raw( $_POST['discovery_url'] ?? '' );

		if ( empty( $discovery_url ) ) {
			wp_send_json_error( __( 'Discovery URL is required.', 'secure-oidc-login' ) );
		}

		// Append well-known path if not already present
		if ( strpos( $discovery_url, '.well-known/openid-configuration' ) === false ) {
			$discovery_url = rtrim( $discovery_url, '/' ) . '/.well-known/openid-configuration';
		}

		$response = wp_remote_get( $discovery_url, array( 'timeout' => 30 ) );

		if ( is_wp_error( $response ) ) {
			wp_send_json_error( $response->get_error_message() );
		}

		$status_code = wp_remote_retrieve_response_code( $response );

		if ( $status_code !== 200 ) {
			wp_send_json_error( __( 'Failed to fetch discovery document.', 'secure-oidc-login' ) );
		}

		$body         = wp_remote_retrieve_body( $response );
		$content_type = wp_remote_retrieve_header( $response, 'content-type' );
		if ( is_array( $content_type ) ) {
			$content_type = $content_type[0] ?? '';
		}
		// Ensure content_type is a string for stripos() in PHP 8+
		$content_type = (string) $content_type;
		if ( stripos( $content_type, 'application/json' ) === false ) {
			wp_send_json_error( __( 'Discovery response was not JSON. Please verify the identity provider configuration.', 'secure-oidc-login' ) );
		}

		$config = json_decode( $body, true );

		if ( ! $config ) {
			wp_send_json_error( __( 'Invalid discovery response.', 'secure-oidc-login' ) );
		}

		wp_send_json_success( $config );
	}
}

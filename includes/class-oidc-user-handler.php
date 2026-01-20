<?php
/**
 * OIDC User Handler class for managing WordPress user creation and mapping.
 *
 * @package Secure_OIDC_Login
 * @since 0.1.0
 */

// Prevent direct file access
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Handles WordPress user creation and mapping from OIDC claims.
 *
 * Maps OIDC identity claims to WordPress user accounts, supporting both
 * automatic user creation and linking to existing accounts.
 */
class OIDC_User_Handler {
	/** @var array<string, mixed> Plugin settings from WordPress options */
	private array $options;

	/**
	 * Initialize the handler with plugin settings.
	 */
	public function __construct() {
		$this->options = get_option( 'secure_oidc_login_settings', array() );
	}

	/**
	 * Get a setting value with environment variable support.
	 *
	 * @param string $key The setting key to retrieve.
	 * @return string The setting value.
	 */
	private function get_setting( $key ): string {
		return Secure_OIDC_Login::get_setting( $key, $this->options );
	}

	/**
	 * Get an existing WordPress user or create a new one based on OIDC claims.
	 *
	 * User lookup strategy and priority (ensures consistent identity mapping):
	 * 1. By OIDC subject identifier (stored in user meta) - most reliable, IdP guarantees uniqueness
	 * 2. By email address (links existing account to OIDC) - convenience for existing users
	 * 3. Create new user (if enabled in settings) - first-time OIDC users
	 *
	 * @param array<string, mixed> $id_token_claims Claims from the ID token.
	 * @param array<string, mixed> $userinfo        Additional claims from userinfo endpoint.
	 * @return WP_User|WP_Error WordPress user object or error.
	 */
	public function get_or_create_user( array $id_token_claims, array $userinfo = array() ): WP_User|WP_Error {
		// Combine claims from both sources (userinfo takes precedence for overlapping keys)
		// This allows userinfo endpoint to provide more detailed/updated information
		$claims = array_merge( $id_token_claims, $userinfo );

		// The 'sub' (subject) claim is the unique, persistent identifier from the IdP
		// It never changes for a user, even if they change email/username at the IdP
		$subject = isset( $claims['sub'] ) ? $claims['sub'] : null;

		if ( empty( $subject ) ) {
			return new WP_Error( 'oidc_error', __( 'Missing subject claim in token.', 'secure-oidc-login' ) );
		}

		// Step 1: Try to find user by their OIDC subject identifier (stored in oidc_subject user meta)
		// This is the most reliable lookup method as 'sub' is guaranteed unique and immutable
		$user = $this->get_user_by_oidc_subject( $subject );

		if ( $user ) {
			// Returning user: Update their profile with latest IdP data
			$this->update_user_from_claims( $user, $claims );
			return $user;
		}

		// Step 2: Try to find and link existing WordPress user by email address
		// This allows existing WordPress users to seamlessly link to OIDC authentication
		$email = $this->get_claim_value( $claims, 'email_claim', 'email' );

		if ( ! empty( $email ) ) {
			// SECURITY: Check if email verification is required before linking accounts
			$require_verified_email = $this->get_setting( 'require_verified_email' );

			// Default to true if not set (secure by default)
			if ( ! isset( $this->options['require_verified_email'] ) ) {
				$require_verified_email = true;
			}

			if ( $require_verified_email ) {
				// SECURITY: Verify email_verified claim to prevent account takeover attacks.
				// Threat model: An attacker registers a malicious IdP account using a victim's
				// email address (without verifying it). If we link accounts based on unverified
				// emails, the attacker gains access to the victim's WordPress account.
				// Defense: Require email_verified=true from the IdP before account linking.
				// NOTE: Some major IdP providers (e.g., certain configurations) may not verify
				// emails by default. Check your IdP's email verification settings.
				// Flexible validation: accepts boolean true, string "true"/"1", or integer 1
				$email_verified = $this->is_email_verified( $claims );

				if ( ! $email_verified ) {
					// SECURITY WARNING: If this check is disabled, account takeover is possible
					// through unverified email addresses at the IdP
					return new WP_Error(
						'oidc_error',
						__( 'Cannot link account: email address not verified by identity provider.', 'secure-oidc-login' )
					);
				}
			}

			// Check if email domain is allowed
			if ( ! $this->is_email_domain_allowed( $email ) ) {
				// SECURITY: Log domain filtering rejections for security auditing
				$domain = substr( $email, strpos( $email, '@' ) + 1 );
				$log_msg = sprintf(
					'OIDC authentication blocked: email domain not allowed (email: %s, domain: %s, subject: %s)',
					$email,
					$domain,
					$subject
				);
				error_log( '[Secure OIDC Login] ' . $log_msg );

				return new WP_Error(
					'oidc_domain_not_allowed',
					sprintf(
						/* translators: %s: email domain */
						__( 'Your email domain (%s) is not authorized to access this site. Please contact your administrator.', 'secure-oidc-login' ),
						esc_html( $domain )
					)
				);
			}

			$user = get_user_by( 'email', $email );

			if ( $user ) {
				// Link this WordPress account to the OIDC identity
				// CRITICAL: If metadata storage fails, authentication should fail
				// Without the oidc_subject link, future logins will fail or create duplicate accounts
				$subject_stored = update_user_meta( $user->ID, 'oidc_subject', $subject );

				if ( false === $subject_stored ) {
					$error_msg = sprintf(
						'Failed to link OIDC identity to existing user (user_id: %d, email: %s, subject: %s)',
						$user->ID,
						$email,
						$subject
					);
					error_log( '[Secure OIDC Login] ' . $error_msg );

					return new WP_Error(
						'oidc_metadata_storage_failed',
						__( 'Failed to link your identity. Please contact the site administrator.', 'secure-oidc-login' )
					);
				}

				$this->update_user_from_claims( $user, $claims );
				return $user;
			}
		}

		// No existing user found - check if we should create one
		if ( empty( $this->options['create_users'] ) ) {
			return new WP_Error( 'oidc_error', __( 'User does not exist and automatic user creation is disabled.', 'secure-oidc-login' ) );
		}

		return $this->create_user( $subject, $claims );
	}

	/**
	 * Find a WordPress user by their OIDC subject identifier.
	 *
	 * @param string $subject The OIDC subject identifier.
	 * @return WP_User|null User object or null if not found.
	 */
	private function get_user_by_oidc_subject( string $subject ): ?WP_User {
		$users = get_users(
			array(
				'meta_key'   => 'oidc_subject',
				'meta_value' => $subject,
				'number'     => 1,
			)
		);

		return ! empty( $users ) ? $users[0] : null;
	}

	/**
	 * Create a new WordPress user from OIDC claims.
	 *
	 * @param string $subject The OIDC subject identifier.
	 * @param array<string, mixed>  $claims  The merged OIDC claims.
	 * @return WP_User|WP_Error New user object or error.
	 */
	private function create_user( string $subject, array $claims ): WP_User|WP_Error {
		$username = $this->generate_username( $claims );
		$email    = $this->get_claim_value( $claims, 'email_claim', 'email' );

		if ( empty( $email ) ) {
			return new WP_Error( 'oidc_error', __( 'Email is required to create a user.', 'secure-oidc-login' ) );
		}

		if ( ! is_email( $email ) ) {
			return new WP_Error( 'oidc_error', __( 'Invalid email address.', 'secure-oidc-login' ) );
		}

		$username = $this->ensure_unique_username( $username );

		$user_data = array(
			'user_login'   => $username,
			'user_email'   => $email,
			// SECURITY: Generate a strong random password that the user will never know or use.
			// Users authenticate via OIDC only, not passwords. This prevents:
			// 1. Password-based brute force attacks on OIDC-created accounts
			// 2. Credential stuffing (reusing passwords from other sites)
			// 3. Social engineering attacks to obtain passwords
			// The password is stored in hashed form in the database and provides no value to attackers.
			'user_pass'    => wp_generate_password( 32, true, true ),
			'first_name'   => $this->get_claim_value( $claims, 'first_name_claim', 'given_name' ),
			'last_name'    => $this->get_claim_value( $claims, 'last_name_claim', 'family_name' ),
			'display_name' => $this->generate_display_name( $claims ),
			'role'         => $this->get_default_role(),
		);

		$user_id = wp_insert_user( $user_data );

		if ( is_wp_error( $user_id ) ) {
			return $user_id;
		}

		// Store OIDC metadata for future authentication
		// CRITICAL: If metadata storage fails, delete the user to prevent orphaned accounts
		$subject_stored = update_user_meta( $user_id, 'oidc_subject', $subject );
		$created_stored = update_user_meta( $user_id, 'oidc_created', true );

		if ( false === $subject_stored || false === $created_stored ) {
			// Rollback: Delete the user we just created since OIDC metadata couldn't be stored
			// Without this metadata, the user cannot authenticate via OIDC on future logins
			require_once ABSPATH . 'wp-admin/includes/user.php';
			wp_delete_user( $user_id );

			$error_msg = sprintf(
				'Failed to store OIDC metadata for user (subject: %s, oidc_subject stored: %s, oidc_created stored: %s)',
				$subject,
				$subject_stored ? 'true' : 'false',
				$created_stored ? 'true' : 'false'
			);
			error_log( '[Secure OIDC Login] ' . $error_msg );

			return new WP_Error(
				'oidc_metadata_storage_failed',
				__( 'Failed to create user account. Please contact the site administrator.', 'secure-oidc-login' )
			);
		}

		/**
		 * Fires after a new user is created via OIDC authentication.
		 *
		 * @param int   $user_id The new user's ID.
		 * @param array $claims  The OIDC claims used to create the user.
		 */
		do_action( 'secure_oidc_login_user_created', $user_id, $claims );

		// Retrieve the created user object
		$user = get_user_by( 'ID', $user_id );

		// Handle edge case: user was deleted between creation and retrieval (race condition or hook interference)
		if ( false === $user ) {
			$error_msg = sprintf(
				'User object not found after creation (user_id: %d, subject: %s). This may indicate a race condition or problematic action hook.',
				$user_id,
				$subject
			);
			error_log( '[Secure OIDC Login] ' . $error_msg );

			return new WP_Error(
				'oidc_user_retrieval_failed',
				__( 'Failed to retrieve user account after creation. Please contact the site administrator.', 'secure-oidc-login' )
			);
		}

		return $user;
	}

	/**
	 * Update an existing user's profile with the latest OIDC claims.
	 *
	 * @param WP_User $user   The user to update.
	 * @param array<string, mixed>   $claims The OIDC claims.
	 */
	private function update_user_from_claims( WP_User $user, array $claims ): void {
		$user_data = array(
			'ID' => $user->ID,
		);

		$first_name = $this->get_claim_value( $claims, 'first_name_claim', 'given_name' );
		$last_name  = $this->get_claim_value( $claims, 'last_name_claim', 'family_name' );

		if ( ! empty( $first_name ) ) {
			$user_data['first_name'] = $first_name;
		}

		if ( ! empty( $last_name ) ) {
			$user_data['last_name'] = $last_name;
		}

		if ( ! empty( $first_name ) || ! empty( $last_name ) ) {
			$user_data['display_name'] = $this->generate_display_name( $claims );
		}

		// Only call wp_update_user if we have fields to update
		if ( count( $user_data ) > 1 ) {
			$update_result = wp_update_user( $user_data );

			// Log failures for debugging, but don't block authentication
			// Profile updates are not critical - the user can still authenticate
			if ( is_wp_error( $update_result ) ) {
				$error_msg = sprintf(
					'Failed to update user profile from OIDC claims (user_id: %d, error: %s)',
					$user->ID,
					$update_result->get_error_message()
				);
				error_log( '[Secure OIDC Login] ' . $error_msg );
			}
		}

		/**
		 * Fires after a user's profile is updated from OIDC claims.
		 *
		 * @param int   $user_id The user's ID.
		 * @param array $claims  The OIDC claims used for the update.
		 */
		do_action( 'secure_oidc_login_user_updated', $user->ID, $claims );
	}

	/**
	 * Generate a WordPress username from OIDC claims.
	 *
	 * Tries multiple claim sources in order of preference:
	 * 1. Configured username claim (e.g., preferred_username)
	 * 2. Email prefix (part before @)
	 * 3. Subject identifier prefix
	 *
	 * @param array<string, mixed> $claims The OIDC claims.
	 * @return string The generated username.
	 */
	private function generate_username( array $claims ): string {
		// Step 1: Try the configured username claim first (most IdP-friendly)
		// This respects the IdP's intended username for the user
		$username = $this->get_claim_value( $claims, 'username_claim', 'preferred_username' );

		// Step 2: Fall back to email prefix if username claim is empty
		// Extract part before @ sign (e.g., "john.doe@example.com" -> "john.doe")
		if ( empty( $username ) ) {
			$email = $this->get_claim_value( $claims, 'email_claim', 'email' );
			if ( ! empty( $email ) ) {
				$username = strstr( $email, '@', true );
			}
		}

		// Step 3: Fall back to subject identifier if email not available
		// Use first 8 characters of sub claim to keep username readable
		// Sub is guaranteed to exist (validated earlier in get_or_create_user)
		if ( empty( $username ) ) {
			$username = isset( $claims['sub'] ) ? 'user_' . substr( $claims['sub'], 0, 8 ) : 'oidc_user';
		}

		// Step 4: Sanitize for WordPress username requirements (alphanumeric, underscore, dash, period, @)
		// The strict=true parameter removes special characters and ensures compatibility
		$username = sanitize_user( $username, true );

		// Step 5: Final fallback if sanitization resulted in empty string
		// This can happen if the username contained only special characters
		if ( empty( $username ) ) {
			$username = 'oidc_user_' . wp_generate_password( 6, false );
		}

		return $username;
	}

	/**
	 * Ensure a username is unique by appending a counter if necessary.
	 *
	 * Handles username collisions when multiple OIDC users would generate the same
	 * WordPress username (e.g., two users with email john@company1.com and john@company2.com
	 * both map to username "john"). Appends _1, _2, etc. until a unique username is found.
	 *
	 * @param string $username The desired username.
	 * @return string A unique username (original or with counter suffix).
	 */
	private function ensure_unique_username( string $username ): string {
		$original_username = $username;
		$counter           = 1;

		// Loop until we find an available username
		// username_exists() checks the wp_users table for existing usernames
		while ( username_exists( $username ) ) {
			$username = $original_username . '_' . $counter;
			++$counter;
		}

		return $username;
	}

	/**
	 * Generate a display name from OIDC claims.
	 *
	 * @param array<string, mixed> $claims The OIDC claims.
	 * @return string The display name.
	 */
	private function generate_display_name( array $claims ): string {
		$first_name = $this->get_claim_value( $claims, 'first_name_claim', 'given_name' );
		$last_name  = $this->get_claim_value( $claims, 'last_name_claim', 'family_name' );

		if ( ! empty( $first_name ) && ! empty( $last_name ) ) {
			return $first_name . ' ' . $last_name;
		}

		if ( ! empty( $first_name ) ) {
			return $first_name;
		}

		if ( ! empty( $last_name ) ) {
			return $last_name;
		}

		// Try the 'name' claim (full name)
		if ( ! empty( $claims['name'] ) ) {
			return $claims['name'];
		}

		// Last resort: use the username
		return $this->get_claim_value( $claims, 'username_claim', 'preferred_username' );
	}

	/**
	 * Get a claim value using the configured claim name from settings.
	 *
	 * @param array<string, mixed>  $claims        The OIDC claims array.
	 * @param string $option_key    The settings key for the claim name.
	 * @param string $default_claim The default claim name if not configured.
	 * @return string The claim value or empty string.
	 */
	private function get_claim_value( array $claims, string $option_key, string $default_claim ): string {
		$claim_name = ! empty( $this->options[ $option_key ] ) ? $this->options[ $option_key ] : $default_claim;
		return isset( $claims[ $claim_name ] ) ? $claims[ $claim_name ] : '';
	}

	/**
	 * Get the default WordPress role for new OIDC users.
	 *
	 * @return string The role slug.
	 */
	private function get_default_role(): string {
		$role = ! empty( $this->options['default_role'] ) ? $this->options['default_role'] : 'subscriber';

		// Ensure the role exists, fall back to subscriber
		if ( ! get_role( $role ) ) {
			$role = 'subscriber';
		}

		return $role;
	}

	/**
	 * Check if email is verified, accepting various formats from different IdPs.
	 *
	 * Accepts: boolean true, string "true"/"1", integer 1
	 * Rejects: boolean false, string "false"/"0", integer 0, null, missing claim
	 *
	 * @param array<string, mixed> $claims The OIDC claims array.
	 * @return bool True if email is verified.
	 */
	private function is_email_verified( array $claims ): bool {
		if ( ! isset( $claims['email_verified'] ) ) {
			return false;
		}

		$value = $claims['email_verified'];

		// Handle boolean
		if ( is_bool( $value ) ) {
			return $value === true;
		}

		// Handle integer
		if ( is_int( $value ) ) {
			return $value === 1;
		}

		// Handle string
		if ( is_string( $value ) ) {
			$value = strtolower( trim( $value ) );
			return $value === 'true' || $value === '1';
		}

		// Unknown type - reject for safety
		return false;
	}

	/**
	 * Check if an email address matches allowed domains.
	 *
	 * @param string $email Email address to validate.
	 * @return bool True if allowed, false otherwise.
	 */
	private function is_email_domain_allowed( string $email ): bool {
		$allowed_domains = $this->get_setting( 'allowed_email_domains' );

		// If no domains configured, allow all
		if ( empty( trim( $allowed_domains ) ) ) {
			return true;
		}

		// Extract domain from email
		$email_parts = explode( '@', $email );
		if ( count( $email_parts ) !== 2 ) {
			return false;
		}
		$email_domain = strtolower( trim( $email_parts[1] ) );

		// Parse allowed domains list
		$domain_list = array_map( 'trim', explode( ',', $allowed_domains ) );
		$domain_list = array_map( 'strtolower', $domain_list );

		foreach ( $domain_list as $allowed_domain ) {
			if ( empty( $allowed_domain ) ) {
				continue;
			}

			// Handle wildcard subdomain matching
			if ( strpos( $allowed_domain, '*.' ) === 0 ) {
				$base_domain = substr( $allowed_domain, 2 );
				// Match exact domain or any subdomain
				if ( $email_domain === $base_domain || str_ends_with( $email_domain, '.' . $base_domain ) ) {
					return true;
				}
			} else {
				// Exact domain match
				if ( $email_domain === $allowed_domain ) {
					return true;
				}
			}
		}

		return false;
	}
}

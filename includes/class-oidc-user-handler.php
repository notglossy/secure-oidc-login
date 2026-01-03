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
	private $options;

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
	private function get_setting( $key ) {
		return Secure_OIDC_Login::get_setting( $key, $this->options );
	}

	/**
	 * Get an existing WordPress user or create a new one based on OIDC claims.
	 *
	 * User lookup priority:
	 * 1. By OIDC subject identifier (stored in user meta)
	 * 2. By email address (links existing account to OIDC)
	 * 3. Create new user (if enabled in settings)
	 *
	 * @param array<string, mixed> $id_token_claims Claims from the ID token.
	 * @param array<string, mixed> $userinfo        Additional claims from userinfo endpoint.
	 * @return WP_User|WP_Error WordPress user object or error.
	 */
	public function get_or_create_user( array $id_token_claims, array $userinfo = array() ) {
		// Combine claims from both sources (userinfo takes precedence)
		$claims = array_merge( $id_token_claims, $userinfo );

		// The 'sub' claim is the unique identifier from the IdP
		$subject = isset( $claims['sub'] ) ? $claims['sub'] : null;

		if ( empty( $subject ) ) {
			return new WP_Error( 'oidc_error', __( 'Missing subject claim in token.', 'secure-oidc-login' ) );
		}

		// First, try to find user by their OIDC subject identifier
		$user = $this->get_user_by_oidc_subject( $subject );

		if ( $user ) {
			$this->update_user_from_claims( $user, $claims );
			return $user;
		}

		// Try to find and link existing user by email
		$email = $this->get_claim_value( $claims, 'email_claim', 'email' );

		if ( ! empty( $email ) ) {
			// Check if email verification is required
			$require_verified_email = $this->get_setting( 'require_verified_email' );

			// Default to true if not set (secure by default)
			if ( ! isset( $this->options['require_verified_email'] ) ) {
				$require_verified_email = true;
			}

			if ( $require_verified_email ) {
				// Flexible validation: accepts boolean true, string "true"/"1", or integer 1
				$email_verified = $this->is_email_verified( $claims );

				if ( ! $email_verified ) {
					return new WP_Error(
						'oidc_error',
						__( 'Cannot link account: email address not verified by identity provider.', 'secure-oidc-login' )
					);
				}
			}

			$user = get_user_by( 'email', $email );

			if ( $user ) {
				// Link this WordPress account to the OIDC identity
				update_user_meta( $user->ID, 'oidc_subject', $subject );
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
	private function get_user_by_oidc_subject( $subject ) {
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
	private function create_user( string $subject, array $claims ) {
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
			'user_pass'    => wp_generate_password( 32, true, true ), // Random password (user authenticates via OIDC)
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
		update_user_meta( $user_id, 'oidc_subject', $subject );
		update_user_meta( $user_id, 'oidc_created', true );

		/**
		 * Fires after a new user is created via OIDC authentication.
		 *
		 * @param int   $user_id The new user's ID.
		 * @param array $claims  The OIDC claims used to create the user.
		 */
		do_action( 'secure_oidc_login_user_created', $user_id, $claims );

		return get_user_by( 'ID', $user_id );
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
			wp_update_user( $user_data );
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
		// Try the configured username claim first
		$username = $this->get_claim_value( $claims, 'username_claim', 'preferred_username' );

		// Fall back to email prefix
		if ( empty( $username ) ) {
			$email = $this->get_claim_value( $claims, 'email_claim', 'email' );
			if ( ! empty( $email ) ) {
				$username = strstr( $email, '@', true );
			}
		}

		// Fall back to subject identifier
		if ( empty( $username ) ) {
			$username = isset( $claims['sub'] ) ? 'user_' . substr( $claims['sub'], 0, 8 ) : 'oidc_user';
		}

		// Sanitize for WordPress username requirements
		$username = sanitize_user( $username, true );

		if ( empty( $username ) ) {
			$username = 'oidc_user_' . wp_generate_password( 6, false );
		}

		return $username;
	}

	/**
	 * Ensure a username is unique by appending a counter if necessary.
	 *
	 * @param string $username The desired username.
	 * @return string A unique username.
	 */
	private function ensure_unique_username( $username ) {
		$original_username = $username;
		$counter           = 1;

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
	private function get_default_role() {
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
}

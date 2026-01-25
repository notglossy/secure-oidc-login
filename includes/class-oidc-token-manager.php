<?php
declare(strict_types=1);
/**
 * Token storage and management.
 *
 * @package Secure_OIDC_Login
 * @since 0.7.0
 */

// Prevent direct file access
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Manages OIDC token storage, retrieval, and expiration tracking.
 *
 * SECURITY: All tokens are encrypted at rest using OIDC_Token_Crypto.
 * This protects against database compromise attacks.
 *
 * User Meta Keys:
 * - oidc_access_token: Encrypted access token for API calls
 * - oidc_id_token: Encrypted ID token (existing)
 * - oidc_refresh_token: Encrypted refresh token (existing)
 * - oidc_token_expires_at: Unix timestamp when access token expires
 * - oidc_refresh_token_hash: SHA-256 hash for rotation detection
 */
class OIDC_Token_Manager {

	/**
	 * User meta key for encrypted access token.
	 *
	 * @var string
	 */
	const META_ACCESS_TOKEN = 'oidc_access_token';

	/**
	 * User meta key for encrypted ID token.
	 *
	 * @var string
	 */
	const META_ID_TOKEN = 'oidc_id_token';

	/**
	 * User meta key for encrypted refresh token.
	 *
	 * @var string
	 */
	const META_REFRESH_TOKEN = 'oidc_refresh_token';

	/**
	 * User meta key for token expiration timestamp.
	 *
	 * @var string
	 */
	const META_EXPIRES_AT = 'oidc_token_expires_at';

	/**
	 * User meta key for refresh token hash (rotation detection).
	 *
	 * @var string
	 */
	const META_REFRESH_TOKEN_HASH = 'oidc_refresh_token_hash';

	/**
	 * Default token expiration in seconds if not provided by IdP.
	 *
	 * @var int
	 */
	const DEFAULT_EXPIRES_IN = 3600;

	/**
	 * Store tokens for a user with encryption.
	 *
	 * SECURITY: All tokens are encrypted before storage. If encryption fails,
	 * the method returns a WP_Error and does NOT store plaintext tokens.
	 *
	 * @param int                  $user_id The WordPress user ID.
	 * @param array<string, mixed> $tokens  Token response from IdP containing:
	 *                                      - access_token (required)
	 *                                      - id_token (optional for refresh)
	 *                                      - refresh_token (optional)
	 *                                      - expires_in (optional, defaults to 3600).
	 * @return true|WP_Error True on success, WP_Error on encryption failure.
	 */
	public function store_tokens( int $user_id, array $tokens ): bool|WP_Error {
		// Validate required fields
		if ( empty( $tokens['access_token'] ) ) {
			return new WP_Error(
				'oidc_invalid_tokens',
				__( 'Missing access_token in token response.', 'secure-oidc-login' )
			);
		}

		// Encrypt and store access token
		$encrypted_access = OIDC_Token_Crypto::encrypt( $tokens['access_token'] );
		if ( is_wp_error( $encrypted_access ) ) {
			OIDC_Token_Crypto::log_error( 'Access token encryption failed: ' . $encrypted_access->get_error_message() );
			return new WP_Error(
				'oidc_encryption_failed',
				__( 'Failed to encrypt access token.', 'secure-oidc-login' )
			);
		}
		update_user_meta( $user_id, self::META_ACCESS_TOKEN, $encrypted_access );

		// Store expiration timestamp
		$expires_in = isset( $tokens['expires_in'] ) ? (int) $tokens['expires_in'] : self::DEFAULT_EXPIRES_IN;
		$expires_at = time() + $expires_in;
		update_user_meta( $user_id, self::META_EXPIRES_AT, $expires_at );

		// Encrypt and store ID token if present
		if ( ! empty( $tokens['id_token'] ) ) {
			$encrypted_id = OIDC_Token_Crypto::encrypt( $tokens['id_token'] );
			if ( is_wp_error( $encrypted_id ) ) {
				OIDC_Token_Crypto::log_error( 'ID token encryption failed: ' . $encrypted_id->get_error_message() );
				return new WP_Error(
					'oidc_encryption_failed',
					__( 'Failed to encrypt ID token.', 'secure-oidc-login' )
				);
			}
			update_user_meta( $user_id, self::META_ID_TOKEN, $encrypted_id );
		}

		// Encrypt and store refresh token if present
		if ( ! empty( $tokens['refresh_token'] ) ) {
			$encrypted_refresh = OIDC_Token_Crypto::encrypt( $tokens['refresh_token'] );
			if ( is_wp_error( $encrypted_refresh ) ) {
				OIDC_Token_Crypto::log_error( 'Refresh token encryption failed: ' . $encrypted_refresh->get_error_message() );
				return new WP_Error(
					'oidc_encryption_failed',
					__( 'Failed to encrypt refresh token.', 'secure-oidc-login' )
				);
			}
			update_user_meta( $user_id, self::META_REFRESH_TOKEN, $encrypted_refresh );

			// Store hash for rotation detection
			$refresh_hash = $this->hash_token( $tokens['refresh_token'] );
			update_user_meta( $user_id, self::META_REFRESH_TOKEN_HASH, $refresh_hash );
		}

		return true;
	}

	/**
	 * Get the decrypted access token for a user.
	 *
	 * @param int $user_id The WordPress user ID.
	 * @return string|WP_Error The access token or error if not found/decrypt fails.
	 */
	public function get_access_token( int $user_id ): string|WP_Error {
		$encrypted = get_user_meta( $user_id, self::META_ACCESS_TOKEN, true );

		if ( empty( $encrypted ) ) {
			return new WP_Error(
				'oidc_token_not_found',
				__( 'Access token not found.', 'secure-oidc-login' )
			);
		}

		$decrypted = OIDC_Token_Crypto::decrypt_if_needed( $encrypted );
		if ( is_wp_error( $decrypted ) ) {
			return $decrypted;
		}

		return $decrypted;
	}

	/**
	 * Get the decrypted refresh token for a user.
	 *
	 * @param int $user_id The WordPress user ID.
	 * @return string|WP_Error The refresh token or error if not found/decrypt fails.
	 */
	public function get_refresh_token( int $user_id ): string|WP_Error {
		$encrypted = get_user_meta( $user_id, self::META_REFRESH_TOKEN, true );

		if ( empty( $encrypted ) ) {
			return new WP_Error(
				'oidc_token_not_found',
				__( 'Refresh token not found.', 'secure-oidc-login' )
			);
		}

		$decrypted = OIDC_Token_Crypto::decrypt_if_needed( $encrypted );
		if ( is_wp_error( $decrypted ) ) {
			return $decrypted;
		}

		return $decrypted;
	}

	/**
	 * Get the decrypted ID token for a user.
	 *
	 * @param int $user_id The WordPress user ID.
	 * @return string|WP_Error The ID token or error if not found/decrypt fails.
	 */
	public function get_id_token( int $user_id ): string|WP_Error {
		$encrypted = get_user_meta( $user_id, self::META_ID_TOKEN, true );

		if ( empty( $encrypted ) ) {
			return new WP_Error(
				'oidc_token_not_found',
				__( 'ID token not found.', 'secure-oidc-login' )
			);
		}

		$decrypted = OIDC_Token_Crypto::decrypt_if_needed( $encrypted );
		if ( is_wp_error( $decrypted ) ) {
			return $decrypted;
		}

		return $decrypted;
	}

	/**
	 * Check if the access token is expired or will expire within the buffer period.
	 *
	 * @param int $user_id    The WordPress user ID.
	 * @param int $buffer_secs Seconds before actual expiry to consider token expired. Default 0.
	 * @return bool True if token is expired or expiring within buffer, false otherwise.
	 */
	public function is_token_expired( int $user_id, int $buffer_secs = 0 ): bool {
		$expires_at = $this->get_expiration_time( $user_id );

		if ( null === $expires_at ) {
			// No expiration stored - assume expired for safety
			return true;
		}

		// Token is expired if current time + buffer >= expiration
		return ( time() + $buffer_secs ) >= $expires_at;
	}

	/**
	 * Get the token expiration timestamp for a user.
	 *
	 * @param int $user_id The WordPress user ID.
	 * @return int|null Unix timestamp of expiration, or null if not set.
	 */
	public function get_expiration_time( int $user_id ): ?int {
		$expires_at = get_user_meta( $user_id, self::META_EXPIRES_AT, true );

		if ( '' === $expires_at || false === $expires_at ) {
			return null;
		}

		return (int) $expires_at;
	}

	/**
	 * Check if the refresh token was rotated by comparing hashes.
	 *
	 * SECURITY: Refresh token rotation is a security best practice that limits
	 * the lifetime of each refresh token. This method detects when the IdP
	 * has issued a new refresh token (indicating rotation occurred).
	 *
	 * @param int    $user_id   The WordPress user ID.
	 * @param string $new_token The new refresh token from IdP response.
	 * @return bool True if token was rotated (new != old), false if same or no previous.
	 */
	public function was_refresh_token_rotated( int $user_id, string $new_token ): bool {
		$stored_hash = get_user_meta( $user_id, self::META_REFRESH_TOKEN_HASH, true );

		if ( empty( $stored_hash ) ) {
			// No previous hash - can't detect rotation
			return false;
		}

		$new_hash = $this->hash_token( $new_token );

		// Rotation occurred if hashes are different
		return ! hash_equals( $stored_hash, $new_hash );
	}

	/**
	 * Check if user has a stored refresh token.
	 *
	 * @param int $user_id The WordPress user ID.
	 * @return bool True if refresh token exists.
	 */
	public function has_refresh_token( int $user_id ): bool {
		$encrypted = get_user_meta( $user_id, self::META_REFRESH_TOKEN, true );
		return ! empty( $encrypted );
	}

	/**
	 * Clear all OIDC tokens for a user.
	 *
	 * Called during logout to ensure tokens are properly cleaned up.
	 *
	 * @param int $user_id The WordPress user ID.
	 * @return void
	 */
	public function clear_tokens( int $user_id ): void {
		delete_user_meta( $user_id, self::META_ACCESS_TOKEN );
		delete_user_meta( $user_id, self::META_ID_TOKEN );
		delete_user_meta( $user_id, self::META_REFRESH_TOKEN );
		delete_user_meta( $user_id, self::META_EXPIRES_AT );
		delete_user_meta( $user_id, self::META_REFRESH_TOKEN_HASH );
	}

	/**
	 * Generate a hash of a token for comparison/storage.
	 *
	 * Uses SHA-256 for fast, secure hashing suitable for comparison.
	 *
	 * @param string $token The token to hash.
	 * @return string Hex-encoded hash.
	 */
	private function hash_token( string $token ): string {
		return hash( 'sha256', $token );
	}
}

<?php
/**
 * Token encryption utilities for secure storage.
 *
 * @package Secure_OIDC_Login
 */

// Prevent direct file access
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Provides AES-256-GCM encryption/decryption for stored tokens.
 *
 * SECURITY: Uses AES-256-GCM (Galois/Counter Mode) authenticated encryption.
 * AES-256-GCM was chosen because it provides both confidentiality and integrity:
 * - Confidentiality: 256-bit key makes brute force attacks computationally infeasible
 * - Integrity/Authenticity: GCM's authentication tag detects tampering or corruption
 * - Performance: GCM is hardware-accelerated on modern CPUs (AES-NI instruction set)
 * - Standard: NIST-approved, widely used in TLS 1.3 and other security protocols
 */
class OIDC_Token_Crypto {
	const CIPHER     = 'aes-256-gcm';
	const IV_LENGTH  = 12; // Recommended IV length for GCM mode (96 bits)
	const TAG_LENGTH = 16; // Authentication tag length (128 bits)
	const PREFIX     = 'enc:v1:'; // Version prefix for future cipher upgrades

	/**
	 * Check if the environment supports required OpenSSL functions and cipher.
	 *
	 * @return bool
	 */
	public static function is_supported(): bool {
		if ( ! function_exists( 'openssl_encrypt' ) || ! function_exists( 'openssl_decrypt' ) ) {
			return false;
		}

		$ciphers = openssl_get_cipher_methods( true );
		return in_array( self::CIPHER, $ciphers, true );
	}

	/**
	 * Encrypt a token value.
	 *
	 * SECURITY: Uses authenticated encryption (AES-256-GCM) which provides:
	 * - Confidentiality: Encrypted ciphertext cannot be read without the key
	 * - Integrity: Authentication tag ensures data hasn't been modified
	 * - Authenticity: Tag proves data was encrypted with the correct key
	 *
	 * @param string $plaintext Token string to encrypt.
	 * @return string|WP_Error Encrypted token with prefix or error.
	 */
	public static function encrypt( string $plaintext ) {
		if ( '' === $plaintext ) {
			return '';
		}

		if ( ! self::is_supported() ) {
			return new WP_Error( 'oidc_encryption_unavailable', __( 'OpenSSL AES-256-GCM is not available on this server.', 'secure-oidc-login' ) );
		}

		try {
			// Generate random Initialization Vector (IV/nonce) - MUST be unique for each encryption
			// GCM mode requires a fresh IV for every encryption operation with the same key
			$iv  = random_bytes( self::IV_LENGTH );
			$key = self::get_key();

			// Encrypt using GCM mode, which outputs ciphertext and authentication tag
			// OPENSSL_RAW_DATA returns binary data (not base64) for efficiency
			// $tag is populated by openssl_encrypt with the authentication tag
			$ciphertext = openssl_encrypt( $plaintext, self::CIPHER, $key, OPENSSL_RAW_DATA, $iv, $tag, '', self::TAG_LENGTH );

			if ( false === $ciphertext ) {
				return new WP_Error( 'oidc_encryption_failed', __( 'Failed to encrypt token.', 'secure-oidc-login' ) );
			}

			// Concatenate IV + tag + ciphertext and base64 encode for safe storage in database
			// Structure: [12 bytes IV][16 bytes tag][variable length ciphertext]
			$payload = base64_encode( $iv . $tag . $ciphertext );

			return self::PREFIX . $payload;

		} catch ( Exception $e ) {
			return new WP_Error( 'oidc_encryption_failed', __( 'Failed to encrypt token.', 'secure-oidc-login' ) );
		}
	}

	/**
	 * Decrypt a stored token if it is encrypted. Legacy plaintext values are returned as-is.
	 *
	 * SECURITY: Handles backward compatibility with tokens stored before encryption was added.
	 * Legacy plaintext tokens (without PREFIX) are returned as-is. This allows graceful migration
	 * from plaintext to encrypted storage without breaking existing sessions. However, this means
	 * that compromised plaintext tokens from old database backups remain valid until they expire.
	 *
	 * @param string $value Stored token value (encrypted or plaintext).
	 * @return string|WP_Error Decrypted token, original plaintext, or error on decrypt failure.
	 */
	public static function decrypt_if_needed( string $value ) {
		if ( '' === $value ) {
			return '';
		}

		// Check for encryption prefix - if missing, treat as legacy plaintext
		// SECURITY IMPLICATION: This allows unencrypted tokens to be used, which reduces
		// protection against database leaks. Admins should rotate tokens after enabling encryption.
		if ( strpos( $value, self::PREFIX ) !== 0 ) {
			// Legacy plaintext value - return as-is for backward compatibility
			return $value;
		}

		if ( ! self::is_supported() ) {
			return new WP_Error( 'oidc_encryption_unavailable', __( 'OpenSSL AES-256-GCM is not available on this server.', 'secure-oidc-login' ) );
		}

		// Remove prefix and decode base64 payload
		$payload = substr( $value, strlen( self::PREFIX ) );
		$decoded = base64_decode( $payload, true );

		if ( false === $decoded ) {
			return new WP_Error( 'oidc_decryption_failed', __( 'Invalid encrypted token payload.', 'secure-oidc-login' ) );
		}

		// Validate minimum length: IV (12 bytes) + tag (16 bytes) = 28 bytes minimum
		if ( strlen( $decoded ) < ( self::IV_LENGTH + self::TAG_LENGTH ) ) {
			return new WP_Error( 'oidc_decryption_failed', __( 'Encrypted token payload is too short.', 'secure-oidc-login' ) );
		}

		// Extract components from concatenated binary data
		// Byte structure: [0-11: IV][12-27: tag][28+: ciphertext]
		$iv         = substr( $decoded, 0, self::IV_LENGTH );
		$tag        = substr( $decoded, self::IV_LENGTH, self::TAG_LENGTH );
		$ciphertext = substr( $decoded, self::IV_LENGTH + self::TAG_LENGTH );

		try {
			$key       = self::get_key();
			$plaintext = openssl_decrypt( $ciphertext, self::CIPHER, $key, OPENSSL_RAW_DATA, $iv, $tag );

			if ( false === $plaintext ) {
				return new WP_Error( 'oidc_decryption_failed', __( 'Failed to decrypt token.', 'secure-oidc-login' ) );
			}

			return $plaintext;

		} catch ( Exception $e ) {
			return new WP_Error( 'oidc_decryption_failed', __( 'Failed to decrypt token.', 'secure-oidc-login' ) );
		}
	}

	/**
	 * Log an internal error message (without exposing sensitive data).
	 *
	 * @param string $message Message to log.
	 */
	public static function log_error( string $message ): void {
		error_log( '[Secure OIDC Login] ' . $message );
	}

	/**
	 * Derive a 256-bit encryption key from WordPress salts.
	 *
	 * Uses wp_salt() which combines multiple WordPress authentication constants
	 * from wp-config.php (AUTH_KEY, SECURE_AUTH_KEY, etc.) with the provided string.
	 * This creates a site-specific encryption key that is not stored in the database.
	 *
	 * SECURITY: If WordPress salts are rotated (e.g., after a security incident),
	 * all previously encrypted tokens will become undecryptable. This is intentional
	 * behavior - salt rotation should invalidate all sessions. Refer to WordPress
	 * documentation on salt rotation procedures.
	 *
	 * @return string Binary encryption key (32 bytes / 256 bits).
	 */
	private static function get_key(): string {
		// wp_salt() creates a hash from WordPress auth salts + our string
		$salt = wp_salt( 'secure_oidc_token' );
		// Hash to exactly 256 bits (32 bytes) for AES-256, binary output
		return hash( 'sha256', $salt, true );
	}
}

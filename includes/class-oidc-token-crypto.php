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
 * Provides authenticated encryption/decryption for stored tokens.
 *
 * SECURITY: Uses ChaCha20-Poly1305-IETF (Sodium) for authenticated encryption.
 * ChaCha20-Poly1305 is WordPress's preferred cryptographic library and provides:
 * - Confidentiality: 256-bit key makes brute force attacks computationally infeasible
 * - Integrity/Authenticity: Poly1305 authentication tag detects tampering or corruption
 * - Performance: Constant-time operations resistant to timing attacks
 * - Compatibility: Pure-PHP fallback ensures availability on all WordPress installations
 * - Standard: IETF RFC 8439, used in TLS 1.3 and modern security protocols
 *
 * BACKWARD COMPATIBILITY: Supports decrypting legacy OpenSSL AES-256-GCM tokens (v1).
 * New tokens are encrypted with Sodium ChaCha20-Poly1305 (v2).
 */
class OIDC_Token_Crypto {
	// Current version (Sodium ChaCha20-Poly1305-IETF)
	const PREFIX_V2       = 'enc:v2:';
	const NONCE_LENGTH_V2 = 12; // SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES
	const KEY_LENGTH_V2   = 32; // SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_IETF_KEYBYTES

	// Legacy version (OpenSSL AES-256-GCM) - kept for backward compatibility
	const PREFIX_V1     = 'enc:v1:';
	const CIPHER_V1     = 'aes-256-gcm';
	const IV_LENGTH_V1  = 12;
	const TAG_LENGTH_V1 = 16;

	// Deprecated constants for backward compatibility
	const PREFIX     = self::PREFIX_V1;
	const CIPHER     = self::CIPHER_V1;
	const IV_LENGTH  = self::IV_LENGTH_V1;
	const TAG_LENGTH = self::TAG_LENGTH_V1;

	/**
	 * Check if the environment supports required Sodium functions.
	 *
	 * WordPress includes ParagonIE_Sodium_Compat since 5.2.0, which automatically
	 * provides pure-PHP implementations if the native libsodium extension is not
	 * available. This means Sodium functions are always available in WordPress 5.2+.
	 *
	 * This check exists primarily for edge cases (very old WordPress versions or
	 * corrupted installations) rather than performance concerns - sodium_compat
	 * does not override native functions, it only provides fallbacks.
	 *
	 * @return bool
	 */
	public static function is_supported(): bool {
		// Sodium functions are guaranteed available in WordPress 5.2+
		// Either via native PHP extension or sodium_compat pure-PHP fallback
		return function_exists( 'sodium_crypto_aead_chacha20poly1305_ietf_encrypt' )
			&& function_exists( 'sodium_crypto_aead_chacha20poly1305_ietf_decrypt' );
	}

	/**
	 * Check if OpenSSL v1 decryption is available (for backward compatibility).
	 *
	 * @return bool
	 */
	private static function is_openssl_supported(): bool {
		if ( ! function_exists( 'openssl_encrypt' ) || ! function_exists( 'openssl_decrypt' ) ) {
			return false;
		}

		$ciphers = openssl_get_cipher_methods( true );
		return in_array( self::CIPHER_V1, $ciphers, true );
	}

	/**
	 * Encrypt a token value using Sodium ChaCha20-Poly1305-IETF.
	 *
	 * SECURITY: Uses authenticated encryption (AEAD) which provides:
	 * - Confidentiality: Encrypted ciphertext cannot be read without the key
	 * - Integrity: Authentication tag ensures data hasn't been modified
	 * - Authenticity: Tag proves data was encrypted with the correct key
	 *
	 * @param string $plaintext Token string to encrypt.
	 * @return string|WP_Error Encrypted token with v2 prefix or error.
	 */
	public static function encrypt( string $plaintext ) {
		if ( '' === $plaintext ) {
			return '';
		}

		if ( ! self::is_supported() ) {
			return new WP_Error(
				'oidc_encryption_unavailable',
				__( 'Sodium cryptography functions are not available on this server.', 'secure-oidc-login' )
			);
		}

		try {
			// Generate random nonce - MUST be unique for each encryption
			// ChaCha20-Poly1305-IETF requires a fresh 12-byte nonce for every operation
			$nonce = random_bytes( self::NONCE_LENGTH_V2 );
			$key   = self::get_key();

			// Encrypt using ChaCha20-Poly1305-IETF AEAD
			// The authentication tag is automatically included in the ciphertext
			// Associated data (AAD) is empty string - could be used for binding context
			$ciphertext = sodium_crypto_aead_chacha20poly1305_ietf_encrypt(
				$plaintext,
				'', // Additional authenticated data (not needed for simple token encryption)
				$nonce,
				$key
			);

			// Concatenate nonce + ciphertext (tag is embedded in ciphertext)
			// Structure: [12 bytes nonce][variable length ciphertext with embedded tag]
			$payload = base64_encode( $nonce . $ciphertext );

			return self::PREFIX_V2 . $payload;

		} catch ( Exception $e ) {
			return new WP_Error( 'oidc_encryption_failed', __( 'Failed to encrypt token.', 'secure-oidc-login' ) );
		}
	}

	/**
	 * Decrypt a stored token if it is encrypted. Legacy plaintext values are returned as-is.
	 *
	 * SECURITY: Handles backward compatibility with multiple encryption versions:
	 * - v2 (current): Sodium ChaCha20-Poly1305-IETF
	 * - v1 (legacy): OpenSSL AES-256-GCM
	 * - No prefix (legacy): Plaintext tokens from before encryption was added
	 *
	 * SECURITY IMPLICATION: This allows unencrypted tokens to be used, which reduces
	 * protection against database leaks. Admins should rotate tokens after enabling encryption.
	 *
	 * @param string $value Stored token value (encrypted or plaintext).
	 * @return string|WP_Error Decrypted token, original plaintext, or error on decrypt failure.
	 */
	public static function decrypt_if_needed( string $value ) {
		if ( '' === $value ) {
			return '';
		}

		// Route to appropriate decryption method based on version prefix
		if ( strpos( $value, self::PREFIX_V2 ) === 0 ) {
			return self::decrypt_v2_sodium( $value );
		} elseif ( strpos( $value, self::PREFIX_V1 ) === 0 ) {
			return self::decrypt_v1_openssl( $value );
		} else {
			// Legacy plaintext value - return as-is for backward compatibility
			return $value;
		}
	}

	/**
	 * Decrypt a v2 token encrypted with Sodium ChaCha20-Poly1305-IETF.
	 *
	 * @param string $value Encrypted token with v2 prefix.
	 * @return string|WP_Error Decrypted token or error.
	 */
	private static function decrypt_v2_sodium( string $value ) {
		if ( ! self::is_supported() ) {
			return new WP_Error(
				'oidc_encryption_unavailable',
				__( 'Sodium cryptography functions are not available on this server.', 'secure-oidc-login' )
			);
		}

		// Remove prefix and decode base64 payload
		$payload = substr( $value, strlen( self::PREFIX_V2 ) );
		$decoded = base64_decode( $payload, true );

		if ( false === $decoded ) {
			return new WP_Error( 'oidc_decryption_failed', __( 'Invalid encrypted token payload.', 'secure-oidc-login' ) );
		}

		// Validate minimum length: nonce (12 bytes) + minimum ciphertext with tag
		// SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_IETF_ABYTES = 16 bytes for tag
		$min_length = self::NONCE_LENGTH_V2 + 16;
		if ( strlen( $decoded ) < $min_length ) {
			return new WP_Error( 'oidc_decryption_failed', __( 'Encrypted token payload is too short.', 'secure-oidc-login' ) );
		}

		// Extract components: nonce and ciphertext (which includes embedded tag)
		$nonce      = substr( $decoded, 0, self::NONCE_LENGTH_V2 );
		$ciphertext = substr( $decoded, self::NONCE_LENGTH_V2 );

		try {
			$key       = self::get_key();
			$plaintext = sodium_crypto_aead_chacha20poly1305_ietf_decrypt(
				$ciphertext,
				'', // Additional authenticated data (must match what was used during encryption)
				$nonce,
				$key
			);

			return $plaintext;

		} catch ( Exception $e ) {
			return new WP_Error( 'oidc_decryption_failed', __( 'Failed to decrypt token.', 'secure-oidc-login' ) );
		}
	}

	/**
	 * Decrypt a v1 token encrypted with OpenSSL AES-256-GCM (legacy).
	 *
	 * @param string $value Encrypted token with v1 prefix.
	 * @return string|WP_Error Decrypted token or error.
	 */
	private static function decrypt_v1_openssl( string $value ) {
		if ( ! self::is_openssl_supported() ) {
			return new WP_Error(
				'oidc_encryption_unavailable',
				__( 'OpenSSL AES-256-GCM is not available on this server for legacy token decryption.', 'secure-oidc-login' )
			);
		}

		// Remove prefix and decode base64 payload
		$payload = substr( $value, strlen( self::PREFIX_V1 ) );
		$decoded = base64_decode( $payload, true );

		if ( false === $decoded ) {
			return new WP_Error( 'oidc_decryption_failed', __( 'Invalid encrypted token payload.', 'secure-oidc-login' ) );
		}

		// Validate minimum length: IV (12 bytes) + tag (16 bytes) = 28 bytes minimum
		if ( strlen( $decoded ) < ( self::IV_LENGTH_V1 + self::TAG_LENGTH_V1 ) ) {
			return new WP_Error( 'oidc_decryption_failed', __( 'Encrypted token payload is too short.', 'secure-oidc-login' ) );
		}

		// Extract components from concatenated binary data
		// Byte structure: [0-11: IV][12-27: tag][28+: ciphertext]
		$iv         = substr( $decoded, 0, self::IV_LENGTH_V1 );
		$tag        = substr( $decoded, self::IV_LENGTH_V1, self::TAG_LENGTH_V1 );
		$ciphertext = substr( $decoded, self::IV_LENGTH_V1 + self::TAG_LENGTH_V1 );

		try {
			$key       = self::get_key();
			$plaintext = openssl_decrypt( $ciphertext, self::CIPHER_V1, $key, OPENSSL_RAW_DATA, $iv, $tag );

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
	 * The same key is used for both Sodium ChaCha20-Poly1305 (v2) and OpenSSL
	 * AES-256-GCM (v1) to ensure tokens encrypted with v1 can still be decrypted
	 * after the migration to v2.
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
		// Hash to exactly 256 bits (32 bytes) - suitable for both ChaCha20 and AES-256
		return hash( 'sha256', $salt, true );
	}
}

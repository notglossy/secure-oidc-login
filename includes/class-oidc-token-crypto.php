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
 */
class OIDC_Token_Crypto {
	const CIPHER     = 'aes-256-gcm';
	const IV_LENGTH  = 12; // Recommended IV length for GCM
	const TAG_LENGTH = 16; // 128-bit tag
	const PREFIX     = 'enc:v1:';

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
			$iv  = random_bytes( self::IV_LENGTH );
			$key = self::get_key();

			$ciphertext = openssl_encrypt( $plaintext, self::CIPHER, $key, OPENSSL_RAW_DATA, $iv, $tag, '', self::TAG_LENGTH );

			if ( false === $ciphertext ) {
				return new WP_Error( 'oidc_encryption_failed', __( 'Failed to encrypt token.', 'secure-oidc-login' ) );
			}

			$payload = base64_encode( $iv . $tag . $ciphertext );

			return self::PREFIX . $payload;

		} catch ( Exception $e ) {
			return new WP_Error( 'oidc_encryption_failed', __( 'Failed to encrypt token.', 'secure-oidc-login' ) );
		}
	}

	/**
	 * Decrypt a stored token if it is encrypted. Legacy plaintext values are returned as-is.
	 *
	 * @param string $value Stored token value (encrypted or plaintext).
	 * @return string|WP_Error Decrypted token, original plaintext, or error on decrypt failure.
	 */
	public static function decrypt_if_needed( string $value ) {
		if ( '' === $value ) {
			return '';
		}

		if ( strpos( $value, self::PREFIX ) !== 0 ) {
			// Legacy plaintext value
			return $value;
		}

		if ( ! self::is_supported() ) {
			return new WP_Error( 'oidc_encryption_unavailable', __( 'OpenSSL AES-256-GCM is not available on this server.', 'secure-oidc-login' ) );
		}

		$payload = substr( $value, strlen( self::PREFIX ) );
		$decoded = base64_decode( $payload, true );

		if ( false === $decoded ) {
			return new WP_Error( 'oidc_decryption_failed', __( 'Invalid encrypted token payload.', 'secure-oidc-login' ) );
		}

		if ( strlen( $decoded ) < ( self::IV_LENGTH + self::TAG_LENGTH ) ) {
			return new WP_Error( 'oidc_decryption_failed', __( 'Encrypted token payload is too short.', 'secure-oidc-login' ) );
		}

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
	 * Derive a 256-bit key from WordPress salts.
	 *
	 * @return string Binary key.
	 */
	private static function get_key(): string {
		$salt = wp_salt( 'secure_oidc_token' );
		return hash( 'sha256', $salt, true );
	}
}

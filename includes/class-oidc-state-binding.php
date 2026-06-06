<?php
declare(strict_types=1);
/**
 * Browser binding for the OIDC authorization flow.
 *
 * Ties the CSRF `state` to the browser that initiated the login by issuing a
 * secret cookie and storing only its hash server-side. Prevents login-CSRF /
 * forced-login (session fixation): a browser that never received the cookie
 * cannot redeem a captured `state`/`code` callback URL.
 *
 * @package Secure_OIDC_Login
 * @since 1.3.2
 */

// Prevent direct file access
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Helper for binding the OIDC flow to the initiating browser.
 *
 * The binding secret is set as an HttpOnly cookie on the initiating browser;
 * only its SHA-256 hash is persisted in the `oidc_state_$state` transient. On
 * callback the flow proceeds only when SHA-256(cookie) matches the stored hash,
 * which only the initiating browser can satisfy. The secret never appears in any
 * URL, log, history, or Referer, and only its hash is stored server-side.
 */
class OIDC_State_Binding {
	/**
	 * Generate a fresh high-entropy browser-binding secret.
	 *
	 * @return string A 32-character alphanumeric secret.
	 */
	public static function generate(): string {
		return wp_generate_password( 32, false );
	}

	/**
	 * Hash a binding secret for server-side storage.
	 *
	 * @param string $secret The binding secret to hash.
	 * @return string The SHA-256 hash of the secret.
	 */
	public static function hash( string $secret ): string {
		return hash( 'sha256', $secret );
	}

	/**
	 * Verify, in constant time, that a cookie secret matches the stored hash.
	 *
	 * @param mixed  $stored_hash  The hash stored in the state transient.
	 * @param string $cookie_value The binding secret presented by the browser.
	 * @return bool True only when the cookie secret hashes to the stored value.
	 */
	public static function is_valid( $stored_hash, string $cookie_value ): bool {
		if ( empty( $stored_hash ) || ! is_string( $stored_hash ) || '' === $cookie_value ) {
			return false;
		}

		return hash_equals( $stored_hash, self::hash( $cookie_value ) );
	}
}

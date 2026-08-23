<?php
/**
 * Environment variable helpers.
 *
 * @package Secure_OIDC_Login
 */

declare( strict_types = 1 );

// Prevent direct file access
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Strict parsing of boolean environment variables.
 *
 * @since 1.3.2
 */
class OIDC_Env {
	/**
	 * Read a boolean environment variable.
	 *
	 * Values are parsed with FILTER_VALIDATE_BOOLEAN, so "true"/"false",
	 * "1"/"0", "yes"/"no", and "on"/"off" (case-insensitive) are recognized.
	 *
	 * Returns null when the variable is unset/empty or holds an unrecognized
	 * value; callers should fall back to the stored setting in that case (a
	 * warning is logged for unrecognized values so misconfigurations are not
	 * silent).
	 *
	 * @since 1.3.2
	 *
	 * @param string $name Environment variable name.
	 * @return bool|null True/false when recognized, null when unset or invalid.
	 */
	public static function get_bool( string $name ): ?bool {
		$raw = getenv( $name );

		if ( false === $raw || '' === $raw ) {
			return null;
		}

		$value = filter_var( $raw, FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE );

		if ( null === $value ) {
			error_log(
				sprintf(
					'[Secure OIDC Login] Ignoring invalid boolean value "%s" for %s; falling back to stored setting.',
					$raw,
					$name
				)
			);
		}

		return $value;
	}
}

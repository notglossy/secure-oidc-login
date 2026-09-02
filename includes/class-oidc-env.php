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

	/**
	 * Read an integer environment variable with range validation.
	 *
	 * Returns $default when the variable is unset/empty or holds an invalid
	 * value outside the allowed range (a warning is logged for invalid values
	 * so misconfigurations are not silent).
	 *
	 * @since 1.4.0
	 *
	 * @param string $name    Environment variable name.
	 * @param int    $default Default value when not set or invalid.
	 * @param int    $min     Minimum allowed value (inclusive).
	 * @param int    $max     Maximum allowed value (inclusive).
	 * @return int Validated integer value.
	 */
	public static function get_int( string $name, int $default, int $min, int $max ): int {
		$raw = getenv( $name );

		if ( false === $raw || '' === $raw ) {
			return $default;
		}

		$parsed = filter_var( $raw, FILTER_VALIDATE_INT );

		if ( false === $parsed || $parsed < $min || $parsed > $max ) {
			error_log(
				sprintf(
					'[Secure OIDC Login] Invalid %s value: %s. Using default %d.',
					$name,
					$raw,
					$default
				)
			);
			return $default;
		}

		return $parsed;
	}
}

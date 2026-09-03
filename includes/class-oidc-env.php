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
	 * Sanitize a raw env value for safe inclusion in log lines.
	 *
	 * Env values are operator-controlled, but newlines would allow log-line
	 * injection and very long values bloat the log, so collapse CR/LF runs
	 * to a single space and cap the length.
	 *
	 * @since 1.4.0
	 *
	 * @param string $raw Unsanitized raw value.
	 * @return string Value safe to interpolate into a single log line.
	 */
	private static function sanitize_for_log( string $raw ): string {
		$single_line = preg_replace( '/[\r\n]+/', ' ', $raw );

		if ( ! is_string( $single_line ) ) {
			return '';
		}

		return substr( $single_line, 0, 200 );
	}

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
					self::sanitize_for_log( $raw ),
					$name
				)
			);
		}

		return $value;
	}

	/**
	 * Read an integer environment variable with range validation.
	 *
	 * Returns $default_value when the variable is unset/empty or holds an invalid
	 * value outside the allowed range (a warning is logged for invalid values
	 * so misconfigurations are not silent).
	 *
	 * @since 1.4.0
	 *
	 * @param string $name          Environment variable name.
	 * @param int    $default_value Default value when not set or invalid.
	 * @param int    $min           Minimum allowed value (inclusive).
	 * @param int    $max           Maximum allowed value (inclusive).
	 * @return int Validated integer value.
	 */
	public static function get_int( string $name, int $default_value, int $min, int $max ): int {
		$raw = getenv( $name );

		if ( false === $raw || '' === $raw ) {
			return $default_value;
		}

		$parsed = filter_var( $raw, FILTER_VALIDATE_INT );

		if ( false === $parsed || $parsed < $min || $parsed > $max ) {
			error_log(
				sprintf(
					'[Secure OIDC Login] Invalid %s value: %s. Using default %d.',
					$name,
					self::sanitize_for_log( $raw ),
					$default_value
				)
			);
			return $default_value;
		}

		return $parsed;
	}
}

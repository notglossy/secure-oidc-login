<?php
declare(strict_types=1);
/**
 * Rate limiter for OIDC authentication endpoints.
 *
 * Implements rate limiting using WordPress transients, similar to
 * WordPress core's comment flood and email check rate limiting.
 *
 * @package Secure_OIDC_Login
 * @since 0.7.0
 */

// Prevent direct file access
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Rate limiter using WordPress transients.
 *
 * Provides defense against brute force attacks by limiting the number
 * of authentication attempts from a single IP address within a time window.
 *
 * Implementation follows WordPress core patterns:
 * - Similar to check_comment_flood_db() for comment spam prevention
 * - Similar to wp-mail.php email check rate limiting
 * - Uses transients for storage (auto-cleanup on expiration)
 */
class OIDC_Rate_Limiter {
	/**
	 * Maximum attempts allowed within the time window.
	 *
	 * Can be overridden via SECURE_OIDC_RATE_LIMIT_ATTEMPTS environment variable.
	 *
	 * @var int
	 */
	private int $max_attempts;

	/**
	 * Time window in seconds for rate limiting.
	 *
	 * Can be overridden via SECURE_OIDC_RATE_LIMIT_WINDOW environment variable.
	 *
	 * @var int
	 */
	private int $time_window;

	/**
	 * Lockout duration in seconds after max attempts exceeded.
	 *
	 * Can be overridden via SECURE_OIDC_RATE_LIMIT_LOCKOUT environment variable.
	 *
	 * @var int
	 */
	private int $lockout_duration;

	/**
	 * Constructor - Initialize rate limiting configuration.
	 *
	 * Defaults:
	 * - 10 attempts per 5 minutes (similar to typical login rate limits)
	 * - 15 minute lockout after exceeding limit
	 *
	 * Can be configured via environment variables:
	 * - SECURE_OIDC_RATE_LIMIT_ATTEMPTS (1-100)
	 * - SECURE_OIDC_RATE_LIMIT_WINDOW (60-3600 seconds)
	 * - SECURE_OIDC_RATE_LIMIT_LOCKOUT (60-86400 seconds)
	 */
	public function __construct() {
		// Default: 10 attempts
		$this->max_attempts = $this->get_env_int( 'SECURE_OIDC_RATE_LIMIT_ATTEMPTS', 10, 1, 100 );

		// Default: 5 minutes
		$this->time_window = $this->get_env_int( 'SECURE_OIDC_RATE_LIMIT_WINDOW', 5 * MINUTE_IN_SECONDS, MINUTE_IN_SECONDS, HOUR_IN_SECONDS );

		// Default: 15 minutes
		$this->lockout_duration = $this->get_env_int( 'SECURE_OIDC_RATE_LIMIT_LOCKOUT', 15 * MINUTE_IN_SECONDS, MINUTE_IN_SECONDS, DAY_IN_SECONDS );
	}

	/**
	 * Get integer from environment variable with validation.
	 *
	 * @param string $var_name      Environment variable name.
	 * @param int    $default_value Default value if not set or invalid.
	 * @param int    $min           Minimum allowed value.
	 * @param int    $max           Maximum allowed value.
	 * @return int Validated integer value.
	 */
	private function get_env_int( string $var_name, int $default_value, int $min, int $max ): int {
		$env_value = getenv( $var_name );
		if ( false === $env_value || '' === $env_value ) {
			return $default_value;
		}

		$parsed = filter_var( $env_value, FILTER_VALIDATE_INT );
		if ( false === $parsed || $parsed < $min || $parsed > $max ) {
			error_log( "[Secure OIDC Login] Invalid {$var_name} value: {$env_value}. Using default {$default_value}." );
			return $default_value;
		}

		return $parsed;
	}

	/**
	 * Check if the current request should be rate limited.
	 *
	 * SECURITY: Uses IP-based tracking to prevent distributed attacks from
	 * bypassing rate limits via multiple user accounts.
	 *
	 * @param string $action Unique identifier for the action being rate limited (e.g., 'callback', 'login').
	 * @return bool True if rate limit exceeded, false otherwise.
	 */
	public function is_rate_limited( string $action ): bool {
		$ip_address = $this->get_client_ip();

		// Check if IP is currently locked out
		$lockout_key = $this->get_lockout_key( $action, $ip_address );
		if ( get_transient( $lockout_key ) ) {
			// Still locked out
			$this->log_rate_limit_event( $action, $ip_address, 'blocked_during_lockout' );
			return true;
		}

		// Check current attempt count
		$attempts_key = $this->get_attempts_key( $action, $ip_address );
		$attempts     = get_transient( $attempts_key );

		if ( false === $attempts ) {
			// No previous attempts or window expired
			return false;
		}

		if ( $attempts >= $this->max_attempts ) {
			// Exceeded max attempts - initiate lockout
			$this->lockout( $action, $ip_address );
			$this->log_rate_limit_event( $action, $ip_address, 'lockout_initiated', $attempts );
			return true;
		}

		// Within limits
		return false;
	}

	/**
	 * Record an attempt for rate limiting.
	 *
	 * Should be called for each authentication attempt, successful or not.
	 *
	 * @param string $action Unique identifier for the action.
	 */
	public function record_attempt( string $action ): void {
		$ip_address   = $this->get_client_ip();
		$attempts_key = $this->get_attempts_key( $action, $ip_address );
		$attempts     = get_transient( $attempts_key );

		if ( false === $attempts ) {
			// First attempt in this window
			set_transient( $attempts_key, 1, $this->time_window );
		} else {
			// Increment attempt count
			set_transient( $attempts_key, $attempts + 1, $this->time_window );
		}
	}

	/**
	 * Clear rate limit for an IP address (e.g., after successful authentication).
	 *
	 * @param string $action     Unique identifier for the action.
	 * @param string $ip_address Optional. IP address to clear. Defaults to current client IP.
	 */
	public function clear_limit( string $action, string $ip_address = '' ): void {
		if ( empty( $ip_address ) ) {
			$ip_address = $this->get_client_ip();
		}

		$attempts_key = $this->get_attempts_key( $action, $ip_address );
		$lockout_key  = $this->get_lockout_key( $action, $ip_address );

		delete_transient( $attempts_key );
		delete_transient( $lockout_key );
	}

	/**
	 * Initiate lockout for an IP address.
	 *
	 * @param string $action     Action being locked out.
	 * @param string $ip_address IP address to lock out.
	 */
	private function lockout( string $action, string $ip_address ): void {
		$lockout_key = $this->get_lockout_key( $action, $ip_address );
		set_transient( $lockout_key, time(), $this->lockout_duration );

		// Also clear the attempts counter to start fresh after lockout
		$attempts_key = $this->get_attempts_key( $action, $ip_address );
		delete_transient( $attempts_key );
	}

	/**
	 * Get the client IP address.
	 *
	 * SECURITY: Checks for proxied requests but validates headers to prevent spoofing.
	 * Only trusts proxy headers if WordPress is behind a known reverse proxy.
	 *
	 * @return string IP address.
	 */
	private function get_client_ip(): string {
		$ip = '';

		// Standard REMOTE_ADDR (most reliable)
		if ( ! empty( $_SERVER['REMOTE_ADDR'] ) ) {
			$ip = $_SERVER['REMOTE_ADDR'];
		}

		// Check for proxy headers (only if behind trusted proxy)
		// WordPress VIP and other hosting providers set this
		$trust_proxy = ( defined( 'SECURE_OIDC_TRUST_PROXY_HEADERS' ) && SECURE_OIDC_TRUST_PROXY_HEADERS )
			|| filter_var( getenv( 'SECURE_OIDC_TRUST_PROXY_HEADERS' ), FILTER_VALIDATE_BOOLEAN );

		if ( $trust_proxy ) {
			// Check common proxy headers in order of preference
			$proxy_headers = array(
				'HTTP_X_REAL_IP',
				'HTTP_X_FORWARDED_FOR',
				'HTTP_CLIENT_IP',
			);

			foreach ( $proxy_headers as $header ) {
				if ( ! empty( $_SERVER[ $header ] ) ) {
					// X-Forwarded-For can contain multiple IPs, take the first (client IP)
					$forwarded_ips = explode( ',', $_SERVER[ $header ] );
					$forwarded_ip  = trim( $forwarded_ips[0] );

					// Validate it's a real IP address
					if ( filter_var( $forwarded_ip, FILTER_VALIDATE_IP ) ) {
						$ip = $forwarded_ip;
						break;
					}
				}
			}
		}

		// Fallback if no valid IP found
		if ( empty( $ip ) ) {
			$ip = '0.0.0.0';
		}

		return sanitize_text_field( $ip );
	}

	/**
	 * Get transient key for attempt tracking.
	 *
	 * @param string $action     Action identifier.
	 * @param string $ip_address IP address.
	 * @return string Transient key.
	 */
	private function get_attempts_key( string $action, string $ip_address ): string {
		// Hash IP to keep transient key length reasonable and add privacy
		$ip_hash = hash( 'sha256', $ip_address . wp_salt( 'nonce' ) );
		return 'oidc_attempts_' . $action . '_' . substr( $ip_hash, 0, 16 );
	}

	/**
	 * Get transient key for lockout tracking.
	 *
	 * @param string $action     Action identifier.
	 * @param string $ip_address IP address.
	 * @return string Transient key.
	 */
	private function get_lockout_key( string $action, string $ip_address ): string {
		// Hash IP to keep transient key length reasonable and add privacy
		$ip_hash = hash( 'sha256', $ip_address . wp_salt( 'nonce' ) );
		return 'oidc_lockout_' . $action . '_' . substr( $ip_hash, 0, 16 );
	}

	/**
	 * Mask an IP address for privacy-compliant logging.
	 *
	 * Truncates the last octet (IPv4) or last group (IPv6) to anonymize
	 * the specific host while preserving subnet-level information for debugging.
	 *
	 * @param string $ip IP address to mask.
	 * @return string Masked IP address, or 'unknown' if invalid.
	 */
	public static function mask_ip( string $ip ): string {
		if ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
			return preg_replace( '/\.\d+$/', '.xxx', $ip );
		}
		if ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) ) {
			return preg_replace( '/:[^:]*$/', ':xxxx', $ip );
		}
		return 'unknown';
	}

	/**
	 * Log rate limiting events for security auditing.
	 *
	 * @param string $action     Action being rate limited.
	 * @param string $ip_address IP address.
	 * @param string $event      Event type.
	 * @param int    $attempts   Optional. Number of attempts.
	 */
	private function log_rate_limit_event( string $action, string $ip_address, string $event, int $attempts = 0 ): void {
		$message = sprintf(
			'Rate limit %s for action "%s" from IP %s',
			$event,
			$action,
			self::mask_ip( $ip_address )
		);

		if ( $attempts > 0 ) {
			$message .= sprintf( ' (%d attempts)', $attempts );
		}

		error_log( '[Secure OIDC Login] ' . $message );
	}

	/**
	 * Get remaining attempts before lockout.
	 *
	 * Useful for displaying to users or in headers.
	 *
	 * @param string $action Action identifier.
	 * @return int Remaining attempts (0 if locked out).
	 */
	public function get_remaining_attempts( string $action ): int {
		$ip_address   = $this->get_client_ip();
		$lockout_key  = $this->get_lockout_key( $action, $ip_address );
		$attempts_key = $this->get_attempts_key( $action, $ip_address );

		// Check lockout first
		if ( get_transient( $lockout_key ) ) {
			return 0;
		}

		$attempts = get_transient( $attempts_key );
		if ( false === $attempts ) {
			return $this->max_attempts;
		}

		$remaining = $this->max_attempts - (int) $attempts;
		return max( 0, $remaining );
	}

	/**
	 * Get lockout expiration time.
	 *
	 * @param string $action Action identifier.
	 * @return int|false Timestamp when lockout expires, or false if not locked out.
	 */
	public function get_lockout_expiry( string $action ) {
		$ip_address   = $this->get_client_ip();
		$lockout_key  = $this->get_lockout_key( $action, $ip_address );
		$lockout_time = get_transient( $lockout_key );

		if ( false === $lockout_time ) {
			return false;
		}

		return (int) $lockout_time + $this->lockout_duration;
	}
}

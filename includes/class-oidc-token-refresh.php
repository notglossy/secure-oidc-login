<?php
declare(strict_types=1);
/**
 * Automatic token refresh orchestration.
 *
 * @package Secure_OIDC_Login
 * @since 0.7.0
 */

// Prevent direct file access
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Orchestrates automatic token refresh before expiration.
 *
 * SECURITY: Implements M3 (automatic token refresh) and M4 (refresh token rotation
 * enforcement) features for improved UX and security.
 *
 * Token Refresh Flow:
 * 1. Check if auto-refresh is enabled
 * 2. Check if token is expiring within buffer period
 * 3. Call IdP token endpoint with refresh token
 * 4. Validate rotation if enforced
 * 5. Store new tokens
 */
class OIDC_Token_Refresh {

	/**
	 * Default refresh buffer in seconds (5 minutes before expiry).
	 *
	 * @var int
	 */
	const DEFAULT_REFRESH_BUFFER = 300;

	/**
	 * Minimum refresh buffer in seconds.
	 *
	 * @var int
	 */
	const MIN_REFRESH_BUFFER = 60;

	/**
	 * Maximum refresh buffer in seconds.
	 *
	 * @var int
	 */
	const MAX_REFRESH_BUFFER = 3600;

	/**
	 * Lifetime of the per-user refresh lock in seconds.
	 *
	 * Long enough to cover the token endpoint round trip (10s timeout), short
	 * enough that a failed refresh can be retried promptly without hammering the IdP.
	 *
	 * @var int
	 */
	const REFRESH_LOCK_TTL = 30;

	/**
	 * Option-name prefix for the per-user refresh lock.
	 *
	 * Stored as a non-autoloaded option (not a transient) because add_option()
	 * maps to INSERT IGNORE on the option_name unique key, giving an atomic
	 * acquire across concurrent requests. Cleaned up on plugin deactivation.
	 *
	 * @var string
	 */
	const REFRESH_LOCK_PREFIX = 'oidc_refresh_lock_';

	/**
	 * OIDC Client instance for token operations.
	 *
	 * @var OIDC_Client
	 */
	private OIDC_Client $client;

	/**
	 * Token Manager instance for storage operations.
	 *
	 * @var OIDC_Token_Manager
	 */
	private OIDC_Token_Manager $token_manager;

	/**
	 * Plugin options cache.
	 *
	 * @var array<string, mixed>|null
	 */
	private ?array $options = null;

	/**
	 * Initialize the token refresh handler.
	 *
	 * @param OIDC_Client        $client        The OIDC client for token operations.
	 * @param OIDC_Token_Manager $token_manager The token manager for storage.
	 */
	public function __construct( OIDC_Client $client, OIDC_Token_Manager $token_manager ) {
		$this->client        = $client;
		$this->token_manager = $token_manager;
	}

	/**
	 * Check and refresh tokens if needed.
	 *
	 * Main entry point for automatic token refresh. Called from init hook.
	 *
	 * @param int $user_id The WordPress user ID.
	 * @return true|WP_Error True if no refresh needed or refresh succeeded, WP_Error on failure.
	 */
	public function maybe_refresh( int $user_id ): bool|WP_Error {
		// Check if auto-refresh is enabled
		if ( ! $this->is_auto_refresh_enabled() ) {
			return true;
		}

		// Check if user has a refresh token
		if ( ! $this->token_manager->has_refresh_token( $user_id ) ) {
			return true;
		}

		// Check if token is expiring within buffer period
		$buffer = $this->get_refresh_buffer();
		if ( ! $this->token_manager->is_token_expired( $user_id, $buffer ) ) {
			return true;
		}

		// Token needs refresh
		return $this->refresh( $user_id );
	}

	/**
	 * Force a token refresh for a user.
	 *
	 * @param int $user_id The WordPress user ID.
	 * @return true|WP_Error True on success, WP_Error on failure.
	 */
	public function refresh( int $user_id ): bool|WP_Error {
		// CONCURRENCY: Serialize refreshes per user. Parallel requests (multiple tabs,
		// asset requests) would otherwise race: one request replays the old refresh
		// token after another has rotated it, which rotation-enforcing IdPs treat as
		// token reuse and may revoke the whole token family, logging the user out.
		if ( ! $this->acquire_refresh_lock( $user_id ) ) {
			// Another request is refreshing (or recently failed); treat as success so
			// the current request proceeds with the still-valid stored token.
			return true;
		}

		// Get the refresh token
		$refresh_token = $this->token_manager->get_refresh_token( $user_id );
		if ( is_wp_error( $refresh_token ) ) {
			$this->log_refresh_failure( $user_id, $refresh_token->get_error_message() );
			return $refresh_token;
		}

		// Call the IdP to refresh the token
		$tokens = $this->client->refresh_token( $refresh_token );
		if ( is_wp_error( $tokens ) ) {
			$this->log_refresh_failure( $user_id, $tokens->get_error_message() );
			return $tokens;
		}

		// Validate access_token is present
		if ( empty( $tokens['access_token'] ) ) {
			$error = new WP_Error(
				'oidc_refresh_invalid_response',
				__( 'Token refresh failed: missing access_token in response.', 'secure-oidc-login' )
			);
			$this->log_refresh_failure( $user_id, 'Missing access_token in refresh response' );
			return $error;
		}

		// Validate id_token if present (OIDC Core Section 12.2)
		if ( ! empty( $tokens['id_token'] ) ) {
			$id_token_validation = $this->validate_refresh_id_token( $user_id, $tokens );
			if ( is_wp_error( $id_token_validation ) ) {
				return $id_token_validation;
			}
		}

		// Check for refresh token rotation
		$rotation_result = $this->handle_rotation( $user_id, $tokens, $refresh_token );
		if ( is_wp_error( $rotation_result ) ) {
			return $rotation_result;
		}

		// Store the new tokens
		$store_result = $this->token_manager->store_tokens( $user_id, $tokens );
		if ( is_wp_error( $store_result ) ) {
			$this->log_refresh_failure( $user_id, 'Failed to store refreshed tokens: ' . $store_result->get_error_message() );
			return $store_result;
		}

		// Release the lock on success; the updated expiry prevents redundant refreshes.
		$this->release_refresh_lock( $user_id );

		// Log success
		$this->log_refresh_success( $user_id );

		return true;
	}

	/**
	 * Atomically acquire the per-user refresh lock.
	 *
	 * CONCURRENCY: get_transient()+set_transient() is a non-atomic check-then-set,
	 * so two requests could both miss the lock and both refresh. add_option() maps
	 * to INSERT IGNORE on the option_name unique key, making the acquire atomic
	 * across concurrent requests with or without a persistent object cache.
	 *
	 * The stored timestamp gives the lock a TTL: locks from crashed requests expire
	 * after REFRESH_LOCK_TTL, and because the lock is only released on success, a
	 * failed refresh leaves it in place so the TTL throttles retry storms against
	 * a struggling IdP.
	 *
	 * @param int $user_id The WordPress user ID.
	 * @return bool True if the lock was acquired, false if another request holds it.
	 */
	private function acquire_refresh_lock( int $user_id ): bool {
		$lock_key = self::REFRESH_LOCK_PREFIX . $user_id;

		if ( add_option( $lock_key, (string) time(), '', false ) ) {
			return true;
		}

		$acquired_at = (int) get_option( $lock_key, 0 );
		if ( time() - $acquired_at < self::REFRESH_LOCK_TTL ) {
			return false;
		}

		// The existing lock is past its TTL (crashed request or failed refresh):
		// clear it and retry the atomic acquire. If a concurrent request wins the
		// add_option() race here, this request correctly backs off.
		delete_option( $lock_key );
		return add_option( $lock_key, (string) time(), '', false );
	}

	/**
	 * Release the per-user refresh lock.
	 *
	 * @param int $user_id The WordPress user ID.
	 * @return void
	 */
	private function release_refresh_lock( int $user_id ): void {
		delete_option( self::REFRESH_LOCK_PREFIX . $user_id );
	}

	/**
	 * Check if automatic token refresh is enabled.
	 *
	 * @return bool True if auto-refresh is enabled.
	 */
	public function is_auto_refresh_enabled(): bool {
		$options = $this->get_options();
		return ! empty( $options['enable_auto_token_refresh'] );
	}

	/**
	 * Get the refresh buffer in seconds.
	 *
	 * @return int Seconds before expiry to trigger refresh.
	 */
	public function get_refresh_buffer(): int {
		$options = $this->get_options();

		if ( empty( $options['token_refresh_buffer'] ) ) {
			return self::DEFAULT_REFRESH_BUFFER;
		}

		$buffer = (int) $options['token_refresh_buffer'];

		// Clamp to valid range
		if ( $buffer < self::MIN_REFRESH_BUFFER ) {
			return self::MIN_REFRESH_BUFFER;
		}

		if ( $buffer > self::MAX_REFRESH_BUFFER ) {
			return self::MAX_REFRESH_BUFFER;
		}

		return $buffer;
	}

	/**
	 * Check if refresh token rotation enforcement is enabled.
	 *
	 * @return bool True if rotation is enforced.
	 */
	public function is_rotation_enforced(): bool {
		$options = $this->get_options();
		return ! empty( $options['enforce_refresh_token_rotation'] );
	}

	/**
	 * Handle refresh token rotation detection and enforcement.
	 *
	 * @param int                  $user_id           The WordPress user ID.
	 * @param array<string, mixed> $tokens            New tokens from IdP.
	 * @param string               $old_refresh_token The previous refresh token.
	 * @return true|WP_Error True if rotation handling passed, WP_Error if enforced and failed.
	 */
	private function handle_rotation( int $user_id, array $tokens, string $old_refresh_token ): bool|WP_Error {
		// Check if a new refresh token was provided
		$new_refresh_token = $tokens['refresh_token'] ?? '';

		if ( empty( $new_refresh_token ) ) {
			// No new refresh token received - IdP didn't rotate
			$this->log_rotation_warning( $user_id );

			if ( $this->is_rotation_enforced() ) {
				$this->log_rotation_enforced_failure( $user_id );
				return new WP_Error(
					'oidc_rotation_required',
					__( 'Token refresh failed: refresh token rotation required but not received from IdP.', 'secure-oidc-login' )
				);
			}

			return true;
		}

		// Check if the token was actually rotated (new != old)
		if ( ! $this->token_manager->was_refresh_token_rotated( $user_id, $new_refresh_token ) ) {
			// Same token returned - effectively no rotation
			$this->log_rotation_warning( $user_id );

			if ( $this->is_rotation_enforced() ) {
				$this->log_rotation_enforced_failure( $user_id );
				return new WP_Error(
					'oidc_rotation_required',
					__( 'Token refresh failed: refresh token rotation required but IdP returned same token.', 'secure-oidc-login' )
				);
			}
		}

		return true;
	}

	/**
	 * Validate id_token received during token refresh.
	 *
	 * Per OIDC Core Section 12.2, refreshed id_tokens must have their iss, sub,
	 * and aud validated. The sub claim must match the originally authenticated subject.
	 *
	 * @param int                  $user_id The WordPress user ID.
	 * @param array<string, mixed> $tokens  New tokens from IdP including id_token.
	 * @return true|WP_Error True if validation passed, WP_Error on failure.
	 */
	private function validate_refresh_id_token( int $user_id, array $tokens ): bool|WP_Error {
		// Validate JWT signature, issuer, audience, expiration, and at_hash
		$claims = $this->client->validate_id_token( $tokens['id_token'], null, null, $tokens['access_token'] ?? null );
		if ( is_wp_error( $claims ) ) {
			$this->log_refresh_failure( $user_id, 'Refreshed id_token validation failed: ' . $claims->get_error_message() );
			return new WP_Error(
				'oidc_refresh_id_token_invalid',
				__( 'Token refresh failed: refreshed id_token failed validation.', 'secure-oidc-login' )
			);
		}

		// Verify sub claim matches stored subject (OIDC Core Section 12.2)
		$stored_subject = get_user_meta( $user_id, 'oidc_subject', true );
		if ( empty( $stored_subject ) ) {
			$this->log_refresh_failure( $user_id, 'No stored OIDC subject found for sub claim verification' );
			return new WP_Error(
				'oidc_refresh_subject_missing',
				__( 'Token refresh failed: no stored subject for verification.', 'secure-oidc-login' )
			);
		}

		if ( ! isset( $claims['sub'] ) || $claims['sub'] !== $stored_subject ) {
			$this->log_refresh_failure( $user_id, 'Refreshed id_token sub claim does not match stored subject' );
			return new WP_Error(
				'oidc_refresh_subject_mismatch',
				__( 'Token refresh failed: subject mismatch in refreshed id_token.', 'secure-oidc-login' )
			);
		}

		return true;
	}

	/**
	 * Get plugin options with caching.
	 *
	 * @return array<string, mixed> Plugin options.
	 */
	private function get_options(): array {
		if ( null === $this->options ) {
			$this->options = get_option( 'secure_oidc_login_settings', array() );
		}
		return $this->options;
	}

	/**
	 * Log successful token refresh.
	 *
	 * @param int $user_id The WordPress user ID.
	 * @return void
	 */
	private function log_refresh_success( int $user_id ): void {
		error_log(
			sprintf(
				'[Secure OIDC Login] Access token refreshed for user %d',
				$user_id
			)
		);
	}

	/**
	 * Log token refresh failure.
	 *
	 * @param int    $user_id The WordPress user ID.
	 * @param string $error   The error message.
	 * @return void
	 */
	private function log_refresh_failure( int $user_id, string $error ): void {
		error_log(
			sprintf(
				'[Secure OIDC Login] Token refresh failed for user %d: %s',
				$user_id,
				$error
			)
		);
	}

	/**
	 * Log warning when rotation not received (but not enforced).
	 *
	 * @param int $user_id The WordPress user ID.
	 * @return void
	 */
	private function log_rotation_warning( int $user_id ): void {
		error_log(
			sprintf(
				'[Secure OIDC Login] SECURITY: Refresh token rotation not received from IdP for user %d',
				$user_id
			)
		);
	}

	/**
	 * Log failure when rotation is enforced but not received.
	 *
	 * @param int $user_id The WordPress user ID.
	 * @return void
	 */
	private function log_rotation_enforced_failure( int $user_id ): void {
		error_log(
			sprintf(
				'[Secure OIDC Login] SECURITY: Token refresh failed - rotation required but not received for user %d',
				$user_id
			)
		);
	}
}

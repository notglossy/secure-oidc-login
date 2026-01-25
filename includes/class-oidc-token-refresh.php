<?php
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

		// Log success
		$this->log_refresh_success( $user_id );

		return true;
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

<?php
declare(strict_types=1);

/**
 * OIDC Token Response value object.
 *
 * @package Secure_OIDC_Login
 * @since 0.1.0
 */

// Prevent direct file access
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Encapsulates an OIDC token endpoint response.
 *
 * Provides type-safe access to token response fields and validates
 * required fields according to OIDC Core specification.
 */
class OIDC_Token_Response {
	/** @var string Access token for API authorization */
	private $access_token;

	/** @var string ID token containing user claims */
	private $id_token;

	/** @var string Token type (usually "Bearer") */
	private $token_type;

	/** @var int Token expiration time in seconds */
	private $expires_in;

	/** @var string|null Optional refresh token for getting new access tokens */
	private $refresh_token;

	/** @var string|null Optional scope string */
	private $scope;

	/**
	 * Create a token response from the IdP response array.
	 *
	 * @param array<string, mixed> $response Raw response from token endpoint.
	 * @return OIDC_Token_Response|WP_Error Token response object or error if validation fails.
	 */
	public static function from_array( array $response ) {
		// Validate required fields per OIDC Core spec
		if ( empty( $response['access_token'] ) ) {
			return new WP_Error( 'oidc_error', __( 'Missing access_token in token response.', 'secure-oidc-login' ) );
		}

		if ( empty( $response['id_token'] ) ) {
			return new WP_Error( 'oidc_error', __( 'Missing id_token in token response.', 'secure-oidc-login' ) );
		}

		if ( empty( $response['token_type'] ) ) {
			return new WP_Error( 'oidc_error', __( 'Missing token_type in token response.', 'secure-oidc-login' ) );
		}

		$instance                = new self();
		$instance->access_token  = $response['access_token'];
		$instance->id_token      = $response['id_token'];
		$instance->token_type    = $response['token_type'];
		$instance->expires_in    = isset( $response['expires_in'] ) ? (int) $response['expires_in'] : 3600;
		$instance->refresh_token = $response['refresh_token'] ?? null;
		$instance->scope         = $response['scope'] ?? null;

		return $instance;
	}

	/**
	 * Get the access token.
	 *
	 * @return string The access token.
	 */
	public function get_access_token(): string {
		return $this->access_token;
	}

	/**
	 * Get the ID token.
	 *
	 * @return string The ID token (JWT).
	 */
	public function get_id_token(): string {
		return $this->id_token;
	}

	/**
	 * Get the token type.
	 *
	 * @return string The token type (usually "Bearer").
	 */
	public function get_token_type(): string {
		return $this->token_type;
	}

	/**
	 * Get the token expiration time.
	 *
	 * @return int Seconds until token expires.
	 */
	public function get_expires_in(): int {
		return $this->expires_in;
	}

	/**
	 * Get the refresh token if present.
	 *
	 * @return string|null The refresh token or null.
	 */
	public function get_refresh_token(): ?string {
		return $this->refresh_token;
	}

	/**
	 * Get the scope if present.
	 *
	 * @return string|null The scope string or null.
	 */
	public function get_scope(): ?string {
		return $this->scope;
	}

	/**
	 * Check if a refresh token is available.
	 *
	 * @return bool True if refresh token is present.
	 */
	public function has_refresh_token(): bool {
		return $this->refresh_token !== null;
	}

	/**
	 * Convert back to array format for backward compatibility.
	 *
	 * @return array{access_token: string, id_token: string, token_type: string, expires_in: int, refresh_token?: string, scope?: string}
	 */
	public function to_array(): array {
		$array = array(
			'access_token' => $this->access_token,
			'id_token'     => $this->id_token,
			'token_type'   => $this->token_type,
			'expires_in'   => $this->expires_in,
		);

		if ( $this->refresh_token !== null ) {
			$array['refresh_token'] = $this->refresh_token;
		}

		if ( $this->scope !== null ) {
			$array['scope'] = $this->scope;
		}

		return $array;
	}

	/**
	 * Private constructor - use from_array() to create instances.
	 */
	private function __construct() {
		// Use named constructor pattern
	}
}

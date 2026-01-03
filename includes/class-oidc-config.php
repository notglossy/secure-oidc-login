<?php
declare(strict_types=1);

/**
 * OIDC Provider Configuration value object.
 *
 * @package Secure_OIDC_Login
 * @since 0.1.0
 */

// Prevent direct file access
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Encapsulates OIDC Provider Configuration from discovery endpoint.
 *
 * Provides type-safe access to OpenID Provider Metadata per
 * OpenID Connect Discovery 1.0 specification.
 *
 * @immutable
 */
class OIDC_Config {
	/** @var string Issuer identifier URL (required) */
	private string $issuer;

	/** @var string Authorization endpoint URL (required) */
	private string $authorization_endpoint;

	/** @var string Token endpoint URL (required) */
	private string $token_endpoint;

	/** @var string|null UserInfo endpoint URL */
	private ?string $userinfo_endpoint;

	/** @var string JWKS URI for signature verification (required) */
	private string $jwks_uri;

	/** @var string|null End session endpoint for logout */
	private ?string $end_session_endpoint;

	/** @var array<int, string> Supported scopes */
	private array $scopes_supported;

	/** @var array<int, string> Supported response types */
	private array $response_types_supported;

	/** @var array<int, string> Supported grant types */
	private array $grant_types_supported;

	/** @var array<int, string> Supported subject identifier types */
	private array $subject_types_supported;

	/** @var array<int, string> Supported ID token signing algorithms */
	private array $id_token_signing_alg_values_supported;

	/** @var array<int, string> Supported claims */
	private array $claims_supported;

	/** @var array<string, mixed> All raw configuration for extensibility */
	private array $raw_config;

	/**
	 * Create configuration from discovery document.
	 *
	 * @param array<string, mixed> $config Discovery document data.
	 * @return OIDC_Config|WP_Error Configuration object or error if validation fails.
	 */
	public static function from_array( array $config ) {
		// Validate required fields per OIDC Discovery spec
		if ( empty( $config['issuer'] ) ) {
			return new WP_Error( 'oidc_error', __( 'Missing required issuer in discovery document.', 'secure-oidc-login' ) );
		}

		if ( empty( $config['authorization_endpoint'] ) ) {
			return new WP_Error( 'oidc_error', __( 'Missing required authorization_endpoint in discovery document.', 'secure-oidc-login' ) );
		}

		if ( empty( $config['token_endpoint'] ) ) {
			return new WP_Error( 'oidc_error', __( 'Missing required token_endpoint in discovery document.', 'secure-oidc-login' ) );
		}

		if ( empty( $config['jwks_uri'] ) ) {
			return new WP_Error( 'oidc_error', __( 'Missing required jwks_uri in discovery document.', 'secure-oidc-login' ) );
		}

		$instance                         = new self();
		$instance->issuer                 = (string) $config['issuer'];
		$instance->authorization_endpoint = (string) $config['authorization_endpoint'];
		$instance->token_endpoint         = (string) $config['token_endpoint'];
		$instance->userinfo_endpoint      = isset( $config['userinfo_endpoint'] ) ? (string) $config['userinfo_endpoint'] : null;
		$instance->jwks_uri               = (string) $config['jwks_uri'];
		$instance->end_session_endpoint   = isset( $config['end_session_endpoint'] ) ? (string) $config['end_session_endpoint'] : null;

		// Optional arrays - ensure they're arrays
		$instance->scopes_supported                      = isset( $config['scopes_supported'] ) && is_array( $config['scopes_supported'] )
			? $config['scopes_supported']
			: array();
		$instance->response_types_supported              = isset( $config['response_types_supported'] ) && is_array( $config['response_types_supported'] )
			? $config['response_types_supported']
			: array( 'code' );
		$instance->grant_types_supported                 = isset( $config['grant_types_supported'] ) && is_array( $config['grant_types_supported'] )
			? $config['grant_types_supported']
			: array( 'authorization_code' );
		$instance->subject_types_supported               = isset( $config['subject_types_supported'] ) && is_array( $config['subject_types_supported'] )
			? $config['subject_types_supported']
			: array( 'public' );
		$instance->id_token_signing_alg_values_supported = isset( $config['id_token_signing_alg_values_supported'] ) && is_array( $config['id_token_signing_alg_values_supported'] )
			? $config['id_token_signing_alg_values_supported']
			: array( 'RS256' );
		$instance->claims_supported                      = isset( $config['claims_supported'] ) && is_array( $config['claims_supported'] )
			? $config['claims_supported']
			: array();

		$instance->raw_config = $config;

		return $instance;
	}

	/**
	 * Get the issuer identifier.
	 *
	 * @return string The issuer URL.
	 */
	public function get_issuer(): string {
		return $this->issuer;
	}

	/**
	 * Get the authorization endpoint URL.
	 *
	 * @return string The authorization endpoint.
	 */
	public function get_authorization_endpoint(): string {
		return $this->authorization_endpoint;
	}

	/**
	 * Get the token endpoint URL.
	 *
	 * @return string The token endpoint.
	 */
	public function get_token_endpoint(): string {
		return $this->token_endpoint;
	}

	/**
	 * Get the userinfo endpoint URL if available.
	 *
	 * @return string|null The userinfo endpoint or null.
	 */
	public function get_userinfo_endpoint(): ?string {
		return $this->userinfo_endpoint;
	}

	/**
	 * Get the JWKS URI.
	 *
	 * @return string The JWKS URI.
	 */
	public function get_jwks_uri(): string {
		return $this->jwks_uri;
	}

	/**
	 * Get the end session endpoint URL if available.
	 *
	 * @return string|null The end session endpoint or null.
	 */
	public function get_end_session_endpoint(): ?string {
		return $this->end_session_endpoint;
	}

	/**
	 * Get the supported scopes.
	 *
	 * @return array<int, string> List of supported scopes.
	 */
	public function get_scopes_supported(): array {
		return $this->scopes_supported;
	}

	/**
	 * Get the supported response types.
	 *
	 * @return array<int, string> List of supported response types.
	 */
	public function get_response_types_supported(): array {
		return $this->response_types_supported;
	}

	/**
	 * Get the supported grant types.
	 *
	 * @return array<int, string> List of supported grant types.
	 */
	public function get_grant_types_supported(): array {
		return $this->grant_types_supported;
	}

	/**
	 * Get the supported subject identifier types.
	 *
	 * @return array<int, string> List of supported subject types.
	 */
	public function get_subject_types_supported(): array {
		return $this->subject_types_supported;
	}

	/**
	 * Get the supported signing algorithms for ID tokens.
	 *
	 * @return array<int, string> List of supported algorithms.
	 */
	public function get_id_token_signing_alg_values_supported(): array {
		return $this->id_token_signing_alg_values_supported;
	}

	/**
	 * Get the supported claims.
	 *
	 * @return array<int, string> List of supported claims.
	 */
	public function get_claims_supported(): array {
		return $this->claims_supported;
	}

	/**
	 * Check if a specific scope is supported.
	 *
	 * @param string $scope The scope to check.
	 * @return bool True if scope is supported.
	 */
	public function supports_scope( string $scope ): bool {
		return in_array( $scope, $this->scopes_supported, true );
	}

	/**
	 * Check if a specific response type is supported.
	 *
	 * @param string $response_type The response type to check.
	 * @return bool True if response type is supported.
	 */
	public function supports_response_type( string $response_type ): bool {
		return in_array( $response_type, $this->response_types_supported, true );
	}

	/**
	 * Check if PKCE is supported.
	 *
	 * @return bool True if PKCE is supported.
	 */
	public function supports_pkce(): bool {
		// Check if S256 code challenge method is supported
		$methods = $this->raw_config['code_challenge_methods_supported'] ?? array();
		return is_array( $methods ) && in_array( 'S256', $methods, true );
	}

	/**
	 * Check if single logout is supported.
	 *
	 * @return bool True if end session endpoint is available.
	 */
	public function supports_logout(): bool {
		return $this->end_session_endpoint !== null;
	}

	/**
	 * Get a custom configuration value.
	 *
	 * @param string $key The configuration key.
	 * @return mixed The configuration value or null if not present.
	 */
	public function get_config_value( string $key ) {
		return $this->raw_config[ $key ] ?? null;
	}

	/**
	 * Convert back to array format for backward compatibility.
	 *
	 * @return array<string, mixed> All configuration as associative array.
	 */
	public function to_array(): array {
		return $this->raw_config;
	}

	/**
	 * Private constructor - use from_array() to create instances.
	 */
	private function __construct() {
		// Use named constructor pattern
	}
}

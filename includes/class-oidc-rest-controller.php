<?php
/**
 * OIDC REST API Controller.
 *
 * Provides REST API endpoints for OIDC-related operations.
 *
 * @package Secure_OIDC_Login
 * @since 0.6.0
 */

// Prevent direct file access
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * REST API controller for OIDC discovery endpoint.
 *
 * Handles fetching OpenID Provider Configuration documents via the REST API.
 * This replaces the admin-ajax.php implementation for better performance
 * and follows modern WordPress patterns.
 *
 * @since 0.6.0
 */
class OIDC_REST_Controller extends WP_REST_Controller {
	/**
	 * The namespace for REST routes.
	 *
	 * @var string
	 */
	protected $namespace = 'secure-oidc-login/v1';

	/**
	 * Register REST API routes.
	 */
	public function register_routes(): void {
		register_rest_route(
			$this->namespace,
			'/discover',
			array(
				'methods'             => WP_REST_Server::CREATABLE,
				'callback'            => array( $this, 'discover' ),
				'permission_callback' => array( $this, 'discover_permissions_check' ),
				'args'                => array(
					'discovery_url' => array(
						'required'          => true,
						'type'              => 'string',
						'sanitize_callback' => 'esc_url_raw',
						'validate_callback' => array( $this, 'validate_discovery_url_format' ),
						'description'       => __( 'The OIDC discovery URL or base issuer URL.', 'secure-oidc-login' ),
					),
				),
			)
		);
	}

	/**
	 * Check if the current user has permission to perform discovery.
	 *
	 * @param WP_REST_Request $request The REST request.
	 * @return bool|WP_Error True if allowed, WP_Error otherwise.
	 */
	public function discover_permissions_check( WP_REST_Request $request ): bool|WP_Error {
		if ( ! current_user_can( 'manage_options' ) ) {
			return new WP_Error(
				'rest_forbidden',
				__( 'You do not have permission to perform OIDC discovery.', 'secure-oidc-login' ),
				array( 'status' => 403 )
			);
		}
		return true;
	}

	/**
	 * Validate the discovery URL format.
	 *
	 * @param mixed           $value   The URL value.
	 * @param WP_REST_Request $request The REST request.
	 * @param string          $param   The parameter name.
	 * @return bool True if valid, false otherwise.
	 */
	public function validate_discovery_url_format( mixed $value, WP_REST_Request $request, string $param ): bool {
		if ( empty( $value ) || ! is_string( $value ) ) {
			return false;
		}

		// Check if it's a valid URL format
		if ( ! filter_var( $value, FILTER_VALIDATE_URL ) ) {
			return false;
		}

		return true;
	}

	/**
	 * Handle the discovery endpoint request.
	 *
	 * Fetches the OpenID Provider Configuration document from the
	 * well-known endpoint and returns it as JSON.
	 *
	 * @param WP_REST_Request $request The REST request.
	 * @return WP_REST_Response|WP_Error The discovery document or error.
	 */
	public function discover( WP_REST_Request $request ): WP_REST_Response|WP_Error {
		$discovery_url = $request->get_param( 'discovery_url' );

		// SECURITY: Validate URL to prevent SSRF attacks
		$ssrf_validation = $this->validate_discovery_url_ssrf( $discovery_url );
		if ( is_wp_error( $ssrf_validation ) ) {
			return $ssrf_validation;
		}

		// Append well-known path if not already present
		if ( strpos( $discovery_url, '.well-known/openid-configuration' ) === false ) {
			$discovery_url = rtrim( $discovery_url, '/' ) . '/.well-known/openid-configuration';
		}

		$response = wp_remote_get( $discovery_url, array( 'timeout' => 30 ) );

		if ( is_wp_error( $response ) ) {
			return new WP_Error(
				'discovery_request_failed',
				$response->get_error_message(),
				array( 'status' => 502 )
			);
		}

		$status_code = wp_remote_retrieve_response_code( $response );

		if ( 200 !== $status_code ) {
			return new WP_Error(
				'discovery_failed',
				__( 'Failed to fetch discovery document.', 'secure-oidc-login' ),
				array( 'status' => 502 )
			);
		}

		$body = wp_remote_retrieve_body( $response );

		// Try to parse JSON - some providers (like Microsoft) return JSON with incorrect Content-Type
		$config = json_decode( $body, true );

		if ( null === $config || ! is_array( $config ) ) {
			// Check content-type to provide a more helpful error message
			$content_type = wp_remote_retrieve_header( $response, 'content-type' );
			if ( is_array( $content_type ) ) {
				$content_type = $content_type[0] ?? '';
			}
			$content_type = (string) $content_type;

			if ( stripos( $content_type, 'text/html' ) !== false ) {
				return new WP_Error(
					'invalid_content_type',
					__( 'Discovery response was HTML, not JSON. Please verify the identity provider URL.', 'secure-oidc-login' ),
					array( 'status' => 502 )
				);
			}

			return new WP_Error(
				'invalid_json',
				__( 'Invalid discovery response. Could not parse as JSON.', 'secure-oidc-login' ),
				array( 'status' => 502 )
			);
		}

		return new WP_REST_Response( $config, 200 );
	}

	/**
	 * Validate a discovery URL for SSRF protection.
	 *
	 * SECURITY: Prevents Server-Side Request Forgery (SSRF) attacks by:
	 * - Blocking requests to internal/private IP addresses (unless overridden)
	 * - Requiring HTTPS connections (unless overridden)
	 *
	 * Environment variables for intranet deployments:
	 * - SECURE_OIDC_ALLOW_LOCAL_DISCOVERY_URLS=true - Allow internal IPs
	 * - SECURE_OIDC_ALLOW_INSECURE_DISCOVERY=true - Allow HTTP connections
	 *
	 * @since 0.6.0
	 *
	 * @param string $url The URL to validate.
	 * @return true|WP_Error True if valid, WP_Error with message if invalid.
	 */
	private function validate_discovery_url_ssrf( string $url ): bool|WP_Error {
		$parsed = wp_parse_url( $url );

		if ( ! $parsed || empty( $parsed['host'] ) ) {
			return new WP_Error(
				'invalid_url',
				__( 'Invalid discovery URL format.', 'secure-oidc-login' ),
				array( 'status' => 400 )
			);
		}

		$scheme = strtolower( $parsed['scheme'] ?? '' );
		$host   = $parsed['host'];

		// Check HTTPS requirement
		$allow_insecure = getenv( 'SECURE_OIDC_ALLOW_INSECURE_DISCOVERY' );
		if ( 'https' !== $scheme ) {
			if ( false === $allow_insecure || 'true' !== strtolower( (string) $allow_insecure ) ) {
				return new WP_Error(
					'https_required',
					__( 'Discovery URL must use HTTPS. Set SECURE_OIDC_ALLOW_INSECURE_DISCOVERY=true to allow HTTP for testing.', 'secure-oidc-login' ),
					array( 'status' => 400 )
				);
			}
		}

		// Check for local/internal IP addresses
		$allow_local = getenv( 'SECURE_OIDC_ALLOW_LOCAL_DISCOVERY_URLS' );
		if ( false === $allow_local || 'true' !== strtolower( (string) $allow_local ) ) {
			// Resolve hostname to IP address for validation
			$ip = gethostbyname( $host );

			// Check if resolution failed (returns original hostname)
			if ( $ip === $host && ! filter_var( $host, FILTER_VALIDATE_IP ) ) {
				// Could not resolve - allow it (let wp_remote_get handle DNS errors)
				return true;
			}

			// Validate the IP is not private or reserved
			if ( ! filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) ) {
				return new WP_Error(
					'local_url_blocked',
					__( 'Discovery URL points to a local or private IP address. Set SECURE_OIDC_ALLOW_LOCAL_DISCOVERY_URLS=true for intranet identity providers.', 'secure-oidc-login' ),
					array( 'status' => 400 )
				);
			}

			// Additional check for localhost variations
			$blocked_hosts = array( 'localhost', 'localhost.localdomain', '127.0.0.1', '::1', '0.0.0.0' );
			if ( in_array( strtolower( $host ), $blocked_hosts, true ) ) {
				return new WP_Error(
					'localhost_blocked',
					__( 'Discovery URL cannot point to localhost. Set SECURE_OIDC_ALLOW_LOCAL_DISCOVERY_URLS=true for local testing.', 'secure-oidc-login' ),
					array( 'status' => 400 )
				);
			}
		}

		return true;
	}
}

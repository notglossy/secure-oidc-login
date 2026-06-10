<?php
declare(strict_types=1);
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
	 * Rate limiter instance.
	 *
	 * @var OIDC_Rate_Limiter
	 */
	private $rate_limiter;

	/**
	 * Back-channel logout handler, created lazily for the logout route.
	 *
	 * @var OIDC_Backchannel_Logout|null
	 */
	private ?OIDC_Backchannel_Logout $backchannel_handler;

	/**
	 * Constructor - Initialize rate limiter.
	 *
	 * @param OIDC_Backchannel_Logout|null $backchannel_handler Optional handler override for testing.
	 */
	public function __construct( ?OIDC_Backchannel_Logout $backchannel_handler = null ) {
		$this->rate_limiter        = new OIDC_Rate_Limiter();
		$this->backchannel_handler = $backchannel_handler;
	}

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

		register_rest_route(
			$this->namespace,
			'/backchannel-logout',
			array(
				'methods'             => WP_REST_Server::CREATABLE,
				'callback'            => array( $this, 'backchannel_logout' ),
				// SECURITY: This endpoint is called server-to-server by the IdP, not by a
				// logged-in browser, so there is no WordPress authentication context. The
				// request is authenticated by the signed logout token itself (signature,
				// iss, aud, events, jti) in OIDC_Client::validate_logout_token().
				'permission_callback' => '__return_true',
				'args'                => array(
					'logout_token' => array(
						'required'    => true,
						'type'        => 'string',
						'description' => __( 'The signed OIDC logout token (JWT).', 'secure-oidc-login' ),
					),
				),
			)
		);
	}

	/**
	 * Handle a back-channel logout request from the IdP.
	 *
	 * Per OIDC Back-Channel Logout 1.0 Section 2.8: 200 on success, 400 for an
	 * invalid request, both with Cache-Control: no-store.
	 *
	 * @param WP_REST_Request<array<string, mixed>> $request The REST request.
	 * @return WP_REST_Response The logout response.
	 */
	public function backchannel_logout( WP_REST_Request $request ): WP_REST_Response {
		// SECURITY: Rate limit to blunt brute-force attempts against token validation.
		// 400 (not 429) keeps the response within the status codes defined by OIDC
		// Back-Channel Logout 1.0 Section 2.8, which strictly conforming IdPs expect.
		if ( $this->rate_limiter->is_rate_limited( 'backchannel_logout' ) ) {
			return $this->backchannel_response( array( 'error' => 'invalid_request' ), 400 );
		}
		$this->rate_limiter->record_attempt( 'backchannel_logout' );

		// The SECURE_OIDC_ENABLE_BACKCHANNEL_LOGOUT environment variable overrides the
		// stored setting, matching how the admin UI presents env-managed checkboxes
		// (same true/false convention as SECURE_OIDC_ENFORCE_ACR).
		$options = get_option( 'secure_oidc_login_settings', array() );
		$enabled = ! empty( $options['enable_backchannel_logout'] );

		$env_enabled = getenv( 'SECURE_OIDC_ENABLE_BACKCHANNEL_LOGOUT' );
		if ( false !== $env_enabled && '' !== $env_enabled ) {
			$enabled = 'true' === strtolower( (string) $env_enabled );
		}

		if ( ! $enabled ) {
			// Feature disabled: respond 400 rather than 404 to avoid signaling
			// whether the plugin is installed vs. merely unconfigured.
			return $this->backchannel_response( array( 'error' => 'invalid_request' ), 400 );
		}

		$logout_token = $request->get_param( 'logout_token' );
		if ( ! is_string( $logout_token ) || '' === $logout_token ) {
			return $this->backchannel_response( array( 'error' => 'invalid_request' ), 400 );
		}

		$result = $this->get_backchannel_handler()->handle_logout_token( $logout_token );

		if ( is_wp_error( $result ) ) {
			return $this->backchannel_response( array( 'error' => 'invalid_request' ), 400 );
		}

		// Successful logout (or validly-signed token with nothing to log out).
		return $this->backchannel_response( null, 200 );
	}

	/**
	 * Build a back-channel logout response with the spec-required cache headers.
	 *
	 * @param array<string, string>|null $body   Response body, or null for an empty body.
	 * @param int                        $status HTTP status code.
	 * @return WP_REST_Response The response object.
	 */
	private function backchannel_response( ?array $body, int $status ): WP_REST_Response {
		$response = new WP_REST_Response( $body, $status );
		// Section 2.8: the RP's response MUST include Cache-Control: no-store.
		$response->header( 'Cache-Control', 'no-store' );
		return $response;
	}

	/**
	 * Get the back-channel logout handler, creating it on first use.
	 *
	 * @return OIDC_Backchannel_Logout The handler instance.
	 */
	private function get_backchannel_handler(): OIDC_Backchannel_Logout {
		if ( null === $this->backchannel_handler ) {
			$this->backchannel_handler = new OIDC_Backchannel_Logout( new OIDC_Client(), new OIDC_Token_Manager() );
		}
		return $this->backchannel_handler;
	}

	/**
	 * Check if the current user has permission to perform discovery.
	 *
	 * @param WP_REST_Request<array<string, mixed>> $request The REST request.
	 * @return bool|WP_Error True if allowed, WP_Error otherwise.
	 */
	public function discover_permissions_check( WP_REST_Request $request ): bool|WP_Error {
		if ( ! current_user_can( 'manage_options' ) ) {
			// SECURITY: Log unauthorized API access attempts for security auditing
			$current_user = wp_get_current_user();
			$raw_ip       = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : 'unknown';
			$log_msg      = sprintf(
				'Unauthorized OIDC discovery API access attempt (user_id: %d, user_login: %s, ip: %s)',
				$current_user->ID,
				$current_user->user_login ? $current_user->user_login : 'anonymous',
				OIDC_Rate_Limiter::mask_ip( $raw_ip )
			);
			error_log( '[Secure OIDC Login] ' . $log_msg );

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
	 * @param mixed                                  $value   The URL value.
	 * @param WP_REST_Request<array<string, mixed>> $request The REST request.
	 * @param string                                 $param   The parameter name.
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
	 * SECURITY: Uses wp_safe_remote_get() which provides built-in SSRF protection
	 * via wp_http_validate_url(). This blocks:
	 * - Private/local IP addresses (192.168.x.x, 10.x.x.x, 127.0.0.1, etc.)
	 * - Non-standard ports (only 80, 443, 8080 allowed)
	 * - URLs with embedded credentials
	 * - Invalid/malformed URLs
	 *
	 * For intranet IdPs, use the http_request_host_is_external filter.
	 *
	 * @param WP_REST_Request<array<string, mixed>> $request The REST request.
	 * @return WP_REST_Response|WP_Error The discovery document or error.
	 */
	public function discover( WP_REST_Request $request ): WP_REST_Response|WP_Error {
		// SECURITY: Check rate limit to prevent discovery endpoint abuse
		if ( $this->rate_limiter->is_rate_limited( 'discovery' ) ) {
			$expiry = $this->rate_limiter->get_lockout_expiry( 'discovery' );
			if ( false !== $expiry ) {
				$wait_time = $expiry - time();
				$error_msg = sprintf(
					/* translators: %d: number of seconds */
					__( 'Too many discovery requests. Please wait %d seconds before trying again.', 'secure-oidc-login' ),
					$wait_time
				);
			} else {
				$error_msg = __( 'Too many discovery requests. Please try again later.', 'secure-oidc-login' );
			}

			return new WP_Error(
				'rate_limit_exceeded',
				$error_msg,
				array( 'status' => 429 )
			);
		}

		// Record this discovery attempt
		$this->rate_limiter->record_attempt( 'discovery' );

		$discovery_url = $request->get_param( 'discovery_url' );

		// Append well-known path if not already present
		if ( strpos( $discovery_url, '.well-known/openid-configuration' ) === false ) {
			$discovery_url = rtrim( $discovery_url, '/' ) . '/.well-known/openid-configuration';
		}

		// SECURITY: Validate URL before making request
		// This provides early feedback with a clear error message
		$validation_result = $this->validate_discovery_url_ssrf( $discovery_url );
		if ( is_wp_error( $validation_result ) ) {
			return $validation_result;
		}

		// SECURITY: Use wp_safe_remote_get() for SSRF protection
		// This function validates URLs via wp_http_validate_url() and blocks:
		// - Private/reserved IP addresses
		// - Non-standard ports (only 80, 443, 8080 allowed)
		// - URLs with embedded credentials
		// It also validates redirect destinations to prevent redirect-based SSRF
		$response = wp_safe_remote_get( $discovery_url, array( 'timeout' => 30 ) );

		if ( is_wp_error( $response ) ) {
			// Provide user-friendly error messages for common SSRF blocks
			$error_code = $response->get_error_code();
			if ( 'http_request_not_executed' === $error_code ) {
				return new WP_Error(
					'ssrf_blocked',
					__( 'Discovery URL was blocked for security reasons. Ensure the URL uses HTTPS, points to a public IP address, and uses a standard port (80, 443, or 8080).', 'secure-oidc-login' ),
					array( 'status' => 400 )
				);
			}

			return new WP_Error(
				'discovery_request_failed',
				$response->get_error_message(),
				array( 'status' => 502 )
			);
		}

		$status_code = (int) wp_remote_retrieve_response_code( $response );

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

		// SECURITY: Verify the document's issuer matches the discovery URL (OIDC Discovery
		// 1.0 Section 4.3) and that all advertised endpoints use HTTPS, before the
		// configuration is offered to the admin form.
		$validation = OIDC_Client::validate_discovery_document( $config, $discovery_url );
		if ( is_wp_error( $validation ) ) {
			return new WP_Error(
				$validation->get_error_code(),
				$validation->get_error_message(),
				array( 'status' => 400 )
			);
		}

		return new WP_REST_Response( $config, 200 );
	}

	/**
	 * Pre-validate a discovery URL for SSRF protection with clear error messages.
	 *
	 * SECURITY: This provides early validation with user-friendly error messages
	 * before wp_safe_remote_get() performs its validation. While wp_safe_remote_get()
	 * provides the actual SSRF protection, this method gives clearer feedback.
	 *
	 * For intranet identity providers, administrators can use WordPress filters:
	 * - http_request_host_is_external: Allow specific internal hosts
	 * - http_allowed_safe_ports: Allow additional ports
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

		// Check HTTPS requirement (can be bypassed with SECURE_OIDC_ALLOW_INSECURE_DISCOVERY for testing)
		$allow_insecure = getenv( 'SECURE_OIDC_ALLOW_INSECURE_DISCOVERY' );
		if ( 'https' !== $scheme && 'http' !== $scheme ) {
			return new WP_Error(
				'invalid_scheme',
				__( 'Discovery URL must use HTTP or HTTPS.', 'secure-oidc-login' ),
				array( 'status' => 400 )
			);
		}

		if ( 'https' !== $scheme ) {
			if ( false === $allow_insecure || 'true' !== strtolower( (string) $allow_insecure ) ) {
				return new WP_Error(
					'https_required',
					__( 'Discovery URL must use HTTPS. Set SECURE_OIDC_ALLOW_INSECURE_DISCOVERY=true to allow HTTP for testing.', 'secure-oidc-login' ),
					array( 'status' => 400 )
				);
			}
		}

		// Check for obviously blocked hosts with clear messages
		$blocked_hosts = array( 'localhost', 'localhost.localdomain' );
		if ( in_array( strtolower( $host ), $blocked_hosts, true ) ) {
			return new WP_Error(
				'localhost_blocked',
				__( 'Discovery URL cannot point to localhost. For intranet IdPs, use the http_request_host_is_external filter.', 'secure-oidc-login' ),
				array( 'status' => 400 )
			);
		}

		// Use WordPress's built-in URL validation for comprehensive checks
		// This validates against private IPs, ports, and other SSRF vectors
		$validated_url = wp_http_validate_url( $url );
		if ( false === $validated_url ) {
			return new WP_Error(
				'url_validation_failed',
				__( 'Discovery URL failed security validation. Ensure it uses a public IP address and standard port (80, 443, or 8080). For intranet IdPs, use the http_request_host_is_external filter.', 'secure-oidc-login' ),
				array( 'status' => 400 )
			);
		}

		return true;
	}
}

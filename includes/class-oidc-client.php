<?php
/**
 * OIDC Client class for handling OAuth/OIDC protocol operations.
 *
 * @package Secure_OIDC_Login
 * @since 0.1.0
 */

// Prevent direct file access
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use Firebase\JWT\JWT;
use Firebase\JWT\JWK;
use Firebase\JWT\Key;

/**
 * Handles communication with the OIDC identity provider.
 *
 * Implements the OAuth 2.0 / OpenID Connect protocol operations including
 * token exchange, ID token validation, userinfo retrieval, and token refresh.
 */
class OIDC_Client {
	/** @var array<string, mixed> Plugin settings from WordPress options */
	private $options;

	/**
	 * JWKS cache duration in seconds (15 minutes).
	 *
	 * SECURITY: Short cache duration minimizes the window of opportunity for JWKS
	 * cache poisoning attacks. If an attacker can manipulate the cached JWKS,
	 * they could inject their own signing keys and forge valid-looking ID tokens.
	 * The HMAC integrity check (see get_jwks() and verify_jwks_integrity()) prevents
	 * cache tampering, but a short TTL provides defense-in-depth.
	 *
	 * @var int
	 */
	const JWKS_CACHE_DURATION = 900;

	/**
	 * Initialize the client with plugin settings.
	 */
	public function __construct() {
		$this->options = get_option( 'secure_oidc_login_settings', array() );
	}

	/**
	 * Get a setting value with environment variable support.
	 *
	 * @param string $key The setting key to retrieve.
	 * @return string The setting value.
	 */
	private function get_setting( $key ) {
		return Secure_OIDC_Login::get_setting( $key, $this->options );
	}

	/**
	 * Centralized error handling to prevent information disclosure.
	 *
	 * Logs detailed error information for debugging while returning generic
	 * messages to users to prevent leaking sensitive system information.
	 *
	 * @param string $context       Error context (e.g., 'token_exchange', 'userinfo').
	 * @param string $detailed_error Detailed error message for logging.
	 * @param string $generic_message Generic user-facing error message.
	 * @return WP_Error WordPress error object with sanitized message.
	 */
	private function handle_error( $context, $detailed_error, $generic_message ) {
		// Log detailed error for debugging (sanitize for log safety)
		$log_message = sprintf(
			'OIDC Error [%s]: %s',
			$context,
			$detailed_error
		);
		error_log( $log_message );

		// If WP_DEBUG is enabled, provide more context (but not full internal details)
		if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
			$debug_message = sprintf(
				/* translators: 1: Generic error message, 2: Error context */
				__( '%1$s (Context: %2$s)', 'secure-oidc-login' ),
				$generic_message,
				$context
			);
			return new WP_Error( 'oidc_error', $debug_message );
		}

		// Return generic error to users in production
		return new WP_Error( 'oidc_error', $generic_message );
	}

	/**
	 * Exchange an authorization code for access and ID tokens.
	 *
	 * Performs the token endpoint request as part of the authorization code flow.
	 * Supports both confidential clients (with client_secret) and public clients (with PKCE).
	 *
	 * @param string      $code          The authorization code from the IdP.
	 * @param string|null $code_verifier The PKCE code verifier (optional).
	 * @return array<string, mixed>|WP_Error Token response array or error.
	 */
	public function exchange_code( $code, $code_verifier = null ) {
		$token_endpoint = $this->get_setting( 'token_endpoint' );

		if ( empty( $token_endpoint ) ) {
			return new WP_Error( 'oidc_error', __( 'Token endpoint not configured.', 'secure-oidc-login' ) );
		}

		// Get client credentials (check env vars first)
		$client_id     = $this->get_setting( 'client_id' );
		$client_secret = $this->get_setting( 'client_secret' );

		$token_params = array(
			'grant_type'   => 'authorization_code',
			'code'         => $code,
			'redirect_uri' => $this->get_callback_url(),
			'client_id'    => $client_id,
		);

		$headers = array(
			'Content-Type' => 'application/x-www-form-urlencoded',
		);

		// Confidential clients use HTTP Basic auth per RFC 6749 section 2.3.1
		// This is the recommended authentication method for confidential clients
		// as it keeps credentials in headers rather than the request body
		if ( ! empty( $client_secret ) ) {
			$credentials              = $client_id . ':' . $client_secret;
			$headers['Authorization'] = 'Basic ' . base64_encode( $credentials );
		}

		// Public clients use PKCE for security (no client_secret available)
		if ( ! empty( $code_verifier ) ) {
			$token_params['code_verifier'] = $code_verifier;
		}

		$response = wp_remote_post(
			$token_endpoint,
			array(
				'body'    => $token_params,
				'headers' => $headers,
				'timeout' => 30,
			)
		);

		if ( is_wp_error( $response ) ) {
			return $this->handle_error(
				'token_exchange',
				'Failed to connect to token endpoint: ' . $response->get_error_message(),
				__( 'Authentication failed. Please try again.', 'secure-oidc-login' )
			);
		}

		$status_code = wp_remote_retrieve_response_code( $response );
		$body        = wp_remote_retrieve_body( $response );
		$tokens      = json_decode( $body, true );

		if ( $status_code !== 200 ) {
			// Log detailed IdP error but show generic message to users
			$detailed_error = sprintf(
				'Token exchange failed with status %d. IdP error: %s - %s',
				$status_code,
				isset( $tokens['error'] ) ? $tokens['error'] : 'unknown',
				isset( $tokens['error_description'] ) ? $tokens['error_description'] : 'no description'
			);
			return $this->handle_error(
				'token_exchange',
				$detailed_error,
				__( 'Authentication failed. Please try again.', 'secure-oidc-login' )
			);
		}

		if ( empty( $tokens['access_token'] ) || empty( $tokens['id_token'] ) ) {
			return new WP_Error( 'oidc_error', __( 'Invalid token response.', 'secure-oidc-login' ) );
		}

		// Validate token_type (RFC 6749 section 5.1)
		if ( ! empty( $tokens['token_type'] ) && 'Bearer' !== $tokens['token_type'] ) {
			return new WP_Error(
				'oidc_error',
				sprintf(
					/* translators: %s: token type returned by IdP */
					__( 'Unsupported token type: %s. Only Bearer tokens are supported.', 'secure-oidc-login' ),
					$tokens['token_type']
				)
			);
		}

		return $tokens;
	}

	/**
	 * Validate an ID token and extract its claims.
	 *
	 * Performs full JWT validation including signature verification, issuer,
	 * audience, and expiration checks per OIDC Core spec.
	 *
	 * @param string $id_token The JWT ID token from the IdP.
	 * @param string|null $expected_nonce Expected nonce value for validation.
	 * @param string|null $auth_code Authorization code for c_hash validation.
	 * @return array<string, mixed>|WP_Error Decoded claims array or error.
	 */
	public function validate_id_token( $id_token, $expected_nonce = null, $auth_code = null ) {
		// Decode and verify JWT using Firebase JWT library
		$claims = $this->decode_and_verify_jwt( $id_token );
		if ( is_wp_error( $claims ) ) {
			return $claims;
		}

		// Verify required 'sub' claim is present (OIDC Core spec 2.2)
		if ( empty( $claims['sub'] ) ) {
			return new WP_Error( 'oidc_error', __( 'Missing required sub claim in ID token.', 'secure-oidc-login' ) );
		}

		// Verify the token was issued by the expected IdP
		$issuer = $this->get_setting( 'issuer' );
		if ( ! empty( $issuer ) && $claims['iss'] !== $issuer ) {
			return new WP_Error( 'oidc_error', __( 'Invalid token issuer.', 'secure-oidc-login' ) );
		}

		// Verify the token was issued for this client
		$client_id = $this->get_setting( 'client_id' );
		$aud       = is_array( $claims['aud'] ) ? $claims['aud'] : array( $claims['aud'] );
		if ( ! in_array( $client_id, $aud, true ) ) {
			return new WP_Error( 'oidc_error', __( 'Invalid token audience.', 'secure-oidc-login' ) );
		}

		// If multiple audiences, verify azp claim matches client_id (OIDC Core spec 3.1.3.7)
		if ( count( $aud ) > 1 ) {
			if ( empty( $claims['azp'] ) || $claims['azp'] !== $client_id ) {
				return new WP_Error( 'oidc_error', __( 'Invalid or missing azp claim for multi-audience token.', 'secure-oidc-login' ) );
			}
		}

		// Validate nonce to prevent replay attacks (OIDC Core spec 3.1.3.7)
		if ( null !== $expected_nonce ) {
			if ( ! isset( $claims['nonce'] ) ) {
				return new WP_Error( 'missing_nonce', 'ID token missing required nonce claim' );
			}
			if ( $claims['nonce'] !== $expected_nonce ) {
				return new WP_Error( 'invalid_nonce', 'ID token nonce does not match expected value' );
			}
		}

		// SECURITY: Validate c_hash (authorization code hash) for hybrid flows per OIDC Core 3.3.2.11
		// The c_hash claim prevents token substitution attacks in hybrid flows. If an attacker
		// intercepts an ID token from a different authorization code exchange, the c_hash will
		// not match, preventing the token from being accepted. This binds the ID token to the
		// specific authorization code used in this exchange.
		if ( null !== $auth_code && isset( $claims['c_hash'] ) ) {
			// Per spec: c_hash is left-most half of SHA-256 hash, base64url encoded
			$computed_hash = rtrim( strtr( base64_encode( substr( hash( 'sha256', $auth_code, true ), 0, 16 ) ), '+/', '-_' ), '=' );
			if ( $claims['c_hash'] !== $computed_hash ) {
				return new WP_Error( 'invalid_c_hash', 'ID token c_hash does not match authorization code' );
			}
		}

		return $claims;
	}

	/**
	 * Decode and verify a JWT using Firebase JWT library.
	 *
	 * Performs signature verification, expiration validation, and decoding.
	 * Includes retry logic for key rotation scenarios.
	 *
	 * @param string $jwt   The complete JWT string.
	 * @param bool   $retry Internal flag to prevent infinite retry loop.
	 * @return array<string, mixed>|WP_Error Decoded claims array or error.
	 */
	private function decode_and_verify_jwt( $jwt, $retry = true ) {
		// Get JWKS from IdP
		$jwks = $this->get_jwks();
		if ( is_wp_error( $jwks ) ) {
			return $jwks;
		}

		// Extract algorithm from JWT header to handle IdP compatibility
		$tks = explode( '.', $jwt );
		if ( count( $tks ) !== 3 ) {
			return new WP_Error( 'oidc_error', __( 'Invalid JWT format.', 'secure-oidc-login' ) );
		}

		$header_encoded = $tks[0];
		$header         = json_decode( JWT::urlsafeB64Decode( $header_encoded ), true );
		// Default to RS256 (asymmetric) if algorithm not specified - most common for OIDC
		$alg            = isset( $header['alg'] ) ? $header['alg'] : 'RS256';

		// IdP compatibility: Some identity providers omit the "alg" field in their JWKS keys
		// The Firebase JWT library requires it, so we add it based on the JWT header if missing
		if ( isset( $jwks['keys'] ) && is_array( $jwks['keys'] ) ) {
			foreach ( $jwks['keys'] as &$key ) {
				if ( ! isset( $key['alg'] ) ) {
					$key['alg'] = $alg;
				}
			}
			unset( $key ); // Break reference to avoid unexpected behavior
		}

		try {
			// Convert JWKS to Key objects using Firebase JWT library
			$keys = JWK::parseKeySet( $jwks );

			// Decode and verify JWT (automatically validates signature, exp, nbf, iat)
			JWT::$leeway = 300; // 5 minutes clock skew tolerance
			$decoded     = JWT::decode( $jwt, $keys );

			// Convert stdClass to array for consistency with existing code
			return json_decode( json_encode( $decoded ), true );

		} catch ( \Firebase\JWT\SignatureInvalidException $e ) {
			// Signature verification failed - could be due to IdP key rotation
			// Key rotation scenario: IdP generates new signing keys and signs tokens with the new key,
			// but our cached JWKS still contains only the old key. Retry once with fresh JWKS to handle this.
			if ( $retry ) {
				$fresh_jwks = $this->get_jwks( true );
				if ( ! is_wp_error( $fresh_jwks ) ) {
					// Retry decode with fresh JWKS (retry=false prevents infinite loop)
					return $this->decode_and_verify_jwt( $jwt, false );
				}
			}
			return new WP_Error( 'oidc_error', __( 'ID token signature verification failed.', 'secure-oidc-login' ) );

		} catch ( \Firebase\JWT\ExpiredException $e ) {
			return new WP_Error( 'oidc_error', __( 'ID token has expired.', 'secure-oidc-login' ) );

		} catch ( \Firebase\JWT\BeforeValidException $e ) {
			return new WP_Error( 'oidc_error', __( 'ID token not yet valid.', 'secure-oidc-login' ) );

		} catch ( \Exception $e ) {
			return $this->handle_error(
				'jwt_decode',
				'Failed to decode ID token: ' . $e->getMessage(),
				__( 'Invalid authentication token. Please try again.', 'secure-oidc-login' )
			);
		}
	}

	/**
	 * Fetch JWKS from the IdP with caching and integrity protection.
	 *
	 * SECURITY: Implements HMAC-based integrity checks to prevent cache poisoning attacks.
	 * Cache poisoning threat model: If an attacker can write to the WordPress database
	 * or object cache, they could replace the cached JWKS with their own signing keys.
	 * This would allow them to forge valid-looking ID tokens and impersonate any user.
	 *
	 * Defense: We store an HMAC signature alongside the cached JWKS. The HMAC uses
	 * WordPress authentication salts (from wp-config.php) as the key, which are not
	 * stored in the database. An attacker with database access cannot forge a valid
	 * HMAC without also compromising the wp-config.php file.
	 *
	 * @param bool $force_refresh Force fetching fresh JWKS, bypassing cache.
	 * @return array<string, mixed>|WP_Error JWKS array or error.
	 */
	private function get_jwks( $force_refresh = false ) {
		$jwks_uri = $this->get_setting( 'jwks_uri' );

		if ( empty( $jwks_uri ) ) {
			return new WP_Error( 'oidc_error', __( 'JWKS URI not configured. Please run discovery or configure manually.', 'secure-oidc-login' ) );
		}

		$cache_key = 'oidc_jwks_' . md5( $jwks_uri );

		// Check cache first (unless force refresh requested)
		if ( ! $force_refresh ) {
			$cached_data = get_transient( $cache_key );
			if ( $cached_data !== false && is_array( $cached_data ) ) {
				// SECURITY: Verify HMAC signature to ensure cache hasn't been tampered with
				if ( $this->verify_jwks_integrity( $cached_data ) ) {
					return $cached_data['jwks'];
				}
				// Cache integrity check failed - delete potentially compromised cache and fetch fresh
				delete_transient( $cache_key );
			}
		}

		// Fetch JWKS from IdP
		$response = wp_remote_get(
			$jwks_uri,
			array(
				'timeout' => 30,
			)
		);

		if ( is_wp_error( $response ) ) {
			return $this->handle_error(
				'jwks_fetch',
				'Failed to fetch JWKS: ' . $response->get_error_message(),
				__( 'Authentication configuration error. Please contact the site administrator.', 'secure-oidc-login' )
			);
		}

		$status_code = wp_remote_retrieve_response_code( $response );
		if ( $status_code !== 200 ) {
			return $this->handle_error(
				'jwks_fetch',
				'Failed to fetch JWKS. HTTP status: ' . $status_code,
				__( 'Authentication configuration error. Please contact the site administrator.', 'secure-oidc-login' )
			);
		}

		$body = wp_remote_retrieve_body( $response );
		$jwks = json_decode( $body, true );

		if ( ! $jwks || ! isset( $jwks['keys'] ) || ! is_array( $jwks['keys'] ) ) {
			return new WP_Error( 'oidc_error', __( 'Invalid JWKS response.', 'secure-oidc-login' ) );
		}

		// Cache the JWKS with integrity protection
		$cache_data = array(
			'jwks' => $jwks,
			'hmac' => $this->generate_jwks_hmac( $jwks ),
		);
		set_transient( $cache_key, $cache_data, self::JWKS_CACHE_DURATION );

		return $jwks;
	}

	/**
	 * Generate HMAC signature for JWKS data.
	 *
	 * SECURITY: Uses WordPress authentication salts from wp-config.php to create
	 * a site-specific, tamper-proof HMAC signature. These salts are not stored in
	 * the database, so an attacker with database access alone cannot forge valid HMACs.
	 *
	 * Threat model: An attacker who compromises the database attempts to inject
	 * malicious JWKS. Without access to wp-config.php, they cannot generate a valid
	 * HMAC signature, so the tampered cache will be detected and rejected.
	 *
	 * @param array<string, mixed> $jwks The JWKS data to sign.
	 * @return string HMAC-SHA256 signature (64 hex characters).
	 */
	private function generate_jwks_hmac( $jwks ) {
		$data = wp_json_encode( $jwks );
		// Concatenate WordPress authentication salts to create HMAC key
		// These constants are defined in wp-config.php and not stored in the database
		$key  = defined( 'SECURE_AUTH_KEY' ) ? SECURE_AUTH_KEY : '';
		$key .= defined( 'SECURE_AUTH_SALT' ) ? SECURE_AUTH_SALT : '';
		return hash_hmac( 'sha256', $data, $key );
	}

	/**
	 * Verify integrity of cached JWKS data.
	 *
	 * SECURITY: Validates that the cached JWKS has not been tampered with by verifying
	 * its HMAC signature. Uses hash_equals() for timing-safe comparison to prevent
	 * timing attacks that could leak signature information.
	 *
	 * @param array<string, mixed> $cached_data Cached data containing 'jwks' and 'hmac'.
	 * @return bool True if integrity check passes, false if tampered or malformed.
	 */
	private function verify_jwks_integrity( $cached_data ) {
		if ( ! isset( $cached_data['jwks'] ) || ! isset( $cached_data['hmac'] ) ) {
			return false;
		}

		$expected_hmac = $this->generate_jwks_hmac( $cached_data['jwks'] );
		// Use hash_equals() for timing-safe comparison (prevents timing attacks)
		return hash_equals( $expected_hmac, $cached_data['hmac'] );
	}

	/**
	 * Retrieve user information from the userinfo endpoint.
	 *
	 * @param string $access_token The access token for authorization.
	 * @return array<string, mixed>|WP_Error User info claims array or error.
	 */
	public function get_userinfo( $access_token ) {
		$userinfo_endpoint = $this->get_setting( 'userinfo_endpoint' );

		if ( empty( $userinfo_endpoint ) ) {
			return array(); // Userinfo endpoint is optional
		}

		$response = wp_remote_get(
			$userinfo_endpoint,
			array(
				'headers' => array(
					'Authorization' => 'Bearer ' . $access_token,
				),
				'timeout' => 30,
			)
		);

		if ( is_wp_error( $response ) ) {
			return $this->handle_error(
				'userinfo',
				'Failed to connect to userinfo endpoint: ' . $response->get_error_message(),
				__( 'Failed to retrieve user information. Please try again.', 'secure-oidc-login' )
			);
		}

		$status_code = wp_remote_retrieve_response_code( $response );
		$body        = wp_remote_retrieve_body( $response );

		if ( $status_code !== 200 ) {
			return $this->handle_error(
				'userinfo',
				'Userinfo request failed with status ' . $status_code,
				__( 'Failed to retrieve user information. Please try again.', 'secure-oidc-login' )
			);
		}

		$userinfo = json_decode( $body, true );

		if ( ! $userinfo ) {
			return new WP_Error( 'oidc_error', __( 'Invalid userinfo response.', 'secure-oidc-login' ) );
		}

		return $userinfo;
	}

	/**
	 * Refresh an access token using a refresh token.
	 *
	 * @param string $refresh_token The refresh token from a previous token response.
	 * @return array<string, mixed>|WP_Error New token response array or error.
	 */
	public function refresh_token( $refresh_token ) {
		$token_endpoint = $this->get_setting( 'token_endpoint' );

		if ( empty( $token_endpoint ) ) {
			return new WP_Error( 'oidc_error', __( 'Token endpoint not configured.', 'secure-oidc-login' ) );
		}

		// Get client credentials (check env vars first)
		$client_id     = $this->get_setting( 'client_id' );
		$client_secret = $this->get_setting( 'client_secret' );

		$token_params = array(
			'grant_type'    => 'refresh_token',
			'refresh_token' => $refresh_token,
			'client_id'     => $client_id,
		);

		$headers = array(
			'Content-Type' => 'application/x-www-form-urlencoded',
		);

		// Confidential clients use HTTP Basic auth per RFC 6749
		if ( ! empty( $client_secret ) ) {
			$credentials              = $client_id . ':' . $client_secret;
			$headers['Authorization'] = 'Basic ' . base64_encode( $credentials );
		}

		$response = wp_remote_post(
			$token_endpoint,
			array(
				'body'    => $token_params,
				'headers' => $headers,
				'timeout' => 30,
			)
		);

		if ( is_wp_error( $response ) ) {
			return $this->handle_error(
				'token_refresh',
				'Failed to connect to token endpoint: ' . $response->get_error_message(),
				__( 'Session refresh failed. Please log in again.', 'secure-oidc-login' )
			);
		}

		$status_code = wp_remote_retrieve_response_code( $response );
		$body        = wp_remote_retrieve_body( $response );
		$tokens      = json_decode( $body, true );

		if ( $status_code !== 200 ) {
			// Log detailed IdP error but show generic message to users
			$detailed_error = sprintf(
				'Token refresh failed with status %d. IdP error: %s - %s',
				$status_code,
				isset( $tokens['error'] ) ? $tokens['error'] : 'unknown',
				isset( $tokens['error_description'] ) ? $tokens['error_description'] : 'no description'
			);
			return $this->handle_error(
				'token_refresh',
				$detailed_error,
				__( 'Session refresh failed. Please log in again.', 'secure-oidc-login' )
			);
		}

		return $tokens;
	}

	/**
	 * Discover OIDC configuration from the well-known endpoint.
	 *
	 * Fetches the OpenID Provider Configuration document which contains
	 * all the endpoint URLs and supported features of the IdP.
	 *
	 * @param string $issuer_url The base URL of the identity provider.
	 * @return array<string, mixed>|WP_Error Configuration array or error.
	 */
	public function discover( $issuer_url ) {
		$discovery_url = rtrim( $issuer_url, '/' ) . '/.well-known/openid-configuration';

		$response = wp_remote_get(
			$discovery_url,
			array(
				'timeout' => 30,
			)
		);

		if ( is_wp_error( $response ) ) {
			return $response;
		}

		$status_code = wp_remote_retrieve_response_code( $response );
		$body        = wp_remote_retrieve_body( $response );

		if ( $status_code !== 200 ) {
			return new WP_Error( 'oidc_error', __( 'Failed to discover OIDC configuration.', 'secure-oidc-login' ) );
		}

		$config = json_decode( $body, true );

		if ( ! $config ) {
			return new WP_Error( 'oidc_error', __( 'Invalid discovery response.', 'secure-oidc-login' ) );
		}

		return $config;
	}

	/**
	 * Get the OIDC callback URL for this site.
	 *
	 * @return string The callback URL.
	 */
	private function get_callback_url() {
		return add_query_arg( 'oidc_callback', '1', home_url( '/' ) );
	}
}

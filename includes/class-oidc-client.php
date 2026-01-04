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

	/** @var int JWKS cache duration in seconds (15 minutes to minimize cache poisoning window) */
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

		// Confidential clients use HTTP Basic auth per RFC 6749
		if ( ! empty( $client_secret ) ) {
			$credentials              = $client_id . ':' . $client_secret;
			$headers['Authorization'] = 'Basic ' . base64_encode( $credentials );
		}

		// Public clients use PKCE for security
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
			return new WP_Error( 'oidc_error', __( 'Failed to connect to token endpoint: ', 'secure-oidc-login' ) . $response->get_error_message() );
		}

		$status_code = wp_remote_retrieve_response_code( $response );
		$body        = wp_remote_retrieve_body( $response );
		$tokens      = json_decode( $body, true );

		if ( $status_code !== 200 ) {
			$error_message = isset( $tokens['error_description'] ) ? $tokens['error_description'] : ( isset( $tokens['error'] ) ? $tokens['error'] : __( 'Token exchange failed.', 'secure-oidc-login' ) );
			return new WP_Error( 'oidc_error', $error_message );
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

		// Validate c_hash for hybrid flows
		if ( null !== $auth_code && isset( $claims['c_hash'] ) ) {
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

		// Get algorithm from JWT header
		$tks = explode( '.', $jwt );
		if ( count( $tks ) !== 3 ) {
			return new WP_Error( 'oidc_error', __( 'Invalid JWT format.', 'secure-oidc-login' ) );
		}

		$header_encoded = $tks[0];
		$header         = json_decode( JWT::urlsafeB64Decode( $header_encoded ), true );
		$alg            = isset( $header['alg'] ) ? $header['alg'] : 'RS256'; // Default to RS256 for OIDC

		// Add "alg" parameter to keys if missing (some IdPs don't include it)
		if ( isset( $jwks['keys'] ) && is_array( $jwks['keys'] ) ) {
			foreach ( $jwks['keys'] as &$key ) {
				if ( ! isset( $key['alg'] ) ) {
					$key['alg'] = $alg;
				}
			}
			unset( $key ); // Break reference
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
			// Signature verification failed - retry once with fresh JWKS (handles key rotation)
			if ( $retry ) {
				$fresh_jwks = $this->get_jwks( true );
				if ( ! is_wp_error( $fresh_jwks ) ) {
					return $this->decode_and_verify_jwt( $jwt, false );
				}
			}
			return new WP_Error( 'oidc_error', __( 'ID token signature verification failed.', 'secure-oidc-login' ) );

		} catch ( \Firebase\JWT\ExpiredException $e ) {
			return new WP_Error( 'oidc_error', __( 'ID token has expired.', 'secure-oidc-login' ) );

		} catch ( \Firebase\JWT\BeforeValidException $e ) {
			return new WP_Error( 'oidc_error', __( 'ID token not yet valid.', 'secure-oidc-login' ) );

		} catch ( \Exception $e ) {
			return new WP_Error( 'oidc_error', __( 'Failed to decode ID token: ', 'secure-oidc-login' ) . $e->getMessage() );
		}
	}

	/**
	 * Fetch JWKS from the IdP with caching and integrity protection.
	 *
	 * Implements HMAC-based integrity checks to prevent cache poisoning attacks.
	 * Uses WordPress authentication salts to generate tamper-proof signatures.
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

		// Check cache first
		if ( ! $force_refresh ) {
			$cached_data = get_transient( $cache_key );
			if ( $cached_data !== false && is_array( $cached_data ) ) {
				// Verify integrity of cached data
				if ( $this->verify_jwks_integrity( $cached_data ) ) {
					return $cached_data['jwks'];
				}
				// Cache integrity check failed - delete compromised cache
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
			return new WP_Error( 'oidc_error', __( 'Failed to fetch JWKS: ', 'secure-oidc-login' ) . $response->get_error_message() );
		}

		$status_code = wp_remote_retrieve_response_code( $response );
		if ( $status_code !== 200 ) {
			return new WP_Error( 'oidc_error', __( 'Failed to fetch JWKS. HTTP status: ', 'secure-oidc-login' ) . $status_code );
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
	 * Uses WordPress authentication salts from wp-config.php to create
	 * a site-specific, tamper-proof HMAC signature.
	 *
	 * @param array<string, mixed> $jwks The JWKS data to sign.
	 * @return string HMAC signature.
	 */
	private function generate_jwks_hmac( $jwks ) {
		$data = wp_json_encode( $jwks );
		// Use WordPress salts to create a site-specific HMAC key
		$key  = defined( 'SECURE_AUTH_KEY' ) ? SECURE_AUTH_KEY : '';
		$key .= defined( 'SECURE_AUTH_SALT' ) ? SECURE_AUTH_SALT : '';
		return hash_hmac( 'sha256', $data, $key );
	}

	/**
	 * Verify integrity of cached JWKS data.
	 *
	 * Validates that the cached JWKS has not been tampered with by verifying
	 * its HMAC signature against the stored data.
	 *
	 * @param array<string, mixed> $cached_data Cached data containing 'jwks' and 'hmac'.
	 * @return bool True if integrity check passes, false otherwise.
	 */
	private function verify_jwks_integrity( $cached_data ) {
		if ( ! isset( $cached_data['jwks'] ) || ! isset( $cached_data['hmac'] ) ) {
			return false;
		}

		$expected_hmac = $this->generate_jwks_hmac( $cached_data['jwks'] );
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
			return new WP_Error( 'oidc_error', __( 'Failed to connect to userinfo endpoint: ', 'secure-oidc-login' ) . $response->get_error_message() );
		}

		$status_code = wp_remote_retrieve_response_code( $response );
		$body        = wp_remote_retrieve_body( $response );

		if ( $status_code !== 200 ) {
			return new WP_Error( 'oidc_error', __( 'Failed to retrieve user info.', 'secure-oidc-login' ) );
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
			return $response;
		}

		$status_code = wp_remote_retrieve_response_code( $response );
		$body        = wp_remote_retrieve_body( $response );
		$tokens      = json_decode( $body, true );

		if ( $status_code !== 200 ) {
			$error_message = isset( $tokens['error_description'] ) ? $tokens['error_description'] : __( 'Token refresh failed.', 'secure-oidc-login' );
			return new WP_Error( 'oidc_error', $error_message );
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

<?php
declare(strict_types=1);
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
	private array $options;

	/**
	 * Flag to prevent logging weak salt warnings multiple times per request.
	 *
	 * @var bool
	 */
	private static bool $has_logged_salt_warning = false;

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
	 * Allowed JWT signing algorithms (asymmetric only).
	 *
	 * SECURITY: Only asymmetric algorithms are permitted for OIDC ID token verification.
	 * Symmetric algorithms (HS256, HS384, HS512) are excluded to prevent algorithm
	 * confusion attacks where an attacker sets alg=HS256 and uses the public key as
	 * the HMAC secret. The 'none' algorithm is also excluded.
	 *
	 * @var array<int, string>
	 */
	const ALLOWED_JWT_ALGORITHMS = array(
		'RS256',
		'RS384',
		'RS512',
		'ES256',
		'ES384',
		'ES512',
		'PS256',
		'PS384',
		'PS512',
		'EdDSA',
	);

	/**
	 * Mapping from JWK key type (kty) to default signing algorithm.
	 *
	 * Used to infer a safe algorithm for JWKS keys that lack an 'alg' field,
	 * rather than trusting the attacker-controlled JWT header.
	 *
	 * @var array<string, string>
	 */
	const KTY_DEFAULT_ALGORITHM = array(
		'RSA' => 'RS256',
		'EC'  => 'ES256',
		'OKP' => 'EdDSA',
	);

	/**
	 * Get the hash algorithm and left-half byte count for a JWT signing algorithm.
	 *
	 * Per OIDC Core Section 3.3.2.11, the hash used for at_hash and c_hash must
	 * correspond to the alg header parameter of the ID token's JOSE header:
	 *   - *256 algorithms → SHA-256, left 128 bits (16 bytes)
	 *   - *384 algorithms → SHA-384, left 192 bits (24 bytes)
	 *   - *512 algorithms → SHA-512, left 256 bits (32 bytes)
	 *
	 * @param string $alg The JWT signing algorithm (e.g., 'RS256', 'ES384', 'PS512', 'EdDSA').
	 * @return array{0: string, 1: int} Array of [hash_algorithm, left_half_bytes].
	 */
	private static function get_hash_params_for_alg( string $alg ): array {
		if ( preg_match( '/(\d{3})$/', $alg, $matches ) ) {
			$bits = (int) $matches[1];
		} elseif ( 'EdDSA' === $alg ) {
			$bits = 512; // Ed25519 uses SHA-512 internally
		} else {
			$bits = 256; // Safe default
		}

		return match ( $bits ) {
			384 => array( 'sha384', 24 ),
			512 => array( 'sha512', 32 ),
			default => array( 'sha256', 16 ),
		};
	}

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
	private function get_setting( $key ): string {
		return Secure_OIDC_Login::get_setting( $key, $this->options );
	}

	/**
	 * Centralized error handling to prevent information disclosure.
	 *
	 * Logs detailed error information for debugging while returning generic
	 * messages to users to prevent leaking sensitive system information.
	 *
	 * SECURITY: Always returns generic user-facing messages regardless of WP_DEBUG.
	 * Detailed error context is logged to error_log for administrator debugging.
	 * This prevents information disclosure through WP_Error objects that may be
	 * displayed to end users in REST API responses or login screens.
	 *
	 * @param string $context       Error context (e.g., 'token_exchange', 'userinfo').
	 * @param string $detailed_error Detailed error message for logging.
	 * @param string $generic_message Generic user-facing error message.
	 * @return WP_Error WordPress error object with sanitized message.
	 */
	private function handle_error( $context, $detailed_error, $generic_message ): WP_Error {
		// Log detailed error for debugging (sanitize for log safety)
		$log_message = sprintf(
			'OIDC Error [%s]: %s',
			$context,
			$detailed_error
		);
		error_log( $log_message );

		// Always return generic error to users to prevent information disclosure
		return new WP_Error( 'oidc_error', $generic_message );
	}

	/**
	 * Apply client authentication to a token endpoint request.
	 *
	 * Confidential clients authenticate per RFC 6749 section 2.3. The method is
	 * configurable: client_secret_basic (Authorization header) or client_secret_post
	 * (request body). Public clients include client_id in the body for identification.
	 *
	 * @param array<string, string> $token_params Token request body parameters.
	 * @param array<string, string> $headers      Token request HTTP headers.
	 * @return array{0: array<string, string>, 1: array<string, string>} Updated [params, headers].
	 */
	private function apply_client_authentication( array $token_params, array $headers ): array {
		$client_id     = $this->get_setting( 'client_id' );
		$client_secret = $this->get_setting( 'client_secret' );

		if ( ! empty( $client_secret ) ) {
			$auth_method = $this->get_setting( 'token_endpoint_auth_method' );

			if ( 'client_secret_post' === $auth_method ) {
				// client_secret_post: credentials sent in the request body (RFC 6749 section 2.3.1)
				$token_params['client_id']     = $client_id;
				$token_params['client_secret'] = $client_secret;
			} else {
				// client_secret_basic (default): credentials in Authorization header only.
				// Per RFC 6749 section 2.3.1, clients using Basic auth MUST NOT include
				// credentials in the request body, and the client_id and client_secret
				// MUST each be application/x-www-form-urlencoded (spaces become '+')
				// before being combined with a colon and base64-encoded. This matters
				// for secrets containing ':', '%', '+', or spaces.
				$credentials              = urlencode( $client_id ) . ':' . urlencode( $client_secret );
				$headers['Authorization'] = 'Basic ' . base64_encode( $credentials );
			}
		} else {
			// Public clients: include client_id in body for identification
			$token_params['client_id'] = $client_id;
		}

		return array( $token_params, $headers );
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
	public function exchange_code( string $code, ?string $code_verifier = null ): array|WP_Error {
		$token_endpoint = $this->get_setting( 'token_endpoint' );

		if ( empty( $token_endpoint ) ) {
			return new WP_Error( 'oidc_error', __( 'Token endpoint not configured.', 'secure-oidc-login' ) );
		}

		// Token endpoint request parameters for OAuth 2.0 Authorization Code Flow
		$token_params = array(
			'grant_type'   => 'authorization_code',  // Specifies the grant type being used
			'code'         => $code,                 // The authorization code received from the IdP redirect
			'redirect_uri' => Secure_OIDC_Login::get_callback_url(), // Must match the redirect URI from the auth request
		);

		// HTTP headers for the token request
		// Content-Type must be application/x-www-form-urlencoded per OAuth 2.0 spec (RFC 6749 Section 4.1.3)
		$headers = array(
			'Content-Type' => 'application/x-www-form-urlencoded',
		);

		list( $token_params, $headers ) = $this->apply_client_authentication( $token_params, $headers );

		// Public clients use PKCE for security (no client_secret available)
		if ( ! empty( $code_verifier ) ) {
			$token_params['code_verifier'] = $code_verifier;
		}

		// SECURITY: Use wp_safe_remote_post() to prevent SSRF attacks
		// This validates the token_endpoint URL and blocks private IPs, non-standard ports, etc.
		$response = wp_safe_remote_post(
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

		// Extract response components from the token endpoint HTTP response
		$status_code  = (int) wp_remote_retrieve_response_code( $response );  // HTTP status code (e.g., 200, 400)
		$body         = wp_remote_retrieve_body( $response );                  // Raw response body
		$content_type = wp_remote_retrieve_header( $response, 'content-type' ); // Content-Type header

		// Handle case where header might be an array (multiple values)
		if ( is_array( $content_type ) ) {
			$content_type = $content_type[0] ?? '';
		}

		// Ensure content_type is a string for stripos() in PHP 8+.
		$content_type = (string) $content_type;

		// Check if the server is returning a proper json reponse
		if ( stripos( $content_type, 'application/json' ) === false ) {
			return $this->handle_error(
				'token_exchange',
				sprintf(
					'Token endpoint returned unexpected Content-Type "%s". Body: %s',
					sanitize_text_field( $content_type ),
					substr( wp_strip_all_tags( $body ), 0, 200 )
				),
				__( 'Authentication failed. Unexpected response from identity provider.', 'secure-oidc-login' )
			);
		}

		$tokens = json_decode( $body, true );

		// Check if we recieved OK from server
		if ( 200 !== $status_code ) {
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

		// Validate that both required tokens are present in the response.
		// Per OAuth 2.0 / OIDC spec, the token endpoint must return access_token and id_token.
		if ( empty( $tokens['access_token'] ) || empty( $tokens['id_token'] ) ) {
			return new WP_Error( 'oidc_error', __( 'Invalid token response.', 'secure-oidc-login' ) );
		}

		// Validate token_type is present (RFC 6749 section 5.1: REQUIRED field).
		if ( empty( $tokens['token_type'] ) ) {
			return new WP_Error( 'oidc_error', __( 'Missing required token_type in token response.', 'secure-oidc-login' ) );
		}

		// Validate token_type value (RFC 6749 section 5.1: value is case insensitive).
		if ( strcasecmp( $tokens['token_type'], 'Bearer' ) !== 0 ) {
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
	 * @param string|null $access_token Access token for at_hash validation.
	 * @return array<string, mixed>|WP_Error Decoded claims array or error.
	 */
	public function validate_id_token( string $id_token, ?string $expected_nonce = null, ?string $auth_code = null, ?string $access_token = null ): array|WP_Error {
		// Decode and verify JWT signature (OIDC Core Section 3.1.3.7, steps 6-7).
		$claims = $this->decode_and_verify_jwt( $id_token );
		if ( is_wp_error( $claims ) ) {
			return $claims;
		}

		// Extract and remove the internal JWT algorithm marker set by decode_and_verify_jwt.
		$jwt_alg = $claims['__jwt_alg'] ?? 'RS256';
		unset( $claims['__jwt_alg'] );

		// Verify required 'sub' claim is present (OIDC Core spec 2.2)
		if ( empty( $claims['sub'] ) ) {
			return new WP_Error( 'oidc_error', __( 'Missing required sub claim in ID token.', 'secure-oidc-login' ) );
		}

		// Verify the token was issued by the expected IdP (OIDC Core spec 3.1.3.7)
		// If we are missing the issuer in settings, fail since there is nothing to compare against.
		$issuer = $this->get_setting( 'issuer' );
		if ( empty( $issuer ) ) {
			return $this->handle_error(
				'id_token_validation',
				'Issuer setting is not configured. ID token issuer validation cannot be performed.',
				__( 'Authentication configuration error. Please contact the site administrator.', 'secure-oidc-login' )
			);
		}

		// Verify the 'iss' claim matches the expected issuer (OIDC Core Section 3.1.3.7, step 2).
		if ( ! isset( $claims['iss'] ) || $claims['iss'] !== $issuer ) {
			return new WP_Error( 'oidc_error', __( 'Invalid token issuer.', 'secure-oidc-login' ) );
		}

		// Verify the token was issued for this client (OIDC Core Section 3.1.3.7, steps 3-4).
		$client_id = $this->get_setting( 'client_id' );
		$aud       = is_array( $claims['aud'] ) ? $claims['aud'] : array( $claims['aud'] );
		if ( ! in_array( $client_id, $aud, true ) ) {
			return new WP_Error( 'oidc_error', __( 'Invalid token audience.', 'secure-oidc-login' ) );
		}

		// If multiple audiences, the azp claim MUST be present (OIDC Core spec 3.1.3.7, step 5).
		if ( count( $aud ) > 1 && empty( $claims['azp'] ) ) {
			return new WP_Error( 'oidc_error', __( 'Invalid or missing azp claim for multi-audience token.', 'secure-oidc-login' ) );
		}

		// If the azp claim is present, it MUST match client_id (OIDC Core spec 3.1.3.7, step 6).
		if ( isset( $claims['azp'] ) && $claims['azp'] !== $client_id ) {
			return new WP_Error( 'oidc_error', __( 'Invalid azp claim.', 'secure-oidc-login' ) );
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
			// Per spec: c_hash is base64url of left-most half of hash, using the alg's hash function.
			list( $hash_alg, $hash_len ) = self::get_hash_params_for_alg( $jwt_alg );
			$computed_hash               = rtrim( strtr( base64_encode( substr( hash( $hash_alg, $auth_code, true ), 0, $hash_len ) ), '+/', '-_' ), '=' );
			if ( $claims['c_hash'] !== $computed_hash ) {
				return new WP_Error( 'invalid_c_hash', 'ID token c_hash does not match authorization code' );
			}
		}

		// SECURITY: Validate at_hash (access token hash) per OIDC Core 3.1.3.3
		// The at_hash claim cryptographically binds the access token to the ID token,
		// preventing token substitution attacks where an attacker pairs a legitimate
		// ID token with a different access token to get UserInfo for another user.
		if ( null !== $access_token && isset( $claims['at_hash'] ) ) {
			list( $hash_alg, $hash_len ) = self::get_hash_params_for_alg( $jwt_alg );
			$computed_hash               = rtrim( strtr( base64_encode( substr( hash( $hash_alg, $access_token, true ), 0, $hash_len ) ), '+/', '-_' ), '=' );
			if ( $claims['at_hash'] !== $computed_hash ) {
				return new WP_Error( 'invalid_at_hash', 'ID token at_hash does not match access token' );
			}
		}

		// All validation checks passed; return the verified claims.
		return $claims;
	}

	/**
	 * Validate the acr claim in the ID token against requested ACR values.
	 *
	 * When enforce_acr is enabled and acr_values are configured, this method
	 * verifies that the ID token contains an acr claim matching one of the
	 * requested values. This ensures the identity provider performed the
	 * requested level of authentication.
	 *
	 * @param array<string, mixed> $claims  The decoded ID token claims.
	 * @param array<string, mixed> $options Plugin settings from WordPress options.
	 * @return true|WP_Error True if validation passes, WP_Error on failure.
	 */
	public function validate_acr_claim( array $claims, array $options ): bool|WP_Error {
		$acr_values = Secure_OIDC_Login::get_setting( 'acr_values', $options );

		// Determine whether ACR enforcement is enabled. The plugin setting is
		// used as default, but can be overridden by the SECURE_OIDC_ENFORCE_ACR
		// environment variable when set (accepts "true"/"false").
		$enforce_acr = ! empty( $options['enforce_acr'] );
		$env_enforce = getenv( 'SECURE_OIDC_ENFORCE_ACR' );

		if ( false !== $env_enforce && '' !== $env_enforce ) {
			if ( 'true' === strtolower( (string) $env_enforce ) ) {
				$enforce_acr = true;
			} else {
				$enforce_acr = false;
			}
		}

		// If enforcement is off or no ACR values configured, skip validation
		if ( ! $enforce_acr || empty( trim( $acr_values ) ) ) {
			return true;
		}

		// Split on whitespace and filter empty entries
		$requested_values = array_filter( array_map( 'trim', preg_split( '/\s+/', $acr_values ) ) );

		// No valid ACR values remain after parsing; nothing to enforce.
		if ( empty( $requested_values ) ) {
			return true;
		}

		// Verify acr claim is present in ID token
		if ( ! isset( $claims['acr'] ) || '' === $claims['acr'] ) {
			return new WP_Error(
				'oidc_acr_missing',
				__( 'ID token is missing the required acr claim.', 'secure-oidc-login' )
			);
		}

		// Verify acr claim matches one of the requested values (strict comparison)
		if ( ! in_array( (string) $claims['acr'], $requested_values, true ) ) {
			return new WP_Error(
				'oidc_acr_mismatch',
				__( 'ID token acr claim does not match any of the requested ACR values.', 'secure-oidc-login' )
			);
		}

		return true;
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
	protected function decode_and_verify_jwt( string $jwt, bool $retry = true ): array|WP_Error {
		// Get JWKS from IdP
		$jwks = $this->get_jwks();
		if ( is_wp_error( $jwks ) ) {
			return $jwks;
		}

		// Split JWT into its three dot-separated components: header, payload, and signature.
		$tks = explode( '.', $jwt );

		// If we don't have all 3 parts, return an error.
		if ( count( $tks ) !== 3 ) {
			return new WP_Error( 'oidc_error', __( 'Invalid JWT format.', 'secure-oidc-login' ) );
		}

		$header_encoded = $tks[0];
		$header         = json_decode( JWT::urlsafeB64Decode( $header_encoded ), true );
		// Default to RS256 (asymmetric) if algorithm not specified - most common for OIDC
		$alg = isset( $header['alg'] ) ? $header['alg'] : 'RS256';

		// SECURITY: Validate algorithm against allowlist to prevent algorithm confusion attacks.
		// This blocks symmetric algorithms (HS256/384/512), 'none', and any other unexpected values.
		// First check: must be in the hardcoded safe asymmetric algorithm list.
		if ( ! in_array( $alg, self::ALLOWED_JWT_ALGORITHMS, true ) ) {
			return new WP_Error( 'oidc_error', __( 'Unsupported JWT signing algorithm.', 'secure-oidc-login' ) );
		}

		// Second check: if the IdP declared id_token_signing_alg_values_supported during
		// discovery, the JWT algorithm must also be in that list. This narrows the allowlist
		// to only the algorithms the specific IdP actually uses (OIDC Discovery 1.0 Section 3).
		if ( isset( $this->options['id_token_signing_alg_values_supported'] )
			&& is_array( $this->options['id_token_signing_alg_values_supported'] )
		) {
			$idp_algorithms = $this->options['id_token_signing_alg_values_supported'];
		} else {
			$idp_algorithms = array();
		}

		// Reject the token if the IdP advertised supported algorithms and this one isn't among them.
		if ( ! empty( $idp_algorithms ) && ! in_array( $alg, $idp_algorithms, true ) ) {
			return new WP_Error( 'oidc_error', __( 'JWT algorithm not supported by the identity provider.', 'secure-oidc-login' ) );
		}

		// IdP compatibility: Some identity providers omit the "alg" field in their JWKS keys.
		// The Firebase JWT library requires it, so we infer from the key type (kty) when missing.
		// SECURITY: We derive the algorithm from the trusted JWKS key type rather than copying
		// the attacker-controlled JWT header value, preventing algorithm confusion attacks.
		// Keys with an unknown kty are dropped entirely instead of inheriting the header value.
		if ( isset( $jwks['keys'] ) && is_array( $jwks['keys'] ) ) {
			$usable_keys = array();
			foreach ( $jwks['keys'] as $key ) {
				if ( ! isset( $key['alg'] ) ) {
					$kty = isset( $key['kty'] ) ? $key['kty'] : '';
					if ( ! isset( self::KTY_DEFAULT_ALGORITHM[ $kty ] ) ) {
						continue;
					}
					$key['alg'] = self::KTY_DEFAULT_ALGORITHM[ $kty ];
				}
				$usable_keys[] = $key;
			}
			$jwks['keys'] = $usable_keys;
		}

		try {
			// Convert JWKS to Key objects using Firebase JWT library
			$keys = JWK::parseKeySet( $jwks );

			// SECURITY: Set clock skew tolerance for JWT validation
			// This accommodates time differences between IdP and WordPress server
			// Default: 15 seconds (reduced from 5 minutes for better security)
			// Override with SECURE_OIDC_JWT_LEEWAY environment variable (in seconds)
			$leeway     = 15; // Default: 15 seconds
			$env_leeway = getenv( 'SECURE_OIDC_JWT_LEEWAY' );
			if ( false !== $env_leeway && '' !== $env_leeway ) {
				$parsed_leeway = filter_var( $env_leeway, FILTER_VALIDATE_INT );
				if ( false !== $parsed_leeway && $parsed_leeway > 0 && $parsed_leeway <= 600 ) {
					$leeway = $parsed_leeway;
				} else {
					error_log( '[Secure OIDC Login] Invalid SECURE_OIDC_JWT_LEEWAY value: ' . $env_leeway . '. Using default 15 seconds.' );
				}
			}
			JWT::$leeway = $leeway;

			// Decode and verify JWT (automatically validates signature, exp, nbf, iat)
			$decoded = JWT::decode( $jwt, $keys );

			// Convert stdClass to array for consistency with existing code
			$claims              = json_decode( json_encode( $decoded ), true );
			$claims['__jwt_alg'] = $alg;
			return $claims;

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
	private function get_jwks( bool $force_refresh = false ): array|WP_Error {
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
				// SECURITY: Cache integrity check failed - could be salt rotation or tampering
				// Log this event for monitoring and fetch fresh JWKS from IdP
				error_log( '[Secure OIDC Login] JWKS cache HMAC verification failed - fetching fresh keys from IdP. This may indicate WordPress salt rotation or cache tampering.' );

				$deleted = delete_transient( $cache_key );
				if ( false === $deleted ) {
					error_log( '[Secure OIDC Login] Failed to delete compromised JWKS cache - this may indicate database issues.' );
				}
				// Fall through to fetch fresh JWKS
			}
		}

		// SECURITY: Use wp_safe_remote_get() to prevent SSRF attacks
		// This validates the jwks_uri and blocks private IPs, non-standard ports, etc.
		$response = wp_safe_remote_get(
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

		$status_code = (int) wp_remote_retrieve_response_code( $response );

		// If the sever returns anthing other than OK, retun an error.
		if ( 200 !== $status_code ) {
			return $this->handle_error(
				'jwks_fetch',
				'Failed to fetch JWKS. HTTP status: ' . $status_code,
				__( 'Authentication configuration error. Please contact the site administrator.', 'secure-oidc-login' )
			);
		}

		$body = wp_remote_retrieve_body( $response );
		$jwks = json_decode( $body, true );

		// Ensure the JWKS response is valid and contains a "keys" array per RFC 7517 Section 5.
		if ( ! $jwks || ! isset( $jwks['keys'] ) || ! is_array( $jwks['keys'] ) ) {
			return new WP_Error( 'oidc_error', __( 'Invalid JWKS response.', 'secure-oidc-login' ) );
		}

		// Cache the JWKS with integrity protection
		$cache_data = array(
			'jwks' => $jwks,
			'hmac' => $this->generate_jwks_hmac( $jwks ),
		);
		$cached     = set_transient( $cache_key, $cache_data, self::JWKS_CACHE_DURATION );

		if ( false === $cached ) {
			error_log( '[Secure OIDC Login] Failed to cache JWKS - this may indicate database issues or object cache problems. Authentication will continue but performance may be impacted.' );
		}

		return $jwks;
	}

	/**
	 * Check if WordPress authentication salts are strong enough for HMAC key derivation.
	 *
	 * SECURITY: Logs a warning if SECURE_AUTH_KEY or SECURE_AUTH_SALT are weak, empty,
	 * or set to the WordPress default placeholder. Weak salts reduce the security of
	 * the JWKS cache integrity protection, potentially allowing cache poisoning attacks.
	 *
	 * A salt is considered weak if:
	 * - The constant is not defined
	 * - The value is empty
	 * - The value contains the WordPress default placeholder: "put your unique phrase here"
	 * - The value is shorter than 32 characters (insufficient entropy)
	 *
	 * @return void
	 */
	private function check_salt_strength(): void {
		// Only warn once per request to avoid log spam.
		if ( self::$has_logged_salt_warning ) {
			return;
		}

		$weak_salts          = array();
		$default_placeholder = 'put your unique phrase here';

		// Check SECURE_AUTH_KEY.
		if ( ! defined( 'SECURE_AUTH_KEY' ) ||
			SECURE_AUTH_KEY === '' ||
			stripos( SECURE_AUTH_KEY, $default_placeholder ) !== false ||
			strlen( SECURE_AUTH_KEY ) < 32 ) {
			$weak_salts[] = 'SECURE_AUTH_KEY';
		}

		// Check SECURE_AUTH_SALT.
		if ( ! defined( 'SECURE_AUTH_SALT' ) ||
			SECURE_AUTH_SALT === '' ||
			stripos( SECURE_AUTH_SALT, $default_placeholder ) !== false ||
			strlen( SECURE_AUTH_SALT ) < 32 ) {
			$weak_salts[] = 'SECURE_AUTH_SALT';
		}

		// Log a one-time warning if WordPress salts are weak, as they are used for JWKS cache HMAC integrity.
		if ( ! empty( $weak_salts ) ) {
			error_log(
				'[Secure OIDC Login] Security warning: Weak WordPress salts detected (' .
				implode( ', ', $weak_salts ) .
				'). JWKS cache integrity protection is weakened. ' .
				'Please configure strong, unique values in wp-config.php. ' .
				'See: https://api.wordpress.org/secret-key/1.1/salt/'
			);
			self::$has_logged_salt_warning = true;
		}
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
	private function generate_jwks_hmac( array $jwks ): string {
		// Check salt strength and log warning if weak (once per request).
		$this->check_salt_strength();

		// Serialize the JWKS to JSON for storage and HMAC computation.
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
	private function verify_jwks_integrity( array $cached_data ): bool {
		if ( ! isset( $cached_data['jwks'] ) || ! isset( $cached_data['hmac'] ) ) {
			return false;
		}

		// Recompute the HMAC from the cached JWKS to verify it hasn't been tampered with.
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
	public function get_userinfo( string $access_token ): array|WP_Error {
		$userinfo_endpoint = $this->get_setting( 'userinfo_endpoint' );

		if ( empty( $userinfo_endpoint ) ) {
			return array(); // Userinfo endpoint is optional
		}

		// SECURITY: Use wp_safe_remote_get() to prevent SSRF attacks
		// This validates the userinfo_endpoint and blocks private IPs, non-standard ports, etc.
		$response = wp_safe_remote_get(
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

		$status_code  = (int) wp_remote_retrieve_response_code( $response );
		$body         = wp_remote_retrieve_body( $response );
		$content_type = wp_remote_retrieve_header( $response, 'content-type' );
		if ( is_array( $content_type ) ) {
			$content_type = $content_type[0] ?? '';
		}
		// Ensure content_type is a string for stripos() in PHP 8+
		$content_type = (string) $content_type;

		// If we do not recieve a valid json reponse, return an error.
		if ( stripos( $content_type, 'application/json' ) === false ) {
			return $this->handle_error(
				'userinfo',
				sprintf(
					'Userinfo endpoint returned unexpected Content-Type "%s". Body: %s',
					sanitize_text_field( $content_type ),
					substr( wp_strip_all_tags( $body ), 0, 200 )
				),
				__( 'Failed to retrieve user information. Unexpected response from identity provider.', 'secure-oidc-login' )
			);
		}

		// If we did not reiceve OK from the server, return an error.
		if ( 200 !== $status_code ) {
			return $this->handle_error(
				'userinfo',
				'Userinfo request failed with status ' . $status_code,
				__( 'Failed to retrieve user information. Please try again.', 'secure-oidc-login' )
			);
		}

		// Decode the UserInfo response JSON into an associative array.
		$userinfo = json_decode( $body, true );

		// If we dont have valid data, return an error.
		if ( ! $userinfo ) {
			return new WP_Error( 'oidc_error', __( 'Invalid userinfo response.', 'secure-oidc-login' ) );
		}

		// Return the verified UserInfo claims.
		return $userinfo;
	}

	/**
	 * Refresh an access token using a refresh token.
	 *
	 * @param string $refresh_token The refresh token from a previous token response.
	 * @return array<string, mixed>|WP_Error New token response array or error.
	 */
	public function refresh_token( string $refresh_token ): array|WP_Error {
		$token_endpoint = $this->get_setting( 'token_endpoint' );

		if ( empty( $token_endpoint ) ) {
			return new WP_Error( 'oidc_error', __( 'Token endpoint not configured.', 'secure-oidc-login' ) );
		}

		$token_params = array(
			'grant_type'    => 'refresh_token',
			'refresh_token' => $refresh_token,
		);

		$headers = array(
			'Content-Type' => 'application/x-www-form-urlencoded',
		);

		list( $token_params, $headers ) = $this->apply_client_authentication( $token_params, $headers );

		// SECURITY: Use wp_safe_remote_post() to prevent SSRF attacks
		// This validates the token_endpoint URL and blocks private IPs, non-standard ports, etc.
		// Timeout is shorter than the login-time token exchange because refresh runs
		// synchronously on init and would otherwise block page loads on a slow IdP.
		$response = wp_safe_remote_post(
			$token_endpoint,
			array(
				'body'    => $token_params,
				'headers' => $headers,
				'timeout' => 10,
			)
		);

		if ( is_wp_error( $response ) ) {
			return $this->handle_error(
				'token_refresh',
				'Failed to connect to token endpoint: ' . $response->get_error_message(),
				__( 'Session refresh failed. Please log in again.', 'secure-oidc-login' )
			);
		}

		$status_code  = (int) wp_remote_retrieve_response_code( $response );
		$body         = wp_remote_retrieve_body( $response );
		$content_type = wp_remote_retrieve_header( $response, 'content-type' );
		if ( is_array( $content_type ) ) {
			$content_type = $content_type[0] ?? '';
		}
		// Ensure content_type is a string for stripos() in PHP 8+
		$content_type = (string) $content_type;

		// If we didnt recieve a valid JSON response, return an error.
		if ( stripos( $content_type, 'application/json' ) === false ) {
			return $this->handle_error(
				'token_refresh',
				sprintf(
					'Token refresh returned unexpected Content-Type "%s". Body: %s',
					sanitize_text_field( $content_type ),
					substr( wp_strip_all_tags( $body ), 0, 200 )
				),
				__( 'Session refresh failed. Unexpected response from identity provider.', 'secure-oidc-login' )
			);
		}

		// Decode response early — error responses also contain JSON with diagnostic fields (RFC 6749 Section 5.2).
		$tokens = json_decode( $body, true );

		// If we didnt recieve OK from the server return an error.
		if ( 200 !== $status_code ) {
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

		// Validate the refresh response shape like exchange_code() does, so every
		// caller gets the same guarantees (RFC 6749 section 5.1: access_token and
		// token_type are REQUIRED; only Bearer tokens are supported).
		if ( ! is_array( $tokens ) || empty( $tokens['access_token'] ) ) {
			return new WP_Error( 'oidc_error', __( 'Invalid token response.', 'secure-oidc-login' ) );
		}

		if ( empty( $tokens['token_type'] ) ) {
			return new WP_Error( 'oidc_error', __( 'Missing required token_type in token response.', 'secure-oidc-login' ) );
		}

		if ( strcasecmp( $tokens['token_type'], 'Bearer' ) !== 0 ) {
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
	 * Discover OIDC configuration from the well-known endpoint.
	 *
	 * Fetches the OpenID Provider Configuration document which contains
	 * all the endpoint URLs and supported features of the IdP.
	 *
	 * @param string $issuer_url The base URL of the identity provider.
	 * @return array<string, mixed>|WP_Error Configuration array or error.
	 */
	public function discover( string $issuer_url ): array|WP_Error {
		$discovery_url = rtrim( $issuer_url, '/' ) . '/.well-known/openid-configuration';

		// SECURITY: Use wp_safe_remote_get() to prevent SSRF attacks
		// This validates the discovery_url and blocks private IPs, non-standard ports, etc.
		$response = wp_safe_remote_get(
			$discovery_url,
			array(
				'timeout' => 30,
			)
		);

		if ( is_wp_error( $response ) ) {
			return $response;
		}

		$status_code  = (int) wp_remote_retrieve_response_code( $response );
		$body         = wp_remote_retrieve_body( $response );
		$content_type = wp_remote_retrieve_header( $response, 'content-type' );
		if ( is_array( $content_type ) ) {
			$content_type = $content_type[0] ?? '';
		}
		// Ensure content_type is a string for stripos() in PHP 8+
		$content_type = (string) $content_type;

		// If we didnt recieve a valid JSON response, return an error.
		if ( stripos( $content_type, 'application/json' ) === false ) {
			return new WP_Error(
				'oidc_error',
				__( 'Failed to discover OIDC configuration. Identity provider returned an unexpected response format.', 'secure-oidc-login' )
			);
		}

		// If the server did not return OK, return an error.
		if ( 200 !== $status_code ) {
			return new WP_Error( 'oidc_error', __( 'Failed to discover OIDC configuration.', 'secure-oidc-login' ) );
		}

		$config = json_decode( $body, true );

		// If the config is invalid, return an error.
		if ( ! $config || ! is_array( $config ) ) {
			return new WP_Error( 'oidc_error', __( 'Invalid discovery response.', 'secure-oidc-login' ) );
		}

		$validation = self::validate_discovery_document( $config, $discovery_url );
		if ( is_wp_error( $validation ) ) {
			return $validation;
		}

		return $config;
	}

	/**
	 * Validate an OpenID Provider Configuration document against the URL it was fetched from.
	 *
	 * SECURITY: Per OIDC Discovery 1.0 Section 4.3, the issuer in the document MUST be
	 * the discovery URL with the /.well-known/openid-configuration suffix removed. A
	 * mismatch means the document describes a different issuer than the one queried
	 * (misconfiguration, or an attempt to point this client at another provider's
	 * endpoints — the precondition for IdP mix-up attacks). Endpoint URLs must also be
	 * HTTPS unless SECURE_OIDC_ALLOW_INSECURE_DISCOVERY=true is set for testing.
	 *
	 * @param array<string, mixed> $config        The decoded discovery document.
	 * @param string               $discovery_url The URL the document was fetched from.
	 * @return true|WP_Error True if the document is valid, WP_Error otherwise.
	 */
	public static function validate_discovery_document( array $config, string $discovery_url ): bool|WP_Error {
		$issuer = $config['issuer'] ?? '';

		if ( ! is_string( $issuer ) || '' === $issuer ) {
			return new WP_Error(
				'oidc_discovery_missing_issuer',
				__( 'Discovery document is missing the required issuer field.', 'secure-oidc-login' )
			);
		}

		// Strip query string and fragment before comparing — some providers (e.g. Azure AD B2C)
		// require query parameters on the discovery URL that are not part of the issuer.
		// strcspn()+substr() is used instead of strtok() to avoid resetting PHP's
		// shared tokeniser state for unrelated code in the same request.
		$normalized_url = substr( $discovery_url, 0, strcspn( $discovery_url, '?#' ) );
		$expected_url   = rtrim( $issuer, '/' ) . '/.well-known/openid-configuration';

		if ( rtrim( (string) $normalized_url, '/' ) !== $expected_url ) {
			return new WP_Error(
				'oidc_discovery_issuer_mismatch',
				sprintf(
					/* translators: 1: issuer value from the discovery document, 2: discovery URL */
					__( 'Discovery document issuer "%1$s" does not match the discovery URL "%2$s". Refusing to use this configuration.', 'secure-oidc-login' ),
					$issuer,
					$discovery_url
				)
			);
		}

		// Require HTTPS on all advertised endpoints (matches the HTTPS requirement
		// already enforced for the discovery URL itself).
		$allow_insecure = getenv( 'SECURE_OIDC_ALLOW_INSECURE_DISCOVERY' );
		$require_https  = false === $allow_insecure || 'true' !== strtolower( (string) $allow_insecure );

		$endpoint_keys = array(
			'authorization_endpoint',
			'token_endpoint',
			'jwks_uri',
			'userinfo_endpoint',
			'end_session_endpoint',
		);

		foreach ( $endpoint_keys as $key ) {
			if ( empty( $config[ $key ] ) ) {
				continue;
			}

			$endpoint = $config[ $key ];

			if ( ! is_string( $endpoint ) || false === filter_var( $endpoint, FILTER_VALIDATE_URL ) ) {
				return new WP_Error(
					'oidc_discovery_invalid_endpoint',
					sprintf(
						/* translators: %s: discovery document field name */
						__( 'Discovery document contains an invalid %s URL.', 'secure-oidc-login' ),
						$key
					)
				);
			}

			$parsed = wp_parse_url( $endpoint );
			$scheme = is_array( $parsed ) && isset( $parsed['scheme'] ) ? strtolower( (string) $parsed['scheme'] ) : '';
			if ( $require_https && 'https' !== $scheme ) {
				return new WP_Error(
					'oidc_discovery_insecure_endpoint',
					sprintf(
						/* translators: %s: discovery document field name */
						__( 'Discovery document %s must use HTTPS. Set SECURE_OIDC_ALLOW_INSECURE_DISCOVERY=true to allow HTTP for testing.', 'secure-oidc-login' ),
						$key
					)
				);
			}
		}

		return true;
	}
}

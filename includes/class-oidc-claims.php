<?php
declare(strict_types=1);

/**
 * OIDC Claims value object.
 *
 * @package Secure_OIDC_Login
 * @since 0.1.0
 */

// Prevent direct file access
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Encapsulates OIDC ID token claims.
 *
 * Provides type-safe access to ID token claims and validates
 * required fields according to OIDC Core specification.
 *
 * @immutable
 */
class OIDC_Claims {
	/** @var string Unique identifier for the end-user (required) */
	private string $sub;

	/** @var string Issuer identifier (required) */
	private string $iss;

	/** @var string|array<int, string> Audience(s) this token is intended for (required) */
	private $aud;

	/** @var int Expiration time (Unix timestamp) */
	private int $exp;

	/** @var int Time token was issued (Unix timestamp) */
	private int $iat;

	/** @var string|null Nonce value for replay attack prevention */
	private ?string $nonce;

	/** @var string|null Email address */
	private ?string $email;

	/** @var bool Whether email has been verified */
	private bool $email_verified;

	/** @var string|null Full name */
	private ?string $name;

	/** @var string|null Given name / first name */
	private ?string $given_name;

	/** @var string|null Family name / last name */
	private ?string $family_name;

	/** @var string|null Preferred username */
	private ?string $preferred_username;

	/** @var array<string, mixed> All raw claims for extensibility */
	private array $raw_claims;

	/**
	 * Create claims object from decoded ID token.
	 *
	 * @param array<string, mixed> $claims Decoded ID token claims.
	 * @return OIDC_Claims|WP_Error Claims object or error if validation fails.
	 */
	public static function from_array( array $claims ) {
		// Validate required claims per OIDC Core spec
		if ( empty( $claims['sub'] ) ) {
			return new WP_Error( 'oidc_error', __( 'Missing required sub claim in ID token.', 'secure-oidc-login' ) );
		}

		if ( empty( $claims['iss'] ) ) {
			return new WP_Error( 'oidc_error', __( 'Missing required iss claim in ID token.', 'secure-oidc-login' ) );
		}

		if ( empty( $claims['aud'] ) ) {
			return new WP_Error( 'oidc_error', __( 'Missing required aud claim in ID token.', 'secure-oidc-login' ) );
		}

		if ( empty( $claims['exp'] ) ) {
			return new WP_Error( 'oidc_error', __( 'Missing required exp claim in ID token.', 'secure-oidc-login' ) );
		}

		if ( empty( $claims['iat'] ) ) {
			return new WP_Error( 'oidc_error', __( 'Missing required iat claim in ID token.', 'secure-oidc-login' ) );
		}

		$instance                     = new self();
		$instance->sub                = (string) $claims['sub'];
		$instance->iss                = (string) $claims['iss'];
		$instance->aud                = $claims['aud'];
		$instance->exp                = (int) $claims['exp'];
		$instance->iat                = (int) $claims['iat'];
		$instance->nonce              = isset( $claims['nonce'] ) ? (string) $claims['nonce'] : null;
		$instance->email              = isset( $claims['email'] ) ? (string) $claims['email'] : null;
		$instance->email_verified     = isset( $claims['email_verified'] ) && $claims['email_verified'] === true;
		$instance->name               = isset( $claims['name'] ) ? (string) $claims['name'] : null;
		$instance->given_name         = isset( $claims['given_name'] ) ? (string) $claims['given_name'] : null;
		$instance->family_name        = isset( $claims['family_name'] ) ? (string) $claims['family_name'] : null;
		$instance->preferred_username = isset( $claims['preferred_username'] ) ? (string) $claims['preferred_username'] : null;
		$instance->raw_claims         = $claims;

		return $instance;
	}

	/**
	 * Get the subject identifier (unique user ID from IdP).
	 *
	 * @return string The subject identifier.
	 */
	public function get_subject(): string {
		return $this->sub;
	}

	/**
	 * Get the issuer identifier.
	 *
	 * @return string The issuer URL.
	 */
	public function get_issuer(): string {
		return $this->iss;
	}

	/**
	 * Get the audience (client ID this token is for).
	 *
	 * @return string|array<int, string> Single audience or array of audiences.
	 */
	public function get_audience() {
		return $this->aud;
	}

	/**
	 * Get the expiration time.
	 *
	 * @return int Unix timestamp when token expires.
	 */
	public function get_expiration(): int {
		return $this->exp;
	}

	/**
	 * Get the issued-at time.
	 *
	 * @return int Unix timestamp when token was issued.
	 */
	public function get_issued_at(): int {
		return $this->iat;
	}

	/**
	 * Get the nonce if present.
	 *
	 * @return string|null The nonce value or null.
	 */
	public function get_nonce(): ?string {
		return $this->nonce;
	}

	/**
	 * Get the email address if present.
	 *
	 * @return string|null The email address or null.
	 */
	public function get_email(): ?string {
		return $this->email;
	}

	/**
	 * Check if email has been verified by the IdP.
	 *
	 * @return bool True if email is verified.
	 */
	public function is_email_verified(): bool {
		return $this->email_verified;
	}

	/**
	 * Get the full name if present.
	 *
	 * @return string|null The full name or null.
	 */
	public function get_name(): ?string {
		return $this->name;
	}

	/**
	 * Get the given name (first name) if present.
	 *
	 * @return string|null The given name or null.
	 */
	public function get_given_name(): ?string {
		return $this->given_name;
	}

	/**
	 * Get the family name (last name) if present.
	 *
	 * @return string|null The family name or null.
	 */
	public function get_family_name(): ?string {
		return $this->family_name;
	}

	/**
	 * Get the preferred username if present.
	 *
	 * @return string|null The preferred username or null.
	 */
	public function get_preferred_username(): ?string {
		return $this->preferred_username;
	}

	/**
	 * Get a custom claim value.
	 *
	 * @param string $claim_name The claim name.
	 * @return mixed The claim value or null if not present.
	 */
	public function get_claim( string $claim_name ) {
		return $this->raw_claims[ $claim_name ] ?? null;
	}

	/**
	 * Check if the token has expired.
	 *
	 * @param int $clock_skew_seconds Allowed clock skew in seconds (default 300 = 5 minutes).
	 * @return bool True if token has expired.
	 */
	public function is_expired( int $clock_skew_seconds = 300 ): bool {
		return $this->exp < ( time() - $clock_skew_seconds );
	}

	/**
	 * Check if the token was issued in the future (potential clock skew issue).
	 *
	 * @param int $clock_skew_seconds Allowed clock skew in seconds (default 300 = 5 minutes).
	 * @return bool True if issued in future.
	 */
	public function is_issued_in_future( int $clock_skew_seconds = 300 ): bool {
		return $this->iat > ( time() + $clock_skew_seconds );
	}

	/**
	 * Convert back to array format for backward compatibility.
	 *
	 * @return array<string, mixed> All claims as associative array.
	 */
	public function to_array(): array {
		return $this->raw_claims;
	}

	/**
	 * Private constructor - use from_array() to create instances.
	 */
	private function __construct() {
		// Use named constructor pattern
	}
}

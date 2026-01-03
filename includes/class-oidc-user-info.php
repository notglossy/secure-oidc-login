<?php
declare(strict_types=1);

/**
 * OIDC UserInfo value object.
 *
 * @package Secure_OIDC_Login
 * @since 0.1.0
 */

// Prevent direct file access
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Encapsulates OIDC UserInfo endpoint response.
 *
 * Provides type-safe access to user information claims from the
 * UserInfo endpoint per OIDC Core specification.
 *
 * @immutable
 */
class OIDC_User_Info {
	/** @var string Subject identifier - must match ID token sub */
	private string $sub;

	/** @var string|null Full name */
	private ?string $name;

	/** @var string|null Given name / first name */
	private ?string $given_name;

	/** @var string|null Family name / last name */
	private ?string $family_name;

	/** @var string|null Middle name */
	private ?string $middle_name;

	/** @var string|null Casual name or nickname */
	private ?string $nickname;

	/** @var string|null Preferred username */
	private ?string $preferred_username;

	/** @var string|null Profile page URL */
	private ?string $profile;

	/** @var string|null Profile picture URL */
	private ?string $picture;

	/** @var string|null Website URL */
	private ?string $website;

	/** @var string|null Email address */
	private ?string $email;

	/** @var bool Whether email has been verified */
	private bool $email_verified;

	/** @var string|null Gender */
	private ?string $gender;

	/** @var string|null Birthdate (YYYY-MM-DD format) */
	private ?string $birthdate;

	/** @var string|null Timezone (e.g., America/Los_Angeles) */
	private ?string $zoneinfo;

	/** @var string|null Locale (e.g., en-US) */
	private ?string $locale;

	/** @var string|null Phone number */
	private ?string $phone_number;

	/** @var bool Whether phone number has been verified */
	private bool $phone_number_verified;

	/** @var int|null Last update timestamp */
	private ?int $updated_at;

	/** @var array<string, mixed> All raw claims for extensibility */
	private array $raw_info;

	/**
	 * Create UserInfo from endpoint response.
	 *
	 * @param array<string, mixed> $userinfo UserInfo endpoint response data.
	 * @return OIDC_User_Info|WP_Error UserInfo object or error if validation fails.
	 */
	public static function from_array( array $userinfo ) {
		// Validate required sub claim
		if ( empty( $userinfo['sub'] ) ) {
			return new WP_Error( 'oidc_error', __( 'Missing required sub claim in UserInfo.', 'secure-oidc-login' ) );
		}

		$instance                        = new self();
		$instance->sub                   = (string) $userinfo['sub'];
		$instance->name                  = isset( $userinfo['name'] ) ? (string) $userinfo['name'] : null;
		$instance->given_name            = isset( $userinfo['given_name'] ) ? (string) $userinfo['given_name'] : null;
		$instance->family_name           = isset( $userinfo['family_name'] ) ? (string) $userinfo['family_name'] : null;
		$instance->middle_name           = isset( $userinfo['middle_name'] ) ? (string) $userinfo['middle_name'] : null;
		$instance->nickname              = isset( $userinfo['nickname'] ) ? (string) $userinfo['nickname'] : null;
		$instance->preferred_username    = isset( $userinfo['preferred_username'] ) ? (string) $userinfo['preferred_username'] : null;
		$instance->profile               = isset( $userinfo['profile'] ) ? (string) $userinfo['profile'] : null;
		$instance->picture               = isset( $userinfo['picture'] ) ? (string) $userinfo['picture'] : null;
		$instance->website               = isset( $userinfo['website'] ) ? (string) $userinfo['website'] : null;
		$instance->email                 = isset( $userinfo['email'] ) ? (string) $userinfo['email'] : null;
		$instance->email_verified        = isset( $userinfo['email_verified'] ) && $userinfo['email_verified'] === true;
		$instance->gender                = isset( $userinfo['gender'] ) ? (string) $userinfo['gender'] : null;
		$instance->birthdate             = isset( $userinfo['birthdate'] ) ? (string) $userinfo['birthdate'] : null;
		$instance->zoneinfo              = isset( $userinfo['zoneinfo'] ) ? (string) $userinfo['zoneinfo'] : null;
		$instance->locale                = isset( $userinfo['locale'] ) ? (string) $userinfo['locale'] : null;
		$instance->phone_number          = isset( $userinfo['phone_number'] ) ? (string) $userinfo['phone_number'] : null;
		$instance->phone_number_verified = isset( $userinfo['phone_number_verified'] ) && $userinfo['phone_number_verified'] === true;
		$instance->updated_at            = isset( $userinfo['updated_at'] ) ? (int) $userinfo['updated_at'] : null;
		$instance->raw_info              = $userinfo;

		return $instance;
	}

	/**
	 * Get the subject identifier.
	 *
	 * @return string The subject identifier.
	 */
	public function get_subject(): string {
		return $this->sub;
	}

	/**
	 * Get the full name.
	 *
	 * @return string|null The full name or null.
	 */
	public function get_name(): ?string {
		return $this->name;
	}

	/**
	 * Get the given name (first name).
	 *
	 * @return string|null The given name or null.
	 */
	public function get_given_name(): ?string {
		return $this->given_name;
	}

	/**
	 * Get the family name (last name).
	 *
	 * @return string|null The family name or null.
	 */
	public function get_family_name(): ?string {
		return $this->family_name;
	}

	/**
	 * Get the middle name.
	 *
	 * @return string|null The middle name or null.
	 */
	public function get_middle_name(): ?string {
		return $this->middle_name;
	}

	/**
	 * Get the nickname.
	 *
	 * @return string|null The nickname or null.
	 */
	public function get_nickname(): ?string {
		return $this->nickname;
	}

	/**
	 * Get the preferred username.
	 *
	 * @return string|null The preferred username or null.
	 */
	public function get_preferred_username(): ?string {
		return $this->preferred_username;
	}

	/**
	 * Get the profile page URL.
	 *
	 * @return string|null The profile URL or null.
	 */
	public function get_profile(): ?string {
		return $this->profile;
	}

	/**
	 * Get the profile picture URL.
	 *
	 * @return string|null The picture URL or null.
	 */
	public function get_picture(): ?string {
		return $this->picture;
	}

	/**
	 * Get the website URL.
	 *
	 * @return string|null The website URL or null.
	 */
	public function get_website(): ?string {
		return $this->website;
	}

	/**
	 * Get the email address.
	 *
	 * @return string|null The email address or null.
	 */
	public function get_email(): ?string {
		return $this->email;
	}

	/**
	 * Check if email has been verified.
	 *
	 * @return bool True if email is verified.
	 */
	public function is_email_verified(): bool {
		return $this->email_verified;
	}

	/**
	 * Get the gender.
	 *
	 * @return string|null The gender or null.
	 */
	public function get_gender(): ?string {
		return $this->gender;
	}

	/**
	 * Get the birthdate.
	 *
	 * @return string|null The birthdate in YYYY-MM-DD format or null.
	 */
	public function get_birthdate(): ?string {
		return $this->birthdate;
	}

	/**
	 * Get the timezone.
	 *
	 * @return string|null The timezone identifier or null.
	 */
	public function get_zoneinfo(): ?string {
		return $this->zoneinfo;
	}

	/**
	 * Get the locale.
	 *
	 * @return string|null The locale identifier or null.
	 */
	public function get_locale(): ?string {
		return $this->locale;
	}

	/**
	 * Get the phone number.
	 *
	 * @return string|null The phone number or null.
	 */
	public function get_phone_number(): ?string {
		return $this->phone_number;
	}

	/**
	 * Check if phone number has been verified.
	 *
	 * @return bool True if phone number is verified.
	 */
	public function is_phone_number_verified(): bool {
		return $this->phone_number_verified;
	}

	/**
	 * Get the last updated timestamp.
	 *
	 * @return int|null Unix timestamp of last update or null.
	 */
	public function get_updated_at(): ?int {
		return $this->updated_at;
	}

	/**
	 * Get a custom claim value.
	 *
	 * @param string $claim_name The claim name.
	 * @return mixed The claim value or null if not present.
	 */
	public function get_claim( string $claim_name ) {
		return $this->raw_info[ $claim_name ] ?? null;
	}

	/**
	 * Get a display name from available name fields.
	 *
	 * Tries full name first, then first + last, then username.
	 *
	 * @return string A suitable display name.
	 */
	public function get_display_name(): string {
		if ( $this->name !== null ) {
			return $this->name;
		}

		if ( $this->given_name !== null && $this->family_name !== null ) {
			return $this->given_name . ' ' . $this->family_name;
		}

		if ( $this->given_name !== null ) {
			return $this->given_name;
		}

		if ( $this->preferred_username !== null ) {
			return $this->preferred_username;
		}

		return $this->sub;
	}

	/**
	 * Convert back to array format for backward compatibility.
	 *
	 * @return array<string, mixed> All user info as associative array.
	 */
	public function to_array(): array {
		return $this->raw_info;
	}

	/**
	 * Private constructor - use from_array() to create instances.
	 */
	private function __construct() {
		// Use named constructor pattern
	}
}

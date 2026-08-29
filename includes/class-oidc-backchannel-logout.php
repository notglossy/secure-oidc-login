<?php
declare(strict_types=1);
/**
 * Back-channel logout handling per OIDC Back-Channel Logout 1.0.
 *
 * @package Secure_OIDC_Login
 * @since 1.4.0
 */

// Prevent direct file access
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Terminates WordPress sessions in response to IdP-initiated logout.
 *
 * The IdP POSTs a signed logout token directly to this site's back-channel
 * endpoint when the user's IdP session ends (logout at the IdP, admin-forced
 * logout, session timeout). Without this, WordPress sessions survive until the
 * auth cookie expires - up to 14 days after the IdP session ended.
 */
class OIDC_Backchannel_Logout {

	/**
	 * User meta key holding SHA-256 hashes of the IdP session IDs (sid claims).
	 *
	 * One meta row per IdP session (non-unique meta), so logout tokens for any
	 * of a user's concurrent IdP sessions can be correlated. Hashed so raw IdP
	 * session identifiers are never stored in the database; lookups compare
	 * hashes, which is all the logout flow needs.
	 *
	 * @var string
	 */
	const SID_HASH_META_KEY = 'oidc_sid_hash';

	/**
	 * Maximum number of IdP session hashes tracked per user.
	 *
	 * Bounds user-meta growth for IdPs that issue a fresh sid on every login.
	 * When exceeded, older associations are dropped; their sessions can still
	 * be logged out via the logout token's sub claim.
	 *
	 * @var int
	 */
	const MAX_TRACKED_SIDS = 10;

	/**
	 * OIDC Client for logout token validation.
	 *
	 * @var OIDC_Client
	 */
	private OIDC_Client $client;
	/**
	 * Token Manager for clearing stored tokens.
	 *
	 * @var OIDC_Token_Manager
	 */
	private OIDC_Token_Manager $token_manager;

	/**
	 * Initialize the back-channel logout handler.
	 *
	 * @param OIDC_Client        $client        The OIDC client for token validation.
	 * @param OIDC_Token_Manager $token_manager The token manager for cleanup.
	 */
	public function __construct( OIDC_Client $client, OIDC_Token_Manager $token_manager ) {
		$this->client        = $client;
		$this->token_manager = $token_manager;
	}

	/**
	 * Record the IdP session ID for a user at login time.
	 *
	 * Called from the OIDC callback when the ID token carries a sid claim, so a
	 * later logout token containing only sid can be mapped back to the user.
	 * Each sid is stored as its own meta row (appended, not overwritten) so
	 * concurrent IdP sessions - e.g. two browsers - all remain correlated.
	 * Stores both the indexed form (oidc_sid_<hash> meta_key, served by the
	 * meta_key index) and the legacy form (oidc_sid_hash meta_key + meta_value)
	 * for migration/downgrade safety.
	 *
	 * @param int                  $user_id The WordPress user ID.
	 * @param array<string, mixed> $claims  Validated ID token claims.
	 * @return void
	 */
	public static function store_session_id( int $user_id, array $claims ): void {
		if ( empty( $claims['sid'] ) || ! is_string( $claims['sid'] ) ) {
			return;
		}

		$sid          = $claims['sid'];
		$sid_hash     = hash( 'sha256', $sid );
		$indexed_key  = OIDC_User_Index::sid_key( $sid );

		// Already indexed: nothing to do.
		$already_indexed = get_user_meta( $user_id, $indexed_key, true );
		if ( '' !== $already_indexed && false !== $already_indexed && null !== $already_indexed ) {
			return;
		}

		$existing = get_user_meta( $user_id, self::SID_HASH_META_KEY, false );
		$existing = is_array( $existing ) ? $existing : array();

		// Same IdP session already tracked via legacy storage: migrate to indexed and return.
		if ( in_array( $sid_hash, $existing, true ) ) {
			OIDC_User_Index::ensure_sid_index( $user_id, $sid, self::MAX_TRACKED_SIDS );
			return;
		}

		// Bound growth: past the cap, drop all older associations rather than
		// growing forever. Affected sessions remain reachable via the sub claim.
		// Count both legacy and indexed rows so the cap is enforced during migration.
		$indexed_count = self::count_indexed_sids( $user_id );
		$total         = count( $existing ) + ( $indexed_count >= 0 ? $indexed_count : 0 );
		if ( $total >= self::MAX_TRACKED_SIDS ) {
			delete_user_meta( $user_id, self::SID_HASH_META_KEY );
			OIDC_User_Index::delete_sid_indexes( $user_id );
		}

		add_user_meta( $user_id, self::SID_HASH_META_KEY, $sid_hash );
		update_user_meta( $user_id, $indexed_key, '1' );
	}

	/**
	 * Count indexed sid rows for a user.
	 *
	 * @param int $user_id The WordPress user ID.
	 * @return int Count, or -1 if unavailable (e.g. no $wpdb in tests).
	 */
	private static function count_indexed_sids( int $user_id ): int {
		global $wpdb;
		if ( ! isset( $wpdb ) || ! $wpdb instanceof wpdb ) {
			return -1;
		}
		$like = $wpdb->esc_like( OIDC_User_Index::SID_PREFIX ) . '%';
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- indexed count, no caching.
		$count = $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM {$wpdb->usermeta} WHERE user_id = %d AND meta_key LIKE %s",
				$user_id,
				$like
			)
		);
		return null !== $count ? (int) $count : -1;
	}

	/**
	 * Process a back-channel logout request.
	 *
	 * Validates the logout token, resolves the affected user, and destroys all
	 * of their WordPress sessions. Per OIDC Back-Channel Logout 1.0 Section 2.8
	 * the response is 200 on success and 400 for an invalid request.
	 *
	 * @param string $logout_token The raw logout token from the request body.
	 * @return true|WP_Error True if processed, WP_Error (invalid token) otherwise.
	 */
	public function handle_logout_token( string $logout_token ): bool|WP_Error {
		$claims = $this->client->validate_logout_token( $logout_token );
		if ( is_wp_error( $claims ) ) {
			error_log( '[Secure OIDC Login] Back-channel logout token rejected: ' . $claims->get_error_message() );
			return $claims;
		}

		$sub_user = ! empty( $claims['sub'] ) ? $this->get_user_by_subject( (string) $claims['sub'] ) : null;
		$sid_user = ! empty( $claims['sid'] ) ? $this->get_user_by_sid( (string) $claims['sid'] ) : null;

		// SECURITY: If both identifiers are present they must agree; a token whose
		// sub and sid point at different accounts is malformed or mixed up.
		if ( $sub_user && $sid_user && $sub_user->ID !== $sid_user->ID ) {
			error_log( '[Secure OIDC Login] Back-channel logout rejected: sub and sid resolve to different users.' );
			return new WP_Error( 'oidc_error', __( 'Logout token sub and sid identify different users.', 'secure-oidc-login' ) );
		}

		$user = $sub_user ?? $sid_user;

		// No matching user/session: return success without acting. The token was
		// validly signed by the IdP, so this is a session we never had (or already
		// cleaned up) - and a uniform success response avoids confirming which
		// subjects have accounts here (Section 2.8 allows 200 when there is
		// nothing to log out).
		if ( null === $user ) {
			return true;
		}

		$this->terminate_user_sessions( $user->ID );

		error_log(
			sprintf(
				'[Secure OIDC Login] Back-channel logout: terminated sessions for user %d',
				$user->ID
			)
		);

		return true;
	}

	/**
	 * Destroy all WordPress sessions and stored OIDC state for a user.
	 *
	 * The logout token's sid identifies one IdP session, but WordPress sessions
	 * are not mapped one-to-one to IdP sessions, so all WordPress sessions for
	 * the user are destroyed - the conservative reading the spec permits.
	 * delete_user_meta() without a value removes every tracked sid row.
	 *
	 * @param int $user_id The WordPress user ID.
	 * @return void
	 */
	private function terminate_user_sessions( int $user_id ): void {
		$sessions = WP_Session_Tokens::get_instance( $user_id );
		$sessions->destroy_all();

		$this->token_manager->clear_tokens( $user_id );
		delete_user_meta( $user_id, self::SID_HASH_META_KEY );
		OIDC_User_Index::delete_sid_indexes( $user_id );
	}

	/**
	 * Find a WordPress user by their OIDC subject identifier.
	 *
	 * Tries the indexed lookup (meta_key = oidc_subject_<sha256>) first so the
	 * existing meta_key index serves the query; falls back to the legacy
	 * meta_key + meta_value query and lazily creates the indexed row.
	 *
	 * @param string $subject The sub claim value.
	 * @return WP_User|null User object or null if not found.
	 */
	private function get_user_by_subject( string $subject ): ?WP_User {
		$indexed_key = OIDC_User_Index::subject_key( $subject );
		$users       = get_users(
			array(
				'meta_key' => $indexed_key,
				'number'   => 1,
			)
		);
		if ( ! empty( $users ) ) {
			return $users[0];
		}

		// Legacy fallback.
		$users = get_users(
			array(
				'meta_key'   => OIDC_User_Index::LEGACY_SUBJECT_KEY,
				'meta_value' => $subject,
				'number'     => 1,
			)
		);
		if ( ! empty( $users ) ) {
			OIDC_User_Index::ensure_subject_index( (int) $users[0]->ID, $subject );
			return $users[0];
		}

		return null;
	}

	/**
	 * Find a WordPress user by the hash of their IdP session ID.
	 *
	 * Tries the indexed lookup (meta_key = oidc_sid_<sha256(sid)>) first so the
	 * existing meta_key index serves the query; falls back to the legacy
	 * meta_key + meta_value query and lazily creates the indexed row.
	 *
	 * @param string $sid The sid claim value.
	 * @return WP_User|null User object or null if not found.
	 */
	private function get_user_by_sid( string $sid ): ?WP_User {
		$indexed_key = OIDC_User_Index::sid_key( $sid );
		$users       = get_users(
			array(
				'meta_key' => $indexed_key,
				'number'   => 1,
			)
		);
		if ( ! empty( $users ) ) {
			return $users[0];
		}

		// Legacy fallback.
		$users = get_users(
			array(
				'meta_key'   => self::SID_HASH_META_KEY,
				'meta_value' => hash( 'sha256', $sid ),
				'number'     => 1,
			)
		);
		if ( ! empty( $users ) ) {
			OIDC_User_Index::ensure_sid_index( (int) $users[0]->ID, $sid, self::MAX_TRACKED_SIDS );
			return $users[0];
		}

		return null;
	}
}

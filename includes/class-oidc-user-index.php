<?php
declare(strict_types=1);
/**
 * Indexed WordPress user lookups for OIDC identifiers.
 *
 * @package Secure_OIDC_Login
 * @since 1.4.0
 */

// Prevent direct file access
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Resolves WordPress users from OIDC identifiers via indexed meta keys.
 *
 * WordPress indexes wp_usermeta.meta_key but not meta_value, so looking a
 * user up by meta value scans every row sharing the key - one row per OIDC
 * user. On large memberships every SSO login (and every back-channel logout)
 * pays that linear scan. These helpers store the identifier's hash *in the
 * meta key* (e.g. oidc_subject_idx_{sha256(sub)}) so the existing meta_key
 * index serves the lookup regardless of user count.
 *
 * The legacy value-bearing rows (meta_key 'oidc_subject' / 'oidc_sid_hash')
 * remain the authoritative store: they are still written on every login and
 * are what other code reads per-user. The indexed rows only accelerate
 * reverse lookups, and every indexed hit is verified against the legacy row
 * so a stale index row can never resolve the wrong user. Rows created before
 * this class existed are found via a value-scan fallback and indexed lazily
 * on first hit, so no migration step is required and downgrades stay safe.
 */
class OIDC_User_Index {

	/**
	 * Meta key prefix for the subject lookup index.
	 *
	 * Full key: prefix + sha256(subject). Hashing keeps arbitrary-length
	 * subjects within the 255-char meta_key column and avoids storing raw
	 * identifiers in the key. The value carries no information ('1').
	 *
	 * @var string
	 */
	const SUBJECT_KEY_PREFIX = 'oidc_subject_idx_';

	/**
	 * Meta key prefix for the IdP session (sid) lookup index.
	 *
	 * Full key: prefix + sha256(sid) - the same hash the legacy
	 * 'oidc_sid_hash' rows store as their value.
	 *
	 * @var string
	 */
	const SID_KEY_PREFIX = 'oidc_sid_idx_';

	/**
	 * Legacy meta key holding the raw OIDC subject as its value.
	 *
	 * @var string
	 */
	const LEGACY_SUBJECT_META_KEY = 'oidc_subject';

	/**
	 * Build the indexed meta key for an OIDC subject.
	 *
	 * @param string $subject The raw sub claim value.
	 * @return string The indexed meta key.
	 */
	public static function subject_index_key( string $subject ): string {
		return self::SUBJECT_KEY_PREFIX . hash( 'sha256', $subject );
	}

	/**
	 * Build the indexed meta key for a hashed IdP session ID.
	 *
	 * @param string $sid_hash SHA-256 hash of the sid claim value.
	 * @return string The indexed meta key.
	 */
	public static function sid_index_key( string $sid_hash ): string {
		return self::SID_KEY_PREFIX . $sid_hash;
	}

	/**
	 * Find a WordPress user by their OIDC subject identifier.
	 *
	 * Tries the indexed meta key first (served by the meta_key index), then
	 * falls back to the legacy meta_value scan for rows written before the
	 * index existed - lazily indexing the user on a fallback hit.
	 *
	 * @param string $subject The raw sub claim value.
	 * @return WP_User|null User object or null if not found.
	 */
	public static function find_user_by_subject( string $subject ): ?WP_User {
		$indexed = get_users(
			array(
				'meta_key' => self::subject_index_key( $subject ),
				'number'   => 1,
			)
		);

		if ( ! empty( $indexed ) ) {
			$user = $indexed[0];

			// SECURITY: Verify against the authoritative legacy row so a stale
			// index row (e.g. left behind by an older build that relinked the
			// account without touching the index) can never resolve the wrong
			// user.
			if ( get_user_meta( $user->ID, self::LEGACY_SUBJECT_META_KEY, true ) === $subject ) {
				return $user;
			}

			delete_user_meta( $user->ID, self::subject_index_key( $subject ) );
		}

		$users = get_users(
			array(
				'meta_key'   => self::LEGACY_SUBJECT_META_KEY,
				'meta_value' => $subject,
				'number'     => 1,
			)
		);

		if ( empty( $users ) ) {
			return null;
		}

		// Lazy migration: index this user so the next lookup skips the scan.
		update_user_meta( $users[0]->ID, self::subject_index_key( $subject ), '1' );

		return $users[0];
	}

	/**
	 * Store the subject-to-user link (legacy row plus indexed row).
	 *
	 * Mirrors update_user_meta() semantics for the authoritative legacy row:
	 * returns false when that write fails, in which case the index is not
	 * touched. The indexed row itself is best-effort - if it cannot be
	 * written, the value-scan fallback still resolves the user and indexing
	 * is re-attempted on that hit.
	 *
	 * @param int    $user_id The WordPress user ID.
	 * @param string $subject The raw sub claim value.
	 * @return int|bool Result of the legacy meta write (meta ID, true, or false).
	 */
	public static function link_subject( int $user_id, string $subject ): int|bool {
		$previous = get_user_meta( $user_id, self::LEGACY_SUBJECT_META_KEY, true );

		$result = update_user_meta( $user_id, self::LEGACY_SUBJECT_META_KEY, $subject );

		if ( false === $result ) {
			return false;
		}

		// Relinked to a different subject: drop the old index row so the
		// previous subject can no longer resolve to this user.
		if ( is_string( $previous ) && '' !== $previous && $previous !== $subject ) {
			delete_user_meta( $user_id, self::subject_index_key( $previous ) );
		}

		update_user_meta( $user_id, self::subject_index_key( $subject ), '1' );

		return $result;
	}

	/**
	 * Find a WordPress user by the hash of their IdP session ID.
	 *
	 * Same strategy as find_user_by_subject(): indexed key first, verified
	 * against the authoritative legacy rows, then legacy value-scan fallback
	 * with lazy indexing.
	 *
	 * @param string $sid_hash SHA-256 hash of the sid claim value.
	 * @return WP_User|null User object or null if not found.
	 */
	public static function find_user_by_sid_hash( string $sid_hash ): ?WP_User {
		$indexed = get_users(
			array(
				'meta_key' => self::sid_index_key( $sid_hash ),
				'number'   => 1,
			)
		);

		if ( ! empty( $indexed ) ) {
			$user    = $indexed[0];
			$tracked = get_user_meta( $user->ID, OIDC_Backchannel_Logout::SID_HASH_META_KEY, false );

			if ( is_array( $tracked ) && in_array( $sid_hash, $tracked, true ) ) {
				return $user;
			}

			// Stale index row (e.g. session cleanup ran on a build unaware of
			// the index): remove it and fall through to the legacy scan.
			delete_user_meta( $user->ID, self::sid_index_key( $sid_hash ) );
		}

		$users = get_users(
			array(
				'meta_key'   => OIDC_Backchannel_Logout::SID_HASH_META_KEY,
				'meta_value' => $sid_hash,
				'number'     => 1,
			)
		);

		if ( empty( $users ) ) {
			return null;
		}

		update_user_meta( $users[0]->ID, self::sid_index_key( $sid_hash ), '1' );

		return $users[0];
	}

	/**
	 * Create (or re-assert) the index row for a tracked IdP session.
	 *
	 * Idempotent: writing an already-present row is a no-op.
	 *
	 * @param int    $user_id  The WordPress user ID.
	 * @param string $sid_hash SHA-256 hash of the sid claim value.
	 * @return void
	 */
	public static function index_sid( int $user_id, string $sid_hash ): void {
		update_user_meta( $user_id, self::sid_index_key( $sid_hash ), '1' );
	}

	/**
	 * Remove the index row for an IdP session that is no longer tracked.
	 *
	 * @param int    $user_id  The WordPress user ID.
	 * @param string $sid_hash SHA-256 hash of the sid claim value.
	 * @return void
	 */
	public static function unindex_sid( int $user_id, string $sid_hash ): void {
		delete_user_meta( $user_id, self::sid_index_key( $sid_hash ) );
	}
}

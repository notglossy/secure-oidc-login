<?php
declare(strict_types=1);
/**
 * Indexed usermeta helpers for OIDC lookups.
 *
 * @package Secure_OIDC_Login
 * @since 1.3.1
 */

// Prevent direct file access
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Helpers for indexed OIDC usermeta lookups.
 *
 * WordPress indexes wp_usermeta.meta_key but not meta_value, so queries of the
 * form meta_key='oidc_subject' AND meta_value='<sub>' scan all rows sharing the
 * key. This helper stores the lookup hash in the meta_key itself (e.g.
 * oidc_subject_<sha256(sub)>), allowing the lookup to be served by the existing
 * meta_key index without a dedicated table. Legacy meta_value queries remain as
 * a read fallback and are lazily migrated to the indexed form.
 */
class OIDC_User_Index {

	/**
	 * Prefix for the indexed subject meta key.
	 *
	 * @var string
	 */
	const SUBJECT_PREFIX = 'oidc_subject_';

	/**
	 * Legacy subject meta key (meta_key='oidc_subject', meta_value=<sub>).
	 *
	 * @var string
	 */
	const LEGACY_SUBJECT_KEY = 'oidc_subject';

	/**
	 * Legacy sid hash meta key (meta_key='oidc_sid_hash', meta_value=<sha256(sid)>).
	 *
	 * @var string
	 */
	const LEGACY_SID_KEY = 'oidc_sid_hash';

	/**
	 * Prefix for the indexed sid meta key.
	 *
	 * @var string
	 */
	const SID_PREFIX = 'oidc_sid_';

	/**
	 * Build the indexed meta_key for an OIDC subject.
	 *
	 * @param string $subject Raw subject identifier.
	 * @return string Indexed meta_key.
	 */
	public static function subject_key( string $subject ): string {
		return self::SUBJECT_PREFIX . hash( 'sha256', $subject );
	}

	/**
	 * Build the indexed meta_key for an IdP session ID.
	 *
	 * @param string $sid Raw sid claim value.
	 * @return string Indexed meta_key.
	 */
	public static function sid_key( string $sid ): string {
		return self::SID_PREFIX . hash( 'sha256', $sid );
	}

	/**
	 * Ensure the indexed subject row exists for a user.
	 *
	 * Creates the indexed meta row if missing and removes stale subject index
	 * rows if the subject changed (defensive; sub is normally immutable).
	 *
	 * @param int    $user_id The WordPress user ID.
	 * @param string $subject The OIDC subject identifier.
	 * @return void
	 */
	public static function ensure_subject_index( int $user_id, string $subject ): void {
		if ( '' === $subject ) {
			return;
		}
		$expected = self::subject_key( $subject );
		$existing = get_user_meta( $user_id, $expected, true );
		if ( '' !== $existing && false !== $existing && null !== $existing ) {
			self::delete_stale_subject_indexes( $user_id, $expected );
			return;
		}
		update_user_meta( $user_id, $expected, '1' );
		self::delete_stale_subject_indexes( $user_id, $expected );
	}

	/**
	 * Ensure the indexed sid row exists for a user, with cap enforcement.
	 *
	 * Tracks one row per IdP session under an indexed meta_key so logout lookups
	 * are served by the meta_key index. Enforces the per-user sid cap; when the
	 * cap is reached all older sid associations are dropped (remaining sessions
	 * remain reachable via the sub claim).
	 *
	 * @param int    $user_id The WordPress user ID.
	 * @param string $sid     Raw sid claim value.
	 * @param int    $max_tracked Maximum number of sids to track.
	 * @return void
	 */
	public static function ensure_sid_index( int $user_id, string $sid, int $max_tracked = 10 ): void {
		if ( '' === $sid ) {
			return;
		}
		$expected = self::sid_key( $sid );
		$existing_val = get_user_meta( $user_id, $expected, true );
		if ( '' !== $existing_val && false !== $existing_val && null !== $existing_val ) {
			return;
		}

		$count = self::count_sid_indexes( $user_id );
		// Include legacy rows in the cap count during migration so we don't
		// unboundedly grow. If we can't count (no $wpdb), still store.
		if ( $count >= 0 ) {
			$legacy = get_user_meta( $user_id, self::LEGACY_SID_KEY, false );
			$legacy_count = is_array( $legacy ) ? count( $legacy ) : 0;
			$total = $count + $legacy_count;
			if ( $total >= $max_tracked ) {
				self::delete_sid_indexes( $user_id );
				// Also drop legacy rows at cap so growth remains bounded during migration.
				delete_user_meta( $user_id, self::LEGACY_SID_KEY );
			}
		}

		update_user_meta( $user_id, $expected, '1' );
	}

	/**
	 * Count indexed sid rows for a user.
	 *
	 * @param int $user_id The WordPress user ID.
	 * @return int Count, or -1 if counting is unavailable.
	 */
	private static function count_sid_indexes( int $user_id ): int {
		global $wpdb;
		if ( ! isset( $wpdb ) || ! $wpdb instanceof wpdb ) {
			return -1;
		}
		$like = $wpdb->esc_like( self::SID_PREFIX ) . '%';
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
	 * Remove stale indexed subject rows for a user, keeping only the expected key.
	 *
	 * @param int    $user_id      The WordPress user ID.
	 * @param string $expected_key The meta_key that should remain.
	 * @return void
	 */
	private static function delete_stale_subject_indexes( int $user_id, string $expected_key ): void {
		global $wpdb;
		if ( ! isset( $wpdb ) || ! $wpdb instanceof wpdb ) {
			return;
		}
		$like = $wpdb->esc_like( self::SUBJECT_PREFIX ) . '%';
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- indexed cleanup, no caching.
		$wpdb->query(
			$wpdb->prepare(
				"DELETE FROM {$wpdb->usermeta} WHERE user_id = %d AND meta_key LIKE %s AND meta_key != %s",
				$user_id,
				$like,
				$expected_key
			)
		);
	}

	/**
	 * Delete all indexed subject rows for a user.
	 *
	 * @param int $user_id The WordPress user ID.
	 * @return void
	 */
	public static function delete_subject_indexes( int $user_id ): void {
		global $wpdb;
		if ( ! isset( $wpdb ) || ! $wpdb instanceof wpdb ) {
			return;
		}
		$like = $wpdb->esc_like( self::SUBJECT_PREFIX ) . '%';
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$wpdb->query(
			$wpdb->prepare(
				"DELETE FROM {$wpdb->usermeta} WHERE user_id = %d AND meta_key LIKE %s",
				$user_id,
				$like
			)
		);
	}

	/**
	 * Delete all indexed sid rows for a user.
	 *
	 * @param int $user_id The WordPress user ID.
	 * @return void
	 */
	public static function delete_sid_indexes( int $user_id ): void {
		global $wpdb;
		if ( ! isset( $wpdb ) || ! $wpdb instanceof wpdb ) {
			return;
		}
		$like = $wpdb->esc_like( self::SID_PREFIX ) . '%';
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$wpdb->query(
			$wpdb->prepare(
				"DELETE FROM {$wpdb->usermeta} WHERE user_id = %d AND meta_key LIKE %s",
				$user_id,
				$like
			)
		);
	}
}

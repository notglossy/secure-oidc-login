<?php
/**
 * Tests for OIDC_User_Index class.
 *
 * @package SecureOIDCLogin\Tests\Unit\User
 */

declare(strict_types=1);

namespace SecureOIDCLogin\Tests\Unit\User;

use Brain\Monkey\Functions;
use OIDC_User_Index;
use SecureOIDCLogin\Tests\OIDCTestCase;
use WP_User;

/**
 * Tests for the OIDC_User_Index indexed lookup helpers.
 *
 * @covers OIDC_User_Index
 */
class OIDCUserIndexTest extends OIDCTestCase
{
    /**
     * Build a WP_User with the given ID.
     *
     * @param int $id The user ID.
     * @return WP_User The user object.
     */
    private function makeUser(int $id): WP_User
    {
        $user = new WP_User($id, 'user' . $id, 'user' . $id . '@example.com');
        return $user;
    }

    /**
     * Test subject_index_key embeds the SHA-256 of the subject in the meta key.
     */
    public function testSubjectIndexKeyEmbedsSubjectHash(): void
    {
        $this->assertSame(
            'oidc_subject_idx_' . hash('sha256', 'user-123-abc'),
            OIDC_User_Index::subject_index_key('user-123-abc')
        );
    }

    /**
     * Test sid_index_key embeds the already-hashed sid in the meta key.
     */
    public function testSidIndexKeyEmbedsSidHash(): void
    {
        $sid_hash = hash('sha256', 'idp-session-1');

        $this->assertSame('oidc_sid_idx_' . $sid_hash, OIDC_User_Index::sid_index_key($sid_hash));
    }

    /**
     * Test find_user_by_subject returns a verified indexed hit without
     * falling back to the legacy meta_value scan.
     */
    public function testFindUserBySubjectReturnsVerifiedIndexedHit(): void
    {
        $user = $this->makeUser(42);
        $queried_keys = [];

        Functions\when('get_users')->alias(function ($args) use ($user, &$queried_keys) {
            $queried_keys[] = $args['meta_key'];
            return OIDC_User_Index::subject_index_key('user-123-abc') === $args['meta_key'] ? [$user] : [];
        });
        Functions\when('get_user_meta')->alias(function ($user_id, $key, $single = false) {
            return 'oidc_subject' === $key ? 'user-123-abc' : [];
        });

        $result = OIDC_User_Index::find_user_by_subject('user-123-abc');

        $this->assertSame($user, $result);
        $this->assertSame(
            [OIDC_User_Index::subject_index_key('user-123-abc')],
            $queried_keys,
            'A verified indexed hit must not trigger the legacy meta_value scan'
        );
    }

    /**
     * Test find_user_by_subject rejects a stale indexed row whose user is
     * linked to a different subject, deletes it, and uses the legacy scan.
     */
    public function testFindUserBySubjectRejectsStaleIndexedRow(): void
    {
        $stale_user = $this->makeUser(7);
        $real_user = $this->makeUser(42);
        $deleted = [];

        Functions\when('get_users')->alias(function ($args) use ($stale_user, $real_user) {
            if (OIDC_User_Index::subject_index_key('user-123-abc') === $args['meta_key']) {
                return [$stale_user];
            }
            if ('oidc_subject' === $args['meta_key'] && 'user-123-abc' === ($args['meta_value'] ?? null)) {
                return [$real_user];
            }
            return [];
        });
        // The stale user was relinked to a different subject at some point.
        Functions\when('get_user_meta')->alias(function ($user_id, $key, $single = false) {
            return 'oidc_subject' === $key ? 'someone-else' : [];
        });
        Functions\when('delete_user_meta')->alias(function ($user_id, $key) use (&$deleted) {
            $deleted[] = [$user_id, $key];
            return true;
        });
        Functions\when('update_user_meta')->justReturn(true);

        $result = OIDC_User_Index::find_user_by_subject('user-123-abc');

        $this->assertSame($real_user, $result);
        $this->assertContains(
            [7, OIDC_User_Index::subject_index_key('user-123-abc')],
            $deleted,
            'The stale indexed row must be removed'
        );
    }

    /**
     * Test find_user_by_subject falls back to the legacy meta_value scan and
     * lazily indexes the user it finds.
     */
    public function testFindUserBySubjectLazilyIndexesLegacyHit(): void
    {
        $user = $this->makeUser(42);
        $indexed = [];

        Functions\when('get_users')->alias(function ($args) use ($user) {
            if ('oidc_subject' === $args['meta_key'] && 'user-123-abc' === ($args['meta_value'] ?? null)) {
                return [$user];
            }
            return [];
        });
        Functions\when('update_user_meta')->alias(function ($user_id, $key, $value) use (&$indexed) {
            $indexed[] = [$user_id, $key, $value];
            return true;
        });

        $result = OIDC_User_Index::find_user_by_subject('user-123-abc');

        $this->assertSame($user, $result);
        $this->assertSame(
            [[42, OIDC_User_Index::subject_index_key('user-123-abc'), '1']],
            $indexed
        );
    }

    /**
     * Test find_user_by_subject returns null when neither the index nor the
     * legacy rows match.
     */
    public function testFindUserBySubjectReturnsNullOnMiss(): void
    {
        Functions\when('get_users')->justReturn([]);

        $this->assertNull(OIDC_User_Index::find_user_by_subject('unknown-subject'));
    }

    /**
     * Test link_subject writes the legacy row and the indexed row.
     */
    public function testLinkSubjectWritesLegacyAndIndexedRows(): void
    {
        $updated = [];

        Functions\when('get_user_meta')->justReturn('');
        Functions\when('update_user_meta')->alias(function ($user_id, $key, $value) use (&$updated) {
            $updated[] = [$user_id, $key, $value];
            return true;
        });

        $result = OIDC_User_Index::link_subject(42, 'user-123-abc');

        $this->assertTrue($result);
        $this->assertSame(
            [
                [42, 'oidc_subject', 'user-123-abc'],
                [42, OIDC_User_Index::subject_index_key('user-123-abc'), '1'],
            ],
            $updated
        );
    }

    /**
     * Test link_subject drops the previous subject's indexed row when the
     * user is relinked to a different subject.
     */
    public function testLinkSubjectRemovesPreviousSubjectIndex(): void
    {
        $deleted = [];

        Functions\when('get_user_meta')->justReturn('old-subject');
        Functions\when('update_user_meta')->justReturn(true);
        Functions\when('delete_user_meta')->alias(function ($user_id, $key) use (&$deleted) {
            $deleted[] = [$user_id, $key];
            return true;
        });

        $result = OIDC_User_Index::link_subject(42, 'new-subject');

        $this->assertTrue($result);
        $this->assertSame(
            [[42, OIDC_User_Index::subject_index_key('old-subject')]],
            $deleted
        );
    }

    /**
     * Test link_subject treats an unchanged-value no-op as success.
     *
     * update_user_meta() returns false when the stored value already equals
     * the new one, not only on write failure. An idempotent re-link (e.g.
     * two concurrent first logins linking the same account) must succeed
     * and still ensure the indexed row exists.
     */
    public function testLinkSubjectTreatsUnchangedSubjectAsSuccess(): void
    {
        $updated = [];
        $deleted = false;

        Functions\when('get_user_meta')->justReturn('user-123-abc');
        // WP reports an unchanged value as false for every write here.
        Functions\when('update_user_meta')->alias(function ($user_id, $key, $value) use (&$updated) {
            $updated[] = $key;
            return false;
        });
        Functions\when('delete_user_meta')->alias(function () use (&$deleted) {
            $deleted = true;
            return true;
        });

        $result = OIDC_User_Index::link_subject(42, 'user-123-abc');

        $this->assertTrue($result);
        $this->assertSame(
            ['oidc_subject', OIDC_User_Index::subject_index_key('user-123-abc')],
            $updated,
            'The indexed row must still be asserted on an idempotent re-link'
        );
        $this->assertFalse($deleted);
    }

    /**
     * Test link_subject propagates a failed legacy write without touching
     * the index.
     */
    public function testLinkSubjectReturnsFalseWhenLegacyWriteFails(): void
    {
        $update_calls = 0;
        $deleted = false;

        Functions\when('get_user_meta')->justReturn('old-subject');
        Functions\when('update_user_meta')->alias(function () use (&$update_calls) {
            $update_calls++;
            return false;
        });
        Functions\when('delete_user_meta')->alias(function () use (&$deleted) {
            $deleted = true;
            return true;
        });

        $result = OIDC_User_Index::link_subject(42, 'new-subject');

        $this->assertFalse($result);
        $this->assertSame(1, $update_calls, 'The index row must not be written when the legacy write fails');
        $this->assertFalse($deleted);
    }

    /**
     * Test find_user_by_sid_hash returns an indexed hit confirmed by the
     * legacy tracked hashes.
     */
    public function testFindUserBySidHashReturnsVerifiedIndexedHit(): void
    {
        $user = $this->makeUser(7);
        $sid_hash = hash('sha256', 'idp-session-1');
        $queried_keys = [];

        Functions\when('get_users')->alias(function ($args) use ($user, $sid_hash, &$queried_keys) {
            $queried_keys[] = $args['meta_key'];
            return OIDC_User_Index::sid_index_key($sid_hash) === $args['meta_key'] ? [$user] : [];
        });
        Functions\when('get_user_meta')->alias(function ($user_id, $key, $single = false) use ($sid_hash) {
            return 'oidc_sid_hash' === $key ? [$sid_hash] : [];
        });

        $result = OIDC_User_Index::find_user_by_sid_hash($sid_hash);

        $this->assertSame($user, $result);
        $this->assertSame([OIDC_User_Index::sid_index_key($sid_hash)], $queried_keys);
    }

    /**
     * Test find_user_by_sid_hash removes a stale indexed row (no matching
     * tracked hash) and falls back to the legacy scan.
     */
    public function testFindUserBySidHashRejectsStaleIndexedRow(): void
    {
        $stale_user = $this->makeUser(7);
        $sid_hash = hash('sha256', 'idp-session-1');
        $deleted = [];

        Functions\when('get_users')->alias(function ($args) use ($stale_user, $sid_hash) {
            return OIDC_User_Index::sid_index_key($sid_hash) === $args['meta_key'] ? [$stale_user] : [];
        });
        // The user no longer tracks this session (cleanup ran on an older build).
        Functions\when('get_user_meta')->justReturn([]);
        Functions\when('delete_user_meta')->alias(function ($user_id, $key) use (&$deleted) {
            $deleted[] = [$user_id, $key];
            return true;
        });

        $result = OIDC_User_Index::find_user_by_sid_hash($sid_hash);

        $this->assertNull($result);
        $this->assertSame([[7, OIDC_User_Index::sid_index_key($sid_hash)]], $deleted);
    }

    /**
     * Test find_user_by_sid_hash falls back to the legacy meta_value scan
     * and lazily indexes the user it finds.
     */
    public function testFindUserBySidHashLazilyIndexesLegacyHit(): void
    {
        $user = $this->makeUser(7);
        $sid_hash = hash('sha256', 'idp-session-1');
        $indexed = [];

        Functions\when('get_users')->alias(function ($args) use ($user, $sid_hash) {
            if ('oidc_sid_hash' === $args['meta_key'] && $sid_hash === ($args['meta_value'] ?? null)) {
                return [$user];
            }
            return [];
        });
        Functions\when('update_user_meta')->alias(function ($user_id, $key, $value) use (&$indexed) {
            $indexed[] = [$user_id, $key, $value];
            return true;
        });

        $result = OIDC_User_Index::find_user_by_sid_hash($sid_hash);

        $this->assertSame($user, $result);
        $this->assertSame([[7, OIDC_User_Index::sid_index_key($sid_hash), '1']], $indexed);
    }

    /**
     * Test find_user_by_sid_hash returns null when nothing matches.
     */
    public function testFindUserBySidHashReturnsNullOnMiss(): void
    {
        Functions\when('get_users')->justReturn([]);

        $this->assertNull(OIDC_User_Index::find_user_by_sid_hash(hash('sha256', 'unknown-session')));
    }

    /**
     * Test index_sid and unindex_sid maintain the indexed row for a session.
     */
    public function testIndexAndUnindexSidMaintainIndexedRow(): void
    {
        $sid_hash = hash('sha256', 'idp-session-1');
        $updated = [];
        $deleted = [];

        Functions\when('update_user_meta')->alias(function ($user_id, $key, $value) use (&$updated) {
            $updated[] = [$user_id, $key, $value];
            return true;
        });
        Functions\when('delete_user_meta')->alias(function ($user_id, $key) use (&$deleted) {
            $deleted[] = [$user_id, $key];
            return true;
        });

        OIDC_User_Index::index_sid(7, $sid_hash);
        OIDC_User_Index::unindex_sid(7, $sid_hash);

        $this->assertSame([[7, OIDC_User_Index::sid_index_key($sid_hash), '1']], $updated);
        $this->assertSame([[7, OIDC_User_Index::sid_index_key($sid_hash)]], $deleted);
    }
}

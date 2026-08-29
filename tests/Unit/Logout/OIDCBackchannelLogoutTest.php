<?php
/**
 * Tests for OIDC_Backchannel_Logout class.
 *
 * @package SecureOIDCLogin\Tests\Unit\Logout
 */

declare(strict_types=1);

namespace SecureOIDCLogin\Tests\Unit\Logout;

use Brain\Monkey\Functions;
use Mockery;
use OIDC_Backchannel_Logout;
use OIDC_Client;
use OIDC_Token_Manager;
use SecureOIDCLogin\Tests\OIDCTestCase;
use WP_Error;
use WP_Session_Tokens;
use WP_User;

/**
 * Tests for the OIDC_Backchannel_Logout class.
 *
 * @covers OIDC_Backchannel_Logout
 */
class OIDCBackchannelLogoutTest extends OIDCTestCase
{
    /**
     * Mock OIDC_Client.
     *
     * @var OIDC_Client|Mockery\MockInterface
     */
    private $client;

    /**
     * Mock OIDC_Token_Manager.
     *
     * @var OIDC_Token_Manager|Mockery\MockInterface
     */
    private $token_manager;

    /**
     * Handler under test.
     *
     * @var OIDC_Backchannel_Logout
     */
    private OIDC_Backchannel_Logout $handler;

    /**
     * Set up test environment.
     */
    protected function setUp(): void
    {
        parent::setUp();

        WP_Session_Tokens::reset();

        $this->client = Mockery::mock(OIDC_Client::class);
        $this->token_manager = Mockery::mock(OIDC_Token_Manager::class);

        $this->handler = new OIDC_Backchannel_Logout($this->client, $this->token_manager);
    }

    /**
     * Build a WP_User with the given ID.
     *
     * @param int $id The user ID.
     * @return WP_User The user object.
     */
    private function makeUser(int $id): WP_User
    {
        $user = new WP_User();
        $user->ID = $id;
        return $user;
    }

    /**
     * Valid logout token claims identifying a user by sub.
     *
     * @param array<string, mixed> $overrides Claims to add or replace.
     * @return array<string, mixed> Logout token claims.
     */
    private function logoutClaims(array $overrides = []): array
    {
        return array_merge(
            [
                'iss' => 'https://idp.example.com',
                'aud' => 'test-client-id',
                'jti' => 'jti-1',
                'events' => ['http://schemas.openid.net/event/backchannel-logout' => []],
                'sub' => 'user-123-abc',
            ],
            $overrides
        );
    }

    /**
     * Test store_session_id stores the SHA-256 hash of the sid claim as a new meta row.
     */
    public function testStoreSessionIdStoresHashedSid(): void
    {
        $added = [];
        $updated = [];
        Functions\when('get_user_meta')->alias(function ($uid, $key, $single) {
            // Indexed lookup misses, legacy row set empty
            return $single ? '' : [];
        });
        Functions\when('add_user_meta')->alias(function ($user_id, $key, $value) use (&$added) {
            $added[$key] = $value;
            return 1;
        });
        Functions\when('update_user_meta')->alias(function ($uid, $key, $value) use (&$updated) {
            $updated[$key] = $value;
            return true;
        });

        OIDC_Backchannel_Logout::store_session_id(42, ['sid' => 'idp-session-1']);

        $this->assertSame(hash('sha256', 'idp-session-1'), $added['oidc_sid_hash']);
        $this->assertSame('1', $updated[\OIDC_User_Index::sid_key('idp-session-1')]);
    }

    /**
     * Test store_session_id appends a second concurrent session instead of overwriting.
     */
    public function testStoreSessionIdAppendsConcurrentSessions(): void
    {
        $added = [];
        $updated = [];
        $deleted = false;

        // A different IdP session is already tracked via legacy row
        Functions\when('get_user_meta')->alias(function ($uid, $key, $single) {
            if ($key === 'oidc_sid_hash') {
                return [hash('sha256', 'idp-session-1')];
            }
            // Indexed miss for idp-session-2
            return $single ? '' : [];
        });
        Functions\when('add_user_meta')->alias(function ($user_id, $key, $value) use (&$added) {
            $added[] = $value;
            return 2;
        });
        Functions\when('update_user_meta')->alias(function ($uid, $key, $value) use (&$updated) {
            $updated[$key] = $value;
            return true;
        });
        Functions\when('delete_user_meta')->alias(function () use (&$deleted) {
            $deleted = true;
            return true;
        });

        OIDC_Backchannel_Logout::store_session_id(42, ['sid' => 'idp-session-2']);

        $this->assertSame([hash('sha256', 'idp-session-2')], $added);
        $this->assertSame('1', $updated[\OIDC_User_Index::sid_key('idp-session-2')]);
        $this->assertFalse($deleted, 'Existing session hashes must not be removed below the cap');
    }

    /**
     * Test store_session_id does not duplicate an already-tracked session.
     */
    public function testStoreSessionIdSkipsDuplicateSid(): void
    {
        $added = false;
        $updated = false;
        Functions\when('get_user_meta')->alias(function ($uid, $key, $single) {
            // Indexed hit means duplicate
            if (strpos($key, \OIDC_User_Index::SID_PREFIX) === 0) {
                return '1';
            }
            return $single ? '' : [hash('sha256', 'idp-session-1')];
        });
        Functions\when('add_user_meta')->alias(function () use (&$added) {
            $added = true;
            return 1;
        });
        Functions\when('update_user_meta')->alias(function () use (&$updated) {
            $updated = true;
            return true;
        });

        OIDC_Backchannel_Logout::store_session_id(42, ['sid' => 'idp-session-1']);

        $this->assertFalse($added);
        $this->assertFalse($updated);
    }

    /**
     * Test store_session_id resets tracked hashes once the cap is reached.
     */
    public function testStoreSessionIdResetsAtCap(): void
    {
        $existing = [];
        for ($i = 0; $i < OIDC_Backchannel_Logout::MAX_TRACKED_SIDS; $i++) {
            $existing[] = hash('sha256', "idp-session-{$i}");
        }

        $deleted = false;
        $added = [];
        $updated = [];

        Functions\when('get_user_meta')->alias(function ($uid, $key, $single) use ($existing) {
            if ($key === 'oidc_sid_hash') {
                return $existing;
            }
            return $single ? '' : [];
        });
        Functions\when('delete_user_meta')->alias(function () use (&$deleted) {
            $deleted = true;
            return true;
        });
        Functions\when('add_user_meta')->alias(function ($user_id, $key, $value) use (&$added) {
            $added[] = $value;
            return 1;
        });
        Functions\when('update_user_meta')->alias(function ($uid, $key, $value) use (&$updated) {
            $updated[$key] = $value;
            return true;
        });

        OIDC_Backchannel_Logout::store_session_id(42, ['sid' => 'idp-session-new']);

        $this->assertTrue($deleted);
        $this->assertSame([hash('sha256', 'idp-session-new')], $added);
        $this->assertSame('1', $updated[\OIDC_User_Index::sid_key('idp-session-new')]);
    }

    /**
     * Test store_session_id does nothing without a sid claim.
     */
    public function testStoreSessionIdSkipsWithoutSid(): void
    {
        $called = false;
        Functions\when('get_user_meta')->justReturn([]);
        Functions\when('add_user_meta')->alias(function () use (&$called) {
            $called = true;
            return 1;
        });
        Functions\when('update_user_meta')->alias(function () use (&$called) {
            $called = true;
            return true;
        });

        OIDC_Backchannel_Logout::store_session_id(42, ['sub' => 'user-123-abc']);

        $this->assertFalse($called);
    }

    /**
     * Test handle_logout_token propagates token validation errors with no side effects.
     */
    public function testHandleLogoutTokenPropagatesValidationError(): void
    {
        $error = new WP_Error('oidc_error', 'Invalid logout token issuer.');
        $meta_deleted = false;

        Functions\when('delete_user_meta')->alias(function () use (&$meta_deleted) {
            $meta_deleted = true;
            return true;
        });

        $this->client
            ->shouldReceive('validate_logout_token')
            ->with('bad.token.here')
            ->once()
            ->andReturn($error);

        $this->token_manager->shouldNotReceive('clear_tokens');

        $result = $this->handler->handle_logout_token('bad.token.here');

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertSame([], WP_Session_Tokens::$destroyed_user_ids);
        $this->assertFalse($meta_deleted);
    }

    /**
     * Test handle_logout_token terminates sessions for a user matched by sub.
     */
    public function testHandleLogoutTokenTerminatesSessionsBySub(): void
    {
        $user = $this->makeUser(42);

        $this->client
            ->shouldReceive('validate_logout_token')
            ->once()
            ->andReturn($this->logoutClaims());

        // Lookup by indexed or legacy subject meta finds the user
        Functions\when('get_users')->alias(function ($args) use ($user) {
            $indexed = \OIDC_User_Index::subject_key('user-123-abc');
            if ($args['meta_key'] === $indexed || $args['meta_key'] === 'oidc_subject') {
                return [$user];
            }
            return [];
        });

        $deleted_meta = [];
        Functions\when('delete_user_meta')->alias(function ($user_id, $key) use (&$deleted_meta) {
            $deleted_meta[] = [$user_id, $key];
            return true;
        });

        $this->token_manager
            ->shouldReceive('clear_tokens')
            ->with(42)
            ->once();

        $result = $this->handler->handle_logout_token('valid.token.here');

        $this->assertTrue($result);
        $this->assertSame([42], WP_Session_Tokens::$destroyed_user_ids);
        $this->assertContains([42, 'oidc_sid_hash'], $deleted_meta);
    }

    /**
     * Test handle_logout_token terminates sessions for a user matched by sid only.
     */
    public function testHandleLogoutTokenTerminatesSessionsBySid(): void
    {
        $user = $this->makeUser(7);
        $claims = $this->logoutClaims(['sid' => 'idp-session-1']);
        unset($claims['sub']);

        $this->client
            ->shouldReceive('validate_logout_token')
            ->once()
            ->andReturn($claims);

        Functions\when('get_users')->alias(function ($args) use ($user) {
            $indexed = \OIDC_User_Index::sid_key('idp-session-1');
            if ($args['meta_key'] === $indexed) {
                return [$user];
            }
            if ('oidc_sid_hash' === $args['meta_key']
                && hash('sha256', 'idp-session-1') === ($args['meta_value'] ?? null)) {
                return [$user];
            }
            return [];
        });

        Functions\when('delete_user_meta')->justReturn(true);

        $this->token_manager
            ->shouldReceive('clear_tokens')
            ->with(7)
            ->once();

        $result = $this->handler->handle_logout_token('valid.token.here');

        $this->assertTrue($result);
        $this->assertSame([7], WP_Session_Tokens::$destroyed_user_ids);
    }

    /**
     * Test handle_logout_token rejects a token whose sub and sid identify different users.
     */
    public function testHandleLogoutTokenRejectsSubSidUserMismatch(): void
    {
        $sub_user = $this->makeUser(42);
        $sid_user = $this->makeUser(99);
        $meta_deleted = false;

        Functions\when('delete_user_meta')->alias(function () use (&$meta_deleted) {
            $meta_deleted = true;
            return true;
        });

        $this->client
            ->shouldReceive('validate_logout_token')
            ->once()
            ->andReturn($this->logoutClaims(['sid' => 'idp-session-1']));

        Functions\when('get_users')->alias(function ($args) use ($sub_user, $sid_user) {
            $sub_key = \OIDC_User_Index::subject_key('user-123-abc');
            $sid_key = \OIDC_User_Index::sid_key('idp-session-1');
            if ($args['meta_key'] === $sub_key || $args['meta_key'] === 'oidc_subject') {
                return [$sub_user];
            }
            if ($args['meta_key'] === $sid_key || $args['meta_key'] === 'oidc_sid_hash') {
                return [$sid_user];
            }
            return [$sid_user];
        });

        $this->token_manager->shouldNotReceive('clear_tokens');

        $result = $this->handler->handle_logout_token('valid.token.here');

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertSame([], WP_Session_Tokens::$destroyed_user_ids);
        $this->assertFalse($meta_deleted);
    }

    /**
     * Test handle_logout_token succeeds quietly when no user matches.
     *
     * A validly-signed token for an unknown subject returns 200 to avoid
     * confirming which subjects have accounts on this site.
     */
    public function testHandleLogoutTokenSucceedsWhenNoUserMatches(): void
    {
        $this->client
            ->shouldReceive('validate_logout_token')
            ->once()
            ->andReturn($this->logoutClaims());

        Functions\when('get_users')->justReturn([]);

        $this->token_manager->shouldNotReceive('clear_tokens');

        $result = $this->handler->handle_logout_token('valid.token.here');

        $this->assertTrue($result);
        $this->assertSame([], WP_Session_Tokens::$destroyed_user_ids);
    }
}

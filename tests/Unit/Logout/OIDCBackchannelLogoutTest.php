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
        Functions\when('get_user_meta')->justReturn([]);
        Functions\when('add_user_meta')->alias(function ($user_id, $key, $value) use (&$added) {
            $added[$key] = $value;
            return 1;
        });

        OIDC_Backchannel_Logout::store_session_id(42, ['sid' => 'idp-session-1']);

        $this->assertSame(hash('sha256', 'idp-session-1'), $added['oidc_sid_hash']);
    }

    /**
     * Test store_session_id appends a second concurrent session instead of overwriting.
     */
    public function testStoreSessionIdAppendsConcurrentSessions(): void
    {
        $added = [];
        $deleted = false;

        // A different IdP session is already tracked
        Functions\when('get_user_meta')->justReturn([hash('sha256', 'idp-session-1')]);
        Functions\when('add_user_meta')->alias(function ($user_id, $key, $value) use (&$added) {
            $added[] = $value;
            return 2;
        });
        Functions\when('delete_user_meta')->alias(function () use (&$deleted) {
            $deleted = true;
            return true;
        });

        OIDC_Backchannel_Logout::store_session_id(42, ['sid' => 'idp-session-2']);

        $this->assertSame([hash('sha256', 'idp-session-2')], $added);
        $this->assertFalse($deleted, 'Existing session hashes must not be removed below the cap');
    }

    /**
     * Test store_session_id does not duplicate an already-tracked session.
     */
    public function testStoreSessionIdSkipsDuplicateSid(): void
    {
        $added = false;
        Functions\when('get_user_meta')->justReturn([hash('sha256', 'idp-session-1')]);
        Functions\when('add_user_meta')->alias(function () use (&$added) {
            $added = true;
            return 1;
        });

        OIDC_Backchannel_Logout::store_session_id(42, ['sid' => 'idp-session-1']);

        $this->assertFalse($added);
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

        Functions\when('get_user_meta')->justReturn($existing);
        Functions\when('delete_user_meta')->alias(function () use (&$deleted) {
            $deleted = true;
            return true;
        });
        Functions\when('add_user_meta')->alias(function ($user_id, $key, $value) use (&$added) {
            $added[] = $value;
            return 1;
        });

        OIDC_Backchannel_Logout::store_session_id(42, ['sid' => 'idp-session-new']);

        $this->assertTrue($deleted);
        $this->assertSame([hash('sha256', 'idp-session-new')], $added);
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

        // Lookup by oidc_subject meta finds the user
        Functions\when('get_users')->alias(function ($args) use ($user) {
            return 'oidc_subject' === $args['meta_key'] ? [$user] : [];
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
            if ('oidc_sid_hash' === $args['meta_key']
                && hash('sha256', 'idp-session-1') === $args['meta_value']) {
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
            return 'oidc_subject' === $args['meta_key'] ? [$sub_user] : [$sid_user];
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

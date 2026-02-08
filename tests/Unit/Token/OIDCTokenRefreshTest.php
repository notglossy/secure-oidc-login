<?php
/**
 * Tests for OIDC_Token_Refresh class.
 *
 * @package SecureOIDCLogin\Tests\Unit\Token
 */

declare(strict_types=1);

namespace SecureOIDCLogin\Tests\Unit\Token;

use Brain\Monkey\Functions;
use Mockery;
use OIDC_Client;
use OIDC_Token_Manager;
use OIDC_Token_Refresh;
use SecureOIDCLogin\Tests\OIDCTestCase;
use WP_Error;

/**
 * Tests for the OIDC_Token_Refresh class.
 *
 * @covers OIDC_Token_Refresh
 */
class OIDCTokenRefreshTest extends OIDCTestCase
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
     * Token Refresh instance under test.
     *
     * @var OIDC_Token_Refresh
     */
    private OIDC_Token_Refresh $refresh;

    /**
     * Set up test environment.
     */
    protected function setUp(): void
    {
        parent::setUp();

        // Stub wp_salt for encryption
        Functions\when('wp_salt')->justReturn('test-salt-value-for-unit-testing');

        $this->client = Mockery::mock(OIDC_Client::class);
        $this->token_manager = Mockery::mock(OIDC_Token_Manager::class);

        $this->refresh = new OIDC_Token_Refresh($this->client, $this->token_manager);
    }

    /**
     * Test maybe_refresh skips when auto-refresh is disabled.
     */
    public function testMaybeRefreshSkipsWhenDisabled(): void
    {
        Functions\when('get_option')->justReturn([
            'enable_auto_token_refresh' => false,
        ]);

        $result = $this->refresh->maybe_refresh(123);

        $this->assertTrue($result);
    }

    /**
     * Test maybe_refresh skips when no refresh token exists.
     */
    public function testMaybeRefreshSkipsWhenNoRefreshToken(): void
    {
        Functions\when('get_option')->justReturn([
            'enable_auto_token_refresh' => true,
        ]);

        $this->token_manager
            ->shouldReceive('has_refresh_token')
            ->with(123)
            ->once()
            ->andReturn(false);

        $result = $this->refresh->maybe_refresh(123);

        $this->assertTrue($result);
    }

    /**
     * Test maybe_refresh skips when token is not expired.
     */
    public function testMaybeRefreshSkipsWhenNotExpired(): void
    {
        Functions\when('get_option')->justReturn([
            'enable_auto_token_refresh' => true,
            'token_refresh_buffer' => 300,
        ]);

        $this->token_manager
            ->shouldReceive('has_refresh_token')
            ->with(123)
            ->once()
            ->andReturn(true);

        $this->token_manager
            ->shouldReceive('is_token_expired')
            ->with(123, 300)
            ->once()
            ->andReturn(false);

        $result = $this->refresh->maybe_refresh(123);

        $this->assertTrue($result);
    }

    /**
     * Test maybe_refresh triggers when token is expiring.
     */
    public function testMaybeRefreshTriggersWhenExpiring(): void
    {
        $user_id = 123;
        $old_refresh_token = 'old-refresh-token';
        $new_tokens = [
            'access_token' => 'new-access-token',
            'refresh_token' => 'new-refresh-token',
            'expires_in' => 3600,
        ];

        Functions\when('get_option')->justReturn([
            'enable_auto_token_refresh' => true,
            'token_refresh_buffer' => 300,
            'enforce_refresh_token_rotation' => false,
        ]);

        $this->token_manager
            ->shouldReceive('has_refresh_token')
            ->with($user_id)
            ->once()
            ->andReturn(true);

        $this->token_manager
            ->shouldReceive('is_token_expired')
            ->with($user_id, 300)
            ->once()
            ->andReturn(true);

        $this->token_manager
            ->shouldReceive('get_refresh_token')
            ->with($user_id)
            ->once()
            ->andReturn($old_refresh_token);

        $this->client
            ->shouldReceive('refresh_token')
            ->with($old_refresh_token)
            ->once()
            ->andReturn($new_tokens);

        $this->token_manager
            ->shouldReceive('was_refresh_token_rotated')
            ->with($user_id, 'new-refresh-token')
            ->once()
            ->andReturn(true);

        $this->token_manager
            ->shouldReceive('store_tokens')
            ->with($user_id, $new_tokens)
            ->once()
            ->andReturn(true);

        $result = $this->refresh->maybe_refresh($user_id);

        $this->assertTrue($result);
    }

    /**
     * Test refresh success.
     */
    public function testRefreshSuccess(): void
    {
        $user_id = 123;
        $old_refresh_token = 'old-refresh-token';
        $new_tokens = [
            'access_token' => 'new-access-token',
            'refresh_token' => 'new-refresh-token',
            'expires_in' => 3600,
        ];

        Functions\when('get_option')->justReturn([
            'enforce_refresh_token_rotation' => false,
        ]);

        $this->token_manager
            ->shouldReceive('get_refresh_token')
            ->with($user_id)
            ->once()
            ->andReturn($old_refresh_token);

        $this->client
            ->shouldReceive('refresh_token')
            ->with($old_refresh_token)
            ->once()
            ->andReturn($new_tokens);

        $this->token_manager
            ->shouldReceive('was_refresh_token_rotated')
            ->with($user_id, 'new-refresh-token')
            ->once()
            ->andReturn(true);

        $this->token_manager
            ->shouldReceive('store_tokens')
            ->with($user_id, $new_tokens)
            ->once()
            ->andReturn(true);

        $result = $this->refresh->refresh($user_id);

        $this->assertTrue($result);
    }

    /**
     * Test refresh with rotation.
     */
    public function testRefreshWithRotation(): void
    {
        $user_id = 123;
        $old_refresh_token = 'old-refresh-token';
        $new_tokens = [
            'access_token' => 'new-access-token',
            'refresh_token' => 'rotated-refresh-token',
            'expires_in' => 3600,
        ];

        Functions\when('get_option')->justReturn([
            'enforce_refresh_token_rotation' => true,
        ]);

        $this->token_manager
            ->shouldReceive('get_refresh_token')
            ->with($user_id)
            ->once()
            ->andReturn($old_refresh_token);

        $this->client
            ->shouldReceive('refresh_token')
            ->with($old_refresh_token)
            ->once()
            ->andReturn($new_tokens);

        $this->token_manager
            ->shouldReceive('was_refresh_token_rotated')
            ->with($user_id, 'rotated-refresh-token')
            ->once()
            ->andReturn(true);

        $this->token_manager
            ->shouldReceive('store_tokens')
            ->with($user_id, $new_tokens)
            ->once()
            ->andReturn(true);

        $result = $this->refresh->refresh($user_id);

        $this->assertTrue($result);
    }

    /**
     * Test refresh fails without rotation when enforced.
     */
    public function testRefreshFailsWithoutRotationWhenEnforced(): void
    {
        $user_id = 123;
        $old_refresh_token = 'old-refresh-token';
        // No refresh_token in response = IdP didn't rotate
        $new_tokens = [
            'access_token' => 'new-access-token',
            'expires_in' => 3600,
        ];

        Functions\when('get_option')->justReturn([
            'enforce_refresh_token_rotation' => true,
        ]);

        $this->token_manager
            ->shouldReceive('get_refresh_token')
            ->with($user_id)
            ->once()
            ->andReturn($old_refresh_token);

        $this->client
            ->shouldReceive('refresh_token')
            ->with($old_refresh_token)
            ->once()
            ->andReturn($new_tokens);

        $result = $this->refresh->refresh($user_id);

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertSame('oidc_rotation_required', $result->get_error_code());
    }

    /**
     * Test refresh warns without rotation when not enforced.
     */
    public function testRefreshWarnsWithoutRotationWhenNotEnforced(): void
    {
        $user_id = 123;
        $old_refresh_token = 'old-refresh-token';
        // No refresh_token in response = IdP didn't rotate
        $new_tokens = [
            'access_token' => 'new-access-token',
            'expires_in' => 3600,
        ];

        Functions\when('get_option')->justReturn([
            'enforce_refresh_token_rotation' => false,
        ]);

        $this->token_manager
            ->shouldReceive('get_refresh_token')
            ->with($user_id)
            ->once()
            ->andReturn($old_refresh_token);

        $this->client
            ->shouldReceive('refresh_token')
            ->with($old_refresh_token)
            ->once()
            ->andReturn($new_tokens);

        $this->token_manager
            ->shouldReceive('store_tokens')
            ->with($user_id, $new_tokens)
            ->once()
            ->andReturn(true);

        $result = $this->refresh->refresh($user_id);

        // Should succeed even without rotation
        $this->assertTrue($result);
    }

    /**
     * Test refresh fails when client returns error.
     */
    public function testRefreshFailsWhenClientReturnsError(): void
    {
        $user_id = 123;
        $old_refresh_token = 'old-refresh-token';
        $error = new WP_Error('oidc_error', 'Token refresh failed');

        Functions\when('get_option')->justReturn([]);

        $this->token_manager
            ->shouldReceive('get_refresh_token')
            ->with($user_id)
            ->once()
            ->andReturn($old_refresh_token);

        $this->client
            ->shouldReceive('refresh_token')
            ->with($old_refresh_token)
            ->once()
            ->andReturn($error);

        $result = $this->refresh->refresh($user_id);

        $this->assertInstanceOf(WP_Error::class, $result);
    }

    /**
     * Test refresh fails when no access_token in response.
     */
    public function testRefreshFailsWithMissingAccessToken(): void
    {
        $user_id = 123;
        $old_refresh_token = 'old-refresh-token';
        $new_tokens = [
            'refresh_token' => 'new-refresh-token',
            // Missing access_token
        ];

        Functions\when('get_option')->justReturn([]);

        $this->token_manager
            ->shouldReceive('get_refresh_token')
            ->with($user_id)
            ->once()
            ->andReturn($old_refresh_token);

        $this->client
            ->shouldReceive('refresh_token')
            ->with($old_refresh_token)
            ->once()
            ->andReturn($new_tokens);

        $result = $this->refresh->refresh($user_id);

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertSame('oidc_refresh_invalid_response', $result->get_error_code());
    }

    /**
     * Test is_auto_refresh_enabled returns true when enabled.
     */
    public function testIsAutoRefreshEnabledReturnsTrue(): void
    {
        Functions\when('get_option')->justReturn([
            'enable_auto_token_refresh' => true,
        ]);

        $this->assertTrue($this->refresh->is_auto_refresh_enabled());
    }

    /**
     * Test is_auto_refresh_enabled returns false when disabled.
     */
    public function testIsAutoRefreshEnabledReturnsFalse(): void
    {
        Functions\when('get_option')->justReturn([
            'enable_auto_token_refresh' => false,
        ]);

        $this->assertFalse($this->refresh->is_auto_refresh_enabled());
    }

    /**
     * Test get_refresh_buffer returns configured value.
     */
    public function testGetRefreshBufferReturnsConfiguredValue(): void
    {
        Functions\when('get_option')->justReturn([
            'token_refresh_buffer' => 600,
        ]);

        $this->assertSame(600, $this->refresh->get_refresh_buffer());
    }

    /**
     * Test get_refresh_buffer returns default when not set.
     */
    public function testGetRefreshBufferReturnsDefaultWhenNotSet(): void
    {
        Functions\when('get_option')->justReturn([]);

        $this->assertSame(300, $this->refresh->get_refresh_buffer());
    }

    /**
     * Test get_refresh_buffer clamps to minimum.
     */
    public function testGetRefreshBufferClampsToMinimum(): void
    {
        Functions\when('get_option')->justReturn([
            'token_refresh_buffer' => 10, // Below minimum of 60
        ]);

        $this->assertSame(60, $this->refresh->get_refresh_buffer());
    }

    /**
     * Test get_refresh_buffer clamps to maximum.
     */
    public function testGetRefreshBufferClampsToMaximum(): void
    {
        Functions\when('get_option')->justReturn([
            'token_refresh_buffer' => 7200, // Above maximum of 3600
        ]);

        $this->assertSame(3600, $this->refresh->get_refresh_buffer());
    }

    /**
     * Test is_rotation_enforced returns true when enabled.
     */
    public function testIsRotationEnforcedReturnsTrue(): void
    {
        Functions\when('get_option')->justReturn([
            'enforce_refresh_token_rotation' => true,
        ]);

        $this->assertTrue($this->refresh->is_rotation_enforced());
    }

    /**
     * Test is_rotation_enforced returns false when disabled.
     */
    public function testIsRotationEnforcedReturnsFalse(): void
    {
        Functions\when('get_option')->justReturn([
            'enforce_refresh_token_rotation' => false,
        ]);

        $this->assertFalse($this->refresh->is_rotation_enforced());
    }

    /**
     * Test constants are defined correctly.
     */
    public function testConstantsAreDefined(): void
    {
        $this->assertSame(300, OIDC_Token_Refresh::DEFAULT_REFRESH_BUFFER);
        $this->assertSame(60, OIDC_Token_Refresh::MIN_REFRESH_BUFFER);
        $this->assertSame(3600, OIDC_Token_Refresh::MAX_REFRESH_BUFFER);
    }

    /**
     * Test refresh fails when get_refresh_token returns error.
     */
    public function testRefreshFailsWhenGetRefreshTokenFails(): void
    {
        $user_id = 123;
        $error = new WP_Error('oidc_token_not_found', 'Refresh token not found');

        Functions\when('get_option')->justReturn([]);

        $this->token_manager
            ->shouldReceive('get_refresh_token')
            ->with($user_id)
            ->once()
            ->andReturn($error);

        $result = $this->refresh->refresh($user_id);

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertSame('oidc_token_not_found', $result->get_error_code());
    }

    /**
     * Test refresh fails when store_tokens returns error.
     */
    public function testRefreshFailsWhenStoreTokensFails(): void
    {
        $user_id = 123;
        $old_refresh_token = 'old-refresh-token';
        $new_tokens = [
            'access_token' => 'new-access-token',
            'refresh_token' => 'new-refresh-token',
            'expires_in' => 3600,
        ];
        $store_error = new WP_Error('oidc_encryption_failed', 'Failed to encrypt');

        Functions\when('get_option')->justReturn([
            'enforce_refresh_token_rotation' => false,
        ]);

        $this->token_manager
            ->shouldReceive('get_refresh_token')
            ->with($user_id)
            ->once()
            ->andReturn($old_refresh_token);

        $this->client
            ->shouldReceive('refresh_token')
            ->with($old_refresh_token)
            ->once()
            ->andReturn($new_tokens);

        $this->token_manager
            ->shouldReceive('was_refresh_token_rotated')
            ->with($user_id, 'new-refresh-token')
            ->once()
            ->andReturn(true);

        $this->token_manager
            ->shouldReceive('store_tokens')
            ->with($user_id, $new_tokens)
            ->once()
            ->andReturn($store_error);

        $result = $this->refresh->refresh($user_id);

        $this->assertInstanceOf(WP_Error::class, $result);
    }

    /**
     * Test same refresh token returned fails when rotation enforced.
     */
    public function testSameRefreshTokenFailsWhenRotationEnforced(): void
    {
        $user_id = 123;
        $same_refresh_token = 'same-refresh-token';
        $new_tokens = [
            'access_token' => 'new-access-token',
            'refresh_token' => $same_refresh_token, // Same as old
            'expires_in' => 3600,
        ];

        Functions\when('get_option')->justReturn([
            'enforce_refresh_token_rotation' => true,
        ]);

        $this->token_manager
            ->shouldReceive('get_refresh_token')
            ->with($user_id)
            ->once()
            ->andReturn($same_refresh_token);

        $this->client
            ->shouldReceive('refresh_token')
            ->with($same_refresh_token)
            ->once()
            ->andReturn($new_tokens);

        // Hash comparison shows it's the same token
        $this->token_manager
            ->shouldReceive('was_refresh_token_rotated')
            ->with($user_id, $same_refresh_token)
            ->once()
            ->andReturn(false);

        $result = $this->refresh->refresh($user_id);

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertSame('oidc_rotation_required', $result->get_error_code());
    }

    /**
     * Test same refresh token returned succeeds when rotation not enforced.
     *
     * When rotation enforcement is disabled, the same refresh token being returned
     * should still succeed (with a security warning logged).
     */
    public function testSameRefreshTokenSucceedsWhenRotationNotEnforced(): void
    {
        $user_id = 123;
        $same_refresh_token = 'same-refresh-token';
        $new_tokens = [
            'access_token' => 'new-access-token',
            'refresh_token' => $same_refresh_token, // Same as old
            'expires_in' => 3600,
        ];

        Functions\when('get_option')->justReturn([
            'enforce_refresh_token_rotation' => false,
        ]);

        $this->token_manager
            ->shouldReceive('get_refresh_token')
            ->with($user_id)
            ->once()
            ->andReturn($same_refresh_token);

        $this->client
            ->shouldReceive('refresh_token')
            ->with($same_refresh_token)
            ->once()
            ->andReturn($new_tokens);

        // Hash comparison shows it's the same token (not rotated)
        $this->token_manager
            ->shouldReceive('was_refresh_token_rotated')
            ->with($user_id, $same_refresh_token)
            ->once()
            ->andReturn(false);

        // Should still store tokens even without rotation
        $this->token_manager
            ->shouldReceive('store_tokens')
            ->with($user_id, $new_tokens)
            ->once()
            ->andReturn(true);

        $result = $this->refresh->refresh($user_id);

        // Should succeed (with warning logged internally)
        $this->assertTrue($result);
    }

    /**
     * Test multiple consecutive refresh calls succeed with rotation.
     *
     * Simulates a chain of token refreshes where each refresh gets a new
     * rotated refresh token.
     */
    public function testMultipleConsecutiveRefreshesWithRotation(): void
    {
        $user_id = 123;

        Functions\when('get_option')->justReturn([
            'enable_auto_token_refresh' => true,
            'token_refresh_buffer' => 300,
            'enforce_refresh_token_rotation' => true,
        ]);

        // First refresh cycle
        $this->token_manager
            ->shouldReceive('has_refresh_token')
            ->with($user_id)
            ->twice()
            ->andReturn(true);

        $this->token_manager
            ->shouldReceive('is_token_expired')
            ->with($user_id, 300)
            ->twice()
            ->andReturn(true);

        // First refresh
        $this->token_manager
            ->shouldReceive('get_refresh_token')
            ->with($user_id)
            ->once()
            ->andReturn('refresh-token-v1');

        $this->client
            ->shouldReceive('refresh_token')
            ->with('refresh-token-v1')
            ->once()
            ->andReturn([
                'access_token' => 'access-token-v2',
                'refresh_token' => 'refresh-token-v2',
                'expires_in' => 3600,
            ]);

        $this->token_manager
            ->shouldReceive('was_refresh_token_rotated')
            ->with($user_id, 'refresh-token-v2')
            ->once()
            ->andReturn(true);

        $this->token_manager
            ->shouldReceive('store_tokens')
            ->once()
            ->andReturn(true);

        $result1 = $this->refresh->maybe_refresh($user_id);
        $this->assertTrue($result1);

        // Second refresh cycle - need a new instance to clear options cache
        $this->refresh = new OIDC_Token_Refresh($this->client, $this->token_manager);

        $this->token_manager
            ->shouldReceive('get_refresh_token')
            ->with($user_id)
            ->once()
            ->andReturn('refresh-token-v2');

        $this->client
            ->shouldReceive('refresh_token')
            ->with('refresh-token-v2')
            ->once()
            ->andReturn([
                'access_token' => 'access-token-v3',
                'refresh_token' => 'refresh-token-v3',
                'expires_in' => 3600,
            ]);

        $this->token_manager
            ->shouldReceive('was_refresh_token_rotated')
            ->with($user_id, 'refresh-token-v3')
            ->once()
            ->andReturn(true);

        $this->token_manager
            ->shouldReceive('store_tokens')
            ->once()
            ->andReturn(true);

        $result2 = $this->refresh->maybe_refresh($user_id);
        $this->assertTrue($result2);
    }

    /**
     * Test refresh after previous refresh failure recovers correctly.
     */
    public function testRefreshAfterPreviousFailureRecovers(): void
    {
        $user_id = 123;

        Functions\when('get_option')->justReturn([
            'enforce_refresh_token_rotation' => false,
        ]);

        // First attempt fails
        $this->token_manager
            ->shouldReceive('get_refresh_token')
            ->with($user_id)
            ->twice()
            ->andReturn('refresh-token');

        $this->client
            ->shouldReceive('refresh_token')
            ->with('refresh-token')
            ->once()
            ->andReturn(new WP_Error('oidc_error', 'IdP temporarily unavailable'));

        $result1 = $this->refresh->refresh($user_id);
        $this->assertInstanceOf(WP_Error::class, $result1);

        // Second attempt succeeds
        $new_tokens = [
            'access_token' => 'new-access-token',
            'refresh_token' => 'new-refresh-token',
            'expires_in' => 3600,
        ];

        $this->client
            ->shouldReceive('refresh_token')
            ->with('refresh-token')
            ->once()
            ->andReturn($new_tokens);

        $this->token_manager
            ->shouldReceive('was_refresh_token_rotated')
            ->with($user_id, 'new-refresh-token')
            ->once()
            ->andReturn(true);

        $this->token_manager
            ->shouldReceive('store_tokens')
            ->with($user_id, $new_tokens)
            ->once()
            ->andReturn(true);

        $result2 = $this->refresh->refresh($user_id);
        $this->assertTrue($result2);
    }

    /**
     * Test refresh for multiple different users.
     */
    public function testRefreshForMultipleUsers(): void
    {
        $user1_id = 100;
        $user2_id = 200;

        Functions\when('get_option')->justReturn([
            'enforce_refresh_token_rotation' => false,
        ]);

        // User 1 refresh
        $this->token_manager
            ->shouldReceive('get_refresh_token')
            ->with($user1_id)
            ->once()
            ->andReturn('user1-refresh-token');

        $this->client
            ->shouldReceive('refresh_token')
            ->with('user1-refresh-token')
            ->once()
            ->andReturn([
                'access_token' => 'user1-new-access',
                'refresh_token' => 'user1-new-refresh',
                'expires_in' => 3600,
            ]);

        $this->token_manager
            ->shouldReceive('was_refresh_token_rotated')
            ->with($user1_id, 'user1-new-refresh')
            ->once()
            ->andReturn(true);

        $this->token_manager
            ->shouldReceive('store_tokens')
            ->once()
            ->andReturn(true);

        $result1 = $this->refresh->refresh($user1_id);
        $this->assertTrue($result1);

        // User 2 refresh
        $this->token_manager
            ->shouldReceive('get_refresh_token')
            ->with($user2_id)
            ->once()
            ->andReturn('user2-refresh-token');

        $this->client
            ->shouldReceive('refresh_token')
            ->with('user2-refresh-token')
            ->once()
            ->andReturn([
                'access_token' => 'user2-new-access',
                'refresh_token' => 'user2-new-refresh',
                'expires_in' => 3600,
            ]);

        $this->token_manager
            ->shouldReceive('was_refresh_token_rotated')
            ->with($user2_id, 'user2-new-refresh')
            ->once()
            ->andReturn(true);

        $this->token_manager
            ->shouldReceive('store_tokens')
            ->once()
            ->andReturn(true);

        $result2 = $this->refresh->refresh($user2_id);
        $this->assertTrue($result2);
    }

    /**
     * Test refresh with empty access token in response.
     */
    public function testRefreshFailsWithEmptyAccessToken(): void
    {
        $user_id = 123;

        Functions\when('get_option')->justReturn([]);

        $this->token_manager
            ->shouldReceive('get_refresh_token')
            ->with($user_id)
            ->once()
            ->andReturn('refresh-token');

        // Empty string access_token is still invalid
        $this->client
            ->shouldReceive('refresh_token')
            ->with('refresh-token')
            ->once()
            ->andReturn([
                'access_token' => '',
                'refresh_token' => 'new-refresh-token',
                'expires_in' => 3600,
            ]);

        $result = $this->refresh->refresh($user_id);

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertSame('oidc_refresh_invalid_response', $result->get_error_code());
    }

    /**
     * Test refresh with zero expires_in.
     */
    public function testRefreshWithZeroExpiresIn(): void
    {
        $user_id = 123;

        Functions\when('get_option')->justReturn([
            'enforce_refresh_token_rotation' => false,
        ]);

        $tokens = [
            'access_token' => 'new-access-token',
            'refresh_token' => 'new-refresh-token',
            'expires_in' => 0,
        ];

        $this->token_manager
            ->shouldReceive('get_refresh_token')
            ->with($user_id)
            ->once()
            ->andReturn('refresh-token');

        $this->client
            ->shouldReceive('refresh_token')
            ->with('refresh-token')
            ->once()
            ->andReturn($tokens);

        $this->token_manager
            ->shouldReceive('was_refresh_token_rotated')
            ->with($user_id, 'new-refresh-token')
            ->once()
            ->andReturn(true);

        $this->token_manager
            ->shouldReceive('store_tokens')
            ->with($user_id, $tokens)
            ->once()
            ->andReturn(true);

        // Should succeed - expires_in validation is token manager's responsibility
        $result = $this->refresh->refresh($user_id);
        $this->assertTrue($result);
    }

    /**
     * Test refresh with only access_token in response (no refresh token, not enforced).
     */
    public function testRefreshWithOnlyAccessTokenWhenNotEnforced(): void
    {
        $user_id = 123;

        Functions\when('get_option')->justReturn([
            'enforce_refresh_token_rotation' => false,
        ]);

        // Response has only access_token - no refresh token returned
        $tokens = [
            'access_token' => 'new-access-token',
            'expires_in' => 3600,
        ];

        $this->token_manager
            ->shouldReceive('get_refresh_token')
            ->with($user_id)
            ->once()
            ->andReturn('old-refresh-token');

        $this->client
            ->shouldReceive('refresh_token')
            ->with('old-refresh-token')
            ->once()
            ->andReturn($tokens);

        // No rotation check since no refresh_token in response
        // Store should still be called with the tokens
        $this->token_manager
            ->shouldReceive('store_tokens')
            ->with($user_id, $tokens)
            ->once()
            ->andReturn(true);

        $result = $this->refresh->refresh($user_id);
        $this->assertTrue($result);
    }

    /**
     * Test maybe_refresh uses default buffer when not configured.
     */
    public function testMaybeRefreshUsesDefaultBuffer(): void
    {
        $user_id = 123;

        Functions\when('get_option')->justReturn([
            'enable_auto_token_refresh' => true,
            // No token_refresh_buffer set - should use default 300
        ]);

        $this->token_manager
            ->shouldReceive('has_refresh_token')
            ->with($user_id)
            ->once()
            ->andReturn(true);

        // Should use default 300 second buffer
        $this->token_manager
            ->shouldReceive('is_token_expired')
            ->with($user_id, 300)
            ->once()
            ->andReturn(false);

        $result = $this->refresh->maybe_refresh($user_id);
        $this->assertTrue($result);
    }

    /**
     * Test refresh with id_token in response.
     */
    public function testRefreshWithIdToken(): void
    {
        $user_id = 123;

        Functions\when('get_option')->justReturn([
            'enforce_refresh_token_rotation' => false,
        ]);

        Functions\when('get_user_meta')->justReturn('test-subject-123');

        // Response includes id_token (some IdPs return this on refresh)
        $tokens = [
            'access_token' => 'new-access-token',
            'refresh_token' => 'new-refresh-token',
            'id_token' => 'new-id-token.jwt.here',
            'expires_in' => 3600,
        ];

        $this->token_manager
            ->shouldReceive('get_refresh_token')
            ->with($user_id)
            ->once()
            ->andReturn('old-refresh-token');

        $this->client
            ->shouldReceive('refresh_token')
            ->with('old-refresh-token')
            ->once()
            ->andReturn($tokens);

        // id_token must be validated during refresh (OIDC Core Section 12.2)
        $this->client
            ->shouldReceive('validate_id_token')
            ->with('new-id-token.jwt.here', null, null, 'new-access-token')
            ->once()
            ->andReturn(['sub' => 'test-subject-123', 'iss' => 'https://idp.example.com']);

        $this->token_manager
            ->shouldReceive('was_refresh_token_rotated')
            ->with($user_id, 'new-refresh-token')
            ->once()
            ->andReturn(true);

        // Should store all tokens including id_token
        $this->token_manager
            ->shouldReceive('store_tokens')
            ->with($user_id, $tokens)
            ->once()
            ->andReturn(true);

        $result = $this->refresh->refresh($user_id);
        $this->assertTrue($result);
    }

    /**
     * Test refresh buffer at exact minimum boundary.
     */
    public function testRefreshBufferAtMinimumBoundary(): void
    {
        Functions\when('get_option')->justReturn([
            'token_refresh_buffer' => 60, // Exactly at minimum
        ]);

        $this->assertSame(60, $this->refresh->get_refresh_buffer());
    }

    /**
     * Test refresh buffer at exact maximum boundary.
     */
    public function testRefreshBufferAtMaximumBoundary(): void
    {
        Functions\when('get_option')->justReturn([
            'token_refresh_buffer' => 3600, // Exactly at maximum
        ]);

        $this->assertSame(3600, $this->refresh->get_refresh_buffer());
    }

    /**
     * Test options are cached after first call.
     */
    public function testOptionsCaching(): void
    {
        // get_option should only be called once due to caching
        $call_count = 0;
        Functions\when('get_option')->alias(function () use (&$call_count) {
            $call_count++;
            return ['enable_auto_token_refresh' => false];
        });

        // Call multiple methods that use options
        $this->refresh->is_auto_refresh_enabled();
        $this->refresh->is_rotation_enforced();
        $this->refresh->get_refresh_buffer();

        // Options should be cached after first call
        $this->assertSame(1, $call_count);
    }

    /**
     * Test refresh fails when id_token validation fails (e.g. bad signature).
     */
    public function testRefreshFailsWhenIdTokenValidationFails(): void
    {
        $user_id = 123;

        Functions\when('get_option')->justReturn([
            'enforce_refresh_token_rotation' => false,
        ]);

        $tokens = [
            'access_token' => 'new-access-token',
            'refresh_token' => 'new-refresh-token',
            'id_token' => 'invalid-id-token.jwt.here',
            'expires_in' => 3600,
        ];

        $this->token_manager
            ->shouldReceive('get_refresh_token')
            ->with($user_id)
            ->once()
            ->andReturn('old-refresh-token');

        $this->client
            ->shouldReceive('refresh_token')
            ->with('old-refresh-token')
            ->once()
            ->andReturn($tokens);

        // validate_id_token returns error (bad signature)
        $this->client
            ->shouldReceive('validate_id_token')
            ->with('invalid-id-token.jwt.here', null, null, 'new-access-token')
            ->once()
            ->andReturn(new WP_Error('oidc_error', 'Invalid JWT signature'));

        // store_tokens should NOT be called
        $this->token_manager
            ->shouldNotReceive('store_tokens');

        $result = $this->refresh->refresh($user_id);

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertSame('oidc_refresh_id_token_invalid', $result->get_error_code());
    }

    /**
     * Test refresh fails when id_token sub claim mismatches stored subject.
     */
    public function testRefreshFailsWhenIdTokenSubMismatch(): void
    {
        $user_id = 123;

        Functions\when('get_option')->justReturn([
            'enforce_refresh_token_rotation' => false,
        ]);

        // Stored subject is different from the one in the refreshed id_token
        Functions\when('get_user_meta')->justReturn('original-subject-123');

        $tokens = [
            'access_token' => 'new-access-token',
            'refresh_token' => 'new-refresh-token',
            'id_token' => 'new-id-token.jwt.here',
            'expires_in' => 3600,
        ];

        $this->token_manager
            ->shouldReceive('get_refresh_token')
            ->with($user_id)
            ->once()
            ->andReturn('old-refresh-token');

        $this->client
            ->shouldReceive('refresh_token')
            ->with('old-refresh-token')
            ->once()
            ->andReturn($tokens);

        // validate_id_token succeeds but returns a different sub
        $this->client
            ->shouldReceive('validate_id_token')
            ->with('new-id-token.jwt.here', null, null, 'new-access-token')
            ->once()
            ->andReturn(['sub' => 'different-subject-456', 'iss' => 'https://idp.example.com']);

        // store_tokens should NOT be called
        $this->token_manager
            ->shouldNotReceive('store_tokens');

        $result = $this->refresh->refresh($user_id);

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertSame('oidc_refresh_subject_mismatch', $result->get_error_code());
    }

    /**
     * Test refresh fails when no stored subject exists for verification.
     */
    public function testRefreshFailsWhenNoStoredSubjectWithIdToken(): void
    {
        $user_id = 123;

        Functions\when('get_option')->justReturn([
            'enforce_refresh_token_rotation' => false,
        ]);

        // No stored oidc_subject in user meta
        Functions\when('get_user_meta')->justReturn('');

        $tokens = [
            'access_token' => 'new-access-token',
            'refresh_token' => 'new-refresh-token',
            'id_token' => 'new-id-token.jwt.here',
            'expires_in' => 3600,
        ];

        $this->token_manager
            ->shouldReceive('get_refresh_token')
            ->with($user_id)
            ->once()
            ->andReturn('old-refresh-token');

        $this->client
            ->shouldReceive('refresh_token')
            ->with('old-refresh-token')
            ->once()
            ->andReturn($tokens);

        // validate_id_token succeeds
        $this->client
            ->shouldReceive('validate_id_token')
            ->with('new-id-token.jwt.here', null, null, 'new-access-token')
            ->once()
            ->andReturn(['sub' => 'test-subject-123', 'iss' => 'https://idp.example.com']);

        // store_tokens should NOT be called
        $this->token_manager
            ->shouldNotReceive('store_tokens');

        $result = $this->refresh->refresh($user_id);

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertSame('oidc_refresh_subject_missing', $result->get_error_code());
    }

    /**
     * Test refresh succeeds without id_token in response (validation skipped).
     */
    public function testRefreshSucceedsWithoutIdTokenInResponse(): void
    {
        $user_id = 123;

        Functions\when('get_option')->justReturn([
            'enforce_refresh_token_rotation' => false,
        ]);

        // No id_token in response
        $tokens = [
            'access_token' => 'new-access-token',
            'refresh_token' => 'new-refresh-token',
            'expires_in' => 3600,
        ];

        $this->token_manager
            ->shouldReceive('get_refresh_token')
            ->with($user_id)
            ->once()
            ->andReturn('old-refresh-token');

        $this->client
            ->shouldReceive('refresh_token')
            ->with('old-refresh-token')
            ->once()
            ->andReturn($tokens);

        // validate_id_token should NOT be called when no id_token present
        $this->client
            ->shouldNotReceive('validate_id_token');

        $this->token_manager
            ->shouldReceive('was_refresh_token_rotated')
            ->with($user_id, 'new-refresh-token')
            ->once()
            ->andReturn(true);

        $this->token_manager
            ->shouldReceive('store_tokens')
            ->with($user_id, $tokens)
            ->once()
            ->andReturn(true);

        $result = $this->refresh->refresh($user_id);
        $this->assertTrue($result);
    }

    /**
     * Test refresh skips id_token validation when id_token is empty string.
     */
    public function testRefreshSkipsValidationForEmptyIdToken(): void
    {
        $user_id = 123;

        Functions\when('get_option')->justReturn([
            'enforce_refresh_token_rotation' => false,
        ]);

        // Empty string id_token should be treated as absent
        $tokens = [
            'access_token' => 'new-access-token',
            'refresh_token' => 'new-refresh-token',
            'id_token' => '',
            'expires_in' => 3600,
        ];

        $this->token_manager
            ->shouldReceive('get_refresh_token')
            ->with($user_id)
            ->once()
            ->andReturn('old-refresh-token');

        $this->client
            ->shouldReceive('refresh_token')
            ->with('old-refresh-token')
            ->once()
            ->andReturn($tokens);

        // validate_id_token should NOT be called for empty id_token
        $this->client
            ->shouldNotReceive('validate_id_token');

        $this->token_manager
            ->shouldReceive('was_refresh_token_rotated')
            ->with($user_id, 'new-refresh-token')
            ->once()
            ->andReturn(true);

        $this->token_manager
            ->shouldReceive('store_tokens')
            ->with($user_id, $tokens)
            ->once()
            ->andReturn(true);

        $result = $this->refresh->refresh($user_id);
        $this->assertTrue($result);
    }

    /**
     * Test refresh fails when at_hash validation fails in id_token.
     */
    public function testRefreshFailsWhenAtHashValidationFails(): void
    {
        $user_id = 123;

        Functions\when('get_option')->justReturn([
            'enforce_refresh_token_rotation' => false,
        ]);

        $tokens = [
            'access_token' => 'new-access-token',
            'refresh_token' => 'new-refresh-token',
            'id_token' => 'id-token-with-bad-at-hash.jwt.here',
            'expires_in' => 3600,
        ];

        $this->token_manager
            ->shouldReceive('get_refresh_token')
            ->with($user_id)
            ->once()
            ->andReturn('old-refresh-token');

        $this->client
            ->shouldReceive('refresh_token')
            ->with('old-refresh-token')
            ->once()
            ->andReturn($tokens);

        // validate_id_token returns at_hash error
        $this->client
            ->shouldReceive('validate_id_token')
            ->with('id-token-with-bad-at-hash.jwt.here', null, null, 'new-access-token')
            ->once()
            ->andReturn(new WP_Error('oidc_error', 'at_hash claim validation failed'));

        // store_tokens should NOT be called
        $this->token_manager
            ->shouldNotReceive('store_tokens');

        $result = $this->refresh->refresh($user_id);

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertSame('oidc_refresh_id_token_invalid', $result->get_error_code());
    }
}

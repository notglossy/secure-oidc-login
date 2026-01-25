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
}

<?php
/**
 * Tests for OIDC_Token_Manager class.
 *
 * @package SecureOIDCLogin\Tests\Unit\Token
 */

declare(strict_types=1);

namespace SecureOIDCLogin\Tests\Unit\Token;

use Brain\Monkey\Functions;
use OIDC_Token_Manager;
use SecureOIDCLogin\Tests\OIDCTestCase;
use WP_Error;

/**
 * Tests for the OIDC_Token_Manager class.
 *
 * @covers OIDC_Token_Manager
 */
class OIDCTokenManagerTest extends OIDCTestCase
{
    /**
     * Token Manager instance under test.
     *
     * @var OIDC_Token_Manager
     */
    private OIDC_Token_Manager $manager;

    /**
     * Set up test environment.
     */
    protected function setUp(): void
    {
        parent::setUp();

        // Stub wp_salt for encryption
        Functions\when('wp_salt')->justReturn('test-salt-value-for-unit-testing');

        $this->manager = new OIDC_Token_Manager();
    }

    /**
     * Test store_tokens with all token types.
     */
    public function testStoreTokensWithAllTokens(): void
    {
        $user_id = 123;
        $tokens = [
            'access_token' => 'test-access-token',
            'id_token' => 'test-id-token',
            'refresh_token' => 'test-refresh-token',
            'expires_in' => 3600,
        ];

        // Mock user meta functions
        $stored_meta = [];
        Functions\when('update_user_meta')->alias(function ($uid, $key, $value) use (&$stored_meta, $user_id) {
            if ($uid === $user_id) {
                $stored_meta[$key] = $value;
            }
            return true;
        });

        $result = $this->manager->store_tokens($user_id, $tokens);

        $this->assertTrue($result);
        $this->assertArrayHasKey('oidc_access_token', $stored_meta);
        $this->assertArrayHasKey('oidc_id_token', $stored_meta);
        $this->assertArrayHasKey('oidc_refresh_token', $stored_meta);
        $this->assertArrayHasKey('oidc_token_expires_at', $stored_meta);
        $this->assertArrayHasKey('oidc_refresh_token_hash', $stored_meta);

        // Verify tokens are encrypted (prefixed)
        $this->assertStringStartsWith('enc:v2:', $stored_meta['oidc_access_token']);
        $this->assertStringStartsWith('enc:v2:', $stored_meta['oidc_id_token']);
        $this->assertStringStartsWith('enc:v2:', $stored_meta['oidc_refresh_token']);
    }

    /**
     * Test store_tokens fails with missing access_token.
     */
    public function testStoreTokensFailsWithMissingAccessToken(): void
    {
        $tokens = [
            'id_token' => 'test-id-token',
        ];

        $result = $this->manager->store_tokens(123, $tokens);

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertSame('oidc_invalid_tokens', $result->get_error_code());
    }

    /**
     * Test store_tokens without optional tokens.
     */
    public function testStoreTokensWithoutOptionalTokens(): void
    {
        $user_id = 123;
        $tokens = [
            'access_token' => 'test-access-token',
        ];

        $stored_meta = [];
        Functions\when('update_user_meta')->alias(function ($uid, $key, $value) use (&$stored_meta, $user_id) {
            if ($uid === $user_id) {
                $stored_meta[$key] = $value;
            }
            return true;
        });

        $result = $this->manager->store_tokens($user_id, $tokens);

        $this->assertTrue($result);
        $this->assertArrayHasKey('oidc_access_token', $stored_meta);
        $this->assertArrayHasKey('oidc_token_expires_at', $stored_meta);
        // Should not have id_token or refresh_token
        $this->assertArrayNotHasKey('oidc_id_token', $stored_meta);
        $this->assertArrayNotHasKey('oidc_refresh_token', $stored_meta);
    }

    /**
     * Test get_access_token returns decrypted token.
     */
    public function testGetAccessTokenReturnsDecrypted(): void
    {
        $user_id = 123;
        $plain_token = 'test-access-token-value';

        // Encrypt the token
        $encrypted = \OIDC_Token_Crypto::encrypt($plain_token);

        Functions\when('get_user_meta')->alias(function ($uid, $key, $single) use ($user_id, $encrypted) {
            if ($uid === $user_id && $key === 'oidc_access_token' && $single) {
                return $encrypted;
            }
            return '';
        });

        $result = $this->manager->get_access_token($user_id);

        $this->assertSame($plain_token, $result);
    }

    /**
     * Test get_access_token returns error when not found.
     */
    public function testGetAccessTokenReturnsErrorWhenNotFound(): void
    {
        Functions\when('get_user_meta')->justReturn('');

        $result = $this->manager->get_access_token(123);

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertSame('oidc_token_not_found', $result->get_error_code());
    }

    /**
     * Test get_refresh_token returns decrypted token.
     */
    public function testGetRefreshTokenReturnsDecrypted(): void
    {
        $user_id = 123;
        $plain_token = 'test-refresh-token-value';

        $encrypted = \OIDC_Token_Crypto::encrypt($plain_token);

        Functions\when('get_user_meta')->alias(function ($uid, $key, $single) use ($user_id, $encrypted) {
            if ($uid === $user_id && $key === 'oidc_refresh_token' && $single) {
                return $encrypted;
            }
            return '';
        });

        $result = $this->manager->get_refresh_token($user_id);

        $this->assertSame($plain_token, $result);
    }

    /**
     * Test is_token_expired returns false when token is still valid.
     */
    public function testIsTokenExpiredFalseWhenFuture(): void
    {
        $user_id = 123;
        $expires_at = time() + 3600; // 1 hour from now

        Functions\when('get_user_meta')->alias(function ($uid, $key, $single) use ($user_id, $expires_at) {
            if ($uid === $user_id && $key === 'oidc_token_expires_at' && $single) {
                return $expires_at;
            }
            return '';
        });

        $result = $this->manager->is_token_expired($user_id, 0);

        $this->assertFalse($result);
    }

    /**
     * Test is_token_expired returns true when token is past expiry.
     */
    public function testIsTokenExpiredTrueWhenPast(): void
    {
        $user_id = 123;
        $expires_at = time() - 100; // 100 seconds ago

        Functions\when('get_user_meta')->alias(function ($uid, $key, $single) use ($user_id, $expires_at) {
            if ($uid === $user_id && $key === 'oidc_token_expires_at' && $single) {
                return $expires_at;
            }
            return '';
        });

        $result = $this->manager->is_token_expired($user_id, 0);

        $this->assertTrue($result);
    }

    /**
     * Test is_token_expired with buffer time.
     */
    public function testIsTokenExpiredWithBuffer(): void
    {
        $user_id = 123;
        $expires_at = time() + 200; // 200 seconds from now

        Functions\when('get_user_meta')->alias(function ($uid, $key, $single) use ($user_id, $expires_at) {
            if ($uid === $user_id && $key === 'oidc_token_expires_at' && $single) {
                return $expires_at;
            }
            return '';
        });

        // Without buffer (200s left) - not expired
        $this->assertFalse($this->manager->is_token_expired($user_id, 0));

        // With 300s buffer (200s left < 300s buffer) - expired
        $this->assertTrue($this->manager->is_token_expired($user_id, 300));

        // With 100s buffer (200s left > 100s buffer) - not expired
        $this->assertFalse($this->manager->is_token_expired($user_id, 100));
    }

    /**
     * Test is_token_expired returns true when no expiration is set.
     */
    public function testIsTokenExpiredTrueWhenNoExpiration(): void
    {
        Functions\when('get_user_meta')->justReturn('');

        $result = $this->manager->is_token_expired(123, 0);

        $this->assertTrue($result);
    }

    /**
     * Test get_expiration_time returns timestamp.
     */
    public function testGetExpirationTimeReturnsTimestamp(): void
    {
        $user_id = 123;
        $expires_at = time() + 3600;

        Functions\when('get_user_meta')->alias(function ($uid, $key, $single) use ($user_id, $expires_at) {
            if ($uid === $user_id && $key === 'oidc_token_expires_at' && $single) {
                return $expires_at;
            }
            return '';
        });

        $result = $this->manager->get_expiration_time($user_id);

        $this->assertSame($expires_at, $result);
    }

    /**
     * Test get_expiration_time returns null when not set.
     */
    public function testGetExpirationTimeReturnsNullWhenNotSet(): void
    {
        Functions\when('get_user_meta')->justReturn('');

        $result = $this->manager->get_expiration_time(123);

        $this->assertNull($result);
    }

    /**
     * Test refresh token rotation detection.
     */
    public function testRefreshTokenRotationDetected(): void
    {
        $user_id = 123;
        $old_token = 'old-refresh-token';
        $new_token = 'new-refresh-token';
        $stored_hash = hash('sha256', $old_token);

        Functions\when('get_user_meta')->alias(function ($uid, $key, $single) use ($user_id, $stored_hash) {
            if ($uid === $user_id && $key === 'oidc_refresh_token_hash' && $single) {
                return $stored_hash;
            }
            return '';
        });

        // New token should be detected as rotated
        $this->assertTrue($this->manager->was_refresh_token_rotated($user_id, $new_token));

        // Same token (hash matches) should not be detected as rotated
        $this->assertFalse($this->manager->was_refresh_token_rotated($user_id, $old_token));
    }

    /**
     * Test rotation detection returns false when no previous hash.
     */
    public function testRotationDetectionFalseWhenNoPreviousHash(): void
    {
        Functions\when('get_user_meta')->justReturn('');

        $result = $this->manager->was_refresh_token_rotated(123, 'any-token');

        $this->assertFalse($result);
    }

    /**
     * Test has_refresh_token returns true when token exists.
     */
    public function testHasRefreshTokenReturnsTrue(): void
    {
        Functions\when('get_user_meta')->justReturn('enc:v2:encrypted-data');

        $result = $this->manager->has_refresh_token(123);

        $this->assertTrue($result);
    }

    /**
     * Test has_refresh_token returns false when token doesn't exist.
     */
    public function testHasRefreshTokenReturnsFalse(): void
    {
        Functions\when('get_user_meta')->justReturn('');

        $result = $this->manager->has_refresh_token(123);

        $this->assertFalse($result);
    }

    /**
     * Test clear_tokens removes all meta.
     */
    public function testClearTokensRemovesAllMeta(): void
    {
        $user_id = 123;
        $deleted_keys = [];

        Functions\when('delete_user_meta')->alias(function ($uid, $key) use (&$deleted_keys, $user_id) {
            if ($uid === $user_id) {
                $deleted_keys[] = $key;
            }
            return true;
        });

        $this->manager->clear_tokens($user_id);

        $this->assertContains('oidc_access_token', $deleted_keys);
        $this->assertContains('oidc_id_token', $deleted_keys);
        $this->assertContains('oidc_refresh_token', $deleted_keys);
        $this->assertContains('oidc_token_expires_at', $deleted_keys);
        $this->assertContains('oidc_refresh_token_hash', $deleted_keys);
    }

    /**
     * Test default expires_in is used when not provided.
     */
    public function testDefaultExpiresInUsed(): void
    {
        $user_id = 123;
        $tokens = [
            'access_token' => 'test-access-token',
        ];

        $stored_expires = null;
        Functions\when('update_user_meta')->alias(function ($uid, $key, $value) use (&$stored_expires, $user_id) {
            if ($uid === $user_id && $key === 'oidc_token_expires_at') {
                $stored_expires = $value;
            }
            return true;
        });

        $before = time();
        $this->manager->store_tokens($user_id, $tokens);
        $after = time();

        // Default is 3600 seconds
        $this->assertGreaterThanOrEqual($before + 3600, $stored_expires);
        $this->assertLessThanOrEqual($after + 3600, $stored_expires);
    }

    /**
     * Test get_id_token returns decrypted token.
     */
    public function testGetIdTokenReturnsDecrypted(): void
    {
        $user_id = 123;
        $plain_token = 'test-id-token-value';

        $encrypted = \OIDC_Token_Crypto::encrypt($plain_token);

        Functions\when('get_user_meta')->alias(function ($uid, $key, $single) use ($user_id, $encrypted) {
            if ($uid === $user_id && $key === 'oidc_id_token' && $single) {
                return $encrypted;
            }
            return '';
        });

        $result = $this->manager->get_id_token($user_id);

        $this->assertSame($plain_token, $result);
    }

    /**
     * Test get_id_token returns error when not found.
     */
    public function testGetIdTokenReturnsErrorWhenNotFound(): void
    {
        Functions\when('get_user_meta')->justReturn('');

        $result = $this->manager->get_id_token(123);

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertSame('oidc_token_not_found', $result->get_error_code());
    }

    /**
     * Test constants are defined correctly.
     */
    public function testConstantsAreDefined(): void
    {
        $this->assertSame('oidc_access_token', OIDC_Token_Manager::META_ACCESS_TOKEN);
        $this->assertSame('oidc_id_token', OIDC_Token_Manager::META_ID_TOKEN);
        $this->assertSame('oidc_refresh_token', OIDC_Token_Manager::META_REFRESH_TOKEN);
        $this->assertSame('oidc_token_expires_at', OIDC_Token_Manager::META_EXPIRES_AT);
        $this->assertSame('oidc_refresh_token_hash', OIDC_Token_Manager::META_REFRESH_TOKEN_HASH);
        $this->assertSame(3600, OIDC_Token_Manager::DEFAULT_EXPIRES_IN);
    }

    /**
     * Test get_access_token returns error on decryption failure.
     */
    public function testGetAccessTokenReturnsErrorOnDecryptionFailure(): void
    {
        $user_id = 123;
        // Malformed encrypted token that will fail decryption
        $malformed = 'enc:v2:' . base64_encode('short');

        Functions\when('get_user_meta')->alias(function ($uid, $key, $single) use ($user_id, $malformed) {
            if ($uid === $user_id && $key === 'oidc_access_token' && $single) {
                return $malformed;
            }
            return '';
        });

        $result = $this->manager->get_access_token($user_id);

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertSame('oidc_decryption_failed', $result->get_error_code());
    }

    /**
     * Test get_refresh_token returns error on decryption failure.
     */
    public function testGetRefreshTokenReturnsErrorOnDecryptionFailure(): void
    {
        $user_id = 123;
        // Malformed encrypted token that will fail decryption
        $malformed = 'enc:v2:' . base64_encode('short');

        Functions\when('get_user_meta')->alias(function ($uid, $key, $single) use ($user_id, $malformed) {
            if ($uid === $user_id && $key === 'oidc_refresh_token' && $single) {
                return $malformed;
            }
            return '';
        });

        $result = $this->manager->get_refresh_token($user_id);

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertSame('oidc_decryption_failed', $result->get_error_code());
    }

    /**
     * Test get_id_token returns error on decryption failure.
     */
    public function testGetIdTokenReturnsErrorOnDecryptionFailure(): void
    {
        $user_id = 123;
        // Malformed encrypted token that will fail decryption
        $malformed = 'enc:v2:' . base64_encode('short');

        Functions\when('get_user_meta')->alias(function ($uid, $key, $single) use ($user_id, $malformed) {
            if ($uid === $user_id && $key === 'oidc_id_token' && $single) {
                return $malformed;
            }
            return '';
        });

        $result = $this->manager->get_id_token($user_id);

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertSame('oidc_decryption_failed', $result->get_error_code());
    }

    /**
     * Test get_refresh_token returns error when not found.
     */
    public function testGetRefreshTokenReturnsErrorWhenNotFound(): void
    {
        Functions\when('get_user_meta')->justReturn('');

        $result = $this->manager->get_refresh_token(123);

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertSame('oidc_token_not_found', $result->get_error_code());
    }

    /**
     * Test get_expiration_time returns null when false is returned.
     */
    public function testGetExpirationTimeReturnsNullWhenFalse(): void
    {
        Functions\when('get_user_meta')->justReturn(false);

        $result = $this->manager->get_expiration_time(123);

        $this->assertNull($result);
    }

    /**
     * Test store_tokens with empty access_token string.
     */
    public function testStoreTokensFailsWithEmptyAccessToken(): void
    {
        $tokens = [
            'access_token' => '',
            'id_token' => 'test-id-token',
        ];

        $result = $this->manager->store_tokens(123, $tokens);

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertSame('oidc_invalid_tokens', $result->get_error_code());
    }
}

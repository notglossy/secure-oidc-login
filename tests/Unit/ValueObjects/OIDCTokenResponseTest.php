<?php
/**
 * Tests for OIDC_Token_Response value object.
 *
 * @package SecureOIDCLogin\Tests\Unit\ValueObjects
 */

declare(strict_types=1);

namespace SecureOIDCLogin\Tests\Unit\ValueObjects;

use OIDC_Token_Response;
use SecureOIDCLogin\Tests\OIDCTestCase;
use WP_Error;

/**
 * Tests for the OIDC_Token_Response class.
 *
 * @covers OIDC_Token_Response
 */
class OIDCTokenResponseTest extends OIDCTestCase
{
    /**
     * Test successful creation from valid response array.
     */
    public function testFromArrayWithValidResponse(): void
    {
        $response = $this->getSampleTokenResponse();

        $result = OIDC_Token_Response::from_array($response);

        $this->assertInstanceOf(OIDC_Token_Response::class, $result);
        $this->assertSame($response['access_token'], $result->get_access_token());
        $this->assertSame($response['id_token'], $result->get_id_token());
        $this->assertSame('Bearer', $result->get_token_type());
        $this->assertSame(3600, $result->get_expires_in());
        $this->assertSame('refresh_token_value', $result->get_refresh_token());
        $this->assertSame('openid email profile', $result->get_scope());
    }

    /**
     * Test that missing access_token returns WP_Error.
     */
    public function testFromArrayWithMissingAccessToken(): void
    {
        $response = $this->getSampleTokenResponse();
        unset($response['access_token']);

        $result = OIDC_Token_Response::from_array($response);

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertStringContainsString('access_token', $result->get_error_message());
    }

    /**
     * Test that missing id_token returns WP_Error.
     */
    public function testFromArrayWithMissingIdToken(): void
    {
        $response = $this->getSampleTokenResponse();
        unset($response['id_token']);

        $result = OIDC_Token_Response::from_array($response);

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertStringContainsString('id_token', $result->get_error_message());
    }

    /**
     * Test that missing token_type returns WP_Error.
     */
    public function testFromArrayWithMissingTokenType(): void
    {
        $response = $this->getSampleTokenResponse();
        unset($response['token_type']);

        $result = OIDC_Token_Response::from_array($response);

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertStringContainsString('token_type', $result->get_error_message());
    }

    /**
     * Test that empty access_token returns WP_Error.
     */
    public function testFromArrayWithEmptyAccessToken(): void
    {
        $response = $this->getSampleTokenResponse();
        $response['access_token'] = '';

        $result = OIDC_Token_Response::from_array($response);

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertStringContainsString('access_token', $result->get_error_message());
    }

    /**
     * Test default expires_in when not provided.
     */
    public function testDefaultExpiresIn(): void
    {
        $response = [
            'access_token' => 'test_access_token',
            'id_token' => 'test_id_token',
            'token_type' => 'Bearer',
        ];

        $result = OIDC_Token_Response::from_array($response);

        $this->assertInstanceOf(OIDC_Token_Response::class, $result);
        $this->assertSame(3600, $result->get_expires_in());
    }

    /**
     * Test refresh_token is null when not provided.
     */
    public function testRefreshTokenNullWhenNotProvided(): void
    {
        $response = [
            'access_token' => 'test_access_token',
            'id_token' => 'test_id_token',
            'token_type' => 'Bearer',
        ];

        $result = OIDC_Token_Response::from_array($response);

        $this->assertInstanceOf(OIDC_Token_Response::class, $result);
        $this->assertNull($result->get_refresh_token());
    }

    /**
     * Test scope is null when not provided.
     */
    public function testScopeNullWhenNotProvided(): void
    {
        $response = [
            'access_token' => 'test_access_token',
            'id_token' => 'test_id_token',
            'token_type' => 'Bearer',
        ];

        $result = OIDC_Token_Response::from_array($response);

        $this->assertInstanceOf(OIDC_Token_Response::class, $result);
        $this->assertNull($result->get_scope());
    }

    /**
     * Test has_refresh_token returns true when present.
     */
    public function testHasRefreshTokenReturnsTrue(): void
    {
        $response = $this->getSampleTokenResponse();
        $result = OIDC_Token_Response::from_array($response);

        $this->assertTrue($result->has_refresh_token());
    }

    /**
     * Test has_refresh_token returns false when not present.
     */
    public function testHasRefreshTokenReturnsFalse(): void
    {
        $response = [
            'access_token' => 'test_access_token',
            'id_token' => 'test_id_token',
            'token_type' => 'Bearer',
        ];

        $result = OIDC_Token_Response::from_array($response);

        $this->assertFalse($result->has_refresh_token());
    }

    /**
     * Test to_array returns correct structure.
     */
    public function testToArrayReturnsCorrectStructure(): void
    {
        $response = $this->getSampleTokenResponse();
        $result = OIDC_Token_Response::from_array($response);

        $array = $result->to_array();

        $this->assertArrayHasKey('access_token', $array);
        $this->assertArrayHasKey('id_token', $array);
        $this->assertArrayHasKey('token_type', $array);
        $this->assertArrayHasKey('expires_in', $array);
        $this->assertArrayHasKey('refresh_token', $array);
        $this->assertArrayHasKey('scope', $array);

        $this->assertSame($response['access_token'], $array['access_token']);
        $this->assertSame($response['id_token'], $array['id_token']);
        $this->assertSame('Bearer', $array['token_type']);
        $this->assertSame(3600, $array['expires_in']);
    }

    /**
     * Test to_array omits refresh_token when null.
     */
    public function testToArrayOmitsRefreshTokenWhenNull(): void
    {
        $response = [
            'access_token' => 'test_access_token',
            'id_token' => 'test_id_token',
            'token_type' => 'Bearer',
        ];

        $result = OIDC_Token_Response::from_array($response);
        $array = $result->to_array();

        $this->assertArrayNotHasKey('refresh_token', $array);
        $this->assertArrayNotHasKey('scope', $array);
    }

    /**
     * Test expires_in is cast to int.
     */
    public function testExpiresInIsCastToInt(): void
    {
        $response = [
            'access_token' => 'test_access_token',
            'id_token' => 'test_id_token',
            'token_type' => 'Bearer',
            'expires_in' => '7200',
        ];

        $result = OIDC_Token_Response::from_array($response);

        $this->assertSame(7200, $result->get_expires_in());
    }
}

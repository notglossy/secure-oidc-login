<?php
/**
 * Tests for OIDC_Config value object.
 *
 * @package SecureOIDCLogin\Tests\Unit\ValueObjects
 */

declare(strict_types=1);

namespace SecureOIDCLogin\Tests\Unit\ValueObjects;

use OIDC_Config;
use SecureOIDCLogin\Tests\OIDCTestCase;
use WP_Error;

/**
 * Tests for the OIDC_Config class.
 *
 * @covers OIDC_Config
 */
class OIDCConfigTest extends OIDCTestCase
{
    /**
     * Test successful creation from valid config array.
     */
    public function testFromArrayWithValidConfig(): void
    {
        $config = $this->getSampleOIDCConfig();

        $result = OIDC_Config::from_array($config);

        $this->assertInstanceOf(OIDC_Config::class, $result);
        $this->assertSame('https://idp.example.com', $result->get_issuer());
        $this->assertSame('https://idp.example.com/authorize', $result->get_authorization_endpoint());
        $this->assertSame('https://idp.example.com/token', $result->get_token_endpoint());
        $this->assertSame('https://idp.example.com/userinfo', $result->get_userinfo_endpoint());
        $this->assertSame('https://idp.example.com/.well-known/jwks.json', $result->get_jwks_uri());
        $this->assertSame('https://idp.example.com/logout', $result->get_end_session_endpoint());
    }

    /**
     * Test that missing issuer returns WP_Error.
     */
    public function testFromArrayWithMissingIssuer(): void
    {
        $config = $this->getSampleOIDCConfig();
        unset($config['issuer']);

        $result = OIDC_Config::from_array($config);

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertStringContainsString('issuer', $result->get_error_message());
    }

    /**
     * Test that missing authorization_endpoint returns WP_Error.
     */
    public function testFromArrayWithMissingAuthorizationEndpoint(): void
    {
        $config = $this->getSampleOIDCConfig();
        unset($config['authorization_endpoint']);

        $result = OIDC_Config::from_array($config);

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertStringContainsString('authorization_endpoint', $result->get_error_message());
    }

    /**
     * Test that missing token_endpoint returns WP_Error.
     */
    public function testFromArrayWithMissingTokenEndpoint(): void
    {
        $config = $this->getSampleOIDCConfig();
        unset($config['token_endpoint']);

        $result = OIDC_Config::from_array($config);

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertStringContainsString('token_endpoint', $result->get_error_message());
    }

    /**
     * Test that missing jwks_uri returns WP_Error.
     */
    public function testFromArrayWithMissingJwksUri(): void
    {
        $config = $this->getSampleOIDCConfig();
        unset($config['jwks_uri']);

        $result = OIDC_Config::from_array($config);

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertStringContainsString('jwks_uri', $result->get_error_message());
    }

    /**
     * Test optional fields are null when not provided.
     */
    public function testOptionalFieldsAreNullWhenNotProvided(): void
    {
        $config = [
            'issuer' => 'https://idp.example.com',
            'authorization_endpoint' => 'https://idp.example.com/authorize',
            'token_endpoint' => 'https://idp.example.com/token',
            'jwks_uri' => 'https://idp.example.com/.well-known/jwks.json',
        ];

        $result = OIDC_Config::from_array($config);

        $this->assertInstanceOf(OIDC_Config::class, $result);
        $this->assertNull($result->get_userinfo_endpoint());
        $this->assertNull($result->get_end_session_endpoint());
    }

    /**
     * Test scopes_supported getter.
     */
    public function testGetScopesSupported(): void
    {
        $config = $this->getSampleOIDCConfig();
        $result = OIDC_Config::from_array($config);

        $this->assertSame(['openid', 'email', 'profile'], $result->get_scopes_supported());
    }

    /**
     * Test response_types_supported getter with default.
     */
    public function testGetResponseTypesSupportedDefault(): void
    {
        $config = [
            'issuer' => 'https://idp.example.com',
            'authorization_endpoint' => 'https://idp.example.com/authorize',
            'token_endpoint' => 'https://idp.example.com/token',
            'jwks_uri' => 'https://idp.example.com/.well-known/jwks.json',
        ];

        $result = OIDC_Config::from_array($config);

        $this->assertSame(['code'], $result->get_response_types_supported());
    }

    /**
     * Test grant_types_supported getter.
     */
    public function testGetGrantTypesSupported(): void
    {
        $config = $this->getSampleOIDCConfig();
        $result = OIDC_Config::from_array($config);

        $this->assertSame(['authorization_code', 'refresh_token'], $result->get_grant_types_supported());
    }

    /**
     * Test subject_types_supported getter.
     */
    public function testGetSubjectTypesSupported(): void
    {
        $config = $this->getSampleOIDCConfig();
        $result = OIDC_Config::from_array($config);

        $this->assertSame(['public'], $result->get_subject_types_supported());
    }

    /**
     * Test id_token_signing_alg_values_supported getter.
     */
    public function testGetIdTokenSigningAlgValuesSupported(): void
    {
        $config = $this->getSampleOIDCConfig();
        $result = OIDC_Config::from_array($config);

        $this->assertSame(['RS256', 'ES256'], $result->get_id_token_signing_alg_values_supported());
    }

    /**
     * Test claims_supported getter.
     */
    public function testGetClaimsSupported(): void
    {
        $config = $this->getSampleOIDCConfig();
        $result = OIDC_Config::from_array($config);

        $this->assertSame(['sub', 'iss', 'aud', 'exp', 'iat', 'email', 'name'], $result->get_claims_supported());
    }

    /**
     * Test supports_scope returns true for supported scope.
     */
    public function testSupportsScopeReturnsTrue(): void
    {
        $config = $this->getSampleOIDCConfig();
        $result = OIDC_Config::from_array($config);

        $this->assertTrue($result->supports_scope('openid'));
        $this->assertTrue($result->supports_scope('email'));
    }

    /**
     * Test supports_scope returns false for unsupported scope.
     */
    public function testSupportsScopeReturnsFalse(): void
    {
        $config = $this->getSampleOIDCConfig();
        $result = OIDC_Config::from_array($config);

        $this->assertFalse($result->supports_scope('unknown_scope'));
    }

    /**
     * Test supports_response_type returns true for supported type.
     */
    public function testSupportsResponseTypeReturnsTrue(): void
    {
        $config = $this->getSampleOIDCConfig();
        $result = OIDC_Config::from_array($config);

        $this->assertTrue($result->supports_response_type('code'));
        $this->assertTrue($result->supports_response_type('token'));
    }

    /**
     * Test supports_response_type returns false for unsupported type.
     */
    public function testSupportsResponseTypeReturnsFalse(): void
    {
        $config = $this->getSampleOIDCConfig();
        $result = OIDC_Config::from_array($config);

        $this->assertFalse($result->supports_response_type('unknown'));
    }

    /**
     * Test supports_pkce returns true when S256 is supported.
     */
    public function testSupportsPkceReturnsTrue(): void
    {
        $config = $this->getSampleOIDCConfig();
        $result = OIDC_Config::from_array($config);

        $this->assertTrue($result->supports_pkce());
    }

    /**
     * Test supports_pkce returns false when S256 is not supported.
     */
    public function testSupportsPkceReturnsFalse(): void
    {
        $config = $this->getSampleOIDCConfig();
        $config['code_challenge_methods_supported'] = ['plain'];
        $result = OIDC_Config::from_array($config);

        $this->assertFalse($result->supports_pkce());
    }

    /**
     * Test supports_logout returns true when end_session_endpoint is set.
     */
    public function testSupportsLogoutReturnsTrue(): void
    {
        $config = $this->getSampleOIDCConfig();
        $result = OIDC_Config::from_array($config);

        $this->assertTrue($result->supports_logout());
    }

    /**
     * Test supports_logout returns false when end_session_endpoint is not set.
     */
    public function testSupportsLogoutReturnsFalse(): void
    {
        $config = $this->getSampleOIDCConfig();
        unset($config['end_session_endpoint']);
        $result = OIDC_Config::from_array($config);

        $this->assertFalse($result->supports_logout());
    }

    /**
     * Test get_config_value returns value for existing key.
     */
    public function testGetConfigValueReturnsValue(): void
    {
        $config = $this->getSampleOIDCConfig();
        $config['custom_field'] = 'custom_value';
        $result = OIDC_Config::from_array($config);

        $this->assertSame('custom_value', $result->get_config_value('custom_field'));
    }

    /**
     * Test get_config_value returns null for non-existing key.
     */
    public function testGetConfigValueReturnsNull(): void
    {
        $config = $this->getSampleOIDCConfig();
        $result = OIDC_Config::from_array($config);

        $this->assertNull($result->get_config_value('non_existing_key'));
    }

    /**
     * Test to_array returns the original config.
     */
    public function testToArrayReturnsOriginalConfig(): void
    {
        $config = $this->getSampleOIDCConfig();
        $result = OIDC_Config::from_array($config);

        $this->assertSame($config, $result->to_array());
    }
}

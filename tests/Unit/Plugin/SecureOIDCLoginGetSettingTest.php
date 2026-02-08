<?php
/**
 * Tests for Secure_OIDC_Login::get_setting() method.
 *
 * @package SecureOIDCLogin\Tests\Unit\Plugin
 */

declare(strict_types=1);

namespace SecureOIDCLogin\Tests\Unit\Plugin;

use Brain\Monkey\Filters;
use SecureOIDCLogin\Tests\OIDCTestCase;
use Secure_OIDC_Login;

/**
 * Tests for the get_setting() static method.
 *
 * @covers Secure_OIDC_Login::get_setting
 */
class SecureOIDCLoginGetSettingTest extends OIDCTestCase
{
    /**
     * Test that get_setting returns the database value directly.
     */
    public function testGetSettingReturnsDatabaseValue(): void
    {
        $options = [
            'client_id'     => 'my-client-id',
            'client_secret' => 'my-client-secret',
            'issuer'        => 'https://idp.example.com',
        ];

        $this->assertSame('my-client-id', Secure_OIDC_Login::get_setting('client_id', $options));
        $this->assertSame('my-client-secret', Secure_OIDC_Login::get_setting('client_secret', $options));
        $this->assertSame('https://idp.example.com', Secure_OIDC_Login::get_setting('issuer', $options));
    }

    /**
     * Test that get_setting returns empty string for missing keys.
     */
    public function testGetSettingReturnsEmptyStringForMissingKey(): void
    {
        $this->assertSame('', Secure_OIDC_Login::get_setting('nonexistent', []));
    }

    /**
     * Test that no filter is applied to security-critical settings.
     *
     * This is a regression test to prevent reintroduction of runtime filters
     * on settings that control authentication endpoints, keys, and secrets.
     */
    public function testNoFilterAppliedToSettings(): void
    {
        $security_critical_keys = [
            'client_id',
            'client_secret',
            'token_endpoint',
            'authorization_endpoint',
            'jwks_uri',
            'issuer',
            'userinfo_endpoint',
            'end_session_endpoint',
            'token_endpoint_auth_method',
            'acr_values',
            'allowed_email_domains',
            'require_verified_email',
        ];

        $options = array_fill_keys($security_critical_keys, 'test-value');

        foreach ($security_critical_keys as $key) {
            Secure_OIDC_Login::get_setting($key, $options);
            $this->assertSame(
                0,
                Filters\applied('secure_oidc_login_setting_' . $key),
                "Filter 'secure_oidc_login_setting_{$key}' must not be applied to security-critical setting."
            );
        }
    }
}

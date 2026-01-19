<?php
/**
 * Tests for OIDC_Admin class.
 *
 * @package SecureOIDCLogin\Tests\Unit\Admin
 */

declare(strict_types=1);

namespace SecureOIDCLogin\Tests\Unit\Admin;

use Brain\Monkey\Functions;
use OIDC_Admin;
use SecureOIDCLogin\Tests\OIDCTestCase;
use WP_Error;

/**
 * Tests for the OIDC_Admin class.
 *
 * @covers OIDC_Admin
 */
class OIDCAdminTest extends OIDCTestCase
{
    private OIDC_Admin $admin;

    /**
     * Set up test environment.
     */
    protected function setUp(): void
    {
        parent::setUp();

        // Stub WordPress admin functions
        Functions\stubs([
            'add_action' => null,
            'add_options_page' => null,
            'register_setting' => null,
            'add_settings_section' => null,
            'add_settings_field' => null,
            'get_option' => static fn($option, $default = []) => $default,
            'current_user_can' => static fn($cap) => true,
            'wp_verify_nonce' => static fn($nonce, $action) => true,
            'add_settings_error' => null,
            'get_role' => static fn($role) => $role === 'subscriber' ? new \stdClass() : null,
            'home_url' => static fn($path = '') => 'https://example.com' . $path,
            'add_query_arg' => static fn($key, $val, $url = '') => "{$url}?{$key}={$val}",
            'get_admin_page_title' => static fn() => 'OIDC Authentication',
            'settings_fields' => null,
            'do_settings_sections' => null,
            'submit_button' => null,
            'wp_dropdown_roles' => null,
            'plugin_dir_url' => static fn($file) => 'https://example.com/wp-content/plugins/secure-oidc-login/',
            'wp_enqueue_script' => null,
            'wp_localize_script' => null,
            'rest_url' => static fn($path) => 'https://example.com/wp-json/' . $path,
            'wp_create_nonce' => static fn($action) => 'test-nonce',
        ]);

        $this->admin = new OIDC_Admin();
    }

    /**
     * Test constructor registers hooks.
     */
    public function testConstructorRegistersHooks(): void
    {
        // The constructor was called in setUp, so we just verify the object exists
        $this->assertInstanceOf(OIDC_Admin::class, $this->admin);
    }

    /**
     * Test validate_domain_list returns true for empty domains.
     */
    public function testValidateDomainListReturnsTrueForEmptyDomains(): void
    {
        $reflection = new \ReflectionMethod(OIDC_Admin::class, 'validate_domain_list');
        $reflection->setAccessible(true);

        $result = $reflection->invoke($this->admin, '');
        $this->assertTrue($result);

        $result = $reflection->invoke($this->admin, '   ');
        $this->assertTrue($result);
    }

    /**
     * Test validate_domain_list returns true for valid single domain.
     */
    public function testValidateDomainListReturnsTrueForValidSingleDomain(): void
    {
        $reflection = new \ReflectionMethod(OIDC_Admin::class, 'validate_domain_list');
        $reflection->setAccessible(true);

        $result = $reflection->invoke($this->admin, 'example.com');
        $this->assertTrue($result);
    }

    /**
     * Test validate_domain_list returns true for multiple valid domains.
     */
    public function testValidateDomainListReturnsTrueForMultipleValidDomains(): void
    {
        $reflection = new \ReflectionMethod(OIDC_Admin::class, 'validate_domain_list');
        $reflection->setAccessible(true);

        $result = $reflection->invoke($this->admin, 'example.com,test.org,sub.domain.io');
        $this->assertTrue($result);
    }

    /**
     * Test validate_domain_list returns true for wildcard domains.
     */
    public function testValidateDomainListReturnsTrueForWildcardDomains(): void
    {
        $reflection = new \ReflectionMethod(OIDC_Admin::class, 'validate_domain_list');
        $reflection->setAccessible(true);

        $result = $reflection->invoke($this->admin, '*.example.com');
        $this->assertTrue($result);

        $result = $reflection->invoke($this->admin, 'example.com,*.test.org');
        $this->assertTrue($result);
    }

    /**
     * Test validate_domain_list returns WP_Error for invalid domain format.
     */
    public function testValidateDomainListReturnsErrorForInvalidFormat(): void
    {
        $reflection = new \ReflectionMethod(OIDC_Admin::class, 'validate_domain_list');
        $reflection->setAccessible(true);

        $result = $reflection->invoke($this->admin, 'invalid domain.com');
        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertStringContainsString('Invalid domain format', $result->get_error_message());
    }

    /**
     * Test validate_domain_list returns WP_Error for domain starting with hyphen.
     */
    public function testValidateDomainListReturnsErrorForDomainStartingWithHyphen(): void
    {
        $reflection = new \ReflectionMethod(OIDC_Admin::class, 'validate_domain_list');
        $reflection->setAccessible(true);

        $result = $reflection->invoke($this->admin, '-example.com');
        $this->assertInstanceOf(WP_Error::class, $result);
    }

    /**
     * Test validate_domain_list ignores empty entries.
     */
    public function testValidateDomainListIgnoresEmptyEntries(): void
    {
        $reflection = new \ReflectionMethod(OIDC_Admin::class, 'validate_domain_list');
        $reflection->setAccessible(true);

        $result = $reflection->invoke($this->admin, 'example.com,,test.org,');
        $this->assertTrue($result);
    }

    /**
     * Test validate_domain_list handles whitespace.
     */
    public function testValidateDomainListHandlesWhitespace(): void
    {
        $reflection = new \ReflectionMethod(OIDC_Admin::class, 'validate_domain_list');
        $reflection->setAccessible(true);

        $result = $reflection->invoke($this->admin, ' example.com , test.org ');
        $this->assertTrue($result);
    }

    /**
     * Test get_max_lengths returns array with expected keys.
     */
    public function testGetMaxLengthsReturnsExpectedKeys(): void
    {
        $reflection = new \ReflectionMethod(OIDC_Admin::class, 'get_max_lengths');
        $reflection->setAccessible(true);

        $maxLengths = $reflection->invoke($this->admin);

        $this->assertIsArray($maxLengths);
        $this->assertArrayHasKey('client_id', $maxLengths);
        $this->assertArrayHasKey('client_secret', $maxLengths);
        $this->assertArrayHasKey('discovery_url', $maxLengths);
        $this->assertArrayHasKey('authorization_endpoint', $maxLengths);
        $this->assertArrayHasKey('token_endpoint', $maxLengths);
        $this->assertArrayHasKey('allowed_email_domains', $maxLengths);
    }

    /**
     * Test max length values are reasonable.
     */
    public function testMaxLengthValuesAreReasonable(): void
    {
        $reflection = new \ReflectionMethod(OIDC_Admin::class, 'get_max_lengths');
        $reflection->setAccessible(true);

        $maxLengths = $reflection->invoke($this->admin);

        // URLs should have generous limits
        $this->assertGreaterThanOrEqual(2048, $maxLengths['discovery_url']);
        $this->assertGreaterThanOrEqual(2048, $maxLengths['authorization_endpoint']);

        // Short fields should have reasonable limits
        $this->assertGreaterThanOrEqual(100, $maxLengths['login_button_text']);
        $this->assertLessThanOrEqual(200, $maxLengths['login_button_text']);

        // All values should be positive integers
        foreach ($maxLengths as $key => $value) {
            $this->assertIsInt($value, "Max length for {$key} should be int");
            $this->assertGreaterThan(0, $value, "Max length for {$key} should be positive");
        }
    }

    /**
     * Test sanitize_settings preserves valid text fields.
     */
    public function testSanitizeSettingsPreservesValidTextFields(): void
    {
        Functions\when('get_option')->justReturn([]);
        Functions\when('current_user_can')->justReturn(true);
        Functions\when('wp_verify_nonce')->justReturn(true);

        // Simulate POST data
        $_POST['_wpnonce'] = 'valid-nonce';

        $input = [
            'client_id' => 'test-client-id',
            'scope' => 'openid email profile',
            'login_button_text' => 'Sign In with SSO',
        ];

        $result = $this->admin->sanitize_settings($input);

        $this->assertSame('test-client-id', $result['client_id']);
        $this->assertSame('openid email profile', $result['scope']);
        $this->assertSame('Sign In with SSO', $result['login_button_text']);
    }

    /**
     * Test sanitize_settings handles checkbox fields.
     */
    public function testSanitizeSettingsHandlesCheckboxFields(): void
    {
        Functions\when('get_option')->justReturn([]);
        Functions\when('current_user_can')->justReturn(true);
        Functions\when('wp_verify_nonce')->justReturn(true);

        $_POST['_wpnonce'] = 'valid-nonce';

        $input = [
            'enable_single_logout' => '1',
            'create_users' => '1',
            'require_verified_email' => null,
        ];

        $result = $this->admin->sanitize_settings($input);

        $this->assertTrue($result['enable_single_logout']);
        $this->assertTrue($result['create_users']);
        $this->assertFalse($result['require_verified_email']);
    }

    /**
     * Test sanitize_settings validates URL fields.
     */
    public function testSanitizeSettingsValidatesUrlFields(): void
    {
        Functions\when('get_option')->justReturn([]);
        Functions\when('current_user_can')->justReturn(true);
        Functions\when('wp_verify_nonce')->justReturn(true);

        $_POST['_wpnonce'] = 'valid-nonce';

        $input = [
            'authorization_endpoint' => 'https://idp.example.com/authorize',
            'token_endpoint' => 'https://idp.example.com/token',
        ];

        $result = $this->admin->sanitize_settings($input);

        $this->assertSame('https://idp.example.com/authorize', $result['authorization_endpoint']);
        $this->assertSame('https://idp.example.com/token', $result['token_endpoint']);
    }
}

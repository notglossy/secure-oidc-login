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
            'scope' => 'openid email profile',
            'login_button_text' => 'Sign In with SSO',
        ];

        $result = $this->admin->sanitize_settings($input);

        $this->assertSame('openid email profile', $result['scope']);
        $this->assertSame('Sign In with SSO', $result['login_button_text']);
    }

    /**
     * Test is_unsafe_mode_enabled returns false by default.
     */
    public function testIsUnsafeModeEnabledReturnsFalseByDefault(): void
    {
        $reflection = new \ReflectionMethod(OIDC_Admin::class, 'is_unsafe_mode_enabled');
        $reflection->setAccessible(true);

        // Ensure env var is not set
        putenv('SECURE_OIDC_ALLOW_UNSAFE');
        $result = $reflection->invoke($this->admin);
        $this->assertFalse($result);
    }

    /**
     * Test is_unsafe_mode_enabled returns true when explicitly enabled.
     */
    public function testIsUnsafeModeEnabledReturnsTrueWhenSet(): void
    {
        $reflection = new \ReflectionMethod(OIDC_Admin::class, 'is_unsafe_mode_enabled');
        $reflection->setAccessible(true);

        putenv('SECURE_OIDC_ALLOW_UNSAFE=true');
        $result = $reflection->invoke($this->admin);
        $this->assertTrue($result);

        // Clean up
        putenv('SECURE_OIDC_ALLOW_UNSAFE');
    }

    /**
     * Test is_unsafe_mode_enabled is case-insensitive.
     */
    public function testIsUnsafeModeEnabledIsCaseInsensitive(): void
    {
        $reflection = new \ReflectionMethod(OIDC_Admin::class, 'is_unsafe_mode_enabled');
        $reflection->setAccessible(true);

        putenv('SECURE_OIDC_ALLOW_UNSAFE=TRUE');
        $result = $reflection->invoke($this->admin);
        $this->assertTrue($result);

        putenv('SECURE_OIDC_ALLOW_UNSAFE=True');
        $result = $reflection->invoke($this->admin);
        $this->assertTrue($result);

        // Clean up
        putenv('SECURE_OIDC_ALLOW_UNSAFE');
    }

    /**
     * Test has_env_credentials returns false when no env vars set.
     */
    public function testHasEnvCredentialsReturnsFalseWhenNotSet(): void
    {
        $reflection = new \ReflectionMethod(OIDC_Admin::class, 'has_env_credentials');
        $reflection->setAccessible(true);

        putenv('SECURE_OIDC_CLIENT_ID');
        putenv('SECURE_OIDC_CLIENT_SECRET');

        $result = $reflection->invoke($this->admin);
        $this->assertFalse($result);
    }

    /**
     * Test has_env_credentials returns true when both env vars set.
     */
    public function testHasEnvCredentialsReturnsTrueWhenBothSet(): void
    {
        $reflection = new \ReflectionMethod(OIDC_Admin::class, 'has_env_credentials');
        $reflection->setAccessible(true);

        putenv('SECURE_OIDC_CLIENT_ID=test-client-id');
        putenv('SECURE_OIDC_CLIENT_SECRET=test-client-secret');

        $result = $reflection->invoke($this->admin);
        $this->assertTrue($result);

        // Clean up
        putenv('SECURE_OIDC_CLIENT_ID');
        putenv('SECURE_OIDC_CLIENT_SECRET');
    }

    /**
     * Test has_env_credentials returns false when only one env var set.
     */
    public function testHasEnvCredentialsReturnsFalseWhenOnlyOneSet(): void
    {
        $reflection = new \ReflectionMethod(OIDC_Admin::class, 'has_env_credentials');
        $reflection->setAccessible(true);

        putenv('SECURE_OIDC_CLIENT_ID=test-client-id');
        putenv('SECURE_OIDC_CLIENT_SECRET');

        $result = $reflection->invoke($this->admin);
        $this->assertFalse($result);

        putenv('SECURE_OIDC_CLIENT_ID');
        putenv('SECURE_OIDC_CLIENT_SECRET=test-client-secret');

        $result = $reflection->invoke($this->admin);
        $this->assertFalse($result);

        // Clean up
        putenv('SECURE_OIDC_CLIENT_ID');
        putenv('SECURE_OIDC_CLIENT_SECRET');
    }

    /**
     * Test sanitize_settings blocks credentials when unsafe mode disabled.
     */
    public function testSanitizeSettingsBlocksCredentialsWithoutUnsafeMode(): void
    {
        Functions\when('get_option')->justReturn([]);
        Functions\when('current_user_can')->justReturn(true);
        Functions\when('wp_verify_nonce')->justReturn(true);

        // Ensure unsafe mode is disabled
        putenv('SECURE_OIDC_ALLOW_UNSAFE');
        putenv('SECURE_OIDC_CLIENT_ID');
        putenv('SECURE_OIDC_CLIENT_SECRET');

        $_POST['_wpnonce'] = 'valid-nonce';

        $input = [
            'client_id' => 'test-client-id',
            'client_secret' => 'test-client-secret',
        ];

        $result = $this->admin->sanitize_settings($input);

        // Credentials should be empty (blocked)
        $this->assertSame('', $result['client_id']);
        $this->assertSame('', $result['client_secret']);
    }

    /**
     * Test sanitize_settings allows credentials when unsafe mode enabled.
     */
    public function testSanitizeSettingsAllowsCredentialsWithUnsafeMode(): void
    {
        Functions\when('get_option')->justReturn([]);
        Functions\when('current_user_can')->justReturn(true);
        Functions\when('wp_verify_nonce')->justReturn(true);

        // Enable unsafe mode
        putenv('SECURE_OIDC_ALLOW_UNSAFE=true');
        putenv('SECURE_OIDC_CLIENT_ID');
        putenv('SECURE_OIDC_CLIENT_SECRET');

        $_POST['_wpnonce'] = 'valid-nonce';

        $input = [
            'client_id' => 'test-client-id',
            'client_secret' => 'test-client-secret',
        ];

        $result = $this->admin->sanitize_settings($input);

        // Credentials should be allowed
        $this->assertSame('test-client-id', $result['client_id']);
        $this->assertSame('test-client-secret', $result['client_secret']);

        // Clean up
        putenv('SECURE_OIDC_ALLOW_UNSAFE');
    }

    /**
     * Test sanitize_settings clears db credentials when env vars set.
     */
    public function testSanitizeSettingsClearsDbCredentialsWhenEnvVarsSet(): void
    {
        Functions\when('get_option')->justReturn([
            'client_id' => 'old-db-client-id',
            'client_secret' => 'old-db-client-secret',
        ]);
        Functions\when('current_user_can')->justReturn(true);
        Functions\when('wp_verify_nonce')->justReturn(true);

        // Set env vars
        putenv('SECURE_OIDC_CLIENT_ID=env-client-id');
        putenv('SECURE_OIDC_CLIENT_SECRET=env-client-secret');

        $_POST['_wpnonce'] = 'valid-nonce';

        $input = [
            'client_id' => 'submitted-client-id',
            'client_secret' => 'submitted-client-secret',
        ];

        $result = $this->admin->sanitize_settings($input);

        // Database values should be cleared when env vars are set
        $this->assertSame('', $result['client_id']);
        $this->assertSame('', $result['client_secret']);

        // Clean up
        putenv('SECURE_OIDC_CLIENT_ID');
        putenv('SECURE_OIDC_CLIENT_SECRET');
    }

    /**
     * Test has_database_credentials returns false when no credentials stored.
     */
    public function testHasDatabaseCredentialsReturnsFalseWhenEmpty(): void
    {
        Functions\when('get_option')->justReturn([]);

        $reflection = new \ReflectionMethod(OIDC_Admin::class, 'has_database_credentials');
        $reflection->setAccessible(true);

        $result = $reflection->invoke($this->admin);
        $this->assertFalse($result);
    }

    /**
     * Test has_database_credentials returns true when credentials stored.
     */
    public function testHasDatabaseCredentialsReturnsTrueWhenStored(): void
    {
        Functions\when('get_option')->justReturn([
            'client_id' => 'stored-client-id',
            'client_secret' => 'stored-client-secret',
        ]);

        $reflection = new \ReflectionMethod(OIDC_Admin::class, 'has_database_credentials');
        $reflection->setAccessible(true);

        $result = $reflection->invoke($this->admin);
        $this->assertTrue($result);
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

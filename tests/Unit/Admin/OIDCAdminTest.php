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
     * Test render_text_field disables client_id when unsafe mode disabled.
     */
    public function testRenderTextFieldDisablesClientIdWithoutUnsafeMode(): void
    {
        Functions\when('get_option')->justReturn(['client_id' => 'test-id']);
        Functions\when('esc_attr')->alias(fn($v) => $v);
        Functions\when('esc_html')->alias(fn($v) => $v);
        Functions\when('esc_html__')->alias(fn($v, $d) => $v);
        Functions\when('__')->alias(fn($v, $d) => $v);

        // Ensure unsafe mode is disabled
        putenv('SECURE_OIDC_ALLOW_UNSAFE');
        putenv('SECURE_OIDC_CLIENT_ID');

        ob_start();
        $this->admin->render_text_field(['field' => 'client_id', 'required' => true]);
        $output = ob_get_clean();

        $this->assertStringContainsString('disabled', $output);
        $this->assertStringContainsString('SECURE_OIDC_ALLOW_UNSAFE', $output);
    }

    /**
     * Test render_text_field enables client_id when unsafe mode enabled.
     */
    public function testRenderTextFieldEnablesClientIdWithUnsafeMode(): void
    {
        Functions\when('get_option')->justReturn(['client_id' => 'test-id']);
        Functions\when('esc_attr')->alias(fn($v) => $v);
        Functions\when('esc_html')->alias(fn($v) => $v);
        Functions\when('esc_html__')->alias(fn($v, $d) => $v);
        Functions\when('__')->alias(fn($v, $d) => $v);

        // Enable unsafe mode
        putenv('SECURE_OIDC_ALLOW_UNSAFE=true');
        putenv('SECURE_OIDC_CLIENT_ID');

        ob_start();
        $this->admin->render_text_field(['field' => 'client_id', 'required' => true]);
        $output = ob_get_clean();

        $this->assertStringNotContainsString(' disabled', $output);
        $this->assertStringContainsString('Warning:', $output);

        // Clean up
        putenv('SECURE_OIDC_ALLOW_UNSAFE');
    }

    /**
     * Test render_text_field shows override message when env var set.
     */
    public function testRenderTextFieldShowsEnvVarOverrideMessage(): void
    {
        Functions\when('get_option')->justReturn([]);
        Functions\when('esc_attr')->alias(fn($v) => $v);
        Functions\when('esc_html')->alias(fn($v) => $v);
        Functions\when('esc_html__')->alias(fn($v, $d) => $v);
        Functions\when('__')->alias(fn($v, $d) => $v);

        // Set env var
        putenv('SECURE_OIDC_CLIENT_ID=env-client-id');

        ob_start();
        $this->admin->render_text_field(['field' => 'client_id', 'required' => true]);
        $output = ob_get_clean();

        $this->assertStringContainsString('disabled', $output);
        $this->assertStringContainsString('overridden by', $output);

        // Clean up
        putenv('SECURE_OIDC_CLIENT_ID');
    }

    /**
     * Test render_password_field disables client_secret when unsafe mode disabled.
     */
    public function testRenderPasswordFieldDisablesClientSecretWithoutUnsafeMode(): void
    {
        Functions\when('get_option')->justReturn(['client_secret' => 'test-secret']);
        Functions\when('esc_attr')->alias(fn($v) => $v);
        Functions\when('esc_html')->alias(fn($v) => $v);
        Functions\when('esc_html__')->alias(fn($v, $d) => $v);
        Functions\when('__')->alias(fn($v, $d) => $v);

        // Ensure unsafe mode is disabled
        putenv('SECURE_OIDC_ALLOW_UNSAFE');
        putenv('SECURE_OIDC_CLIENT_SECRET');

        ob_start();
        $this->admin->render_password_field(['field' => 'client_secret']);
        $output = ob_get_clean();

        $this->assertStringContainsString('disabled', $output);
        $this->assertStringContainsString('SECURE_OIDC_ALLOW_UNSAFE', $output);
    }

    /**
     * Test render_password_field enables client_secret when unsafe mode enabled.
     */
    public function testRenderPasswordFieldEnablesClientSecretWithUnsafeMode(): void
    {
        Functions\when('get_option')->justReturn(['client_secret' => 'test-secret']);
        Functions\when('esc_attr')->alias(fn($v) => $v);
        Functions\when('esc_html')->alias(fn($v) => $v);
        Functions\when('esc_html__')->alias(fn($v, $d) => $v);
        Functions\when('__')->alias(fn($v, $d) => $v);

        // Enable unsafe mode
        putenv('SECURE_OIDC_ALLOW_UNSAFE=true');
        putenv('SECURE_OIDC_CLIENT_SECRET');

        ob_start();
        $this->admin->render_password_field(['field' => 'client_secret']);
        $output = ob_get_clean();

        $this->assertStringNotContainsString(' disabled', $output);
        $this->assertStringContainsString('Warning:', $output);

        // Clean up
        putenv('SECURE_OIDC_ALLOW_UNSAFE');
    }

    /**
     * Test render_password_field never emits the stored client_secret value into the DOM.
     */
    public function testRenderPasswordFieldDoesNotLeakStoredClientSecret(): void
    {
        Functions\when('get_option')->justReturn(['client_secret' => 'super-secret-value']);
        Functions\when('esc_attr')->alias(fn($v) => $v);
        Functions\when('esc_html')->alias(fn($v) => $v);
        Functions\when('esc_html__')->alias(fn($v, $d) => $v);
        Functions\when('__')->alias(fn($v, $d) => $v);

        putenv('SECURE_OIDC_ALLOW_UNSAFE=true');
        putenv('SECURE_OIDC_CLIENT_SECRET');

        ob_start();
        $this->admin->render_password_field(['field' => 'client_secret']);
        $output = ob_get_clean();

        // The stored value must never appear in the rendered input.
        $this->assertStringNotContainsString('super-secret-value', $output);
        $this->assertStringContainsString('value=""', $output);
        // A placeholder signals that a value is already stored.
        $this->assertStringContainsString('placeholder="', $output);

        putenv('SECURE_OIDC_ALLOW_UNSAFE');
    }

    /**
     * Test render_password_field omits placeholder when no client_secret is stored.
     */
    public function testRenderPasswordFieldOmitsPlaceholderWhenNoStoredSecret(): void
    {
        Functions\when('get_option')->justReturn([]);
        Functions\when('esc_attr')->alias(fn($v) => $v);
        Functions\when('esc_html')->alias(fn($v) => $v);
        Functions\when('esc_html__')->alias(fn($v, $d) => $v);
        Functions\when('__')->alias(fn($v, $d) => $v);

        putenv('SECURE_OIDC_ALLOW_UNSAFE=true');
        putenv('SECURE_OIDC_CLIENT_SECRET');

        ob_start();
        $this->admin->render_password_field(['field' => 'client_secret']);
        $output = ob_get_clean();

        $this->assertStringContainsString('value=""', $output);
        $this->assertStringNotContainsString('placeholder="', $output);

        putenv('SECURE_OIDC_ALLOW_UNSAFE');
    }

    /**
     * Test sanitize_settings preserves existing client_secret when submitted value is empty.
     *
     * The admin form intentionally renders an empty input for client_secret so
     * the stored value is never echoed into the DOM. Saving the form without
     * re-entering the secret must therefore keep the existing value instead
     * of wiping it.
     */
    public function testSanitizeSettingsPreservesClientSecretOnEmptySubmission(): void
    {
        Functions\when('get_option')->justReturn([
            'client_id' => 'existing-client-id',
            'client_secret' => 'existing-client-secret',
        ]);
        Functions\when('current_user_can')->justReturn(true);
        Functions\when('wp_verify_nonce')->justReturn(true);

        putenv('SECURE_OIDC_ALLOW_UNSAFE=true');
        putenv('SECURE_OIDC_CLIENT_ID');
        putenv('SECURE_OIDC_CLIENT_SECRET');

        $_POST['_wpnonce'] = 'valid-nonce';

        $input = [
            'client_id' => 'existing-client-id',
            'client_secret' => '',
        ];

        $result = $this->admin->sanitize_settings($input);

        $this->assertSame('existing-client-secret', $result['client_secret']);

        putenv('SECURE_OIDC_ALLOW_UNSAFE');
    }

    /**
     * Test sanitize_settings replaces client_secret when a new non-empty value is submitted.
     */
    public function testSanitizeSettingsReplacesClientSecretOnNonEmptySubmission(): void
    {
        Functions\when('get_option')->justReturn([
            'client_id' => 'existing-client-id',
            'client_secret' => 'existing-client-secret',
        ]);
        Functions\when('current_user_can')->justReturn(true);
        Functions\when('wp_verify_nonce')->justReturn(true);

        putenv('SECURE_OIDC_ALLOW_UNSAFE=true');
        putenv('SECURE_OIDC_CLIENT_ID');
        putenv('SECURE_OIDC_CLIENT_SECRET');

        $_POST['_wpnonce'] = 'valid-nonce';

        $input = [
            'client_id' => 'existing-client-id',
            'client_secret' => 'rotated-client-secret',
        ];

        $result = $this->admin->sanitize_settings($input);

        $this->assertSame('rotated-client-secret', $result['client_secret']);

        putenv('SECURE_OIDC_ALLOW_UNSAFE');
    }

    /**
     * Test sanitize_settings preserves existing credentials when unsafe mode disabled.
     */
    public function testSanitizeSettingsPreservesExistingCredentialsWithoutUnsafeMode(): void
    {
        Functions\when('get_option')->justReturn([
            'client_id' => 'existing-client-id',
            'client_secret' => 'existing-client-secret',
        ]);
        Functions\when('current_user_can')->justReturn(true);
        Functions\when('wp_verify_nonce')->justReturn(true);

        // Ensure unsafe mode is disabled
        putenv('SECURE_OIDC_ALLOW_UNSAFE');
        putenv('SECURE_OIDC_CLIENT_ID');
        putenv('SECURE_OIDC_CLIENT_SECRET');

        $_POST['_wpnonce'] = 'valid-nonce';

        $input = [
            'client_id' => 'new-client-id',
            'client_secret' => 'new-client-secret',
        ];

        $result = $this->admin->sanitize_settings($input);

        // Should preserve existing values, not accept new ones
        $this->assertSame('existing-client-id', $result['client_id']);
        $this->assertSame('existing-client-secret', $result['client_secret']);
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

    /**
     * Test render_checkbox_field outputs checkbox input.
     */
    public function testRenderCheckboxFieldOutputsCheckboxInput(): void
    {
        Functions\when('get_option')->justReturn(['enable_single_logout' => true]);
        Functions\when('esc_attr')->alias(fn($v) => $v);
        Functions\when('esc_html')->alias(fn($v) => $v);
        Functions\when('esc_html__')->alias(fn($v, $d) => $v);

        ob_start();
        $this->admin->render_checkbox_field(['field' => 'enable_single_logout']);
        $output = ob_get_clean();

        $this->assertStringContainsString('type="checkbox"', $output);
        $this->assertStringContainsString('name="secure_oidc_login_settings[enable_single_logout]"', $output);
        $this->assertStringContainsString('checked', $output);
    }

    /**
     * Test render_checkbox_field outputs unchecked when value is false.
     */
    public function testRenderCheckboxFieldOutputsUncheckedWhenFalse(): void
    {
        Functions\when('get_option')->justReturn(['enable_single_logout' => false]);
        Functions\when('esc_attr')->alias(fn($v) => $v);
        Functions\when('esc_html')->alias(fn($v) => $v);
        Functions\when('esc_html__')->alias(fn($v, $d) => $v);

        ob_start();
        $this->admin->render_checkbox_field(['field' => 'enable_single_logout']);
        $output = ob_get_clean();

        $this->assertStringContainsString('type="checkbox"', $output);
        $this->assertStringNotContainsString('checked', $output);
    }

    /**
     * Test render_checkbox_field shows security warning when require_verified_email is disabled.
     */
    public function testRenderCheckboxFieldShowsSecurityWarningForDisabledEmailVerification(): void
    {
        Functions\when('get_option')->justReturn(['require_verified_email' => false]);
        Functions\when('esc_attr')->alias(fn($v) => $v);
        Functions\when('esc_html')->alias(fn($v) => $v);
        Functions\when('esc_html__')->alias(fn($v, $d) => $v);

        ob_start();
        $this->admin->render_checkbox_field(['field' => 'require_verified_email']);
        $output = ob_get_clean();

        $this->assertStringContainsString('Security Warning:', $output);
        $this->assertStringContainsString('account takeover', $output);
    }

    /**
     * Test render_checkbox_field does not show security warning when require_verified_email is enabled.
     */
    public function testRenderCheckboxFieldNoWarningWhenEmailVerificationEnabled(): void
    {
        Functions\when('get_option')->justReturn(['require_verified_email' => true]);
        Functions\when('esc_attr')->alias(fn($v) => $v);
        Functions\when('esc_html')->alias(fn($v) => $v);
        Functions\when('esc_html__')->alias(fn($v, $d) => $v);

        ob_start();
        $this->admin->render_checkbox_field(['field' => 'require_verified_email']);
        $output = ob_get_clean();

        $this->assertStringNotContainsString('Security Warning:', $output);
    }

    /**
     * Test render_checkbox_field includes description when provided.
     */
    public function testRenderCheckboxFieldIncludesDescription(): void
    {
        Functions\when('get_option')->justReturn([]);
        Functions\when('esc_attr')->alias(fn($v) => $v);
        Functions\when('esc_html')->alias(fn($v) => $v);

        ob_start();
        $this->admin->render_checkbox_field([
            'field' => 'create_users',
            'description' => 'Allow automatic user creation',
        ]);
        $output = ob_get_clean();

        $this->assertStringContainsString('Allow automatic user creation', $output);
        $this->assertStringContainsString('class="description"', $output);
    }

    /**
     * Test render_number_field outputs number input with value.
     */
    public function testRenderNumberFieldOutputsNumberInputWithValue(): void
    {
        Functions\when('get_option')->justReturn(['token_expiry_buffer' => 300]);
        Functions\when('esc_attr')->alias(fn($v) => (string) $v);

        ob_start();
        $this->admin->render_number_field(['field' => 'token_expiry_buffer', 'default' => 60]);
        $output = ob_get_clean();

        $this->assertStringContainsString('type="number"', $output);
        $this->assertStringContainsString('name="secure_oidc_login_settings[token_expiry_buffer]"', $output);
        $this->assertStringContainsString('value="300"', $output);
    }

    /**
     * Test render_number_field uses default when no value set.
     */
    public function testRenderNumberFieldUsesDefaultWhenNoValueSet(): void
    {
        Functions\when('get_option')->justReturn([]);
        Functions\when('esc_attr')->alias(fn($v) => (string) $v);

        ob_start();
        $this->admin->render_number_field(['field' => 'token_expiry_buffer', 'default' => 60]);
        $output = ob_get_clean();

        $this->assertStringContainsString('value="60"', $output);
    }

    /**
     * Test render_number_field includes min and max attributes.
     */
    public function testRenderNumberFieldIncludesMinMaxAttributes(): void
    {
        Functions\when('get_option')->justReturn([]);
        Functions\when('esc_attr')->alias(fn($v) => (string) $v);

        ob_start();
        $this->admin->render_number_field([
            'field' => 'token_expiry_buffer',
            'default' => 60,
            'min' => 0,
            'max' => 3600,
        ]);
        $output = ob_get_clean();

        $this->assertStringContainsString('min="0"', $output);
        $this->assertStringContainsString('max="3600"', $output);
    }

    /**
     * Test render_number_field includes description when provided.
     */
    public function testRenderNumberFieldIncludesDescription(): void
    {
        Functions\when('get_option')->justReturn([]);
        Functions\when('esc_attr')->alias(fn($v) => (string) $v);
        Functions\when('esc_html')->alias(fn($v) => $v);

        ob_start();
        $this->admin->render_number_field([
            'field' => 'token_expiry_buffer',
            'default' => 60,
            'description' => 'Buffer in seconds before token expiry',
        ]);
        $output = ob_get_clean();

        $this->assertStringContainsString('Buffer in seconds before token expiry', $output);
        $this->assertStringContainsString('class="description"', $output);
    }

    /**
     * Test render_role_field outputs select element.
     */
    public function testRenderRoleFieldOutputsSelectElement(): void
    {
        Functions\when('get_option')->justReturn(['default_role' => 'subscriber']);
        Functions\when('esc_attr')->alias(fn($v) => $v);
        Functions\when('esc_html')->alias(fn($v) => $v);
        Functions\when('esc_html__')->alias(fn($v, $d) => $v);
        Functions\when('wp_dropdown_roles')->justReturn(null);

        ob_start();
        $this->admin->render_role_field(['field' => 'default_role']);
        $output = ob_get_clean();

        $this->assertStringContainsString('<select', $output);
        $this->assertStringContainsString('name="secure_oidc_login_settings[default_role]"', $output);
        $this->assertStringContainsString('id="default_role"', $output);
    }

    /**
     * Test render_role_field defaults to subscriber when no value set.
     */
    public function testRenderRoleFieldDefaultsToSubscriber(): void
    {
        Functions\when('get_option')->justReturn([]);
        Functions\when('esc_attr')->alias(fn($v) => $v);
        Functions\when('esc_html')->alias(fn($v) => $v);
        Functions\when('esc_html__')->alias(fn($v, $d) => $v);

        $selectedRole = null;
        Functions\when('wp_dropdown_roles')->alias(function ($role) use (&$selectedRole) {
            $selectedRole = $role;
        });

        ob_start();
        $this->admin->render_role_field(['field' => 'default_role']);
        ob_get_clean();

        $this->assertSame('subscriber', $selectedRole);
    }

    /**
     * Test render_role_field includes description.
     */
    public function testRenderRoleFieldIncludesDescription(): void
    {
        Functions\when('get_option')->justReturn([]);
        Functions\when('esc_attr')->alias(fn($v) => $v);
        Functions\when('esc_html')->alias(fn($v) => $v);
        Functions\when('esc_html__')->alias(fn($v, $d) => $v);
        Functions\when('wp_dropdown_roles')->justReturn(null);

        ob_start();
        $this->admin->render_role_field(['field' => 'default_role']);
        $output = ob_get_clean();

        $this->assertStringContainsString('Role assigned to new users', $output);
        $this->assertStringContainsString('class="description"', $output);
    }

    /**
     * Test admin_notices shows warning when OIDC not configured.
     */
    public function testAdminNoticesShowsWarningWhenOidcNotConfigured(): void
    {
        Functions\when('get_option')->justReturn([]);
        Functions\when('esc_html')->alias(fn($v) => $v);
        Functions\when('esc_html__')->alias(fn($v, $d) => $v);
        Functions\when('esc_attr')->alias(fn($v) => $v);
        Functions\when('get_transient')->justReturn(false);
        Functions\when('set_transient')->justReturn(true);

        $_GET['page'] = 'secure-oidc-login';

        ob_start();
        $this->admin->admin_notices();
        $output = ob_get_clean();

        $this->assertStringContainsString('notice-warning', $output);
    }

    /**
     * Test admin_notices does not show on other admin pages.
     */
    public function testAdminNoticesDoesNotShowOnOtherPages(): void
    {
        $_GET['page'] = 'other-plugin';

        ob_start();
        $this->admin->admin_notices();
        $output = ob_get_clean();

        $this->assertEmpty($output);
    }

    /**
     * Test admin_notices shows error when native login disabled but OIDC not configured.
     */
    public function testAdminNoticesShowsErrorWhenNativeLoginDisabledWithoutOidc(): void
    {
        Functions\when('get_option')->justReturn([
            'disable_native_login' => true,
            // Missing client_id, authorization_endpoint, token_endpoint
        ]);
        Functions\when('esc_html')->alias(fn($v) => $v);
        Functions\when('esc_html__')->alias(fn($v, $d) => $v);
        Functions\when('esc_attr')->alias(fn($v) => $v);
        Functions\when('get_transient')->justReturn(false);
        Functions\when('set_transient')->justReturn(true);

        $_GET['page'] = 'secure-oidc-login';

        ob_start();
        $this->admin->admin_notices();
        $output = ob_get_clean();

        $this->assertStringContainsString('notice-error', $output);
        $this->assertStringContainsString('locked out', $output);
    }

    /**
     * Test admin_notices shows emergency bypass notice when bypass enabled.
     */
    public function testAdminNoticesShowsBypassNoticeWhenBypassEnabled(): void
    {
        putenv('SECURE_OIDC_ENABLE_EMERGENCY_BYPASS=true');

        Functions\when('get_option')->justReturn([
            'disable_native_login' => true,
            'client_id' => 'test-client',
            'authorization_endpoint' => 'https://idp.example.com/authorize',
            'token_endpoint' => 'https://idp.example.com/token',
        ]);
        Functions\when('esc_html')->alias(fn($v) => $v);
        Functions\when('esc_html__')->alias(fn($v, $d) => $v);
        Functions\when('esc_attr')->alias(fn($v) => $v);
        Functions\when('wp_login_url')->justReturn('https://example.com/wp-login.php');
        Functions\when('get_transient')->justReturn(false);
        Functions\when('set_transient')->justReturn(true);
        Functions\when('admin_url')->justReturn('https://example.com/wp-admin/');
        Functions\when('wp_nonce_field')->justReturn(null);

        $_GET['page'] = 'secure-oidc-login';

        ob_start();
        $this->admin->admin_notices();
        $output = ob_get_clean();

        $this->assertStringContainsString('notice-info', $output);
        $this->assertStringContainsString('Emergency admin access', $output);
        $this->assertStringContainsString('?native=1', $output);

        putenv('SECURE_OIDC_ENABLE_EMERGENCY_BYPASS');
    }

    /**
     * Test admin_notices does not show bypass notice when bypass disabled.
     */
    public function testAdminNoticesDoesNotShowBypassNoticeWhenBypassDisabled(): void
    {
        putenv('SECURE_OIDC_ENABLE_EMERGENCY_BYPASS');

        Functions\when('get_option')->justReturn([
            'disable_native_login' => true,
            'client_id' => 'test-client',
            'authorization_endpoint' => 'https://idp.example.com/authorize',
            'token_endpoint' => 'https://idp.example.com/token',
        ]);
        Functions\when('esc_html')->alias(fn($v) => $v);
        Functions\when('esc_html__')->alias(fn($v, $d) => $v);
        Functions\when('esc_attr')->alias(fn($v) => $v);
        Functions\when('get_transient')->justReturn(false);
        Functions\when('set_transient')->justReturn(true);
        Functions\when('admin_url')->justReturn('https://example.com/wp-admin/');
        Functions\when('wp_nonce_field')->justReturn(null);

        $_GET['page'] = 'secure-oidc-login';

        ob_start();
        $this->admin->admin_notices();
        $output = ob_get_clean();

        $this->assertStringNotContainsString('Emergency admin access', $output);
    }

    // =========================================================================
    // Token Endpoint Auth Method Radio Field Tests
    // =========================================================================

    /**
     * Test render_radio_field outputs both radio options.
     */
    public function testRenderRadioFieldOutputsBothOptions(): void
    {
        Functions\when('get_option')->justReturn([]);
        Functions\when('esc_attr')->alias(fn($v) => $v);
        Functions\when('esc_html')->alias(fn($v) => $v);
        Functions\when('esc_html__')->alias(fn($v, $d) => $v);
        Functions\when('checked')->alias(fn($checked, $current, $echo = true) => $checked === $current ? 'checked=\'checked\'' : '');

        putenv('SECURE_OIDC_TOKEN_ENDPOINT_AUTH_METHOD');

        ob_start();
        $this->admin->render_radio_field([
            'field' => 'token_endpoint_auth_method',
            'options' => [
                'client_secret_basic' => 'Client Secret Basic (credentials in Authorization header)',
                'client_secret_post' => 'Client Secret Post (credentials in request body)',
            ],
            'default' => 'client_secret_basic',
        ]);
        $output = ob_get_clean();

        $this->assertStringContainsString('type="radio"', $output);
        $this->assertStringContainsString('value="client_secret_basic"', $output);
        $this->assertStringContainsString('value="client_secret_post"', $output);
        $this->assertStringContainsString('Client Secret Basic', $output);
        $this->assertStringContainsString('Client Secret Post', $output);
    }

    /**
     * Test render_radio_field selects default value when no option stored.
     */
    public function testRenderRadioFieldSelectsDefaultValue(): void
    {
        Functions\when('get_option')->justReturn([]);
        Functions\when('esc_attr')->alias(fn($v) => $v);
        Functions\when('esc_html')->alias(fn($v) => $v);
        Functions\when('esc_html__')->alias(fn($v, $d) => $v);
        Functions\when('checked')->alias(fn($checked, $current, $echo = true) => $checked === $current ? 'checked=\'checked\'' : '');

        putenv('SECURE_OIDC_TOKEN_ENDPOINT_AUTH_METHOD');

        ob_start();
        $this->admin->render_radio_field([
            'field' => 'token_endpoint_auth_method',
            'options' => [
                'client_secret_basic' => 'Basic',
                'client_secret_post' => 'Post',
            ],
            'default' => 'client_secret_basic',
        ]);
        $output = ob_get_clean();

        // The default option should be checked
        $this->assertMatchesRegularExpression(
            '/value="client_secret_basic".*checked/',
            $output
        );
    }

    /**
     * Test render_radio_field disables inputs when env var is set.
     */
    public function testRenderRadioFieldDisabledWhenEnvVarSet(): void
    {
        Functions\when('get_option')->justReturn([]);
        Functions\when('esc_attr')->alias(fn($v) => $v);
        Functions\when('esc_html')->alias(fn($v) => $v);
        Functions\when('esc_html__')->alias(fn($v, $d) => $v);
        Functions\when('checked')->alias(fn($checked, $current, $echo = true) => $checked === $current ? 'checked=\'checked\'' : '');

        putenv('SECURE_OIDC_TOKEN_ENDPOINT_AUTH_METHOD=client_secret_post');

        ob_start();
        $this->admin->render_radio_field([
            'field' => 'token_endpoint_auth_method',
            'options' => [
                'client_secret_basic' => 'Basic',
                'client_secret_post' => 'Post',
            ],
            'default' => 'client_secret_basic',
        ]);
        $output = ob_get_clean();

        $this->assertStringContainsString('disabled', $output);
        $this->assertStringContainsString('overridden by', $output);
        $this->assertStringContainsString('SECURE_OIDC_TOKEN_ENDPOINT_AUTH_METHOD', $output);

        putenv('SECURE_OIDC_TOKEN_ENDPOINT_AUTH_METHOD');
    }

    /**
     * Test render_radio_field uses env var value when set.
     */
    public function testRenderRadioFieldUsesEnvVarValue(): void
    {
        Functions\when('get_option')->justReturn(['token_endpoint_auth_method' => 'client_secret_basic']);
        Functions\when('esc_attr')->alias(fn($v) => $v);
        Functions\when('esc_html')->alias(fn($v) => $v);
        Functions\when('esc_html__')->alias(fn($v, $d) => $v);
        Functions\when('checked')->alias(fn($checked, $current, $echo = true) => $checked === $current ? 'checked=\'checked\'' : '');

        putenv('SECURE_OIDC_TOKEN_ENDPOINT_AUTH_METHOD=client_secret_post');

        ob_start();
        $this->admin->render_radio_field([
            'field' => 'token_endpoint_auth_method',
            'options' => [
                'client_secret_basic' => 'Basic',
                'client_secret_post' => 'Post',
            ],
            'default' => 'client_secret_basic',
        ]);
        $output = ob_get_clean();

        // Env var value (client_secret_post) should be checked, not the stored value
        $this->assertMatchesRegularExpression(
            '/value="client_secret_post".*checked/',
            $output
        );

        putenv('SECURE_OIDC_TOKEN_ENDPOINT_AUTH_METHOD');
    }

    /**
     * Test sanitize_settings validates token_endpoint_auth_method.
     */
    public function testSanitizeSettingsValidatesTokenEndpointAuthMethod(): void
    {
        Functions\when('get_option')->justReturn([]);
        Functions\when('current_user_can')->justReturn(true);
        Functions\when('wp_verify_nonce')->justReturn(true);

        $_POST['_wpnonce'] = 'valid-nonce';

        $input = [
            'token_endpoint_auth_method' => 'client_secret_post',
        ];

        $result = $this->admin->sanitize_settings($input);

        $this->assertSame('client_secret_post', $result['token_endpoint_auth_method']);
    }

    /**
     * Test sanitize_settings defaults invalid token_endpoint_auth_method to client_secret_basic.
     */
    public function testSanitizeSettingsDefaultsInvalidAuthMethod(): void
    {
        Functions\when('get_option')->justReturn([]);
        Functions\when('current_user_can')->justReturn(true);
        Functions\when('wp_verify_nonce')->justReturn(true);

        $_POST['_wpnonce'] = 'valid-nonce';

        $input = [
            'token_endpoint_auth_method' => 'invalid_method',
        ];

        $result = $this->admin->sanitize_settings($input);

        $this->assertSame('client_secret_basic', $result['token_endpoint_auth_method']);
    }

    /**
     * Test sanitize_settings defaults missing token_endpoint_auth_method.
     */
    public function testSanitizeSettingsDefaultsMissingAuthMethod(): void
    {
        Functions\when('get_option')->justReturn([]);
        Functions\when('current_user_can')->justReturn(true);
        Functions\when('wp_verify_nonce')->justReturn(true);

        $_POST['_wpnonce'] = 'valid-nonce';

        $input = [];

        $result = $this->admin->sanitize_settings($input);

        $this->assertSame('client_secret_basic', $result['token_endpoint_auth_method']);
    }

    // =========================================================================
    // ACR Values Settings Tests
    // =========================================================================

    /**
     * Test sanitize_settings handles acr_values as text field.
     */
    public function testSanitizeSettingsHandlesAcrValuesAsTextField(): void
    {
        Functions\when('get_option')->justReturn([]);
        Functions\when('current_user_can')->justReturn(true);
        Functions\when('wp_verify_nonce')->justReturn(true);

        putenv('SECURE_OIDC_ACR_VALUES');

        $_POST['_wpnonce'] = 'valid-nonce';

        $input = [
            'acr_values' => 'urn:mace:incommon:iap:silver urn:mace:incommon:iap:bronze',
        ];

        $result = $this->admin->sanitize_settings($input);

        $this->assertSame('urn:mace:incommon:iap:silver urn:mace:incommon:iap:bronze', $result['acr_values']);
    }

    /**
     * Test sanitize_settings handles enforce_acr as boolean checkbox.
     */
    public function testSanitizeSettingsHandlesEnforceAcrAsBoolean(): void
    {
        Functions\when('get_option')->justReturn([]);
        Functions\when('current_user_can')->justReturn(true);
        Functions\when('wp_verify_nonce')->justReturn(true);

        $_POST['_wpnonce'] = 'valid-nonce';

        // Checked
        $input = ['enforce_acr' => '1'];
        $result = $this->admin->sanitize_settings($input);
        $this->assertTrue($result['enforce_acr']);

        // Unchecked (missing from input)
        $input = [];
        $result = $this->admin->sanitize_settings($input);
        $this->assertFalse($result['enforce_acr']);
    }

    /**
     * Test sanitize_settings triggers error for acr_values exceeding max length.
     */
    public function testSanitizeSettingsTriggersErrorForLongAcrValues(): void
    {
        Functions\when('get_option')->justReturn([]);
        Functions\when('current_user_can')->justReturn(true);
        Functions\when('wp_verify_nonce')->justReturn(true);

        $settingsErrorAdded = false;
        Functions\when('add_settings_error')->alias(function ($setting, $code, $message) use (&$settingsErrorAdded) {
            if ($code === 'acr_values_too_long') {
                $settingsErrorAdded = true;
            }
        });

        putenv('SECURE_OIDC_ACR_VALUES');

        $_POST['_wpnonce'] = 'valid-nonce';

        $input = [
            'acr_values' => str_repeat('a', 1025),
        ];

        $result = $this->admin->sanitize_settings($input);

        $this->assertTrue($settingsErrorAdded, 'Settings error should be triggered for long acr_values');
        // Value should be preserved from existing settings (empty in this case)
        $this->assertSame('', $result['acr_values']);
    }

    /**
     * Test get_max_lengths includes acr_values with value 1024.
     */
    public function testGetMaxLengthsIncludesAcrValues(): void
    {
        $reflection = new \ReflectionMethod(OIDC_Admin::class, 'get_max_lengths');
        $reflection->setAccessible(true);

        $maxLengths = $reflection->invoke($this->admin);

        $this->assertArrayHasKey('acr_values', $maxLengths);
        $this->assertSame(1024, $maxLengths['acr_values']);
    }

    /**
     * Test sanitize_settings parses and stores valid signing algorithms from discovery.
     */
    public function testSanitizeSettingsStoresDiscoveredSigningAlgorithms(): void
    {
        Functions\when('get_option')->justReturn([]);
        Functions\when('current_user_can')->justReturn(true);
        Functions\when('wp_verify_nonce')->justReturn(true);

        $_POST['_wpnonce'] = 'valid-nonce';

        $input = [
            'id_token_signing_alg_values_supported' => json_encode(['RS256', 'ES256']),
        ];

        $result = $this->admin->sanitize_settings($input);

        $this->assertSame(['RS256', 'ES256'], $result['id_token_signing_alg_values_supported']);
    }

    /**
     * Test sanitize_settings filters out unsafe algorithms from discovery.
     *
     * If an IdP's discovery document includes symmetric algorithms, they should
     * be filtered out by the intersection with OIDC_Client::ALLOWED_JWT_ALGORITHMS.
     */
    public function testSanitizeSettingsFiltersUnsafeAlgorithmsFromDiscovery(): void
    {
        Functions\when('get_option')->justReturn([]);
        Functions\when('current_user_can')->justReturn(true);
        Functions\when('wp_verify_nonce')->justReturn(true);

        $_POST['_wpnonce'] = 'valid-nonce';

        // Simulate an IdP that claims to support HS256 and RS256
        $input = [
            'id_token_signing_alg_values_supported' => json_encode(['RS256', 'HS256', 'none']),
        ];

        $result = $this->admin->sanitize_settings($input);

        // Only RS256 should survive the intersection with ALLOWED_JWT_ALGORITHMS
        $this->assertSame(['RS256'], $result['id_token_signing_alg_values_supported']);
    }

    /**
     * Test sanitize_settings preserves existing algorithms when input is empty.
     */
    public function testSanitizeSettingsPreservesExistingAlgorithmsWhenInputEmpty(): void
    {
        Functions\when('get_option')->justReturn([
            'id_token_signing_alg_values_supported' => ['RS256', 'ES256'],
        ]);
        Functions\when('current_user_can')->justReturn(true);
        Functions\when('wp_verify_nonce')->justReturn(true);

        $_POST['_wpnonce'] = 'valid-nonce';

        // No algorithm field in input (form submitted without discovery)
        $input = [];

        $result = $this->admin->sanitize_settings($input);

        $this->assertSame(['RS256', 'ES256'], $result['id_token_signing_alg_values_supported']);
    }

    /**
     * Test sanitize_settings handles invalid JSON in algorithm field.
     */
    public function testSanitizeSettingsHandlesInvalidJsonInAlgorithmField(): void
    {
        Functions\when('get_option')->justReturn([
            'id_token_signing_alg_values_supported' => ['RS256'],
        ]);
        Functions\when('current_user_can')->justReturn(true);
        Functions\when('wp_verify_nonce')->justReturn(true);

        $_POST['_wpnonce'] = 'valid-nonce';

        // Invalid JSON in the field
        $input = [
            'id_token_signing_alg_values_supported' => 'not-valid-json',
        ];

        $result = $this->admin->sanitize_settings($input);

        // Should preserve existing value
        $this->assertSame(['RS256'], $result['id_token_signing_alg_values_supported']);
    }

    /**
     * Test admin_notices shows domain filtering notice when domains configured.
     */
    public function testAdminNoticesShowsDomainFilteringNotice(): void
    {
        Functions\when('get_option')->justReturn([
            'client_id' => 'test-client',
            'authorization_endpoint' => 'https://idp.example.com/authorize',
            'token_endpoint' => 'https://idp.example.com/token',
            'allowed_email_domains' => 'example.com,test.org',
        ]);
        Functions\when('esc_html')->alias(fn($v) => $v);
        Functions\when('esc_html__')->alias(fn($v, $d) => $v);
        Functions\when('esc_attr')->alias(fn($v) => $v);
        Functions\when('getenv')->justReturn(false);
        Functions\when('get_transient')->justReturn(false);
        Functions\when('set_transient')->justReturn(true);
        Functions\when('admin_url')->justReturn('https://example.com/wp-admin/');
        Functions\when('wp_nonce_field')->justReturn(null);

        $_GET['page'] = 'secure-oidc-login';

        ob_start();
        $this->admin->admin_notices();
        $output = ob_get_clean();

        $this->assertStringContainsString('Email Domain Filtering Active', $output);
        $this->assertStringContainsString('example.com,test.org', $output);
    }

    /**
     * Test render_signing_alg_hidden_field outputs hidden input with stored algorithms.
     */
    public function testRenderSigningAlgHiddenFieldWithStoredAlgorithms(): void
    {
        Functions\when('get_option')->justReturn([
            'id_token_signing_alg_values_supported' => ['RS256', 'ES256'],
        ]);
        Functions\when('esc_attr')->alias(fn($v) => $v);
        Functions\when('wp_json_encode')->alias(fn($data) => json_encode($data));

        ob_start();
        $this->admin->render_signing_alg_hidden_field();
        $output = ob_get_clean();

        $this->assertStringContainsString('type="hidden"', $output);
        $this->assertStringContainsString('name="secure_oidc_login_settings[id_token_signing_alg_values_supported]"', $output);
        $this->assertStringContainsString('["RS256","ES256"]', $output);
    }

    /**
     * Test render_signing_alg_hidden_field outputs empty value when no algorithms stored.
     */
    public function testRenderSigningAlgHiddenFieldWithNoStoredAlgorithms(): void
    {
        Functions\when('get_option')->justReturn([]);
        Functions\when('esc_attr')->alias(fn($v) => $v);

        ob_start();
        $this->admin->render_signing_alg_hidden_field();
        $output = ob_get_clean();

        $this->assertStringContainsString('type="hidden"', $output);
        $this->assertStringContainsString('value=""', $output);
    }

    /**
     * Test render_signing_alg_hidden_field handles non-array value gracefully.
     */
    public function testRenderSigningAlgHiddenFieldWithNonArrayValue(): void
    {
        Functions\when('get_option')->justReturn([
            'id_token_signing_alg_values_supported' => 'not-an-array',
        ]);
        Functions\when('esc_attr')->alias(fn($v) => $v);

        ob_start();
        $this->admin->render_signing_alg_hidden_field();
        $output = ob_get_clean();

        $this->assertStringContainsString('value=""', $output);
    }

    /**
     * Test register_settings registers the signing algorithm hidden field.
     */
    public function testRegisterSettingsRegistersSigningAlgField(): void
    {
        $registered_fields = [];

        Functions\when('register_setting')->justReturn(null);
        Functions\when('add_settings_section')->justReturn(null);
        Functions\when('__')->alias(fn($v, $d = '') => $v);
        Functions\when('esc_html__')->alias(fn($v, $d = '') => $v);
        Functions\when('add_settings_field')->alias(function ($id, $title, $callback, $page, $section, $args = []) use (&$registered_fields) {
            $registered_fields[$id] = [
                'title' => $title,
                'callback' => $callback,
                'section' => $section,
            ];
        });

        $this->admin->register_settings();

        $this->assertArrayHasKey('id_token_signing_alg_values_supported', $registered_fields);
        $this->assertSame('', $registered_fields['id_token_signing_alg_values_supported']['title']);
        $this->assertSame('oidc_provider_section', $registered_fields['id_token_signing_alg_values_supported']['section']);
    }

    // =========================================================================
    // Object Cache Invalidation Tests
    // =========================================================================

    /**
     * Test constructor registers the update_option cache invalidation hook.
     */
    public function testConstructorRegistersSettingsCacheInvalidationHook(): void
    {
        $registered_actions = [];

        Functions\when('add_action')->alias(function ($hook, $callback, $priority = 10, $accepted_args = 1) use (&$registered_actions) {
            $registered_actions[] = [
                'hook' => $hook,
                'callback' => $callback,
                'priority' => $priority,
                'accepted_args' => $accepted_args,
            ];
        });

        $admin = new OIDC_Admin();

        $found = false;
        foreach ($registered_actions as $action) {
            if ('update_option_secure_oidc_login_settings' === $action['hook']
                && is_array($action['callback'])
                && $action['callback'][1] === 'invalidate_settings_cache'
            ) {
                $found = true;
                $this->assertSame(10, $action['priority']);
                $this->assertSame(0, $action['accepted_args']);
                break;
            }
        }

        $this->assertTrue($found, 'update_option_secure_oidc_login_settings hook should be registered');
    }

    /**
     * Test invalidate_settings_cache deletes the alloptions cache key.
     */
    public function testInvalidateSettingsCacheDeletesAlloptionsCache(): void
    {
        $deleted_cache_keys = [];

        Functions\when('wp_cache_delete')->alias(function ($key, $group = '') use (&$deleted_cache_keys) {
            $deleted_cache_keys[] = ['key' => $key, 'group' => $group];
            return true;
        });

        $this->admin->invalidate_settings_cache();

        $this->assertCount(1, $deleted_cache_keys);
        $this->assertSame('alloptions', $deleted_cache_keys[0]['key']);
        $this->assertSame('options', $deleted_cache_keys[0]['group']);
    }

    /**
     * Test handle_credential_deletion clears both option and alloptions cache.
     */
    public function testHandleCredentialDeletionClearsBothCacheGroups(): void
    {
        $deleted_cache_keys = [];

        Functions\when('current_user_can')->justReturn(true);
        Functions\when('wp_verify_nonce')->justReturn(true);
        Functions\when('get_option')->justReturn([
            'client_id' => 'test-id',
            'client_secret' => 'test-secret',
        ]);
        Functions\when('maybe_serialize')->alias(fn($data) => serialize($data));
        Functions\when('set_transient')->justReturn(true);
        Functions\when('wp_safe_redirect')->alias(function () {
            // Throw to prevent the subsequent exit() from terminating PHPUnit
            throw new \RuntimeException('Redirect intercepted');
        });
        Functions\when('admin_url')->justReturn('https://example.com/wp-admin/options-general.php?page=secure-oidc-login');
        Functions\when('wp_cache_delete')->alias(function ($key, $group = '') use (&$deleted_cache_keys) {
            $deleted_cache_keys[] = ['key' => $key, 'group' => $group];
            return true;
        });

        // Mock $wpdb
        $wpdb = \Mockery::mock('wpdb');
        $wpdb->options = 'wp_options';
        $wpdb->shouldReceive('update')->once()->andReturn(1);
        $GLOBALS['wpdb'] = $wpdb;

        $_POST['_wpnonce'] = 'valid-nonce';

        // wp_safe_redirect throws to prevent exit() from killing PHPUnit
        try {
            $this->admin->handle_credential_deletion();
        } catch (\RuntimeException $e) {
            $this->assertSame('Redirect intercepted', $e->getMessage());
        }

        // Verify both cache keys were deleted
        $option_deleted = false;
        $alloptions_deleted = false;

        foreach ($deleted_cache_keys as $entry) {
            if ('secure_oidc_login_settings' === $entry['key'] && 'options' === $entry['group']) {
                $option_deleted = true;
            }
            if ('alloptions' === $entry['key'] && 'options' === $entry['group']) {
                $alloptions_deleted = true;
            }
        }

        $this->assertTrue($option_deleted, 'Individual option cache should be deleted');
        $this->assertTrue($alloptions_deleted, 'alloptions cache should be deleted');

        unset($GLOBALS['wpdb']);
    }

    /**
     * Test the settings-section descriptions render escaped paragraph text.
     *
     * Covers render_provider_section, render_login_section, render_token_section,
     * render_user_section, which output their text via esc_html__().
     */
    public function testRenderSectionDescriptionsOutputEscapedParagraphs(): void
    {
        $sections = [
            'render_provider_section' => 'identity provider',
            'render_login_section'    => 'OIDC login appears',
            'render_token_section'    => 'token refresh',
            'render_user_section'     => 'mapped to WordPress users',
        ];

        foreach ($sections as $method => $needle) {
            ob_start();
            $this->admin->{$method}();
            $output = ob_get_clean();

            $this->assertStringContainsString('<p>', $output, "{$method} should render a paragraph");
            $this->assertStringContainsString($needle, $output, "{$method} should render its description text");
        }
    }

    // =========================================================================
    // RFC 9207 iss Parameter Support Flag Tests
    // =========================================================================

    /**
     * Test sanitize_settings stores the iss-support flag from a fresh discovery.
     */
    public function testSanitizeSettingsSetsIssFlagFromDiscovery(): void
    {
        Functions\when('get_option')->justReturn([
            'issuer' => 'https://old-idp.example.com',
            'authorization_response_iss_parameter_supported' => false,
        ]);
        Functions\when('current_user_can')->justReturn(true);
        Functions\when('wp_verify_nonce')->justReturn(true);

        $_POST['_wpnonce'] = 'valid-nonce';

        // Discovery ran on this submission: issuer and flag submitted together
        $input = [
            'issuer' => 'https://new-idp.example.com',
            'authorization_response_iss_parameter_supported' => '1',
        ];

        $result = $this->admin->sanitize_settings($input);

        $this->assertTrue($result['authorization_response_iss_parameter_supported']);
    }

    /**
     * Test sanitize_settings clears the iss-support flag when the issuer changes
     * without a fresh discovery.
     *
     * The flag was discovered for a specific provider; carrying it over to a new
     * issuer could hard-break login against an IdP that never sends iss.
     */
    public function testSanitizeSettingsClearsIssFlagWhenIssuerChangesWithoutDiscovery(): void
    {
        Functions\when('get_option')->justReturn([
            'issuer' => 'https://old-idp.example.com',
            'authorization_response_iss_parameter_supported' => true,
        ]);
        Functions\when('current_user_can')->justReturn(true);
        Functions\when('wp_verify_nonce')->justReturn(true);

        $_POST['_wpnonce'] = 'valid-nonce';

        // Issuer manually changed; hidden iss field is empty (no discovery run)
        $input = [
            'issuer' => 'https://new-idp.example.com',
            'authorization_response_iss_parameter_supported' => '',
        ];

        $result = $this->admin->sanitize_settings($input);

        $this->assertFalse($result['authorization_response_iss_parameter_supported']);
    }

    /**
     * Test sanitize_settings preserves the iss-support flag when the issuer is unchanged.
     */
    public function testSanitizeSettingsPreservesIssFlagWhenIssuerUnchanged(): void
    {
        Functions\when('get_option')->justReturn([
            'issuer' => 'https://idp.example.com',
            'authorization_response_iss_parameter_supported' => true,
        ]);
        Functions\when('current_user_can')->justReturn(true);
        Functions\when('wp_verify_nonce')->justReturn(true);

        $_POST['_wpnonce'] = 'valid-nonce';

        // Normal settings save: same issuer, hidden iss field empty
        $input = [
            'issuer' => 'https://idp.example.com',
            'authorization_response_iss_parameter_supported' => '',
        ];

        $result = $this->admin->sanitize_settings($input);

        $this->assertTrue($result['authorization_response_iss_parameter_supported']);
    }
}

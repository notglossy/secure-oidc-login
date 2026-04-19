<?php
/**
 * Stub for Secure_OIDC_Login class used in testing.
 *
 * Provides minimal implementation of the main plugin class
 * for unit testing dependent classes.
 *
 * @package SecureOIDCLogin\Tests\Stubs
 */

// Prevent direct file access
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Stub class for Secure_OIDC_Login.
 */
class Secure_OIDC_Login
{
    /**
     * Get a setting value with environment variable support.
     *
     * For testing, this simply returns the database option value
     * without checking environment variables (since getenv is an
     * internal PHP function that cannot be easily stubbed).
     *
     * @param string              $option_key The option key to retrieve.
     * @param array<string,mixed> $options    The options array.
     * @param string              $env_var    Environment variable name (ignored in stub).
     * @return string The setting value.
     */
    public static function get_setting(string $option_key, array $options = [], string $env_var = ''): string
    {
        // For testing purposes, skip environment variable check
        // and just return the database/options value
        return (string) ($options[$option_key] ?? '');
    }

    /**
     * Get the OIDC callback URL for this site.
     *
     * @return string The callback URL to be registered with the IdP.
     */
    public static function get_callback_url(): string
    {
        return add_query_arg('oidc_callback', '1', home_url('/'));
    }
}

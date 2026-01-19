<?php
/**
 * Base test case for OIDC plugin tests.
 *
 * @package SecureOIDCLogin\Tests
 */

declare(strict_types=1);

namespace SecureOIDCLogin\Tests;

use Brain\Monkey;
use Brain\Monkey\Functions;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\TestCase;

/**
 * Base test case with Brain Monkey setup.
 *
 * Provides common setup/teardown for mocking WordPress functions
 * and a set of commonly used WP function stubs.
 */
abstract class OIDCTestCase extends TestCase
{
    use MockeryPHPUnitIntegration;

    /**
     * Set up Brain Monkey before each test.
     */
    protected function setUp(): void
    {
        parent::setUp();
        Monkey\setUp();

        // Stub common WordPress functions
        $this->stubCommonWordPressFunctions();
    }

    /**
     * Tear down Brain Monkey after each test.
     */
    protected function tearDown(): void
    {
        Monkey\tearDown();
        parent::tearDown();
    }

    /**
     * Stub commonly used WordPress functions.
     */
    protected function stubCommonWordPressFunctions(): void
    {
        // Translation functions - return input unchanged
        Functions\stubs([
            '__' => static fn($text, $domain = 'default') => $text,
            '_e' => static fn($text, $domain = 'default') => print($text),
            'esc_html__' => static fn($text, $domain = 'default') => $text,
            'esc_html_e' => static fn($text, $domain = 'default') => print($text),
            'esc_attr__' => static fn($text, $domain = 'default') => $text,
            'esc_attr_e' => static fn($text, $domain = 'default') => print($text),
        ]);

        // Escaping functions
        Functions\stubs([
            'esc_html' => static fn($text) => htmlspecialchars((string)$text, ENT_QUOTES, 'UTF-8'),
            'esc_attr' => static fn($text) => htmlspecialchars((string)$text, ENT_QUOTES, 'UTF-8'),
            'esc_url' => static fn($url) => filter_var($url, FILTER_SANITIZE_URL) ?: '',
            'esc_url_raw' => static fn($url) => filter_var($url, FILTER_SANITIZE_URL) ?: '',
            'esc_js' => static fn($text) => $text,
        ]);

        // Sanitization functions
        Functions\stubs([
            'sanitize_text_field' => static fn($str) => htmlspecialchars(strip_tags((string)$str)),
            'sanitize_user' => static fn($username, $strict = false) => preg_replace('/[^a-zA-Z0-9_.\-@]/', '', $username),
            'wp_unslash' => static fn($value) => is_string($value) ? stripslashes($value) : $value,
        ]);

        // Validation functions
        Functions\stubs([
            'is_email' => static fn($email) => filter_var($email, FILTER_VALIDATE_EMAIL) !== false,
        ]);
    }

    /**
     * Get a sample OIDC discovery document configuration.
     *
     * @return array<string, mixed>
     */
    protected function getSampleOIDCConfig(): array
    {
        return [
            'issuer' => 'https://idp.example.com',
            'authorization_endpoint' => 'https://idp.example.com/authorize',
            'token_endpoint' => 'https://idp.example.com/token',
            'userinfo_endpoint' => 'https://idp.example.com/userinfo',
            'jwks_uri' => 'https://idp.example.com/.well-known/jwks.json',
            'end_session_endpoint' => 'https://idp.example.com/logout',
            'scopes_supported' => ['openid', 'email', 'profile'],
            'response_types_supported' => ['code', 'token', 'id_token'],
            'grant_types_supported' => ['authorization_code', 'refresh_token'],
            'subject_types_supported' => ['public'],
            'id_token_signing_alg_values_supported' => ['RS256', 'ES256'],
            'claims_supported' => ['sub', 'iss', 'aud', 'exp', 'iat', 'email', 'name'],
            'code_challenge_methods_supported' => ['S256'],
        ];
    }

    /**
     * Get a sample token response.
     *
     * @return array<string, mixed>
     */
    protected function getSampleTokenResponse(): array
    {
        return [
            'access_token' => 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.access_token_payload.signature',
            'id_token' => 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.id_token_payload.signature',
            'token_type' => 'Bearer',
            'expires_in' => 3600,
            'refresh_token' => 'refresh_token_value',
            'scope' => 'openid email profile',
        ];
    }

    /**
     * Get sample ID token claims.
     *
     * @return array<string, mixed>
     */
    protected function getSampleClaims(): array
    {
        return [
            'sub' => 'user-123-abc',
            'iss' => 'https://idp.example.com',
            'aud' => 'client-id-123',
            'exp' => time() + 3600,
            'iat' => time(),
            'nonce' => 'random-nonce-value',
            'email' => 'user@example.com',
            'email_verified' => true,
            'name' => 'John Doe',
            'given_name' => 'John',
            'family_name' => 'Doe',
            'preferred_username' => 'johndoe',
        ];
    }

    /**
     * Get sample userinfo response.
     *
     * @return array<string, mixed>
     */
    protected function getSampleUserInfo(): array
    {
        return [
            'sub' => 'user-123-abc',
            'name' => 'John Doe',
            'given_name' => 'John',
            'family_name' => 'Doe',
            'middle_name' => 'William',
            'nickname' => 'Johnny',
            'preferred_username' => 'johndoe',
            'profile' => 'https://example.com/johndoe',
            'picture' => 'https://example.com/johndoe/photo.jpg',
            'website' => 'https://johndoe.com',
            'email' => 'john@example.com',
            'email_verified' => true,
            'gender' => 'male',
            'birthdate' => '1990-01-15',
            'zoneinfo' => 'America/Los_Angeles',
            'locale' => 'en-US',
            'phone_number' => '+1-555-555-5555',
            'phone_number_verified' => true,
            'updated_at' => 1609459200,
        ];
    }
}

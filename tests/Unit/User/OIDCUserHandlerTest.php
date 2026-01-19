<?php
/**
 * Tests for OIDC_User_Handler class.
 *
 * @package SecureOIDCLogin\Tests\Unit\User
 */

declare(strict_types=1);

namespace SecureOIDCLogin\Tests\Unit\User;

use Brain\Monkey\Functions;
use OIDC_User_Handler;
use SecureOIDCLogin\Tests\OIDCTestCase;
use WP_Error;

/**
 * Tests for the OIDC_User_Handler class.
 *
 * @covers OIDC_User_Handler
 */
class OIDCUserHandlerTest extends OIDCTestCase
{
    private OIDC_User_Handler $handler;

    /**
     * Set up test environment.
     */
    protected function setUp(): void
    {
        parent::setUp();

        // Stub WordPress functions used by OIDC_User_Handler
        Functions\stubs([
            'get_option' => static fn($option, $default = []) => [
                'create_users' => true,
                'require_verified_email' => true,
                'default_role' => 'subscriber',
                'username_claim' => 'preferred_username',
                'email_claim' => 'email',
                'first_name_claim' => 'given_name',
                'last_name_claim' => 'family_name',
                'allowed_email_domains' => '',
            ],
            'get_users' => static fn($args) => [],
            'get_user_by' => static fn($field, $value) => false,
            'update_user_meta' => static fn($user_id, $key, $value) => true,
            'wp_insert_user' => static fn($userdata) => 1,
            'wp_update_user' => static fn($userdata) => $userdata['ID'],
            'wp_generate_password' => static fn($length, $special, $extra_special) => 'random-password-123',
            'get_role' => static fn($role) => $role === 'subscriber' ? new \stdClass() : null,
            'do_action' => null,
            'apply_filters' => static fn($tag, $value) => $value,
            'username_exists' => static fn($username) => false,
        ]);

        $this->handler = new OIDC_User_Handler();
    }

    /**
     * Test get_or_create_user returns error when sub claim is missing.
     */
    public function testGetOrCreateUserReturnsErrorWhenSubMissing(): void
    {
        $claims = $this->getSampleClaims();
        unset($claims['sub']);

        $result = $this->handler->get_or_create_user($claims);

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertStringContainsString('subject', $result->get_error_message());
    }

    /**
     * Test get_or_create_user returns error when email not verified and required.
     */
    public function testGetOrCreateUserReturnsErrorWhenEmailNotVerified(): void
    {
        $claims = $this->getSampleClaims();
        $claims['email_verified'] = false;

        // Make sure no existing user is found by subject
        Functions\when('get_users')->justReturn([]);
        Functions\when('get_user_by')->justReturn(false);

        $result = $this->handler->get_or_create_user($claims);

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertStringContainsString('email address not verified', $result->get_error_message());
    }

    /**
     * Test get_or_create_user returns error when email domain not allowed.
     */
    public function testGetOrCreateUserReturnsErrorWhenEmailDomainNotAllowed(): void
    {
        Functions\when('get_option')->justReturn([
            'create_users' => true,
            'require_verified_email' => true,
            'allowed_email_domains' => 'allowed.com,other.com',
        ]);

        $claims = $this->getSampleClaims();
        $claims['email'] = 'user@notallowed.com';
        $claims['email_verified'] = true;

        Functions\when('get_users')->justReturn([]);
        Functions\when('get_user_by')->justReturn(false);

        $handler = new OIDC_User_Handler();
        $result = $handler->get_or_create_user($claims);

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertStringContainsString('not authorized', $result->get_error_message());
    }

    /**
     * Test get_or_create_user returns error when user creation disabled and user not found.
     */
    public function testGetOrCreateUserReturnsErrorWhenCreationDisabled(): void
    {
        Functions\when('get_option')->justReturn([
            'create_users' => false,
            'require_verified_email' => true,
            'allowed_email_domains' => '',
        ]);

        $claims = $this->getSampleClaims();
        $claims['email_verified'] = true;

        Functions\when('get_users')->justReturn([]);
        Functions\when('get_user_by')->justReturn(false);

        $handler = new OIDC_User_Handler();
        $result = $handler->get_or_create_user($claims);

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertStringContainsString('user creation is disabled', $result->get_error_message());
    }

    /**
     * Test is_email_domain_allowed returns true when no domains configured.
     */
    public function testIsEmailDomainAllowedReturnsTrueWhenNoDomains(): void
    {
        Functions\when('get_option')->justReturn([
            'allowed_email_domains' => '',
        ]);

        $handler = new OIDC_User_Handler();

        $reflection = new \ReflectionMethod(OIDC_User_Handler::class, 'is_email_domain_allowed');
        $reflection->setAccessible(true);

        $this->assertTrue($reflection->invoke($handler, 'user@anydomain.com'));
    }

    /**
     * Test is_email_domain_allowed returns true for exact domain match.
     */
    public function testIsEmailDomainAllowedReturnsTrueForExactMatch(): void
    {
        Functions\when('get_option')->justReturn([
            'allowed_email_domains' => 'example.com,test.org',
        ]);

        $handler = new OIDC_User_Handler();

        $reflection = new \ReflectionMethod(OIDC_User_Handler::class, 'is_email_domain_allowed');
        $reflection->setAccessible(true);

        $this->assertTrue($reflection->invoke($handler, 'user@example.com'));
        $this->assertTrue($reflection->invoke($handler, 'user@test.org'));
    }

    /**
     * Test is_email_domain_allowed returns false for non-matching domain.
     */
    public function testIsEmailDomainAllowedReturnsFalseForNonMatch(): void
    {
        Functions\when('get_option')->justReturn([
            'allowed_email_domains' => 'example.com,test.org',
        ]);

        $handler = new OIDC_User_Handler();

        $reflection = new \ReflectionMethod(OIDC_User_Handler::class, 'is_email_domain_allowed');
        $reflection->setAccessible(true);

        $this->assertFalse($reflection->invoke($handler, 'user@notallowed.com'));
    }

    /**
     * Test is_email_domain_allowed supports wildcard subdomains.
     */
    public function testIsEmailDomainAllowedSupportsWildcardSubdomains(): void
    {
        Functions\when('get_option')->justReturn([
            'allowed_email_domains' => '*.example.com',
        ]);

        $handler = new OIDC_User_Handler();

        $reflection = new \ReflectionMethod(OIDC_User_Handler::class, 'is_email_domain_allowed');
        $reflection->setAccessible(true);

        // Base domain should match
        $this->assertTrue($reflection->invoke($handler, 'user@example.com'));
        // Subdomain should match
        $this->assertTrue($reflection->invoke($handler, 'user@sub.example.com'));
        // Deep subdomain should match
        $this->assertTrue($reflection->invoke($handler, 'user@deep.sub.example.com'));
        // Different domain should not match
        $this->assertFalse($reflection->invoke($handler, 'user@other.com'));
    }

    /**
     * Test is_email_domain_allowed is case insensitive.
     */
    public function testIsEmailDomainAllowedIsCaseInsensitive(): void
    {
        Functions\when('get_option')->justReturn([
            'allowed_email_domains' => 'EXAMPLE.COM',
        ]);

        $handler = new OIDC_User_Handler();

        $reflection = new \ReflectionMethod(OIDC_User_Handler::class, 'is_email_domain_allowed');
        $reflection->setAccessible(true);

        $this->assertTrue($reflection->invoke($handler, 'user@example.com'));
        $this->assertTrue($reflection->invoke($handler, 'user@EXAMPLE.COM'));
        $this->assertTrue($reflection->invoke($handler, 'user@Example.Com'));
    }

    /**
     * Test is_email_domain_allowed returns false for invalid email.
     */
    public function testIsEmailDomainAllowedReturnsFalseForInvalidEmail(): void
    {
        Functions\when('get_option')->justReturn([
            'allowed_email_domains' => 'example.com',
        ]);

        $handler = new OIDC_User_Handler();

        $reflection = new \ReflectionMethod(OIDC_User_Handler::class, 'is_email_domain_allowed');
        $reflection->setAccessible(true);

        $this->assertFalse($reflection->invoke($handler, 'invalid-email'));
        $this->assertFalse($reflection->invoke($handler, ''));
    }

    /**
     * Test is_email_verified returns true for boolean true.
     */
    public function testIsEmailVerifiedReturnsTrueForBooleanTrue(): void
    {
        $reflection = new \ReflectionMethod(OIDC_User_Handler::class, 'is_email_verified');
        $reflection->setAccessible(true);

        $this->assertTrue($reflection->invoke($this->handler, ['email_verified' => true]));
    }

    /**
     * Test is_email_verified returns false for boolean false.
     */
    public function testIsEmailVerifiedReturnsFalseForBooleanFalse(): void
    {
        $reflection = new \ReflectionMethod(OIDC_User_Handler::class, 'is_email_verified');
        $reflection->setAccessible(true);

        $this->assertFalse($reflection->invoke($this->handler, ['email_verified' => false]));
    }

    /**
     * Test is_email_verified returns true for string "true".
     */
    public function testIsEmailVerifiedReturnsTrueForStringTrue(): void
    {
        $reflection = new \ReflectionMethod(OIDC_User_Handler::class, 'is_email_verified');
        $reflection->setAccessible(true);

        $this->assertTrue($reflection->invoke($this->handler, ['email_verified' => 'true']));
        $this->assertTrue($reflection->invoke($this->handler, ['email_verified' => 'TRUE']));
        $this->assertTrue($reflection->invoke($this->handler, ['email_verified' => '1']));
    }

    /**
     * Test is_email_verified returns false for string "false".
     */
    public function testIsEmailVerifiedReturnsFalseForStringFalse(): void
    {
        $reflection = new \ReflectionMethod(OIDC_User_Handler::class, 'is_email_verified');
        $reflection->setAccessible(true);

        $this->assertFalse($reflection->invoke($this->handler, ['email_verified' => 'false']));
        $this->assertFalse($reflection->invoke($this->handler, ['email_verified' => '0']));
    }

    /**
     * Test is_email_verified returns true for integer 1.
     */
    public function testIsEmailVerifiedReturnsTrueForIntegerOne(): void
    {
        $reflection = new \ReflectionMethod(OIDC_User_Handler::class, 'is_email_verified');
        $reflection->setAccessible(true);

        $this->assertTrue($reflection->invoke($this->handler, ['email_verified' => 1]));
    }

    /**
     * Test is_email_verified returns false for integer 0.
     */
    public function testIsEmailVerifiedReturnsFalseForIntegerZero(): void
    {
        $reflection = new \ReflectionMethod(OIDC_User_Handler::class, 'is_email_verified');
        $reflection->setAccessible(true);

        $this->assertFalse($reflection->invoke($this->handler, ['email_verified' => 0]));
    }

    /**
     * Test is_email_verified returns false when claim missing.
     */
    public function testIsEmailVerifiedReturnsFalseWhenMissing(): void
    {
        $reflection = new \ReflectionMethod(OIDC_User_Handler::class, 'is_email_verified');
        $reflection->setAccessible(true);

        $this->assertFalse($reflection->invoke($this->handler, []));
    }

    /**
     * Test generate_username uses preferred_username claim.
     */
    public function testGenerateUsernameUsesPreferredUsername(): void
    {
        $reflection = new \ReflectionMethod(OIDC_User_Handler::class, 'generate_username');
        $reflection->setAccessible(true);

        $claims = ['preferred_username' => 'johndoe'];

        $result = $reflection->invoke($this->handler, $claims);

        $this->assertSame('johndoe', $result);
    }

    /**
     * Test generate_username falls back to email prefix.
     */
    public function testGenerateUsernameFallsBackToEmailPrefix(): void
    {
        $reflection = new \ReflectionMethod(OIDC_User_Handler::class, 'generate_username');
        $reflection->setAccessible(true);

        $claims = ['email' => 'john.doe@example.com'];

        $result = $reflection->invoke($this->handler, $claims);

        $this->assertSame('john.doe', $result);
    }

    /**
     * Test generate_username falls back to sub when no email.
     */
    public function testGenerateUsernameFallsBackToSub(): void
    {
        $reflection = new \ReflectionMethod(OIDC_User_Handler::class, 'generate_username');
        $reflection->setAccessible(true);

        $claims = ['sub' => 'user123abc'];

        $result = $reflection->invoke($this->handler, $claims);

        $this->assertSame('user_user123a', $result);
    }

    /**
     * Test generate_display_name uses first and last name.
     */
    public function testGenerateDisplayNameUsesFirstAndLastName(): void
    {
        $reflection = new \ReflectionMethod(OIDC_User_Handler::class, 'generate_display_name');
        $reflection->setAccessible(true);

        $claims = [
            'given_name' => 'John',
            'family_name' => 'Doe',
        ];

        $result = $reflection->invoke($this->handler, $claims);

        $this->assertSame('John Doe', $result);
    }

    /**
     * Test generate_display_name uses name claim when first/last not available.
     */
    public function testGenerateDisplayNameUsesNameClaim(): void
    {
        $reflection = new \ReflectionMethod(OIDC_User_Handler::class, 'generate_display_name');
        $reflection->setAccessible(true);

        $claims = ['name' => 'John William Doe'];

        $result = $reflection->invoke($this->handler, $claims);

        $this->assertSame('John William Doe', $result);
    }

    /**
     * Test ensure_unique_username adds suffix when username exists.
     */
    public function testEnsureUniqueUsernameAddsSuffix(): void
    {
        $callCount = 0;
        Functions\when('username_exists')->alias(function ($username) use (&$callCount) {
            $callCount++;
            // First check returns true (username exists), second returns false
            return $callCount === 1;
        });

        $reflection = new \ReflectionMethod(OIDC_User_Handler::class, 'ensure_unique_username');
        $reflection->setAccessible(true);

        $result = $reflection->invoke($this->handler, 'johndoe');

        $this->assertSame('johndoe_1', $result);
    }
}

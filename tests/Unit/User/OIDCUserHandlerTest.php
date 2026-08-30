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
use WP_User;

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
            'get_user_meta' => static fn($user_id, $key, $single = false) => $single ? '' : [],
            'update_user_meta' => static fn($user_id, $key, $value) => true,
            'delete_user_meta' => static fn($user_id, $key) => true,
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

    /**
     * Test get_or_create_user finds existing user by OIDC subject.
     */
    public function testGetOrCreateUserFindsExistingUserBySubject(): void
    {
        $claims = $this->getSampleClaims();

        // Mock existing user, found via the indexed subject lookup and
        // confirmed by the authoritative oidc_subject row.
        $existingUser = new WP_User(42, 'existinguser', 'existing@example.com');

        Functions\when('get_users')->justReturn([$existingUser]);
        Functions\when('get_user_meta')->alias(function($user_id, $key, $single = false) use ($claims) {
            return $key === 'oidc_subject' ? $claims['sub'] : [];
        });
        Functions\when('get_user_by')->alias(function($field, $value) use ($existingUser) {
            return $field === 'ID' && $value === 42 ? $existingUser : false;
        });

        $result = $this->handler->get_or_create_user($claims);

        $this->assertSame($existingUser, $result);
    }

    /**
     * Test get_or_create_user links existing WordPress user by email.
     */
    public function testGetOrCreateUserLinksExistingUserByEmail(): void
    {
        $claims = $this->getSampleClaims();
        $claims['email_verified'] = true;

        // Mock: no user found by subject
        Functions\when('get_users')->justReturn([]);

        // Mock: existing user found by email
        $existingUser = new WP_User(99, 'testuser', $claims['email']);

        Functions\when('get_user_by')->alias(function($field, $value) use ($existingUser, $claims) {
            if ($field === 'email' && $value === $claims['email']) {
                return $existingUser;
            }
            if ($field === 'ID' && $value === 99) {
                return $existingUser;
            }
            return false;
        });

        $result = $this->handler->get_or_create_user($claims);

        $this->assertSame($existingUser, $result);
    }

    /**
     * Test get_or_create_user creates new user successfully.
     */
    public function testGetOrCreateUserCreatesNewUserSuccessfully(): void
    {
        $claims = $this->getSampleClaims();
        $claims['email_verified'] = true;

        Functions\when('get_users')->justReturn([]);
        Functions\when('get_user_by')->alias(function($field, $value) {
            if ($field === 'ID' && $value === 1) {
                return new WP_User(1, 'newuser', 'test@example.com');
            }
            return false;
        });
        Functions\when('is_email')->justReturn(true);
        Functions\when('sanitize_user')->alias(fn($username) => $username);

        $result = $this->handler->get_or_create_user($claims);

        $this->assertIsObject($result);
        $this->assertSame(1, $result->ID);
    }

    /**
     * Test get_or_create_user merges userinfo with id_token_claims.
     */
    public function testGetOrCreateUserMergesUserinfoWithIdTokenClaims(): void
    {
        $idTokenClaims = [
            'sub' => 'user123',
            'email' => 'old@example.com',
            'email_verified' => true,
        ];

        $userinfo = [
            'email' => 'new@example.com',
            'name' => 'Updated Name',
        ];

        Functions\when('get_users')->justReturn([]);
        Functions\when('get_user_by')->alias(function($field, $value) {
            if ($field === 'ID' && $value === 1) {
                return new WP_User(1, 'mergeduser', 'new@example.com');
            }
            return false;
        });
        Functions\when('is_email')->justReturn(true);
        Functions\when('sanitize_user')->alias(fn($username) => $username);

        // Userinfo email should take precedence
        $result = $this->handler->get_or_create_user($idTokenClaims, $userinfo);

        $this->assertIsObject($result);
    }

    /**
     * Test get_or_create_user rejects authentication when sub claim differs between ID token and UserInfo.
     *
     * Per OIDC Core spec §5.3.4, the sub in UserInfo MUST match the sub in the ID token.
     */
    public function testGetOrCreateUserRejectsSubClaimMismatch(): void
    {
        $idTokenClaims = [
            'sub' => 'legitimate-user-123',
            'email' => 'user@example.com',
            'email_verified' => true,
        ];

        $userinfo = [
            'sub' => 'attacker-user-456',
            'email' => 'user@example.com',
        ];

        $result = $this->handler->get_or_create_user($idTokenClaims, $userinfo);

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertSame('oidc_sub_mismatch', $result->get_error_code());
        $this->assertStringContainsString('mismatch', $result->get_error_message());
    }

    /**
     * Test get_or_create_user succeeds when sub claim matches between ID token and UserInfo.
     */
    public function testGetOrCreateUserAllowsMatchingSubInUserinfo(): void
    {
        $idTokenClaims = [
            'sub' => 'user-123-abc',
            'email' => 'old@example.com',
            'email_verified' => true,
        ];

        $userinfo = [
            'sub' => 'user-123-abc',
            'email' => 'new@example.com',
            'name' => 'Updated Name',
        ];

        Functions\when('get_users')->justReturn([]);
        Functions\when('get_user_by')->alias(function($field, $value) {
            if ($field === 'ID' && $value === 1) {
                return new WP_User(1, 'matchingsubuser', 'new@example.com');
            }
            return false;
        });
        Functions\when('is_email')->justReturn(true);
        Functions\when('sanitize_user')->alias(fn($username) => $username);

        $result = $this->handler->get_or_create_user($idTokenClaims, $userinfo);

        $this->assertIsObject($result);
        $this->assertNotInstanceOf(WP_Error::class, $result);
    }

    /**
     * Test get_or_create_user succeeds when UserInfo does not contain a sub claim.
     */
    public function testGetOrCreateUserAllowsUserinfoWithoutSub(): void
    {
        $idTokenClaims = [
            'sub' => 'user-123-abc',
            'email' => 'user@example.com',
            'email_verified' => true,
        ];

        $userinfo = [
            'email' => 'updated@example.com',
            'name' => 'John Doe',
        ];

        Functions\when('get_users')->justReturn([]);
        Functions\when('get_user_by')->alias(function($field, $value) {
            if ($field === 'ID' && $value === 1) {
                return new WP_User(1, 'nosubuser', 'updated@example.com');
            }
            return false;
        });
        Functions\when('is_email')->justReturn(true);
        Functions\when('sanitize_user')->alias(fn($username) => $username);

        $result = $this->handler->get_or_create_user($idTokenClaims, $userinfo);

        $this->assertIsObject($result);
        $this->assertNotInstanceOf(WP_Error::class, $result);
    }

    /**
     * Test create_user returns error when email is missing.
     */
    public function testCreateUserReturnsErrorWhenEmailMissing(): void
    {
        Functions\when('get_option')->justReturn([
            'create_users' => true,
            'require_verified_email' => true,
            'email_claim' => 'email',
        ]);
        Functions\when('get_users')->justReturn([]);
        Functions\when('get_user_by')->justReturn(false);

        $claims = ['sub' => 'user123']; // No email

        $handler = new OIDC_User_Handler();
        $result = $handler->get_or_create_user($claims);

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertStringContainsString('Email is required', $result->get_error_message());
    }

    /**
     * Test create_user returns error when email is invalid.
     */
    public function testCreateUserReturnsErrorWhenEmailInvalid(): void
    {
        Functions\when('get_option')->justReturn([
            'create_users' => true,
            'require_verified_email' => false,
            'email_claim' => 'email',
        ]);
        Functions\when('get_users')->justReturn([]);
        Functions\when('get_user_by')->justReturn(false);
        Functions\when('is_email')->justReturn(false);

        $claims = [
            'sub' => 'user123',
            'email' => 'not-an-email',
        ];

        $handler = new OIDC_User_Handler();
        $result = $handler->get_or_create_user($claims);

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertStringContainsString('Invalid email', $result->get_error_message());
    }

    /**
     * Test create_user returns error when wp_insert_user fails.
     */
    public function testCreateUserReturnsErrorWhenInsertFails(): void
    {
        Functions\when('get_users')->justReturn([]);
        Functions\when('get_user_by')->justReturn(false);
        Functions\when('is_email')->justReturn(true);
        Functions\when('sanitize_user')->alias(fn($username) => $username);
        Functions\when('wp_insert_user')->justReturn(
            new WP_Error('insert_failed', 'Database error')
        );

        $claims = $this->getSampleClaims();
        $claims['email_verified'] = true;

        $result = $this->handler->get_or_create_user($claims);

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertSame('insert_failed', $result->get_error_code());
    }

    /**
     * Test generate_display_name with only first name.
     */
    public function testGenerateDisplayNameWithOnlyFirstName(): void
    {
        $reflection = new \ReflectionMethod(OIDC_User_Handler::class, 'generate_display_name');
        $reflection->setAccessible(true);

        $claims = ['given_name' => 'John'];

        $result = $reflection->invoke($this->handler, $claims);

        $this->assertSame('John', $result);
    }

    /**
     * Test generate_display_name with only last name.
     */
    public function testGenerateDisplayNameWithOnlyLastName(): void
    {
        $reflection = new \ReflectionMethod(OIDC_User_Handler::class, 'generate_display_name');
        $reflection->setAccessible(true);

        $claims = ['family_name' => 'Doe'];

        $result = $reflection->invoke($this->handler, $claims);

        $this->assertSame('Doe', $result);
    }

    /**
     * Test generate_display_name falls back to username when no names.
     */
    public function testGenerateDisplayNameFallsBackToUsername(): void
    {
        $reflection = new \ReflectionMethod(OIDC_User_Handler::class, 'generate_display_name');
        $reflection->setAccessible(true);

        $claims = ['preferred_username' => 'johndoe'];

        $result = $reflection->invoke($this->handler, $claims);

        $this->assertSame('johndoe', $result);
    }

    /**
     * Test get_default_role returns subscriber for invalid role.
     */
    public function testGetDefaultRoleReturnsSubscriberForInvalidRole(): void
    {
        Functions\when('get_option')->justReturn([
            'default_role' => 'invalid_role',
        ]);
        Functions\when('get_role')->alias(function($role) {
            return $role === 'subscriber' ? new \stdClass() : null;
        });

        $handler = new OIDC_User_Handler();
        $reflection = new \ReflectionMethod(OIDC_User_Handler::class, 'get_default_role');
        $reflection->setAccessible(true);

        $result = $reflection->invoke($handler);

        $this->assertSame('subscriber', $result);
    }

    /**
     * Test get_default_role returns valid custom role.
     */
    public function testGetDefaultRoleReturnsValidCustomRole(): void
    {
        Functions\when('get_option')->justReturn([
            'default_role' => 'editor',
        ]);
        Functions\when('get_role')->alias(function($role) {
            return $role === 'editor' ? new \stdClass() : null;
        });

        $handler = new OIDC_User_Handler();
        $reflection = new \ReflectionMethod(OIDC_User_Handler::class, 'get_default_role');
        $reflection->setAccessible(true);

        $result = $reflection->invoke($handler);

        $this->assertSame('editor', $result);
    }

    /**
     * Test is_email_verified returns false for unknown type.
     */
    public function testIsEmailVerifiedReturnsFalseForUnknownType(): void
    {
        $reflection = new \ReflectionMethod(OIDC_User_Handler::class, 'is_email_verified');
        $reflection->setAccessible(true);

        $this->assertFalse($reflection->invoke($this->handler, ['email_verified' => []]));
        $this->assertFalse($reflection->invoke($this->handler, ['email_verified' => new \stdClass()]));
    }

    /**
     * Test email verification defaults to required when not set.
     */
    public function testEmailVerificationDefaultsToRequiredWhenNotSet(): void
    {
        Functions\when('get_option')->justReturn([
            'create_users' => true,
            // require_verified_email not set - should default to true
        ]);
        Functions\when('get_users')->justReturn([]);
        Functions\when('get_user_by')->justReturn(false);

        $claims = $this->getSampleClaims();
        $claims['email_verified'] = false; // Not verified

        $handler = new OIDC_User_Handler();
        $result = $handler->get_or_create_user($claims);

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertStringContainsString('email address not verified', $result->get_error_message());
    }

    /**
     * Test generate_username sanitizes special characters.
     */
    public function testGenerateUsernameSanitizesSpecialCharacters(): void
    {
        Functions\when('sanitize_user')->alias(function($username) {
            // Simulate WordPress sanitization removing special chars
            return preg_replace('/[^a-zA-Z0-9._@-]/', '', $username);
        });

        $reflection = new \ReflectionMethod(OIDC_User_Handler::class, 'generate_username');
        $reflection->setAccessible(true);

        $claims = ['preferred_username' => 'john#doe!'];

        $result = $reflection->invoke($this->handler, $claims);

        $this->assertSame('johndoe', $result);
    }

    /**
     * Test generate_username uses random password when sanitization results in empty string.
     */
    public function testGenerateUsernameUsesRandomWhenSanitizationEmpty(): void
    {
        Functions\when('sanitize_user')->justReturn('');
        Functions\when('wp_generate_password')->justReturn('abc123');

        $reflection = new \ReflectionMethod(OIDC_User_Handler::class, 'generate_username');
        $reflection->setAccessible(true);

        $claims = ['preferred_username' => '###'];

        $result = $reflection->invoke($this->handler, $claims);

        $this->assertSame('oidc_user_abc123', $result);
    }

    /**
     * Test get_claim_value with custom claim mapping.
     */
    public function testGetClaimValueWithCustomMapping(): void
    {
        Functions\when('get_option')->justReturn([
            'email_claim' => 'custom_email_field',
        ]);

        $handler = new OIDC_User_Handler();
        $reflection = new \ReflectionMethod(OIDC_User_Handler::class, 'get_claim_value');
        $reflection->setAccessible(true);

        $claims = [
            'email' => 'standard@example.com',
            'custom_email_field' => 'custom@example.com',
        ];

        $result = $reflection->invoke($handler, $claims, 'email_claim', 'email');

        $this->assertSame('custom@example.com', $result);
    }

    /**
     * Test ensure_unique_username with multiple collisions.
     */
    public function testEnsureUniqueUsernameWithMultipleCollisions(): void
    {
        $callCount = 0;
        Functions\when('username_exists')->alias(function ($username) use (&$callCount) {
            $callCount++;
            // First 3 checks return true (username exists), fourth returns false
            return $callCount <= 3;
        });

        $reflection = new \ReflectionMethod(OIDC_User_Handler::class, 'ensure_unique_username');
        $reflection->setAccessible(true);

        $result = $reflection->invoke($this->handler, 'johndoe');

        $this->assertSame('johndoe_3', $result);
    }

    /**
     * Test is_email_domain_allowed handles whitespace around domains.
     */
    public function testIsEmailDomainAllowedHandlesWhitespace(): void
    {
        Functions\when('get_option')->justReturn([
            'allowed_email_domains' => '  example.com  ,  test.org  ',
        ]);

        $handler = new OIDC_User_Handler();

        $reflection = new \ReflectionMethod(OIDC_User_Handler::class, 'is_email_domain_allowed');
        $reflection->setAccessible(true);

        $this->assertTrue($reflection->invoke($handler, 'user@example.com'));
        $this->assertTrue($reflection->invoke($handler, 'user@test.org'));
    }

    /**
     * Test is_email_domain_allowed handles empty entries in domain list.
     */
    public function testIsEmailDomainAllowedIgnoresEmptyEntries(): void
    {
        Functions\when('get_option')->justReturn([
            'allowed_email_domains' => 'example.com,,,,test.org,',
        ]);

        $handler = new OIDC_User_Handler();

        $reflection = new \ReflectionMethod(OIDC_User_Handler::class, 'is_email_domain_allowed');
        $reflection->setAccessible(true);

        $this->assertTrue($reflection->invoke($handler, 'user@example.com'));
        $this->assertTrue($reflection->invoke($handler, 'user@test.org'));
        $this->assertFalse($reflection->invoke($handler, 'user@other.com'));
    }

    /**
     * Test is_email_domain_allowed prevents partial domain matching.
     */
    public function testIsEmailDomainAllowedPreventsPartialMatch(): void
    {
        Functions\when('get_option')->justReturn([
            'allowed_email_domains' => 'example.com',
        ]);

        $handler = new OIDC_User_Handler();

        $reflection = new \ReflectionMethod(OIDC_User_Handler::class, 'is_email_domain_allowed');
        $reflection->setAccessible(true);

        // Should NOT match: "badexample.com" is not "example.com"
        $this->assertFalse($reflection->invoke($handler, 'user@badexample.com'));
        $this->assertFalse($reflection->invoke($handler, 'user@example.com.evil.com'));
        // Should match
        $this->assertTrue($reflection->invoke($handler, 'user@example.com'));
    }

    /**
     * Test is_email_domain_allowed with wildcard doesn't match unrelated domains.
     */
    public function testIsEmailDomainAllowedWildcardDoesNotMatchUnrelated(): void
    {
        Functions\when('get_option')->justReturn([
            'allowed_email_domains' => '*.example.com',
        ]);

        $handler = new OIDC_User_Handler();

        $reflection = new \ReflectionMethod(OIDC_User_Handler::class, 'is_email_domain_allowed');
        $reflection->setAccessible(true);

        // Wildcard *.example.com should NOT match:
        $this->assertFalse($reflection->invoke($handler, 'user@notexample.com'));
        $this->assertFalse($reflection->invoke($handler, 'user@example.com.evil.com'));
        // Should match:
        $this->assertTrue($reflection->invoke($handler, 'user@example.com'));
        $this->assertTrue($reflection->invoke($handler, 'user@sub.example.com'));
    }

    /**
     * Test is_email_domain_allowed with multiple domains including wildcards.
     */
    public function testIsEmailDomainAllowedMixedDomainsAndWildcards(): void
    {
        Functions\when('get_option')->justReturn([
            'allowed_email_domains' => 'exact.com, *.wildcard.org',
        ]);

        $handler = new OIDC_User_Handler();

        $reflection = new \ReflectionMethod(OIDC_User_Handler::class, 'is_email_domain_allowed');
        $reflection->setAccessible(true);

        $this->assertTrue($reflection->invoke($handler, 'user@exact.com'));
        $this->assertTrue($reflection->invoke($handler, 'user@wildcard.org'));
        $this->assertTrue($reflection->invoke($handler, 'user@sub.wildcard.org'));
        $this->assertFalse($reflection->invoke($handler, 'user@sub.exact.com'));
        $this->assertFalse($reflection->invoke($handler, 'user@other.com'));
    }

    /**
     * Test is_email_domain_allowed with only whitespace returns true (no restrictions).
     */
    public function testIsEmailDomainAllowedWithOnlyWhitespaceAllowsAll(): void
    {
        Functions\when('get_option')->justReturn([
            'allowed_email_domains' => '   ',
        ]);

        $handler = new OIDC_User_Handler();

        $reflection = new \ReflectionMethod(OIDC_User_Handler::class, 'is_email_domain_allowed');
        $reflection->setAccessible(true);

        $this->assertTrue($reflection->invoke($handler, 'user@anydomain.com'));
    }

    /**
     * Test is_email_domain_allowed handles email with multiple @ signs.
     */
    public function testIsEmailDomainAllowedRejectsMultipleAtSigns(): void
    {
        Functions\when('get_option')->justReturn([
            'allowed_email_domains' => 'example.com',
        ]);

        $handler = new OIDC_User_Handler();

        $reflection = new \ReflectionMethod(OIDC_User_Handler::class, 'is_email_domain_allowed');
        $reflection->setAccessible(true);

        // Multiple @ signs should result in invalid parsing
        $this->assertFalse($reflection->invoke($handler, 'user@domain@example.com'));
    }

    /**
     * Test is_email_verified handles string with whitespace.
     */
    public function testIsEmailVerifiedHandlesWhitespaceInString(): void
    {
        $reflection = new \ReflectionMethod(OIDC_User_Handler::class, 'is_email_verified');
        $reflection->setAccessible(true);

        $this->assertTrue($reflection->invoke($this->handler, ['email_verified' => ' true ']));
        $this->assertTrue($reflection->invoke($this->handler, ['email_verified' => ' 1 ']));
        $this->assertFalse($reflection->invoke($this->handler, ['email_verified' => ' false ']));
    }

    /**
     * Test is_email_verified returns false for null value.
     */
    public function testIsEmailVerifiedReturnsFalseForNull(): void
    {
        $reflection = new \ReflectionMethod(OIDC_User_Handler::class, 'is_email_verified');
        $reflection->setAccessible(true);

        $this->assertFalse($reflection->invoke($this->handler, ['email_verified' => null]));
    }

    /**
     * Test is_email_verified returns false for float values.
     */
    public function testIsEmailVerifiedReturnsFalseForFloat(): void
    {
        $reflection = new \ReflectionMethod(OIDC_User_Handler::class, 'is_email_verified');
        $reflection->setAccessible(true);

        $this->assertFalse($reflection->invoke($this->handler, ['email_verified' => 1.0]));
        $this->assertFalse($reflection->invoke($this->handler, ['email_verified' => 0.0]));
    }

    /**
     * Test metadata storage failure when linking existing user.
     */
    public function testMetadataStorageFailureWhenLinkingExistingUser(): void
    {
        $claims = $this->getSampleClaims();
        $claims['email_verified'] = true;

        // Mock: no user found by subject
        Functions\when('get_users')->justReturn([]);

        // Mock: existing user found by email
        $existingUser = new WP_User(99, 'testuser', $claims['email']);

        Functions\when('get_user_by')->alias(function ($field, $value) use ($existingUser, $claims) {
            if ($field === 'email' && $value === $claims['email']) {
                return $existingUser;
            }
            return false;
        });

        // Mock: update_user_meta fails
        Functions\when('update_user_meta')->justReturn(false);

        $result = $this->handler->get_or_create_user($claims);

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertSame('oidc_metadata_storage_failed', $result->get_error_code());
    }
}

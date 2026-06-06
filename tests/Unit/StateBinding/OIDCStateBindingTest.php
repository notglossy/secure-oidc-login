<?php
/**
 * Tests for OIDC_State_Binding class.
 *
 * @package SecureOIDCLogin\Tests\Unit\StateBinding
 */

declare(strict_types=1);

namespace SecureOIDCLogin\Tests\Unit\StateBinding;

use Brain\Monkey\Functions;
use OIDC_State_Binding;
use SecureOIDCLogin\Tests\OIDCTestCase;

/**
 * Tests for the OIDC_State_Binding browser-binding helper.
 *
 * @covers OIDC_State_Binding
 */
class OIDCStateBindingTest extends OIDCTestCase
{
    /**
     * hash() returns the SHA-256 of the secret and is deterministic.
     */
    public function testHashMatchesSha256AndIsDeterministic(): void
    {
        $secret = 'abc123';

        $this->assertSame(hash('sha256', $secret), OIDC_State_Binding::hash($secret));
        $this->assertSame(
            OIDC_State_Binding::hash($secret),
            OIDC_State_Binding::hash($secret),
            'Hashing the same secret must be deterministic'
        );
    }

    /**
     * generate() returns a 32-character secret from wp_generate_password().
     */
    public function testGenerateReturnsSecret(): void
    {
        Functions\expect('wp_generate_password')
            ->once()
            ->with(32, false)
            ->andReturn('abcdefghijklmnopqrstuvwxyz012345');

        $secret = OIDC_State_Binding::generate();

        $this->assertIsString($secret);
        $this->assertSame(32, strlen($secret));
    }

    /**
     * A cookie secret that hashes to the stored value is accepted.
     */
    public function testIsValidAcceptsMatchingSecret(): void
    {
        $secret      = 'the-browser-binding-secret';
        $stored_hash = OIDC_State_Binding::hash($secret);

        $this->assertTrue(OIDC_State_Binding::is_valid($stored_hash, $secret));
    }

    /**
     * A different cookie secret is rejected (this is the forced-login defense).
     */
    public function testIsValidRejectsWrongSecret(): void
    {
        $stored_hash = OIDC_State_Binding::hash('the-real-secret');

        $this->assertFalse(OIDC_State_Binding::is_valid($stored_hash, 'attacker-secret'));
    }

    /**
     * A missing/empty cookie is rejected (victim's browser has no binding cookie).
     */
    public function testIsValidRejectsEmptyCookie(): void
    {
        $stored_hash = OIDC_State_Binding::hash('the-real-secret');

        $this->assertFalse(OIDC_State_Binding::is_valid($stored_hash, ''));
    }

    /**
     * An empty or non-string stored hash is rejected.
     */
    public function testIsValidRejectsEmptyOrNonStringStoredHash(): void
    {
        $this->assertFalse(OIDC_State_Binding::is_valid('', 'some-secret'));
        $this->assertFalse(OIDC_State_Binding::is_valid(false, 'some-secret'));
        $this->assertFalse(OIDC_State_Binding::is_valid(null, 'some-secret'));
        // Legacy `true` value (pre-fix transient contents) must not authenticate.
        $this->assertFalse(OIDC_State_Binding::is_valid(true, 'some-secret'));
    }
}

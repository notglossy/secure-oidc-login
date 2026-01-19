<?php
/**
 * Tests for OIDC_Claims value object.
 *
 * @package SecureOIDCLogin\Tests\Unit\ValueObjects
 */

declare(strict_types=1);

namespace SecureOIDCLogin\Tests\Unit\ValueObjects;

use OIDC_Claims;
use SecureOIDCLogin\Tests\OIDCTestCase;
use WP_Error;

/**
 * Tests for the OIDC_Claims class.
 *
 * @covers OIDC_Claims
 */
class OIDCClaimsTest extends OIDCTestCase
{
    /**
     * Test successful creation from valid claims array.
     */
    public function testFromArrayWithValidClaims(): void
    {
        $claims = $this->getSampleClaims();

        $result = OIDC_Claims::from_array($claims);

        $this->assertInstanceOf(OIDC_Claims::class, $result);
        $this->assertSame('user-123-abc', $result->get_subject());
        $this->assertSame('https://idp.example.com', $result->get_issuer());
        $this->assertSame('client-id-123', $result->get_audience());
        $this->assertSame('user@example.com', $result->get_email());
        $this->assertTrue($result->is_email_verified());
        $this->assertSame('John Doe', $result->get_name());
        $this->assertSame('John', $result->get_given_name());
        $this->assertSame('Doe', $result->get_family_name());
        $this->assertSame('johndoe', $result->get_preferred_username());
        $this->assertSame('random-nonce-value', $result->get_nonce());
    }

    /**
     * Test that missing sub returns WP_Error.
     */
    public function testFromArrayWithMissingSub(): void
    {
        $claims = $this->getSampleClaims();
        unset($claims['sub']);

        $result = OIDC_Claims::from_array($claims);

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertStringContainsString('sub', $result->get_error_message());
    }

    /**
     * Test that missing iss returns WP_Error.
     */
    public function testFromArrayWithMissingIss(): void
    {
        $claims = $this->getSampleClaims();
        unset($claims['iss']);

        $result = OIDC_Claims::from_array($claims);

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertStringContainsString('iss', $result->get_error_message());
    }

    /**
     * Test that missing aud returns WP_Error.
     */
    public function testFromArrayWithMissingAud(): void
    {
        $claims = $this->getSampleClaims();
        unset($claims['aud']);

        $result = OIDC_Claims::from_array($claims);

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertStringContainsString('aud', $result->get_error_message());
    }

    /**
     * Test that missing exp returns WP_Error.
     */
    public function testFromArrayWithMissingExp(): void
    {
        $claims = $this->getSampleClaims();
        unset($claims['exp']);

        $result = OIDC_Claims::from_array($claims);

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertStringContainsString('exp', $result->get_error_message());
    }

    /**
     * Test that missing iat returns WP_Error.
     */
    public function testFromArrayWithMissingIat(): void
    {
        $claims = $this->getSampleClaims();
        unset($claims['iat']);

        $result = OIDC_Claims::from_array($claims);

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertStringContainsString('iat', $result->get_error_message());
    }

    /**
     * Test audience with array value.
     */
    public function testAudienceWithArrayValue(): void
    {
        $claims = $this->getSampleClaims();
        $claims['aud'] = ['client-1', 'client-2'];

        $result = OIDC_Claims::from_array($claims);

        $this->assertSame(['client-1', 'client-2'], $result->get_audience());
    }

    /**
     * Test get_expiration returns correct timestamp.
     */
    public function testGetExpiration(): void
    {
        $claims = $this->getSampleClaims();
        $result = OIDC_Claims::from_array($claims);

        $this->assertSame($claims['exp'], $result->get_expiration());
    }

    /**
     * Test get_issued_at returns correct timestamp.
     */
    public function testGetIssuedAt(): void
    {
        $claims = $this->getSampleClaims();
        $result = OIDC_Claims::from_array($claims);

        $this->assertSame($claims['iat'], $result->get_issued_at());
    }

    /**
     * Test optional fields are null when not provided.
     */
    public function testOptionalFieldsNullWhenNotProvided(): void
    {
        $claims = [
            'sub' => 'user-123',
            'iss' => 'https://idp.example.com',
            'aud' => 'client-id',
            'exp' => time() + 3600,
            'iat' => time(),
        ];

        $result = OIDC_Claims::from_array($claims);

        $this->assertInstanceOf(OIDC_Claims::class, $result);
        $this->assertNull($result->get_email());
        $this->assertNull($result->get_name());
        $this->assertNull($result->get_given_name());
        $this->assertNull($result->get_family_name());
        $this->assertNull($result->get_preferred_username());
        $this->assertNull($result->get_nonce());
        $this->assertFalse($result->is_email_verified());
    }

    /**
     * Test email_verified false when not set.
     */
    public function testEmailVerifiedFalseWhenNotSet(): void
    {
        $claims = $this->getSampleClaims();
        unset($claims['email_verified']);

        $result = OIDC_Claims::from_array($claims);

        $this->assertFalse($result->is_email_verified());
    }

    /**
     * Test email_verified false when set to false.
     */
    public function testEmailVerifiedFalseWhenSetToFalse(): void
    {
        $claims = $this->getSampleClaims();
        $claims['email_verified'] = false;

        $result = OIDC_Claims::from_array($claims);

        $this->assertFalse($result->is_email_verified());
    }

    /**
     * Test is_expired returns true for expired token.
     */
    public function testIsExpiredReturnsTrueForExpiredToken(): void
    {
        $claims = $this->getSampleClaims();
        $claims['exp'] = time() - 3600; // 1 hour ago

        $result = OIDC_Claims::from_array($claims);

        $this->assertTrue($result->is_expired());
    }

    /**
     * Test is_expired returns false for valid token.
     */
    public function testIsExpiredReturnsFalseForValidToken(): void
    {
        $claims = $this->getSampleClaims();
        $claims['exp'] = time() + 3600; // 1 hour from now

        $result = OIDC_Claims::from_array($claims);

        $this->assertFalse($result->is_expired());
    }

    /**
     * Test is_expired respects clock skew.
     */
    public function testIsExpiredRespectsClockSkew(): void
    {
        $claims = $this->getSampleClaims();
        $claims['exp'] = time() - 200; // 200 seconds ago

        $result = OIDC_Claims::from_array($claims);

        // Within default 300s clock skew
        $this->assertFalse($result->is_expired());
        // Exceeds 100s clock skew
        $this->assertTrue($result->is_expired(100));
    }

    /**
     * Test is_issued_in_future returns true for future iat.
     */
    public function testIsIssuedInFutureReturnsTrueForFutureIat(): void
    {
        $claims = $this->getSampleClaims();
        $claims['iat'] = time() + 3600; // 1 hour in future

        $result = OIDC_Claims::from_array($claims);

        $this->assertTrue($result->is_issued_in_future());
    }

    /**
     * Test is_issued_in_future returns false for valid iat.
     */
    public function testIsIssuedInFutureReturnsFalseForValidIat(): void
    {
        $claims = $this->getSampleClaims();
        $claims['iat'] = time(); // Now

        $result = OIDC_Claims::from_array($claims);

        $this->assertFalse($result->is_issued_in_future());
    }

    /**
     * Test is_issued_in_future respects clock skew.
     */
    public function testIsIssuedInFutureRespectsClockSkew(): void
    {
        $claims = $this->getSampleClaims();
        $claims['iat'] = time() + 200; // 200 seconds in future

        $result = OIDC_Claims::from_array($claims);

        // Within default 300s clock skew
        $this->assertFalse($result->is_issued_in_future());
        // Exceeds 100s clock skew
        $this->assertTrue($result->is_issued_in_future(100));
    }

    /**
     * Test get_claim returns custom claim value.
     */
    public function testGetClaimReturnsCustomValue(): void
    {
        $claims = $this->getSampleClaims();
        $claims['custom_claim'] = 'custom_value';

        $result = OIDC_Claims::from_array($claims);

        $this->assertSame('custom_value', $result->get_claim('custom_claim'));
    }

    /**
     * Test get_claim returns null for non-existing claim.
     */
    public function testGetClaimReturnsNullForNonExisting(): void
    {
        $claims = $this->getSampleClaims();
        $result = OIDC_Claims::from_array($claims);

        $this->assertNull($result->get_claim('non_existing'));
    }

    /**
     * Test to_array returns original claims.
     */
    public function testToArrayReturnsOriginalClaims(): void
    {
        $claims = $this->getSampleClaims();
        $result = OIDC_Claims::from_array($claims);

        $this->assertSame($claims, $result->to_array());
    }
}

<?php
/**
 * Tests for OIDC_User_Info value object.
 *
 * @package SecureOIDCLogin\Tests\Unit\ValueObjects
 */

declare(strict_types=1);

namespace SecureOIDCLogin\Tests\Unit\ValueObjects;

use OIDC_User_Info;
use SecureOIDCLogin\Tests\OIDCTestCase;
use WP_Error;

/**
 * Tests for the OIDC_User_Info class.
 *
 * @covers OIDC_User_Info
 */
class OIDCUserInfoTest extends OIDCTestCase
{
    /**
     * Test successful creation from valid userinfo array.
     */
    public function testFromArrayWithValidUserInfo(): void
    {
        $userinfo = $this->getSampleUserInfo();

        $result = OIDC_User_Info::from_array($userinfo);

        $this->assertInstanceOf(OIDC_User_Info::class, $result);
        $this->assertSame('user-123-abc', $result->get_subject());
        $this->assertSame('John Doe', $result->get_name());
        $this->assertSame('John', $result->get_given_name());
        $this->assertSame('Doe', $result->get_family_name());
        $this->assertSame('William', $result->get_middle_name());
        $this->assertSame('Johnny', $result->get_nickname());
        $this->assertSame('johndoe', $result->get_preferred_username());
        $this->assertSame('https://example.com/johndoe', $result->get_profile());
        $this->assertSame('https://example.com/johndoe/photo.jpg', $result->get_picture());
        $this->assertSame('https://johndoe.com', $result->get_website());
        $this->assertSame('john@example.com', $result->get_email());
        $this->assertTrue($result->is_email_verified());
        $this->assertSame('male', $result->get_gender());
        $this->assertSame('1990-01-15', $result->get_birthdate());
        $this->assertSame('America/Los_Angeles', $result->get_zoneinfo());
        $this->assertSame('en-US', $result->get_locale());
        $this->assertSame('+1-555-555-5555', $result->get_phone_number());
        $this->assertTrue($result->is_phone_number_verified());
        $this->assertSame(1609459200, $result->get_updated_at());
    }

    /**
     * Test that missing sub returns WP_Error.
     */
    public function testFromArrayWithMissingSub(): void
    {
        $userinfo = $this->getSampleUserInfo();
        unset($userinfo['sub']);

        $result = OIDC_User_Info::from_array($userinfo);

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertStringContainsString('sub', $result->get_error_message());
    }

    /**
     * Test that empty sub returns WP_Error.
     */
    public function testFromArrayWithEmptySub(): void
    {
        $userinfo = $this->getSampleUserInfo();
        $userinfo['sub'] = '';

        $result = OIDC_User_Info::from_array($userinfo);

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertStringContainsString('sub', $result->get_error_message());
    }

    /**
     * Test optional fields are null when not provided.
     */
    public function testOptionalFieldsNullWhenNotProvided(): void
    {
        $userinfo = ['sub' => 'user-123'];

        $result = OIDC_User_Info::from_array($userinfo);

        $this->assertInstanceOf(OIDC_User_Info::class, $result);
        $this->assertNull($result->get_name());
        $this->assertNull($result->get_given_name());
        $this->assertNull($result->get_family_name());
        $this->assertNull($result->get_middle_name());
        $this->assertNull($result->get_nickname());
        $this->assertNull($result->get_preferred_username());
        $this->assertNull($result->get_profile());
        $this->assertNull($result->get_picture());
        $this->assertNull($result->get_website());
        $this->assertNull($result->get_email());
        $this->assertFalse($result->is_email_verified());
        $this->assertNull($result->get_gender());
        $this->assertNull($result->get_birthdate());
        $this->assertNull($result->get_zoneinfo());
        $this->assertNull($result->get_locale());
        $this->assertNull($result->get_phone_number());
        $this->assertFalse($result->is_phone_number_verified());
        $this->assertNull($result->get_updated_at());
    }

    /**
     * Test email_verified false when not set.
     */
    public function testEmailVerifiedFalseWhenNotSet(): void
    {
        $userinfo = ['sub' => 'user-123', 'email' => 'test@example.com'];

        $result = OIDC_User_Info::from_array($userinfo);

        $this->assertFalse($result->is_email_verified());
    }

    /**
     * Test email_verified false when set to false.
     */
    public function testEmailVerifiedFalseWhenSetToFalse(): void
    {
        $userinfo = ['sub' => 'user-123', 'email' => 'test@example.com', 'email_verified' => false];

        $result = OIDC_User_Info::from_array($userinfo);

        $this->assertFalse($result->is_email_verified());
    }

    /**
     * Test phone_number_verified false when not set.
     */
    public function testPhoneNumberVerifiedFalseWhenNotSet(): void
    {
        $userinfo = ['sub' => 'user-123', 'phone_number' => '+1-555-555-5555'];

        $result = OIDC_User_Info::from_array($userinfo);

        $this->assertFalse($result->is_phone_number_verified());
    }

    /**
     * Test get_display_name returns full name when set.
     */
    public function testGetDisplayNameReturnsFullName(): void
    {
        $userinfo = $this->getSampleUserInfo();
        $result = OIDC_User_Info::from_array($userinfo);

        $this->assertSame('John Doe', $result->get_display_name());
    }

    /**
     * Test get_display_name returns first + last name when name not set.
     */
    public function testGetDisplayNameReturnsFirstLastName(): void
    {
        $userinfo = [
            'sub' => 'user-123',
            'given_name' => 'John',
            'family_name' => 'Doe',
        ];

        $result = OIDC_User_Info::from_array($userinfo);

        $this->assertSame('John Doe', $result->get_display_name());
    }

    /**
     * Test get_display_name returns given_name only when family_name not set.
     */
    public function testGetDisplayNameReturnsGivenNameOnly(): void
    {
        $userinfo = [
            'sub' => 'user-123',
            'given_name' => 'John',
        ];

        $result = OIDC_User_Info::from_array($userinfo);

        $this->assertSame('John', $result->get_display_name());
    }

    /**
     * Test get_display_name returns preferred_username when names not set.
     */
    public function testGetDisplayNameReturnsPreferredUsername(): void
    {
        $userinfo = [
            'sub' => 'user-123',
            'preferred_username' => 'johndoe',
        ];

        $result = OIDC_User_Info::from_array($userinfo);

        $this->assertSame('johndoe', $result->get_display_name());
    }

    /**
     * Test get_display_name returns sub when nothing else is set.
     */
    public function testGetDisplayNameReturnsSub(): void
    {
        $userinfo = ['sub' => 'user-123-abc'];

        $result = OIDC_User_Info::from_array($userinfo);

        $this->assertSame('user-123-abc', $result->get_display_name());
    }

    /**
     * Test get_claim returns custom claim value.
     */
    public function testGetClaimReturnsCustomValue(): void
    {
        $userinfo = $this->getSampleUserInfo();
        $userinfo['custom_claim'] = 'custom_value';

        $result = OIDC_User_Info::from_array($userinfo);

        $this->assertSame('custom_value', $result->get_claim('custom_claim'));
    }

    /**
     * Test get_claim returns null for non-existing claim.
     */
    public function testGetClaimReturnsNullForNonExisting(): void
    {
        $userinfo = $this->getSampleUserInfo();
        $result = OIDC_User_Info::from_array($userinfo);

        $this->assertNull($result->get_claim('non_existing'));
    }

    /**
     * Test to_array returns original userinfo.
     */
    public function testToArrayReturnsOriginalUserInfo(): void
    {
        $userinfo = $this->getSampleUserInfo();
        $result = OIDC_User_Info::from_array($userinfo);

        $this->assertSame($userinfo, $result->to_array());
    }

    /**
     * Test updated_at is cast to int.
     */
    public function testUpdatedAtIsCastToInt(): void
    {
        $userinfo = [
            'sub' => 'user-123',
            'updated_at' => '1609459200',
        ];

        $result = OIDC_User_Info::from_array($userinfo);

        $this->assertSame(1609459200, $result->get_updated_at());
    }
}

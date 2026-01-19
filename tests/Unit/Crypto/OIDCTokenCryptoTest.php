<?php
/**
 * Tests for OIDC_Token_Crypto class.
 *
 * @package SecureOIDCLogin\Tests\Unit\Crypto
 */

declare(strict_types=1);

namespace SecureOIDCLogin\Tests\Unit\Crypto;

use Brain\Monkey\Functions;
use OIDC_Token_Crypto;
use SecureOIDCLogin\Tests\OIDCTestCase;
use WP_Error;

/**
 * Tests for the OIDC_Token_Crypto class.
 *
 * @covers OIDC_Token_Crypto
 */
class OIDCTokenCryptoTest extends OIDCTestCase
{
    /**
     * Set up test environment.
     */
    protected function setUp(): void
    {
        parent::setUp();

        // Stub wp_salt function to return a predictable value for key derivation
        Functions\when('wp_salt')->justReturn('test-salt-value-for-unit-testing');
    }

    /**
     * Test is_supported returns true when sodium functions exist.
     */
    public function testIsSupportedReturnsTrueWhenSodiumExists(): void
    {
        // Sodium should be available in PHP 7.2+
        $this->assertTrue(OIDC_Token_Crypto::is_supported());
    }

    /**
     * Test encrypt returns empty string for empty input.
     */
    public function testEncryptReturnsEmptyStringForEmptyInput(): void
    {
        $result = OIDC_Token_Crypto::encrypt('');

        $this->assertSame('', $result);
    }

    /**
     * Test encrypt returns v2 prefixed encrypted string.
     */
    public function testEncryptReturnsV2PrefixedString(): void
    {
        $plaintext = 'test-token-value';

        $result = OIDC_Token_Crypto::encrypt($plaintext);

        $this->assertIsString($result);
        $this->assertStringStartsWith('enc:v2:', $result);
    }

    /**
     * Test encrypt produces different outputs for same input (due to random nonce).
     */
    public function testEncryptProducesDifferentOutputs(): void
    {
        $plaintext = 'test-token-value';

        $result1 = OIDC_Token_Crypto::encrypt($plaintext);
        $result2 = OIDC_Token_Crypto::encrypt($plaintext);

        $this->assertNotSame($result1, $result2);
    }

    /**
     * Test decrypt_if_needed returns empty string for empty input.
     */
    public function testDecryptIfNeededReturnsEmptyStringForEmptyInput(): void
    {
        $result = OIDC_Token_Crypto::decrypt_if_needed('');

        $this->assertSame('', $result);
    }

    /**
     * Test round-trip encryption and decryption.
     */
    public function testRoundTripEncryptionDecryption(): void
    {
        $plaintext = 'test-token-value-12345';

        $encrypted = OIDC_Token_Crypto::encrypt($plaintext);
        $decrypted = OIDC_Token_Crypto::decrypt_if_needed($encrypted);

        $this->assertSame($plaintext, $decrypted);
    }

    /**
     * Test round-trip with complex token content.
     */
    public function testRoundTripWithComplexContent(): void
    {
        // Simulate a JWT-like token
        $plaintext = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.signature';

        $encrypted = OIDC_Token_Crypto::encrypt($plaintext);
        $decrypted = OIDC_Token_Crypto::decrypt_if_needed($encrypted);

        $this->assertSame($plaintext, $decrypted);
    }

    /**
     * Test decrypt_if_needed returns WP_Error for plaintext (unencrypted) tokens.
     */
    public function testDecryptIfNeededRejectsPlaintextTokens(): void
    {
        $plaintext = 'unencrypted-token-value';

        $result = OIDC_Token_Crypto::decrypt_if_needed($plaintext);

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertSame('oidc_plaintext_token_rejected', $result->get_error_code());
    }

    /**
     * Test decrypt_if_needed returns WP_Error for invalid v2 payload.
     */
    public function testDecryptIfNeededReturnsErrorForInvalidV2Payload(): void
    {
        // Invalid base64 content
        $invalid = 'enc:v2:not-valid-base64!!!';

        $result = OIDC_Token_Crypto::decrypt_if_needed($invalid);

        $this->assertInstanceOf(WP_Error::class, $result);
    }

    /**
     * Test decrypt_if_needed returns WP_Error for truncated v2 payload.
     */
    public function testDecryptIfNeededReturnsErrorForTruncatedV2Payload(): void
    {
        // Base64-encoded content that's too short
        $truncated = 'enc:v2:' . base64_encode('short');

        $result = OIDC_Token_Crypto::decrypt_if_needed($truncated);

        $this->assertInstanceOf(WP_Error::class, $result);
    }

    /**
     * Test decrypt_if_needed returns WP_Error for tampered v2 payload.
     */
    public function testDecryptIfNeededReturnsErrorForTamperedPayload(): void
    {
        $plaintext = 'test-token-value';
        $encrypted = OIDC_Token_Crypto::encrypt($plaintext);

        // Tamper with the payload
        $tampered = $encrypted . 'tampered';

        $result = OIDC_Token_Crypto::decrypt_if_needed($tampered);

        $this->assertInstanceOf(WP_Error::class, $result);
    }

    /**
     * Test encryption of special characters.
     */
    public function testEncryptionOfSpecialCharacters(): void
    {
        $plaintext = "test\n\t\r\0with special chars: @#$%^&*()_+-=[]{}|;':\",./<>?";

        $encrypted = OIDC_Token_Crypto::encrypt($plaintext);
        $decrypted = OIDC_Token_Crypto::decrypt_if_needed($encrypted);

        $this->assertSame($plaintext, $decrypted);
    }

    /**
     * Test encryption of unicode content.
     */
    public function testEncryptionOfUnicodeContent(): void
    {
        $plaintext = 'Test with unicode: 你好世界 🔐 émojis';

        $encrypted = OIDC_Token_Crypto::encrypt($plaintext);
        $decrypted = OIDC_Token_Crypto::decrypt_if_needed($encrypted);

        $this->assertSame($plaintext, $decrypted);
    }

    /**
     * Test encryption of long content.
     */
    public function testEncryptionOfLongContent(): void
    {
        // Generate a long token (like a real JWT could be)
        $plaintext = str_repeat('a', 10000);

        $encrypted = OIDC_Token_Crypto::encrypt($plaintext);
        $decrypted = OIDC_Token_Crypto::decrypt_if_needed($encrypted);

        $this->assertSame($plaintext, $decrypted);
    }

    /**
     * Test log_error method doesn't throw.
     */
    public function testLogErrorDoesNotThrow(): void
    {
        // This test just ensures the method doesn't throw an exception
        OIDC_Token_Crypto::log_error('Test error message');

        $this->assertTrue(true);
    }

    /**
     * Test constants are defined correctly.
     */
    public function testConstantsAreDefined(): void
    {
        $this->assertSame('enc:v2:', OIDC_Token_Crypto::PREFIX_V2);
        $this->assertSame(12, OIDC_Token_Crypto::NONCE_LENGTH_V2);
        $this->assertSame(32, OIDC_Token_Crypto::KEY_LENGTH_V2);

        // Legacy constants
        $this->assertSame('enc:v1:', OIDC_Token_Crypto::PREFIX_V1);
        $this->assertSame('aes-256-gcm', OIDC_Token_Crypto::CIPHER_V1);
    }

    /**
     * Test v1 legacy token handling when OpenSSL is available.
     */
    public function testV1LegacyTokenDecryptionIfSupported(): void
    {
        // Skip if OpenSSL AES-256-GCM is not available
        if (!function_exists('openssl_encrypt') || !in_array('aes-256-gcm', openssl_get_cipher_methods(true))) {
            $this->markTestSkipped('OpenSSL AES-256-GCM not available');
        }

        // Create a v1 encrypted token manually to test backward compatibility
        // This simulates tokens encrypted before the Sodium migration
        $key = hash('sha256', 'test-salt-value-for-unit-testing', true);
        $plaintext = 'legacy-token-value';
        $iv = random_bytes(12);
        $tag = '';

        $ciphertext = openssl_encrypt($plaintext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
        $v1Token = 'enc:v1:' . base64_encode($iv . $tag . $ciphertext);

        $result = OIDC_Token_Crypto::decrypt_if_needed($v1Token);

        $this->assertSame($plaintext, $result);
    }
}

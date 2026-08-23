<?php
/**
 * Tests for OIDC_Env class.
 *
 * @package SecureOIDCLogin\Tests\Unit\Env
 */

declare(strict_types=1);

namespace SecureOIDCLogin\Tests\Unit\Env;

use OIDC_Env;
use SecureOIDCLogin\Tests\OIDCTestCase;

/**
 * Tests for strict boolean environment variable parsing.
 *
 * @covers OIDC_Env
 */
class OIDCEnvTest extends OIDCTestCase
{
    /**
     * Clean up the test variable after each test.
     */
    protected function tearDown(): void
    {
        putenv('SECURE_OIDC_TEST_BOOL');
        parent::tearDown();
    }

    /**
     * Unset and empty variables return null (caller falls back to stored setting).
     */
    public function testReturnsNullWhenVarUnsetOrEmpty(): void
    {
        putenv('SECURE_OIDC_TEST_BOOL');
        $this->assertNull(OIDC_Env::get_bool('SECURE_OIDC_TEST_BOOL'));

        putenv('SECURE_OIDC_TEST_BOOL=');
        $this->assertNull(OIDC_Env::get_bool('SECURE_OIDC_TEST_BOOL'));
    }

    /**
     * Recognized truthy values parse to true, case-insensitively.
     *
     * @dataProvider truthyValueProvider
     */
    public function testRecognizesTruthyValues(string $raw): void
    {
        putenv('SECURE_OIDC_TEST_BOOL=' . $raw);
        $this->assertTrue(OIDC_Env::get_bool('SECURE_OIDC_TEST_BOOL'));
    }

    /**
     * @return array<string, array{0: string}>
     */
    public function truthyValueProvider(): array
    {
        return [
            'lowercase true' => ['true'],
            'numeric one' => ['1'],
            'yes' => ['yes'],
            'on' => ['on'],
        ];
    }

    /**
     * Recognized falsy values parse to false, case-insensitively.
     *
     * @dataProvider falsyValueProvider
     */
    public function testRecognizesFalsyValues(string $raw): void
    {
        putenv('SECURE_OIDC_TEST_BOOL=' . $raw);
        $this->assertFalse(OIDC_Env::get_bool('SECURE_OIDC_TEST_BOOL'));
    }

    /**
     * @return array<string, array{0: string}>
     */
    public function falsyValueProvider(): array
    {
        return [
            'lowercase false' => ['false'],
            'numeric zero' => ['0'],
            'no' => ['no'],
            'off' => ['off'],
        ];
    }

    /**
     * Whitespace around the value is trimmed before parsing.
     */
    public function testTrimsWhitespace(): void
    {
        putenv('SECURE_OIDC_TEST_BOOL= true ');
        $this->assertTrue(OIDC_Env::get_bool('SECURE_OIDC_TEST_BOOL'));

        putenv('SECURE_OIDC_TEST_BOOL=  false ');
        $this->assertFalse(OIDC_Env::get_bool('SECURE_OIDC_TEST_BOOL'));
    }

    /**
     * Unrecognized values return null so callers fall back to the stored setting.
     *
     * Regression test for issue #76: previously any non-"true" value was treated
     * as false, silently disabling protections when operators used values like
     * "1" or "yes" that the old parser did not recognize.
     */
    public function testReturnsNullOnUnrecognizedValue(): void
    {
        putenv('SECURE_OIDC_TEST_BOOL=maybe');
        $this->assertNull(OIDC_Env::get_bool('SECURE_OIDC_TEST_BOOL'));

        putenv('SECURE_OIDC_TEST_BOOL=enabled');
        $this->assertNull(OIDC_Env::get_bool('SECURE_OIDC_TEST_BOOL'));
    }
}

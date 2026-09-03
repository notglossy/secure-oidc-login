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
        putenv('SECURE_OIDC_TEST_INT');
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

    /**
     * Unset and empty variables fall back to the default.
     */
    public function testGetIntReturnsDefaultWhenVarUnsetOrEmpty(): void
    {
        putenv('SECURE_OIDC_TEST_INT');
        $this->assertSame(10, OIDC_Env::get_int('SECURE_OIDC_TEST_INT', 10, 5, 30));

        putenv('SECURE_OIDC_TEST_INT=');
        $this->assertSame(10, OIDC_Env::get_int('SECURE_OIDC_TEST_INT', 10, 5, 30));
    }

    /**
     * In-range integers are returned as-is, including the bounds.
     */
    public function testGetIntReturnsValueWithinRange(): void
    {
        putenv('SECURE_OIDC_TEST_INT=15');
        $this->assertSame(15, OIDC_Env::get_int('SECURE_OIDC_TEST_INT', 10, 5, 30));

        putenv('SECURE_OIDC_TEST_INT=5');
        $this->assertSame(5, OIDC_Env::get_int('SECURE_OIDC_TEST_INT', 10, 5, 30));

        putenv('SECURE_OIDC_TEST_INT=30');
        $this->assertSame(30, OIDC_Env::get_int('SECURE_OIDC_TEST_INT', 10, 5, 30));
    }

    /**
     * Out-of-range and non-integer values fall back to the default.
     */
    public function testGetIntReturnsDefaultWhenOutOfRangeOrInvalid(): void
    {
        putenv('SECURE_OIDC_TEST_INT=4');
        $this->assertSame(10, OIDC_Env::get_int('SECURE_OIDC_TEST_INT', 10, 5, 30));

        putenv('SECURE_OIDC_TEST_INT=31');
        $this->assertSame(10, OIDC_Env::get_int('SECURE_OIDC_TEST_INT', 10, 5, 30));

        putenv('SECURE_OIDC_TEST_INT=fast');
        $this->assertSame(10, OIDC_Env::get_int('SECURE_OIDC_TEST_INT', 10, 5, 30));

        putenv('SECURE_OIDC_TEST_INT=12.5');
        $this->assertSame(10, OIDC_Env::get_int('SECURE_OIDC_TEST_INT', 10, 5, 30));

        // Newlines must not allow log-line injection; value still falls back.
        putenv("SECURE_OIDC_TEST_INT=10\n[Fake]");
        $this->assertSame(10, OIDC_Env::get_int('SECURE_OIDC_TEST_INT', 10, 5, 30));
    }
}

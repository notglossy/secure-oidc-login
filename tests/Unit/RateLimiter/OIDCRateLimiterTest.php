<?php
/**
 * Tests for OIDC_Rate_Limiter class.
 *
 * @package SecureOIDCLogin\Tests\Unit\RateLimiter
 */

declare(strict_types=1);

namespace SecureOIDCLogin\Tests\Unit\RateLimiter;

use Brain\Monkey\Functions;
use OIDC_Rate_Limiter;
use SecureOIDCLogin\Tests\OIDCTestCase;

/**
 * Tests for the OIDC_Rate_Limiter class.
 *
 * @covers OIDC_Rate_Limiter
 */
class OIDCRateLimiterTest extends OIDCTestCase
{
    /**
     * Rate limiter instance.
     *
     * @var OIDC_Rate_Limiter
     */
    private $limiter;

    /**
     * Transient storage for testing.
     *
     * @var array<string, mixed>
     */
    private $transients = [];

    /**
     * Captured transient expirations, keyed by transient key.
     *
     * @var array<string, int>
     */
    private $transient_expirations = [];

    /**
     * Set up test environment.
     */
    protected function setUp(): void
    {
        parent::setUp();

        $this->transients = [];
        $this->transient_expirations = [];

        // Mock WordPress constants
        if (!defined('MINUTE_IN_SECONDS')) {
            define('MINUTE_IN_SECONDS', 60);
        }
        if (!defined('HOUR_IN_SECONDS')) {
            define('HOUR_IN_SECONDS', 3600);
        }
        if (!defined('DAY_IN_SECONDS')) {
            define('DAY_IN_SECONDS', 86400);
        }

        // Mock WordPress transient functions
        Functions\when('get_transient')->alias(function (string $key) {
            return $this->transients[$key] ?? false;
        });

        Functions\when('set_transient')->alias(function (string $key, $value, int $expiration) {
            $this->transients[$key] = $value;
            $this->transient_expirations[$key] = $expiration;
            return true;
        });

        Functions\when('delete_transient')->alias(function (string $key) {
            unset($this->transients[$key]);
            return true;
        });

        // Mock wp_salt
        Functions\when('wp_salt')->justReturn('test-salt-value');

        // Mock sanitize_text_field
        Functions\when('sanitize_text_field')->returnArg();

        // Mock getenv to return false by default
        Functions\when('getenv')->justReturn(false);

        // Mock $_SERVER
        $_SERVER['REMOTE_ADDR'] = '192.168.1.100';

        $this->limiter = new OIDC_Rate_Limiter();
    }

    /**
     * Test is_rate_limited returns false when no attempts recorded.
     */
    public function testIsRateLimitedReturnsFalseWhenNoAttempts(): void
    {
        $result = $this->limiter->is_rate_limited('test_action');

        $this->assertFalse($result);
    }

    /**
     * Test is_rate_limited returns false when under limit.
     */
    public function testIsRateLimitedReturnsFalseWhenUnderLimit(): void
    {
        // Record 5 attempts (default limit is 10)
        for ($i = 0; $i < 5; $i++) {
            $this->limiter->record_attempt('test_action');
        }

        $result = $this->limiter->is_rate_limited('test_action');

        $this->assertFalse($result);
    }

    /**
     * Test is_rate_limited returns true when limit exceeded.
     */
    public function testIsRateLimitedReturnsTrueWhenLimitExceeded(): void
    {
        // Record 10 attempts to reach the limit
        for ($i = 0; $i < 10; $i++) {
            $this->limiter->record_attempt('test_action');
        }

        // Next check should trigger rate limit
        $result = $this->limiter->is_rate_limited('test_action');

        $this->assertTrue($result);
    }

    /**
     * Test is_rate_limited returns true when locked out.
     */
    public function testIsRateLimitedReturnsTrueWhenLockedOut(): void
    {
        // Simulate existing lockout by setting lockout transient
        $ip_hash = hash('sha256', '192.168.1.100' . 'test-salt-value');
        $lockout_key = 'oidc_lockout_test_action_' . substr($ip_hash, 0, 16);
        $this->transients[$lockout_key] = time();

        $result = $this->limiter->is_rate_limited('test_action');

        $this->assertTrue($result);
    }

    /**
     * Test record_attempt creates new transient on first attempt.
     */
    public function testRecordAttemptCreatesNewTransient(): void
    {
        $this->limiter->record_attempt('test_action');

        $ip_hash = hash('sha256', '192.168.1.100' . 'test-salt-value');
        $attempts_key = 'oidc_attempts_test_action_' . substr($ip_hash, 0, 16);

        $this->assertArrayHasKey($attempts_key, $this->transients);
        $state = $this->transients[$attempts_key];
        $this->assertIsArray($state);
        $this->assertSame(1, $state['count']);
        $this->assertEqualsWithDelta(time(), $state['started'], 5);
    }

    /**
     * Legacy integer counters migrate to the new state format.
     */
    public function testRecordAttemptIncrementsExistingTransient(): void
    {
        $attempts_key = $this->seed_attempts('test_action', 5);

        $this->limiter->record_attempt('test_action');

        $state = $this->transients[$attempts_key];
        $this->assertIsArray($state);
        $this->assertSame(6, $state['count']);
        $this->assertEqualsWithDelta(time(), $state['started'], 5);
    }

    /**
     * Test clear_limit removes both attempts and lockout transients.
     */
    public function testClearLimitRemovesTransients(): void
    {
        $ip_hash = hash('sha256', '192.168.1.100' . 'test-salt-value');
        $attempts_key = 'oidc_attempts_test_action_' . substr($ip_hash, 0, 16);
        $lockout_key = 'oidc_lockout_test_action_' . substr($ip_hash, 0, 16);

        $this->transients[$attempts_key] = 5;
        $this->transients[$lockout_key] = time();

        $this->limiter->clear_limit('test_action');

        $this->assertArrayNotHasKey($attempts_key, $this->transients);
        $this->assertArrayNotHasKey($lockout_key, $this->transients);
    }

    /**
     * Test get_remaining_attempts returns max attempts when no attempts recorded.
     */
    public function testGetRemainingAttemptsReturnsMaxWhenNoAttempts(): void
    {
        $remaining = $this->limiter->get_remaining_attempts('test_action');

        $this->assertSame(10, $remaining); // Default max_attempts is 10
    }

    /**
     * Test get_remaining_attempts returns correct count.
     */
    public function testGetRemainingAttemptsReturnsCorrectCount(): void
    {
        // Record 3 attempts
        for ($i = 0; $i < 3; $i++) {
            $this->limiter->record_attempt('test_action');
        }

        $remaining = $this->limiter->get_remaining_attempts('test_action');

        $this->assertSame(7, $remaining); // 10 - 3 = 7
    }

    /**
     * Test get_remaining_attempts returns 0 when locked out.
     */
    public function testGetRemainingAttemptsReturnsZeroWhenLockedOut(): void
    {
        $ip_hash = hash('sha256', '192.168.1.100' . 'test-salt-value');
        $lockout_key = 'oidc_lockout_test_action_' . substr($ip_hash, 0, 16);
        $this->transients[$lockout_key] = time();

        $remaining = $this->limiter->get_remaining_attempts('test_action');

        $this->assertSame(0, $remaining);
    }

    /**
     * Test get_lockout_expiry returns false when not locked out.
     */
    public function testGetLockoutExpiryReturnsFalseWhenNotLockedOut(): void
    {
        $expiry = $this->limiter->get_lockout_expiry('test_action');

        $this->assertFalse($expiry);
    }

    /**
     * Test get_lockout_expiry returns correct timestamp.
     */
    public function testGetLockoutExpiryReturnsCorrectTimestamp(): void
    {
        $lockout_time = time();
        $ip_hash = hash('sha256', '192.168.1.100' . 'test-salt-value');
        $lockout_key = 'oidc_lockout_test_action_' . substr($ip_hash, 0, 16);
        $this->transients[$lockout_key] = $lockout_time;

        $expiry = $this->limiter->get_lockout_expiry('test_action');

        // Default lockout duration is 15 minutes (900 seconds)
        $this->assertSame($lockout_time + 900, $expiry);
    }

    /**
     * Test environment variable configuration for max attempts.
     */
    public function testEnvironmentVariableConfigurationForMaxAttempts(): void
    {
        Functions\when('getenv')->alias(function ($var) {
            if ($var === 'SECURE_OIDC_RATE_LIMIT_ATTEMPTS') {
                return '5';
            }
            return false;
        });

        $limiter = new OIDC_Rate_Limiter();

        // Record 5 attempts to reach the new limit
        for ($i = 0; $i < 5; $i++) {
            $limiter->record_attempt('test_action');
        }

        $result = $limiter->is_rate_limited('test_action');

        $this->assertTrue($result);
    }

    /**
     * Test environment variable configuration for time window.
     */
    public function testEnvironmentVariableConfigurationForTimeWindow(): void
    {
        Functions\when('getenv')->alias(function ($var) {
            if ($var === 'SECURE_OIDC_RATE_LIMIT_WINDOW') {
                return '60'; // 1 minute
            }
            return false;
        });

        $limiter = new OIDC_Rate_Limiter();

        // Environment variable should be used
        $this->assertInstanceOf(OIDC_Rate_Limiter::class, $limiter);
    }

    /**
     * Test environment variable configuration for lockout duration.
     */
    public function testEnvironmentVariableConfigurationForLockoutDuration(): void
    {
        Functions\when('getenv')->alias(function ($var) {
            if ($var === 'SECURE_OIDC_RATE_LIMIT_LOCKOUT') {
                return '300'; // 5 minutes
            }
            return false;
        });

        $limiter = new OIDC_Rate_Limiter();

        // Environment variable should be used
        $this->assertInstanceOf(OIDC_Rate_Limiter::class, $limiter);
    }

    /**
     * Test invalid environment variable falls back to default.
     */
    public function testInvalidEnvironmentVariableFallsBackToDefault(): void
    {
        Functions\when('getenv')->alias(function ($var) {
            if ($var === 'SECURE_OIDC_RATE_LIMIT_ATTEMPTS') {
                return 'invalid'; // Invalid non-numeric value
            }
            return false;
        });

        $limiter = new OIDC_Rate_Limiter();

        // Should fall back to default of 10 attempts
        for ($i = 0; $i < 10; $i++) {
            $limiter->record_attempt('test_action');
        }

        $result = $limiter->is_rate_limited('test_action');

        $this->assertTrue($result);
    }

    /**
     * Test rate limiting is IP-specific.
     */
    public function testRateLimitingIsIPSpecific(): void
    {
        // Record 10 attempts from first IP
        for ($i = 0; $i < 10; $i++) {
            $this->limiter->record_attempt('test_action');
        }

        // Change IP address
        $_SERVER['REMOTE_ADDR'] = '192.168.1.200';
        $limiter2 = new OIDC_Rate_Limiter();

        // Should not be rate limited (different IP)
        $result = $limiter2->is_rate_limited('test_action');

        $this->assertFalse($result);
    }

    /**
     * Test rate limiting is action-specific.
     */
    public function testRateLimitingIsActionSpecific(): void
    {
        // Record 10 attempts for action1
        for ($i = 0; $i < 10; $i++) {
            $this->limiter->record_attempt('action1');
        }

        // action1 should be limited
        $this->assertTrue($this->limiter->is_rate_limited('action1'));

        // action2 should not be limited
        $this->assertFalse($this->limiter->is_rate_limited('action2'));
    }

    /**
     * Test proxy header trust with X-Forwarded-For when enabled.
     */
    public function testProxyHeaderTrustWithXForwardedFor(): void
    {
        Functions\when('getenv')->alias(function ($var) {
            if ($var === 'SECURE_OIDC_TRUST_PROXY_HEADERS') {
                return true;
            }
            return false;
        });

        if (!defined('SECURE_OIDC_TRUST_PROXY_HEADERS')) {
            define('SECURE_OIDC_TRUST_PROXY_HEADERS', true);
        }

        $_SERVER['HTTP_X_FORWARDED_FOR'] = '203.0.113.45, 192.168.1.100';

        $limiter = new OIDC_Rate_Limiter();

        // Record attempts - should use the forwarded IP (203.0.113.45)
        $limiter->record_attempt('test_action');

        // Should use the forwarded IP
        $this->assertInstanceOf(OIDC_Rate_Limiter::class, $limiter);
    }

    /**
     * Test proxy header trust with X-Real-IP when enabled.
     */
    public function testProxyHeaderTrustWithXRealIP(): void
    {
        if (!defined('SECURE_OIDC_TRUST_PROXY_HEADERS')) {
            define('SECURE_OIDC_TRUST_PROXY_HEADERS', true);
        }

        // X-Real-IP is checked first, so it should be used
        $_SERVER['HTTP_X_REAL_IP'] = '198.51.100.50';
        unset($_SERVER['HTTP_X_FORWARDED_FOR']);
        unset($_SERVER['HTTP_CLIENT_IP']);

        $limiter = new OIDC_Rate_Limiter();

        // Record attempts - should use X-Real-IP
        $limiter->record_attempt('test_action');

        $this->assertInstanceOf(OIDC_Rate_Limiter::class, $limiter);
    }

    /**
     * Test proxy header trust with Client-IP when enabled.
     */
    public function testProxyHeaderTrustWithClientIP(): void
    {
        if (!defined('SECURE_OIDC_TRUST_PROXY_HEADERS')) {
            define('SECURE_OIDC_TRUST_PROXY_HEADERS', true);
        }

        // Only set Client-IP
        unset($_SERVER['HTTP_X_REAL_IP']);
        unset($_SERVER['HTTP_X_FORWARDED_FOR']);
        $_SERVER['HTTP_CLIENT_IP'] = '198.51.100.75';

        $limiter = new OIDC_Rate_Limiter();

        // Record attempts - should use Client-IP
        $limiter->record_attempt('test_action');

        $this->assertInstanceOf(OIDC_Rate_Limiter::class, $limiter);
    }

    /**
     * Test proxy header with invalid IP is ignored.
     */
    public function testProxyHeaderWithInvalidIPIsIgnored(): void
    {
        if (!defined('SECURE_OIDC_TRUST_PROXY_HEADERS')) {
            define('SECURE_OIDC_TRUST_PROXY_HEADERS', true);
        }

        // Set invalid IP in proxy header
        $_SERVER['HTTP_X_FORWARDED_FOR'] = 'not-a-valid-ip, also-invalid';
        $_SERVER['REMOTE_ADDR'] = '192.168.1.100';

        $limiter = new OIDC_Rate_Limiter();

        // Should fall back to REMOTE_ADDR since proxy header has invalid IP
        $limiter->record_attempt('test_action');

        $this->assertInstanceOf(OIDC_Rate_Limiter::class, $limiter);
    }

    /**
     * Test proxy header trust via environment variable.
     */
    public function testProxyHeaderTrustViaEnvironmentVariable(): void
    {
        Functions\when('getenv')->alias(function ($var) {
            if ($var === 'SECURE_OIDC_TRUST_PROXY_HEADERS') {
                return 'true';
            }
            return false;
        });

        $_SERVER['HTTP_X_FORWARDED_FOR'] = '203.0.113.99, 192.168.1.100';
        $_SERVER['REMOTE_ADDR'] = '192.168.1.100';

        $limiter = new OIDC_Rate_Limiter();

        // Record attempts - should use the forwarded IP (203.0.113.99)
        $limiter->record_attempt('test_action');

        $this->assertInstanceOf(OIDC_Rate_Limiter::class, $limiter);
    }

    /**
     * Test mask_ip masks IPv4 addresses by replacing the last octet.
     */
    public function testMaskIpMasksIpv4Address(): void
    {
        $this->assertSame('192.168.1.xxx', OIDC_Rate_Limiter::mask_ip('192.168.1.100'));
        $this->assertSame('10.0.0.xxx', OIDC_Rate_Limiter::mask_ip('10.0.0.1'));
        $this->assertSame('0.0.0.xxx', OIDC_Rate_Limiter::mask_ip('0.0.0.0'));
    }

    /**
     * Test mask_ip masks IPv6 addresses by replacing the last group.
     */
    public function testMaskIpMasksIpv6Address(): void
    {
        $this->assertSame(
            '2001:0db8:85a3::8a2e:0370:xxxx',
            OIDC_Rate_Limiter::mask_ip('2001:0db8:85a3::8a2e:0370:7334')
        );
        $this->assertSame('::xxxx', OIDC_Rate_Limiter::mask_ip('::1'));
    }

    /**
     * Test mask_ip returns unknown for invalid input.
     */
    public function testMaskIpReturnsUnknownForInvalidInput(): void
    {
        $this->assertSame('unknown', OIDC_Rate_Limiter::mask_ip(''));
        $this->assertSame('unknown', OIDC_Rate_Limiter::mask_ip('not-an-ip'));
        $this->assertSame('unknown', OIDC_Rate_Limiter::mask_ip('unknown'));
    }

    /**
     * Test fallback to 0.0.0.0 when no valid IP found.
     */
    public function testFallbackToDefaultIPWhenNoValidIP(): void
    {
        unset($_SERVER['REMOTE_ADDR']);

        $limiter = new OIDC_Rate_Limiter();

        // Should not throw exception
        $result = $limiter->is_rate_limited('test_action');

        $this->assertFalse($result);
    }

    /**
     * Test the unresolvable-IP warning is logged at most once per hour.
     *
     * get_client_ip() runs on every rate-limit operation, so the fallback
     * warning is throttled behind a 1-hour transient. Force the no-IP fallback
     * and verify two operations produce exactly one warning.
     */
    public function testUnresolvableIpWarningIsThrottled(): void
    {
        // Preserve the global state this test mutates.
        $savedServer = $_SERVER;

        // Remove every IP source so get_client_ip() must use the 0.0.0.0 fallback.
        unset(
            $_SERVER['REMOTE_ADDR'],
            $_SERVER['HTTP_X_REAL_IP'],
            $_SERVER['HTTP_X_FORWARDED_FOR'],
            $_SERVER['HTTP_CLIENT_IP']
        );

        // Capture the global error_log() output to a temp file.
        $logFile     = tempnam(sys_get_temp_dir(), 'oidc-iplog');
        $previousLog = ini_set('error_log', $logFile);

        try {
            $limiter = new OIDC_Rate_Limiter();
            $limiter->is_rate_limited('test_action');
            $limiter->is_rate_limited('test_action');

            $logContents = (string) file_get_contents($logFile);
            $occurrences = substr_count($logContents, 'Could not determine client IP for rate limiting');
            $this->assertSame(1, $occurrences, 'Warning should be logged once per hour, not on every call');
        } finally {
            ini_set('error_log', $previousLog);
            unlink($logFile);
            $_SERVER = $savedServer;
        }
    }

    /**
     * Test lockout is initiated when max attempts exceeded.
     */
    public function testLockoutInitiatedWhenMaxAttemptsExceeded(): void
    {
        // Record exactly 10 attempts
        for ($i = 0; $i < 10; $i++) {
            $this->limiter->record_attempt('test_action');
        }

        // Trigger lockout by checking rate limit
        $result = $this->limiter->is_rate_limited('test_action');

        // Should be rate limited now
        $this->assertTrue($result);

        // Lockout expiry should be set
        $expiry = $this->limiter->get_lockout_expiry('test_action');
        $this->assertNotFalse($expiry);
        $this->assertGreaterThan(time(), $expiry);
    }

    /**
     * Test attempts counter is cleared when lockout initiated.
     */
    public function testAttemptsCounterClearedWhenLockoutInitiated(): void
    {
        // Record exactly 10 attempts
        for ($i = 0; $i < 10; $i++) {
            $this->limiter->record_attempt('test_action');
        }

        // Should have remaining attempts of 0 (at the limit)
        $this->assertSame(0, $this->limiter->get_remaining_attempts('test_action'));

        // Trigger lockout
        $this->limiter->is_rate_limited('test_action');

        // Should now be locked out with 0 remaining attempts
        $this->assertSame(0, $this->limiter->get_remaining_attempts('test_action'));

        // Lockout should be active
        $this->assertTrue($this->limiter->is_rate_limited('test_action'));
    }

    /**
     * Pin the test client IP, seed the attempts transient, and return its key.
     */
    private function seed_attempts(string $action, $state): string
    {
        $_SERVER['REMOTE_ADDR'] = '192.168.1.100';
        unset($_SERVER['HTTP_X_REAL_IP'], $_SERVER['HTTP_X_FORWARDED_FOR'], $_SERVER['HTTP_CLIENT_IP']);

        $ip_hash = hash('sha256', '192.168.1.100' . 'test-salt-value');
        $attempts_key = 'oidc_attempts_' . $action . '_' . substr($ip_hash, 0, 16);
        $this->transients[$attempts_key] = $state;
        return $attempts_key;
    }

    /**
     * Recording an attempt must preserve the original window start.
     */
    public function testRecordAttemptPreservesWindowStart(): void
    {
        $started = time() - 240; // 60s left in the default 5-minute window
        $attempts_key = $this->seed_attempts('test_action', ['count' => 2, 'started' => $started]);

        $this->limiter->record_attempt('test_action');

        $state = $this->transients[$attempts_key];
        $this->assertIsArray($state);
        $this->assertSame(3, $state['count']);
        $this->assertSame($started, $state['started']);
        $this->assertEqualsWithDelta(60, $this->transient_expirations[$attempts_key], 5);
        $this->assertFalse($this->limiter->is_rate_limited('test_action'));
    }

    /**
     * An expired window is treated as empty even if the transient lingers.
     */
    public function testExpiredWindowStartsNewWindow(): void
    {
        // At the cap, but the window expired: must not lock out.
        $attempts_key = $this->seed_attempts('test_action', ['count' => 10, 'started' => time() - 301]);

        $this->assertFalse($this->limiter->is_rate_limited('test_action'));
        $this->assertSame(10, $this->limiter->get_remaining_attempts('test_action'));

        $this->limiter->record_attempt('test_action');

        $state = $this->transients[$attempts_key];
        $this->assertIsArray($state);
        $this->assertSame(1, $state['count']);
        $this->assertEqualsWithDelta(time(), $state['started'], 5);
    }

    /**
     * A corrupt attempt value is treated as an empty window.
     */
    public function testCorruptAttemptStateStartsNewWindow(): void
    {
        $attempts_key = $this->seed_attempts('test_action', 'garbage');

        $this->assertFalse($this->limiter->is_rate_limited('test_action'));

        $this->limiter->record_attempt('test_action');

        $state = $this->transients[$attempts_key];
        $this->assertIsArray($state);
        $this->assertSame(1, $state['count']);
    }

    /**
     * Test non-positive counts are treated as an empty window.
     */
    public function testNonPositiveAttemptCountsStartNewWindow(): void
    {
        $bad_states = [0, -3, ['count' => 0, 'started' => time()], ['count' => 2, 'started' => 0], ['count' => 2, 'started' => time() + 60]];

        foreach ($bad_states as $bad) {
            $attempts_key = $this->seed_attempts('test_action', $bad);

            $this->assertFalse($this->limiter->is_rate_limited('test_action'));
            $this->assertSame(10, $this->limiter->get_remaining_attempts('test_action'));

            $this->limiter->record_attempt('test_action');

            $state = $this->transients[$attempts_key];
            $this->assertIsArray($state);
            $this->assertSame(1, $state['count']);
        }
    }
}

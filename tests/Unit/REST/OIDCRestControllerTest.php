<?php
/**
 * Tests for OIDC_REST_Controller class.
 *
 * @package SecureOIDCLogin\Tests\Unit\REST
 */

declare(strict_types=1);

namespace SecureOIDCLogin\Tests\Unit\REST;

use Brain\Monkey\Functions;
use OIDC_REST_Controller;
use SecureOIDCLogin\Tests\OIDCTestCase;
use WP_Error;
use WP_REST_Request;
use WP_REST_Response;

/**
 * Tests for the OIDC_REST_Controller class.
 *
 * @covers OIDC_REST_Controller
 */
class OIDCRestControllerTest extends OIDCTestCase
{
    private OIDC_REST_Controller $controller;

    /**
     * Set up test environment.
     */
    protected function setUp(): void
    {
        parent::setUp();

        // Stub WordPress REST API functions
        Functions\stubs([
            'register_rest_route' => true,
            'esc_url_raw' => static fn($url) => $url,
            'wp_safe_remote_get' => static fn($url, $args) => ['body' => '{}', 'response' => ['code' => 200]],
            'wp_remote_retrieve_response_code' => static fn($response) => $response['response']['code'] ?? 200,
            'wp_remote_retrieve_body' => static fn($response) => $response['body'] ?? '',
            'wp_remote_retrieve_header' => static fn($response, $header) => 'application/json',
            'wp_parse_url' => static function($url) {
                $parsed = parse_url($url);
                return $parsed !== false ? $parsed : null;
            },
            'wp_http_validate_url' => static function($url) {
                // Simulate WordPress validation - block private IPs
                $parsed = parse_url($url);
                if (!$parsed || empty($parsed['host'])) {
                    return false;
                }
                $host = $parsed['host'];
                // Block localhost and private IPs
                if (in_array($host, ['localhost', '127.0.0.1', '::1'])) {
                    return false;
                }
                if (preg_match('/^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)/', $host)) {
                    return false;
                }
                return $url;
            },
            'is_wp_error' => static fn($thing) => $thing instanceof WP_Error,
            'wp_get_current_user' => static function() {
                $user = new \stdClass();
                $user->ID = 0;
                $user->user_login = '';
                return $user;
            },
            // Rate limiter stubs
            'wp_salt' => 'test-salt-value',
            'get_transient' => false,
            'set_transient' => true,
            'delete_transient' => true,
            'sanitize_text_field' => static fn($str) => $str,
            'getenv' => false,
        ]);

        $this->controller = new OIDC_REST_Controller();
    }

    /**
     * Test discover_permissions_check allows users with manage_options capability.
     */
    public function testDiscoverPermissionsCheckAllowsAdministrators(): void
    {
        Functions\when('current_user_can')->justReturn(true);

        $request = $this->createMock(WP_REST_Request::class);
        $result = $this->controller->discover_permissions_check($request);

        $this->assertTrue($result);
    }

    /**
     * Test discover_permissions_check denies users without manage_options capability.
     */
    public function testDiscoverPermissionsCheckDeniesNonAdministrators(): void
    {
        Functions\when('current_user_can')->justReturn(false);

        $request = $this->createMock(WP_REST_Request::class);
        $result = $this->controller->discover_permissions_check($request);

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertSame('rest_forbidden', $result->get_error_code());
    }

    /**
     * Test validate_discovery_url_format accepts valid URLs.
     */
    public function testValidateDiscoveryUrlFormatAcceptsValidUrl(): void
    {
        $request = $this->createMock(WP_REST_Request::class);

        $result = $this->controller->validate_discovery_url_format(
            'https://idp.example.com',
            $request,
            'discovery_url'
        );

        $this->assertTrue($result);
    }

    /**
     * Test validate_discovery_url_format rejects empty values.
     */
    public function testValidateDiscoveryUrlFormatRejectsEmptyValue(): void
    {
        $request = $this->createMock(WP_REST_Request::class);

        $result = $this->controller->validate_discovery_url_format(
            '',
            $request,
            'discovery_url'
        );

        $this->assertFalse($result);
    }

    /**
     * Test validate_discovery_url_format rejects non-string values.
     */
    public function testValidateDiscoveryUrlFormatRejectsNonString(): void
    {
        $request = $this->createMock(WP_REST_Request::class);

        $result = $this->controller->validate_discovery_url_format(
            123,
            $request,
            'discovery_url'
        );

        $this->assertFalse($result);
    }

    /**
     * Test validate_discovery_url_format rejects invalid URL format.
     */
    public function testValidateDiscoveryUrlFormatRejectsInvalidUrl(): void
    {
        $request = $this->createMock(WP_REST_Request::class);

        $result = $this->controller->validate_discovery_url_format(
            'not-a-valid-url',
            $request,
            'discovery_url'
        );

        $this->assertFalse($result);
    }

    /**
     * Test discover returns success response with valid discovery document.
     */
    public function testDiscoverReturnsSuccessWithValidDocument(): void
    {
        $discoveryDoc = $this->getSampleOIDCConfig();

        // Mock wp_http_validate_url to accept the URL
        Functions\when('wp_http_validate_url')->justReturn('https://idp.example.com/.well-known/openid-configuration');

        Functions\when('wp_safe_remote_get')->justReturn([
            'body' => json_encode($discoveryDoc),
            'response' => ['code' => 200]
        ]);

        $request = $this->createMock(WP_REST_Request::class);
        $request->method('get_param')->willReturn('https://idp.example.com');

        $result = $this->controller->discover($request);

        $this->assertInstanceOf(WP_REST_Response::class, $result);
        $this->assertSame(200, $result->get_status());
        $this->assertSame($discoveryDoc, $result->get_data());
    }

    /**
     * Test discover appends well-known path when not present.
     */
    public function testDiscoverAppendsWellKnownPath(): void
    {
        $requestedUrl = null;

        // Mock wp_http_validate_url to accept the URL
        Functions\when('wp_http_validate_url')->alias(fn($url) => $url);

        Functions\when('wp_safe_remote_get')->alias(function($url, $args) use (&$requestedUrl) {
            $requestedUrl = $url;
            return [
                'body' => json_encode($this->getSampleOIDCConfig()),
                'response' => ['code' => 200]
            ];
        });

        $request = $this->createMock(WP_REST_Request::class);
        $request->method('get_param')->willReturn('https://idp.example.com');

        $this->controller->discover($request);

        $this->assertStringContainsString('.well-known/openid-configuration', $requestedUrl);
    }

    /**
     * Test discover does not duplicate well-known path.
     */
    public function testDiscoverDoesNotDuplicateWellKnownPath(): void
    {
        $requestedUrl = null;

        // Mock wp_http_validate_url to accept the URL
        Functions\when('wp_http_validate_url')->alias(fn($url) => $url);

        Functions\when('wp_safe_remote_get')->alias(function($url, $args) use (&$requestedUrl) {
            $requestedUrl = $url;
            return [
                'body' => json_encode($this->getSampleOIDCConfig()),
                'response' => ['code' => 200]
            ];
        });

        $request = $this->createMock(WP_REST_Request::class);
        $request->method('get_param')->willReturn('https://idp.example.com/.well-known/openid-configuration');

        $this->controller->discover($request);

        // Should only appear once
        $this->assertSame(1, substr_count($requestedUrl, '.well-known/openid-configuration'));
    }

    /**
     * Test discover returns error on HTTP request failure.
     */
    public function testDiscoverReturnsErrorOnHttpFailure(): void
    {
        // Mock wp_http_validate_url to accept the URL
        Functions\when('wp_http_validate_url')->alias(fn($url) => $url);

        Functions\when('wp_safe_remote_get')->justReturn(new WP_Error('http_error', 'Connection failed'));

        $request = $this->createMock(WP_REST_Request::class);
        $request->method('get_param')->willReturn('https://idp.example.com');

        $result = $this->controller->discover($request);

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertSame('discovery_request_failed', $result->get_error_code());
    }

    /**
     * Test discover returns error on non-200 status.
     */
    public function testDiscoverReturnsErrorOnNon200Status(): void
    {
        // Mock wp_http_validate_url to accept the URL
        Functions\when('wp_http_validate_url')->alias(fn($url) => $url);

        Functions\when('wp_safe_remote_get')->justReturn([
            'body' => '{"error": "not_found"}',
            'response' => ['code' => 404]
        ]);
        Functions\when('wp_remote_retrieve_response_code')->justReturn(404);

        $request = $this->createMock(WP_REST_Request::class);
        $request->method('get_param')->willReturn('https://idp.example.com');

        $result = $this->controller->discover($request);

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertSame('discovery_failed', $result->get_error_code());
    }

    /**
     * Test discover returns error on HTML response.
     */
    public function testDiscoverReturnsErrorOnHtmlResponse(): void
    {
        // Mock wp_http_validate_url to accept the URL
        Functions\when('wp_http_validate_url')->alias(fn($url) => $url);

        Functions\when('wp_safe_remote_get')->justReturn([
            'body' => '<html><body>Not Found</body></html>',
            'response' => ['code' => 200]
        ]);
        Functions\when('wp_remote_retrieve_header')->justReturn('text/html');

        $request = $this->createMock(WP_REST_Request::class);
        $request->method('get_param')->willReturn('https://idp.example.com');

        $result = $this->controller->discover($request);

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertSame('invalid_content_type', $result->get_error_code());
        $this->assertStringContainsString('HTML', $result->get_error_message());
    }

    /**
     * Test discover returns error on invalid JSON.
     */
    public function testDiscoverReturnsErrorOnInvalidJson(): void
    {
        // Mock wp_http_validate_url to accept the URL
        Functions\when('wp_http_validate_url')->alias(fn($url) => $url);

        Functions\when('wp_safe_remote_get')->justReturn([
            'body' => 'not valid json {[',
            'response' => ['code' => 200]
        ]);
        Functions\when('wp_remote_retrieve_header')->justReturn('application/json');

        $request = $this->createMock(WP_REST_Request::class);
        $request->method('get_param')->willReturn('https://idp.example.com');

        $result = $this->controller->discover($request);

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertSame('invalid_json', $result->get_error_code());
    }

    /**
     * Test validate_discovery_url_ssrf blocks HTTP URLs by default.
     */
    public function testValidateDiscoveryUrlSsrfBlocksHttpByDefault(): void
    {
        $reflection = new \ReflectionClass(OIDC_REST_Controller::class);
        $method = $reflection->getMethod('validate_discovery_url_ssrf');
        $method->setAccessible(true);

        $result = $method->invoke($this->controller, 'http://idp.example.com');

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertSame('https_required', $result->get_error_code());
    }

    /**
     * Test validate_discovery_url_ssrf allows HTTP when environment variable set.
     */
    public function testValidateDiscoveryUrlSsrfAllowsHttpWithEnvVar(): void
    {
        // Override getenv stub to return true for the allow insecure env var
        Functions\when('getenv')->alias(function ($var) {
            if ($var === 'SECURE_OIDC_ALLOW_INSECURE_DISCOVERY') {
                return 'true';
            }
            return false;
        });

        // Mock wp_http_validate_url to return the URL (valid)
        Functions\when('wp_http_validate_url')->justReturn('http://idp.example.com');

        $reflection = new \ReflectionClass(OIDC_REST_Controller::class);
        $method = $reflection->getMethod('validate_discovery_url_ssrf');
        $method->setAccessible(true);

        $result = $method->invoke($this->controller, 'http://idp.example.com');

        $this->assertTrue($result);
    }

    /**
     * Test validate_discovery_url_ssrf blocks localhost by default.
     */
    public function testValidateDiscoveryUrlSsrfBlocksLocalhostByDefault(): void
    {
        $reflection = new \ReflectionClass(OIDC_REST_Controller::class);
        $method = $reflection->getMethod('validate_discovery_url_ssrf');
        $method->setAccessible(true);

        $result = $method->invoke($this->controller, 'https://localhost:8080');

        $this->assertInstanceOf(WP_Error::class, $result);
        // localhost is explicitly blocked before wp_http_validate_url check
        $this->assertSame('localhost_blocked', $result->get_error_code());
    }

    /**
     * Test validate_discovery_url_ssrf blocks 127.0.0.1 by default.
     */
    public function testValidateDiscoveryUrlSsrfBlocksLoopbackIpByDefault(): void
    {
        // Mock wp_http_validate_url to return false for loopback IP
        Functions\when('wp_http_validate_url')->justReturn(false);

        $reflection = new \ReflectionClass(OIDC_REST_Controller::class);
        $method = $reflection->getMethod('validate_discovery_url_ssrf');
        $method->setAccessible(true);

        $result = $method->invoke($this->controller, 'https://127.0.0.1:8080');

        $this->assertInstanceOf(WP_Error::class, $result);
        // wp_http_validate_url blocks this
        $this->assertSame('url_validation_failed', $result->get_error_code());
    }

    /**
     * Test validate_discovery_url_ssrf blocks private IP addresses by default.
     */
    public function testValidateDiscoveryUrlSsrfBlocksPrivateIpByDefault(): void
    {
        // Mock wp_http_validate_url to return false for private IPs
        Functions\when('wp_http_validate_url')->justReturn(false);

        $reflection = new \ReflectionClass(OIDC_REST_Controller::class);
        $method = $reflection->getMethod('validate_discovery_url_ssrf');
        $method->setAccessible(true);

        // Test various private IP ranges
        $privateIps = [
            'https://192.168.1.1',
            'https://10.0.0.1',
            'https://172.16.0.1',
        ];

        foreach ($privateIps as $url) {
            $result = $method->invoke($this->controller, $url);
            $this->assertInstanceOf(WP_Error::class, $result, "Failed to block: $url");
            $this->assertSame('url_validation_failed', $result->get_error_code());
        }
    }

    /**
     * Test validate_discovery_url_ssrf allows valid URLs when wp_http_validate_url passes.
     */
    public function testValidateDiscoveryUrlSsrfAllowsValidUrls(): void
    {
        // Mock wp_http_validate_url to return the URL (valid)
        Functions\when('wp_http_validate_url')->justReturn('https://192.168.1.1');

        $reflection = new \ReflectionClass(OIDC_REST_Controller::class);
        $method = $reflection->getMethod('validate_discovery_url_ssrf');
        $method->setAccessible(true);

        $result = $method->invoke($this->controller, 'https://192.168.1.1');

        $this->assertTrue($result);
    }

    /**
     * Test validate_discovery_url_ssrf accepts valid public HTTPS URLs.
     */
    public function testValidateDiscoveryUrlSsrfAcceptsPublicHttpsUrl(): void
    {
        // Mock wp_http_validate_url to return the URL (valid)
        Functions\when('wp_http_validate_url')->justReturn('https://idp.example.com');

        $reflection = new \ReflectionClass(OIDC_REST_Controller::class);
        $method = $reflection->getMethod('validate_discovery_url_ssrf');
        $method->setAccessible(true);

        $result = $method->invoke($this->controller, 'https://idp.example.com');

        $this->assertTrue($result);
    }

    /**
     * Test validate_discovery_url_ssrf returns error for invalid URL format.
     */
    public function testValidateDiscoveryUrlSsrfRejectsInvalidUrlFormat(): void
    {
        $reflection = new \ReflectionClass(OIDC_REST_Controller::class);
        $method = $reflection->getMethod('validate_discovery_url_ssrf');
        $method->setAccessible(true);

        $result = $method->invoke($this->controller, 'not-a-url');

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertSame('invalid_url', $result->get_error_code());
    }

    /**
     * Test validate_discovery_url_ssrf returns error for URL without host.
     */
    public function testValidateDiscoveryUrlSsrfRejectsUrlWithoutHost(): void
    {
        Functions\when('wp_parse_url')->justReturn(['scheme' => 'https']);

        $reflection = new \ReflectionClass(OIDC_REST_Controller::class);
        $method = $reflection->getMethod('validate_discovery_url_ssrf');
        $method->setAccessible(true);

        $result = $method->invoke($this->controller, 'https://');

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertSame('invalid_url', $result->get_error_code());
    }

    /**
     * Test discover with SSRF blocked URL returns appropriate error.
     */
    public function testDiscoverWithSsrfBlockedUrlReturnsError(): void
    {
        $request = $this->createMock(WP_REST_Request::class);
        $request->method('get_param')->willReturn('http://localhost:8080');

        $result = $this->controller->discover($request);

        $this->assertInstanceOf(WP_Error::class, $result);
        // Should fail SSRF validation before making HTTP request
        $this->assertContains($result->get_error_code(), ['https_required', 'localhost_blocked']);
    }

    /**
     * Test discover returns 429 when rate limited.
     */
    public function testDiscoverReturns429WhenRateLimited(): void
    {
        // Create a storage array for transients that persists across calls
        $transients = [];

        // Override transient functions to actually track attempts
        Functions\when('get_transient')->alias(function ($key) use (&$transients) {
            return $transients[$key] ?? false;
        });

        Functions\when('set_transient')->alias(function ($key, $value, $expiration) use (&$transients) {
            $transients[$key] = $value;
            return true;
        });

        Functions\when('delete_transient')->alias(function ($key) use (&$transients) {
            unset($transients[$key]);
            return true;
        });

        // Mock valid URL validation
        Functions\when('wp_http_validate_url')->justReturn('https://idp.example.com/.well-known/openid-configuration');

        Functions\when('wp_safe_remote_get')->justReturn([
            'body' => json_encode($this->getSampleOIDCConfig()),
            'response' => ['code' => 200]
        ]);

        $request = $this->createMock(WP_REST_Request::class);
        $request->method('get_param')->willReturn('https://idp.example.com');

        // Make 10 requests to hit the rate limit
        for ($i = 0; $i < 10; $i++) {
            $controller = new OIDC_REST_Controller();
            $controller->discover($request);
        }

        // The 11th request should be rate limited
        $controller = new OIDC_REST_Controller();
        $result = $controller->discover($request);

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertSame('rate_limit_exceeded', $result->get_error_code());

        $errorData = $result->get_error_data();
        $this->assertSame(429, $errorData['status']);
    }

    /**
     * Test discover proceeds normally when not rate limited.
     */
    public function testDiscoverProceedsWhenNotRateLimited(): void
    {
        // Mock valid URL validation
        Functions\when('wp_http_validate_url')->justReturn('https://idp.example.com/.well-known/openid-configuration');

        Functions\when('wp_safe_remote_get')->justReturn([
            'body' => json_encode($this->getSampleOIDCConfig()),
            'response' => ['code' => 200]
        ]);

        $request = $this->createMock(WP_REST_Request::class);
        $request->method('get_param')->willReturn('https://idp.example.com');

        // First request should succeed
        $result = $this->controller->discover($request);

        $this->assertInstanceOf(WP_REST_Response::class, $result);
        $this->assertSame(200, $result->get_status());
    }
}

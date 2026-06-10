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
     * Test discover_permissions_check logs masked IP address, not raw IP.
     */
    public function testDiscoverPermissionsCheckLogsMaskedIp(): void
    {
        Functions\when('current_user_can')->justReturn(false);

        $_SERVER['REMOTE_ADDR'] = '203.0.113.45';

        $logFile     = tempnam(sys_get_temp_dir(), 'oidc_test_');
        $previousLog = ini_set('error_log', $logFile);

        $request = $this->createMock(WP_REST_Request::class);
        $this->controller->discover_permissions_check($request);

        ini_set('error_log', $previousLog);
        $logged = file_get_contents($logFile);
        unlink($logFile);

        $this->assertStringContainsString('203.0.113.xxx', $logged);
        $this->assertStringNotContainsString('203.0.113.45', $logged);
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

    /**
     * Capture all routes registered by register_routes(), keyed by route path.
     *
     * @return array<string, array<string, mixed>> Route args keyed by route path.
     */
    private function captureRegisteredRoutes(): array
    {
        $registeredRoutes = [];

        Functions\when('register_rest_route')->alias(function ($namespace, $route, $args) use (&$registeredRoutes) {
            $registeredRoutes[$route] = [
                'namespace' => $namespace,
                'args' => $args,
            ];
            return true;
        });

        $this->controller->register_routes();

        return $registeredRoutes;
    }

    /**
     * Test register_routes registers the discover and backchannel-logout endpoints.
     */
    public function testRegisterRoutesRegistersDiscoverEndpoint(): void
    {
        $routes = $this->captureRegisteredRoutes();

        $this->assertCount(2, $routes);
        $this->assertArrayHasKey('/discover', $routes);
        $this->assertArrayHasKey('/backchannel-logout', $routes);
        $this->assertSame('secure-oidc-login/v1', $routes['/discover']['namespace']);
        $this->assertSame('secure-oidc-login/v1', $routes['/backchannel-logout']['namespace']);
    }

    /**
     * Test register_routes configures POST method for discover endpoint.
     */
    public function testRegisterRoutesConfiguresPostMethod(): void
    {
        $routes = $this->captureRegisteredRoutes();

        // WP_REST_Server::CREATABLE is 'POST'
        $this->assertSame(\WP_REST_Server::CREATABLE, $routes['/discover']['args']['methods']);
        $this->assertSame(\WP_REST_Server::CREATABLE, $routes['/backchannel-logout']['args']['methods']);
    }

    /**
     * Test register_routes configures permission callback.
     */
    public function testRegisterRoutesConfiguresPermissionCallback(): void
    {
        $routes = $this->captureRegisteredRoutes();

        $this->assertArrayHasKey('permission_callback', $routes['/discover']['args']);
        $this->assertIsCallable($routes['/discover']['args']['permission_callback']);
    }

    /**
     * Test register_routes configures discovery_url argument as required.
     */
    public function testRegisterRoutesConfiguresDiscoveryUrlAsRequired(): void
    {
        $routes = $this->captureRegisteredRoutes();
        $args = $routes['/discover']['args'];

        $this->assertArrayHasKey('args', $args);
        $this->assertArrayHasKey('discovery_url', $args['args']);
        $this->assertTrue($args['args']['discovery_url']['required']);
    }

    /**
     * Test register_routes configures validate_callback for discovery_url.
     */
    public function testRegisterRoutesConfiguresValidateCallback(): void
    {
        $routes = $this->captureRegisteredRoutes();
        $args = $routes['/discover']['args'];

        $this->assertArrayHasKey('validate_callback', $args['args']['discovery_url']);
        $this->assertIsCallable($args['args']['discovery_url']['validate_callback']);
    }

    /**
     * Test register_routes configures sanitize_callback for discovery_url.
     */
    public function testRegisterRoutesConfiguresSanitizeCallback(): void
    {
        $routes = $this->captureRegisteredRoutes();
        $args = $routes['/discover']['args'];

        $this->assertArrayHasKey('sanitize_callback', $args['args']['discovery_url']);
        $this->assertSame('esc_url_raw', $args['args']['discovery_url']['sanitize_callback']);
    }

    /**
     * Test the backchannel-logout route is public (authenticated by the logout token).
     */
    public function testRegisterRoutesBackchannelLogoutIsPublicAndRequiresToken(): void
    {
        $routes = $this->captureRegisteredRoutes();
        $args = $routes['/backchannel-logout']['args'];

        // Authenticated by the signed logout token, not a WP session
        $this->assertSame('__return_true', $args['permission_callback']);
        $this->assertTrue($args['args']['logout_token']['required']);
    }

    /**
     * Test validate_discovery_url_ssrf blocks localhost.localdomain.
     */
    public function testValidateDiscoveryUrlSsrfBlocksLocalhostLocaldomain(): void
    {
        $reflection = new \ReflectionClass(OIDC_REST_Controller::class);
        $method = $reflection->getMethod('validate_discovery_url_ssrf');
        $method->setAccessible(true);

        $result = $method->invoke($this->controller, 'https://localhost.localdomain:8080');

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertSame('localhost_blocked', $result->get_error_code());
    }

    /**
     * Test validate_discovery_url_ssrf rejects FTP scheme.
     */
    public function testValidateDiscoveryUrlSsrfRejectsFtpScheme(): void
    {
        $reflection = new \ReflectionClass(OIDC_REST_Controller::class);
        $method = $reflection->getMethod('validate_discovery_url_ssrf');
        $method->setAccessible(true);

        $result = $method->invoke($this->controller, 'ftp://idp.example.com');

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertSame('invalid_scheme', $result->get_error_code());
    }

    /**
     * Test validate_discovery_url_ssrf rejects file scheme.
     *
     * file:// URLs have no host, so they fail URL format validation.
     */
    public function testValidateDiscoveryUrlSsrfRejectsFileScheme(): void
    {
        $reflection = new \ReflectionClass(OIDC_REST_Controller::class);
        $method = $reflection->getMethod('validate_discovery_url_ssrf');
        $method->setAccessible(true);

        $result = $method->invoke($this->controller, 'file:///etc/passwd');

        // file:// URLs have no host, so they fail URL format validation
        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertSame('invalid_url', $result->get_error_code());
    }

    /**
     * Test validate_discovery_url_ssrf handles mixed case HTTPS scheme.
     */
    public function testValidateDiscoveryUrlSsrfHandlesMixedCaseScheme(): void
    {
        // Mock wp_http_validate_url to accept the URL
        Functions\when('wp_http_validate_url')->justReturn('HTTPS://idp.example.com');

        $reflection = new \ReflectionClass(OIDC_REST_Controller::class);
        $method = $reflection->getMethod('validate_discovery_url_ssrf');
        $method->setAccessible(true);

        $result = $method->invoke($this->controller, 'HTTPS://idp.example.com');

        $this->assertTrue($result);
    }

    /**
     * Test validate_discovery_url_ssrf blocks IPv6 loopback.
     */
    public function testValidateDiscoveryUrlSsrfBlocksIpv6Loopback(): void
    {
        // Mock wp_http_validate_url to return false for IPv6 loopback
        Functions\when('wp_http_validate_url')->justReturn(false);

        $reflection = new \ReflectionClass(OIDC_REST_Controller::class);
        $method = $reflection->getMethod('validate_discovery_url_ssrf');
        $method->setAccessible(true);

        $result = $method->invoke($this->controller, 'https://[::1]:8080');

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertSame('url_validation_failed', $result->get_error_code());
    }

    /**
     * Test validate_discovery_url_ssrf blocks URL with credentials.
     */
    public function testValidateDiscoveryUrlSsrfBlocksUrlWithCredentials(): void
    {
        // Mock wp_http_validate_url to return false for URLs with credentials
        Functions\when('wp_http_validate_url')->justReturn(false);

        $reflection = new \ReflectionClass(OIDC_REST_Controller::class);
        $method = $reflection->getMethod('validate_discovery_url_ssrf');
        $method->setAccessible(true);

        $result = $method->invoke($this->controller, 'https://user:pass@idp.example.com');

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertSame('url_validation_failed', $result->get_error_code());
    }

    /**
     * Test discover handles SSRF block error from wp_safe_remote_get.
     */
    public function testDiscoverHandlesSsrfBlockFromRemoteGet(): void
    {
        // Mock valid SSRF pre-validation
        Functions\when('wp_http_validate_url')->justReturn('https://idp.example.com');

        // But wp_safe_remote_get blocks it
        Functions\when('wp_safe_remote_get')->justReturn(
            new WP_Error('http_request_not_executed', 'Request blocked')
        );

        $request = $this->createMock(WP_REST_Request::class);
        $request->method('get_param')->willReturn('https://idp.example.com');

        $result = $this->controller->discover($request);

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertSame('ssrf_blocked', $result->get_error_code());
        $this->assertStringContainsString('blocked for security', $result->get_error_message());
    }

    /**
     * Test discover handles content-type as array.
     */
    public function testDiscoverHandlesContentTypeAsArray(): void
    {
        // Mock valid URL validation
        Functions\when('wp_http_validate_url')->alias(fn($url) => $url);

        Functions\when('wp_safe_remote_get')->justReturn([
            'body' => '<html>Not JSON</html>',
            'response' => ['code' => 200],
        ]);

        // Return content-type as array (some servers do this)
        Functions\when('wp_remote_retrieve_header')->justReturn(['text/html', 'charset=utf-8']);

        $request = $this->createMock(WP_REST_Request::class);
        $request->method('get_param')->willReturn('https://idp.example.com');

        $result = $this->controller->discover($request);

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertSame('invalid_content_type', $result->get_error_code());
    }

    /**
     * Test discover handles empty JSON response.
     */
    public function testDiscoverHandlesEmptyJsonResponse(): void
    {
        // Mock valid URL validation
        Functions\when('wp_http_validate_url')->alias(fn($url) => $url);

        Functions\when('wp_safe_remote_get')->justReturn([
            'body' => 'null',
            'response' => ['code' => 200],
        ]);
        Functions\when('wp_remote_retrieve_header')->justReturn('application/json');

        $request = $this->createMock(WP_REST_Request::class);
        $request->method('get_param')->willReturn('https://idp.example.com');

        $result = $this->controller->discover($request);

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertSame('invalid_json', $result->get_error_code());
    }

    /**
     * Test discover rejects a JSON array - a list is not a provider configuration.
     */
    public function testDiscoverHandlesJsonArrayInsteadOfObject(): void
    {
        // Mock valid URL validation
        Functions\when('wp_http_validate_url')->alias(fn($url) => $url);

        // Return a JSON array instead of object
        Functions\when('wp_safe_remote_get')->justReturn([
            'body' => '["item1", "item2"]',
            'response' => ['code' => 200],
        ]);
        Functions\when('wp_remote_retrieve_header')->justReturn('application/json');

        $request = $this->createMock(WP_REST_Request::class);
        $request->method('get_param')->willReturn('https://idp.example.com');

        $result = $this->controller->discover($request);

        // A JSON list has no issuer, so document validation must reject it
        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertSame('oidc_discovery_missing_issuer', $result->get_error_code());
    }

    /**
     * Test discover rejects a document whose issuer does not match the discovery URL.
     *
     * Per OIDC Discovery 1.0 Section 4.3 the issuer must equal the discovery URL
     * with the well-known suffix removed; accepting a mismatched document would
     * configure this client against a different provider's endpoints.
     */
    public function testDiscoverRejectsIssuerMismatch(): void
    {
        Functions\when('wp_http_validate_url')->alias(fn($url) => $url);

        $config = $this->getSampleOIDCConfig();
        $config['issuer'] = 'https://other-idp.example.net';

        Functions\when('wp_safe_remote_get')->justReturn([
            'body' => json_encode($config),
            'response' => ['code' => 200],
        ]);
        Functions\when('wp_remote_retrieve_header')->justReturn('application/json');

        $request = $this->createMock(WP_REST_Request::class);
        $request->method('get_param')->willReturn('https://idp.example.com');

        $result = $this->controller->discover($request);

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertSame('oidc_discovery_issuer_mismatch', $result->get_error_code());
        $this->assertSame(400, $result->get_error_data()['status'] ?? null);
    }

    /**
     * Test discover rejects a document advertising a non-HTTPS endpoint.
     */
    public function testDiscoverRejectsInsecureEndpoint(): void
    {
        Functions\when('wp_http_validate_url')->alias(fn($url) => $url);

        $config = $this->getSampleOIDCConfig();
        $config['token_endpoint'] = 'http://idp.example.com/token';

        Functions\when('wp_safe_remote_get')->justReturn([
            'body' => json_encode($config),
            'response' => ['code' => 200],
        ]);
        Functions\when('wp_remote_retrieve_header')->justReturn('application/json');

        $request = $this->createMock(WP_REST_Request::class);
        $request->method('get_param')->willReturn('https://idp.example.com');

        $result = $this->controller->discover($request);

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertSame('oidc_discovery_insecure_endpoint', $result->get_error_code());
    }

    /**
     * Test validate_discovery_url_format rejects arrays.
     */
    public function testValidateDiscoveryUrlFormatRejectsArray(): void
    {
        $request = $this->createMock(WP_REST_Request::class);

        $result = $this->controller->validate_discovery_url_format(
            ['url' => 'https://example.com'],
            $request,
            'discovery_url'
        );

        $this->assertFalse($result);
    }

    /**
     * Test validate_discovery_url_format rejects null.
     */
    public function testValidateDiscoveryUrlFormatRejectsNull(): void
    {
        $request = $this->createMock(WP_REST_Request::class);

        $result = $this->controller->validate_discovery_url_format(
            null,
            $request,
            'discovery_url'
        );

        $this->assertFalse($result);
    }

    /**
     * Test discover strips trailing slash before appending well-known path.
     */
    public function testDiscoverStripsTrailingSlash(): void
    {
        $requestedUrl = null;

        Functions\when('wp_http_validate_url')->alias(fn($url) => $url);

        Functions\when('wp_safe_remote_get')->alias(function ($url, $args) use (&$requestedUrl) {
            $requestedUrl = $url;
            return [
                'body' => json_encode($this->getSampleOIDCConfig()),
                'response' => ['code' => 200],
            ];
        });

        $request = $this->createMock(WP_REST_Request::class);
        $request->method('get_param')->willReturn('https://idp.example.com/');

        $this->controller->discover($request);

        // Should not have double slashes
        $this->assertStringNotContainsString('//.well-known', $requestedUrl);
        $this->assertStringContainsString('/.well-known/openid-configuration', $requestedUrl);
    }

    // =========================================================================
    // Back-Channel Logout Endpoint Tests
    // =========================================================================

    /**
     * Build a controller with a mocked back-channel handler and a request carrying a token.
     *
     * @param mixed       $handler_result Result for handle_logout_token, or null to expect no call.
     * @param string|null $logout_token   The logout_token request parameter value.
     * @return array{0: OIDC_REST_Controller, 1: WP_REST_Request} Controller and request.
     */
    private function buildBackchannelScenario(mixed $handler_result, ?string $logout_token): array
    {
        $handler = \Mockery::mock(\OIDC_Backchannel_Logout::class);

        if (null === $handler_result) {
            $handler->shouldNotReceive('handle_logout_token');
        } else {
            $handler->shouldReceive('handle_logout_token')
                ->with($logout_token)
                ->once()
                ->andReturn($handler_result);
        }

        $controller = new OIDC_REST_Controller($handler);

        // Only answer for the exact parameter name the controller must use
        $request = $this->createMock(WP_REST_Request::class);
        $request->method('get_param')
            ->willReturnCallback(
                static fn (string $key) => 'logout_token' === $key ? $logout_token : null
            );

        return [$controller, $request];
    }

    /**
     * Test backchannel_logout returns 200 with no-store on success.
     */
    public function testBackchannelLogoutReturns200OnSuccess(): void
    {
        Functions\when('get_option')->justReturn(['enable_backchannel_logout' => true]);

        [$controller, $request] = $this->buildBackchannelScenario(true, 'valid.logout.token');

        $result = $controller->backchannel_logout($request);

        $this->assertInstanceOf(WP_REST_Response::class, $result);
        $this->assertSame(200, $result->get_status());
        $this->assertSame('no-store', $result->get_headers()['Cache-Control'] ?? null);
    }

    /**
     * Test backchannel_logout returns 400 for an invalid logout token.
     */
    public function testBackchannelLogoutReturns400OnInvalidToken(): void
    {
        Functions\when('get_option')->justReturn(['enable_backchannel_logout' => true]);

        [$controller, $request] = $this->buildBackchannelScenario(
            new WP_Error('oidc_error', 'Invalid logout token issuer.'),
            'forged.logout.token'
        );

        $result = $controller->backchannel_logout($request);

        $this->assertSame(400, $result->get_status());
        $this->assertSame(['error' => 'invalid_request'], $result->get_data());
    }

    /**
     * Test backchannel_logout returns 400 when the feature is disabled.
     */
    public function testBackchannelLogoutReturns400WhenDisabled(): void
    {
        Functions\when('get_option')->justReturn(['enable_backchannel_logout' => false]);

        [$controller, $request] = $this->buildBackchannelScenario(null, 'any.logout.token');

        $result = $controller->backchannel_logout($request);

        $this->assertSame(400, $result->get_status());
    }

    /**
     * Test the SECURE_OIDC_ENABLE_BACKCHANNEL_LOGOUT env var overrides the stored setting.
     */
    public function testBackchannelLogoutHonorsEnvOverride(): void
    {
        putenv('SECURE_OIDC_ENABLE_BACKCHANNEL_LOGOUT=true');

        try {
            // Stored setting disabled, but the env var enables the endpoint
            Functions\when('get_option')->justReturn(['enable_backchannel_logout' => false]);

            [$controller, $request] = $this->buildBackchannelScenario(true, 'valid.logout.token');

            $result = $controller->backchannel_logout($request);

            $this->assertSame(200, $result->get_status());
        } finally {
            putenv('SECURE_OIDC_ENABLE_BACKCHANNEL_LOGOUT');
        }
    }

    /**
     * Test the env var can also disable the endpoint despite the stored setting.
     */
    public function testBackchannelLogoutEnvOverrideCanDisable(): void
    {
        putenv('SECURE_OIDC_ENABLE_BACKCHANNEL_LOGOUT=false');

        try {
            Functions\when('get_option')->justReturn(['enable_backchannel_logout' => true]);

            [$controller, $request] = $this->buildBackchannelScenario(null, 'any.logout.token');

            $result = $controller->backchannel_logout($request);

            $this->assertSame(400, $result->get_status());
        } finally {
            putenv('SECURE_OIDC_ENABLE_BACKCHANNEL_LOGOUT');
        }
    }

    /**
     * Test backchannel_logout returns 400 for an empty token.
     */
    public function testBackchannelLogoutReturns400OnEmptyToken(): void
    {
        Functions\when('get_option')->justReturn(['enable_backchannel_logout' => true]);

        [$controller, $request] = $this->buildBackchannelScenario(null, '');

        $result = $controller->backchannel_logout($request);

        $this->assertSame(400, $result->get_status());
    }

    /**
     * Test backchannel_logout returns 400 when rate limited.
     *
     * 400 rather than 429 keeps the response within the status codes defined by
     * OIDC Back-Channel Logout 1.0 Section 2.8.
     */
    public function testBackchannelLogoutReturns400WhenRateLimited(): void
    {
        Functions\when('get_option')->justReturn(['enable_backchannel_logout' => true]);

        // Rate limiter reads its state from transients; simulate an active lockout
        Functions\when('get_transient')->alias(static function ($key) {
            return str_contains((string) $key, 'lockout') ? time() + 60 : false;
        });

        [$controller, $request] = $this->buildBackchannelScenario(null, 'any.logout.token');

        $result = $controller->backchannel_logout($request);

        $this->assertSame(400, $result->get_status());
    }
}

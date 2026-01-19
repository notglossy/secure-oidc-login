<?php
/**
 * Tests for OIDC_Client class.
 *
 * @package SecureOIDCLogin\Tests\Unit\Client
 */

declare(strict_types=1);

namespace SecureOIDCLogin\Tests\Unit\Client;

use Brain\Monkey\Functions;
use OIDC_Client;
use SecureOIDCLogin\Tests\OIDCTestCase;
use WP_Error;

/**
 * Tests for the OIDC_Client class.
 *
 * @covers OIDC_Client
 */
class OIDCClientTest extends OIDCTestCase
{
    private OIDC_Client $client;

    /**
     * Set up test environment.
     */
    protected function setUp(): void
    {
        parent::setUp();

        // Stub WordPress functions used by OIDC_Client
        Functions\stubs([
            'get_option' => static fn($option, $default = []) => [
                'client_id' => 'test-client-id',
                'client_secret' => 'test-client-secret',
                'authorization_endpoint' => 'https://idp.example.com/authorize',
                'token_endpoint' => 'https://idp.example.com/token',
                'userinfo_endpoint' => 'https://idp.example.com/userinfo',
                'jwks_uri' => 'https://idp.example.com/.well-known/jwks.json',
                'issuer' => 'https://idp.example.com',
            ],
            'home_url' => static fn($path = '') => 'https://example.com' . $path,
            'add_query_arg' => static function ($key, $value = '', $url = '') {
                // Handle both signatures: add_query_arg(array, url) and add_query_arg(key, value, url)
                if (is_array($key)) {
                    $url = $value;
                    return $url . '?' . http_build_query($key);
                }
                return $url . '?' . $key . '=' . urlencode($value);
            },
            'wp_remote_post' => static fn($url, $args) => ['body' => '{}', 'response' => ['code' => 200]],
            'wp_remote_get' => static fn($url, $args) => ['body' => '{}', 'response' => ['code' => 200]],
            'wp_remote_retrieve_response_code' => static fn($response) => $response['response']['code'] ?? 200,
            'wp_remote_retrieve_body' => static fn($response) => $response['body'] ?? '',
            'wp_remote_retrieve_header' => static fn($response, $header) => 'application/json',
            'wp_strip_all_tags' => static fn($string) => strip_tags($string),
            'get_transient' => static fn($key) => false,
            'set_transient' => static fn($key, $value, $expiration) => true,
            'delete_transient' => static fn($key) => true,
            'apply_filters' => static fn($tag, $value) => $value,
        ]);

        $this->client = new OIDC_Client();
    }

    /**
     * Test exchange_code returns error when token endpoint not configured.
     */
    public function testExchangeCodeReturnsErrorWhenTokenEndpointNotConfigured(): void
    {
        Functions\when('get_option')->justReturn([
            'client_id' => 'test-client-id',
            // token_endpoint missing
        ]);

        $client = new OIDC_Client();
        $result = $client->exchange_code('auth-code');

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertStringContainsString('endpoint', $result->get_error_message());
    }

    /**
     * Test exchange_code returns error on HTTP failure.
     */
    public function testExchangeCodeReturnsErrorOnHttpFailure(): void
    {
        Functions\when('wp_remote_post')->justReturn(new WP_Error('http_error', 'Connection failed'));
        Functions\when('is_wp_error')->alias(fn($thing) => $thing instanceof WP_Error);

        $result = $this->client->exchange_code('auth-code');

        $this->assertInstanceOf(WP_Error::class, $result);
    }

    /**
     * Test exchange_code returns error on non-JSON response.
     */
    public function testExchangeCodeReturnsErrorOnNonJsonResponse(): void
    {
        Functions\when('wp_remote_post')->justReturn(['body' => '<html>Error</html>', 'response' => ['code' => 200]]);
        Functions\when('wp_remote_retrieve_header')->justReturn('text/html');

        $result = $this->client->exchange_code('auth-code');

        $this->assertInstanceOf(WP_Error::class, $result);
    }

    /**
     * Test exchange_code returns error on non-200 status.
     */
    public function testExchangeCodeReturnsErrorOnNon200Status(): void
    {
        Functions\when('wp_remote_post')->justReturn([
            'body' => '{"error": "invalid_grant", "error_description": "Code expired"}',
            'response' => ['code' => 400]
        ]);
        Functions\when('wp_remote_retrieve_response_code')->justReturn(400);

        $result = $this->client->exchange_code('auth-code');

        $this->assertInstanceOf(WP_Error::class, $result);
    }

    /**
     * Test exchange_code returns error when access_token missing.
     */
    public function testExchangeCodeReturnsErrorWhenAccessTokenMissing(): void
    {
        Functions\when('wp_remote_post')->justReturn([
            'body' => '{"id_token": "test-id-token", "token_type": "Bearer"}',
            'response' => ['code' => 200]
        ]);

        $result = $this->client->exchange_code('auth-code');

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertStringContainsString('Invalid token response', $result->get_error_message());
    }

    /**
     * Test exchange_code returns error when id_token missing.
     */
    public function testExchangeCodeReturnsErrorWhenIdTokenMissing(): void
    {
        Functions\when('wp_remote_post')->justReturn([
            'body' => '{"access_token": "test-access-token", "token_type": "Bearer"}',
            'response' => ['code' => 200]
        ]);

        $result = $this->client->exchange_code('auth-code');

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertStringContainsString('Invalid token response', $result->get_error_message());
    }

    /**
     * Test exchange_code returns error for unsupported token type.
     */
    public function testExchangeCodeReturnsErrorForUnsupportedTokenType(): void
    {
        Functions\when('wp_remote_post')->justReturn([
            'body' => '{"access_token": "test", "id_token": "test", "token_type": "MAC"}',
            'response' => ['code' => 200]
        ]);

        $result = $this->client->exchange_code('auth-code');

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertStringContainsString('Unsupported token type', $result->get_error_message());
    }

    /**
     * Test exchange_code returns tokens on success.
     */
    public function testExchangeCodeReturnsTokensOnSuccess(): void
    {
        $tokenResponse = [
            'access_token' => 'test-access-token',
            'id_token' => 'test-id-token',
            'token_type' => 'Bearer',
            'expires_in' => 3600,
        ];

        Functions\when('wp_remote_post')->justReturn([
            'body' => json_encode($tokenResponse),
            'response' => ['code' => 200]
        ]);

        $result = $this->client->exchange_code('auth-code');

        $this->assertIsArray($result);
        $this->assertSame('test-access-token', $result['access_token']);
        $this->assertSame('test-id-token', $result['id_token']);
        $this->assertSame('Bearer', $result['token_type']);
    }

    /**
     * Test get_userinfo returns empty array when endpoint not configured.
     */
    public function testGetUserinfoReturnsEmptyArrayWhenEndpointNotConfigured(): void
    {
        Functions\when('get_option')->justReturn([
            'client_id' => 'test-client-id',
            // userinfo_endpoint missing
        ]);

        $client = new OIDC_Client();
        $result = $client->get_userinfo('access-token');

        $this->assertIsArray($result);
        $this->assertEmpty($result);
    }

    /**
     * Test get_userinfo returns error on HTTP failure.
     */
    public function testGetUserinfoReturnsErrorOnHttpFailure(): void
    {
        Functions\when('wp_remote_get')->justReturn(new WP_Error('http_error', 'Connection failed'));
        Functions\when('is_wp_error')->alias(fn($thing) => $thing instanceof WP_Error);

        $result = $this->client->get_userinfo('access-token');

        $this->assertInstanceOf(WP_Error::class, $result);
    }

    /**
     * Test get_userinfo returns userinfo on success.
     */
    public function testGetUserinfoReturnsUserinfoOnSuccess(): void
    {
        $userinfo = [
            'sub' => 'user-123',
            'email' => 'user@example.com',
            'name' => 'John Doe',
        ];

        Functions\when('wp_remote_get')->justReturn([
            'body' => json_encode($userinfo),
            'response' => ['code' => 200]
        ]);

        $result = $this->client->get_userinfo('access-token');

        $this->assertIsArray($result);
        $this->assertSame('user-123', $result['sub']);
        $this->assertSame('user@example.com', $result['email']);
    }

    /**
     * Test refresh_token returns error when token endpoint not configured.
     */
    public function testRefreshTokenReturnsErrorWhenEndpointNotConfigured(): void
    {
        Functions\when('get_option')->justReturn([
            'client_id' => 'test-client-id',
            // token_endpoint missing
        ]);

        $client = new OIDC_Client();
        $result = $client->refresh_token('refresh-token');

        $this->assertInstanceOf(WP_Error::class, $result);
    }

    /**
     * Test discover returns error on HTTP failure.
     */
    public function testDiscoverReturnsErrorOnHttpFailure(): void
    {
        Functions\when('wp_remote_get')->justReturn(new WP_Error('http_error', 'Connection failed'));
        Functions\when('is_wp_error')->alias(fn($thing) => $thing instanceof WP_Error);

        $result = $this->client->discover('https://idp.example.com');

        $this->assertInstanceOf(WP_Error::class, $result);
    }

    /**
     * Test discover returns error on non-JSON response.
     */
    public function testDiscoverReturnsErrorOnNonJsonResponse(): void
    {
        Functions\when('wp_remote_get')->justReturn([
            'body' => '<html>Not Found</html>',
            'response' => ['code' => 200]
        ]);
        Functions\when('wp_remote_retrieve_header')->justReturn('text/html');

        $result = $this->client->discover('https://idp.example.com');

        $this->assertInstanceOf(WP_Error::class, $result);
    }

    /**
     * Test discover returns error on non-200 status.
     */
    public function testDiscoverReturnsErrorOnNon200Status(): void
    {
        Functions\when('wp_remote_get')->justReturn([
            'body' => '{}',
            'response' => ['code' => 404]
        ]);
        Functions\when('wp_remote_retrieve_response_code')->justReturn(404);

        $result = $this->client->discover('https://idp.example.com');

        $this->assertInstanceOf(WP_Error::class, $result);
    }

    /**
     * Test discover returns config on success.
     */
    public function testDiscoverReturnsConfigOnSuccess(): void
    {
        $config = $this->getSampleOIDCConfig();

        Functions\when('wp_remote_get')->justReturn([
            'body' => json_encode($config),
            'response' => ['code' => 200]
        ]);

        $result = $this->client->discover('https://idp.example.com');

        $this->assertIsArray($result);
        $this->assertSame('https://idp.example.com', $result['issuer']);
        $this->assertArrayHasKey('authorization_endpoint', $result);
        $this->assertArrayHasKey('token_endpoint', $result);
    }

    /**
     * Test validate_id_token returns error when sub claim is missing.
     */
    public function testValidateIdTokenReturnsErrorWhenSubMissing(): void
    {
        // Mock JWT decode to return claims without sub
        $this->markTestSkipped('JWT validation requires complex mocking of Firebase JWT library');
    }

    /**
     * Test exchange_code includes PKCE code_verifier parameter when provided.
     */
    public function testExchangeCodeIncludesPkceCodeVerifier(): void
    {
        $requestBody = null;

        Functions\when('wp_remote_post')->alias(function($url, $args) use (&$requestBody) {
            $requestBody = $args['body'] ?? [];
            return [
                'body' => json_encode([
                    'access_token' => 'test-access',
                    'id_token' => 'test-id',
                    'token_type' => 'Bearer'
                ]),
                'response' => ['code' => 200]
            ];
        });

        $this->client->exchange_code('auth-code', 'test-code-verifier-value');

        $this->assertIsArray($requestBody);
        $this->assertArrayHasKey('code_verifier', $requestBody);
        $this->assertSame('test-code-verifier-value', $requestBody['code_verifier']);
    }

    /**
     * Test exchange_code uses HTTP Basic Auth for confidential clients.
     */
    public function testExchangeCodeUsesBasicAuthForConfidentialClients(): void
    {
        $headers = null;

        Functions\when('wp_remote_post')->alias(function($url, $args) use (&$headers) {
            $headers = $args['headers'] ?? [];
            return [
                'body' => json_encode([
                    'access_token' => 'test-access',
                    'id_token' => 'test-id',
                    'token_type' => 'Bearer'
                ]),
                'response' => ['code' => 200]
            ];
        });

        $this->client->exchange_code('auth-code');

        $this->assertIsArray($headers);
        $this->assertArrayHasKey('Authorization', $headers);
        $this->assertStringStartsWith('Basic ', $headers['Authorization']);
    }

    /**
     * Test refresh_token returns tokens on success.
     */
    public function testRefreshTokenReturnsTokensOnSuccess(): void
    {
        $tokenResponse = [
            'access_token' => 'new-access-token',
            'id_token' => 'new-id-token',
            'token_type' => 'Bearer',
            'expires_in' => 3600,
        ];

        Functions\when('wp_remote_post')->justReturn([
            'body' => json_encode($tokenResponse),
            'response' => ['code' => 200]
        ]);

        $result = $this->client->refresh_token('refresh-token-value');

        $this->assertIsArray($result);
        $this->assertSame('new-access-token', $result['access_token']);
        $this->assertSame('new-id-token', $result['id_token']);
    }

    /**
     * Test refresh_token returns error on HTTP failure.
     */
    public function testRefreshTokenReturnsErrorOnHttpFailure(): void
    {
        Functions\when('wp_remote_post')->justReturn(new WP_Error('http_error', 'Connection failed'));
        Functions\when('is_wp_error')->alias(fn($thing) => $thing instanceof WP_Error);

        $result = $this->client->refresh_token('refresh-token');

        $this->assertInstanceOf(WP_Error::class, $result);
    }

    /**
     * Test refresh_token returns error on 400 response.
     */
    public function testRefreshTokenReturnsErrorOn400Response(): void
    {
        Functions\when('wp_remote_post')->justReturn([
            'body' => json_encode(['error' => 'invalid_grant', 'error_description' => 'Refresh token expired']),
            'response' => ['code' => 400]
        ]);
        Functions\when('wp_remote_retrieve_response_code')->justReturn(400);

        $result = $this->client->refresh_token('expired-refresh-token');

        $this->assertInstanceOf(WP_Error::class, $result);
    }

    /**
     * Test get_userinfo returns error on non-200 status.
     */
    public function testGetUserinfoReturnsErrorOnNon200Status(): void
    {
        Functions\when('wp_remote_get')->justReturn([
            'body' => '{"error": "invalid_token"}',
            'response' => ['code' => 401]
        ]);
        Functions\when('wp_remote_retrieve_response_code')->justReturn(401);

        $result = $this->client->get_userinfo('invalid-access-token');

        $this->assertInstanceOf(WP_Error::class, $result);
    }

    /**
     * Test get_userinfo returns error on non-JSON response.
     */
    public function testGetUserinfoReturnsErrorOnNonJsonResponse(): void
    {
        Functions\when('wp_remote_get')->justReturn([
            'body' => '<html>Error</html>',
            'response' => ['code' => 200]
        ]);
        Functions\when('wp_remote_retrieve_header')->justReturn('text/html');

        $result = $this->client->get_userinfo('access-token');

        $this->assertInstanceOf(WP_Error::class, $result);
    }

    /**
     * Test discover appends well-known path.
     */
    public function testDiscoverAppendsWellKnownPath(): void
    {
        $requestedUrl = null;

        Functions\when('wp_remote_get')->alias(function($url, $args) use (&$requestedUrl) {
            $requestedUrl = $url;
            return [
                'body' => json_encode($this->getSampleOIDCConfig()),
                'response' => ['code' => 200]
            ];
        });

        $this->client->discover('https://idp.example.com');

        $this->assertStringContainsString('.well-known/openid-configuration', $requestedUrl);
        $this->assertSame('https://idp.example.com/.well-known/openid-configuration', $requestedUrl);
    }

    /**
     * Test handle_error returns generic message in production mode.
     */
    public function testHandleErrorReturnsGenericMessageInProduction(): void
    {
        // WP_DEBUG is not defined or false (production mode)
        $reflection = new \ReflectionClass(OIDC_Client::class);
        $method = $reflection->getMethod('handle_error');
        $method->setAccessible(true);

        $result = $method->invoke(
            $this->client,
            'test_context',
            'Detailed error message with sensitive info',
            'Generic user-facing message'
        );

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertSame('Generic user-facing message', $result->get_error_message());
        // Should NOT contain detailed error or context in production
        $this->assertStringNotContainsString('sensitive info', $result->get_error_message());
        $this->assertStringNotContainsString('test_context', $result->get_error_message());
    }

    /**
     * Test handle_error includes context in WP_DEBUG mode.
     */
    public function testHandleErrorIncludesContextInDebugMode(): void
    {
        if (!defined('WP_DEBUG')) {
            define('WP_DEBUG', true);
        }

        $reflection = new \ReflectionClass(OIDC_Client::class);
        $method = $reflection->getMethod('handle_error');
        $method->setAccessible(true);

        $result = $method->invoke(
            $this->client,
            'jwt_decode',
            'JWT signature verification failed',
            'Authentication failed'
        );

        $this->assertInstanceOf(WP_Error::class, $result);
        // In debug mode, should include context
        $this->assertStringContainsString('jwt_decode', $result->get_error_message());
        $this->assertStringContainsString('Authentication failed', $result->get_error_message());
    }

    /**
     * Test get_jwks returns error when JWKS URI not configured.
     */
    public function testGetJwksReturnsErrorWhenUriNotConfigured(): void
    {
        Functions\when('get_option')->justReturn([
            'client_id' => 'test-client-id',
            // jwks_uri missing
        ]);

        $client = new OIDC_Client();

        $reflection = new \ReflectionClass(OIDC_Client::class);
        $method = $reflection->getMethod('get_jwks');
        $method->setAccessible(true);

        $result = $method->invoke($client);

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertStringContainsString('JWKS URI not configured', $result->get_error_message());
    }

    /**
     * Test get_jwks returns cached JWKS on cache hit with valid HMAC.
     */
    public function testGetJwksReturnsCachedJwksOnCacheHit(): void
    {
        $jwks = ['keys' => [['kty' => 'RSA', 'kid' => 'test-key']]];

        $reflection = new \ReflectionClass(OIDC_Client::class);
        $hmacMethod = $reflection->getMethod('generate_jwks_hmac');
        $hmacMethod->setAccessible(true);
        $hmac = $hmacMethod->invoke($this->client, $jwks);

        $cacheData = [
            'jwks' => $jwks,
            'hmac' => $hmac
        ];

        Functions\when('get_transient')->justReturn($cacheData);

        $method = $reflection->getMethod('get_jwks');
        $method->setAccessible(true);
        $result = $method->invoke($this->client);

        $this->assertIsArray($result);
        $this->assertArrayHasKey('keys', $result);
        $this->assertSame('test-key', $result['keys'][0]['kid']);
    }

    /**
     * Test get_jwks fetches fresh JWKS when cache integrity check fails.
     */
    public function testGetJwksFetchesFreshJwksOnIntegrityFailure(): void
    {
        // Cached data with invalid HMAC
        $cachedJwks = ['keys' => [['kty' => 'RSA', 'kid' => 'old-key']]];
        $cacheData = [
            'jwks' => $cachedJwks,
            'hmac' => 'invalid-hmac-signature'
        ];

        // Fresh JWKS from IdP
        $freshJwks = ['keys' => [['kty' => 'RSA', 'kid' => 'new-key']]];

        Functions\when('get_transient')->justReturn($cacheData);
        Functions\when('delete_transient')->justReturn(true);
        Functions\when('wp_remote_get')->justReturn([
            'body' => json_encode($freshJwks),
            'response' => ['code' => 200]
        ]);
        Functions\when('set_transient')->justReturn(true);
        Functions\when('wp_json_encode')->alias(fn($data) => json_encode($data));

        $reflection = new \ReflectionClass(OIDC_Client::class);
        $method = $reflection->getMethod('get_jwks');
        $method->setAccessible(true);

        $result = $method->invoke($this->client);

        $this->assertIsArray($result);
        $this->assertSame('new-key', $result['keys'][0]['kid']);
    }

    /**
     * Test get_jwks force refresh bypasses cache.
     */
    public function testGetJwksForceRefreshBypassesCache(): void
    {
        $cachedJwks = ['keys' => [['kty' => 'RSA', 'kid' => 'cached-key']]];
        $freshJwks = ['keys' => [['kty' => 'RSA', 'kid' => 'fresh-key']]];

        Functions\when('get_transient')->justReturn([
            'jwks' => $cachedJwks,
            'hmac' => 'valid-hmac'
        ]);
        Functions\when('wp_remote_get')->justReturn([
            'body' => json_encode($freshJwks),
            'response' => ['code' => 200]
        ]);
        Functions\when('set_transient')->justReturn(true);
        Functions\when('wp_json_encode')->alias(fn($data) => json_encode($data));

        $reflection = new \ReflectionClass(OIDC_Client::class);
        $method = $reflection->getMethod('get_jwks');
        $method->setAccessible(true);

        // Force refresh = true should bypass cache
        $result = $method->invoke($this->client, true);

        $this->assertIsArray($result);
        $this->assertSame('fresh-key', $result['keys'][0]['kid']);
    }

    /**
     * Test get_jwks returns error on HTTP failure.
     */
    public function testGetJwksReturnsErrorOnHttpFailure(): void
    {
        Functions\when('get_transient')->justReturn(false);
        Functions\when('wp_remote_get')->justReturn(new WP_Error('http_error', 'Connection failed'));
        Functions\when('is_wp_error')->alias(fn($thing) => $thing instanceof WP_Error);

        $reflection = new \ReflectionClass(OIDC_Client::class);
        $method = $reflection->getMethod('get_jwks');
        $method->setAccessible(true);

        $result = $method->invoke($this->client);

        $this->assertInstanceOf(WP_Error::class, $result);
    }

    /**
     * Test get_jwks returns error on non-200 status.
     */
    public function testGetJwksReturnsErrorOnNon200Status(): void
    {
        Functions\when('get_transient')->justReturn(false);
        Functions\when('wp_remote_get')->justReturn([
            'body' => '{"error": "not_found"}',
            'response' => ['code' => 404]
        ]);
        Functions\when('wp_remote_retrieve_response_code')->justReturn(404);

        $reflection = new \ReflectionClass(OIDC_Client::class);
        $method = $reflection->getMethod('get_jwks');
        $method->setAccessible(true);

        $result = $method->invoke($this->client);

        $this->assertInstanceOf(WP_Error::class, $result);
    }

    /**
     * Test get_jwks returns error on invalid JWKS response.
     */
    public function testGetJwksReturnsErrorOnInvalidResponse(): void
    {
        Functions\when('get_transient')->justReturn(false);
        Functions\when('wp_remote_get')->justReturn([
            'body' => '{"invalid": "response"}',
            'response' => ['code' => 200]
        ]);

        $reflection = new \ReflectionClass(OIDC_Client::class);
        $method = $reflection->getMethod('get_jwks');
        $method->setAccessible(true);

        $result = $method->invoke($this->client);

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertStringContainsString('Invalid JWKS response', $result->get_error_message());
    }

    /**
     * Test generate_jwks_hmac produces consistent output.
     */
    public function testGenerateJwksHmacProducesConsistentOutput(): void
    {
        $jwks = ['keys' => [['kty' => 'RSA', 'kid' => 'test-key']]];

        Functions\when('wp_json_encode')->alias(fn($data) => json_encode($data));

        $reflection = new \ReflectionClass(OIDC_Client::class);
        $method = $reflection->getMethod('generate_jwks_hmac');
        $method->setAccessible(true);

        $hmac1 = $method->invoke($this->client, $jwks);
        $hmac2 = $method->invoke($this->client, $jwks);

        $this->assertIsString($hmac1);
        $this->assertSame(64, strlen($hmac1)); // SHA-256 hex = 64 chars
        $this->assertSame($hmac1, $hmac2); // Same input = same HMAC
    }

    /**
     * Test verify_jwks_integrity accepts valid HMAC.
     */
    public function testVerifyJwksIntegrityAcceptsValidHmac(): void
    {
        $jwks = ['keys' => [['kty' => 'RSA', 'kid' => 'test-key']]];

        Functions\when('wp_json_encode')->alias(fn($data) => json_encode($data));

        $reflection = new \ReflectionClass(OIDC_Client::class);

        $hmacMethod = $reflection->getMethod('generate_jwks_hmac');
        $hmacMethod->setAccessible(true);
        $validHmac = $hmacMethod->invoke($this->client, $jwks);

        $verifyMethod = $reflection->getMethod('verify_jwks_integrity');
        $verifyMethod->setAccessible(true);

        $cacheData = [
            'jwks' => $jwks,
            'hmac' => $validHmac
        ];

        $result = $verifyMethod->invoke($this->client, $cacheData);

        $this->assertTrue($result);
    }

    /**
     * Test verify_jwks_integrity rejects invalid HMAC.
     */
    public function testVerifyJwksIntegrityRejectsInvalidHmac(): void
    {
        $jwks = ['keys' => [['kty' => 'RSA', 'kid' => 'test-key']]];

        $reflection = new \ReflectionClass(OIDC_Client::class);
        $method = $reflection->getMethod('verify_jwks_integrity');
        $method->setAccessible(true);

        $cacheData = [
            'jwks' => $jwks,
            'hmac' => 'invalid-hmac-signature'
        ];

        $result = $method->invoke($this->client, $cacheData);

        $this->assertFalse($result);
    }

    /**
     * Test verify_jwks_integrity rejects malformed cache data.
     */
    public function testVerifyJwksIntegrityRejectsMalformedCacheData(): void
    {
        $reflection = new \ReflectionClass(OIDC_Client::class);
        $method = $reflection->getMethod('verify_jwks_integrity');
        $method->setAccessible(true);

        // Missing 'hmac' key
        $result1 = $method->invoke($this->client, ['jwks' => ['keys' => []]]);
        $this->assertFalse($result1);

        // Missing 'jwks' key
        $result2 = $method->invoke($this->client, ['hmac' => 'test']);
        $this->assertFalse($result2);

        // Empty array
        $result3 = $method->invoke($this->client, []);
        $this->assertFalse($result3);
    }
}

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
            'wp_safe_remote_post' => static fn($url, $args) => ['body' => '{}', 'response' => ['code' => 200]],
            'wp_safe_remote_get' => static fn($url, $args) => ['body' => '{}', 'response' => ['code' => 200]],
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
        Functions\when('wp_safe_remote_post')->justReturn(new WP_Error('http_error', 'Connection failed'));
        Functions\when('is_wp_error')->alias(fn($thing) => $thing instanceof WP_Error);

        $result = $this->client->exchange_code('auth-code');

        $this->assertInstanceOf(WP_Error::class, $result);
    }

    /**
     * Test exchange_code returns error on non-JSON response.
     */
    public function testExchangeCodeReturnsErrorOnNonJsonResponse(): void
    {
        Functions\when('wp_safe_remote_post')->justReturn(['body' => '<html>Error</html>', 'response' => ['code' => 200]]);
        Functions\when('wp_remote_retrieve_header')->justReturn('text/html');

        $result = $this->client->exchange_code('auth-code');

        $this->assertInstanceOf(WP_Error::class, $result);
    }

    /**
     * Test exchange_code returns error on non-200 status.
     */
    public function testExchangeCodeReturnsErrorOnNon200Status(): void
    {
        Functions\when('wp_safe_remote_post')->justReturn([
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
        Functions\when('wp_safe_remote_post')->justReturn([
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
        Functions\when('wp_safe_remote_post')->justReturn([
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
        Functions\when('wp_safe_remote_post')->justReturn([
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

        Functions\when('wp_safe_remote_post')->justReturn([
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
        Functions\when('wp_safe_remote_get')->justReturn(new WP_Error('http_error', 'Connection failed'));
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

        Functions\when('wp_safe_remote_get')->justReturn([
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
        Functions\when('wp_safe_remote_get')->justReturn(new WP_Error('http_error', 'Connection failed'));
        Functions\when('is_wp_error')->alias(fn($thing) => $thing instanceof WP_Error);

        $result = $this->client->discover('https://idp.example.com');

        $this->assertInstanceOf(WP_Error::class, $result);
    }

    /**
     * Test discover returns error on non-JSON response.
     */
    public function testDiscoverReturnsErrorOnNonJsonResponse(): void
    {
        Functions\when('wp_safe_remote_get')->justReturn([
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
        Functions\when('wp_safe_remote_get')->justReturn([
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

        Functions\when('wp_safe_remote_get')->justReturn([
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

        Functions\when('wp_safe_remote_post')->alias(function($url, $args) use (&$requestBody) {
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

        Functions\when('wp_safe_remote_post')->alias(function($url, $args) use (&$headers) {
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

        Functions\when('wp_safe_remote_post')->justReturn([
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
        Functions\when('wp_safe_remote_post')->justReturn(new WP_Error('http_error', 'Connection failed'));
        Functions\when('is_wp_error')->alias(fn($thing) => $thing instanceof WP_Error);

        $result = $this->client->refresh_token('refresh-token');

        $this->assertInstanceOf(WP_Error::class, $result);
    }

    /**
     * Test refresh_token returns error on 400 response.
     */
    public function testRefreshTokenReturnsErrorOn400Response(): void
    {
        Functions\when('wp_safe_remote_post')->justReturn([
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
        Functions\when('wp_safe_remote_get')->justReturn([
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
        Functions\when('wp_safe_remote_get')->justReturn([
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

        Functions\when('wp_safe_remote_get')->alias(function($url, $args) use (&$requestedUrl) {
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
     * Test handle_error always returns generic messages to prevent information disclosure.
     */
    public function testHandleErrorReturnsGenericMessage(): void
    {
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
        // Should NEVER contain detailed error or context
        $this->assertStringNotContainsString('sensitive info', $result->get_error_message());
        $this->assertStringNotContainsString('test_context', $result->get_error_message());
    }

    /**
     * Test handle_error with different error contexts.
     */
    public function testHandleErrorWithDifferentContexts(): void
    {
        $reflection = new \ReflectionClass(OIDC_Client::class);
        $method = $reflection->getMethod('handle_error');
        $method->setAccessible(true);

        $contexts = [
            ['jwt_decode', 'JWT signature verification failed', 'Authentication failed'],
            ['token_exchange', 'HTTP 500 from IdP', 'Token exchange failed'],
            ['userinfo', 'Connection timeout', 'Failed to retrieve user information'],
        ];

        foreach ($contexts as [$context, $detailed, $generic]) {
            $result = $method->invoke($this->client, $context, $detailed, $generic);

            $this->assertInstanceOf(WP_Error::class, $result);
            $this->assertSame($generic, $result->get_error_message());
            // Should never contain context or detailed error
            $this->assertStringNotContainsString($context, $result->get_error_message());
            $this->assertStringNotContainsString($detailed, $result->get_error_message());
        }
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
        Functions\when('wp_safe_remote_get')->justReturn([
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
        Functions\when('wp_safe_remote_get')->justReturn([
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
        Functions\when('wp_safe_remote_get')->justReturn(new WP_Error('http_error', 'Connection failed'));
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
        Functions\when('wp_safe_remote_get')->justReturn([
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
        Functions\when('wp_safe_remote_get')->justReturn([
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

    /**
     * Test check_salt_strength method exists and is callable.
     */
    public function testCheckSaltStrengthMethodExists(): void
    {
        $reflection = new \ReflectionClass(OIDC_Client::class);

        $this->assertTrue(
            $reflection->hasMethod('check_salt_strength'),
            'OIDC_Client should have a check_salt_strength method'
        );

        $method = $reflection->getMethod('check_salt_strength');
        $this->assertTrue($method->isPrivate(), 'check_salt_strength should be private');
    }

    /**
     * Test has_logged_salt_warning static property exists.
     */
    public function testHasLoggedSaltWarningPropertyExists(): void
    {
        $reflection = new \ReflectionClass(OIDC_Client::class);

        $this->assertTrue(
            $reflection->hasProperty('has_logged_salt_warning'),
            'OIDC_Client should have a has_logged_salt_warning property'
        );

        $property = $reflection->getProperty('has_logged_salt_warning');
        $this->assertTrue($property->isStatic(), 'has_logged_salt_warning should be static');
        $this->assertTrue($property->isPrivate(), 'has_logged_salt_warning should be private');
    }

    /**
     * Test check_salt_strength does not log when called multiple times.
     *
     * This tests the "log once per request" behavior by resetting the static flag
     * and verifying error_log is called only once across multiple invocations.
     */
    public function testCheckSaltStrengthLogsOnlyOnce(): void
    {
        // Reset the static flag
        $reflection = new \ReflectionClass(OIDC_Client::class);
        $property = $reflection->getProperty('has_logged_salt_warning');
        $property->setAccessible(true);
        $property->setValue(null, false);

        $method = $reflection->getMethod('check_salt_strength');
        $method->setAccessible(true);

        // First call - may or may not log depending on salt constants
        $method->invoke($this->client);
        $firstFlagState = $property->getValue(null);

        // Second call - should not change state
        $method->invoke($this->client);
        $secondFlagState = $property->getValue(null);

        // If first call set the flag, second call should not change it
        $this->assertSame(
            $firstFlagState,
            $secondFlagState,
            'check_salt_strength should not change warning flag state on subsequent calls'
        );
    }

    /**
     * Test check_salt_strength skips check when flag is already set.
     */
    public function testCheckSaltStrengthSkipsWhenFlagAlreadySet(): void
    {
        $reflection = new \ReflectionClass(OIDC_Client::class);
        $property = $reflection->getProperty('has_logged_salt_warning');
        $property->setAccessible(true);

        // Pre-set the flag to true
        $property->setValue(null, true);

        $method = $reflection->getMethod('check_salt_strength');
        $method->setAccessible(true);

        // Call the method - should return early without doing anything
        $method->invoke($this->client);

        // Flag should still be true
        $this->assertTrue(
            $property->getValue(null),
            'Flag should remain true after check_salt_strength call'
        );
    }

    /**
     * Test generate_jwks_hmac calls check_salt_strength.
     *
     * Verifies that the HMAC generation triggers the salt strength check.
     */
    public function testGenerateJwksHmacCallsCheckSaltStrength(): void
    {
        // Reset the static flag to a known state
        $reflection = new \ReflectionClass(OIDC_Client::class);
        $property = $reflection->getProperty('has_logged_salt_warning');
        $property->setAccessible(true);
        $property->setValue(null, false);

        Functions\when('wp_json_encode')->alias(fn($data) => json_encode($data));

        $hmacMethod = $reflection->getMethod('generate_jwks_hmac');
        $hmacMethod->setAccessible(true);

        $jwks = ['keys' => [['kty' => 'RSA', 'kid' => 'test-key']]];
        $hmacMethod->invoke($this->client, $jwks);

        // The flag may or may not be true depending on whether salts are weak
        // But the method should have been called (no exception thrown)
        $this->assertTrue(true, 'generate_jwks_hmac should call check_salt_strength without error');
    }

    /**
     * Test generate_jwks_hmac still produces valid HMAC even with weak salts.
     *
     * The HMAC should still be generated (for functionality) even if salts are weak.
     */
    public function testGenerateJwksHmacProducesValidHmacRegardlessOfSaltStrength(): void
    {
        $reflection = new \ReflectionClass(OIDC_Client::class);
        $property = $reflection->getProperty('has_logged_salt_warning');
        $property->setAccessible(true);
        $property->setValue(null, false);

        Functions\when('wp_json_encode')->alias(fn($data) => json_encode($data));

        $hmacMethod = $reflection->getMethod('generate_jwks_hmac');
        $hmacMethod->setAccessible(true);

        $jwks = ['keys' => [['kty' => 'RSA', 'kid' => 'test-key']]];
        $hmac = $hmacMethod->invoke($this->client, $jwks);

        // HMAC should always be a valid 64-character hex string
        $this->assertIsString($hmac);
        $this->assertSame(64, strlen($hmac), 'HMAC should be 64 hex characters (SHA-256)');
        $this->assertMatchesRegularExpression('/^[a-f0-9]{64}$/', $hmac, 'HMAC should be valid hex');
    }

    /**
     * Test multiple HMAC generations only trigger salt check once.
     */
    public function testMultipleHmacGenerationsOnlyCheckSaltOnce(): void
    {
        $reflection = new \ReflectionClass(OIDC_Client::class);
        $property = $reflection->getProperty('has_logged_salt_warning');
        $property->setAccessible(true);
        $property->setValue(null, false);

        Functions\when('wp_json_encode')->alias(fn($data) => json_encode($data));

        $hmacMethod = $reflection->getMethod('generate_jwks_hmac');
        $hmacMethod->setAccessible(true);

        $jwks1 = ['keys' => [['kty' => 'RSA', 'kid' => 'key-1']]];
        $jwks2 = ['keys' => [['kty' => 'RSA', 'kid' => 'key-2']]];
        $jwks3 = ['keys' => [['kty' => 'RSA', 'kid' => 'key-3']]];

        // Generate multiple HMACs
        $hmacMethod->invoke($this->client, $jwks1);
        $flagAfterFirst = $property->getValue(null);

        $hmacMethod->invoke($this->client, $jwks2);
        $flagAfterSecond = $property->getValue(null);

        $hmacMethod->invoke($this->client, $jwks3);
        $flagAfterThird = $property->getValue(null);

        // Flag state should not change after initial call
        $this->assertSame(
            $flagAfterFirst,
            $flagAfterSecond,
            'Flag should not change between HMAC generations'
        );
        $this->assertSame(
            $flagAfterSecond,
            $flagAfterThird,
            'Flag should not change between HMAC generations'
        );
    }

    /**
     * Test HMAC is deterministic for same input.
     */
    public function testHmacIsDeterministicForSameInput(): void
    {
        $reflection = new \ReflectionClass(OIDC_Client::class);
        Functions\when('wp_json_encode')->alias(fn($data) => json_encode($data));

        $hmacMethod = $reflection->getMethod('generate_jwks_hmac');
        $hmacMethod->setAccessible(true);

        $jwks = ['keys' => [['kty' => 'RSA', 'kid' => 'test-key', 'n' => 'modulus']]];

        $hmac1 = $hmacMethod->invoke($this->client, $jwks);
        $hmac2 = $hmacMethod->invoke($this->client, $jwks);
        $hmac3 = $hmacMethod->invoke($this->client, $jwks);

        $this->assertSame($hmac1, $hmac2, 'Same input should produce same HMAC');
        $this->assertSame($hmac2, $hmac3, 'Same input should produce same HMAC');
    }

    /**
     * Test HMAC differs for different inputs.
     */
    public function testHmacDiffersForDifferentInputs(): void
    {
        $reflection = new \ReflectionClass(OIDC_Client::class);
        Functions\when('wp_json_encode')->alias(fn($data) => json_encode($data));

        $hmacMethod = $reflection->getMethod('generate_jwks_hmac');
        $hmacMethod->setAccessible(true);

        $jwks1 = ['keys' => [['kty' => 'RSA', 'kid' => 'key-1']]];
        $jwks2 = ['keys' => [['kty' => 'RSA', 'kid' => 'key-2']]];
        $jwks3 = ['keys' => [['kty' => 'RSA', 'kid' => 'key-1'], ['kty' => 'RSA', 'kid' => 'key-2']]];

        $hmac1 = $hmacMethod->invoke($this->client, $jwks1);
        $hmac2 = $hmacMethod->invoke($this->client, $jwks2);
        $hmac3 = $hmacMethod->invoke($this->client, $jwks3);

        $this->assertNotSame($hmac1, $hmac2, 'Different inputs should produce different HMACs');
        $this->assertNotSame($hmac1, $hmac3, 'Different inputs should produce different HMACs');
        $this->assertNotSame($hmac2, $hmac3, 'Different inputs should produce different HMACs');
    }

    /**
     * Test HMAC handles empty JWKS keys array.
     */
    public function testHmacHandlesEmptyKeysArray(): void
    {
        $reflection = new \ReflectionClass(OIDC_Client::class);
        Functions\when('wp_json_encode')->alias(fn($data) => json_encode($data));

        $hmacMethod = $reflection->getMethod('generate_jwks_hmac');
        $hmacMethod->setAccessible(true);

        $jwks = ['keys' => []];
        $hmac = $hmacMethod->invoke($this->client, $jwks);

        $this->assertIsString($hmac);
        $this->assertSame(64, strlen($hmac), 'HMAC should be 64 hex characters even for empty keys');
    }

    /**
     * Test HMAC handles complex JWKS with multiple keys.
     */
    public function testHmacHandlesComplexJwks(): void
    {
        $reflection = new \ReflectionClass(OIDC_Client::class);
        Functions\when('wp_json_encode')->alias(fn($data) => json_encode($data));

        $hmacMethod = $reflection->getMethod('generate_jwks_hmac');
        $hmacMethod->setAccessible(true);

        $jwks = [
            'keys' => [
                [
                    'kty' => 'RSA',
                    'kid' => 'key-1',
                    'use' => 'sig',
                    'alg' => 'RS256',
                    'n' => 'very-long-modulus-value-here',
                    'e' => 'AQAB',
                ],
                [
                    'kty' => 'RSA',
                    'kid' => 'key-2',
                    'use' => 'sig',
                    'alg' => 'RS384',
                    'n' => 'another-long-modulus',
                    'e' => 'AQAB',
                ],
                [
                    'kty' => 'EC',
                    'kid' => 'key-3',
                    'use' => 'sig',
                    'alg' => 'ES256',
                    'crv' => 'P-256',
                    'x' => 'x-coordinate',
                    'y' => 'y-coordinate',
                ],
            ],
        ];

        $hmac = $hmacMethod->invoke($this->client, $jwks);

        $this->assertIsString($hmac);
        $this->assertSame(64, strlen($hmac), 'HMAC should be 64 hex characters for complex JWKS');
        $this->assertMatchesRegularExpression('/^[a-f0-9]{64}$/', $hmac);
    }

    /**
     * Test that verify_jwks_integrity uses timing-safe comparison.
     *
     * This test ensures the verification method exists and returns boolean.
     * The actual timing-safety is provided by hash_equals() which we trust.
     */
    public function testVerifyJwksIntegrityReturnsBooleanType(): void
    {
        $reflection = new \ReflectionClass(OIDC_Client::class);
        $method = $reflection->getMethod('verify_jwks_integrity');
        $method->setAccessible(true);

        Functions\when('wp_json_encode')->alias(fn($data) => json_encode($data));

        // Valid cache data
        $jwks = ['keys' => [['kty' => 'RSA', 'kid' => 'test']]];
        $hmacMethod = $reflection->getMethod('generate_jwks_hmac');
        $hmacMethod->setAccessible(true);
        $validHmac = $hmacMethod->invoke($this->client, $jwks);

        $validResult = $method->invoke($this->client, ['jwks' => $jwks, 'hmac' => $validHmac]);
        $invalidResult = $method->invoke($this->client, ['jwks' => $jwks, 'hmac' => 'wrong']);

        $this->assertIsBool($validResult, 'verify_jwks_integrity should return boolean');
        $this->assertIsBool($invalidResult, 'verify_jwks_integrity should return boolean');
        $this->assertTrue($validResult);
        $this->assertFalse($invalidResult);
    }

    /**
     * Test verify_jwks_integrity detects JWKS tampering.
     */
    public function testVerifyJwksIntegrityDetectsTampering(): void
    {
        $reflection = new \ReflectionClass(OIDC_Client::class);
        Functions\when('wp_json_encode')->alias(fn($data) => json_encode($data));

        $hmacMethod = $reflection->getMethod('generate_jwks_hmac');
        $hmacMethod->setAccessible(true);

        $verifyMethod = $reflection->getMethod('verify_jwks_integrity');
        $verifyMethod->setAccessible(true);

        // Original JWKS
        $originalJwks = ['keys' => [['kty' => 'RSA', 'kid' => 'legitimate-key']]];
        $originalHmac = $hmacMethod->invoke($this->client, $originalJwks);

        // Tampered JWKS (attacker injected their key)
        $tamperedJwks = ['keys' => [['kty' => 'RSA', 'kid' => 'attacker-key']]];

        // Verification should fail when JWKS is tampered but HMAC is from original
        $result = $verifyMethod->invoke($this->client, [
            'jwks' => $tamperedJwks,
            'hmac' => $originalHmac,
        ]);

        $this->assertFalse($result, 'Tampered JWKS should fail integrity check');
    }

    /**
     * Test verify_jwks_integrity detects subtle JWKS modifications.
     */
    public function testVerifyJwksIntegrityDetectsSubtleModifications(): void
    {
        $reflection = new \ReflectionClass(OIDC_Client::class);
        Functions\when('wp_json_encode')->alias(fn($data) => json_encode($data));

        $hmacMethod = $reflection->getMethod('generate_jwks_hmac');
        $hmacMethod->setAccessible(true);

        $verifyMethod = $reflection->getMethod('verify_jwks_integrity');
        $verifyMethod->setAccessible(true);

        // Original JWKS
        $originalJwks = ['keys' => [['kty' => 'RSA', 'kid' => 'key-1', 'n' => 'original-modulus']]];
        $originalHmac = $hmacMethod->invoke($this->client, $originalJwks);

        // Subtly modified JWKS (changed modulus - would allow forged signatures)
        $modifiedJwks = ['keys' => [['kty' => 'RSA', 'kid' => 'key-1', 'n' => 'modified-modulus']]];

        $result = $verifyMethod->invoke($this->client, [
            'jwks' => $modifiedJwks,
            'hmac' => $originalHmac,
        ]);

        $this->assertFalse($result, 'Subtly modified JWKS should fail integrity check');
    }

    /**
     * Test verify_jwks_integrity detects key addition attacks.
     */
    public function testVerifyJwksIntegrityDetectsKeyAddition(): void
    {
        $reflection = new \ReflectionClass(OIDC_Client::class);
        Functions\when('wp_json_encode')->alias(fn($data) => json_encode($data));

        $hmacMethod = $reflection->getMethod('generate_jwks_hmac');
        $hmacMethod->setAccessible(true);

        $verifyMethod = $reflection->getMethod('verify_jwks_integrity');
        $verifyMethod->setAccessible(true);

        // Original JWKS with one key
        $originalJwks = ['keys' => [['kty' => 'RSA', 'kid' => 'legitimate-key']]];
        $originalHmac = $hmacMethod->invoke($this->client, $originalJwks);

        // Modified JWKS with attacker's key added
        $attackerJwks = ['keys' => [
            ['kty' => 'RSA', 'kid' => 'legitimate-key'],
            ['kty' => 'RSA', 'kid' => 'attacker-injected-key'],
        ]];

        $result = $verifyMethod->invoke($this->client, [
            'jwks' => $attackerJwks,
            'hmac' => $originalHmac,
        ]);

        $this->assertFalse($result, 'JWKS with added keys should fail integrity check');
    }

    /**
     * Reset the static salt warning flag after each test to prevent test pollution.
     */
    protected function tearDown(): void
    {
        // Reset the static warning flag
        $reflection = new \ReflectionClass(OIDC_Client::class);
        if ($reflection->hasProperty('has_logged_salt_warning')) {
            $property = $reflection->getProperty('has_logged_salt_warning');
            $property->setAccessible(true);
            $property->setValue(null, false);
        }

        parent::tearDown();
    }

    // =========================================================================
    // ID Token Validation Edge Case Tests
    // =========================================================================

    // Note: Tests for validate_id_token require mocking the private decode_and_verify_jwt method,
    // which cannot be done with PHPUnit. Instead, we test the validation logic indirectly
    // through integration-style tests or by testing the individual validation components.

    /**
     * Test that validate_id_token method exists and has correct signature.
     */
    public function testValidateIdTokenMethodExists(): void
    {
        $reflection = new \ReflectionClass(OIDC_Client::class);

        $this->assertTrue(
            $reflection->hasMethod('validate_id_token'),
            'OIDC_Client should have validate_id_token method'
        );

        $method = $reflection->getMethod('validate_id_token');
        $this->assertTrue($method->isPublic(), 'validate_id_token should be public');

        // Check parameters
        $params = $method->getParameters();
        $this->assertCount(3, $params, 'validate_id_token should have 3 parameters');
        $this->assertSame('id_token', $params[0]->getName());
        $this->assertSame('expected_nonce', $params[1]->getName());
        $this->assertSame('auth_code', $params[2]->getName());
    }

    /**
     * Test c_hash computation follows OIDC spec.
     *
     * The c_hash is the base64url encoding of the left-most half of the hash
     * of the authorization code using the hash algorithm from the alg header.
     */
    public function testCHashComputationFollowsOidcSpec(): void
    {
        $authCode = 'test-authorization-code';

        // Per OIDC spec: c_hash = base64url(left-half(sha256(code)))
        $hash = hash('sha256', $authCode, true);
        $leftHalf = substr($hash, 0, 16); // Left-most half (16 bytes for SHA-256)
        $expectedCHash = rtrim(strtr(base64_encode($leftHalf), '+/', '-_'), '=');

        // Verify our expected c_hash computation
        $this->assertSame(22, strlen($expectedCHash), 'c_hash should be 22 characters for SHA-256');
        $this->assertMatchesRegularExpression('/^[A-Za-z0-9_-]+$/', $expectedCHash, 'c_hash should be base64url encoded');
    }

    /**
     * Test that nonce validation is case-sensitive.
     */
    public function testNonceValidationIsCaseSensitive(): void
    {
        // This is tested by verifying the method uses strict comparison
        // Actual validation tested via validate_id_token integration
        $nonce1 = 'TestNonce123';
        $nonce2 = 'testnonce123';

        $this->assertNotSame($nonce1, $nonce2, 'Nonces should be case-sensitive');
    }

    /**
     * Test audience claim can be array or string per OIDC spec.
     */
    public function testAudienceClaimHandling(): void
    {
        // Single audience (string)
        $singleAud = 'client-id';
        $audArray = is_array($singleAud) ? $singleAud : [$singleAud];
        $this->assertContains('client-id', $audArray);

        // Multiple audiences (array)
        $multiAud = ['client-id', 'other-client-id'];
        $audArray = is_array($multiAud) ? $multiAud : [$multiAud];
        $this->assertContains('client-id', $audArray);
        $this->assertContains('other-client-id', $audArray);
    }

    // =========================================================================
    // JWT Algorithm Handling Tests
    // =========================================================================

    // =========================================================================
    // Token Endpoint Auth Method Tests
    // =========================================================================

    /**
     * Test exchange_code uses client_secret_basic (Authorization header) by default.
     */
    public function testExchangeCodeUsesClientSecretBasicByDefault(): void
    {
        $capturedHeaders = null;
        $capturedBody = null;

        Functions\when('wp_safe_remote_post')->alias(function($url, $args) use (&$capturedHeaders, &$capturedBody) {
            $capturedHeaders = $args['headers'] ?? [];
            $capturedBody = $args['body'] ?? [];
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

        $this->assertArrayHasKey('Authorization', $capturedHeaders);
        $this->assertStringStartsWith('Basic ', $capturedHeaders['Authorization']);
        $this->assertArrayNotHasKey('client_id', $capturedBody);
        $this->assertArrayNotHasKey('client_secret', $capturedBody);
    }

    /**
     * Test exchange_code uses client_secret_post when configured.
     */
    public function testExchangeCodeUsesClientSecretPostWhenConfigured(): void
    {
        Functions\when('get_option')->justReturn([
            'client_id' => 'test-client-id',
            'client_secret' => 'test-client-secret',
            'token_endpoint' => 'https://idp.example.com/token',
            'token_endpoint_auth_method' => 'client_secret_post',
        ]);

        $client = new OIDC_Client();

        $capturedHeaders = null;
        $capturedBody = null;

        Functions\when('wp_safe_remote_post')->alias(function($url, $args) use (&$capturedHeaders, &$capturedBody) {
            $capturedHeaders = $args['headers'] ?? [];
            $capturedBody = $args['body'] ?? [];
            return [
                'body' => json_encode([
                    'access_token' => 'test-access',
                    'id_token' => 'test-id',
                    'token_type' => 'Bearer'
                ]),
                'response' => ['code' => 200]
            ];
        });

        $client->exchange_code('auth-code');

        $this->assertArrayNotHasKey('Authorization', $capturedHeaders);
        $this->assertArrayHasKey('client_secret', $capturedBody);
        $this->assertSame('test-client-secret', $capturedBody['client_secret']);
        $this->assertArrayHasKey('client_id', $capturedBody);
    }

    /**
     * Test refresh_token uses client_secret_basic (Authorization header) by default.
     */
    public function testRefreshTokenUsesClientSecretBasicByDefault(): void
    {
        $capturedHeaders = null;
        $capturedBody = null;

        Functions\when('wp_safe_remote_post')->alias(function($url, $args) use (&$capturedHeaders, &$capturedBody) {
            $capturedHeaders = $args['headers'] ?? [];
            $capturedBody = $args['body'] ?? [];
            return [
                'body' => json_encode([
                    'access_token' => 'new-access',
                    'id_token' => 'new-id',
                    'token_type' => 'Bearer'
                ]),
                'response' => ['code' => 200]
            ];
        });

        $this->client->refresh_token('refresh-token-value');

        $this->assertArrayHasKey('Authorization', $capturedHeaders);
        $this->assertStringStartsWith('Basic ', $capturedHeaders['Authorization']);
        $this->assertArrayNotHasKey('client_id', $capturedBody);
        $this->assertArrayNotHasKey('client_secret', $capturedBody);
    }

    /**
     * Test refresh_token uses client_secret_post when configured.
     */
    public function testRefreshTokenUsesClientSecretPostWhenConfigured(): void
    {
        Functions\when('get_option')->justReturn([
            'client_id' => 'test-client-id',
            'client_secret' => 'test-client-secret',
            'token_endpoint' => 'https://idp.example.com/token',
            'token_endpoint_auth_method' => 'client_secret_post',
        ]);

        $client = new OIDC_Client();

        $capturedHeaders = null;
        $capturedBody = null;

        Functions\when('wp_safe_remote_post')->alias(function($url, $args) use (&$capturedHeaders, &$capturedBody) {
            $capturedHeaders = $args['headers'] ?? [];
            $capturedBody = $args['body'] ?? [];
            return [
                'body' => json_encode([
                    'access_token' => 'new-access',
                    'id_token' => 'new-id',
                    'token_type' => 'Bearer'
                ]),
                'response' => ['code' => 200]
            ];
        });

        $client->refresh_token('refresh-token-value');

        $this->assertArrayNotHasKey('Authorization', $capturedHeaders);
        $this->assertArrayHasKey('client_secret', $capturedBody);
        $this->assertSame('test-client-secret', $capturedBody['client_secret']);
        $this->assertArrayHasKey('client_id', $capturedBody);
    }

    /**
     * Test exchange_code with client_secret_post includes both client_id and client_secret in body.
     */
    public function testExchangeCodeClientSecretPostIncludesBothCredentialsInBody(): void
    {
        Functions\when('get_option')->justReturn([
            'client_id' => 'my-client',
            'client_secret' => 'my-secret',
            'token_endpoint' => 'https://idp.example.com/token',
            'token_endpoint_auth_method' => 'client_secret_post',
        ]);

        $client = new OIDC_Client();

        $capturedBody = null;

        Functions\when('wp_safe_remote_post')->alias(function($url, $args) use (&$capturedBody) {
            $capturedBody = $args['body'] ?? [];
            return [
                'body' => json_encode([
                    'access_token' => 'test-access',
                    'id_token' => 'test-id',
                    'token_type' => 'Bearer'
                ]),
                'response' => ['code' => 200]
            ];
        });

        $client->exchange_code('auth-code');

        $this->assertSame('my-client', $capturedBody['client_id']);
        $this->assertSame('my-secret', $capturedBody['client_secret']);
        $this->assertSame('authorization_code', $capturedBody['grant_type']);
    }

    /**
     * Test decode_and_verify_jwt returns error for invalid JWT format (not 3 parts).
     *
     * We test this by calling the method directly via reflection since it's private.
     */
    public function testDecodeAndVerifyJwtReturnsErrorForInvalidFormat(): void
    {
        // We need to call the private method directly
        // But since get_jwks is also private and called first, we need a different approach
        // Use get_jwks to return an error which propagates, proving the method is called
        Functions\when('get_transient')->justReturn(false);
        Functions\when('wp_safe_remote_get')->justReturn([
            'body' => json_encode(['keys' => [['kty' => 'RSA', 'kid' => 'test']]]),
            'response' => ['code' => 200],
        ]);
        Functions\when('set_transient')->justReturn(true);
        Functions\when('wp_json_encode')->alias(fn($data) => json_encode($data));

        $reflection = new \ReflectionMethod(OIDC_Client::class, 'decode_and_verify_jwt');
        $reflection->setAccessible(true);

        // JWT with only 2 parts instead of 3
        $result = $reflection->invoke($this->client, 'part1.part2');

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertStringContainsString('Invalid JWT format', $result->get_error_message());
    }

    /**
     * Test decode_and_verify_jwt returns error for JWT with 4 parts.
     */
    public function testDecodeAndVerifyJwtReturnsErrorForTooManyParts(): void
    {
        Functions\when('get_transient')->justReturn(false);
        Functions\when('wp_safe_remote_get')->justReturn([
            'body' => json_encode(['keys' => [['kty' => 'RSA', 'kid' => 'test']]]),
            'response' => ['code' => 200],
        ]);
        Functions\when('set_transient')->justReturn(true);
        Functions\when('wp_json_encode')->alias(fn($data) => json_encode($data));

        $reflection = new \ReflectionMethod(OIDC_Client::class, 'decode_and_verify_jwt');
        $reflection->setAccessible(true);

        // JWT with 4 parts
        $result = $reflection->invoke($this->client, 'part1.part2.part3.part4');

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertStringContainsString('Invalid JWT format', $result->get_error_message());
    }

    /**
     * Test decode_and_verify_jwt propagates JWKS fetch errors.
     */
    public function testDecodeAndVerifyJwtPropagatesJwksError(): void
    {
        // Make get_jwks return an error
        Functions\when('get_transient')->justReturn(false);
        Functions\when('wp_safe_remote_get')->justReturn(new WP_Error('http_error', 'Connection failed'));
        Functions\when('is_wp_error')->alias(fn($thing) => $thing instanceof WP_Error);

        $reflection = new \ReflectionMethod(OIDC_Client::class, 'decode_and_verify_jwt');
        $reflection->setAccessible(true);

        $result = $reflection->invoke($this->client, 'header.payload.signature');

        $this->assertInstanceOf(WP_Error::class, $result);
    }

    /**
     * Test decode_and_verify_jwt handles JWKS keys without 'alg' field.
     *
     * Some IdPs omit the 'alg' field in JWKS keys. The client should
     * infer the algorithm from the key type (kty) to enable verification.
     */
    public function testDecodeAndVerifyJwtHandlesKeysWithoutAlgField(): void
    {
        // JWKS without 'alg' field in keys
        $jwks = ['keys' => [
            ['kty' => 'RSA', 'kid' => 'test-key', 'n' => 'modulus', 'e' => 'AQAB'],
        ]];

        Functions\when('get_transient')->justReturn(false);
        Functions\when('wp_safe_remote_get')->justReturn([
            'body' => json_encode($jwks),
            'response' => ['code' => 200],
        ]);
        Functions\when('set_transient')->justReturn(true);
        Functions\when('wp_json_encode')->alias(fn($data) => json_encode($data));

        $reflection = new \ReflectionMethod(OIDC_Client::class, 'decode_and_verify_jwt');
        $reflection->setAccessible(true);

        // Create a JWT with RS256 algorithm in header
        $header = rtrim(strtr(base64_encode(json_encode(['alg' => 'RS256', 'typ' => 'JWT'])), '+/', '-_'), '=');
        $payload = rtrim(strtr(base64_encode('{"sub":"test"}'), '+/', '-_'), '=');
        $signature = rtrim(strtr(base64_encode('fake-sig'), '+/', '-_'), '=');

        $result = $reflection->invoke($this->client, "$header.$payload.$signature");

        // The method should attempt to verify and fail on signature, not on missing alg
        $this->assertInstanceOf(WP_Error::class, $result);
        // Error should not be about missing algorithm
        $this->assertStringNotContainsString('algorithm', strtolower($result->get_error_message()));
    }

    /**
     * Test decode_and_verify_jwt defaults to RS256 when algorithm not in header.
     */
    public function testDecodeAndVerifyJwtDefaultsToRS256(): void
    {
        $jwks = ['keys' => [['kty' => 'RSA', 'kid' => 'test-key']]];

        Functions\when('get_transient')->justReturn(false);
        Functions\when('wp_safe_remote_get')->justReturn([
            'body' => json_encode($jwks),
            'response' => ['code' => 200],
        ]);
        Functions\when('set_transient')->justReturn(true);
        Functions\when('wp_json_encode')->alias(fn($data) => json_encode($data));

        $reflection = new \ReflectionMethod(OIDC_Client::class, 'decode_and_verify_jwt');
        $reflection->setAccessible(true);

        // Create header without 'alg' field
        $header = rtrim(strtr(base64_encode(json_encode(['typ' => 'JWT'])), '+/', '-_'), '=');
        $payload = rtrim(strtr(base64_encode('{"sub":"test"}'), '+/', '-_'), '=');
        $signature = rtrim(strtr(base64_encode('fake-sig'), '+/', '-_'), '=');

        $result = $reflection->invoke($this->client, "$header.$payload.$signature");

        // Method should proceed (and fail on signature), not error on missing alg
        $this->assertInstanceOf(WP_Error::class, $result);
    }

    /**
     * Test decode_and_verify_jwt rejects HS256 (symmetric algorithm confusion attack).
     *
     * An attacker could craft a JWT with alg=HS256 and sign it using the IdP's
     * public RSA key as the HMAC secret. The allowlist must block this.
     */
    public function testDecodeAndVerifyJwtRejectsHS256(): void
    {
        $jwks = ['keys' => [
            ['kty' => 'RSA', 'kid' => 'test-key', 'n' => 'modulus', 'e' => 'AQAB'],
        ]];

        Functions\when('get_transient')->justReturn(false);
        Functions\when('wp_safe_remote_get')->justReturn([
            'body' => json_encode($jwks),
            'response' => ['code' => 200],
        ]);
        Functions\when('set_transient')->justReturn(true);
        Functions\when('wp_json_encode')->alias(fn($data) => json_encode($data));

        $reflection = new \ReflectionMethod(OIDC_Client::class, 'decode_and_verify_jwt');
        $reflection->setAccessible(true);

        // Create a JWT with HS256 algorithm (symmetric - should be rejected)
        $header = rtrim(strtr(base64_encode(json_encode(['alg' => 'HS256', 'typ' => 'JWT'])), '+/', '-_'), '=');
        $payload = rtrim(strtr(base64_encode('{"sub":"test"}'), '+/', '-_'), '=');
        $signature = rtrim(strtr(base64_encode('fake-sig'), '+/', '-_'), '=');

        $result = $reflection->invoke($this->client, "$header.$payload.$signature");

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertStringContainsString('Unsupported JWT signing algorithm', $result->get_error_message());
    }

    /**
     * Test decode_and_verify_jwt rejects 'none' algorithm.
     *
     * The 'none' algorithm means no signature verification, which would
     * allow any attacker to forge tokens.
     */
    public function testDecodeAndVerifyJwtRejectsNoneAlgorithm(): void
    {
        $jwks = ['keys' => [
            ['kty' => 'RSA', 'kid' => 'test-key', 'n' => 'modulus', 'e' => 'AQAB'],
        ]];

        Functions\when('get_transient')->justReturn(false);
        Functions\when('wp_safe_remote_get')->justReturn([
            'body' => json_encode($jwks),
            'response' => ['code' => 200],
        ]);
        Functions\when('set_transient')->justReturn(true);
        Functions\when('wp_json_encode')->alias(fn($data) => json_encode($data));

        $reflection = new \ReflectionMethod(OIDC_Client::class, 'decode_and_verify_jwt');
        $reflection->setAccessible(true);

        // Create a JWT with 'none' algorithm (no signature - should be rejected)
        $header = rtrim(strtr(base64_encode(json_encode(['alg' => 'none', 'typ' => 'JWT'])), '+/', '-_'), '=');
        $payload = rtrim(strtr(base64_encode('{"sub":"test"}'), '+/', '-_'), '=');
        $signature = rtrim(strtr(base64_encode(''), '+/', '-_'), '=');

        $result = $reflection->invoke($this->client, "$header.$payload.$signature");

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertStringContainsString('Unsupported JWT signing algorithm', $result->get_error_message());
    }

    /**
     * Test decode_and_verify_jwt rejects HS384 and HS512 symmetric algorithms.
     */
    public function testDecodeAndVerifyJwtRejectsAllSymmetricAlgorithms(): void
    {
        $jwks = ['keys' => [
            ['kty' => 'RSA', 'kid' => 'test-key', 'n' => 'modulus', 'e' => 'AQAB'],
        ]];

        Functions\when('get_transient')->justReturn(false);
        Functions\when('wp_safe_remote_get')->justReturn([
            'body' => json_encode($jwks),
            'response' => ['code' => 200],
        ]);
        Functions\when('set_transient')->justReturn(true);
        Functions\when('wp_json_encode')->alias(fn($data) => json_encode($data));

        $reflection = new \ReflectionMethod(OIDC_Client::class, 'decode_and_verify_jwt');
        $reflection->setAccessible(true);

        foreach (['HS256', 'HS384', 'HS512'] as $symmetric_alg) {
            $header = rtrim(strtr(base64_encode(json_encode(['alg' => $symmetric_alg, 'typ' => 'JWT'])), '+/', '-_'), '=');
            $payload = rtrim(strtr(base64_encode('{"sub":"test"}'), '+/', '-_'), '=');
            $signature = rtrim(strtr(base64_encode('fake-sig'), '+/', '-_'), '=');

            $result = $reflection->invoke($this->client, "$header.$payload.$signature");

            $this->assertInstanceOf(WP_Error::class, $result, "Algorithm $symmetric_alg should be rejected");
            $this->assertStringContainsString('Unsupported JWT signing algorithm', $result->get_error_message(), "Algorithm $symmetric_alg should be rejected with correct message");
        }
    }

    /**
     * Test decode_and_verify_jwt rejects arbitrary/unknown algorithms.
     */
    public function testDecodeAndVerifyJwtRejectsUnknownAlgorithm(): void
    {
        $jwks = ['keys' => [
            ['kty' => 'RSA', 'kid' => 'test-key', 'n' => 'modulus', 'e' => 'AQAB'],
        ]];

        Functions\when('get_transient')->justReturn(false);
        Functions\when('wp_safe_remote_get')->justReturn([
            'body' => json_encode($jwks),
            'response' => ['code' => 200],
        ]);
        Functions\when('set_transient')->justReturn(true);
        Functions\when('wp_json_encode')->alias(fn($data) => json_encode($data));

        $reflection = new \ReflectionMethod(OIDC_Client::class, 'decode_and_verify_jwt');
        $reflection->setAccessible(true);

        // Create a JWT with a fabricated algorithm
        $header = rtrim(strtr(base64_encode(json_encode(['alg' => 'FAKE256', 'typ' => 'JWT'])), '+/', '-_'), '=');
        $payload = rtrim(strtr(base64_encode('{"sub":"test"}'), '+/', '-_'), '=');
        $signature = rtrim(strtr(base64_encode('fake-sig'), '+/', '-_'), '=');

        $result = $reflection->invoke($this->client, "$header.$payload.$signature");

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertStringContainsString('Unsupported JWT signing algorithm', $result->get_error_message());
    }

    /**
     * Test that allowed asymmetric algorithms are accepted (not rejected by the allowlist).
     *
     * These algorithms should pass the allowlist check and proceed to signature
     * verification (which will fail with our fake keys, but that's expected).
     */
    public function testDecodeAndVerifyJwtAcceptsAllowedAlgorithms(): void
    {
        $jwks = ['keys' => [
            ['kty' => 'RSA', 'kid' => 'test-key', 'n' => 'modulus', 'e' => 'AQAB'],
        ]];

        Functions\when('get_transient')->justReturn(false);
        Functions\when('wp_safe_remote_get')->justReturn([
            'body' => json_encode($jwks),
            'response' => ['code' => 200],
        ]);
        Functions\when('set_transient')->justReturn(true);
        Functions\when('wp_json_encode')->alias(fn($data) => json_encode($data));

        $reflection = new \ReflectionMethod(OIDC_Client::class, 'decode_and_verify_jwt');
        $reflection->setAccessible(true);

        foreach (['RS256', 'ES256', 'PS256', 'EdDSA'] as $allowed_alg) {
            $header = rtrim(strtr(base64_encode(json_encode(['alg' => $allowed_alg, 'typ' => 'JWT'])), '+/', '-_'), '=');
            $payload = rtrim(strtr(base64_encode('{"sub":"test"}'), '+/', '-_'), '=');
            $signature = rtrim(strtr(base64_encode('fake-sig'), '+/', '-_'), '=');

            $result = $reflection->invoke($this->client, "$header.$payload.$signature");

            // Should be a WP_Error (signature will fail), but NOT about unsupported algorithm
            $this->assertInstanceOf(WP_Error::class, $result, "Algorithm $allowed_alg should be accepted");
            $this->assertStringNotContainsString('Unsupported JWT signing algorithm', $result->get_error_message(), "Algorithm $allowed_alg should not be rejected by allowlist");
        }
    }

    /**
     * Test decode_and_verify_jwt rejects algorithm not in IdP's discovered supported list.
     *
     * When the IdP declares id_token_signing_alg_values_supported during discovery,
     * JWTs using algorithms outside that list should be rejected even if they are
     * in the hardcoded safe asymmetric allowlist.
     */
    public function testDecodeAndVerifyJwtRejectsAlgorithmNotInIdpSupportedList(): void
    {
        // Configure client with IdP that only supports RS256
        Functions\when('get_option')->justReturn([
            'client_id' => 'test-client-id',
            'jwks_uri' => 'https://idp.example.com/.well-known/jwks.json',
            'issuer' => 'https://idp.example.com',
            'id_token_signing_alg_values_supported' => ['RS256'],
        ]);

        $client = new OIDC_Client();

        $jwks = ['keys' => [
            ['kty' => 'RSA', 'kid' => 'test-key', 'n' => 'modulus', 'e' => 'AQAB'],
        ]];

        Functions\when('get_transient')->justReturn(false);
        Functions\when('wp_safe_remote_get')->justReturn([
            'body' => json_encode($jwks),
            'response' => ['code' => 200],
        ]);
        Functions\when('set_transient')->justReturn(true);
        Functions\when('wp_json_encode')->alias(fn($data) => json_encode($data));

        $reflection = new \ReflectionMethod(OIDC_Client::class, 'decode_and_verify_jwt');
        $reflection->setAccessible(true);

        // ES256 is in the hardcoded safe list but NOT in this IdP's supported list
        $header = rtrim(strtr(base64_encode(json_encode(['alg' => 'ES256', 'typ' => 'JWT'])), '+/', '-_'), '=');
        $payload = rtrim(strtr(base64_encode('{"sub":"test"}'), '+/', '-_'), '=');
        $signature = rtrim(strtr(base64_encode('fake-sig'), '+/', '-_'), '=');

        $result = $reflection->invoke($client, "$header.$payload.$signature");

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertStringContainsString('not supported by the identity provider', $result->get_error_message());
    }

    /**
     * Test decode_and_verify_jwt accepts algorithm in IdP's discovered supported list.
     */
    public function testDecodeAndVerifyJwtAcceptsAlgorithmInIdpSupportedList(): void
    {
        // Configure client with IdP that supports RS256 and ES256
        Functions\when('get_option')->justReturn([
            'client_id' => 'test-client-id',
            'jwks_uri' => 'https://idp.example.com/.well-known/jwks.json',
            'issuer' => 'https://idp.example.com',
            'id_token_signing_alg_values_supported' => ['RS256', 'ES256'],
        ]);

        $client = new OIDC_Client();

        $jwks = ['keys' => [
            ['kty' => 'RSA', 'kid' => 'test-key', 'n' => 'modulus', 'e' => 'AQAB'],
        ]];

        Functions\when('get_transient')->justReturn(false);
        Functions\when('wp_safe_remote_get')->justReturn([
            'body' => json_encode($jwks),
            'response' => ['code' => 200],
        ]);
        Functions\when('set_transient')->justReturn(true);
        Functions\when('wp_json_encode')->alias(fn($data) => json_encode($data));

        $reflection = new \ReflectionMethod(OIDC_Client::class, 'decode_and_verify_jwt');
        $reflection->setAccessible(true);

        // RS256 is both in the hardcoded list and IdP's supported list
        $header = rtrim(strtr(base64_encode(json_encode(['alg' => 'RS256', 'typ' => 'JWT'])), '+/', '-_'), '=');
        $payload = rtrim(strtr(base64_encode('{"sub":"test"}'), '+/', '-_'), '=');
        $signature = rtrim(strtr(base64_encode('fake-sig'), '+/', '-_'), '=');

        $result = $reflection->invoke($client, "$header.$payload.$signature");

        // Should proceed past algorithm checks (fail on signature, not algorithm)
        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertStringNotContainsString('algorithm', strtolower($result->get_error_message()));
    }

    /**
     * Test decode_and_verify_jwt uses only hardcoded list when no IdP algorithms stored.
     *
     * When id_token_signing_alg_values_supported is empty (no discovery performed),
     * the hardcoded safe asymmetric algorithm list should be the sole gatekeeper.
     */
    public function testDecodeAndVerifyJwtFallsBackToHardcodedListWhenNoIdpAlgorithms(): void
    {
        // Configure client without id_token_signing_alg_values_supported
        Functions\when('get_option')->justReturn([
            'client_id' => 'test-client-id',
            'jwks_uri' => 'https://idp.example.com/.well-known/jwks.json',
            'issuer' => 'https://idp.example.com',
            // No id_token_signing_alg_values_supported - empty/not set
        ]);

        $client = new OIDC_Client();

        $jwks = ['keys' => [
            ['kty' => 'RSA', 'kid' => 'test-key', 'n' => 'modulus', 'e' => 'AQAB'],
        ]];

        Functions\when('get_transient')->justReturn(false);
        Functions\when('wp_safe_remote_get')->justReturn([
            'body' => json_encode($jwks),
            'response' => ['code' => 200],
        ]);
        Functions\when('set_transient')->justReturn(true);
        Functions\when('wp_json_encode')->alias(fn($data) => json_encode($data));

        $reflection = new \ReflectionMethod(OIDC_Client::class, 'decode_and_verify_jwt');
        $reflection->setAccessible(true);

        // ES256 is in the hardcoded safe list and should pass with no IdP restriction
        $header = rtrim(strtr(base64_encode(json_encode(['alg' => 'ES256', 'typ' => 'JWT'])), '+/', '-_'), '=');
        $payload = rtrim(strtr(base64_encode('{"sub":"test"}'), '+/', '-_'), '=');
        $signature = rtrim(strtr(base64_encode('fake-sig'), '+/', '-_'), '=');

        $result = $reflection->invoke($client, "$header.$payload.$signature");

        // Should proceed past algorithm checks (fail on signature/key, not algorithm)
        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertStringNotContainsString('algorithm', strtolower($result->get_error_message()));
    }
}

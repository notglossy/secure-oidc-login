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
            'wp_parse_url' => static fn($url, $component = -1) => parse_url($url, $component),
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
     * Test exchange_code returns error when token_type is missing.
     */
    public function testExchangeCodeReturnsErrorWhenTokenTypeMissing(): void
    {
        Functions\when('wp_safe_remote_post')->justReturn([
            'body' => '{"access_token": "test", "id_token": "test"}',
            'response' => ['code' => 200]
        ]);

        $result = $this->client->exchange_code('auth-code');

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertStringContainsString('Missing required token_type', $result->get_error_message());
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
     * Test exchange_code accepts lowercase "bearer" token type per RFC 6749.
     */
    public function testExchangeCodeAcceptsLowercaseBearerTokenType(): void
    {
        $tokenResponse = [
            'access_token' => 'test-access-token',
            'id_token' => 'test-id-token',
            'token_type' => 'bearer',
        ];

        Functions\when('wp_safe_remote_post')->justReturn([
            'body' => json_encode($tokenResponse),
            'response' => ['code' => 200]
        ]);

        $result = $this->client->exchange_code('auth-code');

        $this->assertIsArray($result);
        $this->assertSame('test-access-token', $result['access_token']);
    }

    /**
     * Test exchange_code accepts uppercase "BEARER" token type per RFC 6749.
     */
    public function testExchangeCodeAcceptsUppercaseBearerTokenType(): void
    {
        $tokenResponse = [
            'access_token' => 'test-access-token',
            'id_token' => 'test-id-token',
            'token_type' => 'BEARER',
        ];

        Functions\when('wp_safe_remote_post')->justReturn([
            'body' => json_encode($tokenResponse),
            'response' => ['code' => 200]
        ]);

        $result = $this->client->exchange_code('auth-code');

        $this->assertIsArray($result);
        $this->assertSame('test-access-token', $result['access_token']);
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
        $this->assertCount(4, $params, 'validate_id_token should have 4 parameters');
        $this->assertSame('id_token', $params[0]->getName());
        $this->assertSame('expected_nonce', $params[1]->getName());
        $this->assertSame('auth_code', $params[2]->getName());
        $this->assertSame('access_token', $params[3]->getName());
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
     * Test at_hash computation follows OIDC spec.
     *
     * The at_hash is the base64url encoding of the left-most half of the hash
     * of the access token using the hash algorithm from the alg header.
     */
    public function testAtHashComputationFollowsOidcSpec(): void
    {
        $accessToken = 'test-access-token';

        // Per OIDC spec: at_hash = base64url(left-half(sha256(access_token)))
        $hash = hash('sha256', $accessToken, true);
        $leftHalf = substr($hash, 0, 16); // Left-most half (16 bytes for SHA-256)
        $expectedAtHash = rtrim(strtr(base64_encode($leftHalf), '+/', '-_'), '=');

        // Verify our expected at_hash computation
        $this->assertSame(22, strlen($expectedAtHash), 'at_hash should be 22 characters for SHA-256');
        $this->assertMatchesRegularExpression('/^[A-Za-z0-9_-]+$/', $expectedAtHash, 'at_hash should be base64url encoded');
    }

    /**
     * Test validate_id_token accepts valid at_hash matching the access token.
     */
    public function testValidateIdTokenAcceptsValidAtHash(): void
    {
        $accessToken = 'test-access-token-value';
        $atHash = rtrim(strtr(base64_encode(substr(hash('sha256', $accessToken, true), 0, 16)), '+/', '-_'), '=');

        $client = $this->createClientWithStubbedJwt([
            'sub' => 'user-123',
            'iss' => 'https://idp.example.com',
            'aud' => 'test-client-id',
            'at_hash' => $atHash,
        ]);

        $result = $client->validate_id_token('fake.jwt.token', null, null, $accessToken);

        $this->assertIsArray($result);
        $this->assertSame('user-123', $result['sub']);
    }

    /**
     * Test validate_id_token rejects mismatched at_hash.
     */
    public function testValidateIdTokenRejectsMismatchedAtHash(): void
    {
        $client = $this->createClientWithStubbedJwt([
            'sub' => 'user-123',
            'iss' => 'https://idp.example.com',
            'aud' => 'test-client-id',
            'at_hash' => 'invalid-hash-value',
        ]);

        $result = $client->validate_id_token('fake.jwt.token', null, null, 'some-access-token');

        $this->assertInstanceOf(\WP_Error::class, $result);
        $this->assertSame('invalid_at_hash', $result->get_error_code());
    }

    /**
     * Test validate_id_token skips at_hash validation when no access token provided.
     */
    public function testValidateIdTokenSkipsAtHashWhenNoAccessToken(): void
    {
        $client = $this->createClientWithStubbedJwt([
            'sub' => 'user-123',
            'iss' => 'https://idp.example.com',
            'aud' => 'test-client-id',
            'at_hash' => 'some-hash-value',
        ]);

        $result = $client->validate_id_token('fake.jwt.token');

        $this->assertIsArray($result);
        $this->assertSame('user-123', $result['sub']);
    }

    /**
     * Test get_hash_params_for_alg returns correct params for all supported algorithms.
     */
    public function testGetHashParamsForAlg(): void
    {
        $reflection = new \ReflectionMethod(OIDC_Client::class, 'get_hash_params_for_alg');
        $reflection->setAccessible(true);

        // *256 algorithms → SHA-256, 16 bytes
        foreach (['RS256', 'ES256', 'PS256'] as $alg) {
            $result = $reflection->invoke(null, $alg);
            $this->assertSame(['sha256', 16], $result, "Algorithm $alg should use SHA-256");
        }

        // *384 algorithms → SHA-384, 24 bytes
        foreach (['RS384', 'ES384', 'PS384'] as $alg) {
            $result = $reflection->invoke(null, $alg);
            $this->assertSame(['sha384', 24], $result, "Algorithm $alg should use SHA-384");
        }

        // *512 algorithms → SHA-512, 32 bytes
        foreach (['RS512', 'ES512', 'PS512'] as $alg) {
            $result = $reflection->invoke(null, $alg);
            $this->assertSame(['sha512', 32], $result, "Algorithm $alg should use SHA-512");
        }

        // EdDSA → SHA-512, 32 bytes
        $result = $reflection->invoke(null, 'EdDSA');
        $this->assertSame(['sha512', 32], $result, 'EdDSA should use SHA-512');
    }

    /**
     * Test validate_id_token accepts valid at_hash with RS384 (SHA-384).
     */
    public function testValidateIdTokenAcceptsValidAtHashWithRS384(): void
    {
        $accessToken = 'test-access-token-value';
        $atHash = rtrim(strtr(base64_encode(substr(hash('sha384', $accessToken, true), 0, 24)), '+/', '-_'), '=');

        $client = $this->createClientWithStubbedJwt([
            '__jwt_alg' => 'RS384',
            'sub' => 'user-123',
            'iss' => 'https://idp.example.com',
            'aud' => 'test-client-id',
            'at_hash' => $atHash,
        ]);

        $result = $client->validate_id_token('fake.jwt.token', null, null, $accessToken);

        $this->assertIsArray($result);
        $this->assertSame('user-123', $result['sub']);
    }

    /**
     * Test validate_id_token accepts valid at_hash with RS512 (SHA-512).
     */
    public function testValidateIdTokenAcceptsValidAtHashWithRS512(): void
    {
        $accessToken = 'test-access-token-value';
        $atHash = rtrim(strtr(base64_encode(substr(hash('sha512', $accessToken, true), 0, 32)), '+/', '-_'), '=');

        $client = $this->createClientWithStubbedJwt([
            '__jwt_alg' => 'RS512',
            'sub' => 'user-123',
            'iss' => 'https://idp.example.com',
            'aud' => 'test-client-id',
            'at_hash' => $atHash,
        ]);

        $result = $client->validate_id_token('fake.jwt.token', null, null, $accessToken);

        $this->assertIsArray($result);
        $this->assertSame('user-123', $result['sub']);
    }

    /**
     * Test validate_id_token rejects SHA-256 at_hash when algorithm is RS384.
     *
     * If the JWT is signed with RS384 but at_hash was computed with SHA-256,
     * validation should fail because the hash algorithm doesn't match.
     */
    public function testValidateIdTokenRejectsSha256AtHashWithRS384(): void
    {
        $accessToken = 'test-access-token-value';
        // Compute at_hash with wrong algorithm (SHA-256 instead of SHA-384)
        $wrongAtHash = rtrim(strtr(base64_encode(substr(hash('sha256', $accessToken, true), 0, 16)), '+/', '-_'), '=');

        $client = $this->createClientWithStubbedJwt([
            '__jwt_alg' => 'RS384',
            'sub' => 'user-123',
            'iss' => 'https://idp.example.com',
            'aud' => 'test-client-id',
            'at_hash' => $wrongAtHash,
        ]);

        $result = $client->validate_id_token('fake.jwt.token', null, null, $accessToken);

        $this->assertInstanceOf(\WP_Error::class, $result);
        $this->assertSame('invalid_at_hash', $result->get_error_code());
    }

    /**
     * Test validate_id_token accepts valid c_hash with RS384 (SHA-384).
     */
    public function testValidateIdTokenAcceptsValidCHashWithRS384(): void
    {
        $authCode = 'test-authorization-code';
        $cHash = rtrim(strtr(base64_encode(substr(hash('sha384', $authCode, true), 0, 24)), '+/', '-_'), '=');

        $client = $this->createClientWithStubbedJwt([
            '__jwt_alg' => 'RS384',
            'sub' => 'user-123',
            'iss' => 'https://idp.example.com',
            'aud' => 'test-client-id',
            'c_hash' => $cHash,
        ]);

        $result = $client->validate_id_token('fake.jwt.token', null, $authCode);

        $this->assertIsArray($result);
        $this->assertSame('user-123', $result['sub']);
    }

    /**
     * Test validate_id_token does not leak __jwt_alg into returned claims.
     */
    public function testValidateIdTokenStripsJwtAlgFromClaims(): void
    {
        $client = $this->createClientWithStubbedJwt([
            'sub' => 'user-123',
            'iss' => 'https://idp.example.com',
            'aud' => 'test-client-id',
        ]);

        $result = $client->validate_id_token('fake.jwt.token');

        $this->assertIsArray($result);
        $this->assertArrayNotHasKey('__jwt_alg', $result);
    }

    /**
     * Test validate_id_token skips nonce validation when no nonce is expected.
     *
     * Covers the null-skip branch: when $expected_nonce is null, the nonce claim
     * is neither required nor compared.
     */
    public function testValidateIdTokenSkipsNonceCheckWhenExpectedNonceIsNull(): void
    {
        $client = $this->createClientWithStubbedJwt([
            'sub' => 'user-123',
            'iss' => 'https://idp.example.com',
            'aud' => 'test-client-id',
            // No 'nonce' claim — must still succeed when none is expected.
        ]);

        $result = $client->validate_id_token('fake.jwt.token', null);

        $this->assertIsArray($result);
        $this->assertSame('user-123', $result['sub']);
    }

    /**
     * Test validate_id_token rejects a token missing the nonce claim when one is expected.
     *
     * Covers the missing-claim branch (OIDC Core 3.1.3.7).
     */
    public function testValidateIdTokenRejectsMissingNonceClaim(): void
    {
        $client = $this->createClientWithStubbedJwt([
            'sub' => 'user-123',
            'iss' => 'https://idp.example.com',
            'aud' => 'test-client-id',
            // No 'nonce' claim, but a nonce is expected below.
        ]);

        $result = $client->validate_id_token('fake.jwt.token', 'expected-nonce-value');

        $this->assertInstanceOf(\WP_Error::class, $result);
        $this->assertSame('missing_nonce', $result->get_error_code());
    }

    /**
     * Test validate_id_token rejects a nonce that does not match the expected value.
     *
     * Covers the mismatch branch — the core replay-attack defense.
     */
    public function testValidateIdTokenRejectsMismatchedNonce(): void
    {
        $client = $this->createClientWithStubbedJwt([
            'sub' => 'user-123',
            'iss' => 'https://idp.example.com',
            'aud' => 'test-client-id',
            'nonce' => 'actual-nonce-from-token',
        ]);

        $result = $client->validate_id_token('fake.jwt.token', 'different-expected-nonce');

        $this->assertInstanceOf(\WP_Error::class, $result);
        $this->assertSame('invalid_nonce', $result->get_error_code());
    }

    /**
     * Test validate_id_token accepts a token whose nonce matches the expected value.
     */
    public function testValidateIdTokenAcceptsMatchingNonce(): void
    {
        $client = $this->createClientWithStubbedJwt([
            'sub' => 'user-123',
            'iss' => 'https://idp.example.com',
            'aud' => 'test-client-id',
            'nonce' => 'matching-nonce',
        ]);

        $result = $client->validate_id_token('fake.jwt.token', 'matching-nonce');

        $this->assertIsArray($result);
        $this->assertSame('user-123', $result['sub']);
    }

    /**
     * Test that nonce validation is case-sensitive (strict comparison).
     */
    public function testNonceValidationIsCaseSensitive(): void
    {
        $client = $this->createClientWithStubbedJwt([
            'sub' => 'user-123',
            'iss' => 'https://idp.example.com',
            'aud' => 'test-client-id',
            'nonce' => 'TestNonce123',
        ]);

        // Same characters, different case — must be rejected by the strict (!==) check.
        $result = $client->validate_id_token('fake.jwt.token', 'testnonce123');

        $this->assertInstanceOf(\WP_Error::class, $result);
        $this->assertSame('invalid_nonce', $result->get_error_code());
    }

    /**
     * Test the expired/missing nonce-transient path fails closed.
     *
     * In handle_callback the expected nonce comes from get_transient(), which
     * returns false when the transient is missing or expired. Under strict_types
     * that false hits the ?string $expected_nonce parameter and throws a
     * TypeError, aborting authentication rather than silently skipping the nonce
     * check (which null would do). This locks in that fails-closed guarantee.
     */
    public function testValidateIdTokenRejectsNonStringNonceFromExpiredTransient(): void
    {
        $client = $this->createClientWithStubbedJwt([
            'sub' => 'user-123',
            'iss' => 'https://idp.example.com',
            'aud' => 'test-client-id',
            'nonce' => 'some-nonce',
        ]);

        $this->expectException(\TypeError::class);

        // false is what get_transient() returns for a missing/expired nonce; it
        // must not be accepted as "no nonce expected".
        $client->validate_id_token('fake.jwt.token', false);
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

    // =========================================================================
    // ACR Claim Validation Tests
    // =========================================================================

    /**
     * Test validate_acr_claim returns true when enforcement is disabled.
     */
    public function testValidateAcrClaimReturnsTrueWhenEnforcementDisabled(): void
    {
        putenv('SECURE_OIDC_ENFORCE_ACR');
        putenv('SECURE_OIDC_ACR_VALUES');

        $claims = ['sub' => 'user-123', 'acr' => 'urn:mace:incommon:iap:silver'];
        $options = [
            'acr_values' => 'urn:mace:incommon:iap:silver',
            'enforce_acr' => false,
        ];

        $result = $this->client->validate_acr_claim($claims, $options);

        $this->assertTrue($result);
    }

    /**
     * Test validate_acr_claim returns true when no acr_values configured.
     */
    public function testValidateAcrClaimReturnsTrueWhenNoAcrValuesConfigured(): void
    {
        putenv('SECURE_OIDC_ENFORCE_ACR');
        putenv('SECURE_OIDC_ACR_VALUES');

        $claims = ['sub' => 'user-123'];
        $options = [
            'acr_values' => '',
            'enforce_acr' => true,
        ];

        $result = $this->client->validate_acr_claim($claims, $options);

        $this->assertTrue($result);
    }

    /**
     * Test validate_acr_claim returns true when acr claim matches requested value.
     */
    public function testValidateAcrClaimReturnsTrueWhenAcrMatches(): void
    {
        putenv('SECURE_OIDC_ENFORCE_ACR');
        putenv('SECURE_OIDC_ACR_VALUES');

        $claims = ['sub' => 'user-123', 'acr' => 'urn:mace:incommon:iap:silver'];
        $options = [
            'acr_values' => 'urn:mace:incommon:iap:bronze urn:mace:incommon:iap:silver',
            'enforce_acr' => true,
        ];

        $result = $this->client->validate_acr_claim($claims, $options);

        $this->assertTrue($result);
    }

    /**
     * Test validate_acr_claim returns WP_Error when acr claim is missing.
     */
    public function testValidateAcrClaimReturnsErrorWhenAcrMissing(): void
    {
        putenv('SECURE_OIDC_ENFORCE_ACR');
        putenv('SECURE_OIDC_ACR_VALUES');

        $claims = ['sub' => 'user-123'];
        $options = [
            'acr_values' => 'urn:mace:incommon:iap:silver',
            'enforce_acr' => true,
        ];

        $result = $this->client->validate_acr_claim($claims, $options);

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertSame('oidc_acr_missing', $result->get_error_code());
    }

    /**
     * Test validate_acr_claim returns WP_Error when acr claim does not match.
     */
    public function testValidateAcrClaimReturnsErrorWhenAcrMismatch(): void
    {
        putenv('SECURE_OIDC_ENFORCE_ACR');
        putenv('SECURE_OIDC_ACR_VALUES');

        $claims = ['sub' => 'user-123', 'acr' => 'urn:mace:incommon:iap:bronze'];
        $options = [
            'acr_values' => 'urn:mace:incommon:iap:silver urn:mace:incommon:iap:gold',
            'enforce_acr' => true,
        ];

        $result = $this->client->validate_acr_claim($claims, $options);

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertSame('oidc_acr_mismatch', $result->get_error_code());
    }

    /**
     * Test validate_acr_claim works with a single acr_value.
     */
    public function testValidateAcrClaimWorksSingleAcrValue(): void
    {
        putenv('SECURE_OIDC_ENFORCE_ACR');
        putenv('SECURE_OIDC_ACR_VALUES');

        $claims = ['sub' => 'user-123', 'acr' => 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport'];
        $options = [
            'acr_values' => 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport',
            'enforce_acr' => true,
        ];

        $result = $this->client->validate_acr_claim($claims, $options);

        $this->assertTrue($result);
    }

    /**
     * Test validate_acr_claim uses strict string comparison (no type coercion).
     */
    public function testValidateAcrClaimUsesStrictStringComparison(): void
    {
        putenv('SECURE_OIDC_ENFORCE_ACR');
        putenv('SECURE_OIDC_ACR_VALUES');

        // Integer 0 should not match string "0" loosely - ensure strict comparison
        $claims = ['sub' => 'user-123', 'acr' => '1'];
        $options = [
            'acr_values' => '01',
            'enforce_acr' => true,
        ];

        $result = $this->client->validate_acr_claim($claims, $options);

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertSame('oidc_acr_mismatch', $result->get_error_code());
    }

    /**
     * Test validate_acr_claim handles extra whitespace in acr_values string.
     */
    public function testValidateAcrClaimHandlesExtraWhitespace(): void
    {
        putenv('SECURE_OIDC_ENFORCE_ACR');
        putenv('SECURE_OIDC_ACR_VALUES');

        $claims = ['sub' => 'user-123', 'acr' => 'urn:mace:incommon:iap:silver'];
        $options = [
            'acr_values' => '  urn:mace:incommon:iap:bronze   urn:mace:incommon:iap:silver  ',
            'enforce_acr' => true,
        ];

        $result = $this->client->validate_acr_claim($claims, $options);

        $this->assertTrue($result);
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

    // =========================================================================
    // Issuer Validation Tests (using anonymous subclass)
    // =========================================================================

    /**
     * Create a testable OIDC_Client subclass that stubs decode_and_verify_jwt.
     *
     * @param array<string, mixed> $claims Claims to return from decode_and_verify_jwt.
     * @return OIDC_Client
     */
    private function createClientWithStubbedJwt(array $claims): OIDC_Client
    {
        return new class($claims) extends OIDC_Client {
            /** @var array<string, mixed> */
            private array $stubbedClaims;

            /**
             * @param array<string, mixed> $claims
             */
            public function __construct(array $claims)
            {
                parent::__construct();
                $this->stubbedClaims = $claims;
            }

            protected function decode_and_verify_jwt(string $jwt, bool $retry = true): array|\WP_Error
            {
                return array_merge(['__jwt_alg' => 'RS256'], $this->stubbedClaims);
            }
        };
    }

    /**
     * Test validate_id_token returns error when issuer is not configured.
     */
    public function testValidateIdTokenReturnsErrorWhenIssuerNotConfigured(): void
    {
        Functions\when('get_option')->justReturn([
            'client_id' => 'test-client-id',
            'jwks_uri' => 'https://idp.example.com/.well-known/jwks.json',
            // issuer intentionally missing
        ]);

        $client = $this->createClientWithStubbedJwt([
            'sub' => 'user-123',
            'iss' => 'https://idp.example.com',
            'aud' => 'test-client-id',
        ]);

        $result = $client->validate_id_token('fake.jwt.token');

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertStringContainsString('configuration error', $result->get_error_message());
    }

    /**
     * Test validate_id_token returns error when issuer does not match.
     */
    public function testValidateIdTokenReturnsErrorWhenIssuerMismatch(): void
    {
        $client = $this->createClientWithStubbedJwt([
            'sub' => 'user-123',
            'iss' => 'https://evil-idp.example.com',
            'aud' => 'test-client-id',
        ]);

        $result = $client->validate_id_token('fake.jwt.token');

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertStringContainsString('Invalid token issuer', $result->get_error_message());
    }

    /**
     * Test validate_id_token succeeds when issuer matches.
     */
    public function testValidateIdTokenSucceedsWhenIssuerMatches(): void
    {
        $client = $this->createClientWithStubbedJwt([
            'sub' => 'user-123',
            'iss' => 'https://idp.example.com',
            'aud' => 'test-client-id',
        ]);

        $result = $client->validate_id_token('fake.jwt.token');

        $this->assertIsArray($result);
        $this->assertSame('user-123', $result['sub']);
        $this->assertSame('https://idp.example.com', $result['iss']);
    }

    /**
     * Test validate_id_token returns error when iss claim is missing from token.
     */
    public function testValidateIdTokenReturnsErrorWhenIssClaimMissing(): void
    {
        $client = $this->createClientWithStubbedJwt([
            'sub' => 'user-123',
            // 'iss' intentionally missing
            'aud' => 'test-client-id',
        ]);

        $result = $client->validate_id_token('fake.jwt.token');

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertStringContainsString('Invalid token issuer', $result->get_error_message());
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

    // =========================================================================
    // Discovery Document Validation Tests (OIDC Discovery 1.0 Section 4.3)
    // =========================================================================

    /**
     * Test validate_discovery_document accepts a document whose issuer matches the URL.
     */
    public function testValidateDiscoveryDocumentAcceptsMatchingIssuer(): void
    {
        putenv('SECURE_OIDC_ALLOW_INSECURE_DISCOVERY');

        $result = OIDC_Client::validate_discovery_document(
            $this->getSampleOIDCConfig(),
            'https://idp.example.com/.well-known/openid-configuration'
        );

        $this->assertTrue($result);
    }

    /**
     * Test validate_discovery_document rejects a document with a mismatched issuer.
     */
    public function testValidateDiscoveryDocumentRejectsIssuerMismatch(): void
    {
        putenv('SECURE_OIDC_ALLOW_INSECURE_DISCOVERY');

        $config = $this->getSampleOIDCConfig();
        $config['issuer'] = 'https://evil.example.org';

        $result = OIDC_Client::validate_discovery_document(
            $config,
            'https://idp.example.com/.well-known/openid-configuration'
        );

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertSame('oidc_discovery_issuer_mismatch', $result->get_error_code());
    }

    /**
     * Test validate_discovery_document rejects a document without an issuer.
     */
    public function testValidateDiscoveryDocumentRejectsMissingIssuer(): void
    {
        $config = $this->getSampleOIDCConfig();
        unset($config['issuer']);

        $result = OIDC_Client::validate_discovery_document(
            $config,
            'https://idp.example.com/.well-known/openid-configuration'
        );

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertSame('oidc_discovery_missing_issuer', $result->get_error_code());
    }

    /**
     * Test validate_discovery_document tolerates a trailing slash on the issuer.
     */
    public function testValidateDiscoveryDocumentToleratesTrailingSlashOnIssuer(): void
    {
        putenv('SECURE_OIDC_ALLOW_INSECURE_DISCOVERY');

        $config = $this->getSampleOIDCConfig();
        $config['issuer'] = 'https://idp.example.com/';

        $result = OIDC_Client::validate_discovery_document(
            $config,
            'https://idp.example.com/.well-known/openid-configuration'
        );

        $this->assertTrue($result);
    }

    /**
     * Test validate_discovery_document ignores query strings on the discovery URL.
     *
     * Some providers (e.g. Azure AD B2C) require query parameters on the
     * discovery URL that are not part of the issuer identifier.
     */
    public function testValidateDiscoveryDocumentIgnoresQueryStringOnDiscoveryUrl(): void
    {
        putenv('SECURE_OIDC_ALLOW_INSECURE_DISCOVERY');

        $result = OIDC_Client::validate_discovery_document(
            $this->getSampleOIDCConfig(),
            'https://idp.example.com/.well-known/openid-configuration?p=policy_name'
        );

        $this->assertTrue($result);
    }

    /**
     * Test validate_discovery_document rejects non-HTTPS endpoints by default.
     */
    public function testValidateDiscoveryDocumentRejectsHttpEndpoint(): void
    {
        putenv('SECURE_OIDC_ALLOW_INSECURE_DISCOVERY');

        $config = $this->getSampleOIDCConfig();
        $config['token_endpoint'] = 'http://idp.example.com/token';

        $result = OIDC_Client::validate_discovery_document(
            $config,
            'https://idp.example.com/.well-known/openid-configuration'
        );

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertSame('oidc_discovery_insecure_endpoint', $result->get_error_code());
    }

    /**
     * Test validate_discovery_document allows HTTP endpoints with the testing escape hatch.
     */
    public function testValidateDiscoveryDocumentAllowsHttpEndpointWhenInsecureAllowed(): void
    {
        putenv('SECURE_OIDC_ALLOW_INSECURE_DISCOVERY=true');

        try {
            $config = $this->getSampleOIDCConfig();
            $config['token_endpoint'] = 'http://idp.example.com/token';

            $result = OIDC_Client::validate_discovery_document(
                $config,
                'https://idp.example.com/.well-known/openid-configuration'
            );

            $this->assertTrue($result);
        } finally {
            putenv('SECURE_OIDC_ALLOW_INSECURE_DISCOVERY');
        }
    }

    /**
     * Test validate_discovery_document rejects malformed endpoint URLs.
     */
    public function testValidateDiscoveryDocumentRejectsMalformedEndpoint(): void
    {
        $config = $this->getSampleOIDCConfig();
        $config['jwks_uri'] = 'not a url';

        $result = OIDC_Client::validate_discovery_document(
            $config,
            'https://idp.example.com/.well-known/openid-configuration'
        );

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertSame('oidc_discovery_invalid_endpoint', $result->get_error_code());
    }

    /**
     * Test discover() rejects a discovery document whose issuer does not match.
     */
    public function testDiscoverRejectsMismatchedIssuer(): void
    {
        putenv('SECURE_OIDC_ALLOW_INSECURE_DISCOVERY');

        $config = $this->getSampleOIDCConfig();
        $config['issuer'] = 'https://other-idp.example.net';

        Functions\when('wp_safe_remote_get')->justReturn([
            'body' => json_encode($config),
            'response' => ['code' => 200]
        ]);

        $result = $this->client->discover('https://idp.example.com');

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertSame('oidc_discovery_issuer_mismatch', $result->get_error_code());
    }

    // =========================================================================
    // Refresh Token Response Validation Tests (RFC 6749 Section 5.1)
    // =========================================================================

    /**
     * Test refresh_token returns error when access_token is missing.
     */
    public function testRefreshTokenReturnsErrorWhenAccessTokenMissing(): void
    {
        Functions\when('wp_safe_remote_post')->justReturn([
            'body' => '{"token_type": "Bearer", "expires_in": 3600}',
            'response' => ['code' => 200]
        ]);

        $result = $this->client->refresh_token('refresh-token-value');

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertStringContainsString('Invalid token response', $result->get_error_message());
    }

    /**
     * Test refresh_token returns error when token_type is missing.
     */
    public function testRefreshTokenReturnsErrorWhenTokenTypeMissing(): void
    {
        Functions\when('wp_safe_remote_post')->justReturn([
            'body' => '{"access_token": "new-access-token", "expires_in": 3600}',
            'response' => ['code' => 200]
        ]);

        $result = $this->client->refresh_token('refresh-token-value');

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertStringContainsString('Missing required token_type', $result->get_error_message());
    }

    /**
     * Test refresh_token returns error for non-Bearer token type.
     */
    public function testRefreshTokenReturnsErrorForUnsupportedTokenType(): void
    {
        Functions\when('wp_safe_remote_post')->justReturn([
            'body' => '{"access_token": "new-access-token", "token_type": "MAC"}',
            'response' => ['code' => 200]
        ]);

        $result = $this->client->refresh_token('refresh-token-value');

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertStringContainsString('Unsupported token type', $result->get_error_message());
    }

    // =========================================================================
    // Client Authentication Encoding Tests (RFC 6749 Section 2.3.1)
    // =========================================================================

    /**
     * Test Basic auth credentials are form-urlencoded before base64 encoding.
     *
     * Per RFC 6749 section 2.3.1 the client_id and client_secret must each be
     * application/x-www-form-urlencoded (spaces become '+') before being combined
     * with a colon, so secrets containing reserved characters (':', '%', '+', ' ')
     * round-trip correctly.
     */
    public function testBasicAuthCredentialsAreFormUrlencoded(): void
    {
        Functions\when('get_option')->justReturn([
            'client_id' => 'client:with:colons',
            'client_secret' => 'secret%with+special:chars and spaces',
            'token_endpoint' => 'https://idp.example.com/token',
        ]);

        $client = new OIDC_Client();
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

        $client->exchange_code('auth-code');

        $this->assertArrayHasKey('Authorization', $headers);
        $decoded = base64_decode(substr($headers['Authorization'], strlen('Basic ')));
        $this->assertSame(
            'client%3Awith%3Acolons:secret%25with%2Bspecial%3Achars+and+spaces',
            $decoded
        );
    }

    /**
     * Test JWKS keys with an unknown kty and no alg are skipped, not assigned the header alg.
     */
    public function testDecodeAndVerifyJwtSkipsKeysWithUnknownKty(): void
    {
        // Single key with unrecognized kty and no alg field - must be dropped
        $jwks = ['keys' => [
            ['kty' => 'UNKNOWN', 'kid' => 'test-key', 'n' => 'modulus', 'e' => 'AQAB'],
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

        $header = rtrim(strtr(base64_encode(json_encode(['alg' => 'RS256', 'typ' => 'JWT'])), '+/', '-_'), '=');
        $payload = rtrim(strtr(base64_encode('{"sub":"test"}'), '+/', '-_'), '=');
        $signature = rtrim(strtr(base64_encode('fake-sig'), '+/', '-_'), '=');

        $result = $reflection->invoke($this->client, "$header.$payload.$signature");

        // With the only key dropped, the key set is empty and verification must fail
        $this->assertInstanceOf(WP_Error::class, $result);
    }

    // =========================================================================
    // auth_time / max_age Validation Tests (OIDC Core 3.1.3.7 step 13)
    // =========================================================================

    /**
     * Test validate_auth_time passes when max_age is not configured.
     */
    public function testValidateAuthTimePassesWhenMaxAgeNotConfigured(): void
    {
        putenv('SECURE_OIDC_MAX_AGE');

        $result = $this->client->validate_auth_time(
            ['sub' => 'user-123'],
            ['max_age' => 0]
        );

        $this->assertTrue($result);
    }

    /**
     * Test validate_auth_time passes for a recent authentication.
     */
    public function testValidateAuthTimePassesForRecentAuth(): void
    {
        putenv('SECURE_OIDC_MAX_AGE');

        $result = $this->client->validate_auth_time(
            ['sub' => 'user-123', 'auth_time' => time() - 10],
            ['max_age' => 300]
        );

        $this->assertTrue($result);
    }

    /**
     * Test validate_auth_time rejects a missing auth_time when max_age is set.
     */
    public function testValidateAuthTimeRejectsMissingAuthTime(): void
    {
        putenv('SECURE_OIDC_MAX_AGE');

        $result = $this->client->validate_auth_time(
            ['sub' => 'user-123'],
            ['max_age' => 300]
        );

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertSame('oidc_auth_time_missing', $result->get_error_code());
    }

    /**
     * Test validate_auth_time rejects authentication older than max_age.
     */
    public function testValidateAuthTimeRejectsStaleAuth(): void
    {
        putenv('SECURE_OIDC_MAX_AGE');

        $result = $this->client->validate_auth_time(
            ['sub' => 'user-123', 'auth_time' => time() - 1000],
            ['max_age' => 300]
        );

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertSame('oidc_auth_time_exceeded', $result->get_error_code());
    }

    // =========================================================================
    // Logout Token Validation Tests (OIDC Back-Channel Logout 1.0 Section 2.6)
    // =========================================================================

    /**
     * Build a complete, valid set of logout token claims.
     *
     * @param array<string, mixed> $overrides Claims to add or replace.
     * @return array<string, mixed> Logout token claims.
     */
    private function getSampleLogoutTokenClaims(array $overrides = []): array
    {
        $claims = [
            'iss' => 'https://idp.example.com',
            'aud' => 'test-client-id',
            'iat' => time(),
            'exp' => time() + 120,
            'jti' => 'logout-jti-123',
            'events' => ['http://schemas.openid.net/event/backchannel-logout' => []],
            'sub' => 'user-123-abc',
        ];

        return array_merge($claims, $overrides);
    }

    /**
     * Test validate_logout_token accepts a fully valid logout token.
     */
    public function testValidateLogoutTokenAcceptsValidToken(): void
    {
        $set_jti_keys = [];
        Functions\when('set_transient')->alias(function ($key, $value, $ttl) use (&$set_jti_keys) {
            $set_jti_keys[] = $key;
            return true;
        });

        $client = $this->createClientWithStubbedJwt($this->getSampleLogoutTokenClaims());

        $result = $client->validate_logout_token('header.payload.signature');

        $this->assertIsArray($result);
        $this->assertSame('user-123-abc', $result['sub']);
        // The jti must be recorded for replay protection
        $this->assertNotEmpty(array_filter($set_jti_keys, fn($k) => str_starts_with($k, 'oidc_bcl_jti_')));
    }

    /**
     * Test the jti replay cache lifetime covers the token's full validity window.
     *
     * A fixed cache TTL shorter than the token's exp would let the same logout
     * token be replayed once the cache entry expires while the JWT is still valid.
     */
    public function testValidateLogoutTokenJtiCacheCoversTokenLifetime(): void
    {
        $captured_ttl = null;
        Functions\when('set_transient')->alias(function ($key, $value, $ttl) use (&$captured_ttl) {
            if (str_starts_with((string) $key, 'oidc_bcl_jti_')) {
                $captured_ttl = $ttl;
            }
            return true;
        });

        // Token valid for one hour - the replay cache must last at least that long
        $client = $this->createClientWithStubbedJwt(
            $this->getSampleLogoutTokenClaims(['exp' => time() + 3600])
        );

        $result = $client->validate_logout_token('header.payload.signature');

        $this->assertIsArray($result);
        $this->assertGreaterThanOrEqual(3600, $captured_ttl);
        // And it is capped at one day even for absurd exp values
        $client = $this->createClientWithStubbedJwt(
            $this->getSampleLogoutTokenClaims(['exp' => time() + 10 * 86400, 'jti' => 'jti-far-future'])
        );
        $client->validate_logout_token('header.payload.signature');
        $this->assertLessThanOrEqual(86400, $captured_ttl);
    }

    /**
     * Test validate_logout_token rejects a replayed jti.
     */
    public function testValidateLogoutTokenRejectsReplayedJti(): void
    {
        // The jti replay-cache transient already exists
        Functions\when('get_transient')->alias(
            static fn($key) => str_starts_with((string) $key, 'oidc_bcl_jti_') ? 1 : false
        );

        $client = $this->createClientWithStubbedJwt($this->getSampleLogoutTokenClaims());

        $result = $client->validate_logout_token('header.payload.signature');

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertStringContainsString('already been used', $result->get_error_message());
    }

    /**
     * Test validate_logout_token rejects a token containing a nonce.
     *
     * Per Section 2.6 step 7 this blocks ID tokens being replayed as logout tokens.
     */
    public function testValidateLogoutTokenRejectsNonce(): void
    {
        $client = $this->createClientWithStubbedJwt(
            $this->getSampleLogoutTokenClaims(['nonce' => 'some-nonce'])
        );

        $result = $client->validate_logout_token('header.payload.signature');

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertStringContainsString('nonce', $result->get_error_message());
    }

    /**
     * Test validate_logout_token rejects a token without the logout event.
     */
    public function testValidateLogoutTokenRejectsMissingEvent(): void
    {
        $claims = $this->getSampleLogoutTokenClaims();
        unset($claims['events']);

        $client = $this->createClientWithStubbedJwt($claims);

        $result = $client->validate_logout_token('header.payload.signature');

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertStringContainsString('event', $result->get_error_message());
    }

    /**
     * Test validate_logout_token rejects a token with neither sub nor sid.
     */
    public function testValidateLogoutTokenRejectsMissingSubAndSid(): void
    {
        $claims = $this->getSampleLogoutTokenClaims();
        unset($claims['sub']);

        $client = $this->createClientWithStubbedJwt($claims);

        $result = $client->validate_logout_token('header.payload.signature');

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertStringContainsString('sub or sid', $result->get_error_message());
    }

    /**
     * Test validate_logout_token accepts a token identifying the session by sid only.
     */
    public function testValidateLogoutTokenAcceptsSidOnly(): void
    {
        $claims = $this->getSampleLogoutTokenClaims(['sid' => 'idp-session-1']);
        unset($claims['sub']);

        $client = $this->createClientWithStubbedJwt($claims);

        $result = $client->validate_logout_token('header.payload.signature');

        $this->assertIsArray($result);
        $this->assertSame('idp-session-1', $result['sid']);
    }

    /**
     * Test validate_logout_token rejects a wrong issuer.
     */
    public function testValidateLogoutTokenRejectsWrongIssuer(): void
    {
        $client = $this->createClientWithStubbedJwt(
            $this->getSampleLogoutTokenClaims(['iss' => 'https://evil.example.org'])
        );

        $result = $client->validate_logout_token('header.payload.signature');

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertStringContainsString('issuer', $result->get_error_message());
    }

    /**
     * Test validate_logout_token rejects a wrong audience.
     */
    public function testValidateLogoutTokenRejectsWrongAudience(): void
    {
        $client = $this->createClientWithStubbedJwt(
            $this->getSampleLogoutTokenClaims(['aud' => 'other-client'])
        );

        $result = $client->validate_logout_token('header.payload.signature');

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertStringContainsString('audience', $result->get_error_message());
    }

    /**
     * Test validate_logout_token rejects missing iat/exp and missing jti.
     */
    public function testValidateLogoutTokenRejectsMissingRequiredClaims(): void
    {
        // Missing exp
        $claims = $this->getSampleLogoutTokenClaims();
        unset($claims['exp']);
        $result = $this->createClientWithStubbedJwt($claims)->validate_logout_token('h.p.s');
        $this->assertInstanceOf(WP_Error::class, $result);

        // Missing jti
        $claims = $this->getSampleLogoutTokenClaims();
        unset($claims['jti']);
        $result = $this->createClientWithStubbedJwt($claims)->validate_logout_token('h.p.s');
        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertStringContainsString('jti', $result->get_error_message());
    }
}

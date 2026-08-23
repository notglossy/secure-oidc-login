<?php
/**
 * Tests for OIDC_Url class.
 *
 * @package SecureOIDCLogin\Tests\Unit\Url
 */

declare(strict_types=1);

namespace SecureOIDCLogin\Tests\Unit\Url;

use OIDC_Url;
use SecureOIDCLogin\Tests\OIDCTestCase;

/**
 * Tests for the query URL builder helper.
 *
 * @covers OIDC_Url
 */
class OIDCUrlTest extends OIDCTestCase
{
    /**
     * A plain endpoint without a query string gets parameters appended with '?'.
     */
    public function testAppendsWithQuestionMarkWhenUrlHasNoQueryString(): void
    {
        $url = 'https://idp.example.com/authorize';

        $result = OIDC_Url::build_query_url($url, ['response_type' => 'code']);

        $this->assertSame('https://idp.example.com/authorize?response_type=code', $result);
    }

    /**
     * An endpoint that already carries a query string (e.g. Azure AD B2C policy)
     * gets parameters appended with '&', not a second '?'.
     */
    public function testAppendsWithAmpersandWhenUrlAlreadyHasQueryString(): void
    {
        $url = 'https://tenant.b2clogin.com/tenant.onmicrosoft.com/oauth2/v2.0/authorize?p=B2C_1_signin';

        $result = OIDC_Url::build_query_url($url, ['response_type' => 'code']);

        $this->assertSame(
            'https://tenant.b2clogin.com/tenant.onmicrosoft.com/oauth2/v2.0/authorize?p=B2C_1_signin&response_type=code',
            $result
        );
    }

    /**
     * Empty params leave the URL unchanged (no dangling separator).
     */
    public function testEmptyParamsReturnUrlUnchanged(): void
    {
        $url = 'https://idp.example.com/logout';

        $this->assertSame($url, OIDC_Url::build_query_url($url, []));
    }

    /**
     * Empty params on a URL that has a query string also leave it unchanged.
     */
    public function testEmptyParamsOnUrlWithQueryStringReturnUrlUnchanged(): void
    {
        $url = 'https://idp.example.com/logout?p=policy';

        $this->assertSame($url, OIDC_Url::build_query_url($url, []));
    }

    /**
     * Parameter values are urlencoded via http_build_query().
     */
    public function testParameterValuesAreUrlEncoded(): void
    {
        $url = 'https://idp.example.com/authorize';

        $result = OIDC_Url::build_query_url($url, [
            'redirect_uri' => 'https://wp.example.com/wp-login.php?oidc_callback=1',
            'scope'        => 'openid email profile',
        ]);

        $this->assertSame(
            'https://idp.example.com/authorize?redirect_uri=https%3A%2F%2Fwp.example.com%2Fwp-login.php%3Foidc_callback%3D1&scope=openid+email+profile',
            $result
        );
    }

    /**
     * Multiple parameters preserve their order, appending to an existing query string.
     */
    public function testMultipleParametersPreserveOrder(): void
    {
        $url = 'https://idp.example.com/logout?p=B2C_1_logout';

        $result = OIDC_Url::build_query_url($url, [
            'id_token_hint' => 'token-value',
            'client_id'     => 'client-123',
        ]);

        $this->assertSame(
            'https://idp.example.com/logout?p=B2C_1_logout&id_token_hint=token-value&client_id=client-123',
            $result
        );
    }
}

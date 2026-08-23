<?php
/**
 * URL helper for building OIDC endpoint URLs.
 *
 * @package Secure_OIDC_Login
 */

declare( strict_types = 1 );

// Prevent direct file access
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Builds query URLs for OIDC endpoints that may already contain a query string.
 *
 * Some providers (e.g. Azure AD B2C) require a policy parameter on their
 * authorization and end-session endpoints, so the configured endpoint can
 * already carry a query string. Appending with a literal '?' would corrupt
 * the resulting URL.
 *
 * @since 1.3.2
 */
class OIDC_Url {
	/**
	 * Append query parameters to a URL that may already contain a query string.
	 *
	 * Parameters are encoded with http_build_query(), which urlencodes both keys
	 * and values (unlike add_query_arg()).
	 *
	 * @since 1.3.2
	 *
	 * @param string              $url    The endpoint URL.
	 * @param array<string,mixed> $params Query parameters to append.
	 * @return string The URL with parameters appended.
	 */
	public static function build_query_url( string $url, array $params ): string {
		$query = http_build_query( $params );

		if ( '' === $query ) {
			return $url;
		}

		$separator = str_contains( $url, '?' ) ? '&' : '?';

		return $url . $separator . $query;
	}
}

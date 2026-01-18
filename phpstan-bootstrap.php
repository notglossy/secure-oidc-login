<?php
/**
 * PHPStan bootstrap file.
 *
 * Defines constants used throughout the plugin for static analysis.
 *
 * @package Secure_OIDC_Login
 */

// Define plugin constants for PHPStan analysis
if ( ! defined( 'SECURE_OIDC_LOGIN_VERSION' ) ) {
	define( 'SECURE_OIDC_LOGIN_VERSION', '0.3.1' );
}

if ( ! defined( 'SECURE_OIDC_LOGIN_PLUGIN_DIR' ) ) {
	define( 'SECURE_OIDC_LOGIN_PLUGIN_DIR', __DIR__ . '/' );
}

if ( ! defined( 'SECURE_OIDC_LOGIN_PLUGIN_URL' ) ) {
	define( 'SECURE_OIDC_LOGIN_PLUGIN_URL', 'https://example.com/wp-content/plugins/secure-oidc-login/' );
}

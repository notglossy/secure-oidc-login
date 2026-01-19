<?php
/**
 * PHPUnit bootstrap file for Secure OIDC Login plugin tests.
 *
 * @package SecureOIDCLogin\Tests
 */

declare(strict_types=1);

// Load Composer autoloader
$autoloader = dirname(__DIR__) . '/vendor/autoload.php';
if (!file_exists($autoloader)) {
    echo 'Please run "composer install" before running tests.' . PHP_EOL;
    exit(1);
}
require_once $autoloader;

// Initialize Brain Monkey
require_once dirname(__DIR__) . '/vendor/antecedent/patchwork/Patchwork.php';

// Define WordPress constants needed by the plugin
if (!defined('ABSPATH')) {
    define('ABSPATH', '/var/www/html/');
}

if (!defined('SECURE_OIDC_LOGIN_VERSION')) {
    define('SECURE_OIDC_LOGIN_VERSION', '0.5.0');
}

if (!defined('SECURE_OIDC_LOGIN_PLUGIN_DIR')) {
    define('SECURE_OIDC_LOGIN_PLUGIN_DIR', dirname(__DIR__) . '/');
}

if (!defined('SECURE_OIDC_LOGIN_PLUGIN_URL')) {
    define('SECURE_OIDC_LOGIN_PLUGIN_URL', 'https://example.com/wp-content/plugins/secure-oidc-login/');
}

// Define WordPress authentication constants for crypto tests
if (!defined('SECURE_AUTH_KEY')) {
    define('SECURE_AUTH_KEY', 'test-secure-auth-key-for-unit-tests-only');
}

if (!defined('SECURE_AUTH_SALT')) {
    define('SECURE_AUTH_SALT', 'test-secure-auth-salt-for-unit-tests-only');
}

// Load stubs
require_once __DIR__ . '/stubs/class-wp-error.php';
require_once __DIR__ . '/stubs/class-secure-oidc-login.php';

// Load plugin class files
require_once dirname(__DIR__) . '/includes/class-oidc-config.php';
require_once dirname(__DIR__) . '/includes/class-oidc-token-response.php';
require_once dirname(__DIR__) . '/includes/class-oidc-claims.php';
require_once dirname(__DIR__) . '/includes/class-oidc-user-info.php';
require_once dirname(__DIR__) . '/includes/class-oidc-token-crypto.php';
require_once dirname(__DIR__) . '/includes/class-oidc-admin.php';
require_once dirname(__DIR__) . '/includes/class-oidc-client.php';
require_once dirname(__DIR__) . '/includes/class-oidc-user-handler.php';

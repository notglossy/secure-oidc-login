<?php
/**
 * Stub for WP_REST_Controller class used in testing.
 *
 * Provides minimal implementation of WordPress REST controller
 * for unit testing without WordPress core.
 *
 * @package SecureOIDCLogin\Tests\Stubs
 */

// Prevent direct file access
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Stub class for WP_REST_Controller.
 */
class WP_REST_Controller
{
    /**
     * The namespace for REST routes.
     *
     * @var string
     */
    protected $namespace = '';

    /**
     * The REST base for routes.
     *
     * @var string
     */
    protected $rest_base = '';
}

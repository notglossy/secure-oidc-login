<?php
/**
 * Stub for WP_REST_Server class used in testing.
 *
 * Provides minimal implementation of WordPress REST server constants
 * for unit testing without WordPress core.
 *
 * @package SecureOIDCLogin\Tests\Stubs
 */

// Prevent direct file access
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Stub class for WP_REST_Server.
 */
class WP_REST_Server
{
    /**
     * POST method constant.
     */
    const CREATABLE = 'POST';

    /**
     * GET method constant.
     */
    const READABLE = 'GET';

    /**
     * PUT/PATCH method constant.
     */
    const EDITABLE = 'PUT, PATCH';

    /**
     * DELETE method constant.
     */
    const DELETABLE = 'DELETE';

    /**
     * All methods constant.
     */
    const ALLMETHODS = 'GET, POST, PUT, PATCH, DELETE';
}

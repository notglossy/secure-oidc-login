<?php
/**
 * Stub for WP_REST_Request class used in testing.
 *
 * Provides minimal implementation of WordPress REST request object
 * for unit testing without WordPress core.
 *
 * @package SecureOIDCLogin\Tests\Stubs
 */

// Prevent direct file access
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Stub class for WP_REST_Request.
 *
 * @template T of array<string, mixed>
 */
class WP_REST_Request
{
    /**
     * Request parameters.
     *
     * @var array<string, mixed>
     */
    protected array $params = [];

    /**
     * Get a parameter from the request.
     *
     * @param string $key Parameter name.
     * @return mixed Parameter value.
     */
    public function get_param(string $key): mixed
    {
        return $this->params[$key] ?? null;
    }

    /**
     * Set a parameter in the request.
     *
     * @param string $key Parameter name.
     * @param mixed $value Parameter value.
     */
    public function set_param(string $key, mixed $value): void
    {
        $this->params[$key] = $value;
    }
}

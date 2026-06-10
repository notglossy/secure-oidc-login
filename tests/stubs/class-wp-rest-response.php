<?php
/**
 * Stub for WP_REST_Response class used in testing.
 *
 * Provides minimal implementation of WordPress REST response object
 * for unit testing without WordPress core.
 *
 * @package SecureOIDCLogin\Tests\Stubs
 */

// Prevent direct file access
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Stub class for WP_REST_Response.
 */
class WP_REST_Response
{
    /**
     * Response data.
     *
     * @var mixed
     */
    protected mixed $data;

    /**
     * Response status code.
     *
     * @var int
     */
    protected int $status;

    /**
     * Constructor.
     *
     * @param mixed $data Response data.
     * @param int $status HTTP status code.
     */
    public function __construct(mixed $data = null, int $status = 200)
    {
        $this->data = $data;
        $this->status = $status;
    }

    /**
     * Get response data.
     *
     * @return mixed Response data.
     */
    public function get_data(): mixed
    {
        return $this->data;
    }

    /**
     * Get response status code.
     *
     * @return int Status code.
     */
    public function get_status(): int
    {
        return $this->status;
    }

    /**
     * Response headers.
     *
     * @var array<string, string>
     */
    protected array $headers = [];

    /**
     * Set a response header.
     *
     * @param string $key Header name.
     * @param string $value Header value.
     */
    public function header(string $key, string $value): void
    {
        $this->headers[$key] = $value;
    }

    /**
     * Get response headers.
     *
     * @return array<string, string> Headers.
     */
    public function get_headers(): array
    {
        return $this->headers;
    }
}

<?php
/**
 * Stub for WP_User class used in testing.
 *
 * Provides minimal implementation of WordPress user object
 * for unit testing without WordPress core.
 *
 * @package SecureOIDCLogin\Tests\Stubs
 */

// Prevent direct file access
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Stub class for WP_User.
 */
class WP_User
{
    /**
     * User ID.
     *
     * @var int
     */
    public int $ID;

    /**
     * User email address.
     *
     * @var string
     */
    public string $user_email;

    /**
     * User login name.
     *
     * @var string
     */
    public string $user_login;

    /**
     * Constructor.
     *
     * @param int    $id         User ID.
     * @param string $user_login User login name.
     * @param string $user_email User email address.
     */
    public function __construct(int $id = 0, string $user_login = '', string $user_email = '')
    {
        $this->ID = $id;
        $this->user_login = $user_login;
        $this->user_email = $user_email;
    }
}

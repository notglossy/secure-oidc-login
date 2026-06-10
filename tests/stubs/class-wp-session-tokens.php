<?php
/**
 * Stub for the WordPress WP_Session_Tokens class.
 *
 * Records destroy_all() calls so tests can assert which users had their
 * sessions terminated.
 *
 * @package SecureOIDCLogin\Tests
 */

declare(strict_types=1);

if (!class_exists('WP_Session_Tokens')) {
    /**
     * Minimal WP_Session_Tokens stand-in for unit tests.
     */
    class WP_Session_Tokens
    {
        /**
         * User IDs whose sessions were destroyed via destroy_all().
         *
         * @var array<int, int>
         */
        public static array $destroyed_user_ids = [];

        /**
         * The user this instance manages sessions for.
         *
         * @var int
         */
        private int $user_id;

        /**
         * @param int $user_id The WordPress user ID.
         */
        private function __construct(int $user_id)
        {
            $this->user_id = $user_id;
        }

        /**
         * Mirror of WP_Session_Tokens::get_instance().
         *
         * @param int $user_id The WordPress user ID.
         * @return self Session manager for the user.
         */
        public static function get_instance(int $user_id): self
        {
            return new self($user_id);
        }

        /**
         * Record that all sessions for this user were destroyed.
         */
        public function destroy_all(): void
        {
            self::$destroyed_user_ids[] = $this->user_id;
        }

        /**
         * Reset recorded state between tests.
         */
        public static function reset(): void
        {
            self::$destroyed_user_ids = [];
        }
    }
}

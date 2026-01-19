<?php
/**
 * Minimal WP_Error stub for testing without WordPress.
 *
 * @package SecureOIDCLogin\Tests\Stubs
 */

declare(strict_types=1);

if (!class_exists('WP_Error')) {
    /**
     * Minimal WP_Error implementation for unit testing.
     *
     * Provides the core functionality needed by the plugin's value objects
     * and other classes that return WP_Error on validation failure.
     */
    class WP_Error
    {
        /** @var string Error code */
        private string $code;

        /** @var string Error message */
        private string $message;

        /** @var mixed Additional error data */
        private mixed $data;

        /** @var array<string, array{0: string, data: mixed}> All errors */
        private array $errors = [];

        /**
         * Constructor.
         *
         * @param string $code    Error code.
         * @param string $message Error message.
         * @param mixed  $data    Optional error data.
         */
        public function __construct(string $code = '', string $message = '', mixed $data = '')
        {
            if (!empty($code)) {
                $this->code = $code;
                $this->message = $message;
                $this->data = $data;
                $this->errors[$code] = [
                    $message,
                    'data' => $data,
                ];
            }
        }

        /**
         * Get the error code.
         *
         * @return string The error code.
         */
        public function get_error_code(): string
        {
            return $this->code ?? '';
        }

        /**
         * Get the error message.
         *
         * @param string $code Optional. Error code to get message for.
         * @return string The error message.
         */
        public function get_error_message(string $code = ''): string
        {
            if (empty($code)) {
                return $this->message ?? '';
            }

            if (isset($this->errors[$code])) {
                return $this->errors[$code][0];
            }

            return '';
        }

        /**
         * Get error data.
         *
         * @param string $code Optional. Error code to get data for.
         * @return mixed Error data or empty string.
         */
        public function get_error_data(string $code = ''): mixed
        {
            if (empty($code)) {
                return $this->data ?? '';
            }

            if (isset($this->errors[$code]['data'])) {
                return $this->errors[$code]['data'];
            }

            return '';
        }

        /**
         * Get all error codes.
         *
         * @return array<string> List of error codes.
         */
        public function get_error_codes(): array
        {
            return array_keys($this->errors);
        }

        /**
         * Get all error messages for a code.
         *
         * @param string $code Optional. Error code to get messages for.
         * @return array<string> List of error messages.
         */
        public function get_error_messages(string $code = ''): array
        {
            if (empty($code)) {
                return array_map(fn($e) => $e[0], $this->errors);
            }

            if (isset($this->errors[$code])) {
                return [$this->errors[$code][0]];
            }

            return [];
        }

        /**
         * Check if there are any errors.
         *
         * @return bool True if errors exist.
         */
        public function has_errors(): bool
        {
            return !empty($this->errors);
        }

        /**
         * Add an error.
         *
         * @param string $code    Error code.
         * @param string $message Error message.
         * @param mixed  $data    Optional error data.
         */
        public function add(string $code, string $message, mixed $data = ''): void
        {
            $this->errors[$code] = [
                $message,
                'data' => $data,
            ];

            if (!isset($this->code)) {
                $this->code = $code;
                $this->message = $message;
                $this->data = $data;
            }
        }
    }
}

/**
 * Check if a value is a WP_Error.
 *
 * @param mixed $thing Value to check.
 * @return bool True if WP_Error.
 */
if (!function_exists('is_wp_error')) {
    function is_wp_error(mixed $thing): bool
    {
        return $thing instanceof WP_Error;
    }
}

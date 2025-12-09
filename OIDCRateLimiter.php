<?php

// No direct call
if (!defined('YOURLS_ABSPATH')) {
    die();
}

/**
 * Class OIDCRateLimiter
 *
 * A rate limiter focused on monitoring and limiting authentication attempts based on IP address,
 * with support for automatic lockout mechanisms and cleanup operations.
 */
class OIDCRateLimiter {
    private static string $table_name;
    private static bool $initialized = false;

    /**
     * Initializes the OIDC Rate Limiter by creating the required database table if it does not exist.
     * The method ensures that the necessary table structure for rate limiting is present and
     * sets the initialization flag to prevent redundant executions.
     *
     * @return bool Returns true if the initialization is successful or has already been completed,
     *              false if an error occurs during table creation or verification.
     */
    public static function init(): bool
    {
        if (self::$initialized) {
            return true;
        }

        global $ydb;

        // Get database prefix with fallback
        $db_prefix = defined('YOURLS_DB_PREFIX') ? YOURLS_DB_PREFIX : 'yourls_';
        self::$table_name = $db_prefix . 'oidc_rate_limit';

        try {
            // Create the rate limit table if it doesn't exist
            $sql = "CREATE TABLE IF NOT EXISTS `" . self::$table_name . "` (
                `ip` VARCHAR(45) NOT NULL,
                `attempts` INT(11) NOT NULL DEFAULT 0,
                `locked_until` TIMESTAMP NULL DEFAULT NULL,
                `last_attempt` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                PRIMARY KEY (`ip`),
                KEY `locked_until` (`locked_until`)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4";

            $result = $ydb->fetchAffected($sql);

            if ($result === false) {
                error_log('OIDC Rate Limiter: Failed to create/verify table');
                return false;
            }

            self::$initialized = true;
            return true;

        } catch (Exception $e) {
            error_log('OIDC Rate Limiter initialization error: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Retrieves the configuration value based on the provided key. If the constant corresponding
     * to the key is defined, its value is returned; otherwise, the specified default value is used.
     *
     * @param string $key The name of the configuration key to retrieve.
     * @param mixed $default The default value to return if the configuration key is not defined.
     *
     * @return mixed Returns the configuration value if the key is defined, or the provided default value.
     */
    private static function getConfig(string $key, mixed $default): mixed
    {
        return defined($key) ? constant($key) : $default;
    }

    /**
     * Determines if the provided IP address is currently blocked due to rate limiting.
     * The method checks if the IP address is listed in the rate limits table with
     * an active lock or excessive attempts.
     *
     * @param string $ip The IP address to check for block status.
     *
     * @return bool Returns true if the IP is currently blocked, false otherwise.
     *              A block is determined by evaluating the `locked_until` timestamp.
     */
    public static function isBlocked(string $ip): bool
    {
        if (!self::init()) {
            return false; // If initialization fails, don't block
        }

        global $ydb;

        $ip = yourls_sanitize_ip($ip);

        try {
            $result = $ydb->fetchObject(
                "SELECT attempts, locked_until FROM `" . self::$table_name . "` WHERE ip = :ip",
                ['ip' => $ip]
            );

            if (!$result) {
                return false;
            }

            // Check if still locked
            if ($result->locked_until && strtotime($result->locked_until) > time()) {
                return true;
            }

            // Reset if the lock expired
            if ($result->locked_until && strtotime($result->locked_until) <= time()) {
                $ydb->fetchAffected(
                    "UPDATE `" . self::$table_name . "` SET attempts = 0, locked_until = NULL WHERE ip = :ip",
                    ['ip' => $ip]
                );
            }

            return false;

        } catch (Exception $e) {
            error_log('OIDC Rate Limiter isBlocked error: ' . $e->getMessage());
            return false; // On error, don't block
        }
    }

    /**
     * Records an authentication attempt for a specified IP address. If the attempt is unsuccessful,
     * it increments the failure count and applies a lockout if the maximum number of attempts is exceeded.
     * If the attempt is successful, it clears any previous failure records for the IP.
     *
     * @param string $ip The IP address of the client making the authentication attempt.
     * @param bool $success Determines whether the authentication attempt was successful.
     *                      If true, all failure records for the IP will be cleared.
     *                      Defaults to false for failed attempts.
     * @return void
     */
    public static function recordAttempt(string $ip, bool $success = false): void
    {
        if (!self::init()) {
            return; // If initialization fails, silently continue
        }

        global $ydb;

        $ip = yourls_sanitize_ip($ip);

        try {
            if ($success) {
                // Clear attempts on success
                $ydb->fetchAffected(
                    "DELETE FROM `" . self::$table_name . "` WHERE ip = :ip",
                    ['ip' => $ip]
                );
                return;
            }

            // Increment failed attempts
            $result = $ydb->fetchObject(
                "SELECT attempts FROM `" . self::$table_name . "` WHERE ip = :ip",
                ['ip' => $ip]
            );

            $attempts = $result ? $result->attempts + 1 : 1;
            $locked_until = null;

            // Use fallback values if constants are not defined
            $max_attempts = self::getConfig('OIDC_MAX_AUTH_ATTEMPTS', 5);
            $lockout_time = self::getConfig('OIDC_AUTH_LOCKOUT_TIME', 900);

            if ($attempts >= $max_attempts) {
                $locked_until = date('Y-m-d H:i:s', time() + $lockout_time);
            }

            if ($result) {
                $ydb->fetchAffected(
                    "UPDATE `" . self::$table_name . "` SET attempts = :attempts, locked_until = :locked_until WHERE ip = :ip",
                    ['ip' => $ip, 'attempts' => $attempts, 'locked_until' => $locked_until]
                );
            } else {
                $ydb->fetchAffected(
                    "INSERT INTO `" . self::$table_name . "` (ip, attempts, locked_until) VALUES (:ip, :attempts, :locked_until)",
                    ['ip' => $ip, 'attempts' => $attempts, 'locked_until' => $locked_until]
                );
            }

        } catch (Exception $e) {
            error_log('OIDC Rate Limiter recordAttempt error: ' . $e->getMessage());
            // Continue silently on error
        }
    }

    /**
     * Cleans up the rate limiter database by removing expired locks and outdated records.
     * This method deletes entries where the lock expiration time has passed or the last
     * attempt occurred more than 24 hours ago. Relies on successful initialization before execution.
     *
     * @return void
     */
    public static function cleanup(): void
    {
        if (!self::init()) {
            return;
        }

        global $ydb;

        try {
            // Remove expired locks and old records (older than 24 hours)
            $ydb->fetchAffected(
                "DELETE FROM `" . self::$table_name . "` WHERE locked_until < NOW() OR last_attempt < DATE_SUB(NOW(), INTERVAL 24 HOUR)"
            );
        } catch (Exception $e) {
            error_log('OIDC Rate Limiter cleanup error: ' . $e->getMessage());
        }
    }
}

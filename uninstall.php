<?php
/*
 * Keycloak Plugin Uninstall Script
 * This file is automatically executed when the plugin is deleted
 */

// No direct call - YOURLS sets YOURLS_UNINSTALL_PLUGIN when calling this file
if (!defined('YOURLS_UNINSTALL_PLUGIN')) {
    die();
}

// Don't run during upgrades, only during actual uninstallation
if (defined('YOURLS_UPGRADING')) {
    return;
}

global $ydb;

try {
    // Get database prefix with fallback
    $db_prefix = defined('YOURLS_DB_PREFIX') ? YOURLS_DB_PREFIX : 'yourls_';
    $table_name = $db_prefix . 'oidc_rate_limit';

    // Check if the table exists before dropping
    $table_exists = $ydb->fetchValue("SHOW TABLES LIKE '$table_name'");

    if ($table_exists) {
        // Drop the rate limits table
        $sql = "DROP TABLE IF EXISTS `$table_name`";
        $result = $ydb->fetchAffected($sql);

        if ($result !== false) {
            error_log("Keycloak plugin: Successfully removed rate limiting table: $table_name");
        }
    }

    // Clear any OIDC-related sessions if the session is active
    if (session_status() === PHP_SESSION_ACTIVE) {
        $session_keys_to_clear = [
            'oidc_access_token',
            'oidc_refresh_token',
            'oidc_token_expires_at',
            'oidc_id_token',
            'oidc_username',
            'oauth2state',
            'oauth2_code_verifier'
        ];

        foreach ($session_keys_to_clear as $key) {
            if (isset($_SESSION[$key])) {
                unset($_SESSION[$key]);
            }
        }

        error_log("Keycloak plugin: Cleared OIDC session data");
    }

    error_log("Keycloak plugin: Uninstall completed successfully");

} catch (Exception $e) {
    error_log("Keycloak plugin uninstall error: " . $e->getMessage());
}

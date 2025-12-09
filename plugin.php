<?php
/*
Plugin Name: Keycloak
Plugin URI: https://github.com/julabo/yourls_keycloak
Description: Provides Keycloak user authentication
Author: Jan Leehr
Author URI: https://julabo.com
Version: 1.0.0
*/

// No direct call
use League\OAuth2\Client\Token\AccessToken;
use Stevenmaguire\OAuth2\Client\Provider\Keycloak;

if (!defined('YOURLS_ABSPATH')) {
    die();
}

// Plugin activation hook
yourls_add_action('activated_keycloak/plugin.php', 'oidc_activate');
function oidc_activate() {
    require_once __DIR__ . '/OIDCRateLimiter.php';

    if (OIDCRateLimiter::init()) {
        yourls_add_notice('Keycloak plugin activated successfully. Rate limiting table created.');
    } else {
        yourls_add_notice('Keycloak plugin activated with warnings. Check error logs.', 'error');
    }
}

// Plugin deactivation hook
yourls_add_action('deactivated_keycloak/plugin.php', 'oidc_deactivate');
function oidc_deactivate() {
    // Clear any OIDC-related sessions
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
    }

    yourls_add_notice('Keycloak plugin deactivated. Sessions cleared. Database table preserved.');
}

// Security constants
if (!defined('OIDC_BYPASS_YOURLS_AUTH')) {
    define('OIDC_BYPASS_YOURLS_AUTH', false);
}

// Rate limiting constants
if (!defined('OIDC_MAX_AUTH_ATTEMPTS')) {
    define('OIDC_MAX_AUTH_ATTEMPTS', 5);
}
if (!defined('OIDC_AUTH_LOCKOUT_TIME')) {
    define('OIDC_AUTH_LOCKOUT_TIME', 900); // 15 minutes
}
if (!defined('OIDC_TOKEN_REFRESH_THRESHOLD')) {
    define('OIDC_TOKEN_REFRESH_THRESHOLD', 300); // 5 minutes before expiry
}

// Load configuration from environment or constants
function oidc_get_config($key, $default = null) {
    $env_key = 'OIDC_' . $key;
    $const_key = 'OIDC_' . $key;

    // Try the environment variable first
    $value = getenv($env_key) ?: ($_ENV[$env_key] ?? null);

    // Fall back to constant
    if ($value === null && defined($const_key)) {
        $value = constant($const_key);
    }

    return $value ?: $default;
}

// Early exit if the required configuration is missing
$required_configs = ['BASE_URL', 'REALM', 'CLIENT_NAME', 'CLIENT_SECRET', 'REDIRECT_URL'];
foreach ($required_configs as $config) {
    if (!oidc_get_config($config)) {
        if (function_exists('yourls_add_notice')) {
            yourls_add_notice('OIDC plugin: Required configuration ' . $config . ' is missing. Plugin disabled.', 'error');
        }
        return;
    }
}

// Validate URLs
if (!filter_var(oidc_get_config('BASE_URL'), FILTER_VALIDATE_URL) ||
    !filter_var(oidc_get_config('REDIRECT_URL'), FILTER_VALIDATE_URL)) {
    if (function_exists('yourls_add_notice')) {
        yourls_add_notice('OIDC plugin: Invalid URL configuration. Plugin disabled.', 'error');
    }
    return;
}

// Start the session securely
if (session_status() === PHP_SESSION_NONE) {
    ini_set('session.cookie_httponly', 1);
    ini_set('session.cookie_secure', yourls_is_ssl() ? 1 : 0);
    ini_set('session.use_strict_mode', 1);
    ini_set('session.cookie_samesite', 'Lax');
    ini_set('session.gc_maxlifetime', 3600); // 1 hour
    ini_set('session.cookie_lifetime', 0); // Session cookie
    session_start();
}

// Load dependencies with error handling
if (!file_exists(__DIR__ . '/vendor/autoload.php')) {
    if (function_exists('yourls_add_notice')) {
        yourls_add_notice('OIDC plugin: Composer dependencies not installed. Run composer install in plugin directory.', 'error');
    }
    return;
}

require_once __DIR__ . '/vendor/autoload.php';
require_once __DIR__ . '/OIDCRateLimiter.php';

// Initialize rate limiter only if the plugin is active (not during activation)
if (!yourls_is_installing() && !defined('YOURLS_INSTALLING')) {
    OIDCRateLimiter::init();
}

// Initialize OIDC provider with validation
function oidc_get_provider(): ?Keycloak
{
    static $oidc = null;

    if ($oidc === null) {
        try {
            $oidc = new Keycloak([
                'authServerUrl'         => rtrim(oidc_get_config('BASE_URL'), '/'),
                'realm'                 => oidc_get_config('REALM'),
                'clientId'              => oidc_get_config('CLIENT_NAME'),
                'clientSecret'          => oidc_get_config('CLIENT_SECRET'),
                'redirectUri'           => oidc_get_config('REDIRECT_URL'),
            ]);
        } catch (Exception $e) {
            error_log('OIDC provider initialization error: ' . $e->getMessage());
            yourls_die('OIDC plugin: Failed to initialize provider.');
        }
    }

    return $oidc;
}

// Token refresh functionality
function oidc_refresh_token_if_needed(): bool
{
    // If we don't have tokens in session, don't attempt refresh
    // This is normal for cookie-based authentication after redirect
    if (!isset($_SESSION['oidc_access_token']) || !isset($_SESSION['oidc_refresh_token'])) {
        return true; // Return true because this is not an error condition
    }

    $expires_at = $_SESSION['oidc_token_expires_at'] ?? 0;
    $refresh_threshold = time() + OIDC_TOKEN_REFRESH_THRESHOLD;

    if ($expires_at > $refresh_threshold) {
        return true; // Token still valid
    }

    try {
        $oidc = oidc_get_provider();

        $refreshToken = new AccessToken([
            'refresh_token' => $_SESSION['oidc_refresh_token']
        ]);

        $newToken = $oidc->getAccessToken('refresh_token', [
            'refresh_token' => $refreshToken->getRefreshToken()
        ]);

        // Update session with new tokens
        $_SESSION['oidc_access_token'] = $newToken->getToken();
        $_SESSION['oidc_token_expires_at'] = $newToken->getExpires();

        if ($newToken->getRefreshToken()) {
            $_SESSION['oidc_refresh_token'] = $newToken->getRefreshToken();
        }

        return true;

    } catch (Exception $e) {
        error_log('Token refresh failed: ' . $e->getMessage());

        // Clear invalid tokens but don't fail authentication
        // The cookie is still valid for authentication purposes
        unset($_SESSION['oidc_access_token']);
        unset($_SESSION['oidc_refresh_token']);
        unset($_SESSION['oidc_token_expires_at']);

        // Return true because cookie-based authentication doesn't require token refresh
        return true;
    }
}

// Secure cookie name generation
function oidc_get_cookie_name(): string
{
    return 'OIDC_user_' . substr(hash('sha256', YOURLS_COOKIEKEY . 'oidc'), 0, 8);
}

// Validate OIDC cookie and refresh token if needed
function oidc_validate_cookie() {
    $cookie_name = oidc_get_cookie_name();

    if (!isset($_COOKIE[$cookie_name])) {
        return false;
    }

    $cookie_data = $_COOKIE[$cookie_name];

    // Use our own decryption method
    $decoded = base64_decode($cookie_data);
    if (!$decoded) {
        return false;
    }

    $parts = explode('|', $decoded);
    if (count($parts) !== 4) { // username|timestamp|hash|signature
        return false;
    }

    $signature_check = array_pop($parts);
    $original_value = implode('|', $parts);
    $expected_signature = hash_hmac('sha256', $original_value, YOURLS_COOKIEKEY);

    if (!hash_equals($expected_signature, $signature_check)) {
        return false;
    }

    // Now parse the original value (username|timestamp|hash)
    $value_parts = explode('|', $original_value, 3);
    if (count($value_parts) !== 3) {
        return false;
    }

    list($username, $timestamp, $hash) = $value_parts;

    // Check timestamp (validate within cookie lifetime)
    $cookie_lifetime = yourls_get_cookie_life();
    if (time() - intval($timestamp) > $cookie_lifetime) {
        return false;
    }

    // Validate hash
    $expected_hash = hash_hmac('sha256', $username . $timestamp, YOURLS_COOKIEKEY);
    if (!hash_equals($expected_hash, $hash)) {
        return false;
    }

    // Try to refresh the token if needed
    if (!oidc_refresh_token_if_needed()) {
        // Token refresh failed, invalidate cookie
        oidc_clear_cookie();
        return false;
    }

    return $username;
}

// Secure cookie setting
function oidc_set_secure_cookie($username) {
    $cookie_name = oidc_get_cookie_name();
    $timestamp = time();
    $hash = hash_hmac('sha256', $username . $timestamp, YOURLS_COOKIEKEY);
    $value = $username . '|' . $timestamp . '|' . $hash;

    // Use our own secure method instead of yourls_auth_signature
    $signature = hash_hmac('sha256', $value, YOURLS_COOKIEKEY);
    $encrypted_value = base64_encode($value . '|' . $signature);

    $time = time() + yourls_get_cookie_life();
    $path = yourls_apply_filter('setcookie_path', '/');
    $domain = yourls_apply_filter('setcookie_domain', parse_url(yourls_get_yourls_site(), PHP_URL_HOST));
    $secure = yourls_apply_filter('setcookie_secure', yourls_is_ssl());
    $httponly = yourls_apply_filter('setcookie_httponly', true);

    setcookie($cookie_name, $encrypted_value, [
        'expires' => $time,
        'path' => $path,
        'domain' => $domain,
        'secure' => $secure,
        'httponly' => $httponly,
        'samesite' => 'Lax'
    ]);
}

// Clear OIDC cookie
function oidc_clear_cookie() {
    $cookie_name = oidc_get_cookie_name();
    $path = yourls_apply_filter('setcookie_path', '/');
    $domain = yourls_apply_filter('setcookie_domain', parse_url(yourls_get_yourls_site(), PHP_URL_HOST));
    $secure = yourls_apply_filter('setcookie_secure', yourls_is_ssl());
    $httponly = yourls_apply_filter('setcookie_httponly', true);

    setcookie($cookie_name, '', [
        'expires' => time() - 3600,
        'path' => $path,
        'domain' => $domain,
        'secure' => $secure,
        'httponly' => $httponly,
        'samesite' => 'Lax'
    ]);
}

// Helper function to remove query arguments from URL
function oidc_remove_query_args($args_to_remove, $url) {
    $url_parts = parse_url($url);

    if (!isset($url_parts['query'])) {
        return $url;
    }

    parse_str($url_parts['query'], $query_params);

    // Remove specified arguments
    foreach ($args_to_remove as $arg) {
        unset($query_params[$arg]);
    }

    // Rebuild the URL
    $new_url = '';

    if (isset($url_parts['scheme'])) {
        $new_url .= $url_parts['scheme'] . '://';
    }

    if (isset($url_parts['host'])) {
        $new_url .= $url_parts['host'];
    }

    if (isset($url_parts['port'])) {
        $new_url .= ':' . $url_parts['port'];
    }

    if (isset($url_parts['path'])) {
        $new_url .= $url_parts['path'];
    }

    if (!empty($query_params)) {
        $new_url .= '?' . http_build_query($query_params);
    }

    if (isset($url_parts['fragment'])) {
        $new_url .= '#' . $url_parts['fragment'];
    }

    return $new_url;
}

yourls_add_filter('is_valid_user', 'oidc_auth');
function oidc_auth($valid) {
    // Skip for API requests
    if (yourls_is_API()) {
        return $valid;
    }

    // Check existing valid authentication first
    if ($valid) {
        return $valid;
    }

    $client_ip = yourls_get_IP();

    // Check rate limiting
    if (OIDCRateLimiter::isBlocked($client_ip)) {
        yourls_die('Too many authentication attempts. Please try again later.', 'Authentication Blocked', 429);
    }

    // Check for a valid OIDC cookie first (before handling callback)
    $username = oidc_validate_cookie();
    if ($username) {
        yourls_set_user($username);
        return true;
    }

    // Handle OAuth2 callback (only if we have code and state, but no valid cookie)
    if (isset($_GET['code']) && isset($_GET['state'])) {
        oidc_handle_callback();
        return true;
    }

    // Only redirect if we don't have any Keycloak session parameters
    // This prevents redirect loops after failed authentication
    if (!isset($_GET['session_state']) && !isset($_GET['iss'])) {
        oidc_redirect_to_provider();
    }

    return false;
}

function oidc_handle_callback() {
    $client_ip = yourls_get_IP();

    // Validate state parameter
    if (empty($_GET['state']) || empty($_SESSION['oauth2state']) ||
        !hash_equals($_SESSION['oauth2state'], $_GET['state'])) {

        unset($_SESSION['oauth2state']);
        unset($_SESSION['oauth2_code_verifier']);
        OIDCRateLimiter::recordAttempt($client_ip, false);
        yourls_die('OIDC: Invalid state parameter. Possible CSRF attack.');
    }

    unset($_SESSION['oauth2state']);

    $oidc = oidc_get_provider();

    try {
        // Get access token with PKCE
        $tokenParams = [
            'code' => $_GET['code']
        ];

        // Add PKCE code verifier if it was used
        if (isset($_SESSION['oauth2_code_verifier'])) {
            $tokenParams['code_verifier'] = $_SESSION['oauth2_code_verifier'];
            unset($_SESSION['oauth2_code_verifier']);
        }

        $token = $oidc->getAccessToken('authorization_code', $tokenParams);

        // Get user information
        $resource_owner = $oidc->getResourceOwner($token);
        $user_data = $resource_owner->toArray();
        $username = $user_data['preferred_username'] ?? null;

        if (!$username) {
            OIDCRateLimiter::recordAttempt($client_ip, false);
            yourls_die('OIDC: Unable to retrieve username from provider.');
        }

        // Validate username (allow various formats but prevent malicious input)
        if (empty($username) || strlen($username) > 255 ||
            preg_match('/[<>"\'\\\\\x00-\x1F\x7F]/', $username)) {
            OIDCRateLimiter::recordAttempt($client_ip, false);
            yourls_die('OIDC: Invalid username format.');
        }

        // Store tokens securely in session
        $_SESSION['oidc_access_token'] = $token->getToken();
        $_SESSION['oidc_refresh_token'] = $token->getRefreshToken();
        $_SESSION['oidc_token_expires_at'] = $token->getExpires();
        $_SESSION['oidc_id_token'] = $token->getValues()['id_token'] ?? null;
        $_SESSION['oidc_username'] = $username;

        // Record successful authentication
        OIDCRateLimiter::recordAttempt($client_ip, true);

        // Set secure cookie
        oidc_set_secure_cookie($username);

        // Set user in YOURLS
        yourls_set_user($username);

        // Clean redirect to avoid replay attacks - redirect to base admin URL
        header('Location: ' . YOURLS_SITE . '/admin/');
        exit;

    } catch (Exception $e) {
        OIDCRateLimiter::recordAttempt($client_ip, false);
        error_log('OIDC authentication error: ' . $e->getMessage());
        yourls_die('OIDC: Authentication failed. Please try again.');
    }
}

function oidc_redirect_to_provider() {
    $oidc = oidc_get_provider();

    try {
        // Generate and store state
        $state = bin2hex(random_bytes(32));
        $_SESSION['oauth2state'] = $state;

        // Generate PKCE parameters
        $codeVerifier = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
        $codeChallenge = rtrim(strtr(base64_encode(hash('sha256', $codeVerifier, true)), '+/', '-_'), '=');

        // Store code verifier in session for later use
        $_SESSION['oauth2_code_verifier'] = $codeVerifier;

        $authUrl = $oidc->getAuthorizationUrl([
            'state' => $state,
            'scope' => 'openid profile email offline_access', // offline_access for refresh tokens
            'code_challenge' => $codeChallenge,
            'code_challenge_method' => 'S256'
        ]);

        header('Location: ' . $authUrl);
        exit;

    } catch (Exception $e) {
        error_log('OIDC redirect error: ' . $e->getMessage());
        yourls_die('OIDC: Unable to redirect to authentication provider.');
    }
}

yourls_add_action('logout', 'oidc_logout');
function oidc_logout() {
    // Clear YOURLS cookie
    yourls_store_cookie(null);

    // Clear OIDC cookie
    oidc_clear_cookie();

    // Get stored tokens for logout
    $id_token = $_SESSION['oidc_id_token'] ?? null;

    // Clear session
    if (session_status() === PHP_SESSION_ACTIVE) {
        session_destroy();
    }

    // Redirect to Keycloak logout
    $logout_url = rtrim(oidc_get_config('BASE_URL'), '/') . '/realms/' . urlencode(oidc_get_config('REALM')) . '/protocol/openid-connect/logout';

    $logout_params = [
        'client_id' => oidc_get_config('CLIENT_NAME'),
        'post_logout_redirect_uri' => YOURLS_SITE
    ];

    if ($id_token) {
        $logout_params['id_token_hint'] = $id_token;
    }

    $full_logout_url = $logout_url . '?' . http_build_query($logout_params);
    header('Location: ' . $full_logout_url);
    exit;
}

// Cleanup old rate limit records periodically
yourls_add_action('init', function() {
    // Run cleanup on 1% of requests
    if (mt_rand(1, 100) === 1) {
        OIDCRateLimiter::cleanup();
    }
});

// Enhanced flood protection with OIDC awareness
yourls_add_filter('shunt_check_IP_flood', 'oidc_check_ip_flood');
function oidc_check_ip_flood($ip): bool
{
    // Don't touch API logic
    if (yourls_is_API()) {
        return false;
    }

    yourls_do_action('pre_check_ip_flood', $ip);

    // Skip if flood protection disabled
    if ((defined('YOURLS_FLOOD_DELAY_SECONDS') && YOURLS_FLOOD_DELAY_SECONDS === 0) ||
        !defined('YOURLS_FLOOD_DELAY_SECONDS') ||
        yourls_is_installing()) {
        return true;
    }

    // Don't throttle authenticated users (OIDC or YOURLS)
    if (yourls_is_private()) {
        $oidc_user = oidc_validate_cookie();
        $yourls_auth = isset($_COOKIE[yourls_cookie_name()]) && yourls_check_auth_cookie();

        if ($oidc_user || $yourls_auth) {
            if ($yourls_auth) {
                yourls_store_cookie(YOURLS_USER);
            }
            return true;
        }
    }

    // Check IP whitelist
    if (defined('YOURLS_FLOOD_IP_WHITELIST') && YOURLS_FLOOD_IP_WHITELIST) {
        $whitelist_ips = array_map('trim', explode(',', YOURLS_FLOOD_IP_WHITELIST));
        $current_ip = $ip ?: yourls_get_IP();

        if (in_array($current_ip, $whitelist_ips, true)) {
            return true;
        }
    }

    $ip = $ip ? yourls_sanitize_ip($ip) : yourls_get_IP();
    yourls_do_action('check_ip_flood', $ip);

    global $ydb;
    $table = YOURLS_DB_TABLE_URL;

    $lasttime = $ydb->fetchValue(
        "SELECT `timestamp` FROM $table WHERE `ip` = :ip ORDER BY `timestamp` DESC LIMIT 1",
        ['ip' => $ip]
    );

    if ($lasttime) {
        $now = time();
        $then = strtotime($lasttime);

        if (($now - $then) <= YOURLS_FLOOD_DELAY_SECONDS) {
            yourls_do_action('ip_flood', $ip, $now - $then);
            yourls_die(
                yourls__('Too many URLs added too fast. Slow down please.'),
                yourls__('Too Many Requests'),
                429
            );
        }
    }

    return true;
}


# OIDC Keycloak Plugin for YOURLS

This plugin provides OpenID Connect (OIDC) authentication integration with Keycloak for YOURLS,
allowing users to authenticate using their Keycloak credentials instead of traditional YOURLS authentication.

## Features

- **OpenID Connect Authentication**: Seamless integration with Keycloak OIDC
- **Rate Limiting**: Built-in protection against brute force attacks
- **Token Management**: Automatic token refresh and session handling
- **Security**: Bypass YOURLS native authentication when enabled
- **Database Integration**: Stores rate limiting data in YOURLS database

## Installation

1. Extract the plugin files to the `user/plugins/keycloak/` directory in your YOURLS installation
2. Run `composer install` in the plugin directory to install dependencies
3. Enable the plugin in your YOURLS admin panel or by adding it to your configuration

## Configuration Options

The plugin supports configuration through environment variables (recommended) or direct configuration constants.
All settings can be defined in a `.env` file or YOURLS configuration.

### OIDC Provider Settings

| Setting | Environment Variable | Required | Description |
|---------|---------------------|----------|-------------|
| Base URL | `OIDC_BASE_URL` | Yes | The base URL of your Keycloak server (e.g., `https://auth.example.com`) |
| Realm | `OIDC_REALM` | Yes | The Keycloak realm name |
| Client Name | `OIDC_CLIENT_NAME` | Yes | The client ID configured in Keycloak |
| Client Secret | `OIDC_CLIENT_SECRET` | Yes | The client secret from Keycloak |
| Redirect URL | `OIDC_REDIRECT_URL` | Yes | The callback URL (typically `https://yourdomain.com/admin/`) |

### Rate Limiting Settings

| Setting | Environment Variable | Default | Description |
|---------|---------------------|---------|-------------|
| Max Attempts | `OIDC_MAX_AUTH_ATTEMPTS` | 5 | Maximum failed authentication attempts before lockout |
| Lockout Time | `OIDC_AUTH_LOCKOUT_TIME` | 900 | Lockout duration in seconds (900 = 15 minutes) |
| Token Refresh | `OIDC_TOKEN_REFRESH_THRESHOLD` | 300 | Time in seconds before token expiry to refresh (300 = 5 minutes) |

### Security Settings

| Setting | Environment Variable | Default | Description |
|---------|---------------------|---------|-------------|
| Bypass YOURLS Auth | `OIDC_BYPASS_YOURLS_AUTH` | true | Whether to bypass native YOURLS authentication |

## Environment Configuration Example

Create or update your `.env` file with the following settings:

```dotenv
# OIDC Configuration
OIDC_BASE_URL=https://auth.example.com
OIDC_REALM=YourRealm
OIDC_CLIENT_NAME=yourls
OIDC_CLIENT_SECRET=your-client-secret-here
OIDC_REDIRECT_URL=https://yourdomain.com/admin/

# Rate Limiting Configuration
OIDC_MAX_AUTH_ATTEMPTS=5
OIDC_AUTH_LOCKOUT_TIME=900
OIDC_TOKEN_REFRESH_THRESHOLD=300

# Security Settings
OIDC_BYPASS_YOURLS_AUTH=true
```


## Keycloak Configuration

### Client Setup

1. **Create a new client** in your Keycloak realm
2. **Set Client ID** to match `OIDC_CLIENT_NAME`
3. **Enable Client Authentication** (for confidential clients)
4. **Set Valid Redirect URIs** to your `OIDC_REDIRECT_URL`
5. **Copy the Client Secret** to use as `OIDC_CLIENT_SECRET`
6. **Proof Key for Code Exchange Code Challenge Method** set to `S256`

### Required Client Settings

- **Access Type**: Confidential
- **Standard Flow Enabled**: ON
- **Direct Access Grants Enabled**: ON (optional)
- **Valid Redirect URIs**: Your YOURLS admin URL
- **Web Origins**: Your YOURLS domain

## Security Considerations

### Rate Limiting

The plugin automatically creates a database table for tracking failed authentication attempts:

- **IP-based tracking**: Each IP address is tracked separately
- **Progressive lockout**: After reaching max attempts, IP is locked for the configured time
- **Automatic cleanup**: Old records and expired locks are automatically cleaned
- **Reset on success**: Successful authentication clears the attempt counter

### Token Security

- Tokens are handled securely and refreshed automatically
- Session management integrates with YOURLS native sessions
- Configurable refresh threshold which prevents token expiration during active use

## Database Tables

The plugin creates the following table:

```sql
CREATE TABLE `yourls_oidc_rate_limit` (
    `ip` VARCHAR(45) NOT NULL,
    `attempts` INT(11) NOT NULL DEFAULT 0,
    `locked_until` TIMESTAMP NULL DEFAULT NULL,
    `last_attempt` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`ip`),
    KEY `locked_until` (`locked_until`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
```

## Troubleshooting

### Common Issues
1. **"Client not found" error**
    - Verify matches the client ID in Keycloak `OIDC_CLIENT_NAME`
    - Ensure the client is enabled in Keycloak

2. **"Invalid redirect URI" error**
    - Check that matches exactly with Keycloak client settings `OIDC_REDIRECT_URL`
    - Ensure the URL includes the protocol (https://)

3. **Rate limiting not working**
    - Verify database permissions allow table creation
    - Check that the rate limit constants are properly defined

4. **Authentication loop**
    - Confirm is set to `true` `OIDC_BYPASS_YOURLS_AUTH`
    - Verify session handling is working correctly

### Debugging
Enable debugging by checking YOURLS error logs and Keycloak server logs. The plugin respects YOURLS debugging settings.
## Dependencies
- **PHP**: >= 7.4
- **YOURLS**: >= 1.8
- **Composer packages**:
    - `league/oauth2-client`
    - `stevenmaguire/oauth2-keycloak`

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for full license text.

## Support
For issues and feature requests, please refer to your YOURLS plugin documentation or contact your system administrator.
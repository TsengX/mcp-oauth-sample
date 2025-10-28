# MCP OAuth Sample

A demonstration server that integrates OAuth authentication with MCP functionality, using statically pre-registered client credentials, ideal for development and debugging purposes.

## Features

- ✅ **Single-Port Deployment**: OAuth and MCP functionality run on the same port
- ✅ **Static Client Registration**: Uses pre-configured `client_id` and `client_secret`
- ✅ **No Dynamic Registration**: Suitable for single-client usage scenarios
- ✅ **Easy to Use**: Start with `uv` in one command
- ✅ **Production-Ready**: Supports custom credentials and configuration files

## Quick Start

### Prerequisites

- Python 3.10+
- [uv](https://github.com/astral-sh/uv) - Python package manager

### Install uv

```bash
# macOS / Linux
curl -LsSf https://astral.sh/uv/install.sh | sh

# Or using Homebrew (macOS)
brew install uv

# Windows
powershell -c "irm https://astral.sh/uv/install.ps1 | iex"
```

### Clone the Repository

```bash
git clone https://github.com/TsengX/mcp-oauth-sample.git
cd mcp-oauth-sample
```

### Start the Server

#### Method 1: Using Default Settings

```bash
# Use default port 9003 and default credentials
uv run python mcp_simple_auth/statically_registered_client_server.py

# Or using uv script command
uv run mcp-static-auth
```

#### Method 2: Custom Port and Credentials

```bash
uv run python mcp_simple_auth/statically_registered_client_server.py \
    --port 9003 \
    --client-id "my-client-001" \
    --client-secret "my-secure-secret-12345"
```

#### Method 3: Using Environment Variables

```bash
export MCP_STATIC_CLIENT_ID="my-client-001"
export MCP_STATIC_CLIENT_SECRET="my-secure-secret"
export MCP_STATIC_PORT=9003

uv run python mcp_simple_auth/statically_registered_client_server.py
```

### Server Endpoints

After starting, the server provides the following endpoints:

- **MCP Endpoint**: `http://localhost:9003/mcp`
- **OAuth Authorization**: `http://localhost:9003/authorize`
- **OAuth Token**: `http://localhost:9003/token`
- **Login Page**: `http://localhost:9003/login`
- **Token Introspection**: `http://localhost:9003/introspect`

## Configuration

### Environment Variables

Supported environment variables (with `MCP_STATIC_` prefix):

- `MCP_STATIC_CLIENT_ID`: Pre-registered client ID
- `MCP_STATIC_CLIENT_SECRET`: Pre-registered client secret
- `MCP_STATIC_PORT`: Server listening port
- `MCP_STATIC_HOST`: Server host address

### Command Line Arguments

```bash
python mcp_simple_auth/statically_registered_client_server.py --help
```

Available arguments:
- `--port`: Listening port (default: 9003)
- `--client-id`: Client ID (default: static-mcp-client-001)
- `--client-secret`: Client secret (default: your-secret-key-change-this-in-production)

## Client Integration

### Java Client Example

```java
public class McpClient {
    // Use the same credentials as server configuration
    private static final String CLIENT_ID = "static-mcp-client-001";
    private static final String CLIENT_SECRET = "your-secret-key-change-this-in-production";
    private static final String SERVER_URL = "http://localhost:9003";
    
    // OAuth endpoints
    private static final String AUTHORIZE_ENDPOINT = SERVER_URL + "/authorize";
    private static final String TOKEN_ENDPOINT = SERVER_URL + "/token";
    private static final String MCP_ENDPOINT = SERVER_URL + "/mcp";
    
    // ... implement OAuth flow
}
```

### Using Pre-registered Credentials

No dynamic registration needed, directly use the pre-registered `client_id` and `client_secret`:

1. Request authorization URL: `GET /authorize`
2. User logs in via browser
3. Get authorization code
4. Exchange token: `POST /token` (using pre-registered credentials)

## OAuth Flow

### Flow Diagram

```
Client                          Server (9003)
  │                                │
  ├── GET /authorize ────────────►│
  │                                │
  │←── Login page URL ────────────┤
  │                                │
  └──► Open browser to login ───►│
  │                                │
  │←── Callback with auth code ───┤
  │    /callback?code=xxx          │
  │                                │
  ├── POST /token ────────────────►│
  │    (using pre-registered creds)│
  │                                │
  │←── access_token ───────────────┤
  │                                │
  ├── Use token to access MCP ───►│
  │    Authorization: Bearer token  │
  │                                │
  │←── MCP Response ───────────────┤
```

## Default Credentials

Development environment default credentials:

- **Client ID**: `static-mcp-client-001`
- **Client Secret**: `your-secret-key-change-this-in-production`

⚠️ **Important**: Make sure to change these credentials in production environments!

## Production Deployment

### Generate Secure Key

```bash
# Using OpenSSL
openssl rand -hex 32

# Using Python
python3 -c "import secrets; print(secrets.token_hex(32))"

# Using /dev/urandom
cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 64 | head -n 1
```

### Start Production Server

```bash
# Generate random key
CLIENT_SECRET=$(openssl rand -hex 32)

# Start server
uv run python mcp_simple_auth/statically_registered_client_server.py \
    --port 9003 \
    --client-id "prod-mcp-client-001" \
    --client-secret "$CLIENT_SECRET"
```

### Security Best Practices

1. ✅ **Don't hardcode secrets in code**
2. ✅ **Use environment variables or secret management services** (e.g., AWS Secrets Manager, HashiCorp Vault)
3. ✅ **Rotate `client_secret` regularly**
4. ✅ **Use strong random keys** (at least 32 characters)
5. ✅ **Disable debug mode in production**

## Available Tools

The server provides the following MCP tools:

### 1. `get_time`

Get the current server time.

**Returns**:
```json
{
  "current_time": "2024-01-01T12:00:00",
  "timezone": "UTC",
  "timestamp": 1704110400.0,
  "formatted": "2024-01-01 12:00:00"
}
```

### 2. `echo`

Echo a message back.

**Parameters**: `message` (string)
**Returns**:
```json
{
  "echo": "Hello, World!",
  "length": 13
}
```

## Testing

### Test OAuth Endpoints

```bash
# 1. View authorization server metadata
curl http://localhost:9003/.well-known/oauth-authorization-server

# 2. Try dynamic registration (should fail with 403)
curl -X POST http://localhost:9003/register \
  -H "Content-Type: application/json" \
  -d '{"client_name": "test"}'

# 3. Access login page
open http://localhost:9003/login?state=test123&client_id=static-mcp-client-001
```

### Test MCP Functionality

```bash
# Connect to server using MCP client
# Example using Python SDK
python -c "
from mcp import Client
client = Client('http://localhost:9003/mcp')
# Requires valid OAuth token
"
```

## Development

### Project Structure

```
mcp-oauth-sample/
├── mcp_simple_auth/
│   ├── statically_registered_client_server.py  # Main server file
│   ├── simple_auth_provider.py                # OAuth provider
│   └── token_verifier.py                      # Token verifier
├── pyproject.toml                              # Project configuration
└── README.md                                   # This document
```

### Adding Custom Tools

Edit `mcp_simple_auth/statically_registered_client_server.py`:

```python
def create_combined_mcp_server(settings: StaticallyRegisteredSettings) -> FastMCP:
    # ... existing code ...
    
    @app.tool()
    async def my_custom_tool(param: str) -> dict[str, Any]:
        """
        Your custom tool description.
        
        Args:
            param: Description of parameter
        
        Returns:
            Tool result
        """
        return {"result": f"Processed: {param}"}
    
    return app
```

### Local Development

```bash
# Install dependencies
uv sync

# Run development server
uv run python mcp_simple_auth/statically_registered_client_server.py --port 9003

# Run tests
uv run pytest
```

## FAQ

### Q: Why use static client registration?

**A**: Static registration is suitable for single-client production scenarios, simpler and more controllable, avoiding the complexity of dynamic registration.

### Q: How to support multiple clients?

**A**: If you need to support multiple clients, consider using dynamic client registration, or run multiple server instances with different credentials for each.

### Q: Does this server support OAuth refresh tokens?

**A**: The current implementation simplifies the refresh token functionality. It is recommended to implement a complete refresh token flow in production.

### Q: How to deploy to production?

**A**: Recommended deployment approach:
1. Use environment variables for secret management
2. Configure reverse proxy (e.g., Nginx)
3. Enable HTTPS
4. Configure firewall rules
5. Use process manager (e.g., systemd, supervisord)

### Q: How to handle token expiration?

**A**: In the current implementation, access tokens have a validity period of 3600 seconds (1 hour). You can adjust the validity period by modifying the `expires_at` parameter in the code.

## License

MIT License

## Contributing

Issues and Pull Requests are welcome!

## Acknowledgments

Built on the [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) Python SDK.


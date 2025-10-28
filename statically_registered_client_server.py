"""
MCP Resource Server with Pre-registered OAuth Client.

This server:
1. Has a pre-registered OAuth client (fixed client_id and client_secret)
2. Can be used without dynamic client registration
3. Useful for production environments where you want to control client credentials

NOTE: this is a simplified example for demonstration purposes.
This is not a production-ready implementation.
"""

import datetime
import logging
import secrets
import time
from typing import Any, Literal

import click
from pydantic import AnyHttpUrl
from pydantic_settings import BaseSettings, SettingsConfigDict
from starlette.applications import Starlette
from starlette.exceptions import HTTPException
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.routing import Route
from uvicorn import Config, Server

from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    OAuthAuthorizationServerProvider,
    RefreshToken,
    construct_redirect_uri,
)
from mcp.server.auth.routes import cors_middleware, create_auth_routes
from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp.server import FastMCP
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

logger = logging.getLogger(__name__)


class StaticallyRegisteredClientProvider(OAuthAuthorizationServerProvider[AuthorizationCode, RefreshToken, AccessToken]):
    """
    OAuth provider with pre-registered client credentials.
    
    In a production environment, you would configure these in:
    - Environment variables
    - Configuration file
    - Secrets management system (e.g., AWS Secrets Manager, HashiCorp Vault)
    """

    def __init__(
        self,
        auth_callback_url: str,
        server_url: str,
        pre_registered_client_id: str,
        pre_registered_client_secret: str,
        mcp_scope: str = "user",
    ):
        self.auth_callback_url = auth_callback_url
        self.server_url = server_url
        self.mcp_scope = mcp_scope
        
        # Store pre-registered client credentials
        self.pre_registered_client_id = pre_registered_client_id
        self.pre_registered_client_secret = pre_registered_client_secret
        
        # Create a single pre-registered client
        self.pre_registered_client = OAuthClientInformationFull(
            client_id=pre_registered_client_id,
            client_secret=pre_registered_client_secret,
            client_name="Pre-registered MCP Client",
            redirect_uris=["http://localhost:3031/callback"],  # Match your Java client
            grant_types=["authorization_code", "refresh_token"],
            response_types=["code"],
            token_endpoint_auth_method="client_secret_post",
        )
        
        # State management
        self.auth_codes: dict[str, AuthorizationCode] = {}
        self.tokens: dict[str, AccessToken] = {}
        self.state_mapping: dict[str, dict[str, str | None]] = {}
        self.user_data: dict[str, dict[str, Any]] = {}

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        """Get OAuth client information."""
        if client_id == self.pre_registered_client_id:
            return self.pre_registered_client
        return None

    async def register_client(self, client_info: OAuthClientInformationFull):
        """Reject dynamic registration - we only accept pre-registered clients."""
        raise HTTPException(
            403,
            "Dynamic client registration is not supported. "
            "This server uses pre-registered client credentials. "
            f"Use client_id: {self.pre_registered_client_id}",
        )

    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        """Generate an authorization URL for simple login flow."""
        state = params.state or secrets.token_hex(16)

        # Store state mapping for callback
        self.state_mapping[state] = {
            "redirect_uri": str(params.redirect_uri),
            "code_challenge": params.code_challenge,
            "redirect_uri_provided_explicitly": str(params.redirect_uri_provided_explicitly),
            "client_id": client.client_id,
            "resource": params.resource,
        }

        # Build simple login URL that points to login page
        auth_url = f"{self.auth_callback_url}?state={state}&client_id={client.client_id}"

        return auth_url

    async def get_login_page(self, state: str) -> HTMLResponse:
        """Generate login page HTML for the given state."""
        if not state:
            raise HTTPException(400, "Missing state parameter")

        # Create simple login form HTML
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>MCP Static Client Authentication</title>
            <style>
                body {{ font-family: Arial, sans-serif; max-width: 500px; margin: 0 auto; padding: 20px; }}
                .form-group {{ margin-bottom: 15px; }}
                input {{ width: 100%; padding: 8px; margin-top: 5px; }}
                button {{ background-color: #4CAF50; color: white; padding: 10px 15px; border: none; cursor: pointer; }}
                .info {{ background-color: #e3f2fd; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
            </style>
        </head>
        <body>
            <h2>MCP Authentication (Pre-registered Client)</h2>
            <div class="info">
                <strong>Pre-registered Client:</strong> {self.pre_registered_client_id}
            </div>
            
            <p>Use the demo credentials below:</p>
            <p><strong>Username:</strong> demo_user<br>
            <strong>Password:</strong> demo_password</p>

            <form action="{self.server_url.rstrip("/")}/login/callback" method="post">
                <input type="hidden" name="state" value="{state}">
                <div class="form-group">
                    <label>Username:</label>
                    <input type="text" name="username" value="demo_user" required>
                </div>
                <div class="form-group">
                    <label>Password:</label>
                    <input type="password" name="password" value="demo_password" required>
                </div>
                <button type="submit">Sign In</button>
            </form>
        </body>
        </html>
        """

        return HTMLResponse(content=html_content)

    async def handle_login_callback(self, request: Request) -> Response:
        """Handle login form submission callback."""
        form = await request.form()
        username = form.get("username")
        password = form.get("password")
        state = form.get("state")

        if not username or not password or not state:
            raise HTTPException(400, "Missing username, password, or state parameter")

        # Ensure we have strings
        if not isinstance(username, str) or not isinstance(password, str) or not isinstance(state, str):
            raise HTTPException(400, "Invalid parameter types")

        # Validate demo credentials
        if username != "demo_user" or password != "demo_password":
            raise HTTPException(401, "Invalid credentials")

        state_data = self.state_mapping.get(state)
        if not state_data:
            raise HTTPException(400, "Invalid state parameter")

        redirect_uri = state_data["redirect_uri"]
        code_challenge = state_data["code_challenge"]
        redirect_uri_provided_explicitly = state_data["redirect_uri_provided_explicitly"] == "True"
        client_id = state_data["client_id"]
        resource = state_data.get("resource")

        # Create authorization code
        new_code = f"mcp_{secrets.token_hex(16)}"
        auth_code = AuthorizationCode(
            code=new_code,
            client_id=client_id,
            redirect_uri=AnyHttpUrl(redirect_uri),
            redirect_uri_provided_explicitly=redirect_uri_provided_explicitly,
            expires_at=time.time() + 300,
            scopes=[self.mcp_scope],
            code_challenge=code_challenge,
            resource=resource,
        )
        self.auth_codes[new_code] = auth_code

        # Store user data
        self.user_data[username] = {
            "username": username,
            "user_id": f"user_{secrets.token_hex(8)}",
            "authenticated_at": time.time(),
        }

        del self.state_mapping[state]
        return RedirectResponse(url=construct_redirect_uri(redirect_uri, code=new_code, state=state), status_code=302)

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> AuthorizationCode | None:
        """Load an authorization code."""
        return self.auth_codes.get(authorization_code)

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ) -> OAuthToken:
        """Exchange authorization code for tokens."""
        if authorization_code.code not in self.auth_codes:
            raise ValueError("Invalid authorization code")

        # Generate access token
        mcp_token = f"mcp_{secrets.token_hex(32)}"

        # Store token
        self.tokens[mcp_token] = AccessToken(
            token=mcp_token,
            client_id=client.client_id,
            scopes=authorization_code.scopes,
            expires_at=int(time.time()) + 3600,
            resource=authorization_code.resource,
        )

        del self.auth_codes[authorization_code.code]

        return OAuthToken(
            access_token=mcp_token,
            token_type="Bearer",
            expires_in=3600,
            scope=" ".join(authorization_code.scopes),
        )

    async def load_access_token(self, token: str) -> AccessToken | None:
        """Load and validate an access token."""
        access_token = self.tokens.get(token)
        if not access_token:
            return None

        # Check if expired
        if access_token.expires_at and access_token.expires_at < time.time():
            del self.tokens[token]
            return None

        return access_token

    async def load_refresh_token(self, client: OAuthClientInformationFull, refresh_token: str) -> RefreshToken | None:
        """Load a refresh token - not supported in this example."""
        return None

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        """Exchange refresh token - not supported in this example."""
        raise NotImplementedError("Refresh tokens not supported")


class StaticallyRegisteredSettings(BaseSettings):
    """Settings for the statically registered OAuth MCP server."""

    model_config = SettingsConfigDict(env_prefix="MCP_STATIC_")

    # Server settings
    host: str = "localhost"
    port: int = 8003
    server_url: AnyHttpUrl = AnyHttpUrl("http://localhost:8003")

    # Pre-registered OAuth client credentials
    # In production, these should be stored securely (e.g., in environment variables)
    client_id: str = "static-mcp-client-001"
    client_secret: str = "your-secret-key-change-this-in-production"
    
    # OAuth settings
    mcp_scope: str = "user"
    auth_callback_path: str = "http://localhost:8003/login"


def create_combined_mcp_server(settings: StaticallyRegisteredSettings) -> FastMCP:
    """Create combined MCP server with OAuth and MCP on the same port."""
    oauth_provider = StaticallyRegisteredClientProvider(
        auth_callback_url=settings.auth_callback_path,
        server_url=str(settings.server_url),
        pre_registered_client_id=settings.client_id,
        pre_registered_client_secret=settings.client_secret,
        mcp_scope=settings.mcp_scope,
    )

    # Create AuthSettings with client registration DISABLED
    mcp_auth_settings = AuthSettings(
        issuer_url=settings.server_url,
        client_registration_options=None,  # Disable dynamic registration
        required_scopes=[settings.mcp_scope],
        resource_server_url=None,
    )

    # Create FastMCP app with auth
    app = FastMCP(
        name="MCP Server with Static OAuth Client",
        instructions="Server with pre-registered OAuth client. Use client_id: static-mcp-client-001",
        host=settings.host,
        port=settings.port,
        debug=True,
        auth_server_provider=oauth_provider,
        auth=mcp_auth_settings,
    )

    # Add custom login page route
    @app.custom_route("/login", methods=["GET"])
    async def login_page_handler(request: Request) -> Response:
        """Show login form."""
        state = request.query_params.get("state")
        if not state:
            raise HTTPException(400, "Missing state parameter")
        return await oauth_provider.get_login_page(state)

    # Add login callback route
    @app.custom_route("/login/callback", methods=["POST"])
    async def login_callback_handler(request: Request) -> Response:
        """Handle authentication callback."""
        return await oauth_provider.handle_login_callback(request)

    # Add token introspection endpoint
    @app.custom_route("/introspect", methods=["POST", "OPTIONS"])
    async def introspect_handler(request: Request) -> Response:
        """Token introspection endpoint."""
        if request.method == "OPTIONS":
            return Response(status_code=200, headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "POST, OPTIONS",
                "Access-Control-Allow-Headers": "Content-Type",
            })
        
        form = await request.form()
        token = form.get("token")
        if not token or not isinstance(token, str):
            return JSONResponse({"active": False}, status_code=400)

        access_token = await oauth_provider.load_access_token(token)
        if not access_token:
            return JSONResponse({"active": False})

        return JSONResponse(
            {
                "active": True,
                "client_id": access_token.client_id,
                "scope": " ".join(access_token.scopes),
                "exp": access_token.expires_at,
                "iat": int(time.time()),
                "token_type": "Bearer",
                "aud": access_token.resource,
            }
        )

    # Add MCP tools
    @app.tool()
    async def get_time() -> dict[str, Any]:
        """
        Get the current server time.

        Demonstrates protected resource that requires OAuth authentication.
        """
        now = datetime.datetime.now()
        return {
            "current_time": now.isoformat(),
            "timezone": "UTC",
            "timestamp": now.timestamp(),
            "formatted": now.strftime("%Y-%m-%d %H:%M:%S"),
        }

    @app.tool()
    async def echo(message: str) -> dict[str, Any]:
        """
        Echo a message back.

        Simple example tool that requires authentication.
        """
        return {"echo": message, "length": len(message)}

    return app


def run_server(settings: StaticallyRegisteredSettings):
    """Run the combined OAuth and MCP server."""
    # Create combined FastMCP server
    mcp_server = create_combined_mcp_server(settings)
    
    logger.info(f"🚀 Combined MCP Server with Static OAuth Client")
    logger.info(f"   Server URL: http://{settings.host}:{settings.port}")
    logger.info(f"   OAuth endpoints:")
    logger.info(f"     - Authorization: http://{settings.host}:{settings.port}/authorize")
    logger.info(f"     - Token: http://{settings.host}:{settings.port}/token")
    logger.info(f"     - Login: http://{settings.host}:{settings.port}/login")
    logger.info(f"   MCP endpoint: http://{settings.host}:{settings.port}/mcp")
    logger.info(f"🔑 Pre-registered client_id: {settings.client_id}")
    logger.info(f"⚠️  Client secret: {settings.client_secret[:10]}... (change in production!)")
    
    # Run the server with streamable-http transport
    mcp_server.run(transport="streamable-http")


@click.command()
@click.option("--port", default=9003, help="Port to listen on")
@click.option("--client-id", default="static-mcp-client-001", help="Pre-registered client ID")
@click.option("--client-secret", default="your-secret-key-change-this-in-production", help="Pre-registered client secret")
def main(port: int, client_id: str, client_secret: str) -> int:
    """
    Run MCP Server with Pre-registered OAuth Client.
    
    This server combines OAuth authorization and MCP functionality on the same port.
    Uses a pre-registered OAuth client instead of dynamic registration.
    
    Endpoints:
        - MCP: http://localhost:{port}/mcp
        - OAuth authorize: http://localhost:{port}/authorize
        - OAuth token: http://localhost:{port}/token
        - Login page: http://localhost:{port}/login
    
    Example usage:
        # Use default port and credentials
        uv run mcp-static-auth
        
        # Specify custom port and credentials
        uv run mcp-static-auth --port 9003 \\
            --client-id "my-client-001" \\
            --client-secret "my-secure-secret"
    """
    logging.basicConfig(level=logging.INFO)

    # Create server settings
    host = "localhost"
    server_url = f"http://{host}:{port}"
    settings = StaticallyRegisteredSettings(
        host=host,
        port=port,
        server_url=AnyHttpUrl(server_url),
        auth_callback_path=f"{server_url}/login",
        client_id=client_id,
        client_secret=client_secret,
    )

    try:
        run_server(settings)
        return 0
    except Exception:
        logger.exception("Server error")
        return 1


if __name__ == "__main__":
    main()  # type: ignore[call-arg]


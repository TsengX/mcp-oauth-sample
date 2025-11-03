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
from pydantic import AnyHttpUrl, Field
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
        redirect_uris: list[str],
        mcp_scope: str = "user",
    ):
        self.auth_callback_url = auth_callback_url
        self.server_url = server_url
        self.mcp_scope = mcp_scope
        
        # Store pre-registered client credentials
        self.pre_registered_client_id = pre_registered_client_id
        self.pre_registered_client_secret = pre_registered_client_secret
        
        # Create a single pre-registered client
        # Log the redirect_uris being registered for debugging
        logger.info(f"🔧 Registering OAuth client:")
        logger.info(f"   Input redirect_uris type: {type(redirect_uris)}")
        logger.info(f"   Input redirect_uris value: {redirect_uris}")
        logger.info(f"   Input redirect_uris length: {len(redirect_uris) if isinstance(redirect_uris, list) else 'N/A'}")
        
        self.pre_registered_client = OAuthClientInformationFull(
            client_id=pre_registered_client_id,
            client_secret=pre_registered_client_secret,
            client_name="Pre-registered MCP Client",
            redirect_uris=redirect_uris,
            grant_types=["authorization_code", "refresh_token"],
            response_types=["code"],
            token_endpoint_auth_method="client_secret_post",
        )
        
        # Verify the client was created correctly
        logger.info(f"🔍 Client created successfully:")
        logger.info(f"   Stored redirect_uris type: {type(self.pre_registered_client.redirect_uris)}")
        logger.info(f"   Stored redirect_uris value: {self.pre_registered_client.redirect_uris}")
        logger.info(f"   Stored redirect_uris length: {len(self.pre_registered_client.redirect_uris)}")
        logger.info(f"   Individual URIs:")
        for i, uri in enumerate(self.pre_registered_client.redirect_uris, 1):
            logger.info(f"     {i}. '{uri}' (type: {type(uri)})")
        
        # State management
        self.auth_codes: dict[str, AuthorizationCode] = {}
        self.tokens: dict[str, AccessToken] = {}
        self.state_mapping: dict[str, dict[str, str | None]] = {}
        self.user_data: dict[str, dict[str, Any]] = {}

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        """Get OAuth client information."""
        if client_id == self.pre_registered_client_id:
            # Debug: Log the client being returned
            logger.info(f"🔍 get_client called with client_id: {client_id}")
            logger.info(f"   Returning client with redirect_uris: {self.pre_registered_client.redirect_uris}")
            logger.info(f"   Redirect URIs count: {len(self.pre_registered_client.redirect_uris)}")
            return self.pre_registered_client
        logger.warning(f"❌ get_client: Unknown client_id: {client_id}")
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
        # Debug logging for redirect_uri validation
        requested_redirect_uri = str(params.redirect_uri)
        registered_uris = client.redirect_uris
        logger.info(f"🔍 OAuth authorize request:")
        logger.info(f"   Requested redirect_uri: {requested_redirect_uri}")
        logger.info(f"   Registered redirect_uris: {registered_uris}")
        logger.info(f"   Redirect URI match: {requested_redirect_uri in registered_uris}")
        
        state = params.state or secrets.token_hex(16)

        # Store state mapping for callback
        self.state_mapping[state] = {
            "redirect_uri": requested_redirect_uri,
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

    model_config = SettingsConfigDict(
        env_prefix="MCP_STATIC_",
        env_ignore_empty=True,
        # We'll handle redirect_uris parsing manually in validator
    )

    # Server settings
    host: str = "0.0.0.0"  # Listen on all interfaces for production deployment
    port: int = 8003
    # Public URL for OAuth callbacks and redirects (should be your public domain)
    public_url: str = "http://localhost:8003"
    server_url: AnyHttpUrl = AnyHttpUrl("http://localhost:8003")

    # Pre-registered OAuth client credentials
    # In production, these should be stored securely (e.g., in environment variables)
    client_id: str = "static-mcp-client-001"
    client_secret: str = "your-secret-key-change-this-in-production"
    
    # OAuth settings
    mcp_scope: str = "user"
    auth_callback_path: str = "http://localhost:8003/login"
    # Redirect URIs for OAuth client (stored as string to avoid JSON parsing issues)
    # Use alias so environment variable MCP_STATIC_REDIRECT_URIS maps to this field
    redirect_uris_str: str = Field(default="http://localhost:3031/callback", alias="redirect_uris")
    
    @property
    def redirect_uris(self) -> list[str]:
        """Parse redirect URIs from comma-separated string to list."""
        if not self.redirect_uris_str:
            return ["http://localhost:3031/callback"]
        # Parse comma-separated string
        uris = [uri.strip() for uri in self.redirect_uris_str.split(",") if uri.strip()]
        return uris if uris else ["http://localhost:3031/callback"]


def create_combined_mcp_server(settings: StaticallyRegisteredSettings) -> FastMCP:
    """Create combined MCP server with OAuth and MCP on the same port."""
    # Use public_url for OAuth callbacks and redirects
    public_base_url = settings.public_url.rstrip("/")
    auth_callback_url = f"{public_base_url}/login"
    
    # Debug: Log the redirect_uris being passed
    redirect_uris_list = settings.redirect_uris
    logger.info(f"🔧 Creating OAuth provider with redirect_uris:")
    for i, uri in enumerate(redirect_uris_list, 1):
        logger.info(f"   {i}. {uri}")
    logger.info(f"   Total count: {len(redirect_uris_list)}")
    logger.info(f"   Type: {type(redirect_uris_list)}")
    
    oauth_provider = StaticallyRegisteredClientProvider(
        auth_callback_url=auth_callback_url,
        server_url=str(settings.server_url),
        pre_registered_client_id=settings.client_id,
        pre_registered_client_secret=settings.client_secret,
        redirect_uris=redirect_uris_list,
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
    
    public_base_url = settings.public_url.rstrip("/")
    logger.info(f"🚀 Combined MCP Server with Static OAuth Client")
    logger.info(f"   Listening on: {settings.host}:{settings.port}")
    logger.info(f"   Public URL: {public_base_url}")
    logger.info(f"   OAuth endpoints:")
    logger.info(f"     - Authorization: {public_base_url}/authorize")
    logger.info(f"     - Token: {public_base_url}/token")
    logger.info(f"     - Login: {public_base_url}/login")
    logger.info(f"   MCP endpoint: {public_base_url}/mcp")
    logger.info(f"🔑 Pre-registered client_id: {settings.client_id}")
    logger.info(f"⚠️  Client secret: {settings.client_secret[:10]}... (change in production!)")
    logger.info(f"")
    logger.info(f"📋 Registered Redirect URIs (客户端必须使用这些 URI):")
    for i, uri in enumerate(settings.redirect_uris, 1):
        logger.info(f"     {i}. {uri}")
    logger.info(f"")
    logger.info(f"💡 提示: 如果客户端使用其他 redirect_uri，请将其添加到环境变量或启动参数中")
    
    # Run the server with streamable-http transport
    mcp_server.run(transport="streamable-http")


@click.command()
@click.option("--port", default=9003, help="Port to listen on")
@click.option("--host", default="0.0.0.0", help="Host to bind to (use 0.0.0.0 for all interfaces)")
@click.option("--public-url", default=None, help="Public URL for OAuth callbacks (e.g., https://yourdomain.com)")
@click.option("--client-id", default="static-mcp-client-001", help="Pre-registered client ID")
@click.option("--client-secret", default="your-secret-key-change-this-in-production", help="Pre-registered client secret")
@click.option("--redirect-uris", default=None, help="Comma-separated redirect URIs (e.g., 'http://client1.com/callback,http://client2.com/callback')")
def main(port: int, host: str, public_url: str | None, client_id: str, client_secret: str, redirect_uris: str | None) -> int:
    """
    Run MCP Server with Pre-registered OAuth Client.
    
    This server combines OAuth authorization and MCP functionality on the same port.
    Uses a pre-registered OAuth client instead of dynamic registration.
    
    Example usage:
        # Use default settings (localhost)
        uv run mcp-static-auth
        
        # Deploy on public server
        uv run mcp-static-auth \\
            --host 0.0.0.0 \\
            --port 8003 \\
            --public-url https://yourdomain.com \\
            --redirect-uris "https://client.com/callback,https://client2.com/callback" \\
            --client-id "my-client-001" \\
            --client-secret "my-secure-secret"
    """
    logging.basicConfig(level=logging.INFO)

    # Determine public URL (use provided or construct from host/port)
    if public_url is None:
        # If host is 0.0.0.0, use localhost for public URL (for local dev)
        if host == "0.0.0.0":
            public_url = f"http://localhost:{port}"
        else:
            public_url = f"http://{host}:{port}"
    
    server_url = public_url
    
    # Parse redirect URIs - convert to comma-separated string for settings
    import os
    env_redirect_uris = os.getenv("MCP_STATIC_REDIRECT_URIS")
    logger.info(f"📝 Environment variable MCP_STATIC_REDIRECT_URIS: {env_redirect_uris}")
    
    # Priority: command line > environment variable > default
    if redirect_uris is not None:
        # Use command line parameter (highest priority)
        redirect_uris_str = redirect_uris
        logger.info(f"📝 Using redirect_uris from command line: {redirect_uris_str}")
    elif env_redirect_uris:
        # Use environment variable (if no command line parameter)
        redirect_uris_str = env_redirect_uris
        logger.info(f"📝 Using redirect_uris from environment variable: {redirect_uris_str}")
    else:
        # Default redirect URIs based on public URL (fallback)
        redirect_uris_str = f"{public_url.rstrip('/')}/callback"
        logger.info(f"📝 Using default redirect_uris (from public_url): {redirect_uris_str}")
    
    settings = StaticallyRegisteredSettings(
        host=host,
        port=port,
        public_url=public_url,
        server_url=AnyHttpUrl(server_url),
        auth_callback_path=f"{public_url.rstrip('/')}/login",
        client_id=client_id,
        client_secret=client_secret,
        redirect_uris=redirect_uris_str,  # Pass as string, will be parsed by property
    )
    
    # Debug: Log what was actually parsed
    logger.info(f"📝 Settings.redirect_uris_str: {settings.redirect_uris_str}")
    logger.info(f"📝 Settings.redirect_uris (property): {settings.redirect_uris}")
    logger.info(f"📝 Settings.redirect_uris type: {type(settings.redirect_uris)}")

    try:
        run_server(settings)
        return 0
    except Exception:
        logger.exception("Server error")
        return 1


if __name__ == "__main__":
    main()  # type: ignore[call-arg]


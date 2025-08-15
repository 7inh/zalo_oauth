import os
import hashlib
import base64
import secrets
import urllib.parse
from typing import Optional, Dict, Any
from datetime import datetime, timedelta

import httpx
from fastapi import FastAPI, Request, Response, HTTPException, status, Cookie
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Zalo OAuth Server")

# Zalo OAuth configuration
ZALO_APP_ID = os.getenv("ZALO_APP_ID")
ZALO_APP_SECRET = os.getenv("ZALO_APP_SECRET")
BASE_URL = os.getenv("BASE_URL", "http://localhost:8000")
ZALO_REDIRECT_URI = os.getenv("ZALO_REDIRECT_URI", f"{BASE_URL}/auth/zalo/callback")

# Zalo OAuth URLs
ZALO_AUTH_URL = "https://oauth.zaloapp.com/v4/permission"
ZALO_TOKEN_URL = "https://oauth.zaloapp.com/v4/access_token"
ZALO_USER_INFO_URL = "https://graph.zalo.me/v2.0/me"


class ZaloTokenResponse(BaseModel):
    access_token: str
    token_type: str
    expires_in: int
    refresh_token: str


class ZaloUserInfo(BaseModel):
    id: str
    name: str
    picture: Optional[Dict[str, Any]] = None


class AuthUrlResponse(BaseModel):
    loginUrl: str
    state: str
    codeChallenge: str


class CallbackResponse(BaseModel):
    success: bool
    user_info: Dict[str, Any]
    is_new_user: bool
    access_token: str
    refresh_token: str
    provider: str
    zalo_access_token: str
    referral_code: Optional[str] = None


def generate_code_verifier() -> str:
    """Generate a cryptographically random code verifier for PKCE."""
    return secrets.token_urlsafe(96)


def generate_code_challenge(code_verifier: str) -> str:
    """Generate code challenge from code verifier using SHA256."""
    code_sha = hashlib.sha256(code_verifier.encode('utf-8')).digest()
    return base64.urlsafe_b64encode(code_sha).decode('utf-8').rstrip('=')


def generate_state() -> str:
    """Generate a random state parameter for CSRF protection."""
    return secrets.token_urlsafe(32)


@app.get("/auth/zalo", response_model=AuthUrlResponse)
async def get_zalo_auth_url(response: Response):
    """Generate Zalo OAuth authorization URL."""
    try:
        if not ZALO_APP_ID:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Zalo App ID not configured"
            )

        # Generate state for CSRF protection
        state = generate_state()
        
        # Generate code challenge for PKCE
        code_verifier = generate_code_verifier()
        code_challenge = generate_code_challenge(code_verifier)

        # Build Zalo OAuth URL
        auth_params = {
            "app_id": ZALO_APP_ID,
            "redirect_uri": ZALO_REDIRECT_URI,
            "state": state,
            "code_challenge": code_challenge,
        }
        
        zalo_auth_url = f"{ZALO_AUTH_URL}?{urllib.parse.urlencode(auth_params)}"

        # Debug logging
        logger.info(f"🔍 [DEBUG] Complete Zalo OAuth URL: {zalo_auth_url}")
        logger.info(f"🔍 [DEBUG] OAuth URL Parameters:")
        logger.info(f"  - app_id: {ZALO_APP_ID}")
        logger.info(f"  - redirect_uri: {ZALO_REDIRECT_URI}")
        logger.info(f"  - state: {state}")
        logger.info(f"  - code_challenge: {code_challenge}")
        logger.info(f"🔍 [DEBUG] Code verifier (for callback): {code_verifier}")

        # Set secure cookies for state verification
        cookie_settings = {
            "httponly": True,
            "secure": os.getenv("ENVIRONMENT") == "production",
            "samesite": "lax",
            "max_age": 600,  # 10 minutes
        }
        
        response.set_cookie("zalo_state", state, **cookie_settings)
        response.set_cookie("zalo_code_verifier", code_verifier, **cookie_settings)

        logger.info("🔍 [DEBUG] Response cookies set for state and code verifier")

        return AuthUrlResponse(
            loginUrl=zalo_auth_url,
            state=state,
            codeChallenge=code_challenge
        )

    except Exception as error:
        logger.error(f"Error generating Zalo login URL: {error}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate login URL"
        )


@app.get("/auth/zalo/callback")
async def zalo_callback_redirect(
    request: Request,
    code: Optional[str] = None,
    state: Optional[str] = None,
    referral_code: Optional[str] = None,
    zalo_state: Optional[str] = Cookie(None),
    zalo_code_verifier: Optional[str] = Cookie(None)
):
    """Handle Zalo OAuth callback with redirect response."""
    try:
        # Debug logging
        logger.info("🔍 [DEBUG] Zalo OAuth Callback Parameters:")
        logger.info(f"  - code: {code}")
        logger.info(f"  - state: {state}")
        logger.info(f"  - referral_code: {referral_code}")
        logger.info(f"  - redirect_uri: {ZALO_REDIRECT_URI}")

        # Verify required parameters
        if not code:
            error_url = f"{BASE_URL}/auth/zalo/error?error=invalid_code&message=Authorization code is required"
            return RedirectResponse(url=error_url)

        if not ZALO_APP_ID or not ZALO_APP_SECRET:
            error_url = f"{BASE_URL}/auth/zalo/error?error=config_error&message=Zalo OAuth not properly configured"
            return RedirectResponse(url=error_url)

        # Verify state parameter for CSRF protection
        if state != zalo_state:
            error_url = f"{BASE_URL}/auth/zalo/error?error=invalid_state&message=Invalid state parameter - possible CSRF attack"
            return RedirectResponse(url=error_url)

        # Get user data from callback processing
        user_data = await process_zalo_callback(code, zalo_code_verifier or "")
        
        # Redirect to success page with user data
        success_params = {
            "success": "true",
            "user_id": user_data["id"],
            "user_name": user_data["name"],
        }
        
        if user_data.get("avatar"):
            success_params["avatar"] = user_data["avatar"]
        if referral_code:
            success_params["referral_code"] = referral_code

        success_url = f"{BASE_URL}/auth/zalo/success?{urllib.parse.urlencode(success_params)}"
        
        # Create redirect response and clear temporary cookies
        response = RedirectResponse(url=success_url)
        response.delete_cookie("zalo_state")
        response.delete_cookie("zalo_code_verifier")
        
        # Here you would set your own authentication cookies
        # response.set_cookie("auth_token", "your_jwt_token", httponly=True, secure=True, samesite="lax", max_age=86400)

        logger.info(f"🔍 [DEBUG] Redirecting to success page: {success_url}")
        return response

    except Exception as error:
        logger.error(f"Zalo OAuth callback error: {error}")
        error_url = f"{BASE_URL}/auth/zalo/error?error=internal_error&message=Internal server error during authentication"
        return RedirectResponse(url=error_url)


@app.post("/auth/zalo/callback", response_model=CallbackResponse)
async def zalo_callback_api(
    request: Request,
    code: Optional[str] = None,
    state: Optional[str] = None,
    referral_code: Optional[str] = None,
    zalo_code_verifier: Optional[str] = Cookie(None)
):
    """Handle Zalo OAuth callback with JSON API response."""
    try:
        # Debug logging
        logger.info("🔍 [DEBUG] Zalo API Callback Parameters:")
        logger.info(f"  - code: {code}")
        logger.info(f"  - state: {state}")
        logger.info(f"  - referral_code: {referral_code}")

        # Verify required parameters
        if not code:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Authorization code is required"
            )

        if not ZALO_APP_ID or not ZALO_APP_SECRET:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Zalo OAuth not properly configured"
            )

        # Get user data from callback processing
        user_data = await process_zalo_callback(code, zalo_code_verifier or "")
        zalo_access_token = user_data.pop("zalo_access_token", "")

        # Return authentication data
        return CallbackResponse(
            success=True,
            user_info={
                "id": user_data["id"],
                "name": user_data["name"],
                "avatar": user_data.get("avatar"),
                "email": None,  # Zalo doesn't provide email by default
            },
            is_new_user=True,  # You would determine this from your database
            access_token="your_generated_jwt_token",  # Generate your own JWT
            refresh_token="your_generated_refresh_token",  # Generate your own refresh token
            provider="zalo",
            zalo_access_token=zalo_access_token,
            referral_code=referral_code,
        )

    except HTTPException:
        raise
    except Exception as error:
        logger.error(f"Zalo OAuth callback error: {error}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error during authentication"
        )


async def process_zalo_callback(code: str, code_verifier: str) -> Dict[str, Any]:
    """Process Zalo OAuth callback and return user data."""
    async with httpx.AsyncClient() as client:
        # Exchange authorization code for access token
        logger.info("🔍 [DEBUG] Token Exchange Request:")
        logger.info(f"  - app_id: {ZALO_APP_ID}")
        logger.info(f"  - code: {code}")
        logger.info(f"  - code_verifier: {code_verifier}")

        token_data = {
            "app_id": ZALO_APP_ID,
            "grant_type": "authorization_code",
            "code": code,
            "code_verifier": code_verifier,
        }

        token_response = await client.post(
            ZALO_TOKEN_URL,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "secret_key": ZALO_APP_SECRET,
            },
            data=token_data
        )

        if not token_response.is_success:
            error_text = token_response.text
            logger.error(f"Zalo token exchange failed: {error_text}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Failed to exchange authorization code for token"
            )

        token_json = token_response.json()
        access_token = token_json["access_token"]
        
        logger.info("🔍 [DEBUG] Token Exchange Success:")
        logger.info(f"  - access_token: {access_token[:20]}...")
        logger.info(f"  - expires_in: {token_json.get('expires_in')}")

        # Get user information from Zalo
        user_response = await client.get(
            f"{ZALO_USER_INFO_URL}?fields=id,name,picture",
            headers={"access_token": access_token}
        )

        if not user_response.is_success:
            error_text = user_response.text
            logger.error(f"Zalo user info fetch failed: {error_text}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Failed to fetch user information from Zalo"
            )

        user_json = user_response.json()
        
        logger.info("🔍 [DEBUG] User Info Retrieved:")
        logger.info(f"  - id: {user_json['id']}")
        logger.info(f"  - name: {user_json['name']}")
        logger.info(f"  - avatar: {user_json.get('picture', {}).get('data', {}).get('url')}")

        return {
            "id": user_json["id"],
            "name": user_json["name"],
            "avatar": user_json.get("picture", {}).get("data", {}).get("url"),
            "zalo_access_token": access_token,
        }


@app.get("/auth/zalo/error")
async def zalo_error_page(error: str, message: str):
    """Handle OAuth error page."""
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={"error": error, "message": message}
    )


@app.get("/auth/zalo/success")
async def zalo_success_page(
    success: str,
    user_id: str,
    user_name: str,
    avatar: Optional[str] = None,
    referral_code: Optional[str] = None,
):
    """Handle OAuth success page."""
    return JSONResponse(
        content={
            "success": success == "true",
            "user_info": {
                "id": user_id,
                "name": user_name,
                "avatar": avatar,
            },
            "referral_code": referral_code,
        }
    )


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "timestamp": datetime.utcnow()}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
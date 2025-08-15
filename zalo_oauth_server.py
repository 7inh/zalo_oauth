# main.py
import os
import time
import base64
import hashlib
import secrets
import string

from fastapi import FastAPI, Request, HTTPException, Query
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import httpx

try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

app = FastAPI(title="Zalo Login Backend")

# ---- Config ----
ZALO_APP_ID = os.getenv("ZALO_APP_ID") or os.getenv("NEXT_PUBLIC_ZALO_APP_ID")
ZALO_REDIRECT_URI = os.getenv(
    "ZALO_REDIRECT_URI",
    f"{os.getenv('NEXT_PUBLIC_BASE_URL', 'https://dev-ops.clickai.vn')}/auth/zalo",
)
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "true").lower() == "true"
COOKIE_MAX_AGE = int(os.getenv("COOKIE_MAX_AGE", "600"))  # seconds
CORS_ORIGINS = [o.strip() for o in os.getenv("CORS_ORIGINS", "*").split(",")]

if not ZALO_APP_ID:
    raise RuntimeError("ZALO_APP_ID (or NEXT_PUBLIC_ZALO_APP_ID) is required")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if CORS_ORIGINS == ["*"] else CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---- Helpers ----
def _b64url_no_padding(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")

def generate_code_verifier(length: int = 43) -> str:
    # RFC 7636 valid charset: ALPHA / DIGIT / "-" / "." / "_" / "~"
    alphabet = string.ascii_letters + string.digits + "-._~"
    return "".join(secrets.choice(alphabet) for _ in range(length))

def code_challenge_s256(code_verifier: str) -> str:
    digest = hashlib.sha256(code_verifier.encode()).digest()
    return _b64url_no_padding(digest)

# ---- Endpoints ----
@app.get("/zalo/auth-url")
async def get_zalo_auth_url():
    state = secrets.token_urlsafe(16)
    code_verifier = generate_code_verifier(43)
    code_challenge = code_challenge_s256(code_verifier)

    auth_url = (
        "https://oauth.zaloapp.com/v4/permission"
        f"?app_id={ZALO_APP_ID}"
        f"&redirect_uri={ZALO_REDIRECT_URI}"
        f"&state={state}"
        f"&code_challenge={code_challenge}"
        f"&code_challenge_method=S256"
    )

    # Return JSON and set HttpOnly cookies so we can verify later
    resp = JSONResponse({"auth_url": auth_url, "state": state})
    resp.set_cookie(
        key="zalo_state",
        value=state,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="lax",
        max_age=COOKIE_MAX_AGE,
        path="/",
    )
    resp.set_cookie(
        key="zalo_code_verifier",
        value=code_verifier,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="lax",
        max_age=COOKIE_MAX_AGE,
        path="/",
    )
    # Optional: a timestamp for debugging / TTL enforcement
    resp.set_cookie(
        key="zalo_state_at",
        value=str(int(time.time())),
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="lax",
        max_age=COOKIE_MAX_AGE,
        path="/",
    )
    return resp

@app.get("/zalo/verify")
async def verify_zalo_login(
    request: Request,
    code: str = Query(..., description="authorization code from Zalo"),
    state: str = Query(..., description="state returned by Zalo"),
):
    # Read cookies set during /zalo/auth-url
    cookie_state = request.cookies.get("zalo_state")
    code_verifier = request.cookies.get("zalo_code_verifier")

    if not cookie_state or not code_verifier:
        raise HTTPException(status_code=400, detail="Missing login cookies")
    if state != cookie_state:
        raise HTTPException(status_code=400, detail="Invalid state")

    # Exchange code -> access token (PKCE)
    token_url = "https://oauth.zaloapp.com/v4/access_token"
    form = {
        "app_id": ZALO_APP_ID,
        "code": code,
        "redirect_uri": ZALO_REDIRECT_URI,
        "grant_type": "authorization_code",
        "code_verifier": code_verifier,
    }

    async with httpx.AsyncClient(timeout=15.0) as client:
        token_res = await client.post(
            token_url,
            data=form,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
    if token_res.status_code >= 400:
        raise HTTPException(status_code=token_res.status_code, detail=token_res.text)

    token_data = token_res.json()
    access_token = token_data.get("access_token")
    if not access_token:
        raise HTTPException(status_code=400, detail={"token_error": token_data})

    # Fetch user profile
    async with httpx.AsyncClient(timeout=15.0) as client:
        profile_res = await client.get(
            "https://graph.zalo.me/v2.0/me",
            params={"access_token": access_token, "fields": "id,name,picture"},
        )
    if profile_res.status_code >= 400:
        raise HTTPException(status_code=profile_res.status_code, detail=profile_res.text)

    profile = profile_res.json()

    # Optionally clear cookies after use (uncomment if you want one-time)
    resp = JSONResponse({"tokens": token_data, "profile": profile})
    resp.delete_cookie("zalo_state", path="/")
    resp.delete_cookie("zalo_code_verifier", path="/")
    resp.delete_cookie("zalo_state_at", path="/")
    return resp

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host=os.getenv("HOST", "0.0.0.0"),
        port=int(os.getenv("PORT", "8000")),
        reload=os.getenv("RELOAD", "true").lower() == "true",
    )

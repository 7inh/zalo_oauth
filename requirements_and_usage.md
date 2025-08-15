# Zalo OAuth Python Server

This is a Python FastAPI implementation of Zalo OAuth authentication, based on the original TypeScript Next.js code.

## Requirements

Create a `requirements.txt` file:

```txt
fastapi==0.104.1
uvicorn[standard]==0.24.0
httpx==0.25.2
pydantic==2.5.0
python-multipart==0.0.6
```

## Installation

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Set up environment variables:
```bash
export ZALO_APP_ID="your_zalo_app_id"
export ZALO_APP_SECRET="your_zalo_app_secret"
export BASE_URL="http://localhost:8000"
export ZALO_REDIRECT_URI="http://localhost:8000/auth/zalo/callback"
export ENVIRONMENT="development"  # or "production"
```

Or create a `.env` file:
```env
ZALO_APP_ID=your_zalo_app_id
ZALO_APP_SECRET=your_zalo_app_secret
BASE_URL=http://localhost:8000
ZALO_REDIRECT_URI=http://localhost:8000/auth/zalo/callback
ENVIRONMENT=development
```

## Usage

1. Start the server:
```bash
python main.py
# or
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

2. The server will be available at `http://localhost:8000`

## API Endpoints

### 1. Get Authorization URL
**GET** `/auth/zalo`

Returns the Zalo OAuth authorization URL that users should visit to authenticate.

**Response:**
```json
{
  "loginUrl": "https://oauth.zaloapp.com/v4/permission?app_id=...&redirect_uri=...&state=...&code_challenge=...",
  "state": "random_state_string",
  "codeChallenge": "code_challenge_string"
}
```

**Example usage:**
```bash
curl http://localhost:8000/auth/zalo
```

### 2. Handle Callback (Redirect)
**GET** `/auth/zalo/callback`

Handles the OAuth callback from Zalo and redirects to success/error pages.

**Parameters:**
- `code`: Authorization code from Zalo
- `state`: State parameter for CSRF protection
- `referral_code` (optional): Referral code

**Response:** Redirects to success or error page

### 3. Handle Callback (API)
**POST** `/auth/zalo/callback`

Handles the OAuth callback from Zalo and returns JSON response.

**Parameters:** Same as GET version

**Response:**
```json
{
  "success": true,
  "user_info": {
    "id": "zalo_user_id",
    "name": "User Name",
    "avatar": "https://avatar.url",
    "email": null
  },
  "is_new_user": true,
  "access_token": "your_generated_jwt_token",
  "refresh_token": "your_generated_refresh_token",
  "provider": "zalo",
  "zalo_access_token": "zalo_access_token",
  "referral_code": "referral_code_if_provided"
}
```

## Integration Example

### Frontend Integration

```javascript
// 1. Get the authorization URL
const response = await fetch('/auth/zalo');
const { loginUrl } = await response.json();

// 2. Redirect user to Zalo for authentication
window.location.href = loginUrl;

// 3. User will be redirected back to /auth/zalo/callback
// Handle success/error on your frontend
```

### API Integration

```javascript
// For API-based integration, you can handle the callback with POST
const callbackResponse = await fetch('/auth/zalo/callback', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
  },
  // Include the authorization code and state from URL params
});

const authData = await callbackResponse.json();
if (authData.success) {
  // Store the tokens and user info
  localStorage.setItem('access_token', authData.access_token);
  // Handle successful authentication
}
```

## Key Features

1. **PKCE Support**: Implements Proof Key for Code Exchange for enhanced security
2. **CSRF Protection**: Uses state parameter to prevent CSRF attacks
3. **Secure Cookies**: Stores temporary data in HTTP-only cookies
4. **Comprehensive Logging**: Detailed debug logging for troubleshooting
5. **Error Handling**: Proper error responses and redirects
6. **Dual Response Types**: Supports both redirect and JSON API responses
7. **Environment Configuration**: Flexible configuration via environment variables

## Security Notes

- The server uses HTTP-only cookies for storing temporary OAuth state
- PKCE (Proof Key for Code Exchange) is implemented for additional security
- State parameters are used for CSRF protection
- In production, ensure HTTPS is used and set secure cookie flags

## Development vs Production

The server automatically adjusts cookie security settings based on the `ENVIRONMENT` variable:
- **Development**: Cookies are not marked as secure (works with HTTP)
- **Production**: Cookies are marked as secure (requires HTTPS)

## Next Steps

To complete the implementation, you would typically:

1. **Database Integration**: Store user information in your database
2. **JWT Token Generation**: Implement proper JWT token generation and validation
3. **Session Management**: Implement proper session management
4. **User Registration**: Handle new user registration flow
5. **Refresh Tokens**: Implement refresh token logic
6. **Rate Limiting**: Add rate limiting for API endpoints
7. **Monitoring**: Add proper monitoring and alerting
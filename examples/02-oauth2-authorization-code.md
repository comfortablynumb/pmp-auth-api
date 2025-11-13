# OAuth2 Authorization Code Flow

This example demonstrates the OAuth2 Authorization Code grant type, which is the most common flow for **web applications** where a user is involved.

## Use Case

Perfect for:
- Web applications requiring user authentication
- Single Page Applications (SPAs) with a backend
- Mobile applications with proper security
- Any application that can securely store a client secret

## Flow Overview

```
┌──────────┐                                           ┌──────────────┐
│          │                                           │              │
│  Client  │                                           │     User     │
│   App    │                                           │              │
│          │                                           │              │
└────┬─────┘                                           └──────┬───────┘
     │                                                         │
     │  1. Redirect to authorize endpoint                     │
     ├────────────────────────────────────────────────────────►
     │                                                         │
     │  2. User logs in and grants permission                 │
     │                                                         │
     ◄────────────────────────────────────────────────────────┤
     │  3. Redirect back with authorization code              │
     │                                                         │
     │  4. Exchange code for access token                     │
     ├───────────────────────►┌─────────────┐                │
     │                         │             │                │
     │  5. Return access token │  Auth API   │                │
     ◄─────────────────────────┤             │                │
     │                         └─────────────┘                │
     │  6. Use access token                                   │
     │                                                         │
```

## Prerequisites

1. API is running on `http://localhost:3000`
2. You have a tenant configured in `config.yaml`
3. OAuth2 is enabled for the tenant
4. You have registered a client application with a redirect URI

## Step-by-Step Example

### Step 1: Initiate Authorization Request

Direct the user's browser to the authorization endpoint:

```bash
# This would typically be a link in your web application
open "http://localhost:3000/api/v1/tenant/test-tenant/oauth/authorize?response_type=code&client_id=your-client-id&redirect_uri=http://localhost:8080/callback&scope=openid%20profile%20email&state=random-state-string"
```

**Parameters:**
- `response_type`: Must be `code` for authorization code flow
- `client_id`: Your application's client ID
- `redirect_uri`: Where to redirect after authorization (must match registered URI)
- `scope`: Space-separated list of requested scopes
- `state`: Random string to prevent CSRF attacks (highly recommended)

**What happens:**
1. User is presented with a login page (if not already logged in)
2. User authenticates with their credentials
3. User is shown a consent screen with requested permissions
4. User approves or denies the request

### Step 2: Receive Authorization Code

After the user approves, they are redirected back to your application:

```
http://localhost:8080/callback?code=auth-code-here&state=random-state-string
```

**Your application should:**
1. Verify the `state` parameter matches what you sent
2. Extract the authorization `code`
3. Validate that the redirect came from the expected authorization server

### Step 3: Exchange Code for Access Token

Exchange the authorization code for an access token:

```bash
curl -X POST http://localhost:3000/api/v1/tenant/test-tenant/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=auth-code-here" \
  -d "client_id=your-client-id" \
  -d "client_secret=your-client-secret" \
  -d "redirect_uri=http://localhost:8080/callback"
```

**Parameters:**
- `grant_type`: Must be `authorization_code`
- `code`: The authorization code received in step 2
- `client_id`: Your application's client ID
- `client_secret`: Your application's client secret
- `redirect_uri`: Must match the redirect_uri from step 1

**Expected Response:**
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Im9hdXRoMi1rZXktMSJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "refresh-token-string-here",
  "scope": "openid profile email"
}
```

**Important:** Authorization codes are single-use and expire quickly (typically 5-10 minutes).

### Step 4: Use the Access Token

Make authenticated API requests using the access token:

```bash
curl -X GET http://localhost:3000/api/v1/user/profile \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Im9hdXRoMi1rZXktMSJ9..."
```

**Expected Response:**
```json
{
  "sub": "user-123",
  "email": "user@example.com",
  "name": "John Doe",
  "picture": "https://example.com/photo.jpg"
}
```

### Step 5: Refresh the Access Token

When the access token expires, use the refresh token to get a new one:

```bash
curl -X POST http://localhost:3000/api/v1/tenant/test-tenant/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token" \
  -d "refresh_token=refresh-token-string-here" \
  -d "client_id=your-client-id" \
  -d "client_secret=your-client-secret"
```

**Expected Response:**
```json
{
  "access_token": "new-access-token-here...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "new-refresh-token-here",
  "scope": "openid profile email"
}
```

## Complete Example with Mock Server

Here's a complete example using a simple HTTP server to receive the callback:

### 1. Start a Simple Callback Server

Create `callback-server.js`:

```javascript
const http = require('http');
const url = require('url');

const server = http.createServer((req, res) => {
  const queryObject = url.parse(req.url, true).query;

  if (queryObject.code) {
    console.log('\n✓ Authorization code received:', queryObject.code);
    console.log('✓ State:', queryObject.state);

    res.writeHead(200, {'Content-Type': 'text/html'});
    res.end(`
      <html>
        <body>
          <h1>Authorization Successful!</h1>
          <p>You can close this window and return to the terminal.</p>
          <pre>Code: ${queryObject.code}</pre>
        </body>
      </html>
    `);

    // Exit after receiving the code
    setTimeout(() => process.exit(0), 1000);
  } else if (queryObject.error) {
    console.error('\n✗ Authorization failed:', queryObject.error);
    console.error('  Description:', queryObject.error_description);

    res.writeHead(400, {'Content-Type': 'text/html'});
    res.end(`
      <html>
        <body>
          <h1>Authorization Failed</h1>
          <p>Error: ${queryObject.error}</p>
        </body>
      </html>
    `);

    setTimeout(() => process.exit(1), 1000);
  }
});

server.listen(8080, () => {
  console.log('Callback server listening on http://localhost:8080');
  console.log('Waiting for OAuth callback...\n');
});
```

Run the callback server:

```bash
node callback-server.js
```

### 2. Run the Full Flow Script

Create `oauth2-flow.sh`:

```bash
#!/bin/bash

TENANT_ID="test-tenant"
CLIENT_ID="your-client-id"
CLIENT_SECRET="your-client-secret"
REDIRECT_URI="http://localhost:8080/callback"
BASE_URL="http://localhost:3000"

# Generate random state
STATE=$(openssl rand -hex 16)

# Build authorization URL
AUTH_URL="${BASE_URL}/api/v1/tenant/${TENANT_ID}/oauth/authorize"
AUTH_URL="${AUTH_URL}?response_type=code"
AUTH_URL="${AUTH_URL}&client_id=${CLIENT_ID}"
AUTH_URL="${AUTH_URL}&redirect_uri=${REDIRECT_URI}"
AUTH_URL="${AUTH_URL}&scope=openid%20profile%20email"
AUTH_URL="${AUTH_URL}&state=${STATE}"

echo "==> Step 1: Opening authorization page in browser..."
echo "    URL: $AUTH_URL"
echo ""

# Open browser (works on macOS, Linux, and WSL)
if command -v open > /dev/null; then
  open "$AUTH_URL"
elif command -v xdg-open > /dev/null; then
  xdg-open "$AUTH_URL"
else
  echo "Please open this URL in your browser:"
  echo "$AUTH_URL"
fi

echo "==> Step 2: Waiting for authorization code..."
echo "    (The callback server should receive it)"
echo ""
echo "==> Enter the authorization code:"
read -r CODE

echo ""
echo "==> Step 3: Exchanging code for access token..."

RESPONSE=$(curl -s -X POST "${BASE_URL}/api/v1/tenant/${TENANT_ID}/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=${CODE}" \
  -d "client_id=${CLIENT_ID}" \
  -d "client_secret=${CLIENT_SECRET}" \
  -d "redirect_uri=${REDIRECT_URI}")

echo "$RESPONSE" | jq .

ACCESS_TOKEN=$(echo "$RESPONSE" | jq -r .access_token)
REFRESH_TOKEN=$(echo "$RESPONSE" | jq -r .refresh_token)

echo ""
echo "==> Step 4: Using access token to fetch user profile..."

curl -s -X GET "${BASE_URL}/api/v1/user/profile" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" | jq .

echo ""
echo "==> Tokens obtained:"
echo "    Access Token:  ${ACCESS_TOKEN:0:50}..."
echo "    Refresh Token: ${REFRESH_TOKEN:0:50}..."
```

Run the script:

```bash
chmod +x oauth2-flow.sh
./oauth2-flow.sh
```

## Security Considerations

### 1. State Parameter (CSRF Protection)

Always use a random `state` parameter:

```bash
# Generate random state
STATE=$(openssl rand -hex 16)

# Store state in session
echo "$STATE" > /tmp/oauth_state

# Use in authorization request
curl "...&state=$STATE"

# Verify on callback
RECEIVED_STATE="..."
STORED_STATE=$(cat /tmp/oauth_state)
if [ "$RECEIVED_STATE" != "$STORED_STATE" ]; then
  echo "CSRF attack detected!"
  exit 1
fi
```

### 2. PKCE (Proof Key for Code Exchange)

For public clients (SPAs, mobile apps), use PKCE:

```bash
# Generate code verifier
CODE_VERIFIER=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-43)

# Generate code challenge
CODE_CHALLENGE=$(echo -n "$CODE_VERIFIER" | openssl sha256 -binary | base64 | tr -d "=+/" | cut -c1-43)

# Authorization request with PKCE
curl "http://localhost:3000/api/v1/tenant/test-tenant/oauth/authorize?response_type=code&client_id=your-client-id&redirect_uri=http://localhost:8080/callback&code_challenge=$CODE_CHALLENGE&code_challenge_method=S256&state=$STATE"

# Token request with code verifier
curl -X POST http://localhost:3000/api/v1/tenant/test-tenant/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=$CODE" \
  -d "client_id=your-client-id" \
  -d "redirect_uri=http://localhost:8080/callback" \
  -d "code_verifier=$CODE_VERIFIER"
```

### 3. Secure Storage

- **Never expose client secrets** in frontend code
- **Store refresh tokens securely** (encrypted, httpOnly cookies)
- **Use HTTPS in production** to prevent token interception

## Error Scenarios

### Invalid Authorization Code

```bash
curl -X POST http://localhost:3000/api/v1/tenant/test-tenant/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=invalid-code" \
  -d "client_id=your-client-id" \
  -d "client_secret=your-client-secret" \
  -d "redirect_uri=http://localhost:8080/callback"
```

**Response:**
```json
{
  "error": "invalid_grant",
  "error_description": "Authorization code is invalid or expired"
}
```

### Mismatched Redirect URI

```bash
curl -X POST http://localhost:3000/api/v1/tenant/test-tenant/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=valid-code" \
  -d "client_id=your-client-id" \
  -d "client_secret=your-client-secret" \
  -d "redirect_uri=http://wrong-uri.com/callback"
```

**Response:**
```json
{
  "error": "invalid_request",
  "error_description": "Redirect URI mismatch"
}
```

## Next Steps

- Try [OpenID Connect](03-openid-connect.md) to get ID tokens with user identity
- Explore [API Key Management](04-api-key-management.md) for long-lived tokens
- Learn about [SAML SSO](05-saml-sso.md) for enterprise integrations

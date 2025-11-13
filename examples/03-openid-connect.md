# OpenID Connect (OIDC) Flow

This example demonstrates OpenID Connect, which is an **identity layer** built on top of OAuth2. OIDC provides standardized user identity information through ID tokens and the UserInfo endpoint.

## Use Case

Perfect for:
- Applications needing user identity information (name, email, profile)
- Single Sign-On (SSO) implementations
- Applications requiring standardized authentication
- Multi-application environments sharing user identity

## OAuth2 vs OpenID Connect

| Feature | OAuth2 | OpenID Connect |
|---------|--------|----------------|
| Purpose | Authorization | Authentication + Authorization |
| User Info | Custom | Standardized claims |
| ID Token | ❌ | ✅ JWT with user info |
| UserInfo Endpoint | ❌ | ✅ Standardized |
| Discovery | Optional | ✅ Required |

## Prerequisites

1. API is running on `http://localhost:3000`
2. You have a tenant configured with OIDC enabled
3. You have registered a client application

## Step-by-Step Example

### Step 1: Discover OIDC Configuration

Retrieve the OIDC configuration from the discovery endpoint:

```bash
curl -X GET http://localhost:3000/api/v1/tenant/test-tenant/.well-known/openid-configuration
```

**Expected Response:**
```json
{
  "issuer": "https://auth.example.com",
  "authorization_endpoint": "https://auth.example.com/api/v1/tenant/test-tenant/oauth/authorize",
  "token_endpoint": "https://auth.example.com/api/v1/tenant/test-tenant/oauth/token",
  "userinfo_endpoint": "https://auth.example.com/api/v1/tenant/test-tenant/oauth/userinfo",
  "jwks_uri": "https://auth.example.com/api/v1/tenant/test-tenant/.well-known/jwks.json",
  "response_types_supported": ["code", "token"],
  "grant_types_supported": ["authorization_code", "client_credentials", "refresh_token"],
  "scopes_supported": ["openid", "profile", "email"],
  "claims_supported": [
    "sub",
    "email",
    "email_verified",
    "name",
    "given_name",
    "family_name",
    "picture",
    "locale"
  ],
  "id_token_signing_alg_values_supported": ["RS256"]
}
```

**Use this to:**
- Automatically configure your OIDC client library
- Discover available endpoints
- Understand supported features

### Step 2: Initiate OIDC Authentication

Request authorization with the `openid` scope:

```bash
# Direct user to this URL
open "http://localhost:3000/api/v1/tenant/test-tenant/oauth/authorize?response_type=code&client_id=your-client-id&redirect_uri=http://localhost:8080/callback&scope=openid%20profile%20email&state=random-state-string"
```

**Key difference from OAuth2:** The `openid` scope is **required** for OIDC.

**Available scopes:**
- `openid` - Required for OIDC, returns `sub` claim
- `profile` - Returns name, given_name, family_name, picture, etc.
- `email` - Returns email and email_verified claims
- `address` - Returns address claim (if supported)
- `phone` - Returns phone_number claim (if supported)

### Step 3: Exchange Code for Tokens

Exchange the authorization code for both an **access token** and an **ID token**:

```bash
curl -X POST http://localhost:3000/api/v1/tenant/test-tenant/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=authorization-code-here" \
  -d "client_id=your-client-id" \
  -d "client_secret=your-client-secret" \
  -d "redirect_uri=http://localhost:8080/callback"
```

**Expected Response:**
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "refresh-token-string",
  "scope": "openid profile email",
  "id_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Im9hdXRoMi1rZXktMSJ9..."
}
```

**Note:** The `id_token` is included when the `openid` scope was requested.

### Step 4: Decode and Validate ID Token

The ID token contains user identity information. Decode it to see the claims:

```bash
# Using jwt-cli
echo "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Im9hdXRoMi1rZXktMSJ9..." | jwt decode -

# Or use jwt.io in your browser
```

**ID Token Contents:**
```json
{
  "iss": "https://auth.example.com",
  "sub": "user-123",
  "aud": ["your-client-id"],
  "exp": 1234567890,
  "iat": 1234564290,
  "auth_time": 1234564290,
  "nonce": "random-nonce-if-provided",
  "email": "user@example.com",
  "email_verified": true,
  "name": "John Doe",
  "given_name": "John",
  "family_name": "Doe",
  "picture": "https://example.com/photo.jpg",
  "locale": "en-US"
}
```

**Standard OIDC Claims:**
- `iss` - Issuer identifier
- `sub` - Subject (unique user identifier)
- `aud` - Audience (your client ID)
- `exp` - Expiration time
- `iat` - Issued at time
- `auth_time` - Time when user authenticated
- `nonce` - Nonce value (if provided in request)

### Step 5: Validate ID Token Signature

Retrieve the public keys and validate the token signature:

```bash
# Get JWKS
curl -X GET http://localhost:3000/api/v1/tenant/test-tenant/.well-known/jwks.json
```

**Response:**
```json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "kid": "oauth2-key-1",
      "n": "xGOr-H7A-wiuASDFl...",
      "e": "AQAB",
      "alg": "RS256"
    }
  ]
}
```

**Validation steps:**
1. Verify signature using the public key (matching `kid`)
2. Verify `iss` matches the issuer from discovery
3. Verify `aud` contains your client ID
4. Verify `exp` hasn't passed
5. Verify `nonce` matches (if you sent one)

### Step 6: Get User Info from UserInfo Endpoint

Use the access token to get additional user claims:

```bash
curl -X GET http://localhost:3000/api/v1/tenant/test-tenant/oauth/userinfo \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
```

**Expected Response:**
```json
{
  "sub": "user-123",
  "email": "user@example.com",
  "email_verified": true,
  "name": "John Doe",
  "given_name": "John",
  "family_name": "Doe",
  "picture": "https://example.com/photo.jpg",
  "locale": "en-US",
  "updated_at": 1234567890
}
```

**When to use UserInfo endpoint:**
- To get fresh user claims (ID token is static)
- To get claims that weren't in the ID token
- To verify the access token is still valid

## Complete OIDC Flow Script

```bash
#!/bin/bash

TENANT_ID="test-tenant"
CLIENT_ID="your-client-id"
CLIENT_SECRET="your-client-secret"
REDIRECT_URI="http://localhost:8080/callback"
BASE_URL="http://localhost:3000"

echo "==> Step 1: OIDC Discovery"
echo ""
curl -s "${BASE_URL}/api/v1/tenant/${TENANT_ID}/.well-known/openid-configuration" | jq .

echo ""
echo "==> Step 2: Generate PKCE parameters and nonce"
STATE=$(openssl rand -hex 16)
NONCE=$(openssl rand -hex 16)
CODE_VERIFIER=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-43)
CODE_CHALLENGE=$(echo -n "$CODE_VERIFIER" | openssl sha256 -binary | base64 | tr -d "=+/" | cut -c1-43)

echo "    State: $STATE"
echo "    Nonce: $NONCE"
echo "    Code Challenge: $CODE_CHALLENGE"

echo ""
echo "==> Step 3: Build authorization URL"
AUTH_URL="${BASE_URL}/api/v1/tenant/${TENANT_ID}/oauth/authorize"
AUTH_URL="${AUTH_URL}?response_type=code"
AUTH_URL="${AUTH_URL}&client_id=${CLIENT_ID}"
AUTH_URL="${AUTH_URL}&redirect_uri=${REDIRECT_URI}"
AUTH_URL="${AUTH_URL}&scope=openid%20profile%20email"
AUTH_URL="${AUTH_URL}&state=${STATE}"
AUTH_URL="${AUTH_URL}&nonce=${NONCE}"
AUTH_URL="${AUTH_URL}&code_challenge=${CODE_CHALLENGE}"
AUTH_URL="${AUTH_URL}&code_challenge_method=S256"

echo "    $AUTH_URL"
echo ""
echo "==> Open this URL in your browser and complete authentication"
echo "    Then enter the authorization code:"
read -r CODE

echo ""
echo "==> Step 4: Exchange code for tokens"
TOKEN_RESPONSE=$(curl -s -X POST "${BASE_URL}/api/v1/tenant/${TENANT_ID}/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=${CODE}" \
  -d "client_id=${CLIENT_ID}" \
  -d "client_secret=${CLIENT_SECRET}" \
  -d "redirect_uri=${REDIRECT_URI}" \
  -d "code_verifier=${CODE_VERIFIER}")

echo "$TOKEN_RESPONSE" | jq .

ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r .access_token)
ID_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r .id_token)

echo ""
echo "==> Step 5: Decode ID Token"
echo "$ID_TOKEN" | jwt decode - 2>/dev/null || echo "Install jwt-cli to decode: cargo install jwt-cli"

echo ""
echo "==> Step 6: Fetch user info"
curl -s "${BASE_URL}/api/v1/tenant/${TENANT_ID}/oauth/userinfo" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" | jq .

echo ""
echo "==> Done! ID Token sub claim should match UserInfo sub claim"
```

## Using Nonce for Security

The `nonce` parameter prevents replay attacks:

```bash
# Generate nonce
NONCE=$(openssl rand -hex 16)

# Include in authorization request
curl "http://localhost:3000/api/v1/tenant/test-tenant/oauth/authorize?...&nonce=$NONCE"

# After receiving ID token, verify nonce
ID_TOKEN_NONCE=$(echo "$ID_TOKEN" | jwt decode - | jq -r .nonce)

if [ "$NONCE" != "$ID_TOKEN_NONCE" ]; then
  echo "Nonce mismatch! Possible replay attack"
  exit 1
fi
```

## Integration with Popular Libraries

### JavaScript (Node.js) with openid-client

```javascript
const { Issuer } = require('openid-client');

(async () => {
  const issuer = await Issuer.discover('http://localhost:3000/api/v1/tenant/test-tenant/.well-known/openid-configuration');

  const client = new issuer.Client({
    client_id: 'your-client-id',
    client_secret: 'your-client-secret',
    redirect_uris: ['http://localhost:8080/callback'],
    response_types: ['code'],
  });

  // Generate authorization URL
  const authUrl = client.authorizationUrl({
    scope: 'openid profile email',
    state: 'random-state',
    nonce: 'random-nonce',
  });

  console.log('Visit:', authUrl);

  // After callback, exchange code
  const tokenSet = await client.callback('http://localhost:8080/callback', { code: 'auth-code' }, { state: 'random-state', nonce: 'random-nonce' });

  console.log('ID Token claims:', tokenSet.claims());
  console.log('Access Token:', tokenSet.access_token);

  // Get user info
  const userinfo = await client.userinfo(tokenSet.access_token);
  console.log('User Info:', userinfo);
})();
```

### Python with authlib

```python
from authlib.integrations.requests_client import OAuth2Session

client_id = 'your-client-id'
client_secret = 'your-client-secret'
redirect_uri = 'http://localhost:8080/callback'
discovery_url = 'http://localhost:3000/api/v1/tenant/test-tenant/.well-known/openid-configuration'

# Create OAuth2 session
client = OAuth2Session(
    client_id=client_id,
    client_secret=client_secret,
    redirect_uri=redirect_uri,
    scope='openid profile email'
)

# Get authorization URL
authorization_url, state = client.create_authorization_url(
    'http://localhost:3000/api/v1/tenant/test-tenant/oauth/authorize'
)

print('Visit:', authorization_url)

# After callback, exchange code
authorization_response = 'http://localhost:8080/callback?code=xxx&state=xxx'
token = client.fetch_token(
    'http://localhost:3000/api/v1/tenant/test-tenant/oauth/token',
    authorization_response=authorization_response
)

# Decode ID token
id_token = token['id_token']
print('ID Token:', id_token)

# Get user info
userinfo = client.get('http://localhost:3000/api/v1/tenant/test-tenant/oauth/userinfo').json()
print('User Info:', userinfo)
```

## ID Token vs Access Token vs UserInfo

| Data Source | Purpose | Contains | Cached |
|-------------|---------|----------|--------|
| **ID Token** | User authentication | User identity claims | Yes (until expired) |
| **Access Token** | API authorization | Permissions/scopes | Yes (until expired) |
| **UserInfo Endpoint** | Fresh user data | Latest user claims | No (always fresh) |

**Best practice:** Use ID token for initial user info, then call UserInfo endpoint if you need fresh data.

## Error Handling

### Missing openid Scope

```bash
# Without openid scope
curl "http://localhost:3000/api/v1/tenant/test-tenant/oauth/authorize?response_type=code&client_id=your-client-id&redirect_uri=http://localhost:8080/callback&scope=profile%20email&state=random-state"
```

**Result:** No ID token in response, only access token.

### Invalid Access Token at UserInfo

```bash
curl -X GET http://localhost:3000/api/v1/tenant/test-tenant/oauth/userinfo \
  -H "Authorization: Bearer invalid-token"
```

**Response:**
```json
{
  "error": "invalid_token",
  "error_description": "The access token is invalid or expired"
}
```

## Next Steps

- Try [API Key Management](04-api-key-management.md) for long-lived tokens
- Explore [SAML SSO](05-saml-sso.md) for enterprise integrations
- Return to [OAuth2 flows](01-oauth2-client-credentials.md) for comparison

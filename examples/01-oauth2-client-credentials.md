# OAuth2 Client Credentials Flow

This example demonstrates the OAuth2 Client Credentials grant type, which is used for **machine-to-machine** authentication where there is no user involved.

## Use Case

Perfect for:
- Backend services authenticating with APIs
- Microservices communicating with each other
- Automated scripts or cron jobs
- Server-to-server authentication

## Prerequisites

1. API is running on `http://localhost:3000`
2. You have a tenant configured in `config.yaml`
3. OAuth2 is enabled for the tenant

## Step-by-Step Example

### Step 1: Check Available Identity Providers

First, verify that OAuth2 is available for your tenant:

```bash
curl -X GET http://localhost:3000/api/v1/tenant/test-tenant/strategies
```

**Expected Response:**
```json
{
  "tenant_id": "test-tenant",
  "tenant_name": "Test Tenant",
  "strategies": [
    {"name": "oauth2", "type": "OAuth2 Authorization Server"},
    {"name": "oidc", "type": "OpenID Connect Provider"}
  ]
}
```

### Step 2: Request Access Token (Client Credentials)

Request an access token using client credentials:

```bash
curl -X POST http://localhost:3000/api/v1/tenant/test-tenant/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "client_id=your-client-id" \
  -d "client_secret=your-client-secret" \
  -d "scope=api:read api:write"
```

**Parameters:**
- `grant_type`: Must be `client_credentials`
- `client_id`: Your application's client ID
- `client_secret`: Your application's client secret
- `scope`: Space-separated list of requested scopes (optional)

**Expected Response:**
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Im9hdXRoMi1rZXktMSJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "api:read api:write"
}
```

### Step 3: Use the Access Token

Use the access token to make authenticated requests:

```bash
curl -X GET http://localhost:3000/api/v1/protected-resource \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Im9hdXRoMi1rZXktMSJ9..."
```

### Step 4: Inspect the Token (Optional)

You can decode the JWT to see its contents (use jwt.io or a JWT library):

```bash
# Using jwt-cli (if installed)
echo "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Im9hdXRoMi1rZXktMSJ9..." | jwt decode -
```

**Token Contents:**
```json
{
  "iss": "https://auth.example.com",
  "sub": "client-id",
  "aud": ["your-api"],
  "exp": 1234567890,
  "iat": 1234564290,
  "scope": "api:read api:write",
  "client_id": "your-client-id"
}
```

### Step 5: Verify Token Signature (Optional)

Retrieve the public keys to verify the token signature:

```bash
curl -X GET http://localhost:3000/api/v1/tenant/test-tenant/.well-known/jwks.json
```

**Expected Response:**
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

## Complete Script

Here's a complete bash script to automate the flow:

```bash
#!/bin/bash

TENANT_ID="test-tenant"
CLIENT_ID="your-client-id"
CLIENT_SECRET="your-client-secret"
BASE_URL="http://localhost:3000"

echo "==> Requesting access token..."
RESPONSE=$(curl -s -X POST "$BASE_URL/api/v1/tenant/$TENANT_ID/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "client_id=$CLIENT_ID" \
  -d "client_secret=$CLIENT_SECRET" \
  -d "scope=api:read api:write")

echo "$RESPONSE" | jq .

ACCESS_TOKEN=$(echo "$RESPONSE" | jq -r .access_token)

echo ""
echo "==> Access token obtained: ${ACCESS_TOKEN:0:50}..."
echo ""
echo "==> Making authenticated request..."

curl -X GET "$BASE_URL/api/v1/protected-resource" \
  -H "Authorization: Bearer $ACCESS_TOKEN"
```

## Error Handling

### Invalid Client Credentials

```bash
curl -X POST http://localhost:3000/api/v1/tenant/test-tenant/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "client_id=invalid" \
  -d "client_secret=wrong"
```

**Response:**
```json
{
  "error": "invalid_client",
  "error_description": "Client authentication failed"
}
```

### Missing Grant Type

```bash
curl -X POST http://localhost:3000/api/v1/tenant/test-tenant/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=your-client-id" \
  -d "client_secret=your-client-secret"
```

**Response:**
```json
{
  "error": "invalid_request",
  "error_description": "Missing grant_type parameter"
}
```

## Security Considerations

1. **Never expose client secrets**: Keep client secrets secure and never commit them to version control
2. **Use HTTPS in production**: Always use HTTPS to prevent token interception
3. **Rotate credentials regularly**: Implement a process to rotate client credentials
4. **Limit scopes**: Request only the minimum scopes needed for your application
5. **Store tokens securely**: Don't log or expose access tokens

## Token Expiration

Access tokens expire after 1 hour by default. When a token expires:

```bash
curl -X GET http://localhost:3000/api/v1/protected-resource \
  -H "Authorization: Bearer expired-token"
```

**Response:**
```json
{
  "error": "invalid_token",
  "error_description": "Token has expired"
}
```

Simply request a new token using the same client credentials.

## Next Steps

- Try the [OAuth2 Authorization Code Flow](02-oauth2-authorization-code.md) for user authentication
- Explore [API Key Management](04-api-key-management.md) for long-lived tokens
- Learn about [OpenID Connect](03-openid-connect.md) for identity information

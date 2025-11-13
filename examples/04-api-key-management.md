# API Key Management

This example demonstrates how to create, list, and revoke API keys for **long-lived authentication**. API keys are JWT tokens with extended or no expiration, perfect for machine-to-machine communication.

## Use Case

Perfect for:
- CI/CD pipelines and automation scripts
- Server-to-server communication
- Background jobs and scheduled tasks
- Third-party integrations
- CLI tools and SDKs
- Monitoring and alerting systems

## API Keys vs OAuth2 Tokens

| Feature | OAuth2 Access Token | API Key |
|---------|-------------------|---------|
| Lifespan | Short (1 hour) | Long (months) or unlimited |
| Rotation | Automatic (refresh token) | Manual |
| Revocation | Expiration-based | Immediate |
| Use Case | User sessions | Automated systems |
| Scopes | Dynamic | Fixed at creation |

## Prerequisites

1. API is running on `http://localhost:3000`
2. You have a tenant configured with API keys enabled
3. You have admin/service credentials to create API keys

## Step-by-Step Example

### Step 1: Create an API Key

Create a new API key with specific scopes:

```bash
curl -X POST http://localhost:3000/api/v1/tenant/test-tenant/api-keys/create \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Production Backend Service",
    "scopes": ["api:read", "api:write", "users:read"],
    "expires_in_days": 90
  }'
```

**Request Body:**
- `name` - Descriptive name for the API key (required)
- `scopes` - Array of permission scopes (required)
- `expires_in_days` - Expiration in days, or 0 for no expiration (optional, default: 0)

**Expected Response:**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "Production Backend Service",
  "api_key": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImFwaS1rZXktMSJ9.eyJzdWIiOiI1NTBlODQwMC1lMjliLTQxZDQtYTcxNi00NDY2NTU0NDAwMDAiLCJpc3MiOiJodHRwczovL2F1dGguZXhhbXBsZS5jb20iLCJhdWQiOlsieW91ci1hcGkiXSwiZXhwIjpudWxsLCJpYXQiOjE3MDAwMDAwMDAsInNjb3BlIjoiYXBpOnJlYWQgYXBpOndyaXRlIHVzZXJzOnJlYWQiLCJhcGlfa2V5Ijp0cnVlfQ...",
  "scopes": ["api:read", "api:write", "users:read"],
  "created_at": 1700000000,
  "expires_at": 1707776000
}
```

**⚠️ Important:** Save the `api_key` value immediately! It won't be shown again.

### Step 2: Use the API Key

Use the API key as a Bearer token in API requests:

```bash
curl -X GET http://localhost:3000/api/v1/protected-resource \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImFwaS1rZXktMSJ9..."
```

**The API key works exactly like an OAuth2 access token**, but with much longer expiration.

### Step 3: List All API Keys

Retrieve all API keys for a tenant:

```bash
curl -X GET http://localhost:3000/api/v1/tenant/test-tenant/api-keys/list
```

**Expected Response:**
```json
[
  {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "name": "Production Backend Service",
    "scopes": ["api:read", "api:write", "users:read"],
    "created_at": 1700000000,
    "expires_at": 1707776000,
    "last_used": 1700123456,
    "revoked": false
  },
  {
    "id": "660e8400-e29b-41d4-a716-446655440001",
    "name": "CI/CD Pipeline",
    "scopes": ["api:write", "deployments:create"],
    "created_at": 1699000000,
    "expires_at": null,
    "last_used": null,
    "revoked": false
  }
]
```

**Note:** The actual API key value is **never** returned in list operations for security.

### Step 4: Revoke an API Key

Immediately revoke an API key:

```bash
curl -X POST http://localhost:3000/api/v1/tenant/test-tenant/api-keys/550e8400-e29b-41d4-a716-446655440000/revoke
```

**Expected Response:**
```json
{
  "success": true,
  "message": "API key revoked successfully"
}
```

**After revocation**, any requests using this API key will fail:

```bash
curl -X GET http://localhost:3000/api/v1/protected-resource \
  -H "Authorization: Bearer revoked-api-key"
```

**Response:**
```json
{
  "error": "invalid_token",
  "error_description": "API key has been revoked"
}
```

## Complete API Key Lifecycle Script

```bash
#!/bin/bash

TENANT_ID="test-tenant"
BASE_URL="http://localhost:3000"

echo "==> Step 1: Create API Key"
echo ""

CREATE_RESPONSE=$(curl -s -X POST "${BASE_URL}/api/v1/tenant/${TENANT_ID}/api-keys/create" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Test API Key",
    "scopes": ["api:read", "api:write"],
    "expires_in_days": 30
  }')

echo "$CREATE_RESPONSE" | jq .

API_KEY=$(echo "$CREATE_RESPONSE" | jq -r .api_key)
API_KEY_ID=$(echo "$CREATE_RESPONSE" | jq -r .id)

echo ""
echo "==> Step 2: Test API Key"
echo ""

curl -s -X GET "${BASE_URL}/api/v1/protected-resource" \
  -H "Authorization: Bearer ${API_KEY}" | jq .

echo ""
echo "==> Step 3: List All API Keys"
echo ""

curl -s -X GET "${BASE_URL}/api/v1/tenant/${TENANT_ID}/api-keys/list" | jq .

echo ""
echo "==> Step 4: Decode API Key (inspect claims)"
echo ""

echo "$API_KEY" | jwt decode - 2>/dev/null || echo "Install jwt-cli: cargo install jwt-cli"

echo ""
echo "==> Step 5: Revoke API Key"
echo ""

curl -s -X POST "${BASE_URL}/api/v1/tenant/${TENANT_ID}/api-keys/${API_KEY_ID}/revoke" | jq .

echo ""
echo "==> Step 6: Try Using Revoked Key (should fail)"
echo ""

curl -s -X GET "${BASE_URL}/api/v1/protected-resource" \
  -H "Authorization: Bearer ${API_KEY}" | jq .

echo ""
echo "==> Done!"
```

## Advanced Usage Examples

### Creating API Keys with Different Scopes

#### Read-Only API Key

```bash
curl -X POST http://localhost:3000/api/v1/tenant/test-tenant/api-keys/create \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Monitoring Service (Read-Only)",
    "scopes": ["api:read", "metrics:read"],
    "expires_in_days": 365
  }'
```

#### Admin API Key (No Expiration)

```bash
curl -X POST http://localhost:3000/api/v1/tenant/test-tenant/api-keys/create \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Admin Tools",
    "scopes": ["api:read", "api:write", "admin:all"],
    "expires_in_days": 0
  }'
```

#### CI/CD Pipeline Key

```bash
curl -X POST http://localhost:3000/api/v1/tenant/test-tenant/api-keys/create \
  -H "Content-Type: application/json" \
  -d '{
    "name": "GitHub Actions CI/CD",
    "scopes": ["deployments:create", "deployments:read"],
    "expires_in_days": 90
  }'
```

### Storing API Keys Securely

#### Environment Variables

```bash
# .env file (don't commit to git!)
API_KEY=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...

# Load and use
export $(cat .env | xargs)
curl -H "Authorization: Bearer $API_KEY" http://localhost:3000/api/v1/resource
```

#### GitHub Secrets (CI/CD)

```yaml
# .github/workflows/deploy.yml
name: Deploy
on: [push]
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Deploy to API
        env:
          API_KEY: ${{ secrets.API_KEY }}
        run: |
          curl -X POST http://api.example.com/deploy \
            -H "Authorization: Bearer $API_KEY" \
            -d '{"version": "${{ github.sha }}"}'
```

#### AWS Secrets Manager

```bash
# Store API key
aws secretsmanager create-secret \
  --name production/api-key \
  --secret-string "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."

# Retrieve and use
API_KEY=$(aws secretsmanager get-secret-value \
  --secret-id production/api-key \
  --query SecretString \
  --output text)

curl -H "Authorization: Bearer $API_KEY" http://localhost:3000/api/v1/resource
```

#### HashiCorp Vault

```bash
# Store API key
vault kv put secret/api-key value="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."

# Retrieve and use
API_KEY=$(vault kv get -field=value secret/api-key)
curl -H "Authorization: Bearer $API_KEY" http://localhost:3000/api/v1/resource
```

## Monitoring and Auditing

### Track API Key Usage

The `last_used` field helps monitor API key activity:

```bash
curl -X GET http://localhost:3000/api/v1/tenant/test-tenant/api-keys/list | jq '.[] | {name: .name, last_used: .last_used}'
```

**Output:**
```json
{
  "name": "Production Backend Service",
  "last_used": 1700123456
}
{
  "name": "CI/CD Pipeline",
  "last_used": null
}
```

**Unused keys** (where `last_used` is `null`) should be reviewed and potentially revoked.

### Expiring Keys Report

Find keys expiring soon:

```bash
# Get current timestamp
NOW=$(date +%s)

# Find keys expiring in next 7 days
curl -s http://localhost:3000/api/v1/tenant/test-tenant/api-keys/list | \
  jq --arg now "$NOW" '.[] | select(.expires_at != null and (.expires_at - ($now | tonumber)) < 604800 and .revoked == false) | {name: .name, expires_at: .expires_at}'
```

## API Key Best Practices

### 1. Principle of Least Privilege

Only grant necessary scopes:

```bash
# Bad: Overly permissive
curl -X POST http://localhost:3000/api/v1/tenant/test-tenant/api-keys/create \
  -H "Content-Type: application/json" \
  -d '{"name": "My Service", "scopes": ["admin:all"]}'

# Good: Minimal scopes
curl -X POST http://localhost:3000/api/v1/tenant/test-tenant/api-keys/create \
  -H "Content-Type: application/json" \
  -d '{"name": "My Service", "scopes": ["api:read", "data:write"]}'
```

### 2. Regular Rotation

Rotate API keys periodically:

```bash
#!/bin/bash
# rotate-api-key.sh

OLD_KEY_ID="$1"
KEY_NAME="$2"

# Create new key
NEW_KEY=$(curl -s -X POST http://localhost:3000/api/v1/tenant/test-tenant/api-keys/create \
  -H "Content-Type: application/json" \
  -d "{\"name\": \"${KEY_NAME}\", \"scopes\": [\"api:read\", \"api:write\"], \"expires_in_days\": 90}")

echo "New key created:"
echo "$NEW_KEY" | jq .

# Update your application configuration with new key
# ... deployment steps ...

# After successful deployment, revoke old key
sleep 300  # Wait 5 minutes to ensure new key is working

curl -s -X POST "http://localhost:3000/api/v1/tenant/test-tenant/api-keys/${OLD_KEY_ID}/revoke"
echo "Old key revoked"
```

### 3. Descriptive Names

Use descriptive names to identify API keys:

```bash
# Bad
curl -d '{"name": "Key1", "scopes": ["api:read"]}'

# Good
curl -d '{"name": "Production-Backend-Service-v2-ReadOnly-2024", "scopes": ["api:read"]}'
```

### 4. Monitoring and Alerts

Set up alerts for:
- Unused API keys (never used after 30 days)
- Keys expiring soon (< 7 days)
- Revoked key usage attempts
- Excessive failed authentication attempts

## Error Scenarios

### Invalid Scopes

```bash
curl -X POST http://localhost:3000/api/v1/tenant/test-tenant/api-keys/create \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Test Key",
    "scopes": ["invalid:scope"],
    "expires_in_days": 30
  }'
```

**Response:**
```json
{
  "error": "invalid_scope",
  "error_description": "Scope 'invalid:scope' is not allowed for this tenant"
}
```

### Missing Name

```bash
curl -X POST http://localhost:3000/api/v1/tenant/test-tenant/api-keys/create \
  -H "Content-Type: application/json" \
  -d '{
    "scopes": ["api:read"]
  }'
```

**Response:**
```json
{
  "error": "invalid_request",
  "error_description": "Missing required field: name"
}
```

### API Key Not Found

```bash
curl -X POST http://localhost:3000/api/v1/tenant/test-tenant/api-keys/invalid-id/revoke
```

**Response:**
```json
{
  "error": "not_found",
  "error_description": "API key not found"
}
```

## Decoding API Key JWT

API keys are JWTs with special claims:

```bash
echo "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImFwaS1rZXktMSJ9..." | jwt decode -
```

**API Key Claims:**
```json
{
  "sub": "550e8400-e29b-41d4-a716-446655440000",
  "iss": "https://auth.example.com",
  "aud": ["your-api"],
  "exp": null,
  "iat": 1700000000,
  "scope": "api:read api:write users:read",
  "api_key": true,
  "tenant_id": "test-tenant"
}
```

**Special claims:**
- `api_key: true` - Identifies this JWT as an API key
- `exp: null` - No expiration (or future date if expiration was set)
- `sub` - API key ID (used for revocation)

## Migration from OAuth2 to API Keys

If migrating from OAuth2 client credentials to API keys:

```bash
#!/bin/bash
# migrate-to-api-keys.sh

# Step 1: Create API key with same scopes as OAuth2 client
API_KEY=$(curl -s -X POST http://localhost:3000/api/v1/tenant/test-tenant/api-keys/create \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Migrated from OAuth2 Client",
    "scopes": ["api:read", "api:write"],
    "expires_in_days": 0
  }' | jq -r .api_key)

echo "New API Key: $API_KEY"
echo "Store this in your environment variables and redeploy"
echo ""
echo "# Before:"
echo "curl -X POST .../oauth/token -d grant_type=client_credentials ..."
echo ""
echo "# After:"
echo "curl -H \"Authorization: Bearer $API_KEY\" ..."
```

## Next Steps

- Explore [SAML SSO](05-saml-sso.md) for enterprise integrations
- Review [OAuth2 Client Credentials](01-oauth2-client-credentials.md) for comparison
- Learn about [OpenID Connect](03-openid-connect.md) for user authentication

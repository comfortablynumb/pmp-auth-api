# API Key Management

**Difficulty**: ⭐ Easy
**Use Case**: Long-lived authentication, CI/CD, automation, third-party integrations

## Overview

API keys provide long-lived authentication tokens perfect for automated systems, CI/CD pipelines, and third-party integrations. They are JWT-based tokens with configurable scopes and expiration.

## When to Use

- CI/CD pipelines
- Automated scripts and cron jobs
- Third-party service integrations
- CLI tools
- Server-to-server authentication
- Developer testing and debugging

## Creating API Keys

### Create API Key (curl)

```bash
curl -X POST \
  'http://localhost:3000/api/v1/tenant/my-tenant/api-keys/create' \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer <user-access-token>' \
  -d '{
    "name": "CI/CD Pipeline Key",
    "scopes": ["api:read", "api:write", "deploy:production"],
    "expires_in_days": 90
  }'
```

### Response

```json
{
  "id": "key-550e8400-e29b-41d4-a716-446655440000",
  "name": "CI/CD Pipeline Key",
  "api_key": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImFwaS1rZXktMSJ9.eyJzdWIiOiJ1c2VyLTEyMyIsInNjb3BlcyI6WyJhcGk6cmVhZCIsImFwaTp3cml0ZSIsImRlcGxveTpwcm9kdWN0aW9uIl0sImtleV9pZCI6ImtleS01NTBlODQwMC1lMjliLTQxZDQtYTcxNi00NDY2NTU0NDAwMDAiLCJpc3MiOiJodHRwczovL2F1dGguZXhhbXBsZS5jb20iLCJpYXQiOjE3MDU0MTYwMDAsImV4cCI6MTcxMzE5MjAwMH0.signature",
  "scopes": ["api:read", "api:write", "deploy:production"],
  "created_at": 1705416000,
  "expires_at": 1713192000,
  "last_used": null,
  "revoked": false
}
```

**Important**: Save the `api_key` value immediately - it won't be shown again!

### Create Non-Expiring API Key

```bash
curl -X POST \
  'http://localhost:3000/api/v1/tenant/my-tenant/api-keys/create' \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer <user-access-token>' \
  -d '{
    "name": "Permanent Integration Key",
    "scopes": ["api:read"],
    "expires_in_days": 0
  }'
```

## Using API Keys

### Authentication Header

```bash
curl -X GET \
  'http://localhost:3000/api/v1/protected-resource' \
  -H 'Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImFwaS1rZXktMSJ9...'
```

### Example: Python Script

```python
import requests
import os

class APIKeyClient:
    def __init__(self, api_key, base_url):
        self.api_key = api_key
        self.base_url = base_url
        self.headers = {
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json'
        }

    def get(self, endpoint):
        """Make GET request"""
        response = requests.get(
            f"{self.base_url}{endpoint}",
            headers=self.headers
        )
        response.raise_for_status()
        return response.json()

    def post(self, endpoint, data):
        """Make POST request"""
        response = requests.post(
            f"{self.base_url}{endpoint}",
            headers=self.headers,
            json=data
        )
        response.raise_for_status()
        return response.json()

    def put(self, endpoint, data):
        """Make PUT request"""
        response = requests.put(
            f"{self.base_url}{endpoint}",
            headers=self.headers,
            json=data
        )
        response.raise_for_status()
        return response.json()

    def delete(self, endpoint):
        """Make DELETE request"""
        response = requests.delete(
            f"{self.base_url}{endpoint}",
            headers=self.headers
        )
        response.raise_for_status()
        return response.status_code == 204

# Usage
api_key = os.environ.get('API_KEY')  # Load from environment
client = APIKeyClient(api_key, 'http://localhost:3000')

try:
    # Fetch resources
    resources = client.get('/api/v1/resources')
    print(f"Found {len(resources)} resources")

    # Create resource
    new_resource = client.post('/api/v1/resources', {
        'name': 'New Resource',
        'type': 'automated'
    })
    print(f"Created resource: {new_resource['id']}")

except requests.exceptions.HTTPError as e:
    print(f"API error: {e}")
except Exception as e:
    print(f"Error: {e}")
```

### Example: GitHub Actions CI/CD

```yaml
# .github/workflows/deploy.yml
name: Deploy Application

on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout code
        uses: actions/checkout@v3

      - name: Deploy to production
        env:
          API_KEY: ${{ secrets.DEPLOY_API_KEY }}
        run: |
          curl -X POST \
            'https://api.example.com/deploy' \
            -H "Authorization: Bearer $API_KEY" \
            -H 'Content-Type: application/json' \
            -d '{
              "environment": "production",
              "version": "${{ github.sha }}"
            }'
```

### Example: Node.js CLI Tool

```javascript
#!/usr/bin/env node

const axios = require('axios');
const fs = require('fs');
const path = require('path');
const os = require('os');

class APIClient {
    constructor() {
        // Load API key from config file
        const configPath = path.join(os.homedir(), '.myapp', 'config.json');
        const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));

        this.apiKey = config.apiKey;
        this.baseURL = config.baseURL || 'http://localhost:3000';
    }

    async request(method, endpoint, data = null) {
        const config = {
            method,
            url: `${this.baseURL}${endpoint}`,
            headers: {
                'Authorization': `Bearer ${this.apiKey}`,
                'Content-Type': 'application/json'
            }
        };

        if (data) {
            config.data = data;
        }

        const response = await axios(config);
        return response.data;
    }

    async listResources() {
        return this.request('GET', '/api/v1/resources');
    }

    async createResource(name, type) {
        return this.request('POST', '/api/v1/resources', { name, type });
    }

    async deleteResource(id) {
        return this.request('DELETE', `/api/v1/resources/${id}`);
    }
}

// CLI commands
const commands = {
    list: async () => {
        const client = new APIClient();
        const resources = await client.listResources();
        console.table(resources);
    },

    create: async (name, type) => {
        const client = new APIClient();
        const resource = await client.createResource(name, type);
        console.log('Created:', resource);
    },

    delete: async (id) => {
        const client = new APIClient();
        await client.deleteResource(id);
        console.log(`Deleted resource ${id}`);
    }
};

// Parse command line
const [,, command, ...args] = process.argv;

if (commands[command]) {
    commands[command](...args).catch(err => {
        console.error('Error:', err.message);
        process.exit(1);
    });
} else {
    console.log('Usage: myapp <command> [args]');
    console.log('Commands: list, create <name> <type>, delete <id>');
    process.exit(1);
}
```

## Managing API Keys

### List All API Keys

```bash
curl -X GET \
  'http://localhost:3000/api/v1/tenant/my-tenant/api-keys/list' \
  -H 'Authorization: Bearer <user-access-token>'
```

### Response

```json
[
  {
    "id": "key-550e8400-e29b-41d4-a716-446655440000",
    "name": "CI/CD Pipeline Key",
    "scopes": ["api:read", "api:write", "deploy:production"],
    "created_at": 1705416000,
    "expires_at": 1713192000,
    "last_used": 1705500000,
    "revoked": false
  },
  {
    "id": "key-7c9e6679-7425-40de-944b-e07fc1f90ae7",
    "name": "Development Key",
    "scopes": ["api:read"],
    "created_at": 1705330000,
    "expires_at": 1712106000,
    "last_used": null,
    "revoked": false
  }
]
```

### Revoke API Key

```bash
curl -X POST \
  'http://localhost:3000/api/v1/tenant/my-tenant/api-keys/key-550e8400-e29b-41d4-a716-446655440000/revoke' \
  -H 'Authorization: Bearer <user-access-token>'
```

### Response

```json
{
  "success": true,
  "message": "API key revoked successfully"
}
```

## Scope Management

### Common Scopes

```javascript
const scopes = {
    // Read access
    'api:read': 'Read API resources',
    'admin:read': 'Read admin resources',

    // Write access
    'api:write': 'Create/update API resources',
    'admin:write': 'Create/update admin resources',

    // Special permissions
    'deploy:staging': 'Deploy to staging',
    'deploy:production': 'Deploy to production',
    'billing:manage': 'Manage billing',
    'users:manage': 'Manage users',

    // Full access
    'admin:all': 'Full administrative access'
};
```

### Checking Scopes in Your API

```python
from functools import wraps
from flask import request, jsonify
import jwt

def require_scope(*required_scopes):
    """Decorator to check API key scopes"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Extract token from header
            auth_header = request.headers.get('Authorization', '')
            if not auth_header.startswith('Bearer '):
                return jsonify({'error': 'No token provided'}), 401

            token = auth_header[7:]

            try:
                # Decode and verify token
                payload = jwt.decode(
                    token,
                    PUBLIC_KEY,
                    algorithms=['RS256'],
                    audience='your-api'
                )

                # Check scopes
                token_scopes = payload.get('scopes', [])
                if not any(scope in token_scopes for scope in required_scopes):
                    return jsonify({
                        'error': 'Insufficient permissions',
                        'required': list(required_scopes),
                        'provided': token_scopes
                    }), 403

                # Attach payload to request
                request.api_key_info = payload

            except jwt.ExpiredSignatureError:
                return jsonify({'error': 'Token expired'}), 401
            except jwt.InvalidTokenError as e:
                return jsonify({'error': 'Invalid token', 'detail': str(e)}), 401

            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Usage
@app.route('/api/v1/deploy', methods=['POST'])
@require_scope('deploy:production')
def deploy_production():
    # Only keys with 'deploy:production' scope can access
    return jsonify({'status': 'deployed'})

@app.route('/api/v1/resources', methods=['GET'])
@require_scope('api:read', 'admin:all')
def list_resources():
    # Keys with either 'api:read' OR 'admin:all' can access
    key_id = request.api_key_info.get('key_id')
    return jsonify({'resources': [], 'accessed_by': key_id})
```

## Best Practices

### 1. Secure Storage

```bash
# Store in environment variable (Linux/macOS)
export API_KEY="eyJhbGciOiJSUzI1NiIs..."

# Store in .env file (not in version control!)
echo "API_KEY=eyJhbGciOiJSUzI1NiIs..." >> .env

# Use secrets manager (AWS)
aws secretsmanager create-secret \
  --name prod/api-key \
  --secret-string "eyJhbGciOiJSUzI1NiIs..."
```

### 2. Key Rotation

```python
import schedule
import time

def rotate_api_key():
    """Rotate API key every 90 days"""
    # Create new key
    new_key = create_api_key(
        name='Automated Key (Rotated)',
        scopes=['api:read', 'api:write'],
        expires_in_days=90
    )

    # Update configuration
    update_configuration(new_key['api_key'])

    # Revoke old key after grace period
    time.sleep(86400)  # 24 hour grace period
    revoke_api_key(old_key_id)

# Schedule rotation
schedule.every(90).days.do(rotate_api_key)

while True:
    schedule.run_pending()
    time.sleep(3600)  # Check every hour
```

### 3. Principle of Least Privilege

```javascript
// Bad: Overly broad permissions
const apiKey = createAPIKey({
    name: 'Read-only script',
    scopes: ['admin:all']  // ❌ Too much access!
});

// Good: Minimal required permissions
const apiKey = createAPIKey({
    name: 'Read-only script',
    scopes: ['api:read']   // ✅ Only what's needed
});
```

### 4. Monitoring and Auditing

```python
def log_api_key_usage(key_id, endpoint, success):
    """Log all API key usage"""
    logger.info('API Key Usage', extra={
        'key_id': key_id,
        'endpoint': endpoint,
        'success': success,
        'timestamp': datetime.utcnow().isoformat()
    })

def check_suspicious_activity(key_id):
    """Monitor for suspicious patterns"""
    # Check for unusual usage patterns
    recent_requests = get_recent_requests(key_id, hours=1)

    if len(recent_requests) > 1000:
        alert_security_team(f'High request volume from key {key_id}')

    # Check for access from new locations
    current_ip = get_current_ip()
    known_ips = get_known_ips(key_id)

    if current_ip not in known_ips:
        alert_security_team(f'Access from new IP: {current_ip}')
```

## Security Considerations

1. **Never commit API keys to version control**
   - Use `.gitignore` for `.env` files
   - Scan repositories for leaked keys
   - Revoke immediately if exposed

2. **Use short expiration for high-risk keys**
   - Production deployment keys: 30-90 days
   - Development keys: 7-30 days
   - Testing keys: 1-7 days

3. **Implement rate limiting**
   - Prevent brute force attempts
   - Protect against abuse
   - Monitor for suspicious patterns

4. **Rotate keys regularly**
   - Automated rotation every 90 days
   - Manual rotation on security events
   - Grace period for seamless transition

5. **Monitor key usage**
   - Track last used timestamp
   - Alert on unusual patterns
   - Revoke unused keys

6. **Scope management**
   - Grant minimum required permissions
   - Regularly audit scopes
   - Revoke unnecessary access

## Common Errors

### Expired API Key
```json
{
  "error": "invalid_token",
  "error_description": "API key has expired"
}
```
**Solution**: Create a new API key

### Insufficient Scope
```json
{
  "error": "insufficient_scope",
  "error_description": "API key does not have required permissions"
}
```
**Solution**: Create new key with required scopes or update existing key scopes

### Revoked API Key
```json
{
  "error": "invalid_token",
  "error_description": "API key has been revoked"
}
```
**Solution**: Create a new API key

## Related Examples

- [OAuth2 Client Credentials](oauth2_client_credentials.md) - Alternative for M2M auth
- [Rate Limiting](rate_limiting.md) - Protect your API
- [Audit Logging](audit_logging.md) - Track API key usage

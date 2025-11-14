# OAuth2 Client Credentials Flow

**Difficulty**: ⭐ Easy
**Use Case**: Machine-to-machine authentication, backend services, CI/CD pipelines

## Overview

The Client Credentials grant is used when applications request an access token to access their own resources, not on behalf of a user. This is typically used for server-to-server API calls.

## When to Use

- Backend service authentication
- Microservice-to-microservice communication
- CI/CD pipeline automation
- Scheduled jobs and batch processes
- Server applications without user context

## Prerequisites

1. A registered OAuth2 client with `client_credentials` grant type
2. Client ID and Client Secret
3. Tenant ID

## Example: Simple Client Credentials

### 1. Request Access Token

```bash
curl -X POST \
  'http://localhost:3000/api/v1/tenant/my-tenant/oauth/token' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=client_credentials' \
  -d 'client_id=service-client-123' \
  -d 'client_secret=super-secret-key' \
  -d 'scope=api:read api:write'
```

### 2. Response

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Im9hdXRoMi1rZXktMSJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "api:read api:write"
}
```

### 3. Use Access Token

```bash
curl -X GET \
  'http://localhost:3000/api/v1/protected-resource' \
  -H 'Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Im9hdXRoMi1rZXktMSJ9...'
```

## Example: Python Application

```python
import requests
import json
from datetime import datetime, timedelta

class OAuth2Client:
    def __init__(self, tenant_id, client_id, client_secret, base_url):
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.base_url = base_url
        self.token_url = f"{base_url}/api/v1/tenant/{tenant_id}/oauth/token"
        self.access_token = None
        self.expires_at = None

    def get_access_token(self):
        """Get or refresh access token"""
        # Check if we have a valid cached token
        if self.access_token and self.expires_at > datetime.now():
            return self.access_token

        # Request new token
        payload = {
            'grant_type': 'client_credentials',
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'scope': 'api:read api:write'
        }

        response = requests.post(self.token_url, data=payload)
        response.raise_for_status()

        token_data = response.json()
        self.access_token = token_data['access_token']
        self.expires_at = datetime.now() + timedelta(seconds=token_data['expires_in'] - 60)

        return self.access_token

    def call_api(self, endpoint, method='GET', data=None):
        """Make authenticated API call"""
        token = self.get_access_token()
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }

        url = f"{self.base_url}{endpoint}"

        if method == 'GET':
            response = requests.get(url, headers=headers)
        elif method == 'POST':
            response = requests.post(url, headers=headers, json=data)
        elif method == 'PUT':
            response = requests.put(url, headers=headers, json=data)
        elif method == 'DELETE':
            response = requests.delete(url, headers=headers)

        response.raise_for_status()
        return response.json()

# Usage
if __name__ == "__main__":
    client = OAuth2Client(
        tenant_id="my-tenant",
        client_id="service-client-123",
        client_secret="super-secret-key",
        base_url="http://localhost:3000"
    )

    # Make API calls
    try:
        data = client.call_api('/api/v1/protected-resource')
        print("Response:", json.dumps(data, indent=2))

        # Create resource
        new_resource = client.call_api(
            '/api/v1/resources',
            method='POST',
            data={'name': 'New Resource', 'type': 'test'}
        )
        print("Created:", json.dumps(new_resource, indent=2))

    except requests.exceptions.HTTPError as e:
        print(f"HTTP Error: {e}")
    except Exception as e:
        print(f"Error: {e}")
```

## Example: Node.js Application

```javascript
const axios = require('axios');

class OAuth2Client {
    constructor(tenantId, clientId, clientSecret, baseUrl) {
        this.tenantId = tenantId;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.baseUrl = baseUrl;
        this.tokenUrl = `${baseUrl}/api/v1/tenant/${tenantId}/oauth/token`;
        this.accessToken = null;
        this.expiresAt = null;
    }

    async getAccessToken() {
        // Check cached token
        if (this.accessToken && this.expiresAt > Date.now()) {
            return this.accessToken;
        }

        // Request new token
        const params = new URLSearchParams();
        params.append('grant_type', 'client_credentials');
        params.append('client_id', this.clientId);
        params.append('client_secret', this.clientSecret);
        params.append('scope', 'api:read api:write');

        const response = await axios.post(this.tokenUrl, params, {
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            }
        });

        this.accessToken = response.data.access_token;
        this.expiresAt = Date.now() + (response.data.expires_in - 60) * 1000;

        return this.accessToken;
    }

    async callApi(endpoint, method = 'GET', data = null) {
        const token = await this.getAccessToken();

        const config = {
            method,
            url: `${this.baseUrl}${endpoint}`,
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            }
        };

        if (data) {
            config.data = data;
        }

        const response = await axios(config);
        return response.data;
    }
}

// Usage
(async () => {
    const client = new OAuth2Client(
        'my-tenant',
        'service-client-123',
        'super-secret-key',
        'http://localhost:3000'
    );

    try {
        const data = await client.callApi('/api/v1/protected-resource');
        console.log('Response:', JSON.stringify(data, null, 2));

        const newResource = await client.callApi(
            '/api/v1/resources',
            'POST',
            { name: 'New Resource', type: 'test' }
        );
        console.log('Created:', JSON.stringify(newResource, null, 2));

    } catch (error) {
        console.error('Error:', error.message);
    }
})();
```

## Example: Go Application

```go
package main

import (
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "net/url"
    "strings"
    "time"
)

type OAuth2Client struct {
    TenantID     string
    ClientID     string
    ClientSecret string
    BaseURL      string
    TokenURL     string
    accessToken  string
    expiresAt    time.Time
}

type TokenResponse struct {
    AccessToken string `json:"access_token"`
    TokenType   string `json:"token_type"`
    ExpiresIn   int    `json:"expires_in"`
    Scope       string `json:"scope"`
}

func NewOAuth2Client(tenantID, clientID, clientSecret, baseURL string) *OAuth2Client {
    return &OAuth2Client{
        TenantID:     tenantID,
        ClientID:     clientID,
        ClientSecret: clientSecret,
        BaseURL:      baseURL,
        TokenURL:     fmt.Sprintf("%s/api/v1/tenant/%s/oauth/token", baseURL, tenantID),
    }
}

func (c *OAuth2Client) GetAccessToken() (string, error) {
    // Check cached token
    if c.accessToken != "" && time.Now().Before(c.expiresAt) {
        return c.accessToken, nil
    }

    // Request new token
    data := url.Values{}
    data.Set("grant_type", "client_credentials")
    data.Set("client_id", c.ClientID)
    data.Set("client_secret", c.ClientSecret)
    data.Set("scope", "api:read api:write")

    resp, err := http.Post(c.TokenURL, "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
    if err != nil {
        return "", err
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        return "", fmt.Errorf("token request failed: %s", resp.Status)
    }

    var tokenResp TokenResponse
    if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
        return "", err
    }

    c.accessToken = tokenResp.AccessToken
    c.expiresAt = time.Now().Add(time.Duration(tokenResp.ExpiresIn-60) * time.Second)

    return c.accessToken, nil
}

func (c *OAuth2Client) CallAPI(endpoint, method string, body io.Reader) ([]byte, error) {
    token, err := c.GetAccessToken()
    if err != nil {
        return nil, err
    }

    req, err := http.NewRequest(method, c.BaseURL+endpoint, body)
    if err != nil {
        return nil, err
    }

    req.Header.Set("Authorization", "Bearer "+token)
    req.Header.Set("Content-Type", "application/json")

    client := &http.Client{}
    resp, err := client.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    if resp.StatusCode < 200 || resp.StatusCode >= 300 {
        return nil, fmt.Errorf("API call failed: %s", resp.Status)
    }

    return io.ReadAll(resp.Body)
}

func main() {
    client := NewOAuth2Client(
        "my-tenant",
        "service-client-123",
        "super-secret-key",
        "http://localhost:3000",
    )

    // Make API call
    data, err := client.CallAPI("/api/v1/protected-resource", "GET", nil)
    if err != nil {
        fmt.Printf("Error: %v\n", err)
        return
    }

    fmt.Printf("Response: %s\n", string(data))
}
```

## Example: Rust Application

```rust
use reqwest;
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime};

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    token_type: String,
    expires_in: u64,
    scope: String,
}

struct OAuth2Client {
    tenant_id: String,
    client_id: String,
    client_secret: String,
    base_url: String,
    token_url: String,
    access_token: Option<String>,
    expires_at: Option<SystemTime>,
}

impl OAuth2Client {
    fn new(tenant_id: &str, client_id: &str, client_secret: &str, base_url: &str) -> Self {
        Self {
            tenant_id: tenant_id.to_string(),
            client_id: client_id.to_string(),
            client_secret: client_secret.to_string(),
            base_url: base_url.to_string(),
            token_url: format!("{}/api/v1/tenant/{}/oauth/token", base_url, tenant_id),
            access_token: None,
            expires_at: None,
        }
    }

    async fn get_access_token(&mut self) -> Result<String, Box<dyn std::error::Error>> {
        // Check cached token
        if let (Some(token), Some(expires_at)) = (&self.access_token, self.expires_at) {
            if SystemTime::now() < expires_at {
                return Ok(token.clone());
            }
        }

        // Request new token
        let client = reqwest::Client::new();
        let params = [
            ("grant_type", "client_credentials"),
            ("client_id", &self.client_id),
            ("client_secret", &self.client_secret),
            ("scope", "api:read api:write"),
        ];

        let response = client
            .post(&self.token_url)
            .form(&params)
            .send()
            .await?;

        let token_response: TokenResponse = response.json().await?;

        self.access_token = Some(token_response.access_token.clone());
        self.expires_at = Some(SystemTime::now() + Duration::from_secs(token_response.expires_in - 60));

        Ok(token_response.access_token)
    }

    async fn call_api(&mut self, endpoint: &str) -> Result<String, Box<dyn std::error::Error>> {
        let token = self.get_access_token().await?;

        let client = reqwest::Client::new();
        let response = client
            .get(format!("{}{}", self.base_url, endpoint))
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await?;

        Ok(response.text().await?)
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = OAuth2Client::new(
        "my-tenant",
        "service-client-123",
        "super-secret-key",
        "http://localhost:3000",
    );

    let data = client.call_api("/api/v1/protected-resource").await?;
    println!("Response: {}", data);

    Ok(())
}
```

## Best Practices

1. **Token Caching**: Always cache tokens and reuse them until they expire
2. **Error Handling**: Implement proper error handling for network and authentication failures
3. **Token Refresh**: Refresh tokens before they expire (subtract 60 seconds from expiry)
4. **Secure Storage**: Store client secrets securely (environment variables, secrets manager)
5. **Scope Management**: Request only the scopes you need
6. **HTTPS in Production**: Always use HTTPS in production environments
7. **Monitoring**: Log authentication failures for security monitoring

## Common Errors

### Invalid Client Credentials
```json
{
  "error": "invalid_client",
  "error_description": "Invalid client credentials"
}
```
**Solution**: Verify client_id and client_secret are correct

### Unsupported Grant Type
```json
{
  "error": "unsupported_grant_type",
  "error_description": "Grant type not enabled for this client"
}
```
**Solution**: Ensure the client is configured with `client_credentials` grant type

### Invalid Scope
```json
{
  "error": "invalid_scope",
  "error_description": "Requested scope is not allowed for this client"
}
```
**Solution**: Check that the requested scopes are configured for the client

## Security Considerations

- Store client secrets securely (never in code or version control)
- Use environment variables or secrets management systems
- Rotate client secrets periodically
- Monitor for unauthorized access attempts
- Implement rate limiting on the client side
- Use HTTPS to prevent token interception
- Log all authentication attempts for audit trails

## Related Examples

- [Token Introspection](token_introspection.md) - Validate tokens
- [API Key Management](api_keys.md) - Alternative authentication method
- [Rate Limiting](rate_limiting.md) - Implement client-side rate limiting

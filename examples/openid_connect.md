# OpenID Connect (OIDC) Integration

**Difficulty**: ⭐⭐ Moderate
**Use Case**: User authentication, SSO, profile management

## Overview

OpenID Connect is an identity layer built on top of OAuth2 that provides user authentication and profile information. It's the modern standard for Single Sign-On (SSO) and user identity.

## When to Use

- User authentication and SSO
- Retrieving user profile information
- Multi-application environments with shared authentication
- Enterprise SSO scenarios
- Social login implementations

## Key Concepts

- **ID Token**: JWT containing user identity claims
- **UserInfo Endpoint**: Returns user profile information
- **Discovery**: Automatic configuration discovery
- **Claims**: User attributes (email, name, picture, etc.)
- **Scopes**: Control what information is returned

## Discovery

### Fetch OIDC Configuration

```bash
curl 'http://localhost:3000/api/v1/tenant/my-tenant/.well-known/openid-configuration'
```

### Response

```json
{
  "issuer": "https://auth.example.com",
  "authorization_endpoint": "https://auth.example.com/api/v1/tenant/my-tenant/oauth/authorize",
  "token_endpoint": "https://auth.example.com/api/v1/tenant/my-tenant/oauth/token",
  "userinfo_endpoint": "https://auth.example.com/api/v1/tenant/my-tenant/oauth/userinfo",
  "jwks_uri": "https://auth.example.com/api/v1/tenant/my-tenant/.well-known/jwks.json",
  "scopes_supported": ["openid", "profile", "email"],
  "response_types_supported": ["code", "token"],
  "grant_types_supported": ["authorization_code", "client_credentials", "refresh_token"],
  "id_token_signing_alg_values_supported": ["RS256", "ES256"],
  "claims_supported": [
    "sub",
    "iss",
    "aud",
    "exp",
    "iat",
    "email",
    "email_verified",
    "name",
    "picture",
    "given_name",
    "family_name"
  ]
}
```

## Complete OIDC Flow

### Step 1: Authorization Request

```javascript
function initiateOIDCLogin() {
    const params = new URLSearchParams({
        response_type: 'code',
        client_id: 'oidc-client-123',
        redirect_uri: 'http://localhost:8080/callback',
        scope: 'openid profile email',  // Note: 'openid' is required
        state: generateRandomState(),
        nonce: generateRandomNonce()     // For ID token validation
    });

    sessionStorage.setItem('oidc_nonce', nonce);
    sessionStorage.setItem('oidc_state', state);

    window.location.href =
        `http://localhost:3000/api/v1/tenant/my-tenant/oauth/authorize?${params}`;
}
```

### Step 2: Token Exchange (Returns ID Token + Access Token)

```javascript
async function exchangeCodeForTokens(code) {
    const response = await fetch(
        'http://localhost:3000/api/v1/tenant/my-tenant/oauth/token',
        {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: new URLSearchParams({
                grant_type: 'authorization_code',
                code: code,
                client_id: 'oidc-client-123',
                redirect_uri: 'http://localhost:8080/callback'
            })
        }
    );

    const tokens = await response.json();

    return {
        access_token: tokens.access_token,
        id_token: tokens.id_token,        // JWT with user identity
        refresh_token: tokens.refresh_token,
        expires_in: tokens.expires_in
    };
}
```

### Step 3: Validate ID Token

```javascript
async function validateIDToken(idToken) {
    // Decode JWT (3 parts: header.payload.signature)
    const [headerB64, payloadB64, signature] = idToken.split('.');

    const header = JSON.parse(atob(headerB64));
    const payload = JSON.parse(atob(payloadB64));

    // Get public key from JWKS endpoint
    const jwks = await fetch(
        'http://localhost:3000/api/v1/tenant/my-tenant/.well-known/jwks.json'
    ).then(r => r.json());

    const key = jwks.keys.find(k => k.kid === header.kid);

    // Verify signature (use crypto library like jose or jsonwebtoken)
    // ... signature verification code ...

    // Validate claims
    const now = Math.floor(Date.now() / 1000);

    if (payload.exp < now) {
        throw new Error('ID token expired');
    }

    if (payload.iss !== 'https://auth.example.com') {
        throw new Error('Invalid issuer');
    }

    if (payload.aud !== 'oidc-client-123') {
        throw new Error('Invalid audience');
    }

    const storedNonce = sessionStorage.getItem('oidc_nonce');
    if (payload.nonce !== storedNonce) {
        throw new Error('Invalid nonce');
    }

    return payload;  // Validated claims
}
```

### Step 4: Fetch User Information

```javascript
async function getUserInfo(accessToken) {
    const response = await fetch(
        'http://localhost:3000/api/v1/tenant/my-tenant/oauth/userinfo',
        {
            headers: {
                'Authorization': `Bearer ${accessToken}`
            }
        }
    );

    return await response.json();
}

// Example response:
// {
//   "sub": "user-123",
//   "email": "john.doe@example.com",
//   "email_verified": true,
//   "name": "John Doe",
//   "picture": "https://example.com/photo.jpg",
//   "given_name": "John",
//   "family_name": "Doe"
// }
```

## Complete Example: React OIDC Application

```jsx
import React, { useEffect, useState } from 'react';
import * as jose from 'jose';  // npm install jose

const OIDCConfig = {
    issuer: 'https://auth.example.com',
    clientId: 'oidc-client-123',
    redirectUri: 'http://localhost:3000/callback',
    scope: 'openid profile email'
};

// OIDC Client Hook
function useOIDC() {
    const [user, setUser] = useState(null);
    const [loading, setLoading] = useState(true);
    const [config, setConfig] = useState(null);

    useEffect(() => {
        // Load OIDC configuration
        fetch(`${OIDCConfig.issuer}/.well-known/openid-configuration`)
            .then(r => r.json())
            .then(setConfig);
    }, []);

    const login = async () => {
        if (!config) return;

        const state = generateRandomString();
        const nonce = generateRandomString();

        sessionStorage.setItem('oidc_state', state);
        sessionStorage.setItem('oidc_nonce', nonce);

        const params = new URLSearchParams({
            response_type: 'code',
            client_id: OIDCConfig.clientId,
            redirect_uri: OIDCConfig.redirectUri,
            scope: OIDCConfig.scope,
            state,
            nonce
        });

        window.location.href = `${config.authorization_endpoint}?${params}`;
    };

    const handleCallback = async (code, state) => {
        // Validate state
        const storedState = sessionStorage.getItem('oidc_state');
        if (state !== storedState) {
            throw new Error('State mismatch');
        }

        // Exchange code for tokens
        const tokenResponse = await fetch(config.token_endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({
                grant_type: 'authorization_code',
                code,
                client_id: OIDCConfig.clientId,
                redirect_uri: OIDCConfig.redirectUri
            })
        });

        const tokens = await tokenResponse.json();

        // Validate ID token
        const JWKS = jose.createRemoteJWKSet(new URL(config.jwks_uri));
        const { payload } = await jose.jwtVerify(tokens.id_token, JWKS, {
            issuer: config.issuer,
            audience: OIDCConfig.clientId
        });

        // Verify nonce
        const storedNonce = sessionStorage.getItem('oidc_nonce');
        if (payload.nonce !== storedNonce) {
            throw new Error('Nonce mismatch');
        }

        // Store tokens
        sessionStorage.setItem('access_token', tokens.access_token);
        sessionStorage.setItem('id_token', tokens.id_token);
        sessionStorage.setItem('refresh_token', tokens.refresh_token);

        // Fetch full user profile
        const userInfoResponse = await fetch(config.userinfo_endpoint, {
            headers: { 'Authorization': `Bearer ${tokens.access_token}` }
        });

        const userInfo = await userInfoResponse.json();
        setUser(userInfo);

        // Clean up
        sessionStorage.removeItem('oidc_state');
        sessionStorage.removeItem('oidc_nonce');
    };

    const logout = () => {
        sessionStorage.clear();
        setUser(null);
        window.location.href = '/';
    };

    return { user, login, logout, handleCallback, loading };
}

// Login Component
function LoginPage() {
    const { login } = useOIDC();

    return (
        <div className="login-container">
            <h1>Welcome</h1>
            <button onClick={login} className="login-button">
                Sign in with OIDC
            </button>
        </div>
    );
}

// Callback Component
function CallbackPage() {
    const { handleCallback } = useOIDC();
    const [error, setError] = useState(null);

    useEffect(() => {
        const params = new URLSearchParams(window.location.search);
        const code = params.get('code');
        const state = params.get('state');
        const errorParam = params.get('error');

        if (errorParam) {
            setError(errorParam);
            return;
        }

        handleCallback(code, state)
            .then(() => {
                window.location.href = '/profile';
            })
            .catch(err => {
                setError(err.message);
            });
    }, []);

    if (error) {
        return <div>Error: {error}</div>;
    }

    return <div>Processing login...</div>;
}

// Profile Component
function ProfilePage() {
    const { user, logout } = useOIDC();

    if (!user) {
        return <div>Loading...</div>;
    }

    return (
        <div className="profile-container">
            <h1>Profile</h1>
            {user.picture && <img src={user.picture} alt="Profile" />}
            <p><strong>Name:</strong> {user.name}</p>
            <p><strong>Email:</strong> {user.email}</p>
            {user.email_verified && <span>✓ Verified</span>}
            <p><strong>ID:</strong> {user.sub}</p>
            <button onClick={logout}>Logout</button>
        </div>
    );
}

function generateRandomString() {
    const array = new Uint8Array(16);
    crypto.getRandomValues(array);
    return Array.from(array, b => b.toString(16).padStart(2, '0')).join('');
}

export { LoginPage, CallbackPage, ProfilePage };
```

## Example: Python OIDC Client

```python
import requests
import secrets
import hashlib
import base64
from jose import jwt, jwk
from jose.utils import base64url_decode

class OIDCClient:
    def __init__(self, issuer, client_id, client_secret, redirect_uri):
        self.issuer = issuer
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri

        # Discover OIDC configuration
        self.config = self._discover_configuration()

    def _discover_configuration(self):
        """Fetch OIDC configuration from discovery endpoint"""
        url = f"{self.issuer}/.well-known/openid-configuration"
        response = requests.get(url)
        response.raise_for_status()
        return response.json()

    def get_authorization_url(self):
        """Generate authorization URL"""
        state = secrets.token_urlsafe(16)
        nonce = secrets.token_urlsafe(16)

        params = {
            'response_type': 'code',
            'client_id': self.client_id,
            'redirect_uri': self.redirect_uri,
            'scope': 'openid profile email',
            'state': state,
            'nonce': nonce
        }

        auth_url = f"{self.config['authorization_endpoint']}?{requests.compat.urlencode(params)}"

        return auth_url, state, nonce

    def exchange_code(self, code):
        """Exchange authorization code for tokens"""
        data = {
            'grant_type': 'authorization_code',
            'code': code,
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'redirect_uri': self.redirect_uri
        }

        response = requests.post(self.config['token_endpoint'], data=data)
        response.raise_for_status()

        return response.json()

    def validate_id_token(self, id_token, nonce):
        """Validate ID token signature and claims"""
        # Get JWKS
        jwks_response = requests.get(self.config['jwks_uri'])
        jwks = jwks_response.json()

        # Decode header to get kid
        header = jwt.get_unverified_header(id_token)
        kid = header['kid']

        # Find the right key
        key = next((k for k in jwks['keys'] if k['kid'] == kid), None)
        if not key:
            raise ValueError('Public key not found')

        # Verify signature and decode
        claims = jwt.decode(
            id_token,
            key,
            algorithms=['RS256', 'ES256'],
            audience=self.client_id,
            issuer=self.issuer
        )

        # Verify nonce
        if claims.get('nonce') != nonce:
            raise ValueError('Nonce mismatch')

        return claims

    def get_user_info(self, access_token):
        """Fetch user information"""
        headers = {'Authorization': f'Bearer {access_token}'}
        response = requests.get(self.config['userinfo_endpoint'], headers=headers)
        response.raise_for_status()
        return response.json()

# Usage example
client = OIDCClient(
    issuer='http://localhost:3000/api/v1/tenant/my-tenant',
    client_id='oidc-client-123',
    client_secret='client-secret',
    redirect_uri='http://localhost:5000/callback'
)

# Step 1: Get authorization URL
auth_url, state, nonce = client.get_authorization_url()
print(f"Visit: {auth_url}")

# Step 2: After redirect, exchange code
# code = request.args.get('code')
# tokens = client.exchange_code(code)

# Step 3: Validate ID token
# claims = client.validate_id_token(tokens['id_token'], nonce)
# print(f"User ID: {claims['sub']}")
# print(f"Email: {claims.get('email')}")

# Step 4: Get user info
# user_info = client.get_user_info(tokens['access_token'])
# print(f"User: {user_info}")
```

## ID Token Claims

### Standard Claims

```json
{
  "iss": "https://auth.example.com",
  "sub": "user-123",
  "aud": "oidc-client-123",
  "exp": 1234567890,
  "iat": 1234564290,
  "auth_time": 1234564290,
  "nonce": "random-nonce-value",
  "email": "john.doe@example.com",
  "email_verified": true,
  "name": "John Doe",
  "picture": "https://example.com/photo.jpg",
  "given_name": "John",
  "family_name": "Doe"
}
```

### Claim Descriptions

- **iss**: Issuer identifier
- **sub**: Subject (user) identifier - unique and immutable
- **aud**: Audience (client_id)
- **exp**: Expiration time (Unix timestamp)
- **iat**: Issued at time
- **auth_time**: When user authenticated
- **nonce**: Value from authorization request
- **email**: User's email address
- **email_verified**: Email verification status
- **name**: Full name
- **picture**: Profile picture URL
- **given_name**: First name
- **family_name**: Last name

## Scopes

### Available Scopes

- **openid**: Required - enables OIDC
- **profile**: Returns name, picture, given_name, family_name
- **email**: Returns email, email_verified

### Scope Examples

```javascript
// Minimal - only get user ID
scope: 'openid'

// Get user ID and profile
scope: 'openid profile'

// Get everything
scope: 'openid profile email'
```

## Best Practices

1. **Always validate ID tokens**: Check signature, issuer, audience, expiration
2. **Use nonce parameter**: Prevents replay attacks
3. **Verify state parameter**: Prevents CSRF
4. **Use PKCE**: For public clients (SPAs, mobile)
5. **Cache OIDC configuration**: Discovery endpoint rarely changes
6. **Handle token expiration**: Implement refresh token flow
7. **Secure token storage**: Use httpOnly cookies or secure storage
8. **Validate email_verified**: Before trusting email addresses

## Security Considerations

- ID tokens are JWTs - validate signature before trusting
- Never expose ID tokens to third parties
- Use HTTPS in production
- Implement proper CORS policies
- Rotate signing keys periodically
- Monitor for suspicious login patterns
- Implement rate limiting on endpoints

## Common Errors

### Missing openid Scope
```json
{
  "error": "invalid_scope",
  "error_description": "openid scope is required for OIDC"
}
```
**Solution**: Always include 'openid' in scope parameter

### Invalid Nonce
**Solution**: Ensure nonce in ID token matches the one stored before authorization

### Token Signature Verification Failed
**Solution**: Fetch latest JWKS and verify you're using the correct public key

## Related Examples

- [OAuth2 Authorization Code](oauth2_authorization_code.md) - Base flow
- [Session Management](session_management.md) - User session tracking
- [Multi-Factor Authentication](mfa.md) - Enhanced security

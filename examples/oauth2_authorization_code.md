# OAuth2 Authorization Code Flow with PKCE

**Difficulty**: ⭐⭐ Moderate
**Use Case**: Web applications, mobile apps, single-page applications (SPAs)

## Overview

The Authorization Code flow is used when an application needs to access resources on behalf of a user. PKCE (Proof Key for Code Exchange) adds security for public clients like mobile apps and SPAs.

## When to Use

- Web application user login
- Single Page Applications (React, Vue, Angular)
- Mobile applications (iOS, Android)
- Desktop applications
- Any scenario where you need user authentication

## Prerequisites

1. A registered OAuth2 client with `authorization_code` grant type
2. Client ID (and optionally Client Secret for confidential clients)
3. Redirect URI configured for your application
4. Tenant ID

## Flow Diagram

```
┌──────────┐                                  ┌──────────────┐
│          │                                  │              │
│  User    │                                  │  Auth Server │
│          │                                  │              │
└────┬─────┘                                  └──────┬───────┘
     │                                               │
     │ 1. Click "Login"                             │
     ├──────────────────────────────────────────────>
     │                                               │
     │ 2. Redirect to /oauth/authorize              │
     │    + code_challenge (PKCE)                   │
     ├──────────────────────────────────────────────>
     │                                               │
     │ 3. Show login form                           │
     │<──────────────────────────────────────────────┤
     │                                               │
     │ 4. User enters credentials                   │
     ├──────────────────────────────────────────────>
     │                                               │
     │ 5. Redirect back with code                   │
     │<──────────────────────────────────────────────┤
     │                                               │
     │ 6. Exchange code for token                   │
     │    + code_verifier (PKCE)                    │
     ├──────────────────────────────────────────────>
     │                                               │
     │ 7. Return access_token & refresh_token       │
     │<──────────────────────────────────────────────┤
     │                                               │
```

## Step-by-Step Implementation

### Step 1: Generate PKCE Parameters

```javascript
// Generate code verifier (random string)
function generateCodeVerifier() {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return base64URLEncode(array);
}

// Generate code challenge from verifier
async function generateCodeChallenge(verifier) {
    const encoder = new TextEncoder();
    const data = encoder.encode(verifier);
    const hash = await crypto.subtle.digest('SHA-256', data);
    return base64URLEncode(new Uint8Array(hash));
}

function base64URLEncode(buffer) {
    const base64 = btoa(String.fromCharCode(...buffer));
    return base64
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
}

// Usage
const codeVerifier = generateCodeVerifier();
const codeChallenge = await generateCodeChallenge(codeVerifier);

// Store code_verifier in session storage
sessionStorage.setItem('code_verifier', codeVerifier);
```

### Step 2: Redirect to Authorization Endpoint

```javascript
function initiateLogin() {
    const params = new URLSearchParams({
        response_type: 'code',
        client_id: 'web-app-client-123',
        redirect_uri: 'http://localhost:8080/callback',
        scope: 'openid profile email',
        state: generateRandomState(),
        code_challenge: codeChallenge,
        code_challenge_method: 'S256'
    });

    // Store state for validation
    sessionStorage.setItem('oauth_state', state);

    window.location.href = `http://localhost:3000/api/v1/tenant/my-tenant/oauth/authorize?${params}`;
}

function generateRandomState() {
    const array = new Uint8Array(16);
    crypto.getRandomValues(array);
    return base64URLEncode(array);
}
```

### Step 3: Handle Callback and Exchange Code for Token

```javascript
async function handleCallback() {
    const params = new URLSearchParams(window.location.search);
    const code = params.get('code');
    const state = params.get('state');
    const error = params.get('error');

    // Check for errors
    if (error) {
        console.error('Authorization error:', error);
        return;
    }

    // Validate state
    const storedState = sessionStorage.getItem('oauth_state');
    if (state !== storedState) {
        console.error('Invalid state parameter');
        return;
    }

    // Retrieve code verifier
    const codeVerifier = sessionStorage.getItem('code_verifier');

    // Exchange code for token
    const tokenResponse = await fetch(
        'http://localhost:3000/api/v1/tenant/my-tenant/oauth/token',
        {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: new URLSearchParams({
                grant_type: 'authorization_code',
                code: code,
                client_id: 'web-app-client-123',
                redirect_uri: 'http://localhost:8080/callback',
                code_verifier: codeVerifier
            })
        }
    );

    const tokens = await tokenResponse.json();

    // Store tokens securely
    sessionStorage.setItem('access_token', tokens.access_token);
    sessionStorage.setItem('refresh_token', tokens.refresh_token);

    // Clean up
    sessionStorage.removeItem('code_verifier');
    sessionStorage.removeItem('oauth_state');

    // Redirect to app
    window.location.href = '/dashboard';
}
```

## Complete Example: React Application

```jsx
import React, { useEffect, useState } from 'react';

const OAuth2Config = {
    tenantId: 'my-tenant',
    clientId: 'web-app-client-123',
    redirectUri: 'http://localhost:3000/callback',
    authorizationEndpoint: 'http://localhost:3000/api/v1/tenant/my-tenant/oauth/authorize',
    tokenEndpoint: 'http://localhost:3000/api/v1/tenant/my-tenant/oauth/token',
    scope: 'openid profile email'
};

// Utility functions
const base64URLEncode = (buffer) => {
    const base64 = btoa(String.fromCharCode(...buffer));
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
};

const generateCodeVerifier = () => {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return base64URLEncode(array);
};

const generateCodeChallenge = async (verifier) => {
    const encoder = new TextEncoder();
    const data = encoder.encode(verifier);
    const hash = await crypto.subtle.digest('SHA-256', data);
    return base64URLEncode(new Uint8Array(hash));
};

const generateRandomState = () => {
    const array = new Uint8Array(16);
    crypto.getRandomValues(array);
    return base64URLEncode(array);
};

// Login Component
function Login() {
    const handleLogin = async () => {
        const codeVerifier = generateCodeVerifier();
        const codeChallenge = await generateCodeChallenge(codeVerifier);
        const state = generateRandomState();

        // Store for later use
        sessionStorage.setItem('code_verifier', codeVerifier);
        sessionStorage.setItem('oauth_state', state);

        // Build authorization URL
        const params = new URLSearchParams({
            response_type: 'code',
            client_id: OAuth2Config.clientId,
            redirect_uri: OAuth2Config.redirectUri,
            scope: OAuth2Config.scope,
            state: state,
            code_challenge: codeChallenge,
            code_challenge_method: 'S256'
        });

        window.location.href = `${OAuth2Config.authorizationEndpoint}?${params}`;
    };

    return (
        <div>
            <h1>Login</h1>
            <button onClick={handleLogin}>Login with OAuth2</button>
        </div>
    );
}

// Callback Component
function Callback() {
    const [error, setError] = useState(null);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        const handleCallback = async () => {
            try {
                const params = new URLSearchParams(window.location.search);
                const code = params.get('code');
                const state = params.get('state');
                const errorParam = params.get('error');

                if (errorParam) {
                    throw new Error(`Authorization error: ${errorParam}`);
                }

                // Validate state
                const storedState = sessionStorage.getItem('oauth_state');
                if (state !== storedState) {
                    throw new Error('Invalid state parameter');
                }

                // Get code verifier
                const codeVerifier = sessionStorage.getItem('code_verifier');

                // Exchange code for token
                const response = await fetch(OAuth2Config.tokenEndpoint, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded'
                    },
                    body: new URLSearchParams({
                        grant_type: 'authorization_code',
                        code: code,
                        client_id: OAuth2Config.clientId,
                        redirect_uri: OAuth2Config.redirectUri,
                        code_verifier: codeVerifier
                    })
                });

                if (!response.ok) {
                    throw new Error('Token exchange failed');
                }

                const tokens = await response.json();

                // Store tokens
                sessionStorage.setItem('access_token', tokens.access_token);
                sessionStorage.setItem('refresh_token', tokens.refresh_token);

                // Clean up
                sessionStorage.removeItem('code_verifier');
                sessionStorage.removeItem('oauth_state');

                // Redirect to app
                window.location.href = '/dashboard';

            } catch (err) {
                setError(err.message);
                setLoading(false);
            }
        };

        handleCallback();
    }, []);

    if (loading) {
        return <div>Processing login...</div>;
    }

    if (error) {
        return <div>Error: {error}</div>;
    }

    return null;
}

// Protected Component
function Dashboard() {
    const [user, setUser] = useState(null);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        const fetchUser = async () => {
            const accessToken = sessionStorage.getItem('access_token');

            if (!accessToken) {
                window.location.href = '/login';
                return;
            }

            try {
                const response = await fetch(
                    'http://localhost:3000/api/v1/tenant/my-tenant/oauth/userinfo',
                    {
                        headers: {
                            'Authorization': `Bearer ${accessToken}`
                        }
                    }
                );

                if (!response.ok) {
                    throw new Error('Failed to fetch user info');
                }

                const userData = await response.json();
                setUser(userData);
                setLoading(false);

            } catch (err) {
                console.error('Error fetching user:', err);
                // Token might be expired, redirect to login
                window.location.href = '/login';
            }
        };

        fetchUser();
    }, []);

    const handleLogout = () => {
        sessionStorage.clear();
        window.location.href = '/login';
    };

    if (loading) {
        return <div>Loading...</div>;
    }

    return (
        <div>
            <h1>Dashboard</h1>
            <p>Welcome, {user.name}!</p>
            <p>Email: {user.email}</p>
            <button onClick={handleLogout}>Logout</button>
        </div>
    );
}

export { Login, Callback, Dashboard };
```

## Example: Python Flask Application

```python
import os
import secrets
import hashlib
import base64
from flask import Flask, request, redirect, session, url_for
import requests

app = Flask(__name__)
app.secret_key = os.urandom(24)

OAUTH2_CONFIG = {
    'tenant_id': 'my-tenant',
    'client_id': 'web-app-client-123',
    'client_secret': 'optional-for-confidential-clients',
    'redirect_uri': 'http://localhost:5000/callback',
    'authorization_endpoint': 'http://localhost:3000/api/v1/tenant/my-tenant/oauth/authorize',
    'token_endpoint': 'http://localhost:3000/api/v1/tenant/my-tenant/oauth/token',
    'userinfo_endpoint': 'http://localhost:3000/api/v1/tenant/my-tenant/oauth/userinfo',
    'scope': 'openid profile email'
}

def generate_code_verifier():
    """Generate a random code verifier"""
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')

def generate_code_challenge(verifier):
    """Generate code challenge from verifier using S256"""
    digest = hashlib.sha256(verifier.encode('utf-8')).digest()
    return base64.urlsafe_b64encode(digest).decode('utf-8').rstrip('=')

@app.route('/')
def index():
    if 'access_token' in session:
        return redirect(url_for('dashboard'))
    return '<h1>Welcome</h1><a href="/login">Login</a>'

@app.route('/login')
def login():
    # Generate PKCE parameters
    code_verifier = generate_code_verifier()
    code_challenge = generate_code_challenge(code_verifier)
    state = secrets.token_urlsafe(16)

    # Store in session
    session['code_verifier'] = code_verifier
    session['oauth_state'] = state

    # Build authorization URL
    params = {
        'response_type': 'code',
        'client_id': OAUTH2_CONFIG['client_id'],
        'redirect_uri': OAUTH2_CONFIG['redirect_uri'],
        'scope': OAUTH2_CONFIG['scope'],
        'state': state,
        'code_challenge': code_challenge,
        'code_challenge_method': 'S256'
    }

    auth_url = f"{OAUTH2_CONFIG['authorization_endpoint']}?{requests.compat.urlencode(params)}"
    return redirect(auth_url)

@app.route('/callback')
def callback():
    # Get parameters
    code = request.args.get('code')
    state = request.args.get('state')
    error = request.args.get('error')

    if error:
        return f"Authorization error: {error}", 400

    # Validate state
    if state != session.get('oauth_state'):
        return "Invalid state parameter", 400

    # Get code verifier
    code_verifier = session.get('code_verifier')

    # Exchange code for token
    token_data = {
        'grant_type': 'authorization_code',
        'code': code,
        'client_id': OAUTH2_CONFIG['client_id'],
        'redirect_uri': OAUTH2_CONFIG['redirect_uri'],
        'code_verifier': code_verifier
    }

    # Add client secret if using confidential client
    if OAUTH2_CONFIG.get('client_secret'):
        token_data['client_secret'] = OAUTH2_CONFIG['client_secret']

    response = requests.post(OAUTH2_CONFIG['token_endpoint'], data=token_data)

    if response.status_code != 200:
        return f"Token exchange failed: {response.text}", 400

    tokens = response.json()

    # Store tokens in session
    session['access_token'] = tokens['access_token']
    session['refresh_token'] = tokens.get('refresh_token')

    # Clean up
    session.pop('code_verifier', None)
    session.pop('oauth_state', None)

    return redirect(url_for('dashboard'))

@app.route('/dashboard')
def dashboard():
    access_token = session.get('access_token')

    if not access_token:
        return redirect(url_for('login'))

    # Fetch user info
    headers = {'Authorization': f'Bearer {access_token}'}
    response = requests.get(OAUTH2_CONFIG['userinfo_endpoint'], headers=headers)

    if response.status_code != 200:
        # Token expired or invalid
        session.clear()
        return redirect(url_for('login'))

    user = response.json()

    return f"""
    <h1>Dashboard</h1>
    <p>Welcome, {user.get('name')}!</p>
    <p>Email: {user.get('email')}</p>
    <a href="/logout">Logout</a>
    """

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True, port=5000)
```

## Token Refresh

```javascript
async function refreshAccessToken() {
    const refreshToken = sessionStorage.getItem('refresh_token');

    const response = await fetch(
        'http://localhost:3000/api/v1/tenant/my-tenant/oauth/token',
        {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: new URLSearchParams({
                grant_type: 'refresh_token',
                refresh_token: refreshToken,
                client_id: 'web-app-client-123'
            })
        }
    );

    const tokens = await response.json();

    sessionStorage.setItem('access_token', tokens.access_token);
    if (tokens.refresh_token) {
        sessionStorage.setItem('refresh_token', tokens.refresh_token);
    }

    return tokens.access_token;
}
```

## Best Practices

1. **Always use PKCE** for public clients (SPAs, mobile apps)
2. **Validate state parameter** to prevent CSRF attacks
3. **Use secure storage** for tokens (not localStorage for sensitive apps)
4. **Implement token refresh** before expiration
5. **Clear tokens on logout** completely
6. **Use HTTPS** in production
7. **Implement proper error handling** for all OAuth2 errors
8. **Never expose client secrets** in frontend code

## Security Considerations

- PKCE is mandatory for public clients
- State parameter prevents CSRF attacks
- Code verifier is single-use only
- Tokens should be stored securely
- Implement token rotation on refresh
- Monitor for suspicious authorization attempts
- Use short-lived access tokens (1 hour recommended)

## Common Errors

### Invalid Code Verifier
```json
{
  "error": "invalid_grant",
  "error_description": "Invalid code verifier"
}
```
**Solution**: Ensure you're sending the same code_verifier used to generate the code_challenge

### State Mismatch
**Solution**: Verify that the state parameter matches the one stored before redirect

### Redirect URI Mismatch
```json
{
  "error": "invalid_request",
  "error_description": "Redirect URI mismatch"
}
```
**Solution**: Ensure redirect_uri matches exactly what's registered for the client

## Related Examples

- [OpenID Connect](openid_connect.md) - User identity and profile
- [Token Refresh](token_refresh.md) - Refresh access tokens
- [Session Management](session_management.md) - Track user sessions

# pmp-auth-api

PMP Auth API: OAuth2 Authorization Server, OpenID Connect Provider, and SAML Identity Provider.

A high-performance multi-tenant authentication and authorization provider built with Rust and Axum. This API acts as an identity provider (IdP) and authorization server, supporting OAuth2, OpenID Connect (OIDC), and SAML 2.0 protocols.

## Overview

This API provides:
- **OAuth2 Authorization Server**: Full OAuth2 2.0 implementation with multiple grant types
- **OpenID Connect Provider**: OIDC identity layer with ID tokens and userinfo endpoint
- **SAML 2.0 Identity Provider**: Enterprise SSO with SAML IdP functionality
- **API Key Management**: Long-lived JWT tokens for machine-to-machine authentication
- **Device Authorization Grant**: RFC 8628 device flow for IoT and limited-input devices
- **Token Introspection & Revocation**: RFC 7662 and RFC 7009 support
- **Storage Backend Abstraction**: Pluggable storage (in-memory, PostgreSQL)
- **Admin API**: REST API for tenant, client, and user management
- **Identity Backend Abstraction**: Pluggable user storage backends (LDAP, Database, OAuth2, Federated, Mock)

## Features

### Multi-Tenancy
- **Tenant isolation**: Each tenant has its own OAuth2/OIDC/SAML configuration
- **Multiple identity providers per tenant**: Configure OAuth2, OIDC, and SAML simultaneously
- **Flexible configuration**: YAML-based tenant configuration
- **Per-tenant signing keys**: Separate JWK signing keys for each tenant

### OAuth2 Authorization Server
- **Grant types**: authorization_code, client_credentials, refresh_token, device_code (RFC 8628)
- **Token endpoints**: `/oauth/authorize`, `/oauth/token`, `/oauth/device/authorize`, `/oauth/device/token`
- **JWKS endpoint**: Public key distribution at `/.well-known/jwks.json`
- **Token introspection**: RFC 7662 token validation at `/oauth/introspect`
- **Token revocation**: RFC 7009 token revocation at `/oauth/revoke`
- **PKCE support**: RFC 7636 Proof Key for Code Exchange
- **Configurable token expiration**: Access tokens and refresh tokens
- **Multiple signing algorithms**: RS256, ES256

### OpenID Connect (OIDC) Provider
- **Discovery endpoint**: `/.well-known/openid-configuration`
- **UserInfo endpoint**: `/oauth/userinfo`
- **ID token generation**: JWT ID tokens with standard and extended claims
- **Supported claims**: sub, email, email_verified, name, picture, and more
- **Configurable scopes**: openid, profile, email

### SAML 2.0 Identity Provider
- **SAML metadata endpoint**: XML descriptor for SP integration
- **SSO endpoints**: HTTP-POST and HTTP-Redirect bindings
- **SLO (Single Logout)**: Session termination support
- **SAML assertions**: Signed assertions with user attributes
- **Flexible configuration**: Entity ID, SSO/SLO URLs, certificates

### API Key Management
- **Long-lived JWT tokens**: For machine-to-machine authentication
- **Custom scopes**: Fine-grained access control per API key
- **Configurable expiration**: Days or no expiration
- **Revocation support**: Immediate key revocation
- **Metadata tracking**: Created, last used, revoked status

### Identity Backends
- **Mock Backend**: Testing backend with predefined users
- **OAuth2 Backend**: External providers (Google, GitHub, etc.) - *stub*
- **LDAP Backend**: Active Directory integration - *stub*
- **Database Backend**: PostgreSQL/MySQL - *stub*
- **Federated Backend**: Upstream OIDC providers - *stub*

### Device Authorization Grant (RFC 8628)
- **Device flow for limited-input devices**: Smart TVs, IoT devices, CLI tools
- **User-friendly codes**: 8-character codes with unambiguous characters (no I, O, 0, 1)
- **Device endpoints**: Device authorization, token polling, verification, confirmation
- **Web verification page**: Modern responsive UI at `/device`
- **Status tracking**: Pending, authorized, denied, expired
- **Configurable polling interval**: Default 5 seconds

### Storage Backend
- **Pluggable architecture**: Trait-based storage abstraction
- **In-memory storage**: Default, no persistence, perfect for development
- **PostgreSQL storage**: Production-ready with full schema and migrations
- **Supports**: Authorization codes, refresh tokens, API keys, sessions, device codes, token revocation
- **Database migrations**: Complete PostgreSQL schema with indexes and cleanup procedures
- **Future backends**: Redis, MySQL, DynamoDB (extensible design)

### Admin API
- **Tenant management**: CRUD operations for tenants
- **Client management**: OAuth2 client registration and management
- **User management**: Create, update, delete, list users
- **RESTful design**: Standard HTTP methods (GET, POST, PUT, DELETE)
- **Validation**: Comprehensive request validation and error handling
- **Endpoints**: `/api/v1/admin/tenants`, `/api/v1/admin/tenants/{id}/clients`, `/api/v1/admin/tenants/{id}/users`

### Security & Features
- JWT-based authentication with JWK signing
- Role-based authorization (User, Admin)
- RESTful API design
- Comprehensive error handling
- CORS support
- Request tracing and logging

## Prerequisites

- Rust 1.91+ (Rust 2024 edition)
- Cargo (comes with Rust)

## Quick Start

1. Clone the repository:
```bash
git clone <repository-url>
cd pmp-auth-api
```

2. Configure tenants:
```bash
cp config.example.yaml config.yaml
# Edit config.yaml to configure your tenants and identity providers
```

3. Build and run:
```bash
cargo build
cargo run
```

The API will start on `http://0.0.0.0:3000`

## Tenant Configuration

Create a `config.yaml` file to configure tenants and identity providers.

### Configuration Structure

```yaml
tenants:
  tenant-id:
    id: tenant-id
    name: "Tenant Name"
    description: "Optional description"
    active: true

    # Identity Provider Configuration (what this API provides)
    identity_provider:
      oauth2:
        # OAuth2 Authorization Server config
      oidc:
        # OpenID Connect Provider config
      saml:
        # SAML IdP config

    # Identity Backend (where users come from)
    identity_backend:
      type: mock  # or oauth2, ldap, database, federated
      # Backend-specific config...

    # API Key Management (optional)
    api_keys:
      enabled: true
      # API key config...
```

### OAuth2 Authorization Server Configuration

```yaml
identity_provider:
  oauth2:
    issuer: "https://auth.example.com"
    grant_types:
      - "authorization_code"
      - "client_credentials"
      - "refresh_token"
    token_endpoint: "/oauth/token"
    authorize_endpoint: "/oauth/authorize"
    jwks_endpoint: "/.well-known/jwks.json"
    access_token_expiration_secs: 3600    # 1 hour
    refresh_token_expiration_secs: 2592000  # 30 days
    signing_key:
      algorithm: "RS256"
      kid: "oauth2-key-1"
      private_key: "path/to/private.pem"
      public_key: "path/to/public.pem"
```

### OpenID Connect Provider Configuration

```yaml
identity_provider:
  oidc:
    issuer: "https://auth.example.com"
    userinfo_endpoint: "/oauth/userinfo"
    claims_supported:
      - "sub"
      - "email"
      - "email_verified"
      - "name"
      - "picture"
    scopes_supported:
      - "openid"
      - "profile"
      - "email"
    id_token_expiration_secs: 3600  # 1 hour
```

### SAML Identity Provider Configuration

```yaml
identity_provider:
  saml:
    entity_id: "https://auth.example.com/saml/metadata"
    sso_url: "/saml/sso"
    slo_url: "/saml/slo"
    certificate: "path/to/certificate.pem"
    private_key: "path/to/private-key.pem"
    metadata_endpoint: "/saml/metadata"
    name_id_format: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
```

### Identity Backend Configuration

#### Mock Backend (for testing)

```yaml
identity_backend:
  type: mock
  users:
    - id: "user-1"
      email: "user@example.com"
      name: "Test User"
      attributes:
        department: "Engineering"
```

#### OAuth2 Backend (external providers)

```yaml
identity_backend:
  type: oauth2
  provider: "google"  # or github, microsoft, etc.
  client_id: "your-client-id"
  client_secret: "your-client-secret"
  auth_url: "https://accounts.google.com/o/oauth2/v2/auth"
  token_url: "https://oauth2.googleapis.com/token"
  userinfo_url: "https://www.googleapis.com/oauth2/v3/userinfo"
  scopes:
    - "openid"
    - "email"
    - "profile"
```

#### LDAP Backend (Active Directory)

```yaml
identity_backend:
  type: ldap
  url: "ldaps://ldap.example.com"
  bind_dn: "cn=admin,dc=example,dc=com"
  bind_password: "password"
  base_dn: "ou=users,dc=example,dc=com"
  user_filter: "(uid={username})"
  attributes:
    - "uid"
    - "mail"
    - "cn"
    - "displayName"
```

#### Database Backend

```yaml
identity_backend:
  type: database
  connection_url: "postgresql://user:password@localhost/authdb"
  user_table: "users"
  username_field: "email"
  password_field: "password_hash"
```

### API Key Configuration

```yaml
api_keys:
  enabled: true
  expiration_secs: 0  # 0 = no expiration
  allowed_scopes:
    - "api:read"
    - "api:write"
    - "admin:all"
  signing_key:
    algorithm: "RS256"
    kid: "api-key-1"
    private_key: "path/to/api-key-private.pem"
    public_key: "path/to/api-key-public.pem"
```

See `config.example.yaml` for complete examples.

## API Endpoints

### OAuth2 Authorization Server

#### Authorization Endpoint
```bash
GET /api/v1/tenant/{tenant_id}/oauth/authorize
  ?response_type=code
  &client_id=client-id
  &redirect_uri=https://app.example.com/callback
  &scope=openid profile email
  &state=random-state
```

#### Token Endpoint
```bash
POST /api/v1/tenant/{tenant_id}/oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&
code=authorization-code&
client_id=client-id&
client_secret=client-secret&
redirect_uri=https://app.example.com/callback
```

Response:
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "refresh-token-here",
  "scope": "openid profile email"
}
```

#### JWKS Endpoint (Public Keys)
```bash
GET /api/v1/tenant/{tenant_id}/.well-known/jwks.json
```

Response:
```json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "kid": "oauth2-key-1",
      "n": "base64-encoded-modulus...",
      "e": "AQAB"
    }
  ]
}
```

### OpenID Connect (OIDC)

#### Discovery Endpoint
```bash
GET /api/v1/tenant/{tenant_id}/.well-known/openid-configuration
```

Response:
```json
{
  "issuer": "https://auth.example.com",
  "authorization_endpoint": "https://auth.example.com/api/v1/tenant/{tenant_id}/oauth/authorize",
  "token_endpoint": "https://auth.example.com/api/v1/tenant/{tenant_id}/oauth/token",
  "userinfo_endpoint": "https://auth.example.com/api/v1/tenant/{tenant_id}/oauth/userinfo",
  "jwks_uri": "https://auth.example.com/api/v1/tenant/{tenant_id}/.well-known/jwks.json",
  "scopes_supported": ["openid", "profile", "email"],
  "response_types_supported": ["code", "token"],
  "grant_types_supported": ["authorization_code", "client_credentials", "refresh_token"]
}
```

#### UserInfo Endpoint
```bash
GET /api/v1/tenant/{tenant_id}/oauth/userinfo
Authorization: Bearer <access_token>
```

Response:
```json
{
  "sub": "user-123",
  "email": "user@example.com",
  "email_verified": true,
  "name": "John Doe",
  "picture": "https://example.com/photo.jpg",
  "given_name": "John",
  "family_name": "Doe"
}
```

### SAML 2.0 Identity Provider

#### Metadata Endpoint
```bash
GET /api/v1/tenant/{tenant_id}/saml/metadata
```

Returns XML descriptor for Service Provider integration.

#### SSO Endpoint (HTTP-POST)
```bash
POST /api/v1/tenant/{tenant_id}/saml/sso
Content-Type: application/x-www-form-urlencoded

SAMLRequest=base64-encoded-saml-request&
RelayState=optional-relay-state
```

#### SSO Endpoint (HTTP-Redirect)
```bash
GET /api/v1/tenant/{tenant_id}/saml/sso
  ?SAMLRequest=base64-deflate-encoded-saml-request
  &RelayState=optional-relay-state
```

#### Single Logout (SLO)
```bash
POST /api/v1/tenant/{tenant_id}/saml/slo
Content-Type: application/x-www-form-urlencoded

SAMLRequest=base64-encoded-logout-request
```

### API Key Management

#### Create API Key
```bash
POST /api/v1/tenant/{tenant_id}/api-keys/create
Content-Type: application/json

{
  "name": "Production API Key",
  "scopes": ["api:read", "api:write"],
  "expires_in_days": 90
}
```

Response:
```json
{
  "id": "key-uuid",
  "name": "Production API Key",
  "api_key": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "scopes": ["api:read", "api:write"],
  "created_at": 1234567890,
  "expires_at": 1242343890
}
```

#### List API Keys
```bash
GET /api/v1/tenant/{tenant_id}/api-keys/list
```

Response:
```json
[
  {
    "id": "key-uuid",
    "name": "Production API Key",
    "scopes": ["api:read", "api:write"],
    "created_at": 1234567890,
    "expires_at": 1242343890,
    "last_used": 1234567900,
    "revoked": false
  }
]
```

#### Revoke API Key
```bash
POST /api/v1/tenant/{tenant_id}/api-keys/{key_id}/revoke
```

Response:
```json
{
  "success": true,
  "message": "API key revoked successfully"
}
```

### Token Introspection (RFC 7662)

#### Introspect Token
```bash
POST /api/v1/tenant/{tenant_id}/oauth/introspect
Content-Type: application/x-www-form-urlencoded

token=access-token-or-refresh-token&
token_type_hint=access_token
```

Response:
```json
{
  "active": true,
  "scope": "read write",
  "client_id": "client-123",
  "token_type": "Bearer",
  "exp": 1234567890,
  "iat": 1234560000,
  "sub": "user-id-123",
  "iss": "https://auth.example.com"
}
```

### Token Revocation (RFC 7009)

#### Revoke Token
```bash
POST /api/v1/tenant/{tenant_id}/oauth/revoke
Content-Type: application/x-www-form-urlencoded

token=access-token-or-refresh-token&
token_type_hint=refresh_token
```

Response: `200 OK` (always returns success per RFC 7009)

### Device Authorization Grant (RFC 8628)

#### Device Authorization Request
```bash
POST /api/v1/tenant/{tenant_id}/oauth/device/authorize
Content-Type: application/json

{
  "client_id": "device-client-id",
  "scope": "read write"
}
```

Response:
```json
{
  "device_code": "uuid-device-code",
  "user_code": "WDJB-MJHT",
  "verification_uri": "https://auth.example.com/device",
  "verification_uri_complete": "https://auth.example.com/device?user_code=WDJB-MJHT",
  "expires_in": 900,
  "interval": 5
}
```

#### Device Token Polling
```bash
POST /api/v1/tenant/{tenant_id}/oauth/device/token
Content-Type: application/json

{
  "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
  "device_code": "uuid-device-code",
  "client_id": "device-client-id"
}
```

Response (when authorized):
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "refresh-token-here",
  "scope": "read write"
}
```

Response (still pending):
```json
{
  "error": "authorization_pending",
  "error_description": "User has not yet authorized the device"
}
```

#### Device Verification (Internal API)
```bash
POST /api/v1/tenant/{tenant_id}/oauth/device/verify
Content-Type: application/json

{
  "user_code": "WDJB-MJHT"
}
```

#### Device Confirmation (Internal API)
```bash
POST /api/v1/tenant/{tenant_id}/oauth/device/confirm
Content-Type: application/json

{
  "user_code": "WDJB-MJHT",
  "user_id": "user-123",
  "authorized": true
}
```

### Admin API

#### Tenant Management

##### List Tenants
```bash
GET /api/v1/admin/tenants
```

##### Get Tenant
```bash
GET /api/v1/admin/tenants/{tenant_id}
```

##### Create Tenant
```bash
POST /api/v1/admin/tenants
Content-Type: application/json

{
  "id": "new-tenant",
  "name": "New Tenant",
  "description": "Description",
  "identity_provider": { ... },
  "identity_backend": { ... }
}
```

##### Update Tenant
```bash
PUT /api/v1/admin/tenants/{tenant_id}
Content-Type: application/json

{
  "name": "Updated Name",
  "active": true
}
```

##### Delete Tenant
```bash
DELETE /api/v1/admin/tenants/{tenant_id}
```

#### Client Management

##### List Clients
```bash
GET /api/v1/admin/tenants/{tenant_id}/clients
```

##### Create Client
```bash
POST /api/v1/admin/tenants/{tenant_id}/clients
Content-Type: application/json

{
  "name": "My Application",
  "redirect_uris": ["https://app.example.com/callback"],
  "grant_types": ["authorization_code", "refresh_token"],
  "scopes": ["read", "write"]
}
```

Response:
```json
{
  "client_id": "client_abc123",
  "client_secret": "secret_xyz789",
  "name": "My Application",
  "redirect_uris": ["https://app.example.com/callback"],
  "grant_types": ["authorization_code", "refresh_token"],
  "scopes": ["read", "write"],
  "active": true,
  "created_at": "2025-01-13T10:00:00Z"
}
```

##### Update Client
```bash
PUT /api/v1/admin/tenants/{tenant_id}/clients/{client_id}
Content-Type: application/json

{
  "name": "Updated Application Name",
  "active": false
}
```

##### Delete Client
```bash
DELETE /api/v1/admin/tenants/{tenant_id}/clients/{client_id}
```

#### User Management

##### List Users
```bash
GET /api/v1/admin/tenants/{tenant_id}/users
```

##### Create User
```bash
POST /api/v1/admin/tenants/{tenant_id}/users
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "secure-password",
  "name": "John Doe",
  "role": "User"
}
```

##### Update User
```bash
PUT /api/v1/admin/tenants/{tenant_id}/users/{user_id}
Content-Type: application/json

{
  "email": "newemail@example.com",
  "name": "Jane Doe",
  "active": true
}
```

##### Delete User
```bash
DELETE /api/v1/admin/tenants/{tenant_id}/users/{user_id}
```

### Tenant Discovery

#### List Available Identity Providers
```bash
GET /api/v1/tenant/{tenant_id}/strategies
```

Response:
```json
{
  "tenant_id": "test-tenant",
  "tenant_name": "Test Tenant",
  "strategies": [
    {"name": "oauth2", "type": "OAuth2 Authorization Server"},
    {"name": "oidc", "type": "OpenID Connect Provider"},
    {"name": "saml", "type": "SAML 2.0 Identity Provider"}
  ]
}
```

### Health Check

```bash
GET /health
GET /
```

Response:
```json
{
  "status": "healthy",
  "service": "pmp-auth-api",
  "version": "0.1.0"
}
```

## Development

### Run in development mode
```bash
cargo run
```

### Run tests
```bash
cargo test
```

### Run with logging
```bash
RUST_LOG=debug cargo run
```

### Format code
```bash
cargo fmt
```

### Run linter
```bash
cargo clippy -- -D warnings
```

## Environment Variables

- `CONFIG_PATH` - Path to tenant configuration file (default: looks for config.yaml in current directory)
- `RUST_LOG` - Logging level (default: "pmp_auth_api=debug,tower_http=debug")

## Architecture

```
src/
├── main.rs                      # Application entry point and route configuration
├── config.rs                    # Configuration loader and validator
├── auth/                        # Authentication and authorization logic
│   ├── api_keys.rs             # API key management (create, list, revoke)
│   ├── identity_backend.rs     # Identity backend abstraction (LDAP, DB, OAuth2, etc.)
│   ├── jwt.rs                  # JWT token creation (legacy)
│   ├── oauth2.rs               # OAuth2 client implementation (for backends)
│   ├── oauth2_server.rs        # OAuth2 Authorization Server implementation
│   ├── oidc.rs                 # OpenID Connect Provider implementation
│   ├── password.rs             # Password hashing and verification
│   ├── saml.rs                 # SAML 2.0 Identity Provider implementation
│   └── strategies.rs           # Legacy strategy stubs
├── handlers/                    # Request handlers
│   ├── tenant_auth.rs          # Tenant strategy listing
│   ├── health.rs               # Health check handler
│   ├── auth.rs                 # Legacy handlers (deprecated)
│   ├── user.rs                 # Legacy handlers (deprecated)
│   └── admin.rs                # Legacy handlers (deprecated)
├── middleware/                  # Middleware components
│   ├── auth.rs                 # Legacy authentication middleware
│   └── tenant_auth.rs          # Tenant authentication middleware
└── models/                      # Data models
    ├── tenant.rs               # Tenant, OAuth2, OIDC, SAML config models
    └── user.rs                 # User, Claims, and request/response models
```

## Security Considerations

- JWT tokens are signed with RSA or ECDSA keys (RS256, ES256)
- Access tokens expire after 1 hour (configurable)
- Refresh tokens expire after 30 days (configurable)
- API keys can be revoked immediately
- Use HTTPS in production
- Store private keys securely (use key management services in production)
- Implement rate limiting for production deployments
- Validate redirect URIs for OAuth2 flows
- Implement PKCE for authorization code flow
- Sign SAML assertions with X.509 certificates

## Production Deployment

For production deployment:

1. **Generate secure signing keys**:
   ```bash
   # RSA keys for OAuth2/OIDC
   openssl genrsa -out oauth2-private.pem 2048
   openssl rsa -in oauth2-private.pem -pubout -out oauth2-public.pem

   # RSA keys for API keys
   openssl genrsa -out api-key-private.pem 2048
   openssl rsa -in api-key-private.pem -pubout -out api-key-public.pem

   # X.509 certificate for SAML
   openssl req -newkey rsa:2048 -x509 -days 365 -nodes \
     -out saml-cert.pem -keyout saml-key.pem
   ```

2. **Use environment-based configuration**: Store secrets in environment variables or key management services

3. **Implement proper identity backends**: Replace Mock backend with LDAP, Database, or Federated backends

4. **Enable HTTPS/TLS**: Use reverse proxy (nginx, Caddy) or configure TLS directly

5. **Set up proper CORS policies**: Configure allowed origins for your applications

6. **Implement rate limiting**: Protect against brute force and DoS attacks

7. **Add monitoring and alerting**: Track API usage, errors, and performance

8. **Implement audit logging**: Log all authentication attempts and token issuance

9. **Regular key rotation**: Rotate signing keys periodically

10. **Database for persistence**: Replace in-memory storage with Redis or database

## Protocol Support

### OAuth 2.0
- RFC 6749 - The OAuth 2.0 Authorization Framework
- RFC 7519 - JSON Web Token (JWT)
- RFC 7517 - JSON Web Key (JWK)

### OpenID Connect
- OpenID Connect Core 1.0
- OpenID Connect Discovery 1.0

### SAML 2.0
- SAML 2.0 Core
- SAML 2.0 Bindings (HTTP-POST, HTTP-Redirect)
- SAML 2.0 Profiles (Web Browser SSO)

## License

See [LICENSE](LICENSE) file for details.

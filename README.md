# pmp-auth-api

PMP Auth API: An authentication / authorization API. Part of Poor Man's Platform ecosystem.

A high-performance multi-tenant authentication and authorization API built with Rust and Axum, featuring multiple authentication strategies, JWT-based authentication, role-based access control, and secure password hashing.

## Features

### Multi-Tenancy
- **Tenant isolation**: Each tenant has its own users and authentication configuration
- **Multiple auth strategies per tenant**: Configure JWT (JWK/Secret), OAuth2, or Local auth per tenant
- **Flexible configuration**: YAML-based tenant configuration
- **Backward compatible**: Legacy single-tenant routes still supported

### Authentication Strategies
- **Local Auth**: Username/password with JWT tokens
- **JWT with JWK**: Validate tokens from external providers (Auth0, Okta, etc.)
- **JWT with Shared Secret**: Simple JWT validation with a shared secret
- **OAuth2**: Support for OAuth2 providers (Google, GitHub, Microsoft, etc.)

### Security & Features
- Password hashing with bcrypt
- Role-based authorization (User, Admin)
- Protected and public routes
- RESTful API design
- Comprehensive error handling
- CORS support
- Request tracing and logging

## Prerequisites

- Rust 1.70+ (install from [rustup.rs](https://rustup.rs))
- Cargo (comes with Rust)

## Quick Start

1. Clone the repository:
```bash
git clone <repository-url>
cd pmp-auth-api
```

2. Set up environment variables:
```bash
cp .env.example .env
# Edit .env and set your JWT_SECRET
```

3. Configure tenants (for multi-tenant mode):
```bash
cp config.example.yaml config.yaml
# Edit config.yaml to configure your tenants and auth strategies
```

4. Build and run:
```bash
cargo build
cargo run
```

The API will start on `http://0.0.0.0:3000`

## Multi-Tenant Configuration

The API supports multi-tenant mode where each tenant can have its own authentication strategies. Create a `config.yaml` file to enable multi-tenant mode.

### Configuration Structure

```yaml
tenants:
  tenant-id:
    id: tenant-id
    name: "Tenant Name"
    description: "Optional description"
    active: true
    auth_strategies:
      strategy-name:
        type: local|jwkjwt|secretjwt|oauth2
        # Strategy-specific configuration...
```

### Authentication Strategy Types

#### 1. Local Authentication (Username/Password)
```yaml
local:
  type: local
  allow_registration: true
  min_password_length: 8
  require_email_verification: false
  jwt_secret: "your-secret-key"
  expiration_secs: 86400  # 24 hours
```

#### 2. JWT with JWK (Auth0, Okta, etc.)
```yaml
auth0:
  type: jwkjwt
  jwks_uri: "https://your-domain.auth0.com/.well-known/jwks.json"
  issuer: "https://your-domain.auth0.com/"
  audience:
    - "https://your-api.com"
  cache_duration_secs: 3600
  algorithms:
    - "RS256"
```

#### 3. JWT with Shared Secret
```yaml
jwt:
  type: secretjwt
  secret: "your-shared-secret"
  issuer: "your-api"
  audience:
    - "your-api"
  expiration_secs: 43200  # 12 hours
```

#### 4. OAuth2 (Google, GitHub, Microsoft, etc.)
```yaml
google:
  type: oauth2
  client_id: "your-client-id"
  client_secret: "your-client-secret"
  auth_url: "https://accounts.google.com/o/oauth2/v2/auth"
  token_url: "https://oauth2.googleapis.com/token"
  redirect_uri: "https://your-api.com/api/v1/tenant/tenant-id/auth/google/oauth/callback"
  scopes:
    - "openid"
    - "email"
    - "profile"
  userinfo_url: "https://www.googleapis.com/oauth2/v3/userinfo"
```

See `config.example.yaml` for complete examples.

## API Endpoints

### Multi-Tenant Routes

When multi-tenant mode is enabled (config.yaml exists), the following routes are available:

#### List Auth Strategies
```bash
GET /api/v1/tenant/{tenant-id}/strategies
```

Response:
```json
{
  "tenant_id": "test-tenant",
  "tenant_name": "Test Tenant",
  "strategies": [
    {"name": "local", "type": "local"},
    {"name": "jwt", "type": "secretjwt"}
  ]
}
```

#### Register (Local Auth)
```bash
POST /api/v1/tenant/{tenant-id}/auth/{strategy-name}/register
Content-Type: application/json

{
  "email": "user@example.com",
  "username": "johndoe",
  "password": "securepassword"
}
```

#### Login (Local Auth)
```bash
POST /api/v1/tenant/{tenant-id}/auth/{strategy-name}/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "securepassword"
}
```

#### OAuth2 Login
```bash
GET /api/v1/tenant/{tenant-id}/auth/{strategy-name}/oauth/login
```
Redirects to OAuth2 provider's authorization page.

#### OAuth2 Callback
```bash
GET /api/v1/tenant/{tenant-id}/auth/{strategy-name}/oauth/callback?code=...&state=...
```
Handles OAuth2 callback and returns access token and user info.

### Legacy Routes (Backward Compatibility)

### Public Endpoints

#### Health Check
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

#### Register
```bash
POST /api/v1/auth/register
Content-Type: application/json

{
  "email": "user@example.com",
  "username": "johndoe",
  "password": "securepassword"
}
```

Response:
```json
{
  "token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "user": {
    "id": "123e4567-e89b-12d3-a456-426614174000",
    "email": "user@example.com",
    "username": "johndoe",
    "role": "user"
  }
}
```

#### Login
```bash
POST /api/v1/auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "securepassword"
}
```

Response:
```json
{
  "token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "user": {
    "id": "123e4567-e89b-12d3-a456-426614174000",
    "email": "user@example.com",
    "username": "johndoe",
    "role": "user"
  }
}
```

### Protected Endpoints

All protected endpoints require an Authorization header with a Bearer token:
```bash
Authorization: Bearer <your-jwt-token>
```

#### Get User Profile
```bash
GET /api/v1/user/profile
Authorization: Bearer <token>
```

Response:
```json
{
  "id": "123e4567-e89b-12d3-a456-426614174000",
  "email": "user@example.com",
  "role": "user"
}
```

#### List Users (Admin Only)
```bash
GET /api/v1/admin/users
Authorization: Bearer <admin-token>
```

Response:
```json
{
  "message": "Admin endpoint - list all users",
  "requested_by": "admin@example.com",
  "note": "In production, this would return a list of users from the database"
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
cargo clippy
```

## Environment Variables

- `CONFIG_PATH` - Path to tenant configuration file (default: looks for config.yaml in current directory)
- `JWT_SECRET` - Secret key for JWT token signing in legacy mode (default: "your-secret-key-change-this-in-production")
- `RUST_LOG` - Logging level (default: "pmp_auth_api=debug,tower_http=debug")

## Configuration Files

- `config.yaml` - Multi-tenant configuration (see `config.example.yaml` for examples)
- `.env` - Environment variables for legacy mode

## CI/CD

This project uses GitHub Actions for continuous integration. The workflow runs on:
- Pull requests to `main`
- Pushes to `main`

The CI pipeline includes:
1. **Lint**: Format checking and Clippy linting
2. **Test**: Run all tests
3. **Build**: Build release binary

## Architecture

```
src/
├── main.rs                    # Application entry point
├── config.rs                  # Configuration loader and validator
├── auth/                      # Authentication logic
│   ├── jwt.rs                # JWT token creation and validation (legacy)
│   ├── password.rs           # Password hashing and verification
│   ├── strategies.rs         # Multi-strategy token validation (JWK, Secret, Local)
│   └── oauth2.rs             # OAuth2 flow implementation
├── handlers/                  # Request handlers
│   ├── auth.rs               # Legacy registration and login handlers
│   ├── tenant_auth.rs        # Multi-tenant auth handlers
│   ├── user.rs               # User profile handlers
│   ├── admin.rs              # Admin-only handlers
│   └── health.rs             # Health check handler
├── middleware/               # Middleware components
│   ├── auth.rs              # Legacy authentication middleware
│   └── tenant_auth.rs       # Multi-tenant authentication middleware
└── models/                  # Data models
    ├── user.rs             # User, Claims, and request/response models
    └── tenant.rs           # Tenant and auth strategy models
```

## Security Considerations

- Passwords are hashed using bcrypt
- JWT tokens expire after 24 hours
- Admin routes are protected with role-based authorization
- Change the `JWT_SECRET` environment variable in production
- In production, replace the in-memory storage with a proper database
- Use HTTPS in production

## Production Deployment

For production deployment:

1. Set a strong `JWT_SECRET` environment variable
2. Replace in-memory storage with a database (PostgreSQL, MySQL, etc.)
3. Enable HTTPS/TLS
4. Configure proper CORS policies
5. Set up rate limiting
6. Implement refresh tokens
7. Add password strength validation
8. Implement account verification (email)
9. Add audit logging

## License

See [LICENSE](LICENSE) file for details.

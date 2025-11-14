# PMP Auth API

**Enterprise-Grade Multi-Tenant Authentication & Authorization Platform**

A high-performance, production-ready authentication and authorization platform built with Rust and Axum. This API serves as a comprehensive identity provider (IdP) and authorization server, supporting OAuth2, OpenID Connect (OIDC), and SAML 2.0 protocols with enterprise-grade security features.

## Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [Authentication Methods](#authentication-methods)
- [Enterprise Security Features](#enterprise-security-features)
- [Observability & Monitoring](#observability--monitoring)
- [API Endpoints](#api-endpoints)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Examples](#examples)
- [Development](#development)
- [Production Deployment](#production-deployment)
- [Architecture](#architecture)
- [License](#license)

## Overview

PMP Auth API is a complete identity and access management (IAM) platform that provides:

- **OAuth2 Authorization Server**: Full RFC 6749 implementation with PKCE support
- **OpenID Connect Provider**: OIDC 1.0 identity layer with comprehensive claims
- **SAML 2.0 Identity Provider**: Enterprise SSO with SAML assertions
- **Multi-Factor Authentication**: TOTP (RFC 6238) and backup codes
- **Session Management**: Activity tracking, device fingerprinting, concurrent session limits
- **API Key Management**: Long-lived JWT tokens with scoped access control
- **Device Flow**: RFC 8628 for IoT and limited-input devices
- **Certificate Management**: Automatic key rotation with HSM support
- **LDAP/Active Directory**: Integration with group synchronization
- **Audit Logging**: Comprehensive compliance trails with 50+ event types
- **Rate Limiting**: Brute force protection and DoS prevention
- **Health Checks**: Kubernetes-compatible liveness and readiness probes
- **Metrics**: Prometheus and OpenTelemetry integration

## Key Features

### 🏢 Multi-Tenancy
- **Complete tenant isolation**: Separate configuration, keys, and data per tenant
- **Flexible identity providers**: OAuth2, OIDC, and SAML simultaneously
- **YAML-based configuration**: Easy tenant management
- **Per-tenant signing keys**: Independent JWK sets for each tenant
- **Admin API**: REST API for tenant, client, and user management

### 🔐 Authentication Methods

#### OAuth2 Authorization Server (RFC 6749)
- **Authorization Code Flow**: Full implementation with PKCE (RFC 7636)
- **Client Credentials Flow**: Machine-to-machine authentication
- **Refresh Token Flow**: Seamless token renewal
- **Device Authorization Grant**: RFC 8628 for limited-input devices
- **Resource Owner Password Credentials**: Optional direct password flow
- **Token Introspection**: RFC 7662 token validation
- **Token Revocation**: RFC 7009 immediate token invalidation
- **PKCE Support**: S256 and plain challenge methods

#### OpenID Connect (OIDC) 1.0
- **Discovery Endpoint**: Standard OIDC metadata at `/.well-known/openid-configuration`
- **UserInfo Endpoint**: Rich user profile information
- **ID Token Generation**: JWT-based identity tokens
- **Standard Claims**: sub, email, email_verified, name, picture, given_name, family_name
- **Configurable Scopes**: openid, profile, email, and custom scopes

#### SAML 2.0 Identity Provider
- **Metadata Endpoint**: XML descriptor for Service Provider integration
- **SSO Support**: HTTP-POST and HTTP-Redirect bindings
- **Single Logout (SLO)**: Graceful session termination
- **Signed Assertions**: X.509 certificate-based signatures
- **NameID Format**: emailAddress and configurable formats
- **Flexible Attributes**: Custom attribute mapping

#### API Key Management
- **Long-lived Tokens**: JWT-based API keys
- **Scoped Access**: Fine-grained permissions per key
- **Flexible Expiration**: Days-based or permanent keys
- **Immediate Revocation**: Instant key invalidation
- **Usage Tracking**: Created, last used, and revocation status

#### Device Authorization Grant (RFC 8628)
- **User-Friendly Codes**: 8-character codes (no ambiguous characters)
- **Responsive UI**: Modern web verification page
- **Status Tracking**: Pending, authorized, denied, expired states
- **Configurable Polling**: Default 5-second interval
- **Enterprise Support**: Perfect for smart TVs, IoT devices, CLI tools

## Enterprise Security Features

### 🔒 Multi-Factor Authentication (MFA)
**Location**: `/src/mfa/`

- **TOTP (Time-based OTP)**: RFC 6238 compliant
  - 6-digit codes (configurable)
  - 30-second time step (configurable)
  - Time skew tolerance (±1 time step)
  - QR code generation for authenticator apps (Google Authenticator, Authy, etc.)
- **Backup Codes**: Emergency recovery mechanism
  - Encrypted storage
  - Single-use validation
  - Automatic regeneration support

### 📊 Session Management
**Location**: `/src/session/`

- **Comprehensive Activity Tracking**:
  - Last activity timestamp
  - IP address logging
  - User agent capture
  - Device information extraction
  - Geographic location (optional)

- **Device Recognition**:
  - Device type detection (desktop, mobile, tablet)
  - OS identification (Windows, macOS, Linux, iOS, Android)
  - Browser detection (Chrome, Firefox, Safari, Edge, Opera)

- **Session Controls**:
  - Concurrent session limits (configurable per tenant)
  - Idle timeout (default 1 hour)
  - Absolute timeout (default 24 hours)
  - Manual session termination
  - Session status tracking (active, expired, terminated, invalidated)

### 🛡️ Rate Limiting & Brute Force Protection
**Location**: `/src/middleware/`

- **Multiple Backends**:
  - In-memory rate limiter (development)
  - Redis-backed rate limiter (production, distributed)

- **Configurable Policies**:
  - Max requests per time window
  - Failed login attempt tracking
  - Automatic account lockout
  - Configurable block duration
  - IP-based and user-based limiting

### 📝 Comprehensive Audit Logging
**Location**: `/src/audit/`

- **50+ Event Types**:
  - Authentication (Login, LoginFailed, Logout)
  - Token operations (Generated, Refreshed, Revoked, Introspected)
  - MFA events (Enabled, Disabled, Verified, Failed)
  - Password management (Changed, ResetRequested, ResetCompleted)
  - Admin operations (Tenant/Client/User CRUD)
  - Security events (RateLimitExceeded, BruteForceDetected, AccountLocked)
  - Device flow (CodeGenerated, CodeAuthorized, CodeRejected)
  - Session events (Created, Refreshed, Terminated, Expired)

- **Rich Audit Data**:
  - Timestamp, tenant_id, user_id, client_id
  - IP address, user agent, geographic location
  - Action type, resource type, resource ID
  - Severity levels (INFO, WARNING, CRITICAL)
  - Success/failure status
  - Error messages and metadata
  - Session ID and request ID for tracing

- **Storage Options**:
  - In-memory (development)
  - PostgreSQL (production)
  - Export capabilities for compliance reporting

### 🔑 Certificate Management
**Location**: `/src/certs/`

- **Automatic Key Rotation**:
  - Configurable rotation policies per tenant
  - Grace period for zero-downtime rollover
  - Background scheduler for automatic rotation
  - Manual rotation triggers

- **Advanced Key Management**:
  - Multiple active keys simultaneously
  - Key lifecycle management (generation, activation, deactivation)
  - Automatic cleanup of expired keys
  - Algorithm support: RS256, RS384, RS512, ES256, ES384, HS256, HS384, HS512

- **Hardware Security Module (HSM) Integration**:
  - PKCS#11 support
  - AWS CloudHSM
  - Azure Key Vault
  - Google Cloud KMS
  - Software fallback for development

### 🏢 LDAP/Active Directory Integration
**Location**: `/src/ldap/`

- **Authentication & User Lookup**:
  - LDAP bind authentication
  - User search by ID, email, username
  - Configurable search filters
  - StartTLS/TLS support
  - Connection pooling
  - Health checks

- **Group Management**:
  - Group membership resolution
  - Nested group expansion (recursive)
  - Admin group assignment
  - Configurable recursion depth
  - Group membership caching

- **Synchronization**:
  - Periodic group sync scheduler
  - Configurable sync intervals
  - Sync statistics and monitoring
  - Background task support

## Observability & Monitoring

### 🏥 Health Checks
**Location**: `/src/health/`

**Kubernetes-Compatible Endpoints**:
- `GET /health` - General health check
- `GET /healthz` - Liveness probe
- `GET /livez` - Liveness probe
- `GET /readyz` - Readiness probe

**Health Check Types**:
- **Liveness**: Critical system health (process alive, not deadlocked)
- **Readiness**: All dependencies available (database, Redis, LDAP)
- **Startup**: One-time initialization validation

**Dependency Checks**:
- Database connectivity (PostgreSQL, MySQL)
- Redis connectivity
- LDAP/AD connectivity
- External OAuth2 providers
- System health and uptime

**Features**:
- Background health monitoring
- Health check caching
- Configurable timeouts
- Critical vs non-critical checks
- Detailed JSON health status responses

### 📈 Prometheus Metrics
**Location**: `/src/metrics/`

**Token Metrics**:
- `tokens_issued_total{tenant_id, token_type}` - Total tokens issued
- `tokens_revoked_total{tenant_id, token_type}` - Total tokens revoked
- Token lifetime tracking

**Authentication Metrics**:
- `auth_attempts_total{tenant_id, backend_type}` - Total auth attempts
- `auth_success_total{tenant_id, backend_type}` - Successful authentications
- `auth_failures_total{tenant_id, backend_type, reason}` - Failed attempts with reasons

**Performance Metrics**:
- `request_duration_seconds{tenant_id, method, endpoint, status}` - Request latency histograms
- `active_sessions{tenant_id}` - Current active sessions gauge
- `ldap_query_duration_seconds` - LDAP query latency
- `db_query_duration_seconds` - Database query latency

**Error Tracking**:
- `errors_total{tenant_id, error_type, endpoint}` - Error counts by type

**Resource Pool Metrics**:
- LDAP connection pool status
- Database connection pool status
- Redis connection pool status

**OAuth2/SAML Metrics**:
- Authorization request counts
- SAML assertion generation metrics
- Device code flow metrics

**Prometheus Endpoint**: `GET /metrics`

### 🔭 OpenTelemetry Integration
**Location**: `/src/metrics/opentelemetry.rs`

- Prometheus exporter support
- Service metadata (name, version)
- Custom meter and tracer support
- OTLP exporter capability
- Graceful shutdown support
- Distributed tracing readiness

## API Endpoints

### Base URL Pattern
- Multi-tenant: `/api/v1/tenant/{tenant_id}/*`
- Admin API: `/api/v1/admin/*`
- System: `/health`, `/metrics`, `/device`

### OAuth2 Authorization Server

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/oauth/authorize` | GET | Authorization Code Flow - request authorization |
| `/oauth/token` | POST | Exchange authorization code or credentials for tokens |
| `/oauth/introspect` | POST | RFC 7662 - Validate token and retrieve metadata |
| `/oauth/revoke` | POST | RFC 7009 - Revoke access or refresh token |
| `/.well-known/jwks.json` | GET | Public key distribution (JWK Set) |

### OpenID Connect

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/.well-known/openid-configuration` | GET | OIDC Discovery metadata |
| `/oauth/userinfo` | GET | User profile information (requires access token) |

### SAML 2.0 Identity Provider

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/saml/metadata` | GET | SAML IdP metadata XML descriptor |
| `/saml/sso` | GET/POST | Single Sign-On endpoint (Redirect/POST binding) |
| `/saml/slo` | POST | Single Logout endpoint |

### API Key Management

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api-keys/create` | POST | Create new API key with scopes |
| `/api-keys/list` | GET | List all API keys for user |
| `/api-keys/{key_id}/revoke` | POST | Revoke specific API key |

### Device Flow (RFC 8628)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/oauth/device/authorize` | POST | Request device code and user code |
| `/oauth/device/token` | POST | Poll for token (by device) |
| `/oauth/device/verify` | POST | Verify user code (internal) |
| `/oauth/device/confirm` | POST | Confirm authorization (internal) |

### Admin API

#### Tenant Management
- `GET /api/v1/admin/tenants` - List all tenants
- `POST /api/v1/admin/tenants` - Create new tenant
- `GET /api/v1/admin/tenants/{tenant_id}` - Get tenant details
- `PUT /api/v1/admin/tenants/{tenant_id}` - Update tenant
- `DELETE /api/v1/admin/tenants/{tenant_id}` - Delete tenant

#### Client Management
- `GET /api/v1/admin/tenants/{tenant_id}/clients` - List OAuth2 clients
- `POST /api/v1/admin/tenants/{tenant_id}/clients` - Register new client
- `GET /api/v1/admin/tenants/{tenant_id}/clients/{client_id}` - Get client
- `PUT /api/v1/admin/tenants/{tenant_id}/clients/{client_id}` - Update client
- `DELETE /api/v1/admin/tenants/{tenant_id}/clients/{client_id}` - Delete client

#### User Management
- `GET /api/v1/admin/tenants/{tenant_id}/users` - List users
- `POST /api/v1/admin/tenants/{tenant_id}/users` - Create user
- `GET /api/v1/admin/tenants/{tenant_id}/users/{user_id}` - Get user
- `PUT /api/v1/admin/tenants/{tenant_id}/users/{user_id}` - Update user
- `DELETE /api/v1/admin/tenants/{tenant_id}/users/{user_id}` - Delete user

### System Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | General health check |
| `/healthz` | GET | Kubernetes liveness probe |
| `/livez` | GET | Liveness probe |
| `/readyz` | GET | Readiness probe |
| `/metrics` | GET | Prometheus metrics |
| `/device` | GET | Device flow verification page (web UI) |

## Quick Start

### Prerequisites

- Rust 1.91+ (Rust 2024 edition)
- Cargo (included with Rust)
- PostgreSQL (optional, for production)
- Redis (optional, for distributed rate limiting)

### Installation

1. **Clone the repository**:
```bash
git clone <repository-url>
cd pmp-auth-api
```

2. **Generate signing keys**:
```bash
# OAuth2/OIDC signing keys
openssl genrsa -out oauth2-private.pem 2048
openssl rsa -in oauth2-private.pem -pubout -out oauth2-public.pem

# API key signing keys
openssl genrsa -out api-key-private.pem 2048
openssl rsa -in api-key-private.pem -pubout -out api-key-public.pem
```

3. **Configure tenants**:
```bash
cp config.example.yaml config.yaml
# Edit config.yaml with your tenant configuration
```

4. **Build and run**:
```bash
cargo build --release
cargo run --release
```

The API will start on `http://0.0.0.0:3000`

### Docker Quick Start

```bash
docker build -t pmp-auth-api .
docker run -p 3000:3000 -v $(pwd)/config.yaml:/app/config.yaml pmp-auth-api
```

## Configuration

### Configuration File Structure

Create a `config.yaml` file with the following structure:

```yaml
tenants:
  my-tenant:
    id: my-tenant
    name: "My Organization"
    description: "Production authentication tenant"
    active: true

    # Session management configuration
    session:
      idle_timeout_secs: 3600      # 1 hour
      absolute_timeout_secs: 86400  # 24 hours
      max_concurrent_sessions: 5
      track_location: true

    # Rate limiting configuration
    rate_limiting:
      enabled: true
      max_requests: 100
      window_secs: 60
      max_failed_attempts: 5
      block_duration_secs: 300

    # Audit logging configuration
    audit:
      enabled: true
      log_level: "INFO"  # INFO, WARNING, CRITICAL
      storage: "postgres"  # memory or postgres

    # Certificate management
    certificates:
      rotation_enabled: true
      rotation_interval_days: 90
      grace_period_days: 7
      hsm_enabled: false
      hsm_provider: "software"  # software, pkcs11, aws, azure, gcp

    # Identity Provider Configuration
    identity_provider:
      oauth2:
        issuer: "https://auth.example.com"
        grant_types:
          - "authorization_code"
          - "client_credentials"
          - "refresh_token"
          - "urn:ietf:params:oauth:grant-type:device_code"
        access_token_expiration_secs: 3600
        refresh_token_expiration_secs: 2592000
        signing_key:
          algorithm: "RS256"
          kid: "oauth2-key-1"
          private_key: "oauth2-private.pem"
          public_key: "oauth2-public.pem"

      oidc:
        issuer: "https://auth.example.com"
        userinfo_endpoint: "/oauth/userinfo"
        claims_supported:
          - "sub"
          - "email"
          - "email_verified"
          - "name"
          - "picture"
          - "given_name"
          - "family_name"
        scopes_supported:
          - "openid"
          - "profile"
          - "email"
        id_token_expiration_secs: 3600

      saml:
        entity_id: "https://auth.example.com/saml/metadata"
        sso_url: "/saml/sso"
        slo_url: "/saml/slo"
        certificate: "saml-cert.pem"
        private_key: "saml-key.pem"
        name_id_format: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"

    # Identity Backend (where users come from)
    identity_backend:
      type: "ldap"  # mock, oauth2, ldap, database, federated

      # LDAP configuration
      url: "ldaps://ldap.example.com"
      bind_dn: "cn=admin,dc=example,dc=com"
      bind_password: "password"
      base_dn: "ou=users,dc=example,dc=com"
      user_filter: "(uid={username})"
      start_tls: true

      # Group synchronization
      groups:
        enabled: true
        base_dn: "ou=groups,dc=example,dc=com"
        group_filter: "(objectClass=groupOfNames)"
        member_attribute: "member"
        recursive: true
        max_depth: 10
        sync_interval_secs: 3600

    # API Key Management
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
        private_key: "api-key-private.pem"
        public_key: "api-key-public.pem"
```

### Environment Variables

- `CONFIG_PATH` - Path to configuration file (default: `./config.yaml`)
- `RUST_LOG` - Logging level (default: `pmp_auth_api=debug,tower_http=debug`)
- `DATABASE_URL` - PostgreSQL connection string (for production storage)
- `REDIS_URL` - Redis connection string (for distributed rate limiting)

### Identity Backend Options

#### Mock Backend (Development)
```yaml
identity_backend:
  type: mock
  users:
    - id: "user-1"
      email: "admin@example.com"
      name: "Admin User"
      password_hash: "$2b$12$..."
      role: "Admin"
```

#### LDAP/Active Directory
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

#### OAuth2 Backend (External Providers)
```yaml
identity_backend:
  type: oauth2
  provider: "google"
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

#### Database Backend
```yaml
identity_backend:
  type: database
  connection_url: "postgresql://user:password@localhost/authdb"
  user_table: "users"
  username_field: "email"
  password_field: "password_hash"
```

## Examples

See the `/examples` directory for comprehensive examples:

1. **OAuth2 Client Credentials** (`examples/oauth2_client_credentials.md`) - Machine-to-machine authentication
2. **OAuth2 Authorization Code Flow** (`examples/oauth2_authorization_code.md`) - Web app user login with PKCE
3. **OpenID Connect** (`examples/openid_connect.md`) - User identity and SSO
4. **API Key Management** (`examples/api_keys.md`) - Long-lived tokens for automation
5. **SAML 2.0 SSO** (`examples/saml_sso.md`) - Enterprise SSO integration
6. **Device Flow** (`examples/device_flow.md`) - IoT and CLI authentication
7. **Multi-Factor Authentication** (`examples/mfa.md`) - TOTP setup and verification
8. **Session Management** (`examples/session_management.md`) - Activity tracking and device management
9. **LDAP Integration** (`examples/ldap_integration.md`) - Active Directory authentication
10. **Audit Logging** (`examples/audit_logging.md`) - Compliance and security monitoring

## Development

### Build

```bash
# Debug build
cargo build

# Release build (optimized)
cargo build --release
```

### Run

```bash
# Development mode with logging
RUST_LOG=debug cargo run

# Production mode
cargo run --release
```

### Test

```bash
# Run all tests
cargo test

# Run specific test
cargo test test_name

# Run with output
cargo test -- --nocapture
```

### Code Quality

```bash
# Format code
cargo fmt

# Run linter
cargo clippy

# Run linter with warnings as errors
cargo clippy -- -D warnings
```

### Database Setup (PostgreSQL)

```bash
# Create database
createdb pmp_auth

# Run migrations
psql pmp_auth < migrations/001_initial_schema.sql
```

## Production Deployment

### Security Checklist

- [ ] Generate secure RSA/ECDSA keys (4096-bit recommended)
- [ ] Use PostgreSQL for persistent storage (not in-memory)
- [ ] Enable HTTPS/TLS with valid certificates
- [ ] Configure proper CORS policies
- [ ] Implement Redis for distributed rate limiting
- [ ] Use production identity backends (LDAP/Database, not Mock)
- [ ] Enable audit logging with PostgreSQL storage
- [ ] Configure Kubernetes health checks
- [ ] Enable Prometheus metrics export
- [ ] Implement certificate rotation policies
- [ ] Use HSM for production key storage
- [ ] Set up proper backup and disaster recovery
- [ ] Implement monitoring and alerting
- [ ] Review and harden security headers
- [ ] Enable MFA for all administrative accounts

### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: pmp-auth-api
spec:
  replicas: 3
  selector:
    matchLabels:
      app: pmp-auth-api
  template:
    metadata:
      labels:
        app: pmp-auth-api
    spec:
      containers:
      - name: pmp-auth-api
        image: pmp-auth-api:latest
        ports:
        - containerPort: 3000
        env:
        - name: CONFIG_PATH
          value: "/config/config.yaml"
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: pmp-auth-secrets
              key: database-url
        livenessProbe:
          httpGet:
            path: /livez
            port: 3000
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /readyz
            port: 3000
          initialDelaySeconds: 10
          periodSeconds: 5
        volumeMounts:
        - name: config
          mountPath: /config
        - name: keys
          mountPath: /keys
      volumes:
      - name: config
        configMap:
          name: pmp-auth-config
      - name: keys
        secret:
          secretName: pmp-auth-keys
```

### Performance Tuning

- **Connection Pooling**: Configure database and Redis connection pools
- **Caching**: Enable LDAP group membership caching
- **Rate Limiting**: Use Redis backend for distributed environments
- **Metrics**: Monitor request latency and optimize slow endpoints
- **Horizontal Scaling**: Deploy multiple replicas behind load balancer

## Architecture

### Project Structure

```
src/
├── main.rs                  # Application entry point and routing
├── config.rs                # Configuration management
├── auth/                    # Core authentication logic
│   ├── api_keys.rs         # API key management
│   ├── device_flow.rs      # RFC 8628 Device Authorization Grant
│   ├── identity_backend.rs # Identity provider abstraction
│   ├── jwt.rs              # JWT token operations
│   ├── oauth2.rs           # OAuth2 client implementation
│   ├── oauth2_server.rs    # OAuth2 Authorization Server
│   ├── oidc.rs             # OpenID Connect Provider
│   ├── password.rs         # Password hashing (bcrypt)
│   ├── saml.rs             # SAML 2.0 Identity Provider
│   ├── strategies.rs       # Authentication strategies
│   └── token_introspection.rs # RFC 7662 & 7009
├── middleware/             # Request processing middleware
│   ├── auth.rs            # Authentication middleware
│   ├── rate_limit.rs      # Rate limiting abstraction
│   ├── rate_limit_memory.rs # In-memory rate limiter
│   ├── rate_limit_redis.rs  # Redis-backed rate limiter
│   └── tenant_auth.rs     # Tenant authentication
├── handlers/              # HTTP request handlers
│   ├── admin.rs          # Admin API handlers
│   ├── auth.rs           # Authentication handlers
│   ├── device.rs         # Device flow UI
│   ├── health.rs         # Health check endpoints
│   ├── tenant_auth.rs    # Tenant-specific handlers
│   └── user.rs           # User profile handlers
├── admin/                # Admin API management
│   ├── clients.rs       # OAuth2 client CRUD
│   ├── tenants.rs       # Tenant CRUD
│   └── users.rs         # User CRUD
├── models/              # Data models
│   ├── tenant.rs        # Tenant & configuration models
│   └── user.rs          # User & claims models
├── session/             # Session management
│   ├── manager.rs       # Session lifecycle management
│   ├── storage.rs       # Session persistence
│   └── types.rs         # Session data structures
├── mfa/                 # Multi-Factor Authentication
│   ├── totp.rs         # Time-based OTP (RFC 6238)
│   └── backup_codes.rs # Backup codes for MFA recovery
├── ldap/                # LDAP/Active Directory
│   ├── backend.rs       # LDAP authentication & lookup
│   ├── groups.rs        # Group membership resolution
│   └── sync.rs          # Group synchronization scheduler
├── audit/               # Audit logging & compliance
│   ├── logger.rs        # Audit event recording
│   ├── storage.rs       # Audit log persistence
│   └── types.rs         # Audit event types
├── certs/               # Certificate management
│   ├── manager.rs       # Certificate lifecycle
│   ├── rotation.rs      # Automated key rotation
│   └── hsm.rs           # Hardware Security Module integration
├── metrics/             # Observability & monitoring
│   ├── prometheus_metrics.rs # Prometheus metrics
│   ├── opentelemetry.rs      # OpenTelemetry integration
│   └── collectors.rs         # Metric collectors
├── health/              # Health check system
│   ├── checks.rs        # Health check implementations
│   └── probes.rs        # Kubernetes-style probes
└── storage/             # Data persistence abstraction
    ├── memory.rs        # In-memory storage
    └── postgres.rs      # PostgreSQL backend
```

### Technology Stack

- **Web Framework**: Axum 0.7 (async Rust)
- **Async Runtime**: Tokio
- **Authentication**: JWT, bcrypt, OAuth2, SAML
- **Database**: PostgreSQL (via sqlx), Redis
- **LDAP**: ldap3 with TLS support
- **Metrics**: Prometheus, OpenTelemetry
- **MFA**: TOTP (RFC 6238), QR codes
- **Cryptography**: RSA, ECDSA, X.509, PKCS#11
- **Serialization**: serde, serde_json, serde_yaml

### Standards Compliance

- **OAuth 2.0**: RFC 6749, RFC 7636 (PKCE)
- **OpenID Connect**: OIDC Core 1.0, OIDC Discovery 1.0
- **SAML 2.0**: SAML Core, SAML Bindings, Web Browser SSO Profile
- **JWT**: RFC 7519 (JWT), RFC 7517 (JWK)
- **Token Management**: RFC 7662 (Introspection), RFC 7009 (Revocation)
- **Device Flow**: RFC 8628
- **MFA**: RFC 6238 (TOTP)

## License

See [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Support

For issues, questions, or feature requests, please open an issue on GitHub.

## Roadmap

- [ ] WebAuthn/FIDO2 support
- [ ] Risk-based authentication
- [ ] Passwordless authentication
- [ ] Advanced fraud detection
- [ ] Multi-region deployment support
- [ ] GraphQL API
- [ ] Mobile SDK (iOS, Android)
- [ ] Admin dashboard UI
- [ ] Terraform/Helm charts
- [ ] High availability clustering

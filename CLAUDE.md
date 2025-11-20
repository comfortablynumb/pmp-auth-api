# PMP Auth API - Project Documentation

> Multi-tenant OAuth2 Authorization Server, OpenID Connect Provider, and SAML Identity Provider

## 📋 Table of Contents

- [Architecture Overview](#architecture-overview)
- [Complete Features](#complete-features)
- [Incomplete/Started Features](#incompletestarted-features)
- [Missing Features](#missing-features)
- [Development Guidelines](#development-guidelines)
- [Testing](#testing)

---

## Architecture Overview

This is a comprehensive authentication and authorization server supporting:
- **OAuth2** Authorization Server (RFC 6749)
- **OpenID Connect** Provider (OIDC Core, Discovery, Session Management)
- **SAML 2.0** Identity Provider
- **Multi-tenant** architecture with isolated configurations
- **Pluggable identity backends** (PostgreSQL, LDAP)
- **Storage backends** (PostgreSQL with Redis caching)

### Technology Stack
- **Language**: Rust (Edition 2021)
- **Web Framework**: Axum 0.7
- **Database**: PostgreSQL (via SQLx)
- **Cache**: Redis
- **Cryptography**: OpenSSL, jsonwebtoken
- **API Documentation**: OpenAPI/Swagger (utoipa)

---

## ✅ Complete Features

### OAuth2 Authorization Server (RFC 6749)

#### Grant Types
- ✅ **Authorization Code Flow** (RFC 6749 Section 4.1)
  - PKCE support (RFC 7636) - S256 and plain methods
  - Public and confidential clients
  - Code challenge validation
- ✅ **Implicit Flow** (RFC 6749 Section 4.2)
  - Token response type
  - ID token response type
  - Combined token + id_token
- ✅ **Hybrid Flow** (OIDC Core Section 3.3)
  - code + id_token
  - code + token
  - code + id_token + token
- ✅ **Resource Owner Password Credentials** (RFC 6749 Section 4.3)
- ✅ **Client Credentials** (RFC 6749 Section 4.4)
- ✅ **Refresh Token** (RFC 6749 Section 6)
- ✅ **Device Authorization Grant** (RFC 8628)
  - Device code flow
  - User verification endpoint
  - Polling endpoint with slow_down support
- ✅ **Token Exchange** (RFC 8693)
  - Subject token validation
  - Actor token support
  - Token type identifiers

#### Response Modes
- ✅ Query parameter mode (default for code flow)
- ✅ Fragment mode (default for implicit/hybrid)
- ✅ Form POST mode (RFC 6749 Section 4.2.1)

#### Client Authentication
- ✅ client_secret_post (POST body)
- ✅ client_secret_basic (HTTP Basic Auth)
- ✅ private_key_jwt (JWT assertion - RFC 7523)
- ✅ none (for public clients)

#### Token Management
- ✅ **Token Introspection** (RFC 7662)
  - Active status validation
  - Token metadata retrieval
- ✅ **Token Revocation** (RFC 7009)
  - Access token revocation
  - Refresh token revocation
- ✅ **JWKS Endpoint** (RFC 7517)
  - Multiple key support
  - Key rotation ready

#### Security Features
- ✅ **PKCE** (RFC 7636) - Required for public clients
- ✅ **State parameter** validation
- ✅ **Redirect URI** strict validation
- ✅ **Scope validation** against client allowed scopes
- ✅ **Session management** with expiration
- ✅ **Rate limiting** (Redis-backed)

#### Request Objects
- ✅ **Request Object Support** (RFC 9101)
  - Signed JWT request objects
  - JWK to PEM conversion (RSA, EC)
  - Request URI fetching
  - Request URI registration validation
  - Supported curves: P-256, P-384, P-521
  - x5c certificate support

#### Dynamic Client Registration
- ✅ **Client Registration** (RFC 7591)
  - Dynamic client creation
  - Client metadata management
  - Secret generation for confidential clients
- ✅ **Client Management** (RFC 7592)
  - Read client configuration
  - Update client metadata
  - Delete client registration

#### API Keys
- ✅ API key generation and management
- ✅ Key-based authentication for APIs
- ✅ Scoped API keys

---

### OAuth2 Federation (External Identity Providers)

#### Trait-based Provider System
- ✅ **Extensible Architecture**
  - FederationProvider trait for implementing new providers
  - Easy to add new providers (Azure AD, Okta, Auth0, etc.)
  - Stateless, thread-safe providers
  - Factory pattern for provider instantiation

#### Implemented Providers
- ✅ **Google OAuth2/OIDC**
  - OAuth2 authorization code flow
  - OIDC UserInfo endpoint integration
  - Email verification from trusted provider
  - Profile data synchronization
  - Refresh token support
- ✅ **GitHub OAuth2**
  - OAuth2 authorization code flow
  - User and email API integration
  - Private email fetching (user:email scope)
  - Profile data synchronization
  - Verified email handling

#### Federation Flow
- ✅ **Login Initiation** (`/tenant/:tenant_id/federate/:provider_id/login`)
  - State generation and storage (Redis)
  - CSRF protection via state parameter
  - Redirect to external provider
- ✅ **OAuth2 Callback** (`/tenant/:tenant_id/federate/:provider_id/callback`)
  - State validation
  - Authorization code exchange
  - User info retrieval
  - User creation or linking

#### User Management
- ✅ **Automatic User Creation**
  - Create new users from federated login
  - Password-less users (federated-only)
  - Profile data from provider
- ✅ **User Linking**
  - Link multiple providers to same user (via email)
  - Prevent duplicate users
  - Email-based user matching
- ✅ **Profile Synchronization**
  - Update user profile from provider
  - Email verification propagation
  - Last login tracking

#### Storage
- ✅ **Federated Identity Storage**
  - `federated_identities` table with indexes
  - PostgreSQL implementation
  - Memory storage implementation
  - Unique constraint: (tenant_id, provider_id, provider_user_id)
  - Foreign key to users table
- ✅ **User Data**
  - Link provider_user_id to internal user_id
  - Store provider profile data (JSON)
  - Track email verification status
  - Last login timestamps

#### Token Issuance
- ✅ **Our Tokens Only**
  - Always issues OUR access tokens (not provider tokens)
  - Consistent token format across all login methods
  - Unified session management
  - No provider token storage

#### Configuration
- ✅ **Per-Tenant Federation Providers**
  - Configure multiple providers per tenant
  - Provider-specific client credentials
  - Scope configuration
  - Endpoint override support

---

### OpenID Connect Provider

#### Core Features
- ✅ **OIDC Discovery** (RFC 8414)
  - `.well-known/openid-configuration`
  - Complete metadata advertisement
- ✅ **ID Token Generation**
  - Standard claims (iss, sub, aud, exp, iat, auth_time)
  - Nonce support for replay protection
  - Hash claims (at_hash, c_hash) for hybrid flows
  - ACR and AMR support
  - Profile, email, address, phone claims
- ✅ **UserInfo Endpoint** (OIDC Core Section 5.3)
  - JSON response (default)
  - Signed JWT response (via Accept: application/jwt)
  - Bearer token authentication

#### ID Token Encryption
- ✅ **JWE Support** (RFC 7516)
  - RSA-OAEP key encryption
  - AES-GCM content encryption (A128GCM, A192GCM, A256GCM)
  - AES-CBC-HMAC content encryption (A128CBC-HS256, A192CBC-HS384, A256CBC-HS512)
  - Proper HMAC computation per RFC 7518

#### Session Management
- ✅ **Session Management** (OIDC Session Management 1.0)
  - check_session_iframe endpoint
  - session_state parameter
  - Client-side session monitoring
- ✅ **Logout** (OIDC RP-Initiated Logout)
  - End session endpoint
  - ID token hint validation
  - Post-logout redirect

#### Logout Mechanisms
- ✅ **Back-Channel Logout** (RFC 8965)
  - Logout token generation
  - Session ID (sid) support
  - HTTP POST notifications to RPs
- ✅ **Front-Channel Logout** (OIDC Front-Channel Logout 1.0)
  - Iframe-based logout
  - Issuer and session ID propagation
  - Multi-RP logout coordination

#### Authentication Context
- ✅ prompt parameter (none, login, consent, select_account)
- ✅ max_age parameter validation
- ✅ acr_values support structure
- ✅ amr values in ID tokens

#### Claims
- ✅ Standard claims support:
  - sub, name, email, email_verified
  - picture, preferred_username
  - Custom claims via attributes
- ✅ Scope-based claim filtering

---

### SAML 2.0 Identity Provider

#### Protocols
- ✅ **SAML SSO** (Web Browser SSO Profile - SAML 2.0 Core)
  - HTTP-Redirect binding (deflate + base64)
  - HTTP-POST binding (base64 encoded)
  - SP-initiated SSO with AuthnRequest
  - Session-based user authentication
- ✅ **Single Logout (SLO)** (SAML 2.0 Profiles)
  - LogoutRequest parsing with NameID and SessionIndex
  - LogoutResponse generation
  - Session termination integration
- ✅ **Metadata Endpoint** (SAML 2.0 Metadata)
  - EntityDescriptor generation
  - IDPSSODescriptor with endpoints
  - KeyDescriptor with X.509 certificates
  - SingleSignOnService (POST and Redirect)
  - SingleLogoutService

#### Assertions & Security
- ✅ **Complete SAML Assertions**
  - Subject with NameID (multiple formats supported):
    - urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress
    - urn:oasis:names:tc:SAML:2.0:nameid-format:persistent (SHA256-based)
    - urn:oasis:names:tc:SAML:2.0:nameid-format:transient (UUID-based)
    - urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified
  - SubjectConfirmation (bearer method with recipient validation)
  - Conditions (time validity, audience restriction)
  - AuthnStatement with session index
  - AttributeStatement with custom attributes (email, uid)
- ✅ **XML Digital Signatures** (XML-DSig)
  - **Signature Generation**:
    - RSA-SHA256 signature algorithm
    - Enveloped signature transform
    - Exclusive XML canonicalization (exc-c14n)
    - SHA-256 digest method
    - X.509 certificate embedding in KeyInfo
  - **Signature Verification** (NEW):
    - Validates signatures on incoming AuthnRequests
    - Extracts and verifies SignedInfo element
    - Supports RSA-SHA256 verification
    - X.509 certificate-based public key extraction
    - Optional signature verification (configurable per SP)
- ✅ **Assertion Encryption** (NEW - XML Encryption)
  - AES-256-CBC for data encryption
  - RSA-OAEP for key encryption
  - EncryptedAssertion support
  - Encrypted key transport
  - Compatible with standard SAML tooling
- ✅ **Certificate Management**
  - PEM file loading for certificates
  - PEM file loading for private keys
  - Certificate data extraction and formatting
  - X.509 certificate parsing for encryption/signing

#### XML Processing
- ✅ **SAML Request Parsing** (quick-xml)
  - AuthnRequest parsing with namespace support
  - ID, Issuer, AssertionConsumerServiceURL extraction
  - LogoutRequest parsing
  - Error handling for malformed XML
- ✅ **SAML Response Generation**
  - Complete Response structure with InResponseTo
  - Base64 encoding for POST binding
  - Auto-submit HTML forms for transparent SSO

#### Authentication & Authorization
- ✅ Session validation with expiration checking
- ✅ User lookup via StorageBackend
- ✅ Audience restriction enforcement
- ✅ Time-bound assertions (5-minute validity window)

---

### Multi-Tenancy

- ✅ **Tenant Isolation**
  - Per-tenant OAuth2 configuration
  - Per-tenant OIDC configuration
  - Per-tenant SAML configuration
  - Separate signing keys per tenant
  - Isolated user databases
- ✅ **Tenant Management**
  - Dynamic tenant configuration
  - YAML-based configuration
  - Runtime tenant resolution

---

### Identity Backends

- ✅ **PostgreSQL Storage**
  - User CRUD operations
  - Session management
  - Authorization code storage
  - Refresh token storage
  - Client registration storage
  - Device code storage
- ✅ **Identity Storage Abstraction**
  - Pluggable backend architecture
  - StorageUser trait
  - IdentityStorageTrait for custom backends

---

### Security & Compliance

- ✅ **Cryptographic Operations**
  - RSA-256, ES-256 signing algorithms
  - Key management (loading from files or inline PEM)
  - JWT signing and validation
  - HMAC for symmetric operations
- ✅ **Security Headers**
  - CORS configuration
  - Content Security Policy
  - X-Frame-Options
  - X-Content-Type-Options
- ✅ **Password Security**
  - bcrypt hashing
  - Configurable cost factor
- ✅ **MFA/2FA**
  - TOTP support (totp-lite)
  - QR code generation
  - Backup codes

---

### Observability

- ✅ **Metrics** (Prometheus)
  - Request counters
  - Latency histograms
  - Custom metrics
- ✅ **Tracing** (OpenTelemetry)
  - Distributed tracing
  - OTLP export
  - Trace context propagation
- ✅ **Logging** (tracing-subscriber)
  - Structured logging
  - Log levels
  - Environment-based filtering

---

### API Documentation

- ✅ **OpenAPI/Swagger** (utoipa)
  - Complete API documentation
  - Swagger UI endpoint
  - Schema generation
  - Request/response examples

---

## ⚠️ Incomplete/Started Features

### LDAP Identity Backend

**Status**: Interface defined but implementation incomplete

**Location**: `src/auth/identity_storage.rs`

**Missing**:
- ❌ LDAP bind authentication (line 109) - TODO marker
- ❌ LDAP user lookup (line 114) - TODO marker
- ❌ LDAP email lookup (line 119) - TODO marker
- ❌ LDAP user validation (line 124) - TODO marker

**What exists**:
- ✅ LDAP dependency (ldap3 crate)
- ✅ LdapIdentityStorage struct
- ✅ IdentityStorageTrait implementation skeleton

**Next Steps**:
1. Implement LDAP connection pooling
2. Add LDAP search queries for user lookup
3. Implement LDAP bind for authentication
4. Add attribute mapping from LDAP to StorageUser
5. Handle LDAP errors and connection failures

---

### Session Management

**Status**: Basic implementation, needs enhancement

**What's Missing**:
- ❌ Session ID (sid) extraction from OIDC claims (oauth2_server.rs:1252)
- ❌ Proper WebCrypto API for session state hashing (currently using placeholder)
- ❌ Session persistence across application restarts
- ❌ Distributed session management for multi-instance deployments

**Next Steps**:
1. Extract and store sid in authorization codes and tokens
2. Implement proper SHA-256 using WebCrypto in check_session_iframe
3. Add Redis-based session storage for distributed deployments
4. Implement session cleanup/garbage collection

---

### Client Registration

**Status**: Mostly complete, minor TODO

**Missing**:
- ❌ Multiple key support and key selection (client_registration.rs:598)
  - Currently only uses first key from JWKS

**Next Steps**:
1. Implement key rotation support
2. Add kid (Key ID) based key selection
3. Support multiple concurrent keys for graceful rotation

---

## ❌ Missing Features

### OAuth2 Missing Features

#### Pushed Authorization Requests (PAR)
- **RFC**: RFC 9126
- **Description**: Allows clients to push authorization parameters via POST before redirecting user
- **Priority**: Medium
- **Benefits**:
  - Reduces URL length issues
  - Enhances security by keeping parameters server-side
  - Prevents parameter tampering
- **Implementation Scope**:
  - Add POST /oauth/par endpoint
  - Return request_uri for subsequent authorization request
  - Store PAR data with short expiration
  - Validate request_uri in authorization endpoint

#### DPoP (Demonstrating Proof-of-Possession)
- **RFC**: RFC 9449
- **Description**: Cryptographically binds tokens to specific clients
- **Priority**: High (Security)
- **Benefits**:
  - Prevents token theft/replay
  - Token binding to client
  - Enhanced security for public clients
- **Implementation Scope**:
  - DPoP proof validation in token endpoint
  - DPoP header processing
  - cnf claim in access tokens
  - DPoP nonce management

#### JWT Secured Authorization Response Mode (JARM)
- **RFC**: RFC 9101 (related)
- **Description**: Return authorization response as signed/encrypted JWT
- **Priority**: Low
- **Benefits**: Enhanced security for authorization responses

#### Resource Indicators
- **RFC**: RFC 8707
- **Description**: Specify target resource servers in authorization request
- **Priority**: Medium
- **Benefits**: Audience restriction for tokens

---

### OpenID Connect Missing Features

#### Client-Initiated Backchannel Authentication (CIBA)
- **RFC**: OpenID Connect CIBA Core 1.0
- **Description**: Decoupled authentication where client initiates auth without redirect
- **Priority**: Medium
- **Use Cases**:
  - Mobile push notifications
  - Out-of-band authentication
  - Decoupled flows
- **Implementation Scope**:
  - Backchannel authentication endpoint
  - Authentication request validation
  - Async notification to user device
  - Token endpoint poll mode support
  - Push/ping callback modes

#### Pairwise Subject Identifiers
- **RFC**: OIDC Core Section 8
- **Description**: Different sub values per client for same user (privacy)
- **Priority**: Medium
- **Current**: Only "public" subject type supported
- **Benefits**:
  - Enhanced user privacy
  - Prevent cross-site correlation
- **Implementation Scope**:
  - subject_types_supported: ["public", "pairwise"]
  - Per-client subject identifier generation
  - Sector identifier validation
  - Subject identifier mapping storage

#### Claims Parameter Support
- **RFC**: OIDC Core Section 5.5
- **Description**: Request specific claims via claims parameter
- **Priority**: Low
- **Current**: claims_parameter_supported: false
- **Implementation Scope**:
  - Parse claims JSON parameter
  - Filter claims based on request
  - Implement essential/voluntary logic
  - Return requested claims in ID token/UserInfo

#### UserInfo Encryption
- **Status**: Signing supported, encryption missing
- **Description**: Encrypt UserInfo responses (similar to ID token encryption)
- **Priority**: Low

#### ACR (Authentication Context Class Reference)
- **Status**: Structure exists, no implementation
- **Current**: acr_values_supported: []
- **Description**: Specify authentication strength/methods
- **Priority**: Low
- **Implementation Scope**:
  - Define ACR values (password, mfa, etc.)
  - Implement authentication strength checking
  - Return acr claim in ID token
  - Validate acr_values in authorization request

---

### SAML Missing Features

#### Core SAML Functionality
- **Artifact Binding**: Not implemented
  - Would require artifact storage backend
  - SOAP binding implementation
  - Artifact resolution service endpoint
- **SOAP Binding**: Not implemented
- **Attribute Query**: Not implemented
- **Enhanced Client Proxy (ECP)**: Not implemented
- **Enhanced Attribute Mapping**: Basic implementation
  - Currently only maps email and uid attributes
  - Could be enhanced with configurable attribute mapping from user profiles

---

### Federation & Interoperability

#### SAML Federation
- **Description**: Act as SAML SP to consume assertions from external IdPs
- **Priority**: Medium
- **Use Cases**: Enterprise SSO integration

---

### Advanced Features

#### Step-Up Authentication
- **Description**: Request additional authentication for sensitive operations
- **Priority**: Medium
- **Use Cases**: Financial transactions, admin operations

#### Continuous Authentication
- **Description**: Ongoing authentication verification
- **Priority**: Low

#### Universal Second Factor (U2F/WebAuthn)
- **Description**: Hardware token support
- **Priority**: Medium
- **Benefits**: Phishing-resistant authentication

#### Risk-Based Authentication
- **Description**: Adaptive authentication based on risk signals
- **Priority**: Low
- **Scope**: Device fingerprinting, IP reputation, behavioral analysis

---

## Development Guidelines

### Code Style
- Follow Rust standard conventions (rustfmt)
- Use meaningful variable names
- Add documentation comments for public APIs
- Keep functions focused and small

### New Feature Development
1. Create feature branch from main
2. Implement feature with tests
3. Update this CLAUDE.md file
4. Add OpenAPI documentation
5. Create pull request with description

### File Organization
```
src/
├── auth/              # Authentication & authorization modules
│   ├── oauth2_server.rs      # OAuth2 core
│   ├── oidc.rs              # OpenID Connect
│   ├── saml.rs              # SAML provider
│   ├── device_flow.rs       # Device authorization
│   ├── token_exchange.rs    # Token exchange
│   ├── token_introspection.rs
│   ├── client_registration.rs
│   ├── backchannel_logout.rs
│   ├── frontchannel_logout.rs
│   ├── request_object.rs    # RFC 9101
│   ├── id_token_encryption.rs
│   ├── identity_storage.rs  # Identity backend abstraction
│   └── federation/          # OAuth2 Federation (external providers)
│       ├── mod.rs           # Trait and endpoints
│       ├── types.rs         # Common types
│       └── providers/       # Provider implementations
│           ├── google.rs    # Google OAuth2/OIDC
│           └── github.rs    # GitHub OAuth2
├── models/            # Data models and configuration
├── storage/           # Storage backends (PostgreSQL, Redis)
├── handlers/          # HTTP request handlers
├── middleware/        # Security headers, rate limiting
├── admin/             # Admin endpoints
├── ldap/              # LDAP backend
└── config/            # Configuration management
```

### Adding New OAuth2/OIDC Features

1. **Add to spec compliance**:
   - Update `oidc_discovery()` metadata
   - Add new endpoints to routing
   - Implement RFC-compliant logic

2. **Storage layer**:
   - Add database migrations if needed
   - Update storage traits
   - Implement PostgreSQL queries

3. **Security review**:
   - Check for injection vulnerabilities
   - Validate all inputs
   - Use parameterized queries
   - Test with security tools

4. **Testing**:
   - Unit tests for business logic
   - Integration tests for endpoints
   - Test error cases
   - Test edge cases (expired tokens, invalid signatures, etc.)

---

## Testing

### Unit Tests
```bash
# Run all tests
cargo test

# Run specific module tests
cargo test --lib auth::oidc

# Run with output
cargo test -- --nocapture
```

### Integration Tests
```bash
# Run integration tests
cargo test --test '*'

# Specific integration test
cargo test --test multi_tenant_integration_test
```

### Manual Testing with cURL

#### Authorization Code Flow
```bash
# 1. Get authorization code
curl "http://localhost:3000/api/v1/tenant/default/oauth/authorize?response_type=code&client_id=test-client&redirect_uri=http://localhost:8080/callback&scope=openid%20profile%20email&state=random123&session_id=<session>"

# 2. Exchange code for tokens
curl -X POST http://localhost:3000/api/v1/tenant/default/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code=<code>&redirect_uri=http://localhost:8080/callback&client_id=test-client&client_secret=secret"
```

#### Device Flow
```bash
# 1. Start device flow
curl -X POST http://localhost:3000/api/v1/tenant/default/oauth/device/authorize \
  -H "Content-Type: application/json" \
  -d '{"client_id":"test-client","scope":"openid profile"}'

# 2. User verification (browser)
# Visit verification_uri and enter user_code

# 3. Poll for token
curl -X POST http://localhost:3000/api/v1/tenant/default/oauth/device/token \
  -H "Content-Type: application/json" \
  -d '{"grant_type":"urn:ietf:params:oauth:grant-type:device_code","device_code":"<device_code>","client_id":"test-client"}'
```

#### Token Introspection
```bash
curl -X POST http://localhost:3000/api/v1/tenant/default/oauth/introspect \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=<access_token>&client_id=test-client&client_secret=secret"
```

#### UserInfo
```bash
curl http://localhost:3000/api/v1/tenant/default/oauth/userinfo \
  -H "Authorization: Bearer <access_token>"
```

#### OAuth2 Federation (Login with Google/GitHub)
```bash
# 1. Initiate federation login
curl "http://localhost:3000/api/v1/tenant/default/federate/google/login?redirect_uri=http://localhost:8080/callback"
# -> Redirects to Google

# 2. After Google auth, callback returns tokens:
# -> http://localhost:8080/callback#access_token=...&id_token=...&refresh_token=...

# 3. Use the tokens to access protected resources
curl -H "Authorization: Bearer <access_token>" \
     http://localhost:3000/api/v1/tenant/default/oauth/userinfo
```

### Unit Tests

#### Federation Tests
```bash
# Run federation-specific tests
cargo test federation

# Run federation integration tests
cargo test --test federation_integration_test

# Run with output
cargo test federation -- --nocapture
```

Test coverage includes:
- Provider creation and configuration (Google, GitHub)
- User creation from federated authentication
- User linking across multiple providers
- Email verification propagation
- Profile data synchronization
- Last login tracking
- Storage operations for federated identities

### Load Testing
```bash
# Using Apache Bench
ab -n 1000 -c 10 http://localhost:3000/api/v1/tenant/default/.well-known/openid-configuration

# Using hey
hey -n 1000 -c 10 http://localhost:3000/_/health
```

---

## Configuration

### Environment Variables
```bash
# Database
DATABASE_URL=postgres://user:pass@localhost/pmp_auth
REDIS_URL=redis://localhost:6379

# Server
HOST=0.0.0.0
PORT=3000

# Logging
RUST_LOG=info,pmp_auth_api=debug

# Metrics
METRICS_ENABLED=true
OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317
```

### Tenant Configuration
See `config/config.example.yaml` for multi-tenant setup examples.

---

## Security Considerations

### Production Checklist
- [ ] Use HTTPS only (TLS 1.2+)
- [ ] Rotate signing keys regularly
- [ ] Enable rate limiting
- [ ] Configure CORS properly
- [ ] Set secure cookie flags
- [ ] Enable security headers
- [ ] Review audit logs
- [ ] Implement monitoring and alerting
- [ ] Use strong client secrets (min 32 chars)
- [ ] Validate all redirect URIs
- [ ] Implement brute force protection
- [ ] Enable MFA for admin accounts
- [ ] Regular security audits
- [ ] Keep dependencies updated

### Common Vulnerabilities Prevented
- ✅ Authorization code interception (PKCE)
- ✅ Token theft (short-lived tokens, rotation)
- ✅ Open redirect (strict URI validation)
- ✅ CSRF (state parameter)
- ✅ Session fixation (secure session management)
- ✅ Clickjacking (X-Frame-Options)
- ✅ XSS (Content Security Policy)
- ⚠️ Token replay (DPoP not implemented yet)

---

## Performance Optimization

### Current Optimizations
- Redis caching for frequent lookups
- Database connection pooling
- Async/await throughout
- Compiled with release optimizations (LTO, codegen-units=1)

### Scalability
- Stateless design (sessions in Redis)
- Horizontal scaling ready
- Database read replicas supported
- Load balancer compatible

---

## Monitoring & Alerting

### Key Metrics to Monitor
- Token issuance rate
- Failed authentication attempts
- Token validation errors
- Response times (p50, p95, p99)
- Database query times
- Redis cache hit rate
- Error rates by endpoint

### Health Checks
- `GET /_/health` - Basic health check
- `GET /_/metrics` - Prometheus metrics

---

## Contributing

### Priority Features for Contributors
1. **High Priority**:
   - DPoP implementation (RFC 9449)
   - LDAP backend completion

2. **Medium Priority**:
   - PAR (RFC 9126)
   - Pairwise subject identifiers
   - CIBA flow
   - Additional federation providers (Azure AD, Okta, Auth0)
   - SAML Artifact binding

3. **Low Priority**:
   - Claims parameter support
   - ACR implementation
   - Enhanced SAML attribute mapping

---

## License & Compliance

### RFC Compliance Status
- ✅ RFC 6749 - OAuth 2.0 Authorization Framework
- ✅ RFC 7009 - Token Revocation
- ✅ RFC 7517 - JSON Web Key (JWK)
- ✅ RFC 7518 - JSON Web Algorithms (JWA)
- ✅ RFC 7519 - JSON Web Token (JWT)
- ✅ RFC 7523 - JWT Profile for OAuth 2.0 Client Authentication
- ✅ RFC 7591 - OAuth 2.0 Dynamic Client Registration
- ✅ RFC 7592 - OAuth 2.0 Dynamic Client Registration Management
- ✅ RFC 7636 - PKCE
- ✅ RFC 7662 - Token Introspection
- ✅ RFC 8414 - OAuth 2.0 Authorization Server Metadata
- ✅ RFC 8628 - Device Authorization Grant
- ✅ RFC 8693 - Token Exchange
- ✅ RFC 8965 - Back-Channel Logout
- ✅ RFC 9101 - Request Object (JAR)
- ⚠️ RFC 9126 - PAR (Not implemented)
- ⚠️ RFC 9449 - DPoP (Not implemented)

### OpenID Connect Compliance
- ✅ OpenID Connect Core 1.0
- ✅ OpenID Connect Discovery 1.0
- ✅ OpenID Connect Session Management 1.0
- ✅ OpenID Connect Front-Channel Logout 1.0
- ✅ OpenID Connect Back-Channel Logout 1.0
- ⚠️ OpenID Connect CIBA (Not implemented)

### SAML Compliance
- ✅ SAML 2.0 Core (Complete Web Browser SSO Profile)
- ✅ SAML 2.0 Bindings (HTTP-POST, HTTP-Redirect)
- ✅ SAML 2.0 Profiles (Web Browser SSO Profile)
- ✅ XML Digital Signatures (XML-DSig)
- ✅ XML Encryption (XML-Enc)

---

## Version History

### Current Version: 0.1.0

#### Recent Additions
- ✅ Complete Request Object (RFC 9101) with full JWK to PEM conversion
- ✅ Complete ID Token Encryption (AES-CBC-HMAC algorithms)
- ✅ Front-Channel Logout implementation
- ✅ Verified Hybrid & Implicit flows
- ✅ OAuth2 Federation (Google and GitHub providers) with extensible trait system
- ✅ Advanced SAML features:
  - XML signature verification for incoming AuthnRequests (RSA-SHA256)
  - Multiple NameID formats (email, persistent, transient, unspecified)
  - Assertion encryption (AES-256-CBC + RSA-OAEP)
  - Complete Web Browser SSO Profile implementation

#### Known Issues
- LDAP backend stubbed
- DPoP not implemented
- PAR not implemented
- SAML Artifact binding not implemented

---

## Support & Documentation

- **API Documentation**: `/swagger-ui/` when running
- **Issue Tracker**: GitHub Issues
- **Discussion**: GitHub Discussions

---

**Last Updated**: 2025-11-20
**Maintained By**: Development Team

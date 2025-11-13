# PMP Auth API Examples

Welcome to the examples directory! This contains practical, runnable examples demonstrating all major authentication flows supported by the PMP Auth API.

## 📚 Available Examples

### 1. [OAuth2 Client Credentials Flow](01-oauth2-client-credentials.md)
**Difficulty:** ⭐ Easy
**Use Case:** Machine-to-machine authentication

Learn how to authenticate server-to-server without user interaction. Perfect for:
- Backend services
- Microservices
- Automated scripts
- CI/CD pipelines

**Key concepts:** Client credentials, access tokens, scopes

---

### 2. [OAuth2 Authorization Code Flow](02-oauth2-authorization-code.md)
**Difficulty:** ⭐⭐ Moderate
**Use Case:** User authentication for web applications

Learn the standard OAuth2 flow for web applications with user login. Perfect for:
- Web applications
- Single Page Applications (SPAs)
- Mobile apps with backends
- Any app requiring user authentication

**Key concepts:** Authorization codes, redirect URIs, PKCE, state parameter, refresh tokens

---

### 3. [OpenID Connect (OIDC)](03-openid-connect.md)
**Difficulty:** ⭐⭐ Moderate
**Use Case:** User identity and Single Sign-On

Learn how to get standardized user identity information. Perfect for:
- SSO implementations
- Applications needing user profile data
- Multi-application environments
- Modern authentication flows

**Key concepts:** ID tokens, UserInfo endpoint, OIDC Discovery, claims, scopes

---

### 4. [API Key Management](04-api-key-management.md)
**Difficulty:** ⭐ Easy
**Use Case:** Long-lived authentication tokens

Learn how to create and manage API keys for persistent access. Perfect for:
- CI/CD pipelines
- Third-party integrations
- CLI tools
- Monitoring systems
- Background jobs

**Key concepts:** Long-lived JWTs, revocation, scopes, key rotation

---

### 5. [SAML 2.0 Single Sign-On](05-saml-sso.md)
**Difficulty:** ⭐⭐⭐ Advanced
**Use Case:** Enterprise Single Sign-On

Learn how to integrate with SAML Service Providers for enterprise SSO. Perfect for:
- Enterprise B2B integrations
- Corporate SSO solutions
- Legacy enterprise applications
- Compliance requirements

**Key concepts:** SAML metadata, assertions, XML signatures, IdP/SP, SLO

---

## 🚀 Quick Start

### Prerequisites

1. **Start the API server:**
   ```bash
   cd /path/to/pmp-auth-api
   cargo run
   ```
   Server will start on `http://localhost:3000`

2. **Verify server is running:**
   ```bash
   curl http://localhost:3000/health
   ```

3. **Check your tenant configuration:**
   ```bash
   curl http://localhost:3000/api/v1/tenant/test-tenant/strategies
   ```

### Required Tools

Install these tools for the best experience:

```bash
# JSON processor (required)
# macOS: brew install jq
# Ubuntu/Debian: apt-get install jq

# JWT decoder (optional but recommended)
cargo install jwt-cli

# XML processor (for SAML examples)
# macOS: brew install xmlstarlet
# Ubuntu/Debian: apt-get install xmlstarlet
```

## 📖 Learning Path

### Beginner Path
Start here if you're new to authentication:

1. **[API Key Management](04-api-key-management.md)** - Simplest to understand
2. **[OAuth2 Client Credentials](01-oauth2-client-credentials.md)** - Basic OAuth2
3. **[OAuth2 Authorization Code](02-oauth2-authorization-code.md)** - User authentication

### Intermediate Path
For those familiar with OAuth2 basics:

1. **[OAuth2 Authorization Code](02-oauth2-authorization-code.md)** - Review fundamentals
2. **[OpenID Connect](03-openid-connect.md)** - Add identity layer
3. **[API Key Management](04-api-key-management.md)** - Alternative approach

### Enterprise Path
For enterprise integration projects:

1. **[SAML SSO](05-saml-sso.md)** - Enterprise standard
2. **[OpenID Connect](03-openid-connect.md)** - Modern alternative
3. **[OAuth2 Authorization Code](02-oauth2-authorization-code.md)** - Foundation

## 🎯 Use Case Selection Guide

Choose the right authentication method for your use case:

```
┌────────────────────────────────────────────────────────────────┐
│                    Authentication Decision Tree                 │
└────────────────────────────────────────────────────────────────┘

Is there a human user involved?
├─ NO  → Machine-to-Machine
│        ├─ Need revocation? → [API Keys]
│        └─ Dynamic access?  → [OAuth2 Client Credentials]
│
└─ YES → User Authentication
         ├─ Enterprise/B2B?
         │   ├─ SAML required? → [SAML SSO]
         │   └─ Modern tech?   → [OpenID Connect]
         │
         └─ Consumer/B2C?
             ├─ Need user info? → [OpenID Connect]
             └─ Just authz?     → [OAuth2 Authorization Code]
```

### Quick Reference Table

| Use Case | Recommended Flow | Example |
|----------|-----------------|---------|
| Backend API to API | OAuth2 Client Credentials | [Example 1](01-oauth2-client-credentials.md) |
| Web app user login | OAuth2 Authorization Code | [Example 2](02-oauth2-authorization-code.md) |
| User profile/SSO | OpenID Connect | [Example 3](03-openid-connect.md) |
| CI/CD automation | API Keys | [Example 4](04-api-key-management.md) |
| Enterprise SSO | SAML 2.0 | [Example 5](05-saml-sso.md) |
| Mobile app | OAuth2 Authorization Code + PKCE | [Example 2](02-oauth2-authorization-code.md) |
| CLI tool | API Keys or Device Flow | [Example 4](04-api-key-management.md) |
| Third-party integration | API Keys | [Example 4](04-api-key-management.md) |

## 💡 Common Scenarios

### Scenario 1: Web Application with User Login

**Goal:** Users log in with their credentials, access their profile

**Solution:**
1. Start with [OAuth2 Authorization Code](02-oauth2-authorization-code.md)
2. Add [OpenID Connect](03-openid-connect.md) for user identity
3. Implement refresh token rotation for security

### Scenario 2: Microservices Communication

**Goal:** Service A needs to call Service B securely

**Solution:**
1. Use [OAuth2 Client Credentials](01-oauth2-client-credentials.md)
2. Each service has its own client ID/secret
3. Scopes limit what each service can do

### Scenario 3: Mobile App Authentication

**Goal:** Mobile app authenticates users securely

**Solution:**
1. Use [OAuth2 Authorization Code with PKCE](02-oauth2-authorization-code.md)
2. Never store client secret in the app
3. Use PKCE to prevent interception attacks

### Scenario 4: Enterprise Customer Integration

**Goal:** Large customer wants SSO for their employees

**Solution:**
1. Use [SAML SSO](05-saml-sso.md) for enterprise customers
2. Offer [OpenID Connect](03-openid-connect.md) as modern alternative
3. Provide metadata for easy configuration

### Scenario 5: Automated Testing & CI/CD

**Goal:** Tests need API access without manual authentication

**Solution:**
1. Create [API Keys](04-api-key-management.md) for test environments
2. Use different keys for staging/production
3. Rotate keys regularly
4. Store in secrets manager (GitHub Secrets, AWS Secrets Manager, etc.)

## 🔧 Testing Tools

### cURL
All examples use cURL for maximum portability:
```bash
curl -X POST http://localhost:3000/api/v1/tenant/test-tenant/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=xxx&client_secret=yyy"
```

### Postman Collection
Import into Postman for interactive testing:
```bash
# Export from cURL examples
# Or use Postman's built-in OAuth2/OIDC support
```

### JWT Decoder
Inspect JWT tokens:
```bash
# Install
cargo install jwt-cli

# Decode
echo "eyJhbG..." | jwt decode -

# Verify signature
jwt decode --secret "your-secret" "eyJhbG..."
```

### SAML Tools
Validate SAML responses:
- Online: https://www.samltool.com/
- Browser: SAML Tracer extension
- CLI: xmllint, xmlsec1

## 🛡️ Security Best Practices

### General Principles

1. **Always use HTTPS in production**
   ```bash
   # Development (OK)
   http://localhost:3000

   # Production (Required)
   https://auth.example.com
   ```

2. **Never commit secrets to version control**
   ```bash
   # Use environment variables
   export CLIENT_SECRET="secret-value"

   # Or use .env files (gitignored)
   echo "CLIENT_SECRET=secret-value" > .env
   echo ".env" >> .gitignore
   ```

3. **Implement proper token storage**
   - Frontend: httpOnly cookies or secure storage
   - Backend: Environment variables or secrets manager
   - Mobile: Secure keychain/keystore

4. **Validate everything**
   - Verify signatures on JWTs
   - Check token expiration
   - Validate redirect URIs
   - Verify SAML signatures

### Flow-Specific Security

**OAuth2/OIDC:**
- Always use `state` parameter (CSRF protection)
- Implement PKCE for public clients
- Validate redirect URIs
- Use nonce for replay protection

**API Keys:**
- Rotate regularly (90-180 days)
- Use minimal scopes
- Monitor usage
- Revoke immediately if compromised

**SAML:**
- Validate XML signatures
- Check assertion expiration
- Verify audience restriction
- Use secure bindings (POST over Redirect)

## 📝 Example Scripts

Each example includes complete bash scripts you can run:

```bash
# OAuth2 Client Credentials
./oauth2-client-credentials.sh

# OAuth2 Authorization Code
./oauth2-authorization-code.sh

# OpenID Connect
./oidc-flow.sh

# API Key Lifecycle
./api-key-lifecycle.sh

# SAML SSO Test
./saml-test.sh
```

## 🐛 Troubleshooting

### Common Issues

**Issue: "connection refused"**
```bash
# Check if server is running
curl http://localhost:3000/health

# Start server if needed
cd /path/to/pmp-auth-api && cargo run
```

**Issue: "tenant not found"**
```bash
# Check tenant configuration
cat config.yaml

# Verify tenant ID in URL matches config
curl http://localhost:3000/api/v1/tenant/YOUR-TENANT-ID/strategies
```

**Issue: "invalid_client"**
```bash
# Verify client credentials
# Check client_id and client_secret match configuration
# Ensure client is registered for this tenant
```

**Issue: JWT decode fails**
```bash
# Install jwt-cli
cargo install jwt-cli

# Or use online tool
# https://jwt.io
```

**Issue: SAML signature validation fails**
```bash
# Ensure SP has correct certificate from IdP metadata
# Check certificate hasn't expired
# Verify response hasn't been modified
```

## 🔗 Additional Resources

### Documentation
- [Main README](../README.md) - Project overview
- [Configuration Guide](../config.example.yaml) - Tenant configuration
- [API Reference](../README.md#api-endpoints) - Complete endpoint documentation

### Standards & Specifications
- [OAuth 2.0 (RFC 6749)](https://tools.ietf.org/html/rfc6749)
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [JWT (RFC 7519)](https://tools.ietf.org/html/rfc7519)
- [SAML 2.0 Core](http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf)

### External Tools
- [jwt.io](https://jwt.io) - JWT decoder
- [SAML Tool](https://www.samltool.com/) - SAML validator
- [OAuth Playground](https://www.oauth.com/playground/) - OAuth2 testing

## 🤝 Contributing

Found an issue or have a suggestion for a new example?

1. Check existing examples for similar content
2. Create a new markdown file following the template
3. Include complete curl commands
4. Add troubleshooting section
5. Update this README

## 📄 License

See [LICENSE](../LICENSE) file for details.

---

**Ready to start?** Pick an example above and dive in! 🚀

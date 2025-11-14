# Docker Development Environment

This guide explains how to run the PMP Auth API in a complete Docker environment with all services.

## 🚀 Quick Start

### 1. Generate RSA Keys

First, generate RSA keys for JWT signing:

```bash
# Create keys directory
mkdir -p keys

# Generate private key
openssl genrsa -out keys/demo-private.pem 2048

# Extract public key
openssl rsa -in keys/demo-private.pem -pubout -out keys/demo-public.pem
```

### 2. Start All Services

```bash
# Build and start all services
docker-compose up -d

# View logs
docker-compose logs -f pmp-auth-api

# Check service health
docker-compose ps
```

### 3. Access Services

Once running, you can access:

| Service | URL | Credentials |
|---------|-----|-------------|
| **Auth API** | http://localhost:3000 | - |
| **API Health** | http://localhost:3000/health | - |
| **API Metrics** | http://localhost:3000/metrics | - |
| **Swagger/OpenAPI** | http://localhost:3000/docs | - |
| **phpLDAPadmin** | http://localhost:8080 | Login DN: `cn=admin,dc=example,dc=com`<br>Password: `admin_password` |
| **Prometheus** | http://localhost:9090 | - |
| **Grafana** | http://localhost:3001 | User: `admin`<br>Password: `admin` |
| **Mailhog UI** | http://localhost:8025 | - |
| **PostgreSQL** | localhost:5432 | User: `pmp_user`<br>Password: `pmp_password`<br>DB: `pmp_auth` |
| **Redis** | localhost:6379 | - |

## 📦 What's Included

The Docker Compose environment includes:

### Core Services
- **pmp-auth-api**: The main authentication API server
- **PostgreSQL**: Database for OAuth2 tokens, sessions, and audit logs
- **Redis**: Caching and rate limiting backend

### Testing Services
- **OpenLDAP**: LDAP server for testing LDAP authentication
- **phpLDAPadmin**: Web UI for managing LDAP entries
- **Mailhog**: Email testing server (SMTP + web UI)

### Monitoring
- **Prometheus**: Metrics collection
- **Grafana**: Metrics visualization and dashboards

## 🧪 Testing the API

### Test with Mock Backend

The `demo-mock` tenant uses an in-memory backend for quick testing:

```bash
# Test authentication (password: password123)
curl -X POST http://localhost:3000/demo-mock/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "username=testuser" \
  -d "password=password123" \
  -d "client_id=test-app" \
  -d "client_secret=demo-secret"
```

### Test with LDAP Backend

The `demo-ldap` tenant uses OpenLDAP:

```bash
# Available LDAP users:
# - admin / password123 (admin role)
# - jdoe / password123 (developer, user)
# - asmith / password123 (user)

curl -X POST http://localhost:3000/demo-ldap/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "username=jdoe" \
  -d "password=password123" \
  -d "client_id=demo-client" \
  -d "client_secret=demo-secret"
```

### Test OAuth2 Authorization Code Flow

```bash
# 1. Get authorization code (open in browser)
http://localhost:3000/demo-mock/oauth/authorize?response_type=code&client_id=test-app&redirect_uri=http://localhost:8080/callback&scope=openid+profile+email

# 2. After login, exchange code for token
curl -X POST http://localhost:3000/demo-mock/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=<CODE_FROM_REDIRECT>" \
  -d "client_id=test-app" \
  -d "client_secret=demo-secret" \
  -d "redirect_uri=http://localhost:8080/callback"
```

### Test OIDC Discovery

```bash
# Get OIDC configuration
curl http://localhost:3000/demo-mock/.well-known/openid-configuration

# Get JWKS (public keys)
curl http://localhost:3000/demo-mock/.well-known/jwks.json
```

### Test API Key Management

```bash
# Create an API key
curl -X POST http://localhost:3000/demo-mock/api-keys \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <ACCESS_TOKEN>" \
  -d '{
    "name": "Test API Key",
    "scopes": ["read", "write"],
    "expires_in_days": 90
  }'

# List API keys
curl http://localhost:3000/demo-mock/api-keys \
  -H "Authorization: Bearer <ACCESS_TOKEN>"

# Use API key
curl http://localhost:3000/demo-mock/oauth/userinfo \
  -H "Authorization: Bearer <API_KEY>"
```

### Test Device Flow

```bash
# 1. Initiate device flow
curl -X POST http://localhost:3000/demo-mock/oauth/device/authorize \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=test-app"

# Response includes:
# - device_code: for polling
# - user_code: for user to enter
# - verification_uri: where user enters code

# 2. User visits verification_uri and enters user_code

# 3. Poll for token
curl -X POST http://localhost:3000/demo-mock/oauth/device/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:device_code" \
  -d "device_code=<DEVICE_CODE>" \
  -d "client_id=test-app"
```

## 🔧 Development Workflow

### Rebuild After Code Changes

```bash
# Rebuild and restart the API
docker-compose up -d --build pmp-auth-api

# Or restart everything
docker-compose down
docker-compose up -d --build
```

### View Logs

```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f pmp-auth-api
docker-compose logs -f postgres
docker-compose logs -f redis

# Last 100 lines
docker-compose logs --tail=100 pmp-auth-api
```

### Database Operations

```bash
# Connect to PostgreSQL
docker-compose exec postgres psql -U pmp_user -d pmp_auth

# Run SQL commands
docker-compose exec postgres psql -U pmp_user -d pmp_auth -c "SELECT * FROM oauth2_clients;"

# Reset database
docker-compose down -v  # Remove volumes
docker-compose up -d    # Recreate with fresh data
```

### Redis Operations

```bash
# Connect to Redis CLI
docker-compose exec redis redis-cli

# Check keys
docker-compose exec redis redis-cli KEYS '*'

# Clear all data
docker-compose exec redis redis-cli FLUSHALL
```

### LDAP Operations

```bash
# Search users
docker-compose exec openldap ldapsearch -x -H ldap://localhost \
  -D "cn=admin,dc=example,dc=com" \
  -w admin_password \
  -b "dc=example,dc=com" \
  "(objectClass=person)"

# Add a user (create user.ldif first)
docker-compose exec openldap ldapadd -x -H ldap://localhost \
  -D "cn=admin,dc=example,dc=com" \
  -w admin_password \
  -f /tmp/user.ldif
```

## 📊 Monitoring

### Prometheus Queries

Visit http://localhost:9090 and try these queries:

```promql
# Request rate
rate(http_requests_total[5m])

# Token issuance rate
rate(tokens_issued_total[5m])

# Authentication success rate
rate(auth_success_total[5m]) / rate(auth_attempts_total[5m])

# Error rate
rate(errors_total[5m])

# P95 latency
histogram_quantile(0.95, rate(request_duration_seconds_bucket[5m]))
```

### Grafana Dashboards

1. Login to http://localhost:3001 (admin/admin)
2. Create dashboards with Prometheus metrics
3. Example panels:
   - Authentication requests per second
   - Token issuance trends
   - Error rates by type
   - Latency percentiles
   - Active sessions

## 🛠️ Troubleshooting

### Service Won't Start

```bash
# Check logs
docker-compose logs <service-name>

# Check resource usage
docker stats

# Restart service
docker-compose restart <service-name>
```

### Database Connection Issues

```bash
# Verify PostgreSQL is healthy
docker-compose exec postgres pg_isready

# Check connections
docker-compose exec postgres psql -U pmp_user -d pmp_auth -c "\conninfo"
```

### LDAP Connection Issues

```bash
# Test LDAP connectivity
docker-compose exec openldap slapcat

# Verify LDAP is listening
docker-compose exec openldap netstat -tlnp | grep 389
```

### Port Conflicts

If ports are already in use, modify `docker-compose.yml`:

```yaml
services:
  pmp-auth-api:
    ports:
      - "3000:3000"  # Change to "3002:3000" if 3000 is taken
```

## 🧹 Cleanup

```bash
# Stop all services
docker-compose down

# Remove volumes (WARNING: deletes all data)
docker-compose down -v

# Remove images
docker-compose down --rmi all

# Complete cleanup
docker-compose down -v --rmi all
docker system prune -a
```

## 🔐 Security Notes

**For Development Only:**
- Default passwords are intentionally simple
- TLS/SSL is disabled for easier local testing
- CORS is permissive
- Session cookies are not secure (no HTTPS)

**For Production:**
- Change all default passwords
- Enable TLS/SSL everywhere
- Restrict CORS origins
- Use secure cookies with HTTPS
- Enable proper authentication for all services
- Use secrets management (Docker secrets, Vault, etc.)
- Enable network encryption between services

## 📝 Configuration

All configuration is in `config.docker.yaml`. You can:

1. Add more tenants
2. Configure different identity backends
3. Adjust token expiration times
4. Enable/disable features
5. Modify rate limiting rules

After changes, rebuild:

```bash
docker-compose up -d --build pmp-auth-api
```

## 🎯 Next Steps

1. **Explore the API**: Check out the OpenAPI docs at http://localhost:3000/docs
2. **Test all flows**: OAuth2, OIDC, SAML, Device Flow, API Keys
3. **Monitor metrics**: Use Prometheus and Grafana
4. **Test MFA**: Set up TOTP for users
5. **Audit logging**: Check PostgreSQL audit_logs table
6. **Rate limiting**: Test with burst requests
7. **LDAP integration**: Add more users and groups

## 📚 Additional Resources

- [OAuth 2.0 RFC](https://datatracker.ietf.org/doc/html/rfc6749)
- [OpenID Connect Spec](https://openid.net/specs/openid-connect-core-1_0.html)
- [SAML 2.0](http://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-tech-overview-2.0.html)
- [Docker Compose Docs](https://docs.docker.com/compose/)
- [Prometheus Query Examples](https://prometheus.io/docs/prometheus/latest/querying/examples/)

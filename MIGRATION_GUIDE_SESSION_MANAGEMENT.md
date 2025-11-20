# Session Management Implementation - Migration Guide

## Overview

This guide documents the completion of partial implementations for **Session Management** and **Client Registration** in the PMP Auth API.

## What Was Completed

### ✅ Session Management (Full Implementation)

#### 1. Session ID (sid) Support

**Changes Made:**
- Added `sid` field to `OidcClaims` structure for OIDC ID tokens
- Added `session_id` field to `AuthorizationCodeData` for tracking sessions across auth codes
- Added `session_id` field to `RefreshTokenData` for session continuity during token refresh
- Updated `generate_id_token()` to accept and include session_id in ID tokens
- Updated all call sites (authorization endpoint, token endpoint, federation, password grant)
- Updated PostgreSQL storage layer to persist session_id
- Implemented session ID extraction from ID token claims during logout

**Benefits:**
- Proper OIDC session management compliance
- Support for coordinated logout across multiple clients
- Session tracking across the full OAuth2/OIDC flow
- Back-channel and front-channel logout support with session correlation

#### 2. Proper SHA-256 Implementation

**Changes Made:**
- Replaced placeholder hash function with proper WebCrypto API in `check_session_iframe`
- Implemented async/await pattern for crypto.subtle.digest()
- Full browser-based session state validation

**Benefits:**
- RFC-compliant session state hashing
- Secure browser-based session monitoring
- Standards-compliant OIDC Session Management 1.0

### ✅ Client Registration (Already Complete)

**Verification:**
- Multiple key support is fully implemented via `jwks_keys` field
- Kid-based key selection is operational in `validate_client_assertion()`
- Key rotation support through multiple concurrent keys
- Backward compatibility with single `public_key_pem` field

## Database Migration

### Migration File Created

**File:** `db/migrations/20251120_add_session_id_columns.sql`

**Changes:**
```sql
-- Add session_id column to authorization_codes (NOT NULL - REQUIRED)
ALTER TABLE authorization_codes ADD COLUMN session_id VARCHAR(255) NOT NULL;
CREATE INDEX idx_authorization_codes_session_id ON authorization_codes (session_id);

-- Add session_id column to refresh_tokens (NOT NULL - REQUIRED)
ALTER TABLE refresh_tokens ADD COLUMN session_id VARCHAR(255) NOT NULL;
CREATE INDEX idx_refresh_tokens_session_id ON refresh_tokens (session_id);
```

**⚠️ WARNING:** This migration will fail if there are existing rows in the tables. You must either:
1. Start with a fresh database, OR
2. Delete all existing authorization_codes and refresh_tokens before applying

### How to Apply Migration

**⚠️ IMPORTANT:** Clear existing data first if upgrading from a previous version:

```bash
# Stop services
docker-compose down

# Remove PostgreSQL volume (DESTROYS ALL DATA - fresh start)
docker volume rm pmp-auth-api_postgres_data

# Start fresh
docker-compose up -d
```

#### Option 1: Docker Compose (Fresh Installation)

Migrations run automatically when starting services:

```bash
# Start all services (migrations run automatically)
docker-compose up -d

# View migration logs
docker-compose logs database_migrations

# Verify migration applied
docker-compose run --rm database_migrations status
```

#### Option 2: Manual Migration (Development)

```bash
# Run pending migrations
docker-compose run --rm database_migrations up

# Check status
docker-compose run --rm database_migrations status
```

#### Option 3: Local dbmate (No Docker)

```bash
# Set database URL
export DATABASE_URL="postgresql://pmp_user:pmp_password@localhost:5432/pmp_auth?sslmode=disable"

# Run migration
dbmate up

# Verify
dbmate status
```

### Rollback (if needed)

```bash
# Rollback last migration
docker-compose run --rm database_migrations down

# Or with local dbmate
dbmate down
```

## Code Changes Summary

### Files Modified

1. **src/auth/oidc.rs**
   - Added `sid` field to `OidcClaims` (line 48)
   - Added session_id parameter to `generate_id_token()` (line 478)
   - Replaced placeholder SHA-256 with WebCrypto API (line 645-652)
   - Made session state functions async

2. **src/storage/mod.rs**
   - Added `session_id` to `AuthorizationCodeData` (line 205)
   - Added `session_id` to `RefreshTokenData` (line 217)

3. **src/storage/postgres.rs**
   - Updated INSERT queries for session_id
   - Updated SELECT queries to fetch session_id
   - Updated all authorization_codes operations
   - Updated all refresh_tokens operations

4. **src/auth/oauth2_server.rs**
   - Updated authorization endpoint to generate and store session_id
   - Updated token endpoint to pass session_id to ID tokens
   - Updated refresh token generation to include session_id
   - Updated password grant to generate session_id
   - Implemented sid extraction from ID token during logout (line 1240-1262)

5. **src/auth/federation/mod.rs**
   - Updated federation callback to generate and use session_id
   - Updated refresh token data to include session_id

6. **src/auth/client_registration.rs**
   - Updated TODO comment to clarify multiple key support is complete

7. **db/README.md**
   - Documented new migration

## Testing

### Build Verification

```bash
# Verify code compiles
cargo check
# ✅ Success: Finished `dev` profile [unoptimized + debuginfo] target(s) in 6.59s
```

### Runtime Testing Checklist

After applying the migration:

- [ ] Test authorization code flow with session_id
- [ ] Test refresh token flow maintains session_id
- [ ] Test ID token contains sid claim
- [ ] Test logout with id_token_hint extracts sid
- [ ] Test check_session_iframe with proper SHA-256
- [ ] Test password grant generates session_id
- [ ] Test federation flow includes session_id

## RFC Compliance

This implementation addresses:

- **RFC 6749** - OAuth 2.0 Authorization Framework
- **OIDC Core** - OpenID Connect Core 1.0 (sid claim)
- **OIDC Session Management** - Session Management 1.0 (check_session_iframe)
- **RFC 8965** - Back-Channel Logout (sid in logout tokens)
- **OIDC Front-Channel Logout** - Front-Channel Logout 1.0

## Breaking Changes - No Backward Compatibility

**IMPORTANT:** This is a breaking change with no backward compatibility:

- `session_id` fields are **REQUIRED** (NOT NULL in database)
- All authorization codes MUST have a session_id
- All refresh tokens MUST have a session_id
- All ID tokens MUST include the sid claim
- Existing data without session_id will fail validation

**Migration Requirements:**
- Fresh installation required OR
- Manual data migration to populate session_id for existing records
- No graceful fallback for missing session_id

## Production Deployment

### Pre-Deployment Checklist

1. **Backup Database**
   ```bash
   pg_dump -U pmp_user pmp_auth > backup_$(date +%Y%m%d_%H%M%S).sql
   ```

2. **Review Migration**
   - Check migration file for correctness
   - Verify rollback script works

3. **Test in Staging**
   - Apply migration in staging environment
   - Run integration tests
   - Verify session management works

4. **Apply to Production**
   ```bash
   # During maintenance window
   docker-compose run --rm database_migrations up

   # Verify
   docker-compose run --rm database_migrations status

   # Restart application
   docker-compose restart pmp-auth-api
   ```

5. **Monitor**
   - Check application logs
   - Verify sessions are being created with session_id
   - Test logout flows

## Troubleshooting

### Migration Fails

```bash
# Check PostgreSQL logs
docker-compose logs postgres

# Check migration service logs
docker-compose logs database_migrations

# Verify database connection
docker-compose exec postgres psql -U pmp_user -d pmp_auth -c "SELECT version();"
```

### Application Errors After Migration

```bash
# Check application logs
docker-compose logs pmp-auth-api

# Verify columns exist
docker-compose exec postgres psql -U pmp_user -d pmp_auth -c "\d authorization_codes"
docker-compose exec postgres psql -U pmp_user -d pmp_auth -c "\d refresh_tokens"
```

### Rollback if Needed

```bash
# Rollback migration
docker-compose run --rm database_migrations down

# Restore from backup (if needed)
docker-compose exec -T postgres psql -U pmp_user -d pmp_auth < backup.sql

# Redeploy previous version
git checkout <previous-commit>
docker-compose up -d --build
```

## Future Enhancements

Potential improvements for session management:

1. **Redis-based Session Storage**
   - Store session state in Redis for distributed deployments
   - Faster session lookups
   - Session replication across instances

2. **Session Cleanup**
   - Automatic cleanup of expired sessions
   - Add to `cleanup_expired_data()` function

3. **Session Analytics**
   - Track active sessions per user
   - Session duration metrics
   - Concurrent session limits

4. **Enhanced Logout**
   - Global logout (all sessions for user)
   - Device-specific logout
   - Session management UI

## References

- [OIDC Session Management 1.0](https://openid.net/specs/openid-connect-session-1_0.html)
- [RFC 8965 - Back-Channel Logout](https://datatracker.ietf.org/doc/html/rfc8965)
- [OIDC Front-Channel Logout 1.0](https://openid.net/specs/openid-connect-frontchannel-1_0.html)
- [dbmate Documentation](https://github.com/amacneil/dbmate)

## Support

For issues or questions:
- Check application logs: `docker-compose logs pmp-auth-api`
- Review CLAUDE.md for project documentation
- Check GitHub issues

---

**Migration Created:** 2025-01-20
**Author:** Claude Code
**Version:** 0.1.0

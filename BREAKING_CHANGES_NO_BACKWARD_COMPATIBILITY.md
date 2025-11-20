# Breaking Changes - No Backward Compatibility

## Overview

All backward compatibility has been removed from the session management implementation. This is a **breaking change** that requires a fresh database or manual data migration.

## What Changed

### 1. Database Schema - session_id is REQUIRED

**Before (with backward compatibility):**
```sql
ALTER TABLE authorization_codes ADD COLUMN session_id VARCHAR(255);
ALTER TABLE refresh_tokens ADD COLUMN session_id VARCHAR(255);
```

**After (no backward compatibility):**
```sql
ALTER TABLE authorization_codes ADD COLUMN session_id VARCHAR(255) NOT NULL;
ALTER TABLE refresh_tokens ADD COLUMN session_id VARCHAR(255) NOT NULL;
```

### 2. Rust Code - session_id is NOT Optional

**Storage Structures:**
```rust
// Before
pub struct AuthorizationCodeData {
    // ...
    pub session_id: Option<String>,
}

pub struct RefreshTokenData {
    // ...
    pub session_id: Option<String>,
}

// After
pub struct AuthorizationCodeData {
    // ...
    pub session_id: String, // REQUIRED
}

pub struct RefreshTokenData {
    // ...
    pub session_id: String, // REQUIRED
}
```

**Function Signatures:**
```rust
// Before
pub fn generate_id_token(
    // ...
    session_id: Option<String>,
    // ...
) -> Result<String, Error>

async fn generate_refresh_token(
    // ...
    session_id: Option<String>,
    // ...
) -> Result<String, Error>

// After
pub fn generate_id_token(
    // ...
    session_id: String, // REQUIRED
    // ...
) -> Result<String, Error>

async fn generate_refresh_token(
    // ...
    session_id: String, // REQUIRED
    // ...
) -> Result<String, Error>
```

### 3. All Call Sites Updated

Every place that calls these functions now passes a required `session_id`:

- **Authorization endpoint**: Always generates and stores session_id
- **Token endpoint**: Extracts session_id from authorization code
- **Refresh token flow**: Maintains session_id across token rotation
- **Password grant**: Generates new session_id
- **Federation flow**: Generates session_id for federated logins

### 4. PostgreSQL Storage Updated

```rust
// Before
.bind(data.session_id.as_deref())

// After
.bind(&data.session_id)
```

## Migration Requirements

### ⚠️ CRITICAL: Fresh Database Required

**You CANNOT upgrade an existing database with this migration.**

The migration will fail if there are existing rows because:
- `NOT NULL` constraint requires all rows to have session_id
- Existing rows have NULL session_id

### Options for Migration

#### Option 1: Fresh Installation (Recommended)

```bash
# Stop services
docker-compose down

# Remove PostgreSQL volume (DESTROYS ALL DATA)
docker volume rm pmp-auth-api_postgres_data

# Start fresh with new schema
docker-compose up -d
```

#### Option 2: Manual Data Migration (Advanced)

If you have production data you must preserve:

1. **Backup existing database**
   ```bash
   docker-compose exec postgres pg_dump -U pmp_user pmp_auth > backup.sql
   ```

2. **Clear short-lived tokens** (these expire quickly anyway)
   ```sql
   DELETE FROM authorization_codes;
   DELETE FROM refresh_tokens;
   ```

3. **Apply migration**
   ```bash
   docker-compose run --rm database_migrations up
   ```

4. **Restore long-lived data** (users, clients, etc.)
   ```bash
   # Extract and restore only users, oauth2_clients, etc. from backup
   ```

#### Option 3: Development Migration Script

For development environments with existing test data:

```sql
-- Clear ephemeral tokens before migration
DELETE FROM authorization_codes WHERE expires_at < NOW();
DELETE FROM refresh_tokens WHERE expires_at < NOW();

-- Delete remaining tokens (they'll be regenerated on next login)
DELETE FROM authorization_codes;
DELETE FROM refresh_tokens;

-- Now apply migration
ALTER TABLE authorization_codes ADD COLUMN session_id VARCHAR(255) NOT NULL;
CREATE INDEX idx_authorization_codes_session_id ON authorization_codes (session_id);

ALTER TABLE refresh_tokens ADD COLUMN session_id VARCHAR(255) NOT NULL;
CREATE INDEX idx_refresh_tokens_session_id ON refresh_tokens (session_id);
```

## Impact Assessment

### What Breaks

1. **Existing authorization codes** - Will fail validation (missing session_id)
2. **Existing refresh tokens** - Will fail validation (missing session_id)
3. **ID token generation** - Now requires session_id parameter
4. **Any code using Option<String> for session_id** - Type mismatch

### What Still Works

1. **User accounts** - Unchanged
2. **OAuth2 clients** - Unchanged
3. **API keys** - Unchanged
4. **Sessions table** - Unchanged (has its own session_id field)

### User Impact

- **Active sessions**: Will be terminated
- **Refresh tokens**: Will be invalidated
- **Users must re-authenticate**: After migration, all users need to log in again

## Testing After Migration

### Verification Checklist

```bash
# 1. Verify migration applied
docker-compose run --rm database_migrations status

# 2. Check table structure
docker-compose exec postgres psql -U pmp_user -d pmp_auth -c "\d authorization_codes"
docker-compose exec postgres psql -U pmp_user -d pmp_auth -c "\d refresh_tokens"

# 3. Verify NOT NULL constraint
# This should show "not null" for session_id
```

### Test Authorization Flow

```bash
# 1. Get authorization code
curl "http://localhost:3000/api/v1/tenant/default/oauth/authorize?..."

# 2. Check database has session_id
docker-compose exec postgres psql -U pmp_user -d pmp_auth -c \
  "SELECT code, session_id FROM authorization_codes LIMIT 1;"

# 3. Exchange for tokens
curl -X POST "http://localhost:3000/api/v1/tenant/default/oauth/token" \
  -d "grant_type=authorization_code&code=..."

# 4. Verify refresh token has session_id
docker-compose exec postgres psql -U pmp_user -d pmp_auth -c \
  "SELECT token, session_id FROM refresh_tokens LIMIT 1;"

# 5. Decode ID token and verify sid claim is present
echo "<id_token>" | jq -R 'split(".") | .[1] | @base64d | fromjson | .sid'
```

## Rollback

If you need to rollback:

```bash
# Rollback migration
docker-compose run --rm database_migrations down

# Restore from backup
docker-compose exec -T postgres psql -U pmp_user -d pmp_auth < backup.sql

# Checkout previous code version
git checkout <previous-commit>
docker-compose up -d --build
```

## Production Deployment Strategy

### Pre-Deployment

1. **Schedule maintenance window** - Users will be logged out
2. **Notify users** - Active sessions will be terminated
3. **Backup database** - Full pg_dump before changes
4. **Test in staging** - Verify migration works

### Deployment Steps

1. **Enable maintenance mode**
2. **Stop application**
3. **Backup database**
4. **Clear ephemeral tokens** (optional - they'll expire anyway)
5. **Apply migration**
6. **Deploy new application code**
7. **Verify** - Test login/logout flows
8. **Disable maintenance mode**

### Post-Deployment

1. **Monitor logs** - Check for session_id errors
2. **Verify metrics** - Ensure logins working
3. **User communication** - Inform users to re-login

## Files Modified

### Code Changes

- `src/storage/mod.rs` - Made session_id required in structs
- `src/storage/postgres.rs` - Updated SQL queries
- `src/auth/oidc.rs` - Made session_id parameter required
- `src/auth/oauth2_server.rs` - Removed Option<> from all session_id usage
- `src/auth/federation/mod.rs` - Made session_id required
- `src/auth/client_registration.rs` - Updated comments

### Migration Files

- `db/migrations/20251120_add_session_id_columns.sql` - NOT NULL constraint

### Documentation

- `MIGRATION_GUIDE_SESSION_MANAGEMENT.md` - Updated warnings
- `db/README.md` - Added migration entry
- `BREAKING_CHANGES_NO_BACKWARD_COMPATIBILITY.md` - This document

## Why No Backward Compatibility?

Starting from scratch allows for:

1. **Cleaner codebase** - No Option<> wrapping everywhere
2. **Better performance** - No null checks
3. **Simpler logic** - No fallback paths
4. **RFC compliance** - sid is recommended in OIDC spec
5. **Better security** - Proper session tracking from day one

For new projects or fresh installations, this is the right approach.

## Support

For questions or issues:
- Check logs: `docker-compose logs pmp-auth-api`
- Review CLAUDE.md for project documentation
- Check migration status: `docker-compose run --rm database_migrations status`

---

**Created:** 2025-01-20
**Breaking Change:** YES
**Backward Compatible:** NO
**Migration Required:** YES (Fresh database recommended)

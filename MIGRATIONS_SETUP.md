# Database Migrations with dbmate

## Overview

The PMP Auth API now uses **dbmate** for database migrations instead of running migrations from the application code.

## What Changed

### ✅ Before (Application-Managed)
- Migrations embedded in application code
- Application runs migrations on startup
- Potential race conditions with multiple instances
- Migration errors affect app startup

### ✅ After (dbmate-Managed)
- Migrations run as separate Docker Compose service
- Application waits for migrations to complete
- Single migration runner (no race conditions)
- Clean separation of concerns

## Architecture

```
┌─────────────┐
│  postgres   │  (health check)
└──────┬──────┘
       │
       ▼
┌─────────────────────┐
│ database_migrations │  (runs migrations, exits)
└──────┬──────────────┘
       │
       ▼
┌──────────────┐
│ pmp-auth-api │  (starts with correct schema)
└──────────────┘
```

## Service Configuration

### 1. Database Migrations Service

```yaml
database_migrations:
  image: amacneil/dbmate:2.28.0
  container_name: pmp-migrations
  environment:
    - DATABASE_URL=postgresql://pmp_user:pmp_password@postgres:5432/pmp_auth?sslmode=disable
  command: --wait --wait-timeout 60s up
  volumes:
    - ./db/migrations:/db/migrations:ro
  depends_on:
    postgres:
      condition: service_healthy
```

**Key features:**
- Waits up to 60 seconds for PostgreSQL to be ready
- Runs all pending migrations (`up` command)
- Exits successfully when done
- Mounts migrations as read-only

### 2. Application Service

```yaml
pmp-auth-api:
  # ... other config ...
  depends_on:
    database_migrations:
      condition: service_completed_successfully
    # ... other dependencies ...
```

**Key change:**
- App waits for migrations to complete successfully
- Won't start if migrations fail
- Ensures schema is always up-to-date

## Directory Structure

```
pmp-auth-api/
├── db/
│   ├── migrations/
│   │   └── 20250118000001_initial_schema.sql
│   ├── schema.sql (auto-generated)
│   └── README.md
├── migrations/  (legacy - can be removed)
│   └── 001_initial_schema.sql
└── docker-compose.yml
```

## Migration File Format

Each migration file has two sections:

```sql
-- migrate:up
-- SQL to apply the migration
CREATE TABLE users (...);

-- migrate:down  
-- SQL to rollback the migration
DROP TABLE users;
```

## Usage

### Start Services (Automatic)

```bash
# Migrations run automatically
docker-compose up -d

# Check migration status
docker-compose logs database_migrations
```

### Manual Migration Commands

```bash
# Check what migrations have been applied
docker-compose run --rm database_migrations status

# Apply pending migrations
docker-compose run --rm database_migrations up

# Rollback last migration
docker-compose run --rm database_migrations down

# Create new migration
docker-compose run --rm database_migrations new add_feature_name
```

### View Migration History

```sql
-- dbmate creates this table automatically
SELECT * FROM schema_migrations ORDER BY version;
```

## Code Changes

### PostgresStorage

Removed `run_migrations()` method:

```rust
// ❌ Before
impl PostgresStorage {
    pub async fn run_migrations(&self) -> Result<(), StorageError> {
        // ... embedded SQL ...
    }
}

// ✅ After
impl PostgresStorage {
    // No migration method - handled by dbmate
}
```

The application code is now simpler and focused solely on data operations.

## Benefits

1. **Separation of Concerns**
   - Application code doesn't manage schema
   - Clear migration history
   - Easier to audit changes

2. **No Race Conditions**
   - Single migration runner
   - Safe for multiple app instances
   - Atomic migration execution

3. **Better Error Handling**
   - App won't start with wrong schema
   - Migration failures are isolated
   - Easy to rollback if needed

4. **Development Workflow**
   - Create migrations with simple CLI
   - Test up/down migrations independently
   - Schema auto-generated for reference

5. **Production Safety**
   - Migrations run before deployment
   - Failed migrations prevent app start
   - Rollback capability built-in

## Migration Workflow Example

### Create New Feature

```bash
# 1. Create migration
docker-compose run --rm database_migrations new add_user_roles

# 2. Edit generated file
vim db/migrations/20250118120000_add_user_roles.sql

# Add SQL:
-- migrate:up
ALTER TABLE users ADD COLUMN role VARCHAR(50) DEFAULT 'user';

-- migrate:down
ALTER TABLE users DROP COLUMN role;

# 3. Apply migration
docker-compose run --rm database_migrations up

# 4. Verify
docker-compose run --rm database_migrations status
```

### Rollback if Needed

```bash
# Rollback last migration
docker-compose run --rm database_migrations down

# Rollback specific version
docker-compose run --rm database_migrations down --to 20250118000001
```

## Environment Variables

| Variable | Value | Used By |
|----------|-------|---------|
| `DATABASE_URL` | `postgresql://...` | dbmate, app |

Both services use the same connection string (configured in docker-compose.yml).

## Testing

```bash
# Start fresh database
docker-compose down -v
docker-compose up -d postgres

# Run migrations
docker-compose up database_migrations

# Check tables exist
docker exec -it pmp-postgres psql -U pmp_user -d pmp_auth -c "\dt"

# Start app
docker-compose up -d pmp-auth-api
```

## Troubleshooting

### Migrations Don't Run

```bash
# Check postgres health
docker-compose ps postgres

# View migration logs
docker-compose logs database_migrations

# Manually run migrations
docker-compose run --rm database_migrations --verbose up
```

### App Won't Start

```bash
# Check migration service status
docker-compose ps database_migrations

# Must show "exited (0)" not "exited (1)"
```

### Reset Database (Dev Only)

```bash
# CAUTION: Destroys all data
docker-compose down -v
docker-compose up -d
```

## Production Considerations

1. **Run migrations during maintenance window**
2. **Backup database before migrations**
3. **Test migrations in staging first**
4. **Monitor migration duration**
5. **Have rollback plan ready**

Example production workflow:

```bash
# Backup
pg_dump -U pmp_user pmp_auth > backup_$(date +%Y%m%d).sql

# Run migrations
dbmate up

# Verify
dbmate status
psql -U pmp_user -d pmp_auth -c "SELECT COUNT(*) FROM users;"

# Deploy app
docker-compose up -d pmp-auth-api
```

## Summary

✅ **Migrations now run as a separate service**
✅ **Application waits for migrations to complete**
✅ **No migration code in application**
✅ **Proper dependency chain: postgres → migrations → app**
✅ **Safe, atomic, and auditable**

The setup ensures your database schema is always correct before the application starts!

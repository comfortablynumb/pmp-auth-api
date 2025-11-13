# Database Migrations

This directory contains PostgreSQL database migrations for the PMP Auth API.

## Running Migrations

### Option 1: Using psql (Manual)

```bash
# Connect to your PostgreSQL database
psql -U your_username -d your_database -f migrations/001_initial_schema.sql
```

### Option 2: Using sqlx-cli (Recommended for development)

```bash
# Install sqlx-cli
cargo install sqlx-cli --no-default-features --features postgres

# Create database
sqlx database create --database-url "postgresql://user:password@localhost/pmp_auth"

# Run migrations
sqlx migrate run --database-url "postgresql://user:password@localhost/pmp_auth"
```

### Option 3: Using Docker

```bash
# Start PostgreSQL container
docker run -d \
  --name pmp-auth-db \
  -e POSTGRES_PASSWORD=password \
  -e POSTGRES_DB=pmp_auth \
  -p 5432:5432 \
  postgres:15

# Wait for database to be ready
sleep 5

# Run migrations
docker exec -i pmp-auth-db psql -U postgres -d pmp_auth < migrations/001_initial_schema.sql
```

## Configuration

### Using PostgreSQL Storage

Update your `config.yaml`:

```yaml
# Storage configuration
storage:
  type: postgres
  connection_string: "postgresql://user:password@localhost/pmp_auth"

tenants:
  test-tenant:
    # ... rest of tenant config
```

### Using In-Memory Storage (Default)

```yaml
# Storage configuration (optional, defaults to memory)
storage:
  type: memory

tenants:
  test-tenant:
    # ... rest of tenant config
```

## Maintenance

### Cleanup Expired Data

The migrations include a stored procedure for cleaning up expired data:

```sql
-- Run cleanup manually
SELECT cleanup_expired_data();

-- Returns: number of rows deleted
```

You can set up a cron job or scheduled task to run this periodically:

```bash
# Add to crontab (runs daily at 2 AM)
0 2 * * * psql -U postgres -d pmp_auth -c "SELECT cleanup_expired_data();"
```

Or use PostgreSQL's pg_cron extension:

```sql
-- Install pg_cron extension
CREATE EXTENSION IF NOT EXISTS pg_cron;

-- Schedule daily cleanup at 2 AM
SELECT cron.schedule('cleanup-expired-data', '0 2 * * *',
    'SELECT cleanup_expired_data();');
```

## Schema Overview

### Tables

- **authorization_codes**: OAuth2 authorization codes (short-lived, typically 10 minutes)
- **refresh_tokens**: OAuth2 refresh tokens (long-lived, typically 30 days)
- **api_keys**: Long-lived API keys with metadata
- **sessions**: User sessions for OAuth2 and device flows
- **device_codes**: Device authorization codes (RFC 8628)
- **revoked_tokens**: Revoked token JTIs for validation

### Indexes

All tables include appropriate indexes for:
- Expiration-based queries
- Tenant isolation
- User lookups
- Status checks

## Testing

```bash
# Test connection
psql -U postgres -d pmp_auth -c "SELECT version();"

# Verify tables
psql -U postgres -d pmp_auth -c "\dt"

# Test cleanup function
psql -U postgres -d pmp_auth -c "SELECT cleanup_expired_data();"
```

## Backup and Restore

### Backup

```bash
# Full database backup
pg_dump -U postgres pmp_auth > backup_$(date +%Y%m%d).sql

# Schema only
pg_dump -U postgres --schema-only pmp_auth > schema_backup.sql

# Data only
pg_dump -U postgres --data-only pmp_auth > data_backup.sql
```

### Restore

```bash
# Restore from backup
psql -U postgres -d pmp_auth < backup_20250113.sql
```

## Troubleshooting

### Connection Issues

```bash
# Test connection
psql -U postgres -d pmp_auth -c "SELECT 1;"

# Check PostgreSQL is running
sudo systemctl status postgresql

# Check connection in config.yaml
cat config.yaml | grep connection_string
```

### Migration Errors

```bash
# Check if tables exist
psql -U postgres -d pmp_auth -c "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public';"

# Drop all tables (CAUTION: DATA LOSS)
psql -U postgres -d pmp_auth -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public;"

# Re-run migrations
psql -U postgres -d pmp_auth -f migrations/001_initial_schema.sql
```

## Performance Tuning

### Monitoring

```sql
-- Check table sizes
SELECT
    schemaname,
    tablename,
    pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) AS size
FROM pg_tables
WHERE schemaname = 'public'
ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC;

-- Check index usage
SELECT
    schemaname,
    tablename,
    indexname,
    idx_scan,
    idx_tup_read
FROM pg_stat_user_indexes
WHERE schemaname = 'public'
ORDER BY idx_scan DESC;
```

### Optimization

```sql
-- Update statistics
ANALYZE;

-- Vacuum tables
VACUUM ANALYZE;

-- Reindex if needed
REINDEX DATABASE pmp_auth;
```

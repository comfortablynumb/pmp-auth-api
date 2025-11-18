# TODO / Future Improvements

## Dependencies

### Redis Crate Upgrade (Low Priority)
**Status**: Postponed
**Priority**: Low (only affects Rust 2024 edition)

The `redis` crate is currently at v0.25.4, which has a future incompatibility warning related to never type fallback in Rust 2024 edition.

**Issue**: The redis crate's internal code will be incompatible with Rust 2024 edition.

**Impact**:
- No impact on current builds (we're using Rust 2021 edition)
- Warning will become an error when/if upgrading to Rust 2024 edition
- Does not affect runtime behavior

**When to upgrade**:
- When upgrading to Rust 2024 edition, OR
- When redis crate releases v1.0 stable, OR
- When updating other dependencies that require newer redis

**Required changes for upgrade to redis 0.26+**:
1. Update `Cargo.toml`: `redis = { version = "0.26", features = ["tokio-comp", "connection-manager"] }`
2. Fix API changes in `src/health/checks.rs`:
   - Line ~180: The `query_async` method signature changed
   - Old: `query_async::<_, String>(&mut conn)`
   - New: `query_async(&mut conn)` (type inference works differently)

**References**:
- Rust 2024 never type fallback: https://doc.rust-lang.org/edition-guide/rust-2024/never-type-fallback.html
- Redis crate: https://github.com/redis-rs/redis-rs
- Available versions: 0.26.x, 0.27.x, 0.28.x, 0.29.x, 0.30.x, 0.31.x, 0.32.x

## Features

### Complete PostgreSQL Storage Implementation
**Status**: TODO
**Priority**: Medium

The PostgreSQL storage backend is partially implemented with placeholder methods.

**Files**: `src/storage/postgres.rs`

**Tasks**:
- [ ] Add `sqlx` dependency
- [ ] Implement connection pooling
- [ ] Implement all `StorageBackend` trait methods
- [ ] Add migrations for database schema
- [ ] Add integration tests

### Add Rate Limiting for API Endpoints
**Status**: Partial
**Priority**: Medium

Rate limiting is configured but not fully integrated.

**Tasks**:
- [ ] Apply rate limiting middleware to sensitive endpoints
- [ ] Add per-tenant rate limit configuration
- [ ] Add metrics for rate limit violations

### Add Comprehensive API Documentation
**Status**: TODO
**Priority**: Low

**Tasks**:
- [ ] Add OpenAPI/Swagger documentation
- [ ] Document all endpoints with examples
- [ ] Add API versioning strategy
- [ ] Create Postman collection

## Code Quality

### Add More Unit Tests
**Status**: Ongoing
**Priority**: High

**Areas needing tests**:
- [ ] Environment variable interpolation edge cases
- [ ] OAuth2 flows
- [ ] OIDC provider functionality
- [ ] API key generation and validation
- [ ] Error handling paths

### Add Integration Tests
**Status**: TODO
**Priority**: High

**Tasks**:
- [ ] Setup test database
- [ ] Add end-to-end OAuth2 flow tests
- [ ] Add LDAP integration tests
- [ ] Add Redis integration tests

### Improve Error Messages
**Status**: Ongoing
**Priority**: Medium

**Tasks**:
- [x] Add clear error messages on app startup failures
- [ ] Improve validation error messages
- [ ] Add structured error types
- [ ] Add error codes for client debugging

## Security

### Security Audit
**Status**: TODO
**Priority**: High (before production)

**Tasks**:
- [ ] Review JWT signing and validation
- [ ] Audit password hashing implementation
- [ ] Review CORS configuration
- [ ] Check for timing attack vulnerabilities
- [ ] Review secret management
- [ ] Add security headers middleware

### Add Security Headers
**Status**: TODO
**Priority**: High

**Tasks**:
- [ ] Add Content-Security-Policy
- [ ] Add X-Frame-Options
- [ ] Add X-Content-Type-Options
- [ ] Add Strict-Transport-Security (for HTTPS)

## Operations

### Observability Improvements
**Status**: Partial
**Priority**: Medium

**Tasks**:
- [ ] Add structured logging with correlation IDs
- [ ] Add distributed tracing
- [ ] Add more detailed metrics
- [ ] Add health check for all dependencies
- [ ] Add readiness vs liveness checks

### Performance Optimization
**Status**: TODO
**Priority**: Low

**Tasks**:
- [ ] Add connection pooling benchmarks
- [ ] Profile memory usage
- [ ] Add caching layer for frequently accessed data
- [ ] Optimize database queries

## Documentation

### User Documentation
**Status**: Partial
**Priority**: Medium

**Tasks**:
- [x] Configuration guide with environment variables
- [ ] Deployment guide
- [ ] Troubleshooting guide
- [ ] Migration guide from other auth providers

### Developer Documentation
**Status**: Partial
**Priority**: Medium

**Tasks**:
- [ ] Architecture documentation
- [ ] Contributing guidelines
- [ ] Code style guide
- [ ] Release process documentation

## Completed ✓

- [x] Move configuration files to `config/` directory
- [x] Add environment variable interpolation support
- [x] Update all documentation references
- [x] Fix PostgreSQL health check
- [x] Add error logging before application exit
- [x] Build and test environment variable interpolation

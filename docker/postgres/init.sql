-- PostgreSQL initialization script for PMP Auth API
-- This script runs when the PostgreSQL container first starts

-- The database and user are already created by the POSTGRES_* environment variables
-- in docker-compose.yml, so we just need to ensure the schema is created

-- Grant all privileges to the user (already done by default, but being explicit)
GRANT ALL PRIVILEGES ON DATABASE pmp_auth TO pmp_user;

-- Optional: Create extensions if needed in the future
-- CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
-- CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- Log successful initialization
SELECT 'PMP Auth API PostgreSQL database initialized successfully' AS status;

# Configuration Files

This directory contains the configuration files for the PMP Auth API.

## Files

- **config.example.yaml** - Example configuration file with all available options
- **config.docker.yaml** - Configuration for Docker/development environment
- **config.yaml** - Your local configuration (not tracked in git)

## Getting Started

1. Copy the example configuration:
   ```bash
   cp config.example.yaml config.yaml
   ```

2. Edit `config.yaml` with your tenant settings

3. Set environment variables as needed (optional)

## Environment Variable Interpolation

Configuration files support environment variable interpolation using the following syntax:

### Required Environment Variable

If the environment variable is not set, the application will fail to start:

```yaml
database:
  url: "${env:DATABASE_URL}"
```

### Optional with Default Value

If the environment variable is not set, the default value will be used:

```yaml
server:
  host: "${env:SERVER_HOST:0.0.0.0}"
  port: 3000

database:
  url: "${env:DATABASE_URL:postgresql://localhost:5432/mydb}"
```

### Examples

#### Using Environment Variables

```bash
# Set environment variables
export DATABASE_URL="postgresql://user:pass@db.example.com:5432/production"
export REDIS_URL="redis://cache.example.com:6379"
export SERVER_HOST="0.0.0.0"

# Run the application
cargo run
```

#### Configuration with Interpolation

```yaml
# config/config.yaml
server:
  host: "${env:SERVER_HOST:0.0.0.0}"
  port: 3000

database:
  url: "${env:DATABASE_URL:postgresql://localhost:5432/pmp_auth}"
  max_connections: 10

redis:
  url: "${env:REDIS_URL:redis://localhost:6379}"

tenants:
  my-tenant:
    id: my-tenant
    name: "My Tenant"
    active: true
    identity_provider:
      oauth2:
        issuer: "${env:OAUTH_ISSUER:https://auth.example.com}"
        # ... rest of config
```

#### Docker Environment

When using Docker Compose, environment variables are automatically injected:

```yaml
# docker-compose.yml
services:
  pmp-auth-api:
    environment:
      - DATABASE_URL=postgresql://pmp_user:pmp_password@postgres:5432/pmp_auth
      - REDIS_URL=redis://redis:6379
      - SERVER_HOST=0.0.0.0
```

## Configuration Priority

The application looks for configuration files in the following order:

1. Path specified in `CONFIG_PATH` environment variable
2. `config/config.yaml`
3. `config/config.yml`
4. `./config/config.yaml`
5. `./config/config.yml`
6. `config.yaml` (root directory, deprecated)
7. `config.yml` (root directory, deprecated)

## Syntax Rules

- Environment variable names must start with a letter or underscore
- Can contain letters, numbers, and underscores
- Format: `${env:VAR_NAME}` or `${env:VAR_NAME:default_value}`
- Default values can contain colons, slashes, and other special characters
- Example: `${env:URL:https://example.com:8080/path}`

## Security Notes

- **Never commit `config.yaml` with secrets** - It's in `.gitignore` by default
- Use environment variables for sensitive data (passwords, keys, secrets)
- In production, use a secrets management system
- The example configurations use placeholder values that should be changed

## Validation

The application validates the configuration on startup:
- At least one tenant must be configured
- Each tenant must have at least one identity provider
- Required fields must be present
- Environment variables without defaults must be set

If validation fails, the application will exit with a detailed error message.

# pmp-auth-api

PMP Auth API: An authentication / authorization API. Part of Poor Man's Platform ecosystem.

A high-performance authentication and authorization API built with Rust and Axum, featuring JWT-based authentication, role-based access control, and secure password hashing.

## Features

- JWT-based authentication
- Password hashing with bcrypt
- Role-based authorization (User, Admin)
- Protected and public routes
- RESTful API design
- Comprehensive error handling
- CORS support
- Request tracing and logging

## Prerequisites

- Rust 1.70+ (install from [rustup.rs](https://rustup.rs))
- Cargo (comes with Rust)

## Quick Start

1. Clone the repository:
```bash
git clone <repository-url>
cd pmp-auth-api
```

2. Set up environment variables:
```bash
cp .env.example .env
# Edit .env and set your JWT_SECRET
```

3. Build and run:
```bash
cargo build
cargo run
```

The API will start on `http://0.0.0.0:3000`

## API Endpoints

### Public Endpoints

#### Health Check
```bash
GET /health
GET /
```

Response:
```json
{
  "status": "healthy",
  "service": "pmp-auth-api",
  "version": "0.1.0"
}
```

#### Register
```bash
POST /api/v1/auth/register
Content-Type: application/json

{
  "email": "user@example.com",
  "username": "johndoe",
  "password": "securepassword"
}
```

Response:
```json
{
  "token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "user": {
    "id": "123e4567-e89b-12d3-a456-426614174000",
    "email": "user@example.com",
    "username": "johndoe",
    "role": "user"
  }
}
```

#### Login
```bash
POST /api/v1/auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "securepassword"
}
```

Response:
```json
{
  "token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "user": {
    "id": "123e4567-e89b-12d3-a456-426614174000",
    "email": "user@example.com",
    "username": "johndoe",
    "role": "user"
  }
}
```

### Protected Endpoints

All protected endpoints require an Authorization header with a Bearer token:
```bash
Authorization: Bearer <your-jwt-token>
```

#### Get User Profile
```bash
GET /api/v1/user/profile
Authorization: Bearer <token>
```

Response:
```json
{
  "id": "123e4567-e89b-12d3-a456-426614174000",
  "email": "user@example.com",
  "role": "user"
}
```

#### List Users (Admin Only)
```bash
GET /api/v1/admin/users
Authorization: Bearer <admin-token>
```

Response:
```json
{
  "message": "Admin endpoint - list all users",
  "requested_by": "admin@example.com",
  "note": "In production, this would return a list of users from the database"
}
```

## Development

### Run in development mode
```bash
cargo run
```

### Run tests
```bash
cargo test
```

### Run with logging
```bash
RUST_LOG=debug cargo run
```

### Format code
```bash
cargo fmt
```

### Run linter
```bash
cargo clippy
```

## Environment Variables

- `JWT_SECRET` - Secret key for JWT token signing (default: "your-secret-key-change-this-in-production")
- `RUST_LOG` - Logging level (default: "pmp_auth_api=debug,tower_http=debug")

## CI/CD

This project uses GitHub Actions for continuous integration. The workflow runs on:
- Pull requests to `main`
- Pushes to `main`

The CI pipeline includes:
1. **Lint**: Format checking and Clippy linting
2. **Test**: Run all tests
3. **Build**: Build release binary

## Architecture

```
src/
├── main.rs              # Application entry point
├── auth/                # Authentication logic
│   ├── jwt.rs          # JWT token creation and validation
│   └── password.rs     # Password hashing and verification
├── handlers/           # Request handlers
│   ├── auth.rs        # Registration and login handlers
│   ├── user.rs        # User profile handlers
│   ├── admin.rs       # Admin-only handlers
│   └── health.rs      # Health check handler
├── middleware/        # Middleware components
│   └── auth.rs       # Authentication and authorization middleware
└── models/           # Data models
    └── user.rs      # User, Claims, and request/response models
```

## Security Considerations

- Passwords are hashed using bcrypt
- JWT tokens expire after 24 hours
- Admin routes are protected with role-based authorization
- Change the `JWT_SECRET` environment variable in production
- In production, replace the in-memory storage with a proper database
- Use HTTPS in production

## Production Deployment

For production deployment:

1. Set a strong `JWT_SECRET` environment variable
2. Replace in-memory storage with a database (PostgreSQL, MySQL, etc.)
3. Enable HTTPS/TLS
4. Configure proper CORS policies
5. Set up rate limiting
6. Implement refresh tokens
7. Add password strength validation
8. Implement account verification (email)
9. Add audit logging

## License

See [LICENSE](LICENSE) file for details.

# FKS Auth

Lightweight Axum-based authentication service for the FKS Trading Platform.

**Port**: 8009  
**Framework**: Rust + Axum  
**Role**: Authentication and authorization service

## 🎯 Purpose

FKS Auth provides authentication and authorization services for the FKS Trading Platform. Currently in development mode with a hardcoded dev user, it will be expanded to support:

- **JWT Authentication**: Access and refresh tokens
- **User Management**: User registration, login, logout
- **Session Management**: Secure session handling
- **API Key Management**: Integration with fks_web API key system
- **Role-Based Access Control**: Permissions and roles

**Note**: This is currently a development stub. Production implementation will include database-backed user management and full security features.

## 🏗️ Architecture

```
┌─────────────┐
│  fks_web     │
│  (Django)    │
└──────┬───────┘
       │
       │ HTTP/HTTPS
       ▼
┌─────────────┐
│  fks_auth   │
│  (Rust)     │
└──────┬───────┘
       │
       │ (Future: Database)
       ▼
┌─────────────┐
│  PostgreSQL │
│  (Users)    │
└─────────────┘
```

## 🚀 Quick Start

### Development

```bash
# Install Rust (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Build
cargo build

# Run
cargo run --release
```

### Docker

```bash
# Build
docker build -t nuniesmith/fks:auth-latest .

# Run
docker run -p 8009:8009 nuniesmith/fks:auth-latest
```

### Kubernetes

```bash
# Deploy using Helm
cd repo/main/k8s/charts/fks-platform
helm install fks-platform . -n fks-trading

# Or using the unified start script
cd /home/jordan/Documents/code/fks
./start.sh --type k8s
```

## 📡 API Endpoints

### Health Checks

- `GET /health` - Health check (returns "ok")

### Authentication

- `POST /login` - Login endpoint
  ```json
  {
    "username": "jordan",
    "password": "567326"
  }
  ```
  Returns:
  ```json
  {
    "access_token": "...",
    "refresh_token": "...",
    "token_type": "Bearer",
    "expires_in": 3600
  }
  ```

- `POST /refresh` - Refresh access token
  ```json
  {
    "refresh_token": "..."
  }
  ```

- `GET /me` - Get current user (requires Bearer token)
  Headers: `Authorization: Bearer <access_token>`

## 🔧 Configuration

### Environment Variables

```bash
# Service Configuration
SERVICE_NAME=fks_auth
SERVICE_PORT=8009
AUTH_HOST=0.0.0.0

# JWT Configuration (Future)
JWT_SECRET=your-jwt-secret
JWT_EXPIRATION_SECONDS=3600
REFRESH_TOKEN_EXPIRATION_SECONDS=86400

# Database (Future)
DATABASE_URL=postgresql://fks_user:password@db:5432/trading_db

# Security
ALLOWED_ORIGINS=http://localhost:3000,https://fkstrading.xyz
```

### Development Mode

Currently uses hardcoded credentials:
- **Username**: `jordan`
- **Password**: `567326`

**⚠️ Warning**: This is for development only. Production implementation will require database-backed authentication.

## 🧪 Testing

```bash
# Run tests
cargo test

# Integration tests
cargo test --test integration_tests

# With coverage
cargo install cargo-tarpaulin
cargo tarpaulin --out Html
```

### Example Usage

```bash
# Health check
curl -s localhost:8009/health

# Login
LOGIN=$(curl -s -X POST localhost:8009/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"jordan","password":"567326"}')
echo "$LOGIN" | jq '.'

# Extract tokens
REFRESH=$(echo "$LOGIN" | jq -r '.refresh_token')
ACCESS=$(echo "$LOGIN" | jq -r '.access_token')

# Refresh token
curl -s -X POST localhost:8009/refresh \
  -H 'Content-Type: application/json' \
  -d "{\"refresh_token\":\"$REFRESH\"}" | jq '.'

# Get current user
curl -s -H "Authorization: Bearer $ACCESS" \
  localhost:8009/me | jq '.'
```

## 🐳 Docker

### Build

```bash
docker build -t nuniesmith/fks:auth-latest .
```

### Run

```bash
docker run -p 8009:8009 nuniesmith/fks:auth-latest
```

### Docker Compose

```yaml
services:
  fks_auth:
    build: .
    image: nuniesmith/fks:auth-latest
    ports:
      - "8009:8009"
    environment:
      - SERVICE_PORT=8009
```

## ☸️ Kubernetes

### Deployment

```bash
# Deploy using Helm
cd repo/main/k8s/charts/fks-platform
helm install fks-platform . -n fks-trading

# Or using the unified start script
cd /home/jordan/Documents/code/fks
./start.sh --type k8s
```

### Health Checks

Kubernetes probes:
- **Liveness**: `GET /health`
- **Readiness**: `GET /health` (checks service availability)

## 📚 Documentation

- [API Documentation](docs/API.md) - Complete API reference
- [Deployment Guide](docs/DEPLOYMENT.md) - Deployment instructions
- [Security Guide](docs/SECURITY.md) - Security best practices

## 🔗 Integration

### Dependencies

- **PostgreSQL** (Future): User database
- **Redis** (Future): Session storage

### Consumers

- **fks_web**: Django web interface for user authentication
- **fks_api**: API gateway for request authentication
- **All FKS Services**: For service-to-service authentication

## 📊 Monitoring

### Health Check Endpoints

- `GET /health` - Basic health status (returns "ok")

### Metrics

- Authentication request count
- Token generation/validation latency
- Failed authentication attempts
- Active sessions (Future)

### Logging

- Authentication events
- Token operations
- Security events and failures

## 🛠️ Development

### Setup

```bash
# Clone repository
git clone https://github.com/nuniesmith/fks_auth.git
cd fks_auth

# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Build
cargo build --release
```

### Code Structure

```
repo/auth/
├── src/
│   ├── main.rs              # Service entry point
│   ├── lib.rs               # Library root
│   ├── api/                 # HTTP endpoints
│   │   ├── mod.rs
│   │   ├── auth.rs          # Authentication routes
│   │   └── health.rs        # Health check
│   ├── models/              # Data models
│   │   ├── mod.rs
│   │   ├── user.rs          # User model
│   │   └── token.rs         # Token models
│   ├── services/            # Business logic
│   │   ├── mod.rs
│   │   ├── auth_service.rs  # Authentication logic
│   │   └── jwt_service.rs   # JWT handling
│   └── config/              # Configuration
│       ├── mod.rs
│       └── settings.rs
├── tests/
│   ├── integration/
│   └── unit/
├── Cargo.toml
├── Dockerfile
└── README.md
```

### Contributing

1. Follow Rust best practices (clippy, rustfmt)
2. Write tests for authentication flows
3. Document security considerations
4. Update API documentation

## 🔐 Security Considerations

### Current (Development)

- Hardcoded credentials (development only)
- Minimal security for local testing
- No database persistence

### Future (Production)

- Database-backed user management
- Secure password hashing (bcrypt/argon2)
- JWT token signing with RSA keys
- Rate limiting for login attempts
- Session management with Redis
- API key integration with fks_web
- Role-based access control (RBAC)
- OAuth2/OIDC support

## 🐛 Troubleshooting

### Port Already in Use

```bash
# Check what's using port 8009
lsof -i :8009

# Or use a different port
SERVICE_PORT=9009 cargo run
```

### Token Validation Fails

- Verify JWT secret is set correctly
- Check token expiration
- Ensure Bearer token format: `Authorization: Bearer <token>`

---

**Repository**: [nuniesmith/fks_auth](https://github.com/nuniesmith/fks_auth)  
**Docker Image**: `nuniesmith/fks:auth-latest`  
**Status**: Development (Stub Implementation)

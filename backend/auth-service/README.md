# BuildHub Authentication Service

A production-ready authentication microservice built with Rust, featuring JWT-based authentication, email verification, and comprehensive observability.

## 🚀 Features

- **User Registration** with email activation
- **JWT Authentication** (access & refresh tokens)
- **Password Reset** flow with secure tokens
- **Rate Limiting** to prevent abuse
- **Account Lockout** protection
- **OpenTelemetry** tracing and Prometheus metrics
- **Docker Compose** setup for easy deployment
- **PostgreSQL** for data persistence
- **Redis** for caching and rate limiting

## 📋 Prerequisites

- Docker & Docker Compose (for containerized setup)
- OR Rust 1.82+ (for local development)
- Git

## 🏃 Quick Start (Docker - Recommended)

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/buildhub-auth-service.git
   cd buildhub-auth-service
   ```

2. **Create environment file**
   ```bash
   cp .env.example .env.docker
   # Edit .env.docker with your settings (especially email credentials)
   ```

3. **Start services**
   ```bash
   ./scripts/docker-run.sh up
   ```

4. **Test the service**
   ```bash
   # Health check
   curl http://localhost:3000/health
   
   # Register a user
   curl -X POST http://localhost:3000/auth/register \
     -H "Content-Type: application/json" \
     -d '{
       "username": "testuser",
       "email": "test@example.com",
       "password": "SecurePass123!"
     }'
   ```

## 🛠️ Development Setup

### Using Docker (Recommended)

```bash
# Start all services
./scripts/docker-run.sh up

# View logs
./scripts/docker-run.sh logs

# Stop services
./scripts/docker-run.sh down

# Clean everything (including data)
./scripts/docker-run.sh clean
```

### Local Development (Without Docker)

1. **Install dependencies**
   ```bash
   # Install PostgreSQL and Redis
   sudo apt-get install postgresql redis-server
   
   # Install Rust
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   ```

2. **Setup database**
   ```bash
   # Create database and user
   sudo -u postgres psql
   CREATE USER buildhub WITH PASSWORD 'bhdbjpak';
   CREATE DATABASE buildhub_auth OWNER buildhub;
   \q
   
   # Run migrations
   diesel migration run
   ```

3. **Configure environment**
   ```bash
   cp .env.example .env
   # Edit .env for local settings (use localhost instead of container names)
   ```

4. **Run the service**
   ```bash
   cargo run
   ```

## 📁 Project Structure

```
auth-service/
├── src/
│   ├── main.rs              # Application entry point
│   ├── app.rs               # Router configuration
│   ├── handlers/            # HTTP request handlers
│   ├── middleware/          # Auth, rate limiting, telemetry
│   ├── db/                  # Database models and operations
│   ├── config/              # Database and Redis configuration
│   ├── utils/               # Utilities (JWT, email, validation)
│   └── metricss/            # Prometheus metrics
├── migrations/              # Database migrations
├── scripts/                 # Helper scripts
├── docker-compose.yml       # Docker services configuration
├── Dockerfile              # Container build instructions
└── .env.example            # Environment variables template
```

## 🔧 Configuration

### Environment Variables

Copy `.env.example` to `.env.docker` (for Docker) or `.env` (for local) and configure:

| Variable | Description | Example |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection string | `postgres://buildhub:password@localhost:5432/buildhub_auth` |
| `REDIS_URL` | Redis connection string | `redis://localhost:6379` |
| `JWT_SECRET` | Secret key for JWT signing (min 32 chars) | `your-super-secret-key-change-this` |
| `SMTP_SERVER` | SMTP server for emails | `smtp.gmail.com` |
| `SMTP_USERNAME` | Email account username | `your-email@gmail.com` |
| `SMTP_PASSWORD` | Email account password | `your-app-password` |
| `FRONTEND_URL` | Frontend application URL | `http://localhost:3001` |

### Email Configuration (Gmail)

1. Enable 2-factor authentication on your Gmail account
2. Generate an app-specific password: https://myaccount.google.com/apppasswords
3. Use this app password in `SMTP_PASSWORD`

## 📊 Monitoring

### With Monitoring Stack

```bash
# Start with Prometheus and Grafana
./scripts/docker-run.sh monitoring
```

Access:
- **Prometheus**: http://localhost:9090
- **Grafana**: http://localhost:3002 (admin/admin)
- **Metrics**: http://localhost:3000/metrics

## 🧪 API Endpoints

### Authentication

- `POST /auth/register` - Register new user
- `POST /auth/login` - User login
- `POST /auth/logout` - Logout (revoke token)
- `POST /auth/refresh` - Refresh access token
- `GET /auth/activate?code=XXX` - Activate account

### Password Reset

- `POST /auth/password-reset/request` - Request reset email
- `POST /auth/password-reset/confirm` - Reset with token

### Health & Monitoring

- `GET /health` - Service health check
- `GET /readiness` - Readiness probe
- `GET /metrics` - Prometheus metrics

## 🐛 Troubleshooting

### Port Conflicts

If you get port conflicts, edit `.env.docker`:
```bash
POSTGRES_PORT=5433  # Different from default 5432
REDIS_PORT=6380     # Different from default 6379
```

### Email Not Sending

1. Check SMTP credentials in `.env.docker`
2. For Gmail, ensure you're using an app password
3. Check spam folder for activation emails

### Database Connection Issues

```bash
# Test PostgreSQL connection
psql postgres://buildhub:bhdbjpak@localhost:5433/buildhub_auth

# Reset database
./scripts/docker-run.sh clean
./scripts/docker-run.sh up
```

## 📝 License

MIT

## 👥 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📧 Contact

- Your Name - your.email@example.com
- Project Link: https://github.com/yourusername/buildhub-auth-service
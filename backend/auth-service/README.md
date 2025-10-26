# BuildHub Authentication Service

A production-ready, secure, and observable authentication microservice built with Rust. This project demonstrates best practices in API design, database management, security, and containerization.

## 🚀 Features

-   **Secure User Management**: Registration with email activation and secure password reset flow.
-   **JWT Authentication**: Stateless authentication using JSON Web Tokens (access & refresh tokens).
-   **Robust Security**:
    -   Argon2id for password hashing.
    -   Redis-backed rate limiting to prevent brute-force attacks.
    -   Token revocation list for immediate session invalidation (logout).
    -   Protection against user enumeration attacks.
-   **High Performance**: Built on Axum and Tokio for asynchronous, non-blocking I/O.
-   **Comprehensive Observability**:
    -   **Structured Logging** with `tracing`.
    -   **Distributed Tracing** via OpenTelemetry, exportable to Jaeger.
    -   **Metrics** exposed for Prometheus.
-   **Clean Architecture**: Clear separation of concerns between API handlers, business logic, and data access layers.
-   **Containerized Environment**: Full development and monitoring stack managed by Docker Compose.

## 🛠️ Tech Stack

-   **Language**: Rust (Stable)
-   **Web Framework**: Axum
-   **Database**: PostgreSQL (with Diesel ORM and R2D2 connection pooling)
-   **Cache/Broker**: Redis
-   **Containerization**: Docker & Docker Compose
-   **Observability**: OpenTelemetry (Jaeger), Prometheus, Grafana

## 🏃‍♀️ Quick Start

This project is designed to be run with Docker Compose, which orchestrates all services.

### Prerequisites

-   Docker & Docker Compose
-   Git

### Running the Application

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/przemander/BuildHub.git
    cd BuildHub/backend/auth-service
    ```

2.  **Create the environment file:**
    Copy the example configuration and customize it with your secrets (especially for JWT and SMTP).
    ```bash
    cp .env.example .env
    ```
    > **Note**: The `.env` file is ignored by Git. You will need to create it manually.

3.  **Start the services:**
    This command builds the Rust application, starts the database and Redis, and runs the service.
    ```bash
    docker compose up --build
    ```
    To run in the background, add the `-d` flag.

4.  **Verify the service is running:**
    In a new terminal, check the health endpoint.
    ```bash
    curl http://localhost:3000/health
    ```
    You should see `ok`.

## 📈 Running with the Full Monitoring Stack

To run the application along with Jaeger, Prometheus, and Grafana, use the `monitoring` profile.

1.  **Start all services:**
    ```bash
    docker compose --profile monitoring up --build -d
    ```

2.  **Access the tools:**
    -   **Jaeger UI** (Distributed Tracing): `http://localhost:16686`
    -   **Prometheus UI** (Metrics): `http://localhost:9090`
    -   **Grafana UI** (Dashboards): `http://localhost:3002` (login: `admin`, password in `.env`)
    -   **Service Metrics**: `http://localhost:3000/metrics`

## ⚙️ Configuration

All configuration is managed via the `.env` file. See `.env.example` for a complete list of available variables.

| Variable                  | Description                                            | Example                                                    |
| ------------------------- | ------------------------------------------------------ | ---------------------------------------------------------- |
| `APP_PORT`                | The port the application will be exposed on.           | `3000`                                                     |
| `POSTGRES_USER`           | PostgreSQL database username.                          | `buildhub`                                                 |
| `POSTGRES_PASSWORD`       | PostgreSQL database password.                          | `bhdbjpak`                                                 |
| `JWT_SECRET`              | **Critical**: A long, random secret for signing JWTs.  | `generate_a_strong_random_key_here`                        |
| `SMTP_USERNAME`           | Your email account username for sending emails.        | `your-email@gmail.com`                                     |
| `SMTP_PASSWORD`           | Your email account app-specific password.              | `your-google-app-password`                                 |
| `OTEL_ENABLED`            | Set to `true` to enable OpenTelemetry tracing.         | `true`                                                     |

## 🗂️ Project Structure

```
.
├── src/                  # Application source code
│   ├── app.rs            # Axum router and application state
│   ├── main.rs           # Application entry point and setup
│   ├── config/           # Database, Redis, and OTel configuration
│   ├── db/               # Diesel schema and data models
│   ├── handlers/         # HTTP request handlers and business logic
│   ├── middleware/       # JWT auth, rate limiting, telemetry
│   └── utils/            # Shared utilities (hashing, validation, etc.)
├── migrations/           # Diesel database migrations
├── .env.example          # Example environment file
├── .gitignore            # Files and directories to ignore
├── Cargo.toml            # Rust project definition
├── Dockerfile            # Multi-stage Docker build instructions
├── docker-compose.yml    # Service orchestration for all environments
└── prometheus.yml        # Prometheus scrape configuration
```

## 📝 License

This project is licensed under the MIT License. See the `LICENSE` file for details.
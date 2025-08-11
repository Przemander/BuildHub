#!/bin/bash
# filepath: /home/przemander/projects/BuildHub/backend/auth-service/scripts/docker-run.sh

set -e

echo "🚀 Starting BuildHub Auth Service with Docker Compose"

# Check if .env.docker exists, if not create from template
if [ ! -f .env.docker ]; then
    echo "Creating .env.docker from template..."
    cp .env.docker.example .env.docker 2>/dev/null || cp .env.production .env.docker
fi

# Use the Docker environment file
export ENV_FILE=.env.docker

# Parse command
COMMAND=${1:-up}

case $COMMAND in
    up)
        echo "Starting services..."
        docker compose --env-file $ENV_FILE up --build
        ;;
    down)
        echo "Stopping services..."
        docker compose --env-file $ENV_FILE down
        ;;
    logs)
        echo "Showing logs..."
        docker compose --env-file $ENV_FILE logs -f ${2:-auth-service}
        ;;
    restart)
        echo "Restarting services..."
        docker compose --env-file $ENV_FILE restart ${2:-}
        ;;
    rebuild)
        echo "Rebuilding and starting services..."
        docker compose --env-file $ENV_FILE up --build --force-recreate
        ;;
    monitoring)
        echo "Starting with monitoring stack..."
        docker compose --env-file $ENV_FILE --profile monitoring up --build
        ;;
    clean)
        echo "Cleaning up everything (including volumes)..."
        docker compose --env-file $ENV_FILE down -v
        ;;
    ps)
        echo "Service status:"
        docker compose --env-file $ENV_FILE ps
        ;;
    test)
        echo "Testing endpoints..."
        sleep 5
        echo "Health check:"
        curl -s http://localhost:3000/health || echo "Failed"
        echo -e "\nReadiness check:"
        curl -s http://localhost:3000/readiness || echo "Failed"
        echo -e "\nMetrics sample:"
        curl -s http://localhost:3000/metrics | head -20 || echo "Failed"
        ;;
    *)
        echo "Usage: $0 {up|down|logs|restart|rebuild|monitoring|clean|ps|test}"
        exit 1
        ;;
esac
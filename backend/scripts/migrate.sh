#!/bin/bash
# Migration script for database
set -e

echo "Running database migrations..."
DB_URL=${DATABASE_URL:-"postgres://postgres:postgres@localhost:5432/redteam?sslmode=disable"}

if command -v migrate &> /dev/null; then
    migrate -path ./migrations -database "$DB_URL" up
else
    echo "golang-migrate not installed. Installing..."
    go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest
    migrate -path ./migrations -database "$DB_URL" up
fi

echo "Migrations completed successfully!"

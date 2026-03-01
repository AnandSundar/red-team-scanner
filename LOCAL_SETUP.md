# Running Without Docker - Local Setup Guide

This guide explains how to run the Red Team Scanner frontend and backend without using Docker.

## Prerequisites

### 1. Install PostgreSQL
- Download from: https://www.postgresql.org/download/windows/
- During installation:
  - Set password to `postgres` (or remember what you set)
  - Keep default port `5432`
  - Install pgAdmin (optional, for GUI management)

### 2. Install Redis
- Download from: https://github.com/microsoftarchive/redis/releases
- Download `Redis-x64-3.0.504.msi` and install
- Redis will run as a Windows service on port `6379`

### 3. Install Go
- Download from: https://go.dev/dl/
- Choose the Windows installer
- Verify: `go version`

### 4. Install Node.js
- Download from: https://nodejs.org/ (LTS version)
- Verify: `node --version` and `npm --version`

---

## Step 1: Start PostgreSQL and Redis Services

Make sure these Windows services are running:
1. Open Services (Win + R, type `services.msc`)
2. Find and start:
   - `postgresql-x64-XX` (PostgreSQL)
   - `Redis` (Redis)

---

## Step 2: Create the Database

Open pgAdmin or psql and run:

```sql
CREATE DATABASE redteam;
```

Or use command line:
```cmd
psql -U postgres -c "CREATE DATABASE redteam;"
```

---

## Step 3: Run the Backend

```cmd
:: Navigate to backend
cd backend

:: Copy environment file
copy .env.development .env

:: Edit .env file - update DATABASE_URL for local PostgreSQL
:: Change from:
::   DATABASE_URL=postgres://postgres:postgres@postgres:5432/redteam?sslmode=disable
:: To:
::   DATABASE_URL=postgres://postgres:postgres@localhost:5432/redteam?sslmode=disable

:: Install Go dependencies
go mod download

:: Run database migrations
go run backend/scripts/migrate.go up

:: Start the backend server
go run backend/cmd/server/main.go
```

**Backend will be available at:** http://localhost:8080

---

## Step 4: Run the Frontend

Open a **new terminal**:

```cmd
:: Navigate to frontend
cd frontend

:: Install dependencies (if not already installed)
npm install

:: Copy environment file
copy .env.local.example .env.local

:: Start the development server
npm run dev
```

**Frontend will be available at:** http://localhost:3000

---

## Quick Start Script (Windows)

Save this as `start-local.bat` in the project root:

```batch
@echo off
echo Starting Red Team Scanner locally...

:: Start Backend
echo.
echo [1/2] Starting Backend...
cd backend
copy /Y .env.development .env >nul 2>&1
echo DATABASE_URL=postgres://postgres:postgres@localhost:5432/redteam?sslmode=disable > .env.local
go mod download
go run scripts/migrate.go up
go run cmd/server/main.go &
cd ..

:: Start Frontend
echo.
echo [2/2] Starting Frontend...
cd frontend
copy /Y .env.local.example .env.local >nul 2>&1
npm run dev &
cd ..

echo.
echo ==========================================
echo Red Team Scanner is running!
echo Frontend: http://localhost:3000
echo Backend:  http://localhost:8080
echo ==========================================
pause
```

---

## Environment Variables

### Backend (.env file)

```
DATABASE_URL=postgres://postgres:postgres@localhost:5432/redteam?sslmode=disable
DATABASE_HOST=localhost
DATABASE_PORT=5432
DATABASE_USER=postgres
DATABASE_PASSWORD=postgres
DATABASE_NAME=redteam

REDIS_URL=localhost:6379
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=

PORT=8080
HOST=0.0.0.0
ENV=development
```

### Frontend (.env.local file)

Copy from `.env.local.example` and update the API URL:

```
NEXT_PUBLIC_API_URL=http://localhost:8080
```

---

## Troubleshooting

### PostgreSQL Connection Refused
- Check if PostgreSQL service is running in Services
- Verify port 5432 is not blocked by firewall
- Check credentials in .env file

### Redis Connection Refused
- Check if Redis service is running in Services
- Try: `redis-cli ping` should return `PONG`

### Port Already in Use
- Backend: Change `PORT` in .env file
- Frontend: Use `npm run dev -- --port 3001`

### Go Module Errors
```cmd
cd backend
go clean -modcache
go mod download
```

### Node Module Errors
```cmd
cd frontend
del /S /Q node_modules
del package-lock.json
npm install
```

---

## Access the Application

Once both services are running:

- **Frontend:** http://localhost:3000
- **Backend API:** http://localhost:8080
- **API Documentation:** http://localhost:8080/api/docs (if available)

---

## Stopping the Services

Press `Ctrl+C` in each terminal window to stop the servers.

To stop PostgreSQL and Redis services:
- Open Services (Win + R, type `services.msc`)
- Stop `postgresql-x64-XX` and `Redis` services

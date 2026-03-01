@echo off
echo ==========================================
echo Red Team Scanner - Local Development
echo ==========================================
echo.

:: Check prerequisites
echo Checking prerequisites...

where go >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Go is not installed. Please install Go 1.23+
    echo Download from: https://go.dev/dl/
    pause
    exit /b 1
)

where node >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Node.js is not installed. Please install Node.js 18+
    echo Download from: https://nodejs.org/
    pause
    exit /b 1
)

echo [OK] Prerequisites found
echo.

:: Backend Setup
echo ==========================================
echo [1/4] Setting up Backend...
echo ==========================================
cd backend

:: Create .env file for local development
if not exist .env (
    echo Creating .env file for local development...
    (
        echo # Database Configuration
        echo DATABASE_URL=postgres://postgres:postgres@localhost:5432/redteam?sslmode=disable
        echo DATABASE_HOST=localhost
        echo DATABASE_PORT=5432
        echo DATABASE_USER=postgres
        echo DATABASE_PASSWORD=postgres
        echo DATABASE_NAME=redteam
        echo DATABASE_SSL_MODE=disable
        echo.
        echo # Redis Configuration
        echo REDIS_URL=localhost:6379
        echo REDIS_HOST=localhost
        echo REDIS_PORT=6379
        echo REDIS_PASSWORD=
        echo REDIS_DB=0
        echo.
        echo # Server Configuration
        echo PORT=8080
        echo HOST=0.0.0.0
        echo ENV=development
        echo DEBUG=true
        echo LOG_LEVEL=debug
        echo.
        echo # Rate Limiting
        echo RATE_LIMIT_REQUESTS=100
        echo RATE_LIMIT_WINDOW=60
    ) > .env
    echo [OK] .env file created
) else (
    echo [OK] .env file already exists
)

:: Download Go dependencies
echo.
echo Installing Go dependencies...
go mod download
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Failed to download Go dependencies
    pause
    exit /b 1
)
echo [OK] Go dependencies installed

cd ..

:: Frontend Setup
echo.
echo ==========================================
echo [2/4] Setting up Frontend...
echo ==========================================
cd frontend

:: Create .env.local file
if not exist .env.local (
    echo Creating .env.local file...
    copy .env.local.example .env.local >nul 2>&1
    echo [OK] .env.local file created
) else (
    echo [OK] .env.local file already exists
)

:: Install npm dependencies
if not exist node_modules (
    echo.
    echo Installing npm dependencies (this may take a few minutes)...
    npm install
    if %ERRORLEVEL% neq 0 (
        echo [ERROR] Failed to install npm dependencies
        pause
        exit /b 1
    )
    echo [OK] npm dependencies installed
) else (
    echo [OK] npm dependencies already installed
)

cd ..

:: Start Backend
echo.
echo ==========================================
echo [3/4] Starting Backend Server...
echo ==========================================
start "Red Team Scanner - Backend" cmd /k "cd backend && echo Starting Backend on http://localhost:8080 && go run cmd/server/main.go"

:: Wait a moment for backend to start
timeout /t 3 /nobreak >nul

:: Start Frontend
echo.
echo ==========================================
echo [4/4] Starting Frontend Server...
echo ==========================================
start "Red Team Scanner - Frontend" cmd /k "cd frontend && npm run dev"

echo.
echo ==========================================
echo Red Team Scanner is starting up!
echo ==========================================
echo.
echo Frontend: http://localhost:3000
echo Backend:  http://localhost:8080
echo.
echo Note: Make sure PostgreSQL and Redis are running!
echo.
echo To stop: Close the terminal windows or press Ctrl+C in each
echo ==========================================
echo.
pause

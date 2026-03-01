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
echo [1/3] Setting up Backend...
echo ==========================================
cd backend

:: Create .env file for local development
if exist .env goto envExists
echo Creating .env file for local development...
echo # Database Configuration > .env
echo DATABASE_URL=postgres://postgres:postgres@localhost:5432/redteam?sslmode=disable >> .env
echo DATABASE_HOST=localhost >> .env
echo DATABASE_PORT=5432 >> .env
echo DATABASE_USER=postgres >> .env
echo DATABASE_PASSWORD=postgres >> .env
echo DATABASE_NAME=redteam >> .env
echo DATABASE_SSL_MODE=disable >> .env
echo. >> .env
echo # Redis Configuration >> .env
echo REDIS_URL=localhost:6379 >> .env
echo REDIS_HOST=localhost >> .env
echo REDIS_PORT=6379 >> .env
echo REDIS_PASSWORD= >> .env
echo REDIS_DB=0 >> .env
echo. >> .env
echo # Server Configuration >> .env
echo PORT=8080 >> .env
echo HOST=0.0.0.0 >> .env
echo ENV=development >> .env
echo DEBUG=true >> .env
echo LOG_LEVEL=debug >> .env
echo. >> .env
echo # Rate Limiting >> .env
echo RATE_LIMIT_REQUESTS=100 >> .env
echo RATE_LIMIT_WINDOW=60 >> .env
echo [OK] .env file created
goto envDone
:envExists
echo [OK] .env file already exists
:envDone

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
echo [2/3] Setting up Frontend...
echo ==========================================
cd frontend

:: Create .env.local file
if exist .env.local goto envLocalExists
echo Creating .env.local file...
copy .env.local.example .env.local >nul 2>&1
echo [OK] .env.local file created
goto envLocalDone
:envLocalExists
echo [OK] .env.local file already exists
:envLocalDone

:: Install npm dependencies
if exist node_modules goto nodeModulesExist
echo.
echo Installing npm dependencies ^(this may take a few minutes^)...
npm install
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Failed to install npm dependencies
    pause
    exit /b 1
)
echo [OK] npm dependencies installed
goto nodeModulesDone
:nodeModulesExist
echo [OK] npm dependencies already installed
:nodeModulesDone

cd ..

:: Start Backend
echo.
echo ==========================================
echo [3/3] Starting Servers...
echo ==========================================
echo Starting Backend on http://localhost:8080
start "Red Team Scanner - Backend" cmd /k "cd backend && go run cmd/server/main.go"

:: Wait a moment for backend to start
timeout /t 3 /nobreak >nul

:: Start Frontend
echo Starting Frontend on http://localhost:3000
start "Red Team Scanner - Frontend" cmd /k "cd frontend && npm run dev"

echo.
echo ==========================================
echo Red Team Scanner is starting up!
echo ==========================================
echo.
echo Frontend: http://localhost:3000
echo Backend:  http://localhost:8080
echo.
echo NOTE: Make sure PostgreSQL and Redis are running!
echo.
echo To stop: Close the terminal windows or press Ctrl+C in each
echo ==========================================
echo.
pause

# Agentic Red Team Scanner

A full-stack SaaS platform for agentic AI-powered red team security testing.

## Architecture

### Backend (Go)
- **API**: RESTful API with Chi router
- **Authentication**: Clerk
- **Database**: PostgreSQL with sqlc
- **Queue**: Redis with Asynq
- **AI**: OpenAI GPT-4 for adaptive testing
- **Modules**:
  - Reconnaissance (subdomain enumeration, port scanning)
  - Web Application Testing (XSS, SQLi, CSRF)
  - API Security Testing (REST/GraphQL)
  - AI-Driven Adaptive Testing (LLM-powered)
  - Threat Intelligence (CVE correlation)

### Frontend (Next.js 15)
- **Framework**: Next.js 15 with App Router
- **Authentication**: Clerk
- **Styling**: Tailwind CSS + shadcn/ui
- **State**: Zustand
- **Features**:
  - Real-time scan updates (SSE)
  - Interactive dashboard
  - Report viewer
  - Scan history

## Quick Start

### Prerequisites
- Go 1.21+
- Node.js 20+
- PostgreSQL 15
- Redis 7
- Docker (optional)

### Development Setup

1. Clone the repository
```bash
git clone https://github.com/redteam/agentic-scanner.git
cd agentic-scanner
```

2. Start infrastructure services
```bash
docker-compose up -d postgres redis
```

3. Setup backend
```bash
cd backend
cp .env.example .env
# Edit .env with your configuration
go mod download
go run cmd/server/main.go
```

4. Setup frontend
```bash
cd frontend
cp .env.local.example .env.local
# Edit .env.local with your configuration
npm install
npm run dev
```

5. Open http://localhost:3000

### Docker Compose (Full Stack)

```bash
# Copy environment variables
cp backend/.env.example backend/.env
cp frontend/.env.local.example frontend/.env.local
# Edit both files with your configuration

# Start all services
docker-compose up -d
```

## Environment Variables

### Backend
- `DATABASE_URL`: PostgreSQL connection string
- `REDIS_URL`: Redis connection string
- `CLERK_SECRET_KEY`: Clerk authentication secret
- `OPENAI_API_KEY`: OpenAI API key

### Frontend
- `NEXT_PUBLIC_API_URL`: Backend API URL
- `NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY`: Clerk public key

## API Documentation

### Scans
- `POST /api/v1/scans` - Create a new scan
- `GET /api/v1/scans` - List scans
- `GET /api/v1/scans/:id` - Get scan details
- `POST /api/v1/scans/:id/stop` - Stop a scan
- `GET /api/v1/scans/:id/report` - Get scan report

### Modules
- `GET /api/v1/modules` - List available modules

### SSE
- `GET /sse/scans/:id/stream` - Real-time scan updates

## Security Considerations

- All scans must be authorized by the target owner
- Built-in blocklist for protected targets (gov, mil, hospitals, schools)
- Comprehensive audit logging
- Rate limiting on API endpoints
- Authentication required for all scan operations

## License

MIT License - See LICENSE file for details

## Contributing

Please read CONTRIBUTING.md for details on our code of conduct and the process for submitting pull requests.
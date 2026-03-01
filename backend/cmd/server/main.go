package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/hibiken/asynq"
	"github.com/joho/godotenv"

	"github.com/redteam/agentic-scanner/internal/api"
	"github.com/redteam/agentic-scanner/internal/auth"
	"github.com/redteam/agentic-scanner/internal/queue"
	"github.com/redteam/agentic-scanner/internal/scanner"
	"github.com/redteam/agentic-scanner/internal/store"
)

func main() {
	// Load environment variables
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using system environment variables")
	}

	// Initialize database connection
	db, err := store.NewDB(os.Getenv("DATABASE_URL"))
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	// Initialize Redis/Asynq client
	redisOpt := asynq.RedisClientOpt{
		Addr: os.Getenv("REDIS_URL"),
	}

	// Initialize task queue
	taskQueue := queue.NewClient(redisOpt)
	defer taskQueue.Close()

	// Initialize scanner orchestrator
	orchestrator := scanner.NewOrchestrator(db, taskQueue)

	// Initialize auth middleware
	authMiddleware := auth.NewMiddleware(auth.MiddlewareConfig{
		ClerkClient: nil, // Will be initialized from secret key internally
	})

	// Setup router
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Timeout(60 * time.Second))

	// Health check
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"healthy"}`))
	})

	// API routes
	apiRouter := chi.NewRouter()
	api.SetupRoutes(apiRouter, orchestrator, db, authMiddleware)
	r.Mount("/api/v1", apiRouter)

	// SSE routes for live scan updates
	sseRouter := chi.NewRouter()
	api.SetupSSERoutes(sseRouter, orchestrator, db, authMiddleware)
	r.Mount("/sse", sseRouter)

	// Create HTTP server
	srv := &http.Server{
		Addr:         ":8080",
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in a goroutine
	go func() {
		log.Printf("Server starting on %s", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server failed to start: %v", err)
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")

	// Graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	log.Println("Server exited")
}

package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/redteam/agentic-scanner/internal/auth"
	"github.com/redteam/agentic-scanner/internal/scanner"
	"github.com/redteam/agentic-scanner/internal/store"
)

// SSEClient represents a connected SSE client
type SSEClient struct {
	scanID uuid.UUID
	userID string
	ch     chan []byte
	done   chan struct{}
}

// SSEHub manages SSE connections
type SSEHub struct {
	clients    map[string]*SSEClient
	register   chan *SSEClient
	unregister chan *SSEClient
	broadcast  chan []byte
	shutdown   chan struct{}
}

// NewSSEHub creates a new SSE hub
func NewSSEHub() *SSEHub {
	return &SSEHub{
		clients:    make(map[string]*SSEClient),
		register:   make(chan *SSEClient),
		unregister: make(chan *SSEClient),
		broadcast:  make(chan []byte, 256),
		shutdown:   make(chan struct{}),
	}
}

// Run starts the SSE hub event loop
func (h *SSEHub) Run() {
	ticker := time.NewTicker(30 * time.Second) // Heartbeat ticker
	defer ticker.Stop()

	for {
		select {
		case client := <-h.register:
			h.clients[client.scanID.String()] = client

		case client := <-h.unregister:
			if _, ok := h.clients[client.scanID.String()]; ok {
				delete(h.clients, client.scanID.String())
				close(client.ch)
			}

		case message := <-h.broadcast:
			for id, client := range h.clients {
				select {
				case client.ch <- message:
				case <-time.After(100 * time.Millisecond):
					// Client is slow, remove it
					delete(h.clients, id)
					close(client.ch)
				}
			}

		case <-ticker.C:
			// Send heartbeat to all clients
			heartbeat := []byte(":heartbeat\n\n")
			for id, client := range h.clients {
				select {
				case client.ch <- heartbeat:
				default:
					delete(h.clients, id)
					close(client.ch)
				}
			}

		case <-h.shutdown:
			return
		}
	}
}

// Publish publishes an event to all connected clients
func (h *SSEHub) Publish(event []byte) {
	select {
	case h.broadcast <- event:
	case <-time.After(100 * time.Millisecond):
		// Broadcast channel full, drop message
	}
}

// Stop stops the SSE hub
func (h *SSEHub) Stop() {
	close(h.shutdown)
}

// ScanEvent represents a scan update event for SSE
type ScanEvent struct {
	Type      string          `json:"type"`
	ScanID    string          `json:"scan_id"`
	Timestamp time.Time       `json:"timestamp"`
	Payload   json.RawMessage `json:"payload"`
}

// ScanStreamHandler handles SSE stream requests
func ScanStreamHandler(hub *SSEHub, db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// Parse scan ID
		scanID := chi.URLParam(r, "id")
		id, err := uuid.Parse(scanID)
		if err != nil {
			http.Error(w, "Invalid scan ID", http.StatusBadRequest)
			return
		}

		// Get user from context
		user := auth.GetUserFromContext(ctx)
		if user == nil {
			http.Error(w, "Authentication required", http.StatusUnauthorized)
			return
		}

		// Verify scan ownership
		if err := db.SetUserContext(ctx, user.ClerkUserID, user.ID); err != nil {
			http.Error(w, "Failed to set user context", http.StatusInternalServerError)
			return
		}

		scanJob, err := db.GetScanJobByID(ctx, id)
		if err != nil {
			http.Error(w, "Scan not found", http.StatusNotFound)
			return
		}

		if scanJob.UserID != user.ID {
			http.Error(w, "Not authorized to access this scan", http.StatusForbidden)
			return
		}

		// Set SSE headers
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("X-Accel-Buffering", "no") // Disable Nginx buffering

		// Handle Last-Event-ID for reconnection
		lastEventID := r.Header.Get("Last-Event-ID")
		if lastEventID == "" {
			lastEventID = r.URL.Query().Get("last_event_id")
		}
		_ = lastEventID // Could be used to replay missed events from Redis

		// Create flusher
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "Streaming not supported", http.StatusInternalServerError)
			return
		}

		// Create client
		client := &SSEClient{
			scanID: id,
			userID: user.ID.String(),
			ch:     make(chan []byte, 256),
			done:   make(chan struct{}),
		}

		hub.register <- client
		defer func() {
			hub.unregister <- client
			close(client.done)
		}()

		// Send initial connection event
		fmt.Fprintf(w, "event: connected\n")
		fmt.Fprintf(w, "id: %s\n", uuid.New().String())
		fmt.Fprintf(w, "data: %s\n\n", `{"status":"connected","scan_id":"`+scanID+`"}`)
		flusher.Flush()

		// Send current scan status
		statusData, _ := json.Marshal(map[string]interface{}{
			"status":   scanJob.Status,
			"target":   scanJob.Target,
			"progress": 0,
		})
		fmt.Fprintf(w, "event: scan.status\n")
		fmt.Fprintf(w, "id: %s\n", uuid.New().String())
		fmt.Fprintf(w, "data: %s\n\n", statusData)
		flusher.Flush()

		// Main event loop
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-r.Context().Done():
				// Client disconnected
				return

			case <-client.done:
				return

			case msg, ok := <-client.ch:
				if !ok {
					return
				}
				// Write event
				fmt.Fprintf(w, "id: %s\n", uuid.New().String())
				fmt.Fprintf(w, "data: %s\n\n", msg)
				flusher.Flush()

			case <-ticker.C:
				// Send heartbeat comment
				fmt.Fprintf(w, ":heartbeat %d\n\n", time.Now().Unix())
				flusher.Flush()
			}
		}
	}
}

// SetupSSERoutes configures SSE routes
func SetupSSERoutes(r chi.Router, orchestrator *scanner.Orchestrator, db *store.DB, authMiddleware *auth.Middleware) {
	hub := NewSSEHub()
	go hub.Run()

	// Set the hub on the orchestrator for publishing events
	orchestrator.SetSSEHub(hub)

	r.Group(func(r chi.Router) {
		r.Use(authMiddleware.RequireAuth())
		r.Get("/scans/{id}/stream", ScanStreamHandler(hub, db))
	})
}

// BroadcastScanEvent broadcasts a scan event to all connected clients
func (h *SSEHub) BroadcastScanEvent(eventType scanner.ScanEventType, scanID uuid.UUID, data interface{}) {
	event := scanner.ScanEvent{
		Type:      eventType,
		ScanID:    scanID,
		Timestamp: time.Now(),
	}

	if data != nil {
		event.Data, _ = json.Marshal(data)
	}

	eventJSON, _ := json.Marshal(event)
	h.Publish(eventJSON)
}

// Helper function to convert interface{} to JSON
func toJSON(v interface{}) string {
	data, _ := json.Marshal(v)
	return string(data)
}

// Helper to convert string to int
func atoi(s string) int {
	i, _ := strconv.Atoi(s)
	return i
}

// Legacy SSE handler for backward compatibility
func handleSSEStream(hub *SSEHub, orchestrator *scanner.Orchestrator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		scanID := chi.URLParam(r, "id")
		id, err := uuid.Parse(scanID)
		if err != nil {
			http.Error(w, "Invalid scan ID", http.StatusBadRequest)
			return
		}

		userID := auth.GetUserIDFromContext(r.Context())

		// Set SSE headers
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("Access-Control-Allow-Origin", "*")

		// Create client
		client := &SSEClient{
			scanID: id,
			userID: userID,
			ch:     make(chan []byte, 256),
			done:   make(chan struct{}),
		}
		hub.register <- client
		defer func() { hub.unregister <- client }()

		// Send initial connection event
		fmt.Fprintf(w, "event: connected\ndata: %s\n\n", `{"status":"connected"}`)
		w.(http.Flusher).Flush()

		// Send heartbeat and listen for events
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-r.Context().Done():
				return
			case msg, ok := <-client.ch:
				if !ok {
					return
				}
				fmt.Fprintf(w, "data: %s\n\n", msg)
				w.(http.Flusher).Flush()
			case <-ticker.C:
				fmt.Fprintf(w, ":heartbeat\n\n")
				w.(http.Flusher).Flush()
			}
		}
	}
}

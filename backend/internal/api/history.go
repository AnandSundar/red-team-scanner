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

// ============================================================================
// History Request/Response Types
// ============================================================================

// HistoryListRequest represents query parameters for listing scan history
type HistoryListRequest struct {
	Status    string `json:"status,omitempty"`
	Target    string `json:"target,omitempty"`
	StartDate string `json:"start_date,omitempty"`
	EndDate   string `json:"end_date,omitempty"`
	Limit     int    `json:"limit,omitempty"`
	Offset    int    `json:"offset,omitempty"`
	SortBy    string `json:"sort_by,omitempty"`
	SortOrder string `json:"sort_order,omitempty"`
}

// HistoryItem represents a single scan history entry
type HistoryItem struct {
	ID              string           `json:"id"`
	Target          string           `json:"target"`
	TargetType      string           `json:"target_type"`
	Status          string           `json:"status"`
	Scope           string           `json:"scope"`
	FindingsCount   map[string]int64 `json:"findings_count"`
	TotalFindings   int64            `json:"total_findings"`
	RiskScore       float64          `json:"risk_score"`
	StartedAt       *time.Time       `json:"started_at,omitempty"`
	CompletedAt     *time.Time       `json:"completed_at,omitempty"`
	DurationSeconds int              `json:"duration_seconds"`
	CreatedAt       time.Time        `json:"created_at"`
	CanRerun        bool             `json:"can_rerun"`
}

// HistoryListResponse represents the response for listing scan history
type HistoryListResponse struct {
	Scans      []HistoryItem `json:"scans"`
	Total      int64         `json:"total"`
	Page       int           `json:"page"`
	PageSize   int           `json:"page_size"`
	TotalPages int           `json:"total_pages"`
}

// TargetHistoryResponse represents scan history for a specific target
type TargetHistoryResponse struct {
	Target     string        `json:"target"`
	ScanCount  int64         `json:"scan_count"`
	Scans      []HistoryItem `json:"scans"`
	Total      int64         `json:"total"`
	Page       int           `json:"page"`
	PageSize   int           `json:"page_size"`
	TotalPages int           `json:"total_pages"`
}

// RerunScanResponse represents the response for rerunning a scan
type RerunScanResponse struct {
	NewScanID string    `json:"new_scan_id"`
	Target    string    `json:"target"`
	Status    string    `json:"status"`
	Message   string    `json:"message"`
	CreatedAt time.Time `json:"created_at"`
}

// ============================================================================
// History Handlers
// ============================================================================

// ListHistoryHandler handles GET /api/v1/history
// Lists all scans with filtering and pagination
func (h *Handler) ListHistoryHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get user from context
	user := auth.GetUserFromContext(ctx)
	if user == nil {
		respondError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	// Parse query parameters
	req := parseHistoryListRequest(r)

	// Set RLS context
	if err := h.db.SetUserContext(ctx, user.ClerkUserID, user.ID); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to set user context")
		return
	}

	// Build filter params
	filter := store.HistoryFilter{
		UserID:    user.ID,
		Status:    req.Status,
		Target:    req.Target,
		Limit:     int32(req.Limit),
		Offset:    int32(req.Offset),
		SortBy:    req.SortBy,
		SortOrder: req.SortOrder,
	}

	// Parse date range
	if req.StartDate != "" {
		if startDate, err := time.Parse("2006-01-02", req.StartDate); err == nil {
			filter.StartDate = &startDate
		}
	}
	if req.EndDate != "" {
		if endDate, err := time.Parse("2006-01-02", req.EndDate); err == nil {
			// Set to end of day
			endOfDay := endDate.Add(24*time.Hour - time.Second)
			filter.EndDate = &endOfDay
		}
	}

	// Get filtered history
	scans, total, err := h.db.GetScanHistory(ctx, filter)
	if err != nil {
		respondError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to get scan history: %v", err))
		return
	}

	// Build response
	items := make([]HistoryItem, 0, len(scans))
	for _, scan := range scans {
		items = append(items, historyItemFromScanJob(scan))
	}

	totalPages := int(total) / req.Limit
	if int(total)%req.Limit > 0 {
		totalPages++
	}

	page := (req.Offset / req.Limit) + 1

	respondJSON(w, http.StatusOK, HistoryListResponse{
		Scans:      items,
		Total:      total,
		Page:       page,
		PageSize:   req.Limit,
		TotalPages: totalPages,
	})
}

// GetTargetHistoryHandler handles GET /api/v1/history/:target
// Gets scan history for a specific target
func (h *Handler) GetTargetHistoryHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get user from context
	user := auth.GetUserFromContext(ctx)
	if user == nil {
		respondError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	// Get target from URL parameter
	target := chi.URLParam(r, "target")
	if target == "" {
		respondError(w, http.StatusBadRequest, "Target is required")
		return
	}

	// Parse pagination parameters
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 100 {
		limit = 20
	}

	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if offset < 0 {
		offset = 0
	}

	// Set RLS context
	if err := h.db.SetUserContext(ctx, user.ClerkUserID, user.ID); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to set user context")
		return
	}

	// Get target scan history
	scans, total, err := h.db.GetTargetScanHistory(ctx, user.ID, target, int32(limit), int32(offset))
	if err != nil {
		respondError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to get target history: %v", err))
		return
	}

	// Build response
	items := make([]HistoryItem, 0, len(scans))
	for _, scan := range scans {
		items = append(items, historyItemFromScanJob(scan))
	}

	totalPages := int(total) / limit
	if int(total)%limit > 0 {
		totalPages++
	}

	page := (offset / limit) + 1

	respondJSON(w, http.StatusOK, TargetHistoryResponse{
		Target:     target,
		ScanCount:  total,
		Scans:      items,
		Total:      total,
		Page:       page,
		PageSize:   limit,
		TotalPages: totalPages,
	})
}

// RerunScanHandler handles POST /api/v1/scans/:id/rerun
// Reruns a scan with the same configuration
func (h *Handler) RerunScanHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse scan ID from URL
	scanID := chi.URLParam(r, "id")
	id, err := uuid.Parse(scanID)
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid scan ID")
		return
	}

	// Get user from context
	user := auth.GetUserFromContext(ctx)
	if user == nil {
		respondError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	// Set RLS context
	if err := h.db.SetUserContext(ctx, user.ClerkUserID, user.ID); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to set user context")
		return
	}

	// Get the original scan
	originalScan, err := h.db.GetScanJobByID(ctx, id)
	if err != nil {
		respondError(w, http.StatusNotFound, "Scan not found")
		return
	}

	// Verify ownership
	if originalScan.UserID != user.ID {
		respondError(w, http.StatusForbidden, "Access denied")
		return
	}

	// Parse optional override parameters
	var overrides struct {
		Scope         *string           `json:"scope,omitempty"`
		CustomHeaders map[string]string `json:"custom_headers,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&overrides); err != nil {
		// Ignore decode errors - overrides are optional
	}

	// Create new scan with same configuration
	scope := originalScan.Scope
	if overrides.Scope != nil {
		scope = *overrides.Scope
	}

	var customHeaders json.RawMessage
	if overrides.CustomHeaders != nil {
		headers, _ := json.Marshal(overrides.CustomHeaders)
		customHeaders = headers
	} else if originalScan.CustomHeaders != nil {
		customHeaders = originalScan.CustomHeaders
	}

	// Create new scan job
	createParams := store.CreateScanJobParams{
		UserID:          user.ID,
		Target:          originalScan.Target,
		TargetType:      originalScan.TargetType,
		Scope:           scope,
		Status:          string(scanner.ScanStatusPending),
		AuthConfirmed:   false,
		AuthConfirmedIP: "",
		CustomHeaders:   customHeaders,
	}

	newScan, err := h.db.CreateScanJob(ctx, createParams)
	if err != nil {
		respondError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to create scan: %v", err))
		return
	}

	// Start the scan using the orchestrator
	scanConfig := scanner.ScanConfig{
		UserID:        user.ID.String(),
		Target:        originalScan.Target,
		TargetType:    scanner.TargetType(originalScan.TargetType),
		Scope:         scope,
		Modules:       []string{"recon", "web", "api"}, // Default modules for rerun
		Depth:         1,
		MaxDuration:   30 * time.Minute,
		AuthConfirmed: false,
	}

	if customHeaders != nil {
		var headers map[string]string
		if err := json.Unmarshal(customHeaders, &headers); err == nil {
			scanConfig.CustomHeaders = headers
		}
	}

	if err := h.orchestrator.EnqueueScan(ctx, newScan.ID, scanConfig); err != nil {
		// Update scan status to failed
		h.db.UpdateScanJobFailed(ctx, newScan.ID)
		respondError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to start scan: %v", err))
		return
	}

	respondJSON(w, http.StatusCreated, RerunScanResponse{
		NewScanID: newScan.ID.String(),
		Target:    newScan.Target,
		Status:    newScan.Status,
		Message:   "Scan rerun started successfully",
		CreatedAt: newScan.CreatedAt,
	})
}

// ============================================================================
// Helper Functions
// ============================================================================

// parseHistoryListRequest parses query parameters into HistoryListRequest
func parseHistoryListRequest(r *http.Request) HistoryListRequest {
	req := HistoryListRequest{
		Status:    r.URL.Query().Get("status"),
		Target:    r.URL.Query().Get("target"),
		StartDate: r.URL.Query().Get("start_date"),
		EndDate:   r.URL.Query().Get("end_date"),
		SortBy:    r.URL.Query().Get("sort_by"),
		SortOrder: r.URL.Query().Get("sort_order"),
	}

	// Parse limit with default
	limit, err := strconv.Atoi(r.URL.Query().Get("limit"))
	if err != nil || limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}
	req.Limit = limit

	// Parse offset with default
	offset, err := strconv.Atoi(r.URL.Query().Get("offset"))
	if err != nil || offset < 0 {
		offset = 0
	}
	req.Offset = offset

	// Default sort
	if req.SortBy == "" {
		req.SortBy = "created_at"
	}
	if req.SortOrder == "" {
		req.SortOrder = "desc"
	}

	return req
}

// historyItemFromScanJob converts a ScanJob to HistoryItem
func historyItemFromScanJob(scan *store.ScanJobWithStats) HistoryItem {
	item := HistoryItem{
		ID:         scan.ID.String(),
		Target:     scan.Target,
		TargetType: scan.TargetType,
		Status:     scan.Status,
		Scope:      scan.Scope,
		CreatedAt:  scan.CreatedAt,
		CanRerun:   true, // Most scans can be rerun
	}

	// Parse finding counts
	if scan.FindingCounts != nil {
		var counts map[string]int64
		if err := json.Unmarshal(scan.FindingCounts, &counts); err == nil {
			item.FindingsCount = counts
			// Calculate total
			for _, v := range counts {
				item.TotalFindings += v
			}
		}
	}

	// Set risk score
	item.RiskScore = float64(scan.RiskScore) / 10.0

	// Set timestamps
	if scan.StartedAt != nil {
		item.StartedAt = scan.StartedAt
	}
	if scan.CompletedAt != nil {
		item.CompletedAt = scan.CompletedAt
	}

	// Calculate duration
	if scan.StartedAt != nil {
		endTime := time.Now()
		if scan.CompletedAt != nil {
			endTime = *scan.CompletedAt
		}
		item.DurationSeconds = int(endTime.Sub(*scan.StartedAt).Seconds())
	}

	// Determine if scan can be rerun
	terminalStatuses := map[string]bool{
		"completed": true,
		"failed":    true,
		"cancelled": true,
		"stopped":   true,
	}
	item.CanRerun = terminalStatuses[scan.Status]

	return item
}

// ============================================================================
// Store Types (defined in store package)
// ============================================================================

// HistoryFilter represents filter parameters for scan history
type HistoryFilter struct {
	UserID    uuid.UUID
	Status    string
	Target    string
	StartDate *time.Time
	EndDate   *time.Time
	Limit     int32
	Offset    int32
	SortBy    string
	SortOrder string
}

// ScanJobWithStats extends ScanJob with computed statistics
type ScanJobWithStats struct {
	store.ScanJob
	TotalFindings int64
}

// ensureStoreTypes ensures store types are available
var _ store.HistoryFilter = store.HistoryFilter{}
var _ *store.ScanJobWithStats = nil

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
	"github.com/redteam/agentic-scanner/internal/compliance"
	"github.com/redteam/agentic-scanner/internal/modules"
	"github.com/redteam/agentic-scanner/internal/report"
	"github.com/redteam/agentic-scanner/internal/scanner"
	"github.com/redteam/agentic-scanner/internal/store"
)

// Handler holds all HTTP handlers
type Handler struct {
	orchestrator *scanner.Orchestrator
	db           *store.DB
	blocklist    *compliance.Blocklist
	auditLogger  *compliance.AuditLogger
	storage      report.StorageClient
}

// NewHandler creates a new handler instance
func NewHandler(orchestrator *scanner.Orchestrator, db *store.DB) *Handler {
	storage, _ := report.NewStorageClient()
	return &Handler{
		orchestrator: orchestrator,
		db:           db,
		blocklist:    compliance.NewBlocklist(),
		auditLogger:  compliance.NewAuditLoggerSimple(),
		storage:      storage,
	}
}

// CreateScanRequest represents a request to start a new scan
// This type alias is for backward compatibility
type CreateScanRequest scanner.CreateScanRequest

// ScanResponse represents a scan creation response
type ScanResponse struct {
	ID        string    `json:"id"`
	Target    string    `json:"target"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
}

// CreateScanHandler handles POST /api/v1/scans
// Creates a new scan job with full validation
func (h *Handler) CreateScanHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse request body
	var req scanner.CreateScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Validate request
	if err := req.Validate(); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Get user from context (set by auth middleware)
	user := auth.GetUserFromContext(ctx)
	if user == nil {
		respondError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	// Set RLS context for database operations
	if err := h.db.SetUserContext(ctx, user.ClerkUserID, user.ID); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to set user context")
		return
	}

	// Validate target format
	targetType, err := scanner.ValidateTarget(req.Target)
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid target format")
		return
	}

	// Get client info for audit logging early
	clientIP := r.Header.Get("X-Forwarded-For")
	if clientIP == "" {
		clientIP = r.RemoteAddr
	}
	userAgent := r.Header.Get("User-Agent")

	// Check blocklist BEFORE creating scan job
	blockResult := h.blocklist.IsAllowed(req.Target)
	if !blockResult.Allowed {
		// Log the block attempt for compliance
		h.auditLogger.LogBlockAttempt(ctx, user.ID.String(), req.Target, string(blockResult.Reason), clientIP, userAgent)
		respondError(w, http.StatusForbidden, blockResult.Message)
		return
	}

	// Check RFC1918 (private) and loopback addresses
	if h.blocklist.IsRFC1918(req.Target) || h.blocklist.IsLoopback(req.Target) {
		// Log the block attempt
		reason := "RFC1918 private or loopback address"
		h.auditLogger.LogBlockAttempt(ctx, user.ID.String(), req.Target, reason, clientIP, userAgent)
		respondError(w, http.StatusForbidden, "Scan blocked: Target is in a restricted IP range. This scan has been logged for compliance.")
		return
	}

	// Check if authorization is confirmed
	if !req.AuthConfirmed {
		respondError(w, http.StatusForbidden, "Authorization confirmation required before scanning.")
		return
	}

	// Log authorization confirmation with full context
	h.auditLogger.LogAuthConfirmed(ctx, user.ID.String(), uuid.Nil, req.Target, clientIP, userAgent)

	// Validate user tier limits
	tierLimits := scanner.GetTierLimits(string(user.Tier))

	// Check if modules are allowed for user's tier
	if len(req.Modules) > 0 {
		invalidModules := tierLimits.ValidateModules(req.Modules)
		if len(invalidModules) > 0 {
			respondError(w, http.StatusForbidden, fmt.Sprintf("Modules not allowed on your tier: %v", invalidModules))
			return
		}
	}

	// Validate scope
	if !tierLimits.ValidateScope(req.Scope) {
		respondError(w, http.StatusForbidden, fmt.Sprintf("Scope '%s' not allowed on your tier", req.Scope))
		return
	}

	// Check concurrent scan limit
	activeScans, err := h.db.CountActiveScansByUser(ctx, user.ID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to check concurrent scans")
		return
	}
	if activeScans >= int64(tierLimits.MaxConcurrentScans) {
		respondError(w, http.StatusTooManyRequests, "Maximum concurrent scans reached for your tier")
		return
	}

	// Convert custom headers to JSON
	var customHeadersJSON []byte
	if len(req.CustomHeaders) > 0 {
		customHeadersJSON, _ = json.Marshal(req.CustomHeaders)
	}

	// Create scan job in database
	scanJob, err := h.db.CreateScanJob(ctx, store.CreateScanJobParams{
		UserID:          user.ID,
		Target:          req.Target,
		TargetType:      string(targetType),
		Scope:           req.Scope,
		Status:          string(scanner.ScanStatusPending),
		AuthConfirmed:   req.AuthConfirmed,
		AuthConfirmedIP: clientIP,
		CustomHeaders:   customHeadersJSON,
	})
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to create scan job")
		return
	}

	// Log audit event with authorization confirmation
	h.auditLogger.LogScanInitiation(ctx, compliance.ScanInitiationLog{
		UserID:               user.ID.String(),
		ClerkUserID:          user.ClerkUserID,
		ScanID:               scanJob.ID,
		Target:               req.Target,
		TargetType:           string(targetType),
		AuthConfirmed:        req.AuthConfirmed,
		AuthConfirmedIP:      clientIP,
		AuthConfirmedAt:      time.Now(),
		UserAgent:            userAgent,
		Tier:                 string(user.Tier),
		Modules:              req.Modules,
		Scope:                req.Scope,
		CustomHeadersPresent: len(req.CustomHeaders) > 0,
	})

	// Enqueue scan task to Asynq
	if err := h.orchestrator.EnqueueScan(ctx, scanJob.ID, scanner.ScanConfig{
		UserID:        user.ID.String(),
		Target:        req.Target,
		TargetType:    targetType,
		Scope:         req.Scope,
		Modules:       req.Modules,
		Depth:         req.Depth,
		AISeverity:    req.AISeverity,
		MaxDuration:   time.Duration(req.MaxDuration) * time.Second,
		AuthConfirmed: req.AuthConfirmed,
		CustomHeaders: req.CustomHeaders,
		ClientIP:      clientIP,
		UserAgent:     userAgent,
	}); err != nil {
		// Update scan status to failed
		h.db.UpdateScanJobFailed(ctx, scanJob.ID)
		respondError(w, http.StatusInternalServerError, "Failed to enqueue scan task")
		return
	}

	// Return response
	respondJSON(w, http.StatusCreated, ScanResponse{
		ID:        scanJob.ID.String(),
		Target:    scanJob.Target,
		Status:    scanJob.Status,
		CreatedAt: scanJob.CreatedAt,
	})
}

// GetScanHandler handles GET /api/v1/scans/:id
// Retrieves scan details with authorization check
func (h *Handler) GetScanHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse scan ID
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

	// Retrieve scan from database
	scanJob, err := h.db.GetScanJobByID(ctx, id)
	if err != nil {
		respondError(w, http.StatusNotFound, "Scan not found")
		return
	}

	// Build response
	response := scanner.GetScanResponse{
		ID:         scanJob.ID,
		Target:     scanJob.Target,
		TargetType: scanJob.TargetType,
		Status:     scanJob.Status,
		CreatedAt:  scanJob.CreatedAt,
	}

	if scanJob.StartedAt != nil {
		response.StartedAt = scanJob.StartedAt
	}
	if scanJob.CompletedAt != nil {
		response.CompletedAt = scanJob.CompletedAt
	}

	// Calculate duration
	if scanJob.StartedAt != nil {
		if scanJob.CompletedAt != nil {
			response.DurationSeconds = int(scanJob.CompletedAt.Sub(*scanJob.StartedAt).Seconds())
		} else if scanner.ScanStatus(scanJob.Status).IsActive() {
			response.DurationSeconds = int(time.Since(*scanJob.StartedAt).Seconds())
		}
	}

	// Add progress if scan is running
	if scanner.ScanStatus(scanJob.Status).IsActive() {
		progress := h.orchestrator.GetScanProgress(id)
		if progress != nil {
			response.Progress = progress
		}
	}

	// Add summary if scan has findings
	if scanJob.FindingCounts != nil {
		var counts map[string]int
		if err := json.Unmarshal(scanJob.FindingCounts, &counts); err == nil {
			response.Summary = &scanner.ScanSummary{
				BySeverity: counts,
				RiskScore:  float64(scanJob.RiskScore) / 10.0,
			}
		}
	}

	respondJSON(w, http.StatusOK, response)
}

// ListScansHandler handles GET /api/v1/scans
// Lists user's scans with pagination and filtering
func (h *Handler) ListScansHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

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

	// Parse query parameters
	query := r.URL.Query()
	status := query.Get("status")
	target := query.Get("target")

	// Parse pagination
	page := 1
	pageSize := 20
	if p, err := strconv.Atoi(query.Get("page")); err == nil && p > 0 {
		page = p
	}
	if ps, err := strconv.Atoi(query.Get("page_size")); err == nil && ps > 0 && ps <= 100 {
		pageSize = ps
	}

	// Parse date range
	var fromDate, toDate time.Time
	if fd := query.Get("from_date"); fd != "" {
		fromDate, _ = time.Parse(time.RFC3339, fd)
	}
	if td := query.Get("to_date"); td != "" {
		toDate, _ = time.Parse(time.RFC3339, td)
	}

	offset := int32((page - 1) * pageSize)
	limit := int32(pageSize)

	var scans []store.ScanJob
	var total int64
	var listErr error

	// Fetch scans based on filters
	if status != "" {
		scans, listErr = h.db.ListScanJobsByUserAndStatus(ctx, store.ListScanJobsByStatusParams{
			UserID: user.ID,
			Status: status,
			Limit:  limit,
			Offset: offset,
		})
		// Count total for this status
		allScans, _ := h.db.ListScanJobsByUserAndStatus(ctx, store.ListScanJobsByStatusParams{
			UserID: user.ID,
			Status: status,
			Limit:  1000000,
			Offset: 0,
		})
		total = int64(len(allScans))
	} else {
		scans, listErr = h.db.ListScanJobsByUser(ctx, store.ListScanJobsParams{
			UserID: user.ID,
			Limit:  limit,
			Offset: offset,
		})
		total, _ = h.db.CountScanJobsByUser(ctx, user.ID)
	}

	if listErr != nil {
		respondError(w, http.StatusInternalServerError, "Failed to list scans")
		return
	}

	// Filter by target if specified
	var filteredScans []store.ScanJob
	if target != "" {
		for _, s := range scans {
			if containsIgnoreCase(s.Target, target) {
				filteredScans = append(filteredScans, s)
			}
		}
		scans = filteredScans
	}

	// Filter by date range if specified
	if !fromDate.IsZero() || !toDate.IsZero() {
		var dateFiltered []store.ScanJob
		for _, s := range scans {
			if (fromDate.IsZero() || s.CreatedAt.After(fromDate)) &&
				(toDate.IsZero() || s.CreatedAt.Before(toDate)) {
				dateFiltered = append(dateFiltered, s)
			}
		}
		scans = dateFiltered
	}

	// Build response
	var scanItems []scanner.ScanListItem
	for _, s := range scans {
		item := scanner.ScanListItem{
			ID:        s.ID,
			Target:    s.Target,
			Status:    s.Status,
			CreatedAt: s.CreatedAt,
		}

		// Calculate progress
		if scanner.ScanStatus(s.Status).IsActive() {
			progress := h.orchestrator.GetScanProgress(s.ID)
			if progress != nil {
				item.Progress = progress.ProgressPercent
			}
		} else if s.Status == string(scanner.ScanStatusCompleted) {
			item.Progress = 100
		}

		// Parse finding counts
		if s.FindingCounts != nil {
			var counts map[string]int
			if err := json.Unmarshal(s.FindingCounts, &counts); err == nil {
				for _, v := range counts {
					item.FindingsCount += v
				}
			}
		}

		item.RiskScore = float64(s.RiskScore) / 10.0

		if s.StartedAt != nil {
			item.StartedAt = s.StartedAt
		}
		if s.CompletedAt != nil {
			item.CompletedAt = s.CompletedAt
		}

		scanItems = append(scanItems, item)
	}

	totalPages := int(total) / pageSize
	if int(total)%pageSize > 0 {
		totalPages++
	}

	respondJSON(w, http.StatusOK, scanner.ListScansResponse{
		Scans:      scanItems,
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
	})
}

// CancelScanHandler handles POST /api/v1/scans/:id/cancel
// Cancels a running scan
func (h *Handler) CancelScanHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse scan ID
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

	// Retrieve scan to verify ownership and status
	scanJob, err := h.db.GetScanJobByID(ctx, id)
	if err != nil {
		respondError(w, http.StatusNotFound, "Scan not found")
		return
	}

	// Verify scan is not already in a terminal state
	status := scanner.ScanStatus(scanJob.Status)
	if status.IsTerminal() {
		respondError(w, http.StatusConflict, fmt.Sprintf("Scan is already %s", scanJob.Status))
		return
	}

	// Cancel the scan via orchestrator
	if err := h.orchestrator.CancelScan(id); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to cancel scan")
		return
	}

	// Update scan status in database
	if _, err := h.db.UpdateScanJobStatus(ctx, store.UpdateScanJobStatusParams{
		ID:     id,
		Status: string(scanner.ScanStatusCancelled),
	}); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to update scan status")
		return
	}

	// Log cancellation
	h.auditLogger.Log(ctx, compliance.AuditEvent{
		UserID:     user.ID.String(),
		Action:     "scan:cancel",
		Resource:   "scan",
		ResourceID: id.String(),
		Status:     "success",
	})

	respondJSON(w, http.StatusOK, scanner.CancelScanResponse{
		ID:      id,
		Status:  string(scanner.ScanStatusCancelled),
		Message: "Scan cancelled successfully",
	})
}

// Legacy handler for backward compatibility - redirects to new handler
func (h *Handler) CreateScan(w http.ResponseWriter, r *http.Request) {
	h.CreateScanHandler(w, r)
}

// Legacy handler for backward compatibility
func (h *Handler) GetScan(w http.ResponseWriter, r *http.Request) {
	h.GetScanHandler(w, r)
}

// Legacy handler for backward compatibility
func (h *Handler) ListScans(w http.ResponseWriter, r *http.Request) {
	h.ListScansHandler(w, r)
}

// StopScan handles POST /api/v1/scans/{id}/stop (legacy endpoint)
func (h *Handler) StopScan(w http.ResponseWriter, r *http.Request) {
	h.CancelScanHandler(w, r)
}

// GetScanReport handles GET /api/v1/scans/{id}/report
func (h *Handler) GetScanReport(w http.ResponseWriter, r *http.Request) {
	h.GetScanReportHandler(w, r)
}

// GetReport handles GET /api/v1/reports/{id}
func (h *Handler) GetReport(w http.ResponseWriter, r *http.Request) {
	h.GetReportHandler(w, r)
}

// ListReports handles GET /api/v1/reports
func (h *Handler) ListReports(w http.ResponseWriter, r *http.Request) {
	h.ListReportsHandler(w, r)
}

// ShareReport handles POST /api/v1/reports/{id}/share
func (h *Handler) ShareReport(w http.ResponseWriter, r *http.Request) {
	h.ShareReportHandler(w, r)
}

// RevokeShare handles DELETE /api/v1/reports/{id}/share
func (h *Handler) RevokeShare(w http.ResponseWriter, r *http.Request) {
	h.RevokeShareHandler(w, r)
}

// GetSharedReport handles GET /share/{token}
func (h *Handler) GetSharedReport(w http.ResponseWriter, r *http.Request) {
	h.GetSharedReportHandler(w, r)
}

// DownloadReport handles GET /api/v1/reports/{id}/download
func (h *Handler) DownloadReport(w http.ResponseWriter, r *http.Request) {
	h.DownloadReportHandler(w, r)
}

// GenerateReport handles POST /api/v1/scans/{id}/report/generate
func (h *Handler) GenerateReport(w http.ResponseWriter, r *http.Request) {
	h.GenerateReportHandler(w, r)
}

// GetModules handles GET /api/v1/modules
func (h *Handler) GetModules(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUserFromContext(r.Context())
	if user == nil {
		respondError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	tierLimits := scanner.GetTierLimits(string(user.Tier))

	mods := h.orchestrator.GetAvailableModules()

	// Filter modules based on tier
	allowed := make(map[string]bool)
	for _, m := range tierLimits.AllowedModules {
		allowed[m] = true
	}

	var filtered []modules.ModuleInfo
	for _, m := range mods {
		if allowed[m.Name] {
			filtered = append(filtered, m)
		}
	}

	respondJSON(w, http.StatusOK, filtered)
}

// Helper functions

func respondJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(payload)
}

func respondError(w http.ResponseWriter, status int, message string) {
	respondJSON(w, status, map[string]string{"error": message})
}

func containsIgnoreCase(s, substr string) bool {
	return len(substr) == 0 ||
		(len(s) >= len(substr) &&
			(s == substr ||
				containsSubstringIgnoreCase(s, substr)))
}

func containsSubstringIgnoreCase(s, substr string) bool {
	// Simple case-insensitive contains
	for i := 0; i <= len(s)-len(substr); i++ {
		match := true
		for j := 0; j < len(substr); j++ {
			if toLower(s[i+j]) != toLower(substr[j]) {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func toLower(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + ('a' - 'A')
	}
	return c
}

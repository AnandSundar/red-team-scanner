package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/redteam/agentic-scanner/internal/auth"
	"github.com/redteam/agentic-scanner/internal/report"
	"github.com/redteam/agentic-scanner/internal/scanner"
	"github.com/redteam/agentic-scanner/internal/store"
)

// ============================================================================
// Report Service
// ============================================================================

// ReportService handles report generation and management
type ReportService struct {
	db            *store.DB
	storage       report.StorageClient
	tokenGen      *report.TokenGenerator
	orchestrator  *scanner.Orchestrator
	pdfGenerator  *report.PDFGenerator
	jsonGenerator *report.JSONGenerator
}

// NewReportService creates a new report service
func NewReportService(db *store.DB, orchestrator *scanner.Orchestrator) (*ReportService, error) {
	storage, err := report.NewStorageClient()
	if err != nil {
		return nil, fmt.Errorf("failed to create storage client: %w", err)
	}

	pdfGen, err := report.NewPDFGenerator()
	if err != nil {
		return nil, fmt.Errorf("failed to create PDF generator: %w", err)
	}

	return &ReportService{
		db:            db,
		storage:       storage,
		tokenGen:      report.NewTokenGenerator(os.Getenv("APP_BASE_URL")),
		orchestrator:  orchestrator,
		pdfGenerator:  pdfGen,
		jsonGenerator: report.NewJSONGenerator(),
	}, nil
}

// ============================================================================
// Request/Response Types
// ============================================================================

// GenerateReportRequest represents a request to generate a report
type GenerateReportRequest struct {
	Format             string `json:"format"` // "pdf", "json", or "both"
	IncludeRawEvidence bool   `json:"include_raw_evidence"`
}

// GenerateReportResponse represents the response from report generation request
type GenerateReportResponse struct {
	ReportID            string     `json:"report_id"`
	Status              string     `json:"status"`
	EstimatedCompletion *time.Time `json:"estimated_completion,omitempty"`
}

// ReportResponse represents a report in API responses
type ReportResponse struct {
	ID               string     `json:"id"`
	ScanID           string     `json:"scan_id"`
	Status           string     `json:"status"`
	PDFURL           string     `json:"pdf_url,omitempty"`
	JSONURL          string     `json:"json_url,omitempty"`
	ShareToken       string     `json:"share_token,omitempty"`
	ShareURL         string     `json:"share_url,omitempty"`
	ShareExpiresAt   *time.Time `json:"share_expires_at,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
	ExecutiveSummary string     `json:"executive_summary,omitempty"`
}

// ShareReportRequest represents a request to share a report
type ShareReportRequest struct {
	ExpiresInDays int `json:"expires_in_days"`
}

// ShareReportResponse represents the response from sharing a report
type ShareReportResponse struct {
	ShareToken string     `json:"share_token"`
	ShareURL   string     `json:"share_url"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
}

// DownloadReportRequest represents a download request
type DownloadReportRequest struct {
	Format string `json:"format"` // "pdf" or "json"
}

// ============================================================================
// Handler Methods
// ============================================================================

// GetReportHandler handles GET /api/v1/reports/:id
// Returns report metadata and summary
func (h *Handler) GetReportHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse report ID
	reportID := chi.URLParam(r, "id")
	id, err := uuid.Parse(reportID)
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid report ID")
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

	// Get report from database
	rep, err := h.db.GetReportByID(ctx, id)
	if err != nil {
		respondError(w, http.StatusNotFound, "Report not found")
		return
	}

	// Build response
	response := ReportResponse{
		ID:               rep.ID.String(),
		ScanID:           rep.ScanJobID.String(),
		Status:           "completed",
		PDFURL:           rep.PDFURL,
		JSONURL:          rep.JSONURL,
		ShareToken:       rep.ShareToken,
		CreatedAt:        rep.CreatedAt,
		ExecutiveSummary: rep.ExecutiveSummary,
	}

	// Generate share URL if token exists
	if rep.ShareToken != "" {
		tg := report.NewTokenGenerator(os.Getenv("APP_BASE_URL"))
		response.ShareURL = tg.FormatShareURL(rep.ShareToken)
		response.ShareExpiresAt = rep.ShareExpiresAt
	}

	respondJSON(w, http.StatusOK, response)
}

// DownloadReportHandler handles GET /api/v1/reports/:id/download
// Downloads report in PDF or JSON format
func (h *Handler) DownloadReportHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse report ID
	reportID := chi.URLParam(r, "id")
	id, err := uuid.Parse(reportID)
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid report ID")
		return
	}

	// Get format from query parameter
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "pdf"
	}
	if format != "pdf" && format != "json" {
		respondError(w, http.StatusBadRequest, "Invalid format. Must be 'pdf' or 'json'")
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

	// Get report from database
	rep, err := h.db.GetReportByID(ctx, id)
	if err != nil {
		respondError(w, http.StatusNotFound, "Report not found")
		return
	}

	// Get scan job to verify ownership
	scanJob, err := h.db.GetScanJobByID(ctx, rep.ScanJobID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to get scan job")
		return
	}

	// Verify ownership
	if scanJob.UserID != user.ID {
		respondError(w, http.StatusForbidden, "Access denied")
		return
	}

	// Get the appropriate URL
	var downloadURL string
	if format == "pdf" {
		downloadURL = rep.PDFURL
		w.Header().Set("Content-Type", "application/pdf")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"report-%s.pdf\"", reportID))
	} else {
		downloadURL = rep.JSONURL
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"report-%s.json\"", reportID))
	}

	if downloadURL == "" {
		respondError(w, http.StatusNotFound, fmt.Sprintf("%s report not available", format))
		return
	}

	// Generate presigned URL if using S3
	if storage, ok := h.storage.(*report.S3Client); ok {
		var key string
		if format == "pdf" {
			key = report.GeneratePDFKey(rep.ScanJobID, id)
		} else {
			key = report.GenerateJSONKey(rep.ScanJobID, id)
		}
		presignedURL, err := storage.GeneratePresignedURL(ctx, key, time.Hour)
		if err != nil {
			respondError(w, http.StatusInternalServerError, "Failed to generate download URL")
			return
		}
		downloadURL = presignedURL
	}

	// Return download URL
	respondJSON(w, http.StatusOK, map[string]string{
		"download_url": downloadURL,
		"expires_in":   "3600",
	})
}

// ShareReportHandler handles POST /api/v1/reports/:id/share
// Generates a shareable link for the report
func (h *Handler) ShareReportHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse report ID
	reportID := chi.URLParam(r, "id")
	id, err := uuid.Parse(reportID)
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid report ID")
		return
	}

	// Parse request body
	var req ShareReportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		// Use default expiration if no body
		req.ExpiresInDays = 30
	}

	// Validate expiration
	if req.ExpiresInDays <= 0 {
		req.ExpiresInDays = 30
	}
	if req.ExpiresInDays > 365 {
		req.ExpiresInDays = 365
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

	// Get report from database
	rep, err := h.db.GetReportByID(ctx, id)
	if err != nil {
		respondError(w, http.StatusNotFound, "Report not found")
		return
	}

	// Get scan job to verify ownership
	scanJob, err := h.db.GetScanJobByID(ctx, rep.ScanJobID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to get scan job")
		return
	}

	// Verify ownership
	if scanJob.UserID != user.ID {
		respondError(w, http.StatusForbidden, "Access denied")
		return
	}

	// Generate share token
	tg := report.NewTokenGenerator(os.Getenv("APP_BASE_URL"))
	shareLink, err := tg.CreateShareLinkWithDays(id, req.ExpiresInDays)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to generate share link")
		return
	}

	// Update report with share token
	expiresAt := shareLink.ExpiresAt
	_, err = h.db.UpdateReportShareToken(ctx, store.UpdateShareParams{
		ID:         id,
		ShareToken: shareLink.ShareToken,
		ExpiresAt:  expiresAt,
	})
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to save share token")
		return
	}

	respondJSON(w, http.StatusOK, ShareReportResponse{
		ShareToken: shareLink.ShareToken,
		ShareURL:   shareLink.ShareURL,
		ExpiresAt:  expiresAt,
	})
}

// RevokeShareHandler handles DELETE /api/v1/reports/:id/share
// Revokes a share link for the report
func (h *Handler) RevokeShareHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse report ID
	reportID := chi.URLParam(r, "id")
	id, err := uuid.Parse(reportID)
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid report ID")
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

	// Get report from database
	rep, err := h.db.GetReportByID(ctx, id)
	if err != nil {
		respondError(w, http.StatusNotFound, "Report not found")
		return
	}

	// Get scan job to verify ownership
	scanJob, err := h.db.GetScanJobByID(ctx, rep.ScanJobID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to get scan job")
		return
	}

	// Verify ownership
	if scanJob.UserID != user.ID {
		respondError(w, http.StatusForbidden, "Access denied")
		return
	}

	// Revoke share token
	_, err = h.db.RevokeReportShare(ctx, id)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to revoke share")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// GetScanReportHandler handles GET /api/v1/scans/:id/report
// Gets the report for a specific scan
func (h *Handler) GetScanReportHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse scan ID
	scanID := chi.URLParam(r, "scanID")
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

	// Get scan job to verify ownership
	scanJob, err := h.db.GetScanJobByID(ctx, id)
	if err != nil {
		respondError(w, http.StatusNotFound, "Scan not found")
		return
	}

	// Verify ownership
	if scanJob.UserID != user.ID {
		respondError(w, http.StatusForbidden, "Access denied")
		return
	}

	// Get report for the scan
	rep, err := h.db.GetReportByScanJobID(ctx, id)
	if err != nil {
		respondError(w, http.StatusNotFound, "Report not found for this scan")
		return
	}

	// Build response
	response := ReportResponse{
		ID:               rep.ID.String(),
		ScanID:           rep.ScanJobID.String(),
		Status:           "completed",
		PDFURL:           rep.PDFURL,
		JSONURL:          rep.JSONURL,
		ShareToken:       rep.ShareToken,
		CreatedAt:        rep.CreatedAt,
		ExecutiveSummary: rep.ExecutiveSummary,
	}

	// Generate share URL if token exists
	if rep.ShareToken != "" {
		tg := report.NewTokenGenerator(os.Getenv("APP_BASE_URL"))
		response.ShareURL = tg.FormatShareURL(rep.ShareToken)
		response.ShareExpiresAt = rep.ShareExpiresAt
	}

	respondJSON(w, http.StatusOK, response)
}

// GenerateReportHandler handles POST /api/v1/scans/:id/report/generate
// Triggers report generation for a scan
func (h *Handler) GenerateReportHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse scan ID
	scanID := chi.URLParam(r, "scanID")
	id, err := uuid.Parse(scanID)
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid scan ID")
		return
	}

	// Parse request body
	var req GenerateReportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		// Use defaults if no body
		req.Format = "both"
		req.IncludeRawEvidence = true
	}

	// Validate format
	if req.Format == "" {
		req.Format = "both"
	}
	if req.Format != "pdf" && req.Format != "json" && req.Format != "both" {
		respondError(w, http.StatusBadRequest, "Invalid format. Must be 'pdf', 'json', or 'both'")
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

	// Get scan job to verify ownership and status
	scanJob, err := h.db.GetScanJobByID(ctx, id)
	if err != nil {
		respondError(w, http.StatusNotFound, "Scan not found")
		return
	}

	// Verify ownership
	if scanJob.UserID != user.ID {
		respondError(w, http.StatusForbidden, "Access denied")
		return
	}

	// Check if scan is completed
	if scanJob.Status != string(scanner.ScanStatusCompleted) {
		respondError(w, http.StatusConflict, "Report can only be generated for completed scans")
		return
	}

	// Check rate limit (5 per hour per user)
	if !checkReportRateLimit(ctx, h.db, user.ID) {
		respondError(w, http.StatusTooManyRequests, "Report generation rate limit exceeded. Maximum 5 per hour.")
		return
	}

	// Check if report already exists
	existingReport, _ := h.db.GetReportByScanJobID(ctx, id)
	if existingReport != nil {
		// Return existing report
		respondJSON(w, http.StatusOK, GenerateReportResponse{
			ReportID: existingReport.ID.String(),
			Status:   "completed",
		})
		return
	}

	// Create report record
	reportRecord, err := h.db.CreateReport(ctx, store.CreateReportParams{
		ScanJobID: id,
	})
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to create report record")
		return
	}

	// Enqueue report generation task asynchronously
	estimatedCompletion := time.Now().UTC().Add(5 * time.Minute)

	// In a real implementation, this would enqueue a task to the queue
	// h.orchestrator.EnqueueReportGeneration(ctx, id, reportRecord.ID, req.Format)

	respondJSON(w, http.StatusAccepted, GenerateReportResponse{
		ReportID:            reportRecord.ID.String(),
		Status:              "generating",
		EstimatedCompletion: &estimatedCompletion,
	})
}

// GetSharedReportHandler handles GET /share/:token (public route)
// Gets a shared report by token (no auth required)
func (h *Handler) GetSharedReportHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse share token
	token := chi.URLParam(r, "token")
	if token == "" {
		respondError(w, http.StatusBadRequest, "Share token required")
		return
	}

	// Validate token format
	tg := report.NewTokenGenerator("")
	if err := tg.ValidateToken(token); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid share token")
		return
	}

	// Get report by share token
	rep, err := h.db.GetReportByShareToken(ctx, token)
	if err != nil {
		respondError(w, http.StatusNotFound, "Shared report not found or expired")
		return
	}

	// Build response (limited fields for public access)
	response := ReportResponse{
		ID:               rep.ID.String(),
		ScanID:           rep.ScanJobID.String(),
		Status:           "completed",
		PDFURL:           rep.PDFURL,
		JSONURL:          rep.JSONURL,
		CreatedAt:        rep.CreatedAt,
		ExecutiveSummary: rep.ExecutiveSummary,
		ShareExpiresAt:   rep.ShareExpiresAt,
	}

	respondJSON(w, http.StatusOK, response)
}

// ListReportsHandler handles GET /api/v1/reports
// Lists all reports for the authenticated user
func (h *Handler) ListReportsHandler(w http.ResponseWriter, r *http.Request) {
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

	// Parse pagination
	page := 1
	pageSize := 20
	if p, err := strconv.Atoi(r.URL.Query().Get("page")); err == nil && p > 0 {
		page = p
	}
	if ps, err := strconv.Atoi(r.URL.Query().Get("page_size")); err == nil && ps > 0 && ps <= 100 {
		pageSize = ps
	}

	offset := int32((page - 1) * pageSize)
	limit := int32(pageSize)

	// Get reports from database
	reports, err := h.db.ListReportsByUser(ctx, store.ListReportsParams{
		UserID: user.ID,
		Limit:  limit,
		Offset: offset,
	})
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to list reports")
		return
	}

	// Build response
	var items []ReportResponse
	tg := report.NewTokenGenerator(os.Getenv("APP_BASE_URL"))
	for _, rep := range reports {
		item := ReportResponse{
			ID:               rep.ID.String(),
			ScanID:           rep.ScanJobID.String(),
			Status:           "completed",
			PDFURL:           rep.PDFURL,
			JSONURL:          rep.JSONURL,
			ShareToken:       rep.ShareToken,
			CreatedAt:        rep.CreatedAt,
			ExecutiveSummary: rep.ExecutiveSummary,
			ShareExpiresAt:   rep.ShareExpiresAt,
		}

		if rep.ShareToken != "" {
			item.ShareURL = tg.FormatShareURL(rep.ShareToken)
		}

		items = append(items, item)
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"reports":   items,
		"page":      page,
		"page_size": pageSize,
		"total":     len(items),
	})
}

// ============================================================================
// Helper Functions
// ============================================================================

// reportRateLimitKey generates a rate limit key for report generation
func reportRateLimitKey(userID uuid.UUID) string {
	return fmt.Sprintf("report_limit:%s:%s", userID.String(), time.Now().UTC().Format("2006-01-02-15"))
}

// checkReportRateLimit checks if the user has exceeded the report generation rate limit
// Returns true if allowed, false if rate limited
func checkReportRateLimit(ctx context.Context, db *store.DB, userID uuid.UUID) bool {
	// In a real implementation, this would use Redis or another distributed cache
	// to track rate limits across multiple server instances.
	// For now, we use a simple in-memory check that would be replaced with Redis.

	// This is a placeholder implementation
	// The actual implementation should:
	// 1. Check Redis for the current count
	// 2. Increment the count with expiry
	// 3. Return false if count > 5

	return true // Allow for now
}

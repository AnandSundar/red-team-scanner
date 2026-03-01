package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/redteam/agentic-scanner/internal/auth"
	"github.com/redteam/agentic-scanner/internal/compliance"
	"github.com/redteam/agentic-scanner/internal/store"
)

// ComplianceHandler handles compliance-related HTTP requests
type ComplianceHandler struct {
	db          *store.DB
	auditLogger *compliance.AuditLogger
	tosManager  *compliance.ToSManager
	privacyMgr  *compliance.PrivacyManager
}

// NewComplianceHandler creates a new compliance handler
func NewComplianceHandler(db *store.DB) *ComplianceHandler {
	h := &ComplianceHandler{
		db:          db,
		auditLogger: compliance.NewAuditLoggerSimple(),
	}

	// Initialize ToS manager if store implements the interface
	// For now, we skip initialization since store.DB doesn't implement the full interface
	// This will be implemented when the store is updated with compliance methods
	// h.tosManager = compliance.NewToSManager(db)
	// h.privacyMgr = compliance.NewPrivacyManager(db)

	return h
}

// =============================================================================
// Terms of Service Endpoints
// =============================================================================

// GetToSStatusHandler handles GET /api/v1/compliance/tos
// Returns the user's Terms of Service acceptance status
func (h *ComplianceHandler) GetToSStatusHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get user from context
	user := auth.GetUserFromContext(ctx)
	if user == nil {
		respondError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	// Get ToS status
	status, err := h.tosManager.CheckToSStatus(ctx, user.ID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to check ToS status")
		return
	}

	respondJSON(w, http.StatusOK, status)
}

// AcceptToSHandler handles POST /api/v1/compliance/tos
// Records user's acceptance of Terms of Service
func (h *ComplianceHandler) AcceptToSHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get user from context
	user := auth.GetUserFromContext(ctx)
	if user == nil {
		respondError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	// Parse request body
	var req compliance.ToSAcceptRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		// If no body, assume acceptance
		req.Accepted = true
	}

	if !req.Accepted {
		respondError(w, http.StatusBadRequest, "ToS acceptance required")
		return
	}

	// Get client IP
	clientIP := r.Header.Get("X-Forwarded-For")
	if clientIP == "" {
		clientIP = r.RemoteAddr
	}

	// Record ToS acceptance
	resp, err := h.tosManager.AcceptToS(ctx, user.ID, clientIP)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to record ToS acceptance")
		return
	}

	// Log the acceptance
	h.auditLogger.LogToSAcceptance(ctx, user.ID.String(), resp.Version, clientIP)

	respondJSON(w, http.StatusOK, resp)
}

// GetToSContentHandler handles GET /api/v1/compliance/tos/content
// Returns the current Terms of Service content
func (h *ComplianceHandler) GetToSContentHandler(w http.ResponseWriter, r *http.Request) {
	content := h.tosManager.GetToSContent()
	respondJSON(w, http.StatusOK, content)
}

// =============================================================================
// Privacy / GDPR / CCPA Endpoints
// =============================================================================

// ExportDataHandler handles GET /api/v1/compliance/data-export
// Exports all user data for GDPR/CCPA compliance
func (h *ComplianceHandler) ExportDataHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get user from context
	user := auth.GetUserFromContext(ctx)
	if user == nil {
		respondError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	// Get format from query param
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "json"
	}

	// Export user data
	data, err := h.privacyMgr.ExportUserDataJSON(ctx, user.ID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to export user data")
		return
	}

	// Log the export
	h.auditLogger.LogDataExport(ctx, user.ID.String(), uuid.New().String(), []string{format})

	// Set response headers
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=\"user-data-export.json\"")
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

// RequestDataDeletionHandler handles POST /api/v1/compliance/data-deletion
// Requests deletion of all user data (GDPR/CCPA)
func (h *ComplianceHandler) RequestDataDeletionHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get user from context
	user := auth.GetUserFromContext(ctx)
	if user == nil {
		respondError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	// Parse request body for reason
	var req struct {
		Reason string `json:"reason,omitempty"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	requestID := uuid.New().String()

	// Log the deletion request
	h.auditLogger.LogDataDeletion(ctx, user.ID.String(), requestID, req.Reason)

	// In a real implementation, this would queue the deletion for async processing
	// to ensure audit logs are properly handled

	respondJSON(w, http.StatusAccepted, map[string]interface{}{
		"request_id":   requestID,
		"status":       "pending",
		"message":      "Data deletion request received and is being processed",
		"requested_at": time.Now().UTC(),
	})
}

// GetPrivacyPolicyHandler handles GET /api/v1/compliance/privacy-policy
// Returns the privacy policy
func (h *ComplianceHandler) GetPrivacyPolicyHandler(w http.ResponseWriter, r *http.Request) {
	policy := h.privacyMgr.GetPrivacyPolicy()
	respondJSON(w, http.StatusOK, policy)
}

// =============================================================================
// Consent Management Endpoints
// =============================================================================

// RecordConsentHandler handles POST /api/v1/compliance/consent
// Records user consent for a specific purpose
func (h *ComplianceHandler) RecordConsentHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get user from context
	user := auth.GetUserFromContext(ctx)
	if user == nil {
		respondError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	// Parse request
	var req struct {
		ConsentType string `json:"consent_type"`
		Granted     bool   `json:"granted"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Get client info
	clientIP := r.Header.Get("X-Forwarded-For")
	if clientIP == "" {
		clientIP = r.RemoteAddr
	}
	userAgent := r.Header.Get("User-Agent")

	// Record consent
	consentType := compliance.ConsentType(req.ConsentType)
	if err := h.privacyMgr.RecordConsent(ctx, user.ID, consentType, req.Granted, clientIP, userAgent); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to record consent")
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success":      true,
		"consent_type": req.ConsentType,
		"granted":      req.Granted,
		"recorded_at":  time.Now().UTC(),
	})
}

// GetConsentStatusHandler handles GET /api/v1/compliance/consent/:type
// Returns consent status for a specific purpose
func (h *ComplianceHandler) GetConsentStatusHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get user from context
	user := auth.GetUserFromContext(ctx)
	if user == nil {
		respondError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	// Get consent type from URL
	consentType := chi.URLParam(r, "type")

	// Get consent status
	granted, err := h.privacyMgr.GetConsentStatus(ctx, user.ID, compliance.ConsentType(consentType))
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to get consent status")
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"consent_type": consentType,
		"granted":      granted,
	})
}

// =============================================================================
// Audit Log Endpoints (Admin only)
// =============================================================================

// GetAuditLogsHandler handles GET /api/v1/compliance/audit-logs
// Returns audit logs for the authenticated user
func (h *ComplianceHandler) GetAuditLogsHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get user from context
	user := auth.GetUserFromContext(ctx)
	if user == nil {
		respondError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	// Parse pagination params
	limit := int32(50)
	offset := int32(0)

	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := parseInt32(l); err == nil {
			limit = parsed
		}
	}
	if o := r.URL.Query().Get("offset"); o != "" {
		if parsed, err := parseInt32(o); err == nil {
			offset = parsed
		}
	}

	// Get audit logs for user
	logs, err := h.auditLogger.GetUserAuditLogs(ctx, user.ID, limit, offset)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to retrieve audit logs")
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"logs":   logs,
		"limit":  limit,
		"offset": offset,
	})
}

// =============================================================================
// Blocklist Information Endpoints
// =============================================================================

// GetBlocklistInfoHandler handles GET /api/v1/compliance/blocklist
// Returns information about blocked IP ranges and domains
func (h *ComplianceHandler) GetBlocklistInfoHandler(w http.ResponseWriter, r *http.Request) {
	blocklist := compliance.NewBlocklist()

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"blocked_ranges":   blocklist.GetBlockedRanges(),
		"self_hosted_mode": blocklist.IsSelfHostedMode(),
	})
}

// CheckTargetHandler handles POST /api/v1/compliance/check-target
// Checks if a target is allowed (dry-run before scan)
func (h *ComplianceHandler) CheckTargetHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get user from context
	user := auth.GetUserFromContext(ctx)
	if user == nil {
		respondError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	// Parse request
	var req struct {
		Target string `json:"target"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	blocklist := compliance.NewBlocklist()
	result := blocklist.IsAllowed(req.Target)

	respondJSON(w, http.StatusOK, result)
}

// =============================================================================
// Helper Functions
// =============================================================================

func parseInt32(s string) (int32, error) {
	var i int64
	err := json.Unmarshal([]byte(s), &i)
	if err != nil {
		// Try simple parsing
		var val int32
		err := json.Unmarshal([]byte(s), &val)
		return val, err
	}
	return int32(i), nil
}

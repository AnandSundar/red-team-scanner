package compliance

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// AuditEventType represents the type of audit event
type AuditEventType string

const (
	// Scan events
	AuditEventScanInitiated AuditEventType = "scan_initiated"
	AuditEventScanCompleted AuditEventType = "scan_completed"
	AuditEventScanCancelled AuditEventType = "scan_cancelled"
	AuditEventScanFailed    AuditEventType = "scan_failed"

	// Report events
	AuditEventReportGenerated  AuditEventType = "report_generated"
	AuditEventReportShared     AuditEventType = "report_shared"
	AuditEventReportDownloaded AuditEventType = "report_downloaded"

	// Authorization events
	AuditEventAuthConfirmed AuditEventType = "auth_confirmed"

	// Billing events
	AuditEventTierChanged           AuditEventType = "tier_changed"
	AuditEventSubscriptionCreated   AuditEventType = "subscription_created"
	AuditEventSubscriptionCancelled AuditEventType = "subscription_cancelled"

	// API key events
	AuditEventAPIKeyCreated AuditEventType = "api_key_created"
	AuditEventAPIKeyRevoked AuditEventType = "api_key_revoked"
	AuditEventAPIKeyUsed    AuditEventType = "api_key_used"

	// Security events
	AuditEventBlockAttempt AuditEventType = "block_attempt"
	AuditEventAuthFailure  AuditEventType = "auth_failure"
	AuditEventRateLimitHit AuditEventType = "rate_limit_hit"

	// Compliance events
	AuditEventToSAccepted    AuditEventType = "tos_accepted"
	AuditEventDataExport     AuditEventType = "data_export"
	AuditEventDataDeletion   AuditEventType = "data_deletion"
	AuditEventPrivacyRequest AuditEventType = "privacy_request"
)

// AuditLogger handles audit logging with database persistence
type AuditLogger struct {
	db            AuditStore
	retentionDays int
}

// AuditStore interface for database operations
type AuditStore interface {
	CreateAuditLog(ctx context.Context, params CreateAuditLogParams) error
	ListAuditLogs(ctx context.Context, params ListAuditLogsParams) ([]AuditLog, error)
	DeleteOldAuditLogs(ctx context.Context, before time.Time) error
	GetAuditLogsForUser(ctx context.Context, userID uuid.UUID, limit, offset int32) ([]AuditLog, error)
	GetAuditLogsByEventType(ctx context.Context, eventType string, limit, offset int32) ([]AuditLog, error)
	GetAuditLogsByDateRange(ctx context.Context, startDate, endDate time.Time, limit, offset int32) ([]AuditLog, error)
	CountAuditLogs(ctx context.Context) (int64, error)
}

// CreateAuditLogParams parameters for creating an audit log
type CreateAuditLogParams struct {
	UserID    uuid.UUID
	EventType string
	EventData map[string]interface{}
	Target    string
	IPAddress string
	UserAgent string
}

// AuditLog represents an audit log entry
type AuditLog struct {
	ID        uuid.UUID       `json:"id"`
	UserID    uuid.UUID       `json:"user_id"`
	EventType string          `json:"event_type"`
	EventData json.RawMessage `json:"event_data,omitempty"`
	Target    string          `json:"target,omitempty"`
	IPAddress string          `json:"ip_address,omitempty"`
	UserAgent string          `json:"user_agent,omitempty"`
	CreatedAt time.Time       `json:"created_at"`
}

// ListAuditLogsParams parameters for listing audit logs
type ListAuditLogsParams struct {
	Limit  int32
	Offset int32
}

// NewAuditLogger creates a new audit logger
// db parameter can be nil if database persistence is not needed
func NewAuditLogger(db AuditStore) *AuditLogger {
	retention := 90
	if days := os.Getenv("AUDIT_LOG_RETENTION_DAYS"); days != "" {
		if d, err := time.ParseDuration(days + "d"); err == nil {
			retention = int(d.Hours() / 24)
		}
	}

	return &AuditLogger{
		db:            db,
		retentionDays: retention,
	}
}

// NewAuditLoggerSimple creates a new audit logger without database store
// This is a convenience function for backward compatibility
func NewAuditLoggerSimple() *AuditLogger {
	return NewAuditLogger(nil)
}

// LogAuditEvent logs a comprehensive audit event with full context
func (a *AuditLogger) LogAuditEvent(ctx context.Context, params LogAuditEventParams) error {
	event := AuditLog{
		ID:        uuid.New(),
		UserID:    params.UserID,
		EventType: string(params.EventType),
		Target:    params.Target,
		IPAddress: params.IPAddress,
		UserAgent: params.UserAgent,
		CreatedAt: time.Now().UTC(),
	}

	// Marshal event data
	if params.EventData != nil {
		data, err := json.Marshal(params.EventData)
		if err != nil {
			log.Printf("[AUDIT ERROR] Failed to marshal event data: %v", err)
		} else {
			event.EventData = data
		}
	}

	// Log to stdout for immediate visibility
	logData, _ := json.Marshal(event)
	log.Printf("[AUDIT] %s", string(logData))

	// Persist to database if available
	if a.db != nil {
		dbParams := CreateAuditLogParams{
			UserID:    params.UserID,
			EventType: string(params.EventType),
			EventData: params.EventData,
			Target:    params.Target,
			IPAddress: params.IPAddress,
			UserAgent: params.UserAgent,
		}
		if err := a.db.CreateAuditLog(ctx, dbParams); err != nil {
			log.Printf("[AUDIT ERROR] Failed to persist audit log: %v", err)
			// Don't return error - audit logging should not break the application
		}
	}

	return nil
}

// LogAuditEventParams parameters for logging an audit event
type LogAuditEventParams struct {
	UserID    uuid.UUID
	EventType AuditEventType
	EventData map[string]interface{}
	Target    string
	IPAddress string
	UserAgent string
}

// ScanInitiationLog represents detailed scan initiation data for audit
type ScanInitiationLog struct {
	UserID               string    `json:"user_id"`
	ClerkUserID          string    `json:"clerk_user_id"`
	ScanID               uuid.UUID `json:"scan_id"`
	Target               string    `json:"target"`
	TargetType           string    `json:"target_type"`
	AuthConfirmed        bool      `json:"auth_confirmed"`
	AuthConfirmedIP      string    `json:"auth_confirmed_ip"`
	AuthConfirmedAt      time.Time `json:"auth_confirmed_at"`
	UserAgent            string    `json:"user_agent"`
	Tier                 string    `json:"tier"`
	Modules              []string  `json:"modules"`
	Scope                string    `json:"scope"`
	CustomHeadersPresent bool      `json:"custom_headers_present"`
}

// Log records an audit event (legacy method, use LogAuditEvent instead)
func (a *AuditLogger) Log(ctx context.Context, event AuditEvent) error {
	event.ID = uuid.New()
	event.Timestamp = time.Now()

	// In production, this would write to:
	// - Immutable audit log storage
	// - SIEM integration
	// - Compliance database
	// For now, log to stdout
	data, err := json.Marshal(event)
	if err != nil {
		return err
	}

	log.Printf("[AUDIT] %s", string(data))
	return nil
}

// AuditEvent represents an audit event (legacy struct)
type AuditEvent struct {
	ID         uuid.UUID       `json:"id"`
	Timestamp  time.Time       `json:"timestamp"`
	UserID     string          `json:"user_id"`
	Action     string          `json:"action"`
	Resource   string          `json:"resource"`
	ResourceID string          `json:"resource_id"`
	Status     string          `json:"status"`
	IPAddress  string          `json:"ip_address,omitempty"`
	UserAgent  string          `json:"user_agent,omitempty"`
	Details    json.RawMessage `json:"details,omitempty"`
}

// LogScanStart logs when a scan is started (legacy method)
func (a *AuditLogger) LogScanStart(ctx context.Context, userID string, scanID uuid.UUID, target string) error {
	uid, _ := uuid.Parse(userID)
	return a.LogAuditEvent(ctx, LogAuditEventParams{
		UserID:    uid,
		EventType: AuditEventScanInitiated,
		EventData: map[string]interface{}{
			"scan_id": scanID.String(),
			"target":  target,
		},
		Target: target,
	})
}

// LogScanInitiation logs comprehensive scan initiation data with legal protection
func (a *AuditLogger) LogScanInitiation(ctx context.Context, logData ScanInitiationLog) error {
	// This log entry serves as legal evidence of:
	// 1. User's explicit authorization to scan the target
	// 2. Timestamp and IP address for accountability
	// 3. Scope confirmation for authorized testing
	// 4. User tier and permissions at time of scan

	uid, _ := uuid.Parse(logData.UserID)
	eventData := map[string]interface{}{
		"scan_id":                logData.ScanID.String(),
		"clerk_user_id":          logData.ClerkUserID,
		"target":                 logData.Target,
		"target_type":            logData.TargetType,
		"auth_confirmed":         logData.AuthConfirmed,
		"auth_confirmed_ip":      logData.AuthConfirmedIP,
		"auth_confirmed_at":      logData.AuthConfirmedAt.Format(time.RFC3339),
		"user_agent":             logData.UserAgent,
		"tier":                   logData.Tier,
		"modules":                logData.Modules,
		"scope":                  logData.Scope,
		"custom_headers_present": logData.CustomHeadersPresent,
		"legal_basis":            "explicit_authorization_checkbox",
		"compliance_framework":   "responsible_disclosure",
	}

	return a.LogAuditEvent(ctx, LogAuditEventParams{
		UserID:    uid,
		EventType: AuditEventScanInitiated,
		EventData: eventData,
		Target:    logData.Target,
		IPAddress: logData.AuthConfirmedIP,
		UserAgent: logData.UserAgent,
	})
}

// LogScanCompletion logs when a scan completes
func (a *AuditLogger) LogScanCompletion(ctx context.Context, userID string, scanID uuid.UUID, duration int, findingsCount int) error {
	uid, _ := uuid.Parse(userID)
	return a.LogAuditEvent(ctx, LogAuditEventParams{
		UserID:    uid,
		EventType: AuditEventScanCompleted,
		EventData: map[string]interface{}{
			"scan_id":          scanID.String(),
			"duration_seconds": duration,
			"findings_count":   findingsCount,
		},
	})
}

// LogScanCancellation logs when a scan is cancelled
func (a *AuditLogger) LogScanCancellation(ctx context.Context, userID string, scanID uuid.UUID, reason string) error {
	uid, _ := uuid.Parse(userID)
	return a.LogAuditEvent(ctx, LogAuditEventParams{
		UserID:    uid,
		EventType: AuditEventScanCancelled,
		EventData: map[string]interface{}{
			"scan_id": scanID.String(),
			"reason":  reason,
		},
	})
}

// LogScanFailure logs when a scan fails
func (a *AuditLogger) LogScanFailure(ctx context.Context, userID string, scanID uuid.UUID, target string, errorMsg string) error {
	uid, _ := uuid.Parse(userID)
	return a.LogAuditEvent(ctx, LogAuditEventParams{
		UserID:    uid,
		EventType: AuditEventScanFailed,
		EventData: map[string]interface{}{
			"scan_id": scanID.String(),
			"target":  target,
			"error":   errorMsg,
		},
		Target: target,
	})
}

// LogReportGenerated logs when a report is generated
func (a *AuditLogger) LogReportGenerated(ctx context.Context, userID string, scanID uuid.UUID, reportID uuid.UUID, reportFormat string) error {
	uid, _ := uuid.Parse(userID)
	return a.LogAuditEvent(ctx, LogAuditEventParams{
		UserID:    uid,
		EventType: AuditEventReportGenerated,
		EventData: map[string]interface{}{
			"scan_id":       scanID.String(),
			"report_id":     reportID.String(),
			"report_format": reportFormat,
		},
	})
}

// LogReportShared logs when a report share link is created
func (a *AuditLogger) LogReportShared(ctx context.Context, userID string, reportID uuid.UUID, shareToken string, expiresAt *time.Time) error {
	uid, _ := uuid.Parse(userID)
	eventData := map[string]interface{}{
		"report_id":   reportID.String(),
		"share_token": shareToken,
	}
	if expiresAt != nil {
		eventData["expires_at"] = expiresAt.Format(time.RFC3339)
	}
	return a.LogAuditEvent(ctx, LogAuditEventParams{
		UserID:    uid,
		EventType: AuditEventReportShared,
		EventData: eventData,
	})
}

// LogAuthConfirmed logs when user confirms authorization checkbox
func (a *AuditLogger) LogAuthConfirmed(ctx context.Context, userID string, scanID uuid.UUID, target string, clientIP, userAgent string) error {
	uid, _ := uuid.Parse(userID)
	return a.LogAuditEvent(ctx, LogAuditEventParams{
		UserID:    uid,
		EventType: AuditEventAuthConfirmed,
		EventData: map[string]interface{}{
			"scan_id": scanID.String(),
			"target":  target,
			"message": "User explicitly confirmed authorization to scan target",
		},
		Target:    target,
		IPAddress: clientIP,
		UserAgent: userAgent,
	})
}

// LogTierChanged logs when a user's subscription tier changes
func (a *AuditLogger) LogTierChanged(ctx context.Context, userID string, oldTier, newTier string, changedBy string) error {
	uid, _ := uuid.Parse(userID)
	return a.LogAuditEvent(ctx, LogAuditEventParams{
		UserID:    uid,
		EventType: AuditEventTierChanged,
		EventData: map[string]interface{}{
			"old_tier":   oldTier,
			"new_tier":   newTier,
			"changed_by": changedBy,
		},
	})
}

// LogAPIKeyCreated logs when an API key is generated
func (a *AuditLogger) LogAPIKeyCreated(ctx context.Context, userID string, keyID string, clientIP string) error {
	uid, _ := uuid.Parse(userID)
	return a.LogAuditEvent(ctx, LogAuditEventParams{
		UserID:    uid,
		EventType: AuditEventAPIKeyCreated,
		EventData: map[string]interface{}{
			"key_id": keyID,
		},
		IPAddress: clientIP,
	})
}

// LogAPIKeyRevoked logs when an API key is revoked
func (a *AuditLogger) LogAPIKeyRevoked(ctx context.Context, userID string, keyID string, clientIP string) error {
	uid, _ := uuid.Parse(userID)
	return a.LogAuditEvent(ctx, LogAuditEventParams{
		UserID:    uid,
		EventType: AuditEventAPIKeyRevoked,
		EventData: map[string]interface{}{
			"key_id": keyID,
		},
		IPAddress: clientIP,
	})
}

// LogBlockAttempt logs when a scan is blocked by the blocklist
func (a *AuditLogger) LogBlockAttempt(ctx context.Context, userID string, target string, reason string, clientIP, userAgent string) error {
	uid, _ := uuid.Parse(userID)
	return a.LogAuditEvent(ctx, LogAuditEventParams{
		UserID:    uid,
		EventType: AuditEventBlockAttempt,
		EventData: map[string]interface{}{
			"target": target,
			"reason": reason,
		},
		Target:    target,
		IPAddress: clientIP,
		UserAgent: userAgent,
	})
}

// LogToSAcceptance logs when user accepts Terms of Service
func (a *AuditLogger) LogToSAcceptance(ctx context.Context, userID string, version string, clientIP string) error {
	uid, _ := uuid.Parse(userID)
	return a.LogAuditEvent(ctx, LogAuditEventParams{
		UserID:    uid,
		EventType: AuditEventToSAccepted,
		EventData: map[string]interface{}{
			"tos_version": version,
			"accepted_at": time.Now().UTC().Format(time.RFC3339),
		},
		IPAddress: clientIP,
	})
}

// LogDataExport logs when user exports their data (GDPR/CCPA)
func (a *AuditLogger) LogDataExport(ctx context.Context, userID string, requestID string, formats []string) error {
	uid, _ := uuid.Parse(userID)
	return a.LogAuditEvent(ctx, LogAuditEventParams{
		UserID:    uid,
		EventType: AuditEventDataExport,
		EventData: map[string]interface{}{
			"request_id": requestID,
			"formats":    formats,
		},
	})
}

// LogDataDeletion logs when user requests data deletion (GDPR/CCPA)
func (a *AuditLogger) LogDataDeletion(ctx context.Context, userID string, requestID string, reason string) error {
	uid, _ := uuid.Parse(userID)
	return a.LogAuditEvent(ctx, LogAuditEventParams{
		UserID:    uid,
		EventType: AuditEventDataDeletion,
		EventData: map[string]interface{}{
			"request_id": requestID,
			"reason":     reason,
		},
	})
}

// LogSecurityEvent logs a security-related event
func (a *AuditLogger) LogSecurityEvent(ctx context.Context, userID, eventType, description string, severity string) error {
	uid, _ := uuid.Parse(userID)
	return a.LogAuditEvent(ctx, LogAuditEventParams{
		UserID:    uid,
		EventType: AuditEventType(eventType),
		EventData: map[string]interface{}{
			"event_type":  eventType,
			"description": description,
			"severity":    severity,
		},
	})
}

// LogDataAccess logs access to sensitive data
func (a *AuditLogger) LogDataAccess(ctx context.Context, userID, resource, resourceID, action string) error {
	uid, _ := uuid.Parse(userID)
	return a.LogAuditEvent(ctx, LogAuditEventParams{
		UserID:    uid,
		EventType: AuditEventType("data_access"),
		EventData: map[string]interface{}{
			"resource":    resource,
			"resource_id": resourceID,
			"action":      action,
		},
	})
}

// GetRetentionDays returns the audit log retention period
func (a *AuditLogger) GetRetentionDays() int {
	return a.retentionDays
}

// CleanupOldLogs removes audit logs older than the retention period
func (a *AuditLogger) CleanupOldLogs(ctx context.Context) error {
	if a.db == nil {
		return fmt.Errorf("audit store not configured")
	}

	cutoff := time.Now().UTC().AddDate(0, 0, -a.retentionDays)
	return a.db.DeleteOldAuditLogs(ctx, cutoff)
}

// ExportAuditLogs exports audit logs for compliance (CSV/JSON format)
func (a *AuditLogger) ExportAuditLogs(ctx context.Context, startDate, endDate time.Time, eventType string) ([]AuditLog, error) {
	if a.db == nil {
		return nil, fmt.Errorf("audit store not configured")
	}

	if eventType != "" {
		return a.db.GetAuditLogsByEventType(ctx, eventType, 10000, 0)
	}

	return a.db.GetAuditLogsByDateRange(ctx, startDate, endDate, 10000, 0)
}

// GetUserAuditLogs retrieves audit logs for a specific user
func (a *AuditLogger) GetUserAuditLogs(ctx context.Context, userID uuid.UUID, limit, offset int32) ([]AuditLog, error) {
	if a.db == nil {
		return nil, fmt.Errorf("audit store not configured")
	}
	return a.db.GetAuditLogsForUser(ctx, userID, limit, offset)
}

// NullTimeToTime converts pgtype.Timestamptz to time.Time
func NullTimeToTime(t pgtype.Timestamptz) time.Time {
	if t.Valid {
		return t.Time
	}
	return time.Time{}
}

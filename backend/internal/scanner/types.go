package scanner

import (
	"encoding/json"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

// ============================================================================
// Scan Status Types
// ============================================================================

// ScanStatus represents the current state of a scan
type ScanStatus string

const (
	ScanStatusPending   ScanStatus = "pending"
	ScanStatusQueued    ScanStatus = "queued"
	ScanStatusRunning   ScanStatus = "running"
	ScanStatusPaused    ScanStatus = "paused"
	ScanStatusCompleted ScanStatus = "completed"
	ScanStatusFailed    ScanStatus = "failed"
	ScanStatusCancelled ScanStatus = "cancelled"
	ScanStatusStopped   ScanStatus = "stopped"
)

// IsTerminal returns true if the status is a terminal state
func (s ScanStatus) IsTerminal() bool {
	switch s {
	case ScanStatusCompleted, ScanStatusFailed, ScanStatusCancelled, ScanStatusStopped:
		return true
	}
	return false
}

// IsActive returns true if the scan is currently running
func (s ScanStatus) IsActive() bool {
	return s == ScanStatusRunning || s == ScanStatusQueued
}

// ============================================================================
// Severity Types
// ============================================================================

// Severity represents finding severity levels
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Score returns a numeric score for severity comparison
func (s Severity) Score() int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	}
	return 0
}

// ============================================================================
// Target Types
// ============================================================================

// TargetType represents the type of target being scanned
type TargetType string

const (
	TargetTypeWeb     TargetType = "web"
	TargetTypeAPI     TargetType = "api"
	TargetTypeNetwork TargetType = "network"
	TargetTypeMobile  TargetType = "mobile"
	TargetTypeCloud   TargetType = "cloud"
	TargetTypeUnknown TargetType = "unknown"
)

// ValidateTarget validates and classifies a target string
func ValidateTarget(target string) (TargetType, error) {
	if target == "" {
		return TargetTypeUnknown, ErrInvalidTarget
	}

	// Check if it's a URL
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		u, err := url.Parse(target)
		if err != nil {
			return TargetTypeUnknown, ErrInvalidTarget
		}
		if u.Host == "" {
			return TargetTypeUnknown, ErrInvalidTarget
		}

		// Check if it looks like an API
		if isAPITarget(u) {
			return TargetTypeAPI, nil
		}
		return TargetTypeWeb, nil
	}

	// Check if it's an IP address
	ipRegex := regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}$|^([0-9a-fA-F:]+)$`)
	if ipRegex.MatchString(target) {
		return TargetTypeNetwork, nil
	}

	// Check if it's a domain
	domainRegex := regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$`)
	if domainRegex.MatchString(target) {
		return TargetTypeWeb, nil
	}

	return TargetTypeUnknown, ErrInvalidTarget
}

func isAPITarget(u *url.URL) bool {
	apiIndicators := []string{"/api", "/v1", "/v2", "/graphql", "/rest", "/swagger", "/openapi"}
	path := strings.ToLower(u.Path)
	for _, indicator := range apiIndicators {
		if strings.Contains(path, indicator) {
			return true
		}
	}
	return false
}

var ErrInvalidTarget = &ScanError{Code: "invalid_target", Message: "Invalid target format"}

// ============================================================================
// Scan Models
// ============================================================================

// Scan represents a security scan
type Scan struct {
	ID          uuid.UUID  `json:"id" db:"id"`
	UserID      string     `json:"user_id" db:"user_id"`
	Target      string     `json:"target" db:"target"`
	TargetType  string     `json:"target_type" db:"target_type"`
	Status      string     `json:"status" db:"status"`
	Modules     []string   `json:"modules" db:"modules"`
	Depth       int        `json:"depth" db:"depth"`
	AISeverity  string     `json:"ai_severity" db:"ai_severity"`
	MaxDuration int        `json:"max_duration" db:"max_duration_seconds"`
	CreatedAt   time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at" db:"updated_at"`
	StartedAt   *time.Time `json:"started_at,omitempty" db:"started_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty" db:"completed_at"`
}

// ScanConfig represents scan configuration
type ScanConfig struct {
	UserID        string
	Target        string
	TargetType    TargetType
	Scope         string
	Modules       []string
	Depth         int
	AISeverity    string
	MaxDuration   time.Duration
	AuthConfirmed bool
	CustomHeaders map[string]string
	ClientIP      string
	UserAgent     string
}

// ScanProgress represents real-time scan progress
type ScanProgress struct {
	ScanID           uuid.UUID  `json:"scan_id"`
	Status           ScanStatus `json:"status"`
	ProgressPercent  int        `json:"progress_percent"`
	CurrentModule    string     `json:"current_module,omitempty"`
	ModulesCompleted []string   `json:"modules_completed"`
	ModulesPending   []string   `json:"modules_pending"`
	FindingsCount    int        `json:"findings_count"`
	ETA              *time.Time `json:"eta,omitempty"`
	StartedAt        *time.Time `json:"started_at,omitempty"`
	Message          string     `json:"message,omitempty"`
	Timestamp        time.Time  `json:"timestamp"`
}

// ScanSummary provides a summary of scan results
type ScanSummary struct {
	TotalFindings int            `json:"total_findings"`
	BySeverity    map[string]int `json:"by_severity"`
	ByCategory    map[string]int `json:"by_category"`
	RiskScore     float64        `json:"risk_score"`
}

// ============================================================================
// API Request/Response Types
// ============================================================================

// CreateScanRequest represents a request to create a new scan
type CreateScanRequest struct {
	Target        string            `json:"target"`
	Scope         string            `json:"scope,omitempty"`
	Modules       []string          `json:"modules,omitempty"`
	Depth         int               `json:"depth,omitempty"`
	AISeverity    string            `json:"ai_severity,omitempty"`
	MaxDuration   int               `json:"max_duration,omitempty"`
	AuthConfirmed bool              `json:"auth_confirmed"`
	CustomHeaders map[string]string `json:"custom_headers,omitempty"`
}

// Validate validates the create scan request
func (r *CreateScanRequest) Validate() error {
	if r.Target == "" {
		return &ScanError{Code: "missing_target", Message: "Target is required"}
	}
	if !r.AuthConfirmed {
		return &ScanError{Code: "auth_not_confirmed", Message: "Authorization must be confirmed"}
	}
	if r.Scope == "" {
		r.Scope = "standard"
	}
	if r.Depth < 1 {
		r.Depth = 1
	}
	if r.Depth > 5 {
		r.Depth = 5
	}
	return nil
}

// CreateScanResponse represents the response from creating a scan
type CreateScanResponse struct {
	ID        string    `json:"id"`
	Target    string    `json:"target"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
}

// GetScanResponse represents the detailed scan response
type GetScanResponse struct {
	ID              uuid.UUID     `json:"id"`
	Target          string        `json:"target"`
	TargetType      string        `json:"target_type"`
	Status          string        `json:"status"`
	Progress        *ScanProgress `json:"progress,omitempty"`
	Summary         *ScanSummary  `json:"summary,omitempty"`
	Modules         []string      `json:"modules"`
	StartedAt       *time.Time    `json:"started_at,omitempty"`
	CompletedAt     *time.Time    `json:"completed_at,omitempty"`
	CreatedAt       time.Time     `json:"created_at"`
	DurationSeconds int           `json:"duration_seconds,omitempty"`
}

// ListScansRequest represents the request to list scans with filters
type ListScansRequest struct {
	Status   string    `json:"status,omitempty"`
	Target   string    `json:"target,omitempty"`
	FromDate time.Time `json:"from_date,omitempty"`
	ToDate   time.Time `json:"to_date,omitempty"`
	Page     int       `json:"page,omitempty"`
	PageSize int       `json:"page_size,omitempty"`
}

// ListScansResponse represents the response with paginated scans
type ListScansResponse struct {
	Scans      []ScanListItem `json:"scans"`
	Total      int64          `json:"total"`
	Page       int            `json:"page"`
	PageSize   int            `json:"page_size"`
	TotalPages int            `json:"total_pages"`
}

// ScanListItem represents a scan in the list view
type ScanListItem struct {
	ID            uuid.UUID  `json:"id"`
	Target        string     `json:"target"`
	Status        string     `json:"status"`
	Progress      int        `json:"progress"`
	FindingsCount int        `json:"findings_count"`
	RiskScore     float64    `json:"risk_score"`
	StartedAt     *time.Time `json:"started_at,omitempty"`
	CompletedAt   *time.Time `json:"completed_at,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
}

// CancelScanResponse represents the response from cancelling a scan
type CancelScanResponse struct {
	ID      uuid.UUID `json:"id"`
	Status  string    `json:"status"`
	Message string    `json:"message"`
}

// ============================================================================
// Finding Models
// ============================================================================

// Finding represents a security finding
type Finding struct {
	ID          uuid.UUID       `json:"id"`
	ScanID      uuid.UUID       `json:"scan_id"`
	Module      string          `json:"module"`
	Title       string          `json:"title"`
	Description string          `json:"description"`
	Severity    Severity        `json:"severity"`
	Category    string          `json:"category"`
	Evidence    FindingEvidence `json:"evidence"`
	Remediation string          `json:"remediation"`
	CVSS        float64         `json:"cvss,omitempty"`
	CVEs        []string        `json:"cves,omitempty"`
	References  []string        `json:"references"`
	CreatedAt   time.Time       `json:"created_at"`
}

// FindingEvidence contains evidence for a finding
type FindingEvidence struct {
	Request    string            `json:"request,omitempty"`
	Response   string            `json:"response,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`
	Payload    string            `json:"payload,omitempty"`
	Snippet    string            `json:"snippet,omitempty"`
	URL        string            `json:"url,omitempty"`
	Screenshot string            `json:"screenshot,omitempty"`
}

// FindingSummary provides a summary of findings by severity
type FindingSummary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
	Total    int `json:"total"`
}

// ============================================================================
// Module Models
// ============================================================================

// ModuleResult contains results from a single module
type ModuleResult struct {
	Module    string     `json:"module"`
	Status    string     `json:"status"`
	Findings  []Finding  `json:"findings"`
	StartedAt time.Time  `json:"started_at"`
	EndedAt   *time.Time `json:"ended_at,omitempty"`
	Error     string     `json:"error,omitempty"`
}

// ModuleStatus represents the status of a module execution
type ModuleStatus struct {
	Name      string    `json:"name"`
	Status    string    `json:"status"`
	Progress  int       `json:"progress"`
	StartedAt time.Time `json:"started_at"`
	Message   string    `json:"message,omitempty"`
}

// ============================================================================
// Report Models
// ============================================================================

// Report represents a complete scan report
type Report struct {
	ID              uuid.UUID  `json:"id"`
	ScanID          uuid.UUID  `json:"scan_id"`
	Target          string     `json:"target"`
	Status          string     `json:"status"`
	StartedAt       time.Time  `json:"started_at"`
	CompletedAt     *time.Time `json:"completed_at,omitempty"`
	Duration        int        `json:"duration_seconds"`
	ModulesRun      []string   `json:"modules_run"`
	FindingsSummary Summary    `json:"findings_summary"`
	Findings        []Finding  `json:"findings"`
	RiskScore       float64    `json:"risk_score"`
}

// Summary provides aggregated finding counts
type Summary struct {
	Total    int `json:"total"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

// ============================================================================
// SSE Event Types
// ============================================================================

// ScanEventType represents different types of scan events
type ScanEventType string

const (
	EventScanStarted       ScanEventType = "scan.started"
	EventScanCompleted     ScanEventType = "scan.completed"
	EventScanFailed        ScanEventType = "scan.failed"
	EventScanCancelled     ScanEventType = "scan.cancelled"
	EventModuleStarted     ScanEventType = "module.started"
	EventModuleCompleted   ScanEventType = "module.completed"
	EventModuleFailed      ScanEventType = "module.failed"
	EventFindingDiscovered ScanEventType = "finding.discovered"
	EventProgressUpdate    ScanEventType = "progress.update"
	EventHeartbeat         ScanEventType = "heartbeat"
	EventTargetClassified  ScanEventType = "target.classified"
	EventWarning           ScanEventType = "warning"
)

// ScanEvent represents a scan event for SSE
type ScanEvent struct {
	Type      ScanEventType   `json:"type"`
	ScanID    uuid.UUID       `json:"scan_id"`
	Timestamp time.Time       `json:"timestamp"`
	Data      json.RawMessage `json:"data"`
}

// ScanEventData contains event-specific data
type ScanEventData struct {
	ScanStartedData     *ScanStartedData     `json:"scan_started,omitempty"`
	ModuleStartedData   *ModuleStartedData   `json:"module_started,omitempty"`
	ModuleCompletedData *ModuleCompletedData `json:"module_completed,omitempty"`
	FindingData         *FindingEventData    `json:"finding,omitempty"`
	ProgressData        *ProgressEventData   `json:"progress,omitempty"`
	ErrorData           *ErrorEventData      `json:"error,omitempty"`
}

// ScanStartedData contains data for scan.started event
type ScanStartedData struct {
	Target  string   `json:"target"`
	Modules []string `json:"modules"`
}

// ModuleStartedData contains data for module.started event
type ModuleStartedData struct {
	Module string `json:"module"`
}

// ModuleCompletedData contains data for module.completed event
type ModuleCompletedData struct {
	Module   string `json:"module"`
	Findings int    `json:"findings"`
	Duration int    `json:"duration_seconds"`
}

// FindingEventData contains data for finding.discovered event
type FindingEventData struct {
	Finding Finding `json:"finding"`
}

// ProgressEventData contains data for progress.update event
type ProgressEventData struct {
	Percent       int       `json:"percent"`
	CurrentModule string    `json:"current_module,omitempty"`
	ModulesDone   int       `json:"modules_done"`
	ModulesTotal  int       `json:"modules_total"`
	FindingsCount int       `json:"findings_count"`
	ETA           time.Time `json:"eta,omitempty"`
	Message       string    `json:"message,omitempty"`
}

// ErrorEventData contains data for error events
type ErrorEventData struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// ============================================================================
// Error Types
// ============================================================================

// ScanError represents a scan-related error
type ScanError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *ScanError) Error() string {
	return e.Message
}

// Common scan errors
var (
	ErrScanNotFound       = &ScanError{Code: "scan_not_found", Message: "Scan not found"}
	ErrScanNotAuthorized  = &ScanError{Code: "not_authorized", Message: "Not authorized to access this scan"}
	ErrScanAlreadyRunning = &ScanError{Code: "already_running", Message: "Scan is already running"}
	ErrScanNotRunning     = &ScanError{Code: "not_running", Message: "Scan is not running"}
	ErrInvalidScope       = &ScanError{Code: "invalid_scope", Message: "Invalid scan scope"}
	ErrTargetBlocked      = &ScanError{Code: "target_blocked", Message: "Target is blocked from scanning"}
	ErrRateLimitExceeded  = &ScanError{Code: "rate_limit_exceeded", Message: "Rate limit exceeded"}
	ErrInsufficientTier   = &ScanError{Code: "insufficient_tier", Message: "Insufficient subscription tier"}
)

// ============================================================================
// Tier Limits
// ============================================================================

// TierLimits defines scan limits per user tier
type TierLimits struct {
	MaxScansPerDay     int
	MaxConcurrentScans int
	MaxDuration        time.Duration
	AllowedModules     []string
	AllowedScopes      []string
}

// GetTierLimits returns limits for a specific tier
func GetTierLimits(tier string) TierLimits {
	switch tier {
	case "enterprise":
		return TierLimits{
			MaxScansPerDay:     1000,
			MaxConcurrentScans: 10,
			MaxDuration:        4 * time.Hour,
			AllowedModules:     []string{"recon", "web", "api", "agentic", "intel"},
			AllowedScopes:      []string{"quick", "standard", "deep", "comprehensive"},
		}
	case "pro":
		return TierLimits{
			MaxScansPerDay:     100,
			MaxConcurrentScans: 3,
			MaxDuration:        2 * time.Hour,
			AllowedModules:     []string{"recon", "web", "api", "intel"},
			AllowedScopes:      []string{"quick", "standard", "deep"},
		}
	default: // free
		return TierLimits{
			MaxScansPerDay:     5,
			MaxConcurrentScans: 1,
			MaxDuration:        30 * time.Minute,
			AllowedModules:     []string{"recon", "web"},
			AllowedScopes:      []string{"quick", "standard"},
		}
	}
}

// ValidateModules checks if modules are allowed for the tier
func (l TierLimits) ValidateModules(requested []string) []string {
	allowed := make(map[string]bool)
	for _, m := range l.AllowedModules {
		allowed[m] = true
	}

	var invalid []string
	for _, m := range requested {
		if !allowed[m] {
			invalid = append(invalid, m)
		}
	}
	return invalid
}

// ValidateScope checks if scope is allowed for the tier
func (l TierLimits) ValidateScope(scope string) bool {
	for _, s := range l.AllowedScopes {
		if s == scope {
			return true
		}
	}
	return false
}

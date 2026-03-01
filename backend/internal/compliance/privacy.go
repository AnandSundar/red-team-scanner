package compliance

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// PrivacyManager handles GDPR and CCPA compliance operations
type PrivacyManager struct {
	store PrivacyStore
}

// PrivacyStore interface for database operations
type PrivacyStore interface {
	// User data operations
	GetUserData(ctx context.Context, userID uuid.UUID) (*UserData, error)
	DeleteUserData(ctx context.Context, userID uuid.UUID) error

	// Scan data operations
	ListUserScans(ctx context.Context, userID uuid.UUID) ([]ScanData, error)
	DeleteUserScans(ctx context.Context, userID uuid.UUID) error

	// Finding data operations
	ListUserFindings(ctx context.Context, userID uuid.UUID) ([]FindingData, error)
	DeleteUserFindings(ctx context.Context, userID uuid.UUID) error

	// Report data operations
	ListUserReports(ctx context.Context, userID uuid.UUID) ([]ReportData, error)
	DeleteUserReports(ctx context.Context, userID uuid.UUID) error

	// Audit log operations
	GetUserAuditLogs(ctx context.Context, userID uuid.UUID) ([]AuditLog, error)
	AnonymizeAuditLogs(ctx context.Context, userID uuid.UUID) error

	// Consent operations
	GetUserConsents(ctx context.Context, userID uuid.UUID) ([]ConsentRecord, error)
	RecordConsent(ctx context.Context, params RecordConsentParams) error
	WithdrawConsent(ctx context.Context, userID uuid.UUID, consentType string) error

	// ToS operations
	DeleteToSAcceptance(ctx context.Context, userID uuid.UUID) error

	// API key operations
	RevokeUserAPIKeys(ctx context.Context, userID uuid.UUID) error
}

// UserData represents a user's complete data export
type UserData struct {
	UserID        uuid.UUID       `json:"user_id"`
	ClerkUserID   string          `json:"clerk_user_id,omitempty"`
	Tier          string          `json:"tier"`
	APIKey        string          `json:"api_key,omitempty"`
	CreatedAt     time.Time       `json:"created_at"`
	UpdatedAt     time.Time       `json:"updated_at"`
	Scans         []ScanData      `json:"scans"`
	Findings      []FindingData   `json:"findings"`
	Reports       []ReportData    `json:"reports"`
	AuditLogs     []AuditLog      `json:"audit_logs"`
	Consents      []ConsentRecord `json:"consents"`
	ToSAcceptance *ToSAcceptance  `json:"tos_acceptance,omitempty"`
}

// ScanData represents scan data for export
type ScanData struct {
	ID              uuid.UUID       `json:"id"`
	Target          string          `json:"target"`
	TargetType      string          `json:"target_type"`
	Scope           string          `json:"scope"`
	Status          string          `json:"status"`
	AuthConfirmed   bool            `json:"auth_confirmed"`
	AuthConfirmedIP string          `json:"auth_confirmed_ip,omitempty"`
	AuthConfirmedAt *time.Time      `json:"auth_confirmed_at,omitempty"`
	StartedAt       *time.Time      `json:"started_at,omitempty"`
	CompletedAt     *time.Time      `json:"completed_at,omitempty"`
	CreatedAt       time.Time       `json:"created_at"`
	CustomHeaders   json.RawMessage `json:"custom_headers,omitempty"`
}

// FindingData represents finding data for export
type FindingData struct {
	ID                uuid.UUID       `json:"id"`
	ScanJobID         uuid.UUID       `json:"scan_job_id"`
	Module            string          `json:"module"`
	Category          string          `json:"category"`
	Severity          string          `json:"severity"`
	CVSSScore         float64         `json:"cvss_score,omitempty"`
	CVSSVector        string          `json:"cvss_vector,omitempty"`
	OWASPStandard     string          `json:"owasp_standard,omitempty"`
	OWASPAgentic      string          `json:"owasp_agentic,omitempty"`
	Title             string          `json:"title"`
	Description       string          `json:"description"`
	RawEvidence       string          `json:"raw_evidence,omitempty"`
	BusinessImpact    string          `json:"business_impact,omitempty"`
	Remediation       string          `json:"remediation,omitempty"`
	RemediationEffort string          `json:"remediation_effort,omitempty"`
	References        json.RawMessage `json:"references,omitempty"`
	CreatedAt         time.Time       `json:"created_at"`
}

// ReportData represents report data for export
type ReportData struct {
	ID                 uuid.UUID       `json:"id"`
	ScanJobID          uuid.UUID       `json:"scan_job_id"`
	PDFURL             string          `json:"pdf_url,omitempty"`
	JSONURL            string          `json:"json_url,omitempty"`
	ShareToken         string          `json:"share_token,omitempty"`
	ShareExpiresAt     *time.Time      `json:"share_expires_at,omitempty"`
	ExecutiveSummary   string          `json:"executive_summary,omitempty"`
	RemediationRoadmap json.RawMessage `json:"remediation_roadmap,omitempty"`
	CreatedAt          time.Time       `json:"created_at"`
}

// ConsentRecord represents a user's consent record
type ConsentRecord struct {
	ID          uuid.UUID `json:"id"`
	UserID      uuid.UUID `json:"user_id"`
	ConsentType string    `json:"consent_type"`
	Granted     bool      `json:"granted"`
	GrantedAt   time.Time `json:"granted_at"`
	IPAddress   string    `json:"ip_address,omitempty"`
	UserAgent   string    `json:"user_agent,omitempty"`
	Version     string    `json:"version"`
}

// RecordConsentParams parameters for recording consent
type RecordConsentParams struct {
	UserID      uuid.UUID
	ConsentType string
	Granted     bool
	IPAddress   string
	UserAgent   string
	Version     string
}

// ConsentType represents different types of consent
type ConsentType string

const (
	ConsentTypeMarketing      ConsentType = "marketing"
	ConsentTypeAnalytics      ConsentType = "analytics"
	ConsentTypeThirdParty     ConsentType = "third_party_sharing"
	ConsentTypeDataProcessing ConsentType = "data_processing"
)

// DataExportRequest represents a data export request
type DataExportRequest struct {
	RequestID   string    `json:"request_id"`
	UserID      uuid.UUID `json:"user_id"`
	Formats     []string  `json:"formats"`
	RequestedAt time.Time `json:"requested_at"`
	Status      string    `json:"status"`
}

// DataDeletionRequest represents a data deletion request
type DataDeletionRequest struct {
	RequestID   string    `json:"request_id"`
	UserID      uuid.UUID `json:"user_id"`
	Reason      string    `json:"reason,omitempty"`
	RequestedAt time.Time `json:"requested_at"`
	Status      string    `json:"status"`
}

// NewPrivacyManager creates a new privacy manager
func NewPrivacyManager(store PrivacyStore) *PrivacyManager {
	return &PrivacyManager{
		store: store,
	}
}

// ExportUserData exports all user data for GDPR/CCPA compliance
func (p *PrivacyManager) ExportUserData(ctx context.Context, userID uuid.UUID) (*UserData, error) {
	// Get user info
	user, err := p.store.GetUserData(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user data: %w", err)
	}

	// Get scans
	scans, err := p.store.ListUserScans(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user scans: %w", err)
	}

	// Get findings
	findings, err := p.store.ListUserFindings(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user findings: %w", err)
	}

	// Get reports
	reports, err := p.store.ListUserReports(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user reports: %w", err)
	}

	// Get audit logs
	auditLogs, err := p.store.GetUserAuditLogs(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user audit logs: %w", err)
	}

	// Get consents
	consents, err := p.store.GetUserConsents(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user consents: %w", err)
	}

	return &UserData{
		UserID:        userID,
		ClerkUserID:   user.ClerkUserID,
		Tier:          user.Tier,
		APIKey:        user.APIKey,
		CreatedAt:     user.CreatedAt,
		UpdatedAt:     user.UpdatedAt,
		Scans:         scans,
		Findings:      findings,
		Reports:       reports,
		AuditLogs:     auditLogs,
		Consents:      consents,
		ToSAcceptance: user.ToSAcceptance,
	}, nil
}

// ExportUserDataJSON exports user data as JSON
func (p *PrivacyManager) ExportUserDataJSON(ctx context.Context, userID uuid.UUID) ([]byte, error) {
	data, err := p.ExportUserData(ctx, userID)
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(data, "", "  ")
}

// DeleteUserData deletes all user data for GDPR/CCPA compliance
func (p *PrivacyManager) DeleteUserData(ctx context.Context, userID uuid.UUID, requestID string) error {
	// Anonymize audit logs (retain for compliance but remove PII)
	if err := p.store.AnonymizeAuditLogs(ctx, userID); err != nil {
		return fmt.Errorf("failed to anonymize audit logs: %w", err)
	}

	// Delete reports
	if err := p.store.DeleteUserReports(ctx, userID); err != nil {
		return fmt.Errorf("failed to delete reports: %w", err)
	}

	// Delete findings
	if err := p.store.DeleteUserFindings(ctx, userID); err != nil {
		return fmt.Errorf("failed to delete findings: %w", err)
	}

	// Delete scans
	if err := p.store.DeleteUserScans(ctx, userID); err != nil {
		return fmt.Errorf("failed to delete scans: %w", err)
	}

	// Delete ToS acceptance
	if err := p.store.DeleteToSAcceptance(ctx, userID); err != nil {
		return fmt.Errorf("failed to delete ToS acceptance: %w", err)
	}

	// Revoke API keys
	if err := p.store.RevokeUserAPIKeys(ctx, userID); err != nil {
		return fmt.Errorf("failed to revoke API keys: %w", err)
	}

	// Finally delete user record
	if err := p.store.DeleteUserData(ctx, userID); err != nil {
		return fmt.Errorf("failed to delete user data: %w", err)
	}

	return nil
}

// RecordConsent records user consent for a specific purpose
func (p *PrivacyManager) RecordConsent(ctx context.Context, userID uuid.UUID, consentType ConsentType, granted bool, ipAddress, userAgent string) error {
	params := RecordConsentParams{
		UserID:      userID,
		ConsentType: string(consentType),
		Granted:     granted,
		IPAddress:   ipAddress,
		UserAgent:   userAgent,
		Version:     "1.0",
	}
	return p.store.RecordConsent(ctx, params)
}

// WithdrawConsent withdraws user consent for a specific purpose
func (p *PrivacyManager) WithdrawConsent(ctx context.Context, userID uuid.UUID, consentType ConsentType) error {
	return p.store.WithdrawConsent(ctx, userID, string(consentType))
}

// GetConsentStatus checks if user has granted consent for a specific purpose
func (p *PrivacyManager) GetConsentStatus(ctx context.Context, userID uuid.UUID, consentType ConsentType) (bool, error) {
	consents, err := p.store.GetUserConsents(ctx, userID)
	if err != nil {
		return false, err
	}

	for _, consent := range consents {
		if consent.ConsentType == string(consentType) {
			return consent.Granted, nil
		}
	}

	return false, nil
}

// PrivacyRequest represents a privacy-related request (GDPR/CCPA)
type PrivacyRequest struct {
	ID          uuid.UUID  `json:"id"`
	UserID      uuid.UUID  `json:"user_id"`
	Type        string     `json:"type"` // "access", "deletion", "portability"
	Status      string     `json:"status"`
	RequestedAt time.Time  `json:"requested_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
}

// PrivacyPolicy contains privacy policy information
type PrivacyPolicy struct {
	Version     string    `json:"version"`
	LastUpdated time.Time `json:"last_updated"`
	Content     string    `json:"content"`
}

// GetPrivacyPolicy returns the current privacy policy
func (p *PrivacyManager) GetPrivacyPolicy() *PrivacyPolicy {
	return &PrivacyPolicy{
		Version:     "1.0.0",
		LastUpdated: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		Content:     GetDefaultPrivacyPolicy(),
	}
}

// GetDefaultPrivacyPolicy returns the default privacy policy text
func GetDefaultPrivacyPolicy() string {
	return `PRIVACY POLICY

Last Updated: January 1, 2024

1. INTRODUCTION

This Privacy Policy describes how we collect, use, and handle your personal information when you use our security scanning platform.

2. DATA WE COLLECT

2.1 Account Information: Email, user ID, authentication details
2.2 Scan Data: Targets scanned, findings, reports
2.3 Usage Data: IP addresses, user agents, timestamps
2.4 Audit Logs: Security events for compliance

3. HOW WE USE YOUR DATA

- Provide and maintain the Service
- Generate security reports
- Ensure compliance with laws
- Improve our services
- Communicate about your account

4. DATA RETENTION

- Scan data: Retained per your subscription
- Audit logs: 90 days minimum for compliance
- Account data: Until account deletion

5. YOUR RIGHTS (GDPR/CCPA)

You have the right to:
- Access your data
- Correct your data
- Delete your data
- Export your data
- Withdraw consent

6. DATA SECURITY

We implement appropriate technical and organizational measures to protect your data.

7. THIRD PARTIES

We do not sell your personal information. We may share data with:
- Service providers (hosting, AI services)
- Legal authorities when required

8. INTERNATIONAL TRANSFERS

Data may be transferred to and processed in countries outside your jurisdiction.

9. CHANGES TO THIS POLICY

We may update this policy. Continued use constitutes acceptance of changes.

10. CONTACT

For privacy-related requests, contact our Data Protection Officer.`
}

// DataRetentionPolicy defines data retention periods
type DataRetentionPolicy struct {
	ScanDataDays       int `json:"scan_data_days"`
	AuditLogDays       int `json:"audit_log_days"`
	ReportDays         int `json:"report_days"`
	DeletedAccountDays int `json:"deleted_account_days"`
}

// GetDefaultRetentionPolicy returns the default data retention policy
func GetDefaultRetentionPolicy() *DataRetentionPolicy {
	return &DataRetentionPolicy{
		ScanDataDays:       365, // 1 year
		AuditLogDays:       90,  // 90 days minimum for compliance
		ReportDays:         365, // 1 year
		DeletedAccountDays: 30,  // 30 days after deletion request
	}
}

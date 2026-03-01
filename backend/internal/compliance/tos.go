package compliance

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/google/uuid"
)

// ToSVersion is the current version of the Terms of Service
const (
	CurrentToSVersion   = "1.0.0"
	ToSErrorNotAccepted = "Terms of Service must be accepted before scanning."
	ToSErrorOutdated    = "Your Terms of Service acceptance is outdated. Please accept the updated terms."
)

// ToSManager handles Terms of Service operations
type ToSManager struct {
	store          ToSStore
	currentVersion string
}

// ToSStore interface for database operations
type ToSStore interface {
	GetToSAcceptance(ctx context.Context, userID uuid.UUID) (*ToSAcceptance, error)
	CreateToSAcceptance(ctx context.Context, params CreateToSAcceptanceParams) error
	UpdateToSAcceptance(ctx context.Context, params UpdateToSAcceptanceParams) error
	DeleteToSAcceptance(ctx context.Context, userID uuid.UUID) error
	ListAllToSAcceptances(ctx context.Context, limit, offset int32) ([]ToSAcceptance, error)
}

// ToSAcceptance represents a user's Terms of Service acceptance
type ToSAcceptance struct {
	ID         uuid.UUID `json:"id"`
	UserID     uuid.UUID `json:"user_id"`
	Version    string    `json:"version"`
	AcceptedAt time.Time `json:"accepted_at"`
	IPAddress  string    `json:"ip_address,omitempty"`
}

// CreateToSAcceptanceParams parameters for creating a ToS acceptance
type CreateToSAcceptanceParams struct {
	UserID    uuid.UUID
	Version   string
	IPAddress string
}

// UpdateToSAcceptanceParams parameters for updating a ToS acceptance
type UpdateToSAcceptanceParams struct {
	UserID    uuid.UUID
	Version   string
	IPAddress string
}

// ToSStatus represents the ToS acceptance status
type ToSStatus struct {
	Accepted       bool      `json:"accepted"`
	Version        string    `json:"version,omitempty"`
	AcceptedAt     time.Time `json:"accepted_at,omitempty"`
	CurrentVersion string    `json:"current_version"`
	UpToDate       bool      `json:"up_to_date"`
}

// ToSAcceptRequest represents a request to accept ToS
type ToSAcceptRequest struct {
	Accepted bool `json:"accepted"`
}

// ToSAcceptResponse represents the response after accepting ToS
type ToSAcceptResponse struct {
	Success   bool      `json:"success"`
	Message   string    `json:"message"`
	Version   string    `json:"version"`
	Timestamp time.Time `json:"timestamp"`
}

// NewToSManager creates a new ToS manager
func NewToSManager(store ToSStore) *ToSManager {
	version := os.Getenv("TOS_VERSION")
	if version == "" {
		version = CurrentToSVersion
	}

	return &ToSManager{
		store:          store,
		currentVersion: version,
	}
}

// GetCurrentVersion returns the current ToS version
func (t *ToSManager) GetCurrentVersion() string {
	return t.currentVersion
}

// CheckToSStatus checks if a user has accepted the current ToS
func (t *ToSManager) CheckToSStatus(ctx context.Context, userID uuid.UUID) (*ToSStatus, error) {
	acceptance, err := t.store.GetToSAcceptance(ctx, userID)
	if err != nil {
		// No acceptance found
		return &ToSStatus{
			Accepted:       false,
			CurrentVersion: t.currentVersion,
			UpToDate:       false,
		}, nil
	}

	upToDate := acceptance.Version == t.currentVersion

	return &ToSStatus{
		Accepted:       true,
		Version:        acceptance.Version,
		AcceptedAt:     acceptance.AcceptedAt,
		CurrentVersion: t.currentVersion,
		UpToDate:       upToDate,
	}, nil
}

// HasAcceptedToS checks if a user has accepted the current ToS version
func (t *ToSManager) HasAcceptedToS(ctx context.Context, userID uuid.UUID) (bool, error) {
	status, err := t.CheckToSStatus(ctx, userID)
	if err != nil {
		return false, err
	}
	return status.Accepted && status.UpToDate, nil
}

// ValidateToSForScan checks if a user can perform a scan (requires current ToS)
func (t *ToSManager) ValidateToSForScan(ctx context.Context, userID uuid.UUID) error {
	status, err := t.CheckToSStatus(ctx, userID)
	if err != nil {
		return err
	}

	if !status.Accepted {
		return errors.New(ToSErrorNotAccepted)
	}

	if !status.UpToDate {
		return errors.New(ToSErrorOutdated)
	}

	return nil
}

// AcceptToS records a user's acceptance of the Terms of Service
func (t *ToSManager) AcceptToS(ctx context.Context, userID uuid.UUID, ipAddress string) (*ToSAcceptResponse, error) {
	// Check if user already has an acceptance
	existing, err := t.store.GetToSAcceptance(ctx, userID)

	if err != nil {
		// Create new acceptance
		params := CreateToSAcceptanceParams{
			UserID:    userID,
			Version:   t.currentVersion,
			IPAddress: ipAddress,
		}

		if err := t.store.CreateToSAcceptance(ctx, params); err != nil {
			return nil, fmt.Errorf("failed to create ToS acceptance: %w", err)
		}
	} else {
		// Update existing acceptance
		if existing.Version != t.currentVersion {
			params := UpdateToSAcceptanceParams{
				UserID:    userID,
				Version:   t.currentVersion,
				IPAddress: ipAddress,
			}

			if err := t.store.UpdateToSAcceptance(ctx, params); err != nil {
				return nil, fmt.Errorf("failed to update ToS acceptance: %w", err)
			}
		}
	}

	return &ToSAcceptResponse{
		Success:   true,
		Message:   "Terms of Service accepted successfully",
		Version:   t.currentVersion,
		Timestamp: time.Now().UTC(),
	}, nil
}

// RevokeToS revokes a user's ToS acceptance (for account deletion)
func (t *ToSManager) RevokeToS(ctx context.Context, userID uuid.UUID) error {
	return t.store.DeleteToSAcceptance(ctx, userID)
}

// GetClientIP extracts the client IP from a request
func GetClientIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}

// ToSContent contains the Terms of Service text
type ToSContent struct {
	Version   string    `json:"version"`
	Title     string    `json:"title"`
	Content   string    `json:"content"`
	UpdatedAt time.Time `json:"updated_at"`
}

// GetToSContent returns the current ToS content
func (t *ToSManager) GetToSContent() *ToSContent {
	return &ToSContent{
		Version:   t.currentVersion,
		Title:     "Terms of Service",
		Content:   GetDefaultToSText(),
		UpdatedAt: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
	}
}

// GetDefaultToSText returns the default Terms of Service text
func GetDefaultToSText() string {
	return `TERMS OF SERVICE

Last Updated: January 1, 2024

1. ACCEPTANCE OF TERMS

By accessing and using the Red Team Tester security scanning platform ("Service"), you agree to be bound by these Terms of Service ("Terms"). If you do not agree to these Terms, you may not use the Service.

2. DESCRIPTION OF SERVICE

The Service provides security scanning and vulnerability assessment tools designed for authorized security testing and research purposes.

3. AUTHORIZATION REQUIREMENTS

3.1 You MUST have explicit written authorization to scan any target using the Service.
3.2 You are solely responsible for ensuring you have proper authorization before initiating any scan.
3.3 You MUST confirm authorization via the checkbox provided before each scan.

4. PROHIBITED USES

You agree NOT to use the Service to:
- Scan targets without explicit authorization
- Scan government systems (.gov, .mil)
- Scan critical infrastructure without authorization
- Scan private IP ranges (RFC1918) unless in self-hosted mode
- Conduct any illegal activities

5. COMPLIANCE WITH LAWS

You agree to comply with all applicable laws and regulations, including:
- Computer Fraud and Abuse Act (CFAA)
- General Data Protection Regulation (GDPR) where applicable
- California Consumer Privacy Act (CCPA) where applicable
- All local laws governing security testing

6. DATA HANDLING

6.1 Scan results and reports are stored securely.
6.2 We retain audit logs for compliance purposes for 90 days minimum.
6.3 You may request data export or deletion per our Privacy Policy.

7. LIMITATION OF LIABILITY

THE SERVICE IS PROVIDED "AS IS" WITHOUT WARRANTIES. YOU ASSUME ALL RISK FOR YOUR USE OF THE SERVICE.

8. INDEMNIFICATION

You agree to indemnify and hold harmless the Service provider from any claims arising from your use of the Service.

9. TERMINATION

We reserve the right to terminate access for violations of these Terms.

10. CHANGES TO TERMS

We may update these Terms at any time. Continued use constitutes acceptance of changes.

By checking the authorization box, you confirm that you have read, understood, and agree to these Terms of Service.`
}

// ToSRequiredMiddleware is a helper to check ToS acceptance before handling requests
func (t *ToSManager) ToSRequiredMiddleware(next func(ctx context.Context, userID uuid.UUID) error) func(ctx context.Context, userID uuid.UUID) error {
	return func(ctx context.Context, userID uuid.UUID) error {
		if err := t.ValidateToSForScan(ctx, userID); err != nil {
			return err
		}
		return next(ctx, userID)
	}
}

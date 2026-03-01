package api

import (
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/redteam/agentic-scanner/internal/auth"
	"github.com/redteam/agentic-scanner/internal/store"
)

// ============================================================================
// Diff Request/Response Types
// ============================================================================

// FindingDiff represents a finding in the diff comparison
type FindingDiff struct {
	ID               string  `json:"id"`
	Module           string  `json:"module"`
	Category         string  `json:"category"`
	Severity         string  `json:"severity"`
	Title            string  `json:"title"`
	Description      string  `json:"description"`
	CVSSScore        float64 `json:"cvss_score,omitempty"`
	Remediation      string  `json:"remediation,omitempty"`
	MatchedFindingID *string `json:"matched_finding_id,omitempty"`
}

// ScanDiff represents the diff between two scans
type ScanDiff struct {
	Scan1ID           string        `json:"scan1_id"`
	Scan2ID           string        `json:"scan2_id"`
	Scan1Date         string        `json:"scan1_date"`
	Scan2Date         string        `json:"scan2_date"`
	Scan1Target       string        `json:"scan1_target"`
	Scan2Target       string        `json:"scan2_target"`
	NewFindings       []FindingDiff `json:"new_findings"`
	ResolvedFindings  []FindingDiff `json:"resolved_findings"`
	UnchangedFindings []FindingDiff `json:"unchanged_findings"`
	ChangedFindings   []FindingDiff `json:"changed_findings"`
	RiskScoreChange   int           `json:"risk_score_change"`
	Summary           DiffSummary   `json:"summary"`
}

// DiffSummary provides a summary of the diff
type DiffSummary struct {
	NewCount       int `json:"new_count"`
	ResolvedCount  int `json:"resolved_count"`
	UnchangedCount int `json:"unchanged_count"`
	ChangedCount   int `json:"changed_count"`
	TotalScan1     int `json:"total_scan1"`
	TotalScan2     int `json:"total_scan2"`
}

// DiffScansHandler handles GET /api/v1/scans/:id1/diff/:id2
// Compares two scans and returns the differences
func (h *Handler) DiffScansHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get user from context
	user := auth.GetUserFromContext(ctx)
	if user == nil {
		respondError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	// Parse scan IDs from URL
	scan1ID := chi.URLParam(r, "id1")
	scan2ID := chi.URLParam(r, "id2")

	id1, err := uuid.Parse(scan1ID)
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid scan1 ID")
		return
	}

	id2, err := uuid.Parse(scan2ID)
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid scan2 ID")
		return
	}

	// Set RLS context
	if err := h.db.SetUserContext(ctx, user.ClerkUserID, user.ID); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to set user context")
		return
	}

	// Get both scans to verify ownership and get metadata
	scan1, err := h.db.GetScanJobByID(ctx, id1)
	if err != nil {
		respondError(w, http.StatusNotFound, "Scan 1 not found")
		return
	}

	scan2, err := h.db.GetScanJobByID(ctx, id2)
	if err != nil {
		respondError(w, http.StatusNotFound, "Scan 2 not found")
		return
	}

	// Verify both scans belong to the user
	if scan1.UserID != user.ID || scan2.UserID != user.ID {
		respondError(w, http.StatusForbidden, "Access denied to one or both scans")
		return
	}

	// Get findings for both scans
	findings1, err := h.db.GetScanFindingsForDiff(ctx, id1)
	if err != nil {
		respondError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to get findings for scan 1: %v", err))
		return
	}

	findings2, err := h.db.GetScanFindingsForDiff(ctx, id2)
	if err != nil {
		respondError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to get findings for scan 2: %v", err))
		return
	}

	// Perform diff comparison
	diff := performDiffComparison(scan1, scan2, findings1, findings2)

	respondJSON(w, http.StatusOK, diff)
}

// performDiffComparison compares two sets of findings and returns the diff
func performDiffComparison(
	scan1, scan2 *store.ScanJob,
	findings1, findings2 []*store.FindingForDiff,
) ScanDiff {
	diff := ScanDiff{
		Scan1ID:           scan1.ID.String(),
		Scan2ID:           scan2.ID.String(),
		Scan1Date:         scan1.CreatedAt.Format("2006-01-02T15:04:05Z"),
		Scan2Date:         scan2.CreatedAt.Format("2006-01-02T15:04:05Z"),
		Scan1Target:       scan1.Target,
		Scan2Target:       scan2.Target,
		NewFindings:       []FindingDiff{},
		ResolvedFindings:  []FindingDiff{},
		UnchangedFindings: []FindingDiff{},
		ChangedFindings:   []FindingDiff{},
		RiskScoreChange:   int(scan2.RiskScore) - int(scan1.RiskScore),
	}

	// Create maps for efficient lookup
	findings1Map := make(map[string]*store.FindingForDiff)
	for _, f := range findings1 {
		key := generateFindingKey(f)
		findings1Map[key] = f
	}

	findings2Map := make(map[string]*store.FindingForDiff)
	for _, f := range findings2 {
		key := generateFindingKey(f)
		findings2Map[key] = f
	}

	// Track matched findings to identify unchanged ones
	matchedInScan2 := make(map[string]bool)

	// Find resolved and unchanged findings (present in scan1)
	for key, f1 := range findings1Map {
		if f2, exists := findings2Map[key]; exists {
			// Finding exists in both - check if it changed
			findingDiff := FindingDiff{
				ID:               f2.ID.String(),
				Module:           f2.Module,
				Category:         f2.Category,
				Severity:         f2.Severity,
				Title:            f2.Title,
				Description:      f2.Description,
				CVSSScore:        f2.CVSSScore,
				Remediation:      f2.Remediation,
				MatchedFindingID: strPtr(f1.ID.String()),
			}

			// Check if severity changed
			if f1.Severity != f2.Severity {
				findingDiff.MatchedFindingID = strPtr(f1.ID.String())
				diff.ChangedFindings = append(diff.ChangedFindings, findingDiff)
			} else {
				diff.UnchangedFindings = append(diff.UnchangedFindings, findingDiff)
			}
			matchedInScan2[key] = true
		} else {
			// Finding only in scan1 - resolved
			diff.ResolvedFindings = append(diff.ResolvedFindings, FindingDiff{
				ID:          f1.ID.String(),
				Module:      f1.Module,
				Category:    f1.Category,
				Severity:    f1.Severity,
				Title:       f1.Title,
				Description: f1.Description,
				CVSSScore:   f1.CVSSScore,
				Remediation: f1.Remediation,
			})
		}
	}

	// Find new findings (present in scan2 but not scan1)
	for key, f2 := range findings2Map {
		if !matchedInScan2[key] {
			diff.NewFindings = append(diff.NewFindings, FindingDiff{
				ID:          f2.ID.String(),
				Module:      f2.Module,
				Category:    f2.Category,
				Severity:    f2.Severity,
				Title:       f2.Title,
				Description: f2.Description,
				CVSSScore:   f2.CVSSScore,
				Remediation: f2.Remediation,
			})
		}
	}

	// Set summary
	diff.Summary = DiffSummary{
		NewCount:       len(diff.NewFindings),
		ResolvedCount:  len(diff.ResolvedFindings),
		UnchangedCount: len(diff.UnchangedFindings),
		ChangedCount:   len(diff.ChangedFindings),
		TotalScan1:     len(findings1),
		TotalScan2:     len(findings2),
	}

	return diff
}

// generateFindingKey creates a unique key for a finding based on its characteristics
// This is used to match findings between scans
func generateFindingKey(f *store.FindingForDiff) string {
	// Use a combination of module, category, and normalized title for matching
	// This allows us to match findings even if some details changed
	normalizedTitle := normalizeFindingTitle(f.Title)
	return fmt.Sprintf("%s|%s|%s", f.Module, f.Category, normalizedTitle)
}

// normalizeFindingTitle normalizes a finding title for comparison
func normalizeFindingTitle(title string) string {
	// Simple normalization: lowercase and remove extra spaces
	// In a production system, you might want more sophisticated matching
	result := ""
	inSpace := false
	for _, c := range title {
		if c == ' ' || c == '\t' || c == '\n' {
			if !inSpace {
				result += " "
				inSpace = true
			}
		} else {
			// Convert to lowercase
			if c >= 'A' && c <= 'Z' {
				result += string(c + 32)
			} else {
				result += string(c)
			}
			inSpace = false
		}
	}
	return result
}

// strPtr returns a pointer to a string
func strPtr(s string) *string {
	return &s
}

// ensureDiffTypes ensures store types are available
var _ *store.FindingForDiff = nil

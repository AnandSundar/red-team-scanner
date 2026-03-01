package api

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/redteam/agentic-scanner/internal/auth"
	"github.com/redteam/agentic-scanner/internal/store"
)

// ============================================================================
// Dashboard Response Types
// ============================================================================

// DashboardStatsResponse represents the dashboard statistics response
type DashboardStatsResponse struct {
	TotalScans             int64            `json:"total_scans"`
	ScansThisMonth         int64            `json:"scans_this_month"`
	ActiveScans            int64            `json:"active_scans"`
	FindingsBySeverity     map[string]int64 `json:"findings_by_severity"`
	AvgScanDurationSeconds float64          `json:"avg_scan_duration_seconds"`
	SuccessRate            float64          `json:"success_rate"`
	LastScanAt             *time.Time       `json:"last_scan_at,omitempty"`
}

// ScanActivityItem represents a single scan activity entry
type ScanActivityItem struct {
	ID            string    `json:"id"`
	Target        string    `json:"target"`
	Status        string    `json:"status"`
	FindingsCount int64     `json:"findings_count"`
	RiskScore     float64   `json:"risk_score"`
	StartedAt     time.Time `json:"started_at"`
	DurationSecs  int       `json:"duration_seconds"`
}

// DashboardActivityResponse represents the recent scan activity response
type DashboardActivityResponse struct {
	Activities []ScanActivityItem `json:"activities"`
	Total      int64              `json:"total"`
}

// DashboardTrendsResponse represents vulnerability trends over time
type DashboardTrendsResponse struct {
	Dates    []string `json:"dates"`
	Critical []int64  `json:"critical"`
	High     []int64  `json:"high"`
	Medium   []int64  `json:"medium"`
	Low      []int64  `json:"low"`
	Info     []int64  `json:"info"`
}

// TargetStatsItem represents statistics for a scanned target
type TargetStatsItem struct {
	Target         string    `json:"target"`
	ScanCount      int64     `json:"scan_count"`
	LastScannedAt  time.Time `json:"last_scanned_at"`
	LastScanID     string    `json:"last_scan_id"`
	LastScanStatus string    `json:"last_scan_status"`
	AvgRiskScore   float64   `json:"avg_risk_score"`
	TotalFindings  int64     `json:"total_findings"`
}

// DashboardTargetsResponse represents the top targets response
type DashboardTargetsResponse struct {
	Targets []TargetStatsItem `json:"targets"`
	Total   int64             `json:"total"`
}

// ============================================================================
// Dashboard Handlers
// ============================================================================

// DashboardStatsHandler handles GET /api/v1/dashboard/stats
// Returns user's scan statistics
func (h *Handler) DashboardStatsHandler(w http.ResponseWriter, r *http.Request) {
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

	// Get scan statistics
	stats, err := h.db.GetScanStatistics(ctx, user.ID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to get scan statistics: %v", err))
		return
	}

	// Get findings by severity
	severityCounts, err := h.db.GetFindingsBySeverityStats(ctx, user.ID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to get findings statistics: %v", err))
		return
	}

	// Calculate success rate
	var successRate float64
	if stats.TotalScans > 0 {
		successRate = float64(stats.CompletedScans) / float64(stats.TotalScans) * 100
	}

	response := DashboardStatsResponse{
		TotalScans:     stats.TotalScans,
		ScansThisMonth: stats.ScansThisMonth,
		ActiveScans:    stats.ActiveScans,
		FindingsBySeverity: map[string]int64{
			"Critical":      severityCounts.Critical,
			"High":          severityCounts.High,
			"Medium":        severityCounts.Medium,
			"Low":           severityCounts.Low,
			"Informational": severityCounts.Informational,
		},
		AvgScanDurationSeconds: stats.AvgDurationSeconds,
		SuccessRate:            successRate,
		LastScanAt:             stats.LastScanAt,
	}

	respondJSON(w, http.StatusOK, response)
}

// DashboardActivityHandler handles GET /api/v1/dashboard/activity
// Returns recent scan activity
func (h *Handler) DashboardActivityHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get user from context
	user := auth.GetUserFromContext(ctx)
	if user == nil {
		respondError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	// Parse pagination parameters
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 100 {
		limit = 20 // Default limit
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

	// Get scan activity
	activities, total, err := h.db.GetScanActivity(ctx, user.ID, int32(limit), int32(offset))
	if err != nil {
		respondError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to get scan activity: %v", err))
		return
	}

	var items []ScanActivityItem
	for _, activity := range activities {
		item := ScanActivityItem{
			ID:            activity.ID.String(),
			Target:        activity.Target,
			Status:        activity.Status,
			FindingsCount: activity.FindingsCount,
			RiskScore:     activity.RiskScore,
			StartedAt:     activity.StartedAt,
		}

		// Calculate duration
		if activity.CompletedAt != nil {
			item.DurationSecs = int(activity.CompletedAt.Sub(activity.StartedAt).Seconds())
		} else if activity.Status == "running" || activity.Status == "queued" {
			item.DurationSecs = int(time.Since(activity.StartedAt).Seconds())
		}

		items = append(items, item)
	}

	respondJSON(w, http.StatusOK, DashboardActivityResponse{
		Activities: items,
		Total:      total,
	})
}

// DashboardTrendsHandler handles GET /api/v1/dashboard/trends
// Returns vulnerability trends over time
func (h *Handler) DashboardTrendsHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get user from context
	user := auth.GetUserFromContext(ctx)
	if user == nil {
		respondError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	// Parse days parameter (default to 30 days)
	days, _ := strconv.Atoi(r.URL.Query().Get("days"))
	if days <= 0 || days > 365 {
		days = 30
	}

	// Parse start_date and end_date if provided
	var startDate, endDate *time.Time
	if startDateStr := r.URL.Query().Get("start_date"); startDateStr != "" {
		if parsed, err := time.Parse("2006-01-02", startDateStr); err == nil {
			startDate = &parsed
		}
	}
	if endDateStr := r.URL.Query().Get("end_date"); endDateStr != "" {
		if parsed, err := time.Parse("2006-01-02", endDateStr); err == nil {
			endDate = &parsed
		}
	}

	// Set RLS context
	if err := h.db.SetUserContext(ctx, user.ClerkUserID, user.ID); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to set user context")
		return
	}

	// Get vulnerability trends
	trends, err := h.db.GetVulnerabilityTrends(ctx, user.ID, days, startDate, endDate)
	if err != nil {
		respondError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to get vulnerability trends: %v", err))
		return
	}

	// Build response arrays
	var dates []string
	var critical, high, medium, low, info []int64

	for _, trend := range trends {
		dates = append(dates, trend.Date)
		critical = append(critical, trend.Critical)
		high = append(high, trend.High)
		medium = append(medium, trend.Medium)
		low = append(low, trend.Low)
		info = append(info, trend.Info)
	}

	respondJSON(w, http.StatusOK, DashboardTrendsResponse{
		Dates:    dates,
		Critical: critical,
		High:     high,
		Medium:   medium,
		Low:      low,
		Info:     info,
	})
}

// DashboardTargetsHandler handles GET /api/v1/dashboard/targets
// Returns most scanned targets
func (h *Handler) DashboardTargetsHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get user from context
	user := auth.GetUserFromContext(ctx)
	if user == nil {
		respondError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	// Parse limit parameter
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 50 {
		limit = 10 // Default limit
	}

	// Set RLS context
	if err := h.db.SetUserContext(ctx, user.ClerkUserID, user.ID); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to set user context")
		return
	}

	// Get most scanned targets
	targets, total, err := h.db.GetMostScannedTargets(ctx, user.ID, int32(limit))
	if err != nil {
		respondError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to get targets: %v", err))
		return
	}

	var items []TargetStatsItem
	for _, target := range targets {
		items = append(items, TargetStatsItem{
			Target:         target.Target,
			ScanCount:      target.ScanCount,
			LastScannedAt:  target.LastScannedAt,
			LastScanID:     target.LastScanID.String(),
			LastScanStatus: target.LastScanStatus,
			AvgRiskScore:   target.AvgRiskScore,
			TotalFindings:  target.TotalFindings,
		})
	}

	respondJSON(w, http.StatusOK, DashboardTargetsResponse{
		Targets: items,
		Total:   total,
	})
}

// ensureDashboardTypes ensures store types are available
var _ *store.ScanStatistics = nil
var _ *store.FindingSeverityStats = nil
var _ []store.ScanActivity = nil
var _ []store.VulnerabilityTrend = nil
var _ []store.TargetStats = nil

package report

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/redteam/agentic-scanner/internal/ai"
	"github.com/redteam/agentic-scanner/internal/scanner"
)

// ============================================================================
// JSON Report Generator
// ============================================================================

// JSONGenerator generates JSON reports
type JSONGenerator struct{}

// NewJSONGenerator creates a new JSON generator
func NewJSONGenerator() *JSONGenerator {
	return &JSONGenerator{}
}

// ReportExport represents the exported report structure
type ReportExport struct {
	ReportID       string                 `json:"report_id"`
	ScanID         string                 `json:"scan_id"`
	Target         string                 `json:"target"`
	TargetType     string                 `json:"target_type"`
	GeneratedAt    time.Time              `json:"generated_at"`
	ScannerVersion string                 `json:"scanner_version"`
	AIAnalysis     *ai.AIAnalysisResponse `json:"ai_analysis,omitempty"`
	RawFindings    []ai.RawFinding        `json:"raw_findings"`
	Summary        scanner.Summary        `json:"summary"`
	RiskScore      float64                `json:"risk_score"`
	RiskLevel      string                 `json:"risk_level"`
	ModulesRun     []string               `json:"modules_run"`
	ScanDuration   int                    `json:"scan_duration_seconds"`
	Metadata       ReportMetadata         `json:"metadata"`
}

// ReportMetadata contains additional report metadata
type ReportMetadata struct {
	GeneratedBy    string            `json:"generated_by"`
	AIProvider     string            `json:"ai_provider,omitempty"`
	TokenUsage     ai.TokenUsage     `json:"token_usage,omitempty"`
	AnalysisCached bool              `json:"analysis_cached"`
	CustomFields   map[string]string `json:"custom_fields,omitempty"`
}

// AIReportExport represents a report with full AI analysis
type AIReportExport struct {
	ReportID         string               `json:"report_id"`
	ScanID           string               `json:"scan_id"`
	Target           string               `json:"target"`
	GeneratedAt      time.Time            `json:"generated_at"`
	ScannerVersion   string               `json:"scanner_version"`
	ExecutiveSummary string               `json:"executive_summary"`
	RiskScore        int                  `json:"risk_score"`
	RiskLevel        string               `json:"risk_level"`
	Findings         []ai.AIFinding       `json:"findings"`
	RemediationPlan  []ai.RemediationStep `json:"remediation_plan"`
	ModulesRun       []string             `json:"modules_run"`
	ScanDuration     int                  `json:"scan_duration_seconds"`
	Technologies     []string             `json:"technologies,omitempty"`
	AIProvider       string               `json:"ai_provider"`
}

// Generate creates a basic JSON report
func (g *JSONGenerator) Generate(report *scanner.Report) ([]byte, error) {
	export := ReportExport{
		ReportID:       report.ID.String(),
		ScanID:         report.ScanID.String(),
		Target:         report.Target,
		GeneratedAt:    time.Now(),
		ScannerVersion: "1.0.0",
		Summary: scanner.Summary{
			Total:    report.FindingsSummary.Total,
			Critical: report.FindingsSummary.Critical,
			High:     report.FindingsSummary.High,
			Medium:   report.FindingsSummary.Medium,
			Low:      report.FindingsSummary.Low,
			Info:     report.FindingsSummary.Info,
		},
		RiskScore:    report.RiskScore,
		RiskLevel:    calculateRiskLevel(report.RiskScore),
		ModulesRun:   report.ModulesRun,
		ScanDuration: report.Duration,
		Metadata: ReportMetadata{
			GeneratedBy: "Agentic Scanner v1.0",
		},
	}
	return json.MarshalIndent(export, "", "  ")
}

// GenerateWithAI creates a JSON report with AI analysis
func (g *JSONGenerator) GenerateWithAI(report *scanner.Report, analysis *ai.AIAnalysisResponse) ([]byte, error) {
	// Convert scanner findings to raw findings
	rawFindings := make([]ai.RawFinding, len(report.Findings))
	for i, f := range report.Findings {
		rawFindings[i] = ai.RawFinding{
			ID:          f.ID,
			Module:      f.Module,
			Title:       f.Title,
			Description: f.Description,
			Severity:    string(f.Severity),
			Category:    f.Category,
			Evidence: ai.FindingEvidence{
				Request:    f.Evidence.Request,
				Response:   f.Evidence.Response,
				Headers:    f.Evidence.Headers,
				Payload:    f.Evidence.Payload,
				Snippet:    f.Evidence.Snippet,
				URL:        f.Evidence.URL,
				Screenshot: f.Evidence.Screenshot,
			},
			CVSS:       f.CVSS,
			CVEs:       f.CVEs,
			References: f.References,
			Timestamp:  f.CreatedAt,
		}
	}

	export := ReportExport{
		ReportID:       report.ID.String(),
		ScanID:         report.ScanID.String(),
		Target:         report.Target,
		GeneratedAt:    time.Now(),
		ScannerVersion: "1.0.0",
		AIAnalysis:     analysis,
		RawFindings:    rawFindings,
		Summary: scanner.Summary{
			Total:    report.FindingsSummary.Total,
			Critical: report.FindingsSummary.Critical,
			High:     report.FindingsSummary.High,
			Medium:   report.FindingsSummary.Medium,
			Low:      report.FindingsSummary.Low,
			Info:     report.FindingsSummary.Info,
		},
		RiskScore:    report.RiskScore,
		RiskLevel:    calculateRiskLevel(report.RiskScore),
		ModulesRun:   report.ModulesRun,
		ScanDuration: report.Duration,
		Metadata: ReportMetadata{
			GeneratedBy:    "Agentic Scanner v1.0",
			AIProvider:     analysis.AIProvider,
			TokenUsage:     analysis.TokenUsage,
			AnalysisCached: analysis.Cached,
		},
	}

	return json.MarshalIndent(export, "", "  ")
}

// GenerateAIFullReport creates a comprehensive AI-powered report
func (g *JSONGenerator) GenerateAIFullReport(report *ai.AIReport) ([]byte, error) {
	export := AIReportExport{
		ReportID:         report.ReportID.String(),
		ScanID:           report.ScanID.String(),
		Target:           report.Target,
		GeneratedAt:      report.GeneratedAt,
		ScannerVersion:   report.ScannerVersion,
		ExecutiveSummary: report.Analysis.ExecutiveSummary,
		RiskScore:        report.Analysis.RiskScore,
		RiskLevel:        report.Analysis.RiskLevel,
		Findings:         report.Analysis.Findings,
		RemediationPlan:  report.Analysis.RemediationRoadmap,
		ModulesRun:       report.ScanMetadata.ModulesRun,
		ScanDuration:     report.ScanMetadata.Duration,
		Technologies:     report.ScanMetadata.Technologies,
		AIProvider:       report.Analysis.AIProvider,
	}

	return json.MarshalIndent(export, "", "  ")
}

// GenerateMinimal creates a minimal JSON report with just the essentials
func (g *JSONGenerator) GenerateMinimal(report *scanner.Report) ([]byte, error) {
	minimal := struct {
		ReportID    string          `json:"report_id"`
		ScanID      string          `json:"scan_id"`
		Target      string          `json:"target"`
		RiskScore   float64         `json:"risk_score"`
		RiskLevel   string          `json:"risk_level"`
		Findings    int             `json:"total_findings"`
		Summary     scanner.Summary `json:"summary"`
		GeneratedAt time.Time       `json:"generated_at"`
	}{
		ReportID:    report.ID.String(),
		ScanID:      report.ScanID.String(),
		Target:      report.Target,
		RiskScore:   report.RiskScore,
		RiskLevel:   calculateRiskLevel(report.RiskScore),
		Findings:    len(report.Findings),
		Summary:     report.FindingsSummary,
		GeneratedAt: time.Now(),
	}

	return json.MarshalIndent(minimal, "", "  ")
}

// ExportFindings exports findings in various formats
func (g *JSONGenerator) ExportFindings(findings []scanner.Finding, format string) ([]byte, error) {
	type ExportFinding struct {
		ID          string                 `json:"id"`
		Title       string                 `json:"title"`
		Description string                 `json:"description"`
		Severity    string                 `json:"severity"`
		Category    string                 `json:"category"`
		CVSS        float64                `json:"cvss"`
		CVEs        []string               `json:"cves"`
		Evidence    map[string]interface{} `json:"evidence"`
		Remediation string                 `json:"remediation"`
		References  []string               `json:"references"`
	}

	export := make([]ExportFinding, len(findings))
	for i, f := range findings {
		export[i] = ExportFinding{
			ID:          f.ID.String(),
			Title:       f.Title,
			Description: f.Description,
			Severity:    string(f.Severity),
			Category:    f.Category,
			CVSS:        f.CVSS,
			CVEs:        f.CVEs,
			Evidence: map[string]interface{}{
				"request":  f.Evidence.Request,
				"response": f.Evidence.Response,
				"payload":  f.Evidence.Payload,
				"snippet":  f.Evidence.Snippet,
				"url":      f.Evidence.URL,
			},
			Remediation: f.Remediation,
			References:  f.References,
		}
	}

	switch format {
	case "json":
		return json.MarshalIndent(export, "", "  ")
	case "sarif":
		return g.toSARIF(findings)
	default:
		return json.MarshalIndent(export, "", "  ")
	}
}

// toSARIF converts findings to SARIF format
func (g *JSONGenerator) toSARIF(findings []scanner.Finding) ([]byte, error) {
	sarif := map[string]interface{}{
		"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		"version": "2.1.0",
		"runs": []map[string]interface{}{
			{
				"tool": map[string]interface{}{
					"driver": map[string]interface{}{
						"name":           "Agentic Scanner",
						"version":        "1.0.0",
						"informationUri": "https://github.com/redteam/agentic-scanner",
					},
				},
				"results": g.findingsToSARIFResults(findings),
			},
		},
	}

	return json.MarshalIndent(sarif, "", "  ")
}

func (g *JSONGenerator) findingsToSARIFResults(findings []scanner.Finding) []map[string]interface{} {
	results := make([]map[string]interface{}, len(findings))

	for i, f := range findings {
		level := "note"
		switch f.Severity {
		case scanner.SeverityCritical, scanner.SeverityHigh:
			level = "error"
		case scanner.SeverityMedium:
			level = "warning"
		}

		results[i] = map[string]interface{}{
			"ruleId": f.Category,
			"level":  level,
			"message": map[string]interface{}{
				"text": f.Description,
			},
			"locations": []map[string]interface{}{
				{
					"physicalLocation": map[string]interface{}{
						"artifactLocation": map[string]interface{}{
							"uri": f.Evidence.URL,
						},
					},
				},
			},
			"properties": map[string]interface{}{
				"severity":    string(f.Severity),
				"cvss":        f.CVSS,
				"module":      f.Module,
				"remediation": f.Remediation,
			},
		}
	}

	return results
}

// ============================================================================
// Helper Functions
// ============================================================================

func calculateRiskLevel(score float64) string {
	switch {
	case score >= 80:
		return "critical"
	case score >= 60:
		return "high"
	case score >= 40:
		return "medium"
	case score >= 20:
		return "low"
	default:
		return "info"
	}
}

// ValidateReport validates a report structure
func ValidateReport(report *scanner.Report) error {
	if report.ID == uuid.Nil {
		return fmt.Errorf("report ID is required")
	}
	if report.ScanID == uuid.Nil {
		return fmt.Errorf("scan ID is required")
	}
	if report.Target == "" {
		return fmt.Errorf("target is required")
	}
	return nil
}

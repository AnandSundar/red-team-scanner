package ai

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"
)

// Analyzer provides AI-powered security analysis capabilities
type Analyzer struct {
	client *AIClient
}

// NewAnalyzer creates a new AI analyzer
func NewAnalyzer() (*Analyzer, error) {
	client, err := NewAIClient()
	if err != nil {
		return nil, fmt.Errorf("failed to create AI client: %w", err)
	}

	return &Analyzer{
		client: client,
	}, nil
}

// NewAnalyzerWithClient creates an analyzer with an existing client
func NewAnalyzerWithClient(client *AIClient) *Analyzer {
	return &Analyzer{
		client: client,
	}
}

// AnalyzeScan performs complete AI analysis on a scan
func (a *Analyzer) AnalyzeScan(ctx context.Context, req AIAnalysisRequest) (*AIAnalysisResponse, error) {
	if a.client == nil {
		return nil, fmt.Errorf("AI client not initialized")
	}

	// Validate request
	if req.ScanID == uuid.Nil {
		return nil, fmt.Errorf("scan ID is required")
	}

	if len(req.Findings) == 0 {
		return a.generateEmptyAnalysis(req), nil
	}

	// Perform AI analysis
	response, err := a.client.AnalyzeScan(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("AI analysis failed: %w", err)
	}

	// Post-process findings
	response.Findings = a.enrichFindings(response.Findings, req.Findings)
	response.RemediationRoadmap = a.prioritizeRemediation(response.RemediationRoadmap)
	response.RiskScore = a.CalculateRiskScore(response.Findings)
	response.RiskLevel = calculateRiskLevel(response.RiskScore)

	return response, nil
}

// AnalyzeFinding performs individual finding analysis
func (a *Analyzer) AnalyzeFinding(ctx context.Context, finding RawFinding, context string) (*AIFinding, error) {
	req := AIAnalysisRequest{
		Target:     finding.Target,
		TargetType: "finding",
		Findings:   []RawFinding{finding},
		Timestamp:  time.Now(),
	}

	response, err := a.client.AnalyzeScan(ctx, req)
	if err != nil {
		return nil, err
	}

	if len(response.Findings) > 0 {
		return &response.Findings[0], nil
	}

	return nil, fmt.Errorf("no findings returned from AI analysis")
}

// GenerateExecutiveSummary creates a non-technical executive summary
func (a *Analyzer) GenerateExecutiveSummary(findings []AIFinding, target string, riskScore int) string {
	if len(findings) == 0 {
		return fmt.Sprintf("The security assessment of %s completed successfully with no vulnerabilities identified.", target)
	}

	// Count findings by severity
	severityCounts := make(map[string]int)
	for _, f := range findings {
		severityCounts[f.Severity]++
	}

	// Find top categories
	categoryCounts := make(map[string]int)
	for _, f := range findings {
		categoryCounts[f.ModuleSource]++
	}

	// Get top 3 categories
	type catCount struct {
		name  string
		count int
	}
	var categories []catCount
	for name, count := range categoryCounts {
		categories = append(categories, catCount{name, count})
	}
	sort.Slice(categories, func(i, j int) bool {
		return categories[i].count > categories[j].count
	})

	summary := fmt.Sprintf(
		"A comprehensive security assessment of %s was conducted, identifying %d security findings. ",
		target, len(findings),
	)

	// Add severity breakdown
	if severityCounts["Critical"] > 0 {
		summary += fmt.Sprintf("Critical vulnerabilities were discovered (%d) that require immediate remediation. ", severityCounts["Critical"])
	}
	if severityCounts["High"] > 0 {
		summary += fmt.Sprintf("High severity issues (%d) were found that pose significant security risks. ", severityCounts["High"])
	}
	if severityCounts["Medium"] > 0 {
		summary += fmt.Sprintf("Medium severity findings (%d) were identified that should be addressed in the near term. ", severityCounts["Medium"])
	}

	summary += fmt.Sprintf("The overall risk score is %d out of 100, indicating a %s risk level. ",
		riskScore, calculateRiskLevel(riskScore))

	// Add category information
	if len(categories) > 0 {
		summary += "The primary areas of concern include: "
		for i, cat := range categories {
			if i >= 3 {
				break
			}
			if i > 0 {
				summary += ", "
			}
			summary += fmt.Sprintf("%s (%d findings)", cat.name, cat.count)
		}
		summary += ". "
	}

	summary += "Immediate action is recommended to address critical and high severity findings, followed by a systematic approach to resolve remaining issues based on the provided remediation roadmap."

	return summary
}

// GenerateRemediationRoadmap creates a prioritized remediation plan
func (a *Analyzer) GenerateRemediationRoadmap(findings []AIFinding) []RemediationStep {
	if len(findings) == 0 {
		return []RemediationStep{}
	}

	steps := []RemediationStep{}

	// Group findings by severity and effort
	criticalHighFindings := []string{}
	mediumFindings := []string{}
	lowInfoFindings := []string{}

	quickWins := []string{} // Low effort fixes

	for _, f := range findings {
		switch f.Severity {
		case "Critical", "High":
			criticalHighFindings = append(criticalHighFindings, f.ID)
		case "Medium":
			mediumFindings = append(mediumFindings, f.ID)
		default:
			lowInfoFindings = append(lowInfoFindings, f.ID)
		}

		if f.RemediationEffort == "Low" {
			quickWins = append(quickWins, f.ID)
		}
	}

	priority := 1

	// Step 1: Immediate critical/high fixes
	if len(criticalHighFindings) > 0 {
		steps = append(steps, RemediationStep{
			Priority:   priority,
			FindingIDs: criticalHighFindings,
			Action:     "Address all Critical and High severity vulnerabilities immediately",
			Effort:     "High",
			Impact:     "Eliminates the most severe security risks and prevents potential exploitation",
			Category:   "Critical",
		})
		priority++
	}

	// Step 2: Quick wins (low effort fixes)
	if len(quickWins) > 0 {
		steps = append(steps, RemediationStep{
			Priority:   priority,
			FindingIDs: quickWins,
			Action:     "Implement quick-win fixes - low effort security improvements",
			Effort:     "Low",
			Impact:     "Rapidly improves security posture with minimal resource investment",
			Category:   "Quick Wins",
		})
		priority++
	}

	// Step 3: Medium priority
	if len(mediumFindings) > 0 {
		steps = append(steps, RemediationStep{
			Priority:   priority,
			FindingIDs: mediumFindings,
			Action:     "Address Medium severity findings according to scheduled maintenance windows",
			Effort:     "Medium",
			Impact:     "Reduces overall attack surface and addresses moderate security concerns",
			Category:   "Medium",
		})
		priority++
	}

	// Step 4: Low/Informational
	if len(lowInfoFindings) > 0 {
		steps = append(steps, RemediationStep{
			Priority:   priority,
			FindingIDs: lowInfoFindings,
			Action:     "Review and address Low priority and Informational findings",
			Effort:     "Low",
			Impact:     "Improves security hygiene and addresses minor concerns",
			Category:   "Low",
		})
	}

	return steps
}

// CalculateRiskScore calculates the overall risk score from findings
func (a *Analyzer) CalculateRiskScore(findings []AIFinding) int {
	if len(findings) == 0 {
		return 0
	}

	critical, high, medium, low := 0, 0, 0, 0

	for _, f := range findings {
		switch f.Severity {
		case "Critical":
			critical++
		case "High":
			high++
		case "Medium":
			medium++
		case "Low":
			low++
		}
	}

	return CalculateRiskScore(critical, high, medium, low)
}

// CalculateCVSS calculates CVSS v3.1 score from a finding
func (a *Analyzer) CalculateCVSS(finding AIFinding) CVSSMetrics {
	vector := ParseCVSSVector(finding.CVSSVector)
	return CalculateCVSS(vector)
}

// BatchAnalyze performs analysis on batches of findings
func (a *Analyzer) BatchAnalyze(ctx context.Context, findings []RawFinding, batchSize int) ([]AIFinding, error) {
	if batchSize <= 0 {
		batchSize = 10
	}

	allFindings := []AIFinding{}

	for i := 0; i < len(findings); i += batchSize {
		end := i + batchSize
		if end > len(findings) {
			end = len(findings)
		}

		batch := findings[i:end]
		req := AIAnalysisRequest{
			Target:    "batch_analysis",
			Findings:  batch,
			Timestamp: time.Now(),
		}

		resp, err := a.client.AnalyzeScan(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("batch %d analysis failed: %w", i/batchSize, err)
		}

		allFindings = append(allFindings, resp.Findings...)
	}

	return allFindings, nil
}

// GetAnalysisStats returns statistics about the analysis
func (a *Analyzer) GetAnalysisStats() AnalysisStats {
	if a.client == nil {
		return AnalysisStats{}
	}

	usage := a.client.GetTokenUsage()
	return AnalysisStats{
		TotalTokensUsed: usage.TotalTokens,
		TotalCostUSD:    usage.CostUSD,
	}
}

// AnalysisStats contains analysis statistics
type AnalysisStats struct {
	TotalTokensUsed int
	TotalCostUSD    float64
}

// ============================================================================
// Helper Functions
// ============================================================================

func (a *Analyzer) enrichFindings(aiFindings []AIFinding, rawFindings []RawFinding) []AIFinding {
	// Create a map of raw findings by ID for quick lookup
	rawMap := make(map[string]RawFinding)
	for _, rf := range rawFindings {
		rawMap[rf.ID.String()] = rf
	}

	enriched := make([]AIFinding, len(aiFindings))
	for i, af := range aiFindings {
		if raw, found := rawMap[af.OriginalFindingID]; found {
			// Preserve module source
			if af.ModuleSource == "" {
				af.ModuleSource = raw.Module
			}
			// Ensure CVSS is calculated if not provided
			if af.CVSSScore == 0 {
				af.CVSSScore = severityToCVSS(raw.Severity)
			}
			// Ensure CVSS vector is present
			if af.CVSSVector == "" {
				af.CVSSVector = SeverityToCVSSVector(raw.Severity)
			}
		}
		enriched[i] = af
	}

	return enriched
}

func (a *Analyzer) prioritizeRemediation(steps []RemediationStep) []RemediationStep {
	// Sort by priority
	sort.Slice(steps, func(i, j int) bool {
		return steps[i].Priority < steps[j].Priority
	})

	// Ensure priorities are sequential
	for i := range steps {
		steps[i].Priority = i + 1
	}

	return steps
}

func (a *Analyzer) generateEmptyAnalysis(req AIAnalysisRequest) *AIAnalysisResponse {
	return &AIAnalysisResponse{
		ExecutiveSummary: fmt.Sprintf(
			"Security assessment of %s completed successfully. No vulnerabilities were identified during the scan. "+
				"This indicates a strong security posture for the tested target.",
			req.Target,
		),
		RiskScore:          0,
		RiskLevel:          "Informational",
		Findings:           []AIFinding{},
		RemediationRoadmap: []RemediationStep{},
		AIProvider:         string(ProviderFallback),
		AnalysisDuration:   0,
		Cached:             false,
	}
}

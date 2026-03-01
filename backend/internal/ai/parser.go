package ai

import (
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
)

// ============================================================================
// Main Parsing Functions
// ============================================================================

// ParseAnalysisJSON parses the AI analysis JSON response
func ParseAnalysisJSON(content string) (*AIAnalysisResponse, error) {
	// Try to extract JSON from markdown code blocks if present
	jsonContent := extractJSONFromMarkdown(content)

	// First, try to parse directly as AIAnalysisResponse
	var response AIAnalysisResponse
	if err := json.Unmarshal([]byte(jsonContent), &response); err == nil {
		// Validate the response
		if err := validateAnalysisResponse(&response); err != nil {
			return nil, fmt.Errorf("validation failed: %w", err)
		}
		return &response, nil
	}

	// If direct parsing fails, try to parse and construct manually
	var rawData map[string]interface{}
	if err := json.Unmarshal([]byte(jsonContent), &rawData); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	return parseRawAnalysisData(rawData)
}

// ParseAnalysisResponse parses the AI response into AnalysisResult (legacy)
func ParseAnalysisResponse(response string) (*AnalysisResult, error) {
	// Try to extract JSON from the response
	jsonPattern := regexp.MustCompile(`(?s)\{.*\}`)
	match := jsonPattern.FindString(response)

	if match == "" {
		return nil, fmt.Errorf("no JSON found in response")
	}

	var result AnalysisResult
	if err := json.Unmarshal([]byte(match), &result); err != nil {
		// Try to parse non-JSON format
		return parseTextAnalysis(response), nil
	}

	return &result, nil
}

// ParseAttackVectors parses the AI response into attack vectors (legacy)
func ParseAttackVectors(response string) ([]AttackVector, error) {
	// Try to extract JSON array
	jsonPattern := regexp.MustCompile(`(?s)\[.*\]`)
	match := jsonPattern.FindString(response)

	if match != "" {
		var vectors []AttackVector
		if err := json.Unmarshal([]byte(match), &vectors); err == nil {
			return vectors, nil
		}
	}

	// Fallback to text parsing
	return parseTextAttackVectors(response), nil
}

// ============================================================================
// JSON Extraction Helpers
// ============================================================================

func extractJSONFromMarkdown(content string) string {
	// Try to extract JSON from markdown code blocks
	codeBlockPattern := regexp.MustCompile("```(?:json)?\\s*\\n?([\\s\\S]*?)```")
	matches := codeBlockPattern.FindStringSubmatch(content)
	if len(matches) > 1 {
		return strings.TrimSpace(matches[1])
	}

	// Try to find JSON between braces
	jsonPattern := regexp.MustCompile(`(?s)\{.*\}`)
	match := jsonPattern.FindString(content)
	if match != "" {
		return match
	}

	return content
}

// ============================================================================
// Validation Functions
// ============================================================================

func validateAnalysisResponse(response *AIAnalysisResponse) error {
	// Validate risk score
	if response.RiskScore < 0 || response.RiskScore > 100 {
		return fmt.Errorf("invalid risk score: %d", response.RiskScore)
	}

	// Validate findings
	for i, finding := range response.Findings {
		if finding.ID == "" {
			return fmt.Errorf("finding %d: missing ID", i)
		}
		if finding.Title == "" {
			return fmt.Errorf("finding %d: missing title", i)
		}
		if !isValidSeverity(finding.Severity) {
			return fmt.Errorf("finding %d: invalid severity: %s", i, finding.Severity)
		}
		if finding.CVSSScore < 0 || finding.CVSSScore > 10 {
			return fmt.Errorf("finding %d: invalid CVSS score: %.2f", i, finding.CVSSScore)
		}
	}

	return nil
}

func isValidSeverity(severity string) bool {
	validSeverities := []string{"Critical", "High", "Medium", "Low", "Informational"}
	for _, s := range validSeverities {
		if severity == s {
			return true
		}
	}
	return false
}

// ============================================================================
// Raw Data Parsing
// ============================================================================

func parseRawAnalysisData(data map[string]interface{}) (*AIAnalysisResponse, error) {
	response := &AIAnalysisResponse{
		Findings:           []AIFinding{},
		RemediationRoadmap: []RemediationStep{},
	}

	// Parse executive summary
	if summary, ok := data["executive_summary"].(string); ok {
		response.ExecutiveSummary = summary
	}

	// Parse risk score
	if score, ok := data["risk_score"].(float64); ok {
		response.RiskScore = int(score)
	}

	// Parse findings
	if findings, ok := data["findings"].([]interface{}); ok {
		for _, f := range findings {
			if findingMap, ok := f.(map[string]interface{}); ok {
				finding := parseAIFinding(findingMap)
				response.Findings = append(response.Findings, finding)
			}
		}
	}

	// Parse remediation roadmap
	if roadmap, ok := data["remediation_roadmap"].([]interface{}); ok {
		for _, r := range roadmap {
			if stepMap, ok := r.(map[string]interface{}); ok {
				step := parseRemediationStep(stepMap)
				response.RemediationRoadmap = append(response.RemediationRoadmap, step)
			}
		}
	}

	return response, nil
}

func parseAIFinding(data map[string]interface{}) AIFinding {
	finding := AIFinding{
		References: []string{},
	}

	if id, ok := data["id"].(string); ok {
		finding.ID = id
	}
	if title, ok := data["title"].(string); ok {
		finding.Title = title
	}
	if severity, ok := data["severity"].(string); ok {
		finding.Severity = severity
	}
	if cvss, ok := data["cvss_score"].(float64); ok {
		finding.CVSSScore = cvss
	}
	if vector, ok := data["cvss_vector"].(string); ok {
		finding.CVSSVector = vector
	}
	if owasp, ok := data["owasp_standard"].(string); ok {
		finding.OWASPStandard = &owasp
	}
	if owaspAgentic, ok := data["owasp_agentic"].(string); ok {
		finding.OWASPAgentic = &owaspAgentic
	}
	if desc, ok := data["description"].(string); ok {
		finding.Description = desc
	}
	if evidence, ok := data["raw_evidence"].(string); ok {
		finding.RawEvidence = evidence
	}
	if impact, ok := data["business_impact"].(string); ok {
		finding.BusinessImpact = impact
	}
	if remediation, ok := data["remediation"].(string); ok {
		finding.Remediation = remediation
	}
	if effort, ok := data["remediation_effort"].(string); ok {
		finding.RemediationEffort = effort
	}
	if refs, ok := data["references"].([]interface{}); ok {
		for _, r := range refs {
			if ref, ok := r.(string); ok {
				finding.References = append(finding.References, ref)
			}
		}
	}
	if confidence, ok := data["confidence"].(float64); ok {
		finding.Confidence = confidence
	}

	return finding
}

func parseRemediationStep(data map[string]interface{}) RemediationStep {
	step := RemediationStep{
		FindingIDs: []string{},
	}

	if priority, ok := data["priority"].(float64); ok {
		step.Priority = int(priority)
	}
	if ids, ok := data["finding_ids"].([]interface{}); ok {
		for _, id := range ids {
			if idStr, ok := id.(string); ok {
				step.FindingIDs = append(step.FindingIDs, idStr)
			}
		}
	}
	if action, ok := data["action"].(string); ok {
		step.Action = action
	}
	if effort, ok := data["effort"].(string); ok {
		step.Effort = effort
	}
	if impact, ok := data["impact"].(string); ok {
		step.Impact = impact
	}

	return step
}

// ============================================================================
// Legacy Parsing Functions
// ============================================================================

func parseTextAnalysis(response string) *AnalysisResult {
	result := &AnalysisResult{
		IsVulnerable: false,
		VulnType:     "unknown",
		Severity:     "info",
		Confidence:   0.0,
	}

	lower := strings.ToLower(response)

	// Check for vulnerability indicators
	if strings.Contains(lower, "vulnerable") || strings.Contains(lower, "vulnerability found") {
		result.IsVulnerable = true
	}

	// Extract severity
	if strings.Contains(lower, "critical") {
		result.Severity = "critical"
		result.Confidence = 0.9
	} else if strings.Contains(lower, "high") {
		result.Severity = "high"
		result.Confidence = 0.8
	} else if strings.Contains(lower, "medium") {
		result.Severity = "medium"
		result.Confidence = 0.7
	} else if strings.Contains(lower, "low") {
		result.Severity = "low"
		result.Confidence = 0.6
	}

	result.Details = response
	return result
}

func parseTextAttackVectors(response string) []AttackVector {
	var vectors []AttackVector
	lines := strings.Split(response, "\n")

	var currentVector *AttackVector

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Check for vector name (numbered or bulleted)
		if matched, _ := regexp.MatchString(`^(\d+\.|-|\*)\s+`, line); matched {
			if currentVector != nil {
				vectors = append(vectors, *currentVector)
			}
			currentVector = &AttackVector{
				Name: strings.TrimPrefix(line, regexp.MustCompile(`^(\d+\.|-|\*)\s+`).FindString(line)),
			}
		} else if currentVector != nil {
			// Add to description
			currentVector.Description += line + " "
		}
	}

	if currentVector != nil {
		vectors = append(vectors, *currentVector)
	}

	return vectors
}

// ExtractCodeBlocks extracts code blocks from markdown response
func ExtractCodeBlocks(response string) []string {
	pattern := regexp.MustCompile("```(?:\\w+)?\\n?([\\s\\S]*?)```")
	matches := pattern.FindAllStringSubmatch(response, -1)

	var blocks []string
	for _, match := range matches {
		if len(match) > 1 {
			blocks = append(blocks, strings.TrimSpace(match[1]))
		}
	}

	return blocks
}

// ============================================================================
// CVSS v3.1 Calculator
// ============================================================================

// CalculateCVSS calculates the CVSS v3.1 base score from vector components
func CalculateCVSS(vector CVSSVector) CVSSMetrics {
	// Metric values to scores mapping
	avScores := map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
	acScores := map[string]float64{"L": 0.77, "H": 0.44}
	prScores := map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	prScoresChanged := map[string]float64{"N": 0.85, "L": 0.68, "H": 0.5}
	uiScores := map[string]float64{"N": 0.85, "R": 0.62}
	ciaScores := map[string]float64{"N": 0.0, "L": 0.22, "H": 0.56}

	// Get scores
	avScore := avScores[vector.AttackVector]
	acScore := acScores[vector.AttackComplexity]
	uiScore := uiScores[vector.UserInteraction]
	cScore := ciaScores[vector.Confidentiality]
	iScore := ciaScores[vector.Integrity]
	aScore := ciaScores[vector.Availability]

	// Privileges Required depends on Scope
	var prScore float64
	if vector.Scope == "C" {
		prScore = prScoresChanged[vector.PrivilegesRequired]
	} else {
		prScore = prScores[vector.PrivilegesRequired]
	}

	// Calculate ISS (Impact Sub-Score)
	iss := 1 - ((1 - cScore) * (1 - iScore) * (1 - aScore))

	// Calculate Impact
	var impact float64
	if vector.Scope == "C" {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	} else {
		impact = 6.42 * iss
	}

	// Calculate Exploitability
	exploitability := 8.22 * avScore * acScore * prScore * uiScore

	// Calculate Base Score
	var baseScore float64
	if impact <= 0 {
		baseScore = 0.0
	} else {
		if vector.Scope == "C" {
			baseScore = math.Min(1.08*(impact+exploitability), 10)
		} else {
			baseScore = math.Min(impact+exploitability, 10)
		}
	}

	// Round to one decimal place
	baseScore = math.Ceil(baseScore*10) / 10

	// Determine severity
	severity := cvssToSeverity(baseScore)

	// Build vector string
	vectorString := fmt.Sprintf("CVSS:3.1/AV:%s/AC:%s/PR:%s/UI:%s/S:%s/C:%s/I:%s/A:%s",
		vector.AttackVector, vector.AttackComplexity, vector.PrivilegesRequired,
		vector.UserInteraction, vector.Scope, vector.Confidentiality,
		vector.Integrity, vector.Availability)

	return CVSSMetrics{
		BaseScore:    baseScore,
		BaseSeverity: severity,
		VectorString: vectorString,
	}
}

// ParseCVSSVector parses a CVSS v3.1 vector string
func ParseCVSSVector(vector string) CVSSVector {
	v := CVSSVector{}

	// Default values
	v.AttackVector = "N"
	v.AttackComplexity = "L"
	v.PrivilegesRequired = "N"
	v.UserInteraction = "N"
	v.Scope = "U"
	v.Confidentiality = "N"
	v.Integrity = "N"
	v.Availability = "N"

	// Parse vector string
	parts := strings.Split(vector, "/")
	for _, part := range parts {
		kv := strings.SplitN(part, ":", 2)
		if len(kv) != 2 {
			continue
		}

		switch kv[0] {
		case "AV":
			v.AttackVector = kv[1]
		case "AC":
			v.AttackComplexity = kv[1]
		case "PR":
			v.PrivilegesRequired = kv[1]
		case "UI":
			v.UserInteraction = kv[1]
		case "S":
			v.Scope = kv[1]
		case "C":
			v.Confidentiality = kv[1]
		case "I":
			v.Integrity = kv[1]
		case "A":
			v.Availability = kv[1]
		}
	}

	return v
}

func cvssToSeverity(score float64) string {
	switch {
	case score >= 9.0:
		return "Critical"
	case score >= 7.0:
		return "High"
	case score >= 4.0:
		return "Medium"
	case score >= 0.1:
		return "Low"
	default:
		return "None"
	}
}

// ============================================================================
// Severity to CVSS Mapping
// ============================================================================

// SeverityToCVSSVector converts severity to a default CVSS vector
func SeverityToCVSSVector(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" // ~9.8
	case "high":
		return "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" // ~8.8
	case "medium":
		return "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:L" // ~6.3
	case "low":
		return "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N" // ~3.3
	default:
		return "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N" // ~0.0
	}
}

// CVSSToSeverity converts a CVSS score to severity string
func CVSSToSeverity(score float64) string {
	score = math.Round(score*10) / 10
	switch {
	case score >= 9.0:
		return "Critical"
	case score >= 7.0:
		return "High"
	case score >= 4.0:
		return "Medium"
	case score >= 0.1:
		return "Low"
	default:
		return "Informational"
	}
}

// ExtractCVSSFromVector extracts the base score from a CVSS vector string
func ExtractCVSSFromVector(vector string) float64 {
	// Parse the vector and calculate the score
	v := ParseCVSSVector(vector)
	metrics := CalculateCVSS(v)
	return metrics.BaseScore
}

// ValidateCVSSVector validates a CVSS v3.1 vector string
func ValidateCVSSVector(vector string) error {
	if !strings.HasPrefix(vector, "CVSS:3.1/") && !strings.HasPrefix(vector, "CVSS:3.0/") {
		return fmt.Errorf("invalid CVSS version prefix")
	}

	// Check for required metrics
	required := []string{"AV:", "AC:", "PR:", "UI:", "S:", "C:", "I:", "A:"}
	for _, metric := range required {
		if !strings.Contains(vector, metric) {
			return fmt.Errorf("missing required metric: %s", metric)
		}
	}

	// Validate metric values
	validValues := map[string][]string{
		"AV": {"N", "A", "L", "P"},
		"AC": {"L", "H"},
		"PR": {"N", "L", "H"},
		"UI": {"N", "R"},
		"S":  {"U", "C"},
		"C":  {"N", "L", "H"},
		"I":  {"N", "L", "H"},
		"A":  {"N", "L", "H"},
	}

	for metric, valid := range validValues {
		pattern := regexp.MustCompile(metric + `:(\w)`)
		matches := pattern.FindStringSubmatch(vector)
		if len(matches) > 1 {
			value := matches[1]
			found := false
			for _, v := range valid {
				if value == v {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("invalid value for %s: %s", metric, value)
			}
		}
	}

	return nil
}

// CalculateRiskScoreFromFindings calculates an overall risk score from findings
func CalculateRiskScoreFromFindings(findings []AIFinding) int {
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

	// Formula: (Critical × 25 + High × 10 + Medium × 4 + Low × 1) / max_possible × 100
	score := critical*25 + high*10 + medium*4 + low*1

	// Normalize based on reasonable maximum
	maxPossible := 100
	normalizedScore := (score * 100) / maxPossible

	if normalizedScore > 100 {
		normalizedScore = 100
	}

	return normalizedScore
}

// ParseNumericScore parses a numeric score from various formats
func ParseNumericScore(value interface{}) (float64, error) {
	switch v := value.(type) {
	case float64:
		return v, nil
	case float32:
		return float64(v), nil
	case int:
		return float64(v), nil
	case int64:
		return float64(v), nil
	case string:
		return strconv.ParseFloat(v, 64)
	default:
		return 0, fmt.Errorf("cannot parse %T as numeric", value)
	}
}

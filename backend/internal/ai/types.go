package ai

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/google/uuid"
)

// ============================================================================
// AI Analysis Request/Response Types
// ============================================================================

// AIAnalysisRequest contains all data needed for AI analysis
type AIAnalysisRequest struct {
	Target       string            `json:"target"`
	TargetType   string            `json:"target_type"`
	ScanScope    string            `json:"scan_scope"`
	Findings     []RawFinding      `json:"findings"`
	Technologies []string          `json:"technologies"`
	ScanID       uuid.UUID         `json:"scan_id"`
	ScanDuration int               `json:"scan_duration_seconds"`
	ModulesRun   []string          `json:"modules_run"`
	Timestamp    time.Time         `json:"timestamp"`
	Metadata     map[string]string `json:"metadata,omitempty"`
}

// AIAnalysisResponse is the structured output from AI analysis
type AIAnalysisResponse struct {
	ExecutiveSummary   string            `json:"executive_summary"`
	RiskScore          int               `json:"risk_score"`
	RiskLevel          string            `json:"risk_level"`
	Findings           []AIFinding       `json:"findings"`
	RemediationRoadmap []RemediationStep `json:"remediation_roadmap"`
	AIProvider         string            `json:"ai_provider"`
	TokenUsage         TokenUsage        `json:"token_usage"`
	AnalysisDuration   int               `json:"analysis_duration_seconds"`
	Cached             bool              `json:"cached"`
}

// RawFinding represents a finding from a scanning module before AI analysis
type RawFinding struct {
	ID          uuid.UUID       `json:"id"`
	Module      string          `json:"module"`
	Title       string          `json:"title"`
	Description string          `json:"description"`
	Severity    string          `json:"severity"`
	Category    string          `json:"category"`
	Evidence    FindingEvidence `json:"evidence"`
	CVSS        float64         `json:"cvss,omitempty"`
	CVEs        []string        `json:"cves,omitempty"`
	References  []string        `json:"references"`
	Remediation string          `json:"remediation,omitempty"`
	Target      string          `json:"target,omitempty"`
	Port        int             `json:"port,omitempty"`
	Timestamp   time.Time       `json:"timestamp"`
}

// FindingEvidence contains evidence for a finding (local copy to avoid import cycles)
type FindingEvidence struct {
	Request    string                 `json:"request,omitempty"`
	Response   string                 `json:"response,omitempty"`
	Headers    map[string]string      `json:"headers,omitempty"`
	Payload    string                 `json:"payload,omitempty"`
	Snippet    string                 `json:"snippet,omitempty"`
	URL        string                 `json:"url,omitempty"`
	Screenshot string                 `json:"screenshot,omitempty"`
	Details    map[string]interface{} `json:"details,omitempty"`
}

// Client is an alias for AIClient for backward compatibility
type Client = AIClient

// Legacy types for backward compatibility
type AnalysisResult struct {
	IsVulnerable bool     `json:"is_vulnerable"`
	VulnType     string   `json:"vulnerability_type"`
	Severity     string   `json:"severity"`
	Confidence   float64  `json:"confidence"`
	Details      string   `json:"details"`
	Evidence     []string `json:"evidence"`
}

type AttackVector struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Severity    string   `json:"severity"`
	Techniques  []string `json:"techniques"`
	Payloads    []string `json:"payloads"`
}

// AIFinding represents a fully analyzed security finding with AI enrichment
type AIFinding struct {
	ID                string   `json:"id"`
	Title             string   `json:"title"`
	Severity          string   `json:"severity"`
	CVSSScore         float64  `json:"cvss_score"`
	CVSSVector        string   `json:"cvss_vector"`
	OWASPStandard     *string  `json:"owasp_standard,omitempty"`
	OWASPAgentic      *string  `json:"owasp_agentic,omitempty"`
	Description       string   `json:"description"`
	RawEvidence       string   `json:"raw_evidence"`
	BusinessImpact    string   `json:"business_impact"`
	Remediation       string   `json:"remediation"`
	RemediationEffort string   `json:"remediation_effort"`
	References        []string `json:"references"`
	ModuleSource      string   `json:"module_source"`
	OriginalFindingID string   `json:"original_finding_id"`
	Confidence        float64  `json:"confidence"`
}

// RemediationStep represents a single step in the remediation roadmap
type RemediationStep struct {
	Priority   int      `json:"priority"`
	FindingIDs []string `json:"finding_ids"`
	Action     string   `json:"action"`
	Effort     string   `json:"effort"`
	Impact     string   `json:"impact"`
	Category   string   `json:"category"`
}

// ============================================================================
// CVSS v3.1 Types
// ============================================================================

// CVSSVector represents the CVSS v3.1 vector components
type CVSSVector struct {
	AttackVector       string `json:"attack_vector"`       // N/A/L/P
	AttackComplexity   string `json:"attack_complexity"`   // L/H
	PrivilegesRequired string `json:"privileges_required"` // N/L/H
	UserInteraction    string `json:"user_interaction"`    // N/R
	Scope              string `json:"scope"`               // U/C
	Confidentiality    string `json:"confidentiality"`     // N/L/H
	Integrity          string `json:"integrity"`           // N/L/H
	Availability       string `json:"availability"`        // N/L/H
}

// CVSSMetrics contains the calculated CVSS scores
type CVSSMetrics struct {
	BaseScore    float64 `json:"base_score"`
	BaseSeverity string  `json:"base_severity"`
	VectorString string  `json:"vector_string"`
}

// ============================================================================
// Cache Types
// ============================================================================

// CacheEntry represents a cached AI response
type CacheEntry struct {
	Key        string             `json:"key"`
	Response   AIAnalysisResponse `json:"response"`
	CreatedAt  time.Time          `json:"created_at"`
	ExpiresAt  time.Time          `json:"expires_at"`
	TokenUsage TokenUsage         `json:"token_usage"`
}

// TokenUsage tracks AI API token consumption
type TokenUsage struct {
	PromptTokens     int     `json:"prompt_tokens"`
	CompletionTokens int     `json:"completion_tokens"`
	TotalTokens      int     `json:"total_tokens"`
	CostUSD          float64 `json:"cost_usd"`
}

// ============================================================================
// AI Provider Types
// ============================================================================

// AIProvider represents the AI provider being used
type AIProvider string

const (
	ProviderAnthropic AIProvider = "anthropic"
	ProviderOpenAI    AIProvider = "openai"
	ProviderFallback  AIProvider = "fallback"
)

// AIModel represents the AI model configuration
type AIModel struct {
	Name        string     `json:"name"`
	Provider    AIProvider `json:"provider"`
	MaxTokens   int        `json:"max_tokens"`
	Temperature float64    `json:"temperature"`
}

// Default models
var (
	ModelClaude35Sonnet = AIModel{
		Name:        "claude-3-5-sonnet-20241022",
		Provider:    ProviderAnthropic,
		MaxTokens:   4096,
		Temperature: 0.1,
	}
	ModelGPT4o = AIModel{
		Name:        "gpt-4o",
		Provider:    ProviderOpenAI,
		MaxTokens:   4096,
		Temperature: 0.1,
	}
)

// ============================================================================
// Circuit Breaker Types
// ============================================================================

// CircuitState represents the state of the circuit breaker
type CircuitState string

const (
	CircuitClosed   CircuitState = "closed"
	CircuitOpen     CircuitState = "open"
	CircuitHalfOpen CircuitState = "half-open"
)

// CircuitBreakerConfig contains circuit breaker settings
type CircuitBreakerConfig struct {
	MaxFailures      int           `json:"max_failures"`
	ResetTimeout     time.Duration `json:"reset_timeout"`
	SuccessThreshold int           `json:"success_threshold"`
}

// DefaultCircuitBreakerConfig returns default circuit breaker settings
func DefaultCircuitBreakerConfig() CircuitBreakerConfig {
	return CircuitBreakerConfig{
		MaxFailures:      5,
		ResetTimeout:     60 * time.Second,
		SuccessThreshold: 3,
	}
}

// ============================================================================
// Report Types
// ============================================================================

// AIReport represents a complete AI-generated security report
type AIReport struct {
	ReportID       uuid.UUID          `json:"report_id"`
	ScanID         uuid.UUID          `json:"scan_id"`
	Target         string             `json:"target"`
	GeneratedAt    time.Time          `json:"generated_at"`
	ScannerVersion string             `json:"scanner_version"`
	Analysis       AIAnalysisResponse `json:"analysis"`
	RawFindings    []RawFinding       `json:"raw_findings"`
	ScanMetadata   ScanMetadata       `json:"scan_metadata"`
}

// ScanMetadata contains information about the scan
type ScanMetadata struct {
	StartTime    time.Time `json:"start_time"`
	EndTime      time.Time `json:"end_time"`
	Duration     int       `json:"duration_seconds"`
	ModulesRun   []string  `json:"modules_run"`
	Technologies []string  `json:"technologies"`
	ScanScope    string    `json:"scan_scope"`
}

// ============================================================================
// Conversion Helpers
// ============================================================================

// ToRawFindingFromScanner converts a scanner.Finding (via JSON) to RawFinding
func ToRawFindingFromJSON(data []byte) (RawFinding, error) {
	var rf RawFinding
	err := json.Unmarshal(data, &rf)
	return rf, err
}

// RawFindingSliceFromScannerFindings converts scanner findings to raw findings using JSON marshaling
func RawFindingSliceFromScannerFindings(findings []interface{}) ([]RawFinding, error) {
	raw := make([]RawFinding, 0, len(findings))
	for _, f := range findings {
		data, err := json.Marshal(f)
		if err != nil {
			continue
		}
		rf, err := ToRawFindingFromJSON(data)
		if err != nil {
			continue
		}
		raw = append(raw, rf)
	}
	return raw, nil
}

// ============================================================================
// JSON Schema Types
// ============================================================================

// JSONSchema represents a JSON schema for structured output
type JSONSchema struct {
	Type       string                 `json:"type"`
	Properties map[string]interface{} `json:"properties"`
	Required   []string               `json:"required"`
}

// GetAnalysisResponseSchema returns the JSON schema for AI analysis response
func GetAnalysisResponseSchema() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"executive_summary": map[string]interface{}{
				"type":        "string",
				"description": "2-3 paragraph non-technical summary of findings",
			},
			"risk_score": map[string]interface{}{
				"type":        "integer",
				"minimum":     0,
				"maximum":     100,
				"description": "Overall risk score (0-100)",
			},
			"findings": map[string]interface{}{
				"type": "array",
				"items": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"id": map[string]interface{}{
							"type": "string",
						},
						"title": map[string]interface{}{
							"type": "string",
						},
						"severity": map[string]interface{}{
							"type": "string",
							"enum": []string{"Critical", "High", "Medium", "Low", "Informational"},
						},
						"cvss_score": map[string]interface{}{
							"type":    "number",
							"minimum": 0.0,
							"maximum": 10.0,
						},
						"cvss_vector": map[string]interface{}{
							"type":    "string",
							"pattern": "^CVSS:3\\.1/.*$",
						},
						"owasp_standard": map[string]interface{}{
							"type": []string{"string", "null"},
						},
						"owasp_agentic": map[string]interface{}{
							"type": []string{"string", "null"},
						},
						"description": map[string]interface{}{
							"type": "string",
						},
						"raw_evidence": map[string]interface{}{
							"type": "string",
						},
						"business_impact": map[string]interface{}{
							"type": "string",
						},
						"remediation": map[string]interface{}{
							"type": "string",
						},
						"remediation_effort": map[string]interface{}{
							"type": "string",
							"enum": []string{"Low", "Medium", "High"},
						},
						"references": map[string]interface{}{
							"type":  "array",
							"items": map[string]interface{}{"type": "string"},
						},
					},
					"required": []string{
						"id", "title", "severity", "cvss_score", "cvss_vector",
						"description", "raw_evidence", "business_impact",
						"remediation", "remediation_effort", "references",
					},
				},
			},
			"remediation_roadmap": map[string]interface{}{
				"type": "array",
				"items": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"priority": map[string]interface{}{
							"type":    "integer",
							"minimum": 1,
						},
						"finding_ids": map[string]interface{}{
							"type":  "array",
							"items": map[string]interface{}{"type": "string"},
						},
						"action": map[string]interface{}{
							"type": "string",
						},
						"effort": map[string]interface{}{
							"type": "string",
						},
						"impact": map[string]interface{}{
							"type": "string",
						},
					},
					"required": []string{"priority", "finding_ids", "action", "effort", "impact"},
				},
			},
		},
		"required": []string{"executive_summary", "risk_score", "findings", "remediation_roadmap"},
	}
}

// GetOpenAIJSONSchema returns the schema formatted for OpenAI structured output
func GetOpenAIJSONSchema() map[string]interface{} {
	schema := GetAnalysisResponseSchema()
	return map[string]interface{}{
		"type": "json_schema",
		"json_schema": map[string]interface{}{
			"name":   "security_analysis",
			"strict": true,
			"schema": schema,
		},
	}
}

// SerializeForPrompt serializes data for use in AI prompts with sanitization
func SerializeForPrompt(v interface{}) (string, error) {
	bytes, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return "", err
	}
	return sanitizePromptInput(string(bytes)), nil
}

// sanitizePromptInput sanitizes user input to prevent prompt injection
func sanitizePromptInput(input string) string {
	// Remove potential prompt injection markers
	replacements := []struct {
		old string
		new string
	}{
		{"<|im_start|>", ""},
		{"<|im_end|>", ""},
		{"<|endoftext|>", ""},
		{"[SYSTEM]", ""},
		{"[INST]", ""},
		{"[/INST]", ""},
		{"<<SYS>>", ""},
		{"<</SYS>>", ""},
		{"system:", ""},
		{"user:", ""},
		{"assistant:", ""},
	}

	for _, r := range replacements {
		input = strings.ReplaceAll(input, r.old, r.new)
	}

	// Limit length to prevent token abuse
	maxLen := 100000
	if len(input) > maxLen {
		input = input[:maxLen] + "\n... [truncated]"
	}

	return input
}

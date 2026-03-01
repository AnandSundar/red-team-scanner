package ai

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ============================================================================
// System Prompt
// ============================================================================

// SystemPrompt is the system prompt for the AI security analyzer
const SystemPrompt = `You are a senior penetration tester and security researcher with 15 years of experience.
You are analyzing raw findings from an automated security scan.
Your job is to produce accurate, professional, actionable security findings.
Do not hallucinate vulnerabilities. If evidence is ambiguous, classify as
Informational and explain what would confirm the finding. Always cite the
raw evidence that supports each finding.

CRITICAL RULES:
1. Only report vulnerabilities that are supported by evidence
2. Be precise and technical in your descriptions
3. Calculate CVSS scores accurately using CVSS v3.1 methodology
4. Map findings to appropriate OWASP categories when applicable
5. Provide clear, actionable remediation steps
6. Estimate remediation effort realistically
7. Include authoritative references (CVE, CWE, OWASP)

You must respond with valid JSON matching the provided schema exactly.`

// ============================================================================
// Prompt Building Functions
// ============================================================================

// BuildAnalysisPrompt builds the complete analysis prompt for the AI
func BuildAnalysisPrompt(req AIAnalysisRequest) (string, error) {
	var sb strings.Builder

	// Add target metadata
	sb.WriteString("# Security Scan Analysis Request\n\n")
	sb.WriteString("## Target Information\n")
	sb.WriteString(fmt.Sprintf("- Target: %s\n", req.Target))
	sb.WriteString(fmt.Sprintf("- Target Type: %s\n", req.TargetType))
	sb.WriteString(fmt.Sprintf("- Scan Scope: %s\n", req.ScanScope))
	sb.WriteString(fmt.Sprintf("- Scan ID: %s\n", req.ScanID.String()))
	sb.WriteString(fmt.Sprintf("- Scan Duration: %d seconds\n", req.ScanDuration))
	sb.WriteString(fmt.Sprintf("- Timestamp: %s\n", req.Timestamp.Format("2006-01-02 15:04:05")))

	// Add modules run
	sb.WriteString(fmt.Sprintf("- Modules Run: %s\n", strings.Join(req.ModulesRun, ", ")))

	// Add technologies
	if len(req.Technologies) > 0 {
		sb.WriteString(fmt.Sprintf("- Technologies Detected: %s\n", strings.Join(req.Technologies, ", ")))
	}

	sb.WriteString("\n")

	// Add findings summary
	sb.WriteString("## Raw Findings Summary\n")
	severityCounts := make(map[string]int)
	for _, f := range req.Findings {
		severityCounts[f.Severity]++
	}

	severities := []string{"critical", "high", "medium", "low", "info"}
	for _, sev := range severities {
		if count := severityCounts[sev]; count > 0 {
			sb.WriteString(fmt.Sprintf("- %s: %d\n", strings.ToUpper(sev), count))
		}
	}

	sb.WriteString(fmt.Sprintf("- Total Findings: %d\n\n", len(req.Findings)))

	// Add detailed findings
	sb.WriteString("## Detailed Findings\n\n")

	for i, finding := range req.Findings {
		sb.WriteString(fmt.Sprintf("### Finding %d: %s\n", i+1, finding.Title))
		sb.WriteString(fmt.Sprintf("- ID: %s\n", finding.ID.String()))
		sb.WriteString(fmt.Sprintf("- Module: %s\n", finding.Module))
		sb.WriteString(fmt.Sprintf("- Category: %s\n", finding.Category))
		sb.WriteString(fmt.Sprintf("- Original Severity: %s\n", finding.Severity))

		if finding.CVSS > 0 {
			sb.WriteString(fmt.Sprintf("- Original CVSS: %.1f\n", finding.CVSS))
		}

		if len(finding.CVEs) > 0 {
			sb.WriteString(fmt.Sprintf("- CVEs: %s\n", strings.Join(finding.CVEs, ", ")))
		}

		sb.WriteString(fmt.Sprintf("- Description: %s\n", finding.Description))

		// Add evidence
		sb.WriteString("- Evidence:\n")
		if finding.Evidence.URL != "" {
			sb.WriteString(fmt.Sprintf("  - URL: %s\n", finding.Evidence.URL))
		}
		if finding.Evidence.Request != "" {
			sb.WriteString(fmt.Sprintf("  - Request: %s\n", truncateString(finding.Evidence.Request, 500)))
		}
		if finding.Evidence.Response != "" {
			sb.WriteString(fmt.Sprintf("  - Response: %s\n", truncateString(finding.Evidence.Response, 500)))
		}
		if finding.Evidence.Payload != "" {
			sb.WriteString(fmt.Sprintf("  - Payload: %s\n", finding.Evidence.Payload))
		}
		if finding.Evidence.Snippet != "" {
			sb.WriteString(fmt.Sprintf("  - Code Snippet: %s\n", finding.Evidence.Snippet))
		}
		if len(finding.Evidence.Headers) > 0 {
			headers, _ := json.Marshal(finding.Evidence.Headers)
			sb.WriteString(fmt.Sprintf("  - Headers: %s\n", string(headers)))
		}

		sb.WriteString("\n")
	}

	// Add output requirements
	sb.WriteString("## Required Output\n\n")
	sb.WriteString("Please analyze the findings and provide:\n")
	sb.WriteString("1. An executive summary (2-3 paragraphs, non-technical)\n")
	sb.WriteString("2. Overall risk score (0-100)\n")
	sb.WriteString("3. Detailed analysis of each finding with:\n")
	sb.WriteString("   - Accurate severity classification\n")
	sb.WriteString("   - CVSS v3.1 score and vector\n")
	sb.WriteString("   - OWASP mapping (standard and agentic frameworks)\n")
	sb.WriteString("   - Business impact assessment\n")
	sb.WriteString("   - Detailed remediation guidance\n")
	sb.WriteString("   - Remediation effort estimate\n")
	sb.WriteString("   - Authoritative references\n")
	sb.WriteString("4. Prioritized remediation roadmap\n\n")

	// Add JSON schema reference
	sb.WriteString("## Output Format\n\n")
	sb.WriteString("Respond with valid JSON matching this structure:\n\n")

	schemaJSON, _ := json.MarshalIndent(GetAnalysisResponseSchema(), "", "  ")
	sb.WriteString("```json\n")
	sb.WriteString(string(schemaJSON))
	sb.WriteString("\n```\n")

	return sb.String(), nil
}

// ============================================================================
// Legacy Prompts (for backward compatibility)
// ============================================================================

// PayloadGenerationPrompt generates payloads for testing
const PayloadGenerationPrompt = `Generate a security testing payload for %s.

Target Context:
%s

Requirements:
- The payload should be designed for authorized security testing only
- Consider the specific technology stack and context
- Include variations for different security levels
- Provide clear explanations of what the payload tests

Response format:
1. Primary payload
2. Alternative variations
3. Explanation of the attack vector`

// ResponseAnalysisPrompt analyzes HTTP responses for vulnerabilities
const ResponseAnalysisPrompt = `Analyze the following HTTP request and response for security vulnerabilities.

Request:
%s

Response:
%s

Analyze for:
- Information disclosure
- Error messages revealing system details
- Missing security headers
- Potential injection points
- Authentication/authorization issues
- Business logic flaws

Respond in JSON format with the following structure:
{
  "is_vulnerable": boolean,
  "vulnerability_type": "type or 'none'",
  "severity": "critical|high|medium|low|info",
  "confidence": 0.0-1.0,
  "details": "explanation",
  "evidence": ["list of evidence strings"]
}`

// AttackVectorPrompt suggests attack vectors
const AttackVectorPrompt = `Based on the following target information, suggest relevant attack vectors for authorized security testing.

Target Information:
%s

Provide:
1. Most likely vulnerable areas
2. Recommended testing approaches
3. Specific techniques to try
4. Expected outcomes and how to verify

Format as structured JSON with attack vectors array.`

// SeverityClassificationPrompt classifies finding severity
const SeverityClassificationPrompt = `Classify the severity of the following security finding.

Finding Details:
%s

Context:
- Environment: %s
- Asset Criticality: %s
- Exposure: %s

Classify based on:
1. CVSS score estimation
2. Business impact
3. Exploitability
4. Data sensitivity

Respond with severity level and justification.`

// RemediationPrompt generates remediation advice
const RemediationPrompt = `Provide remediation advice for the following security finding.

Finding:
%s

Include:
1. Immediate mitigation steps
2. Long-term fix recommendations
3. Code examples if applicable
4. Verification steps
5. References to security standards`

// ============================================================================
// Helper Functions
// ============================================================================

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "... [truncated]"
}

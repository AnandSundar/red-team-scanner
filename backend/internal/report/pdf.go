package report

import (
	"bytes"
	"fmt"
	"html/template"
	"time"

	"github.com/redteam/agentic-scanner/internal/ai"
	"github.com/redteam/agentic-scanner/internal/scanner"
)

// PDFGenerator generates PDF reports
type PDFGenerator struct {
	template *template.Template
}

// NewPDFGenerator creates a new PDF report generator
func NewPDFGenerator() (*PDFGenerator, error) {
	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"formatDate": func(t time.Time) string {
			return t.Format("2006-01-02 15:04:05")
		},
		"severityColor": func(severity string) string {
			switch severity {
			case "Critical":
				return "#dc2626" // red-600
			case "High":
				return "#ea580c" // orange-600
			case "Medium":
				return "#ca8a04" // yellow-600
			case "Low":
				return "#16a34a" // green-600
			default:
				return "#6b7280" // gray-500
			}
		},
		"severityBgColor": func(severity string) string {
			switch severity {
			case "Critical":
				return "#fef2f2" // red-50
			case "High":
				return "#fff7ed" // orange-50
			case "Medium":
				return "#fefce8" // yellow-50
			case "Low":
				return "#f0fdf4" // green-50
			default:
				return "#f9fafb" // gray-50
			}
		},
		"riskColor": func(score int) string {
			switch {
			case score >= 80:
				return "#dc2626"
			case score >= 60:
				return "#ea580c"
			case score >= 40:
				return "#ca8a04"
			case score >= 20:
				return "#16a34a"
			default:
				return "#6b7280"
			}
		},
		"add": func(a, b int) int {
			return a + b
		},
		"sub": func(a, b int) int {
			return a - b
		},
	}).Parse(reportHTMLTemplate)

	if err != nil {
		return nil, fmt.Errorf("failed to parse template: %w", err)
	}

	return &PDFGenerator{
		template: tmpl,
	}, nil
}

// PDFReportData contains data for PDF generation
type PDFReportData struct {
	ReportID         string
	ScanID           string
	Target           string
	GeneratedAt      time.Time
	ScannerVersion   string
	ExecutiveSummary string
	RiskScore        int
	RiskLevel        string
	Findings         []ai.AIFinding
	RawFindings      []ai.RawFinding
	RemediationPlan  []ai.RemediationStep
	ModulesRun       []string
	ScanDuration     int
	Technologies     []string
	AIProvider       string
	Summary          struct {
		Critical int
		High     int
		Medium   int
		Low      int
		Info     int
		Total    int
	}
}

// Generate creates a PDF report from scan data
func (g *PDFGenerator) Generate(report *scanner.Report, analysis *ai.AIAnalysisResponse) ([]byte, error) {
	data := g.prepareData(report, analysis)
	return g.generateHTMLPDF(data)
}

// GenerateFromAIReport creates a PDF from an AI report
func (g *PDFGenerator) GenerateFromAIReport(report *ai.AIReport) ([]byte, error) {
	data := PDFReportData{
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

	// Count severities
	for _, f := range report.Analysis.Findings {
		switch f.Severity {
		case "Critical":
			data.Summary.Critical++
		case "High":
			data.Summary.High++
		case "Medium":
			data.Summary.Medium++
		case "Low":
			data.Summary.Low++
		default:
			data.Summary.Info++
		}
		data.Summary.Total++
	}

	return g.generateHTMLPDF(data)
}

// GenerateSimple creates a simple PDF report without AI analysis
func (g *PDFGenerator) GenerateSimple(report *scanner.Report) ([]byte, error) {
	data := g.prepareData(report, nil)
	return g.generateHTMLPDF(data)
}

func (g *PDFGenerator) prepareData(report *scanner.Report, analysis *ai.AIAnalysisResponse) PDFReportData {
	data := PDFReportData{
		ReportID:       report.ID.String(),
		ScanID:         report.ScanID.String(),
		Target:         report.Target,
		GeneratedAt:    time.Now(),
		ScannerVersion: "1.0.0",
		ModulesRun:     report.ModulesRun,
		ScanDuration:   report.Duration,
		RiskScore:      int(report.RiskScore),
		RiskLevel:      calculateRiskLevel(report.RiskScore),
	}

	data.Summary.Critical = report.FindingsSummary.Critical
	data.Summary.High = report.FindingsSummary.High
	data.Summary.Medium = report.FindingsSummary.Medium
	data.Summary.Low = report.FindingsSummary.Low
	data.Summary.Info = report.FindingsSummary.Info
	data.Summary.Total = report.FindingsSummary.Total

	// Convert scanner findings to raw findings
	data.RawFindings = make([]ai.RawFinding, len(report.Findings))
	for i, f := range report.Findings {
		data.RawFindings[i] = ai.RawFinding{
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
			CVSS:        f.CVSS,
			CVEs:        f.CVEs,
			References:  f.References,
			Remediation: f.Remediation,
			Timestamp:   f.CreatedAt,
		}
	}

	if analysis != nil {
		data.ExecutiveSummary = analysis.ExecutiveSummary
		data.RiskScore = analysis.RiskScore
		data.RiskLevel = analysis.RiskLevel
		data.Findings = analysis.Findings
		data.RemediationPlan = analysis.RemediationRoadmap
		data.AIProvider = analysis.AIProvider
	} else {
		data.ExecutiveSummary = g.generateExecutiveSummary(report)
		data.RemediationPlan = g.generateSimpleRemediationPlan(report)
	}

	return data
}

func (g *PDFGenerator) generateHTMLPDF(data PDFReportData) ([]byte, error) {
	var buf bytes.Buffer
	if err := g.template.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("failed to execute template: %w", err)
	}

	// For now, return HTML that can be converted to PDF by the frontend or a PDF service
	// In production, you'd use a library like unidoc, wkhtmltopdf, or puppeteer
	return buf.Bytes(), nil
}

func (g *PDFGenerator) generateExecutiveSummary(report *scanner.Report) string {
	return fmt.Sprintf(
		"A security assessment of %s was conducted, identifying %d findings. "+
			"The assessment includes %d critical, %d high, %d medium, and %d low severity issues. "+
			"Immediate action is recommended to address critical and high severity findings.",
		report.Target,
		report.FindingsSummary.Total,
		report.FindingsSummary.Critical,
		report.FindingsSummary.High,
		report.FindingsSummary.Medium,
		report.FindingsSummary.Low,
	)
}

func (g *PDFGenerator) generateSimpleRemediationPlan(report *scanner.Report) []ai.RemediationStep {
	steps := []ai.RemediationStep{}
	priority := 1

	if report.FindingsSummary.Critical > 0 {
		steps = append(steps, ai.RemediationStep{
			Priority: priority,
			Action:   fmt.Sprintf("Address %d critical vulnerabilities immediately", report.FindingsSummary.Critical),
			Effort:   "High",
			Impact:   "Eliminates critical security risks",
			Category: "Critical",
		})
		priority++
	}

	if report.FindingsSummary.High > 0 {
		steps = append(steps, ai.RemediationStep{
			Priority: priority,
			Action:   fmt.Sprintf("Address %d high severity vulnerabilities", report.FindingsSummary.High),
			Effort:   "Medium",
			Impact:   "Reduces attack surface significantly",
			Category: "High",
		})
		priority++
	}

	if report.FindingsSummary.Medium > 0 {
		steps = append(steps, ai.RemediationStep{
			Priority: priority,
			Action:   fmt.Sprintf("Schedule remediation for %d medium severity issues", report.FindingsSummary.Medium),
			Effort:   "Medium",
			Impact:   "Improves overall security posture",
			Category: "Medium",
		})
	}

	return steps
}

// HTML template for the PDF report
const reportHTMLTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Assessment Report - {{.Target}}</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            color: #1f2937;
            background: #fff;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 40px;
        }
        .header {
            text-align: center;
            padding: 40px 0;
            border-bottom: 4px solid #e5e7eb;
            margin-bottom: 40px;
        }
        .header h1 {
            font-size: 32px;
            color: #111827;
            margin-bottom: 10px;
        }
        .header .subtitle {
            font-size: 18px;
            color: #6b7280;
        }
        .meta-info {
            display: flex;
            justify-content: space-between;
            background: #f9fafb;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 40px;
        }
        .meta-item {
            text-align: center;
        }
        .meta-label {
            font-size: 12px;
            color: #6b7280;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 5px;
        }
        .meta-value {
            font-size: 16px;
            font-weight: 600;
            color: #111827;
        }
        .risk-score {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            width: 80px;
            height: 80px;
            border-radius: 50%;
            font-size: 24px;
            font-weight: bold;
            color: white;
        }
        .section {
            margin-bottom: 40px;
        }
        .section h2 {
            font-size: 24px;
            color: #111827;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #e5e7eb;
        }
        .executive-summary {
            background: #f9fafb;
            padding: 24px;
            border-radius: 8px;
            font-size: 16px;
            line-height: 1.8;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            gap: 16px;
            margin-bottom: 40px;
        }
        .stat-card {
            text-align: center;
            padding: 24px;
            border-radius: 8px;
            border: 1px solid #e5e7eb;
        }
        .stat-number {
            font-size: 36px;
            font-weight: bold;
            margin-bottom: 8px;
        }
        .stat-label {
            font-size: 14px;
            color: #6b7280;
            text-transform: uppercase;
        }
        .finding-card {
            border: 1px solid #e5e7eb;
            border-radius: 8px;
            margin-bottom: 20px;
            overflow: hidden;
        }
        .finding-header {
            padding: 16px 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .finding-title {
            font-size: 18px;
            font-weight: 600;
        }
        .finding-severity {
            padding: 4px 12px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
        }
        .finding-body {
            padding: 20px;
        }
        .finding-section {
            margin-bottom: 16px;
        }
        .finding-section h4 {
            font-size: 14px;
            color: #6b7280;
            text-transform: uppercase;
            margin-bottom: 8px;
        }
        .finding-section p {
            font-size: 14px;
            color: #374151;
        }
        .cvss-badge {
            display: inline-block;
            padding: 4px 8px;
            background: #e5e7eb;
            border-radius: 4px;
            font-size: 12px;
            font-weight: 600;
            font-family: monospace;
        }
        .remediation-step {
            display: flex;
            gap: 16px;
            padding: 20px;
            background: #f9fafb;
            border-radius: 8px;
            margin-bottom: 16px;
        }
        .step-priority {
            display: flex;
            align-items: center;
            justify-content: center;
            width: 40px;
            height: 40px;
            background: #111827;
            color: white;
            border-radius: 50%;
            font-weight: bold;
            flex-shrink: 0;
        }
        .step-content h4 {
            font-size: 16px;
            margin-bottom: 8px;
        }
        .step-meta {
            display: flex;
            gap: 16px;
            font-size: 14px;
            color: #6b7280;
        }
        .footer {
            text-align: center;
            padding: 40px 0;
            border-top: 1px solid #e5e7eb;
            margin-top: 60px;
            color: #6b7280;
            font-size: 14px;
        }
        .page-break {
            page-break-after: always;
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <h1>Security Assessment Report</h1>
            <p class="subtitle">{{.Target}}</p>
        </div>

        <!-- Meta Information -->
        <div class="meta-info">
            <div class="meta-item">
                <div class="meta-label">Report ID</div>
                <div class="meta-value">{{.ReportID}}</div>
            </div>
            <div class="meta-item">
                <div class="meta-label">Generated</div>
                <div class="meta-value">{{formatDate .GeneratedAt}}</div>
            </div>
            <div class="meta-item">
                <div class="meta-label">Scanner Version</div>
                <div class="meta-value">{{.ScannerVersion}}</div>
            </div>
            <div class="meta-item">
                <div class="meta-label">AI Provider</div>
                <div class="meta-value">{{if .AIProvider}}{{.AIProvider}}{{else}}N/A{{end}}</div>
            </div>
            <div class="meta-item">
                <div class="meta-label">Risk Score</div>
                <div class="risk-score" style="background: {{riskColor .RiskScore}}">{{.RiskScore}}</div>
            </div>
        </div>

        <!-- Risk Summary -->
        <div class="section">
            <h2>Risk Summary</h2>
            <div class="stats-grid">
                <div class="stat-card" style="background: {{severityBgColor "Critical"}}">
                    <div class="stat-number" style="color: {{severityColor "Critical"}}">{{.Summary.Critical}}</div>
                    <div class="stat-label">Critical</div>
                </div>
                <div class="stat-card" style="background: {{severityBgColor "High"}}">
                    <div class="stat-number" style="color: {{severityColor "High"}}">{{.Summary.High}}</div>
                    <div class="stat-label">High</div>
                </div>
                <div class="stat-card" style="background: {{severityBgColor "Medium"}}">
                    <div class="stat-number" style="color: {{severityColor "Medium"}}">{{.Summary.Medium}}</div>
                    <div class="stat-label">Medium</div>
                </div>
                <div class="stat-card" style="background: {{severityBgColor "Low"}}">
                    <div class="stat-number" style="color: {{severityColor "Low"}}">{{.Summary.Low}}</div>
                    <div class="stat-label">Low</div>
                </div>
                <div class="stat-card" style="background: {{severityBgColor "Info"}}">
                    <div class="stat-number" style="color: {{severityColor "Info"}}">{{.Summary.Info}}</div>
                    <div class="stat-label">Info</div>
                </div>
            </div>
        </div>

        <!-- Executive Summary -->
        <div class="section">
            <h2>Executive Summary</h2>
            <div class="executive-summary">
                {{.ExecutiveSummary}}
            </div>
        </div>

        <div class="page-break"></div>

        <!-- Detailed Findings -->
        <div class="section">
            <h2>Detailed Findings</h2>
            {{range .Findings}}
            <div class="finding-card">
                <div class="finding-header" style="background: {{severityBgColor .Severity}}; border-left: 4px solid {{severityColor .Severity}};">
                    <div class="finding-title">{{.Title}}</div>
                    <span class="finding-severity" style="background: {{severityColor .Severity}}; color: white;">{{.Severity}}</span>
                </div>
                <div class="finding-body">
                    <div class="finding-section">
                        <h4>Description</h4>
                        <p>{{.Description}}</p>
                    </div>
                    <div class="finding-section">
                        <h4>CVSS Score</h4>
                        <span class="cvss-badge">{{printf "%.1f" .CVSSScore}}</span>
                        <span style="margin-left: 10px; font-family: monospace; font-size: 12px;">{{.CVSSVector}}</span>
                    </div>
                    {{if .OWASPStandard}}
                    <div class="finding-section">
                        <h4>OWASP Category</h4>
                        <p>{{.OWASPStandard}}</p>
                    </div>
                    {{end}}
                    <div class="finding-section">
                        <h4>Business Impact</h4>
                        <p>{{.BusinessImpact}}</p>
                    </div>
                    <div class="finding-section">
                        <h4>Remediation</h4>
                        <p>{{.Remediation}}</p>
                        <p style="margin-top: 8px;"><strong>Effort:</strong> {{.RemediationEffort}}</p>
                    </div>
                    {{if .References}}
                    <div class="finding-section">
                        <h4>References</h4>
                        {{range .References}}
                        <p style="font-family: monospace; font-size: 12px;">{{.}}</p>
                        {{end}}
                    </div>
                    {{end}}
                </div>
            </div>
            {{end}}
        </div>

        <div class="page-break"></div>

        <!-- Remediation Roadmap -->
        <div class="section">
            <h2>Remediation Roadmap</h2>
            {{range .RemediationPlan}}
            <div class="remediation-step">
                <div class="step-priority">{{.Priority}}</div>
                <div class="step-content">
                    <h4>{{.Action}}</h4>
                    <div class="step-meta">
                        <span><strong>Effort:</strong> {{.Effort}}</span>
                        <span><strong>Impact:</strong> {{.Impact}}</span>
                        <span><strong>Category:</strong> {{.Category}}</span>
                    </div>
                </div>
            </div>
            {{end}}
        </div>

        <!-- Footer -->
        <div class="footer">
            <p>Generated by Agentic Scanner v{{.ScannerVersion}}</p>
            <p style="margin-top: 8px;">Report ID: {{.ReportID}} | Scan ID: {{.ScanID}}</p>
            <p style="margin-top: 8px; font-size: 12px;">This report contains confidential security information.</p>
        </div>
    </div>
</body>
</html>`

// PDFExportOptions contains options for PDF export
type PDFExportOptions struct {
	IncludeRawEvidence bool
	IncludeScreenshots bool
	IncludeTechStack   bool
	MaxFindings        int
}

// DefaultPDFOptions returns default PDF export options
func DefaultPDFOptions() PDFExportOptions {
	return PDFExportOptions{
		IncludeRawEvidence: true,
		IncludeScreenshots: true,
		IncludeTechStack:   true,
		MaxFindings:        100,
	}
}

// GenerateWithOptions creates a PDF with specific options
func (g *PDFGenerator) GenerateWithOptions(report *scanner.Report, analysis *ai.AIAnalysisResponse, opts PDFExportOptions) ([]byte, error) {
	data := g.prepareData(report, analysis)

	// Apply options
	if opts.MaxFindings > 0 && len(data.Findings) > opts.MaxFindings {
		data.Findings = data.Findings[:opts.MaxFindings]
	}

	return g.generateHTMLPDF(data)
}

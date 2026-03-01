package classifier

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/redteam/agentic-scanner/internal/ai"
)

// TargetType represents the classification type of a target
type TargetType string

const (
	TargetTypeWebApp       TargetType = "web_app"
	TargetTypeRESTAPI      TargetType = "rest_api"
	TargetTypeGraphQL      TargetType = "graphql"
	TargetTypeWebSocket    TargetType = "websocket"
	TargetTypeGRPC         TargetType = "grpc"
	TargetTypeAILLMApp     TargetType = "ai_llm_app"
	TargetTypeBareIP       TargetType = "bare_ip"
	TargetTypeCDNProtected TargetType = "cdn_protected"
	TargetTypeUnknown      TargetType = "unknown"
)

// Target represents a parsed and analyzed target
type Target struct {
	Raw          string
	URL          *url.URL
	Host         string
	IP           net.IP
	Port         int
	IsIP         bool
	Protocol     string // http, https, ws, wss, grpc
	Path         string
	TargetTypes  []TargetType
	Technologies []Technology
	Confidence   float64
}

// ClassificationResult represents the complete classification result
type ClassificationResult struct {
	Target           Target
	Types            []TargetType
	Technologies     []Technology
	SuggestedModules []string
	Warnings         []string
	Confidence       float64
	ClassifiedAt     time.Time
}

// ToJSON serializes the result to JSON
func (r *ClassificationResult) ToJSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

// TargetClassifier is the main classifier for analyzing targets
type TargetClassifier struct {
	normalizer   *TargetNormalizer
	prober       *TargetProber
	fingerprints *TechnologyFingerprints
	aiClient     *ai.Client
	cache        map[string]*ClassificationResult
	cacheMu      sync.RWMutex
	ttl          time.Duration
	logger       *log.Logger
}

// NewTargetClassifier creates a new target classifier
func NewTargetClassifier(aiClient *ai.Client) *TargetClassifier {
	return &TargetClassifier{
		normalizer:   NewTargetNormalizer(),
		prober:       NewTargetProber(),
		fingerprints: NewTechnologyFingerprints(),
		aiClient:     aiClient,
		cache:        make(map[string]*ClassificationResult),
		ttl:          time.Hour,
		logger:       log.New(log.Writer(), "[Classifier] ", log.LstdFlags),
	}
}

// SetCacheTTL sets the cache TTL
func (c *TargetClassifier) SetCacheTTL(ttl time.Duration) {
	c.ttl = ttl
}

// Classify performs complete target classification
func (c *TargetClassifier) Classify(ctx context.Context, rawTarget string) (*ClassificationResult, error) {
	start := time.Now()
	c.logger.Printf("Starting classification for target: %s", rawTarget)

	// Check cache first
	if cached := c.getFromCache(rawTarget); cached != nil {
		c.logger.Printf("Cache hit for target: %s", rawTarget)
		return cached, nil
	}

	// Create timeout context
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	result := &ClassificationResult{
		Target:       Target{Raw: rawTarget},
		ClassifiedAt: time.Now(),
	}

	// Step 1: Parse and normalize
	normalized, err := c.normalizer.Normalize(rawTarget)
	if err != nil {
		return nil, fmt.Errorf("failed to normalize target: %w", err)
	}

	result.Target = Target{
		Raw:      rawTarget,
		URL:      normalized.URL,
		Host:     normalized.Host,
		IP:       normalized.IP,
		Port:     normalized.Port,
		IsIP:     normalized.IsIP,
		Protocol: normalized.Protocol,
		Path:     normalized.Path,
	}

	// Check for bare IP
	if normalized.IsIP {
		result.Types = append(result.Types, TargetTypeBareIP)
		result.Warnings = append(result.Warnings, "Target is a bare IP address - limited reconnaissance possible")
	}

	// Check for CDN
	if normalized.IsCDN {
		result.Types = append(result.Types, TargetTypeCDNProtected)
		result.Warnings = append(result.Warnings, fmt.Sprintf("CDN detected (%s) - some tests may be blocked or rate-limited", normalized.CDNProvider))
		result.Technologies = append(result.Technologies, Technology{
			Name:       normalized.CDNProvider,
			Category:   "CDN",
			Confidence: 0.95,
		})
	}

	// Step 2: Probe target
	probeResult, err := c.prober.Probe(ctx, normalized)
	if err != nil {
		c.logger.Printf("Probe error: %v", err)
		result.Warnings = append(result.Warnings, fmt.Sprintf("Probe failed: %v", err))
	}

	if probeResult != nil && probeResult.Success {
		// Detect technologies from headers
		if probeResult.Headers != nil {
			techs := c.fingerprints.DetectTechnologies(probeResult.Headers, "", "")
			result.Technologies = append(result.Technologies, techs...)

			// Check for CDN in headers
			if cdn, confidence := GetCDNProvider(probeResult.Headers); cdn != "" {
				found := false
				for _, t := range result.Technologies {
					if t.Name == cdn {
						found = true
						break
					}
				}
				if !found {
					result.Technologies = append(result.Technologies, Technology{
						Name:       cdn,
						Category:   "CDN",
						Confidence: confidence,
					})
				}
				if !containsType(result.Types, TargetTypeCDNProtected) {
					result.Types = append(result.Types, TargetTypeCDNProtected)
				}
			}
		}

		// Check for WebSocket
		if probeResult.WebSocketInfo != nil && probeResult.WebSocketInfo.Available {
			result.Types = append(result.Types, TargetTypeWebSocket)
			result.Technologies = append(result.Technologies, Technology{
				Name:       "WebSocket",
				Category:   "Protocol",
				Confidence: 0.95,
			})
		}

		// Check for gRPC
		if probeResult.gRPCInfo != nil && probeResult.gRPCInfo.Available {
			result.Types = append(result.Types, TargetTypeGRPC)
			result.Technologies = append(result.Technologies, Technology{
				Name:       "gRPC",
				Category:   "Protocol",
				Confidence: 0.9,
			})
		}
	}

	// Step 3: Check for GraphQL
	graphqlResult := c.prober.ProbeGraphQL(ctx, normalized)
	if graphqlResult.Found {
		result.Types = append(result.Types, TargetTypeGraphQL)
		result.Technologies = append(result.Technologies, Technology{
			Name:       "GraphQL",
			Category:   "API",
			Confidence: 0.95,
		})
		if graphqlResult.IntrospectionEnabled {
			result.Warnings = append(result.Warnings, "GraphQL introspection is enabled - potential information disclosure")
		}
	}

	// Step 4: Check for AI/LLM endpoints
	aiResults := c.prober.ProbeAIEndpoints(ctx, normalized)
	hasAIEndpoints := false
	openAICompatible := false

	for path, aiResult := range aiResults {
		if aiResult.Exists {
			hasAIEndpoints = true
			if aiResult.OpenAICompatible {
				openAICompatible = true
			}
			c.logger.Printf("Found AI endpoint: %s", path)
		}
	}

	if hasAIEndpoints {
		result.Types = append(result.Types, TargetTypeAILLMApp)
		result.Technologies = append(result.Technologies, Technology{
			Name:       "AI/LLM Application",
			Category:   "AI/ML Framework",
			Confidence: 0.85,
		})
		if openAICompatible {
			result.Technologies = append(result.Technologies, Technology{
				Name:       "OpenAI-Compatible API",
				Category:   "AI/ML Framework",
				Confidence: 0.9,
			})
		}
	}

	// Step 5: Analyze HTML content
	if probeResult != nil && len(probeResult.Body) > 0 {
		body := string(probeResult.Body)
		techs := c.fingerprints.DetectTechnologies(nil, body, normalized.Path)
		result.Technologies = mergeTechnologies(result.Technologies, techs)

		// Check for AI frameworks in HTML
		if c.fingerprints.IsAIApplication(techs) {
			if !containsType(result.Types, TargetTypeAILLMApp) {
				result.Types = append(result.Types, TargetTypeAILLMApp)
			}
		}

		// Detect if it's a web app based on HTML content
		if !containsType(result.Types, TargetTypeWebApp) && !normalized.IsIP {
			result.Types = append(result.Types, TargetTypeWebApp)
		}
	}

	// Step 6: Determine if REST API
	if c.isRESTAPI(normalized, probeResult, result.Technologies) {
		if !containsType(result.Types, TargetTypeRESTAPI) {
			result.Types = append(result.Types, TargetTypeRESTAPI)
		}
	}

	// Step 7: Generate suggested modules
	result.SuggestedModules = c.suggestModules(result.Types)

	// Step 8: Calculate overall confidence
	result.Confidence = c.calculateConfidence(result.Types, result.Technologies)

	// Step 9: Add TLS warnings if applicable
	if probeResult != nil && probeResult.TLSInfo != nil {
		if probeResult.TLSInfo.IsSelfSigned {
			result.Warnings = append(result.Warnings, "Self-signed certificate detected")
		}
		if probeResult.TLSInfo.Version < tls.VersionTLS12 {
			result.Warnings = append(result.Warnings, "Outdated TLS version detected")
		}
	}

	// Update target with final types
	result.Target.TargetTypes = result.Types
	result.Target.Technologies = result.Technologies
	result.Target.Confidence = result.Confidence

	c.logger.Printf("Classification completed in %v - Types: %v, Technologies: %d, Confidence: %.2f",
		time.Since(start), result.Types, len(result.Technologies), result.Confidence)

	// Store in cache
	c.storeInCache(rawTarget, result)

	return result, nil
}

// isRESTAPI determines if the target is a REST API
func (c *TargetClassifier) isRESTAPI(normalized *NormalizedTarget, probeResult *ProbeResult, technologies []Technology) bool {
	// Check path indicators
	apiPaths := []string{"/api", "/v1/", "/v2/", "/rest/", "/swagger", "/openapi"}
	for _, path := range apiPaths {
		if strings.Contains(normalized.Path, path) || strings.Contains(normalized.URL.Path, path) {
			return true
		}
	}

	// Check technologies
	for _, tech := range technologies {
		if tech.Category == "API" || tech.Category == "API Documentation" {
			return true
		}
	}

	// Check Content-Type header
	if probeResult != nil && probeResult.Headers != nil {
		contentType := probeResult.Headers.Get("Content-Type")
		if strings.Contains(contentType, "application/json") &&
			!strings.Contains(normalized.URL.Path, ".html") {
			return true
		}
	}

	// Check if it has API endpoints but no HTML content
	if probeResult != nil && probeResult.StatusCode == http.StatusOK {
		contentType := probeResult.Headers.Get("Content-Type")
		if strings.Contains(contentType, "application/json") &&
			len(probeResult.Body) > 0 {
			var jsonData interface{}
			if err := json.Unmarshal(probeResult.Body, &jsonData); err == nil {
				return true
			}
		}
	}

	return false
}

// suggestModules generates module recommendations based on types
func (c *TargetClassifier) suggestModules(types []TargetType) []string {
	moduleMap := map[TargetType][]string{
		TargetTypeWebApp:       {"web"},
		TargetTypeRESTAPI:      {"api", "web"},
		TargetTypeGraphQL:      {"api"},
		TargetTypeWebSocket:    {"api"},
		TargetTypeGRPC:         {"api"},
		TargetTypeAILLMApp:     {"agentic"},
		TargetTypeCDNProtected: {},
		TargetTypeBareIP:       {"recon"},
	}

	// Use map to avoid duplicates
	moduleSet := map[string]bool{
		"recon": true,
		"intel": true,
	}

	for _, t := range types {
		if mods, ok := moduleMap[t]; ok {
			for _, m := range mods {
				moduleSet[m] = true
			}
		}
	}

	// Convert to slice
	result := make([]string, 0, len(moduleSet))
	for m := range moduleSet {
		result = append(result, m)
	}

	return result
}

// calculateConfidence calculates overall confidence score
func (c *TargetClassifier) calculateConfidence(types []TargetType, technologies []Technology) float64 {
	if len(types) == 0 {
		return 0.5 // Default confidence
	}

	// Base confidence on number of indicators
	confidence := 0.5

	// Boost for each detected type
	confidence += float64(len(types)) * 0.1

	// Boost for high-confidence technologies
	for _, tech := range technologies {
		confidence += tech.Confidence * 0.05
	}

	// Cap at 1.0
	if confidence > 1.0 {
		confidence = 1.0
	}

	return confidence
}

// getFromCache retrieves from cache if not expired
func (c *TargetClassifier) getFromCache(key string) *ClassificationResult {
	c.cacheMu.RLock()
	defer c.cacheMu.RUnlock()

	if result, ok := c.cache[key]; ok {
		// Check TTL
		if time.Since(result.ClassifiedAt) < c.ttl {
			return result
		}
	}
	return nil
}

// storeInCache stores result in cache
func (c *TargetClassifier) storeInCache(key string, result *ClassificationResult) {
	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()

	c.cache[key] = result
}

// ClearCache clears the classification cache
func (c *TargetClassifier) ClearCache() {
	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()

	c.cache = make(map[string]*ClassificationResult)
}

// containsType checks if types slice contains a specific type
func containsType(types []TargetType, target TargetType) bool {
	for _, t := range types {
		if t == target {
			return true
		}
	}
	return false
}

// mergeTechnologies merges two technology slices, keeping highest confidence
func mergeTechnologies(existing, new []Technology) []Technology {
	techMap := make(map[string]Technology)

	for _, tech := range existing {
		techMap[tech.Name] = tech
	}

	for _, tech := range new {
		if existing, ok := techMap[tech.Name]; !ok || existing.Confidence < tech.Confidence {
			techMap[tech.Name] = tech
		}
	}

	result := make([]Technology, 0, len(techMap))
	for _, tech := range techMap {
		result = append(result, tech)
	}

	return result
}

// Severity represents finding severity levels (local copy to avoid import cycle)
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Finding represents a security finding (local copy to avoid import cycle)
type Finding struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Severity    Severity `json:"severity"`
	Category    string   `json:"category"`
}

// FindingClassifier classifies security findings
type FindingClassifier struct {
	aiClient *ai.Client
}

// NewFindingClassifier creates a new finding classifier
func NewFindingClassifier(aiClient *ai.Client) *FindingClassifier {
	return &FindingClassifier{aiClient: aiClient}
}

// Classification represents the classification result for a finding
type Classification struct {
	Severity      Severity `json:"severity"`
	Category      string   `json:"category"`
	Confidence    float64  `json:"confidence"`
	FalsePositive bool     `json:"false_positive"`
	Explanation   string   `json:"explanation"`
}

// Classify analyzes a finding and returns a classification
func (c *FindingClassifier) Classify(ctx context.Context, finding Finding, context string) (*Classification, error) {
	// Use AI client to classify if available
	if c.aiClient != nil {
		return c.classifyWithAI(ctx, finding, context)
	}

	// Fallback to rule-based classification
	return c.classifyRuleBased(finding)
}

// classifyWithAI uses AI to classify a finding
func (c *FindingClassifier) classifyWithAI(ctx context.Context, finding Finding, context string) (*Classification, error) {
	// This would call the AI client for classification
	// For now, fall back to rule-based
	return c.classifyRuleBased(finding)
}

// classifyRuleBased performs rule-based classification
func (c *FindingClassifier) classifyRuleBased(finding Finding) (*Classification, error) {
	category := c.mapCategory(finding.Title + " " + finding.Description)

	return &Classification{
		Severity:      finding.Severity,
		Category:      category,
		Confidence:    0.8,
		FalsePositive: false,
		Explanation:   "Automated classification based on finding details",
	}, nil
}

// mapCategory maps finding text to a category
func (c *FindingClassifier) mapCategory(text string) string {
	text = strings.ToLower(text)

	categories := map[string][]string{
		"injection":      {"sql injection", "xss", "command injection", "ldap injection", "nosql"},
		"authentication": {"weak password", "brute force", "session", "jwt", "oauth", "auth"},
		"configuration":  {"ssl", "tls", "header", "cors", "csp", "certificate"},
		"sensitive_data": {"information disclosure", "data exposure", "pii", "leak"},
		"access_control": {"authorization", "privilege escalation", "idor", "access"},
		"ai_security":    {"prompt injection", "model extraction", "adversarial", "llm", "ai"},
	}

	for category, keywords := range categories {
		for _, keyword := range keywords {
			if strings.Contains(text, keyword) {
				return category
			}
		}
	}

	return "other"
}

// SeverityClassifier classifies severity based on context
type SeverityClassifier struct{}

// NewSeverityClassifier creates a new severity classifier
func NewSeverityClassifier() *SeverityClassifier {
	return &SeverityClassifier{}
}

// ClassifySeverity classifies severity based on finding and context
func (c *SeverityClassifier) ClassifySeverity(finding Finding, env string, criticality string) Severity {
	// Base severity
	severity := finding.Severity

	// Adjust based on environment
	if env == "production" && severity == SeverityMedium {
		return SeverityHigh
	}

	// Adjust based on asset criticality
	if criticality == "critical" && (severity == SeverityLow || severity == SeverityMedium) {
		return SeverityHigh
	}

	return severity
}

// CategoryMapper maps findings to standard categories
type CategoryMapper struct {
	categories map[string][]string
}

// NewCategoryMapper creates a new category mapper
func NewCategoryMapper() *CategoryMapper {
	return &CategoryMapper{
		categories: map[string][]string{
			"injection":      {"sql injection", "xss", "command injection", "ldap injection"},
			"authentication": {"weak password", "brute force", "session", "jwt"},
			"configuration":  {"ssl", "tls", "header", "cors", "csp"},
			"sensitive_data": {"information disclosure", "data exposure", "pii"},
			"access_control": {"authorization", "privilege escalation", "idor"},
		},
	}
}

// MapCategory maps a finding title/description to a category
func (m *CategoryMapper) MapCategory(text string) string {
	text = strings.ToLower(text)

	for category, keywords := range m.categories {
		for _, keyword := range keywords {
			if strings.Contains(text, keyword) {
				return category
			}
		}
	}

	return "other"
}

// ClassificationCacheEntry represents a cached classification
type ClassificationCacheEntry struct {
	Result    *ClassificationResult
	Timestamp time.Time
	ScanID    uuid.UUID
}

package ai

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/sashabaranov/go-openai"
)

// ============================================================================
// AI Client Configuration
// ============================================================================

const (
	// Default timeouts
	DefaultRequestTimeout = 120 * time.Second
	MaxRetries            = 3
	BaseRetryDelay        = 2 * time.Second

	// Cache settings
	CacheTTL = 60 * time.Minute

	// Anthropic API settings
	AnthropicAPIURL  = "https://api.anthropic.com/v1/messages"
	AnthropicVersion = "2023-06-01"
)

// AIClient is the production AI client supporting multiple providers
type AIClient struct {
	anthropicAPIKey string
	openaiClient    *openai.Client

	// Circuit breaker
	circuitBreaker *CircuitBreaker

	// Cache
	cache      *Cache
	cacheMutex sync.RWMutex

	// Token tracking
	tokenUsage TokenUsage
	usageMutex sync.RWMutex

	// Configuration
	primaryModel   AIModel
	fallbackModel  AIModel
	requestTimeout time.Duration
}

// CircuitBreaker implements a simple circuit breaker pattern
type CircuitBreaker struct {
	state           CircuitState
	failures        int
	successes       int
	lastFailureTime time.Time
	config          CircuitBreakerConfig
	mutex           sync.RWMutex
}

// Cache provides simple in-memory caching
type Cache struct {
	entries map[string]*CacheEntry
	mutex   sync.RWMutex
}

// NewAIClient creates a new AI client with support for both Claude and OpenAI
func NewAIClient() (*AIClient, error) {
	// Get API keys from environment
	anthropicKey := os.Getenv("ANTHROPIC_API_KEY")
	openaiKey := os.Getenv("OPENAI_API_KEY")

	if anthropicKey == "" && openaiKey == "" {
		return nil, fmt.Errorf("no AI API keys configured: set ANTHROPIC_API_KEY or OPENAI_API_KEY")
	}

	var oaClient *openai.Client
	if openaiKey != "" {
		oaClient = openai.NewClient(openaiKey)
	}

	return &AIClient{
		anthropicAPIKey: anthropicKey,
		openaiClient:    oaClient,
		circuitBreaker:  NewCircuitBreaker(DefaultCircuitBreakerConfig()),
		cache:           NewCache(),
		primaryModel:    ModelClaude35Sonnet,
		fallbackModel:   ModelGPT4o,
		requestTimeout:  DefaultRequestTimeout,
		tokenUsage:      TokenUsage{},
	}, nil
}

// NewCircuitBreaker creates a new circuit breaker
func NewCircuitBreaker(config CircuitBreakerConfig) *CircuitBreaker {
	return &CircuitBreaker{
		state:  CircuitClosed,
		config: config,
	}
}

// NewCache creates a new cache instance
func NewCache() *Cache {
	return &Cache{
		entries: make(map[string]*CacheEntry),
	}
}

// ============================================================================
// Circuit Breaker Methods
// ============================================================================

// CanExecute checks if the circuit allows execution
func (cb *CircuitBreaker) CanExecute() bool {
	cb.mutex.RLock()
	defer cb.mutex.RUnlock()

	switch cb.state {
	case CircuitClosed:
		return true
	case CircuitOpen:
		if time.Since(cb.lastFailureTime) > cb.config.ResetTimeout {
			cb.mutex.RUnlock()
			cb.mutex.Lock()
			cb.state = CircuitHalfOpen
			cb.failures = 0
			cb.mutex.Unlock()
			cb.mutex.RLock()
			return true
		}
		return false
	case CircuitHalfOpen:
		return true
	}
	return false
}

// RecordSuccess records a successful execution
func (cb *CircuitBreaker) RecordSuccess() {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()

	switch cb.state {
	case CircuitHalfOpen:
		cb.successes++
		if cb.successes >= cb.config.SuccessThreshold {
			cb.state = CircuitClosed
			cb.failures = 0
			cb.successes = 0
		}
	case CircuitClosed:
		cb.failures = 0
	}
}

// RecordFailure records a failed execution
func (cb *CircuitBreaker) RecordFailure() {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()

	cb.failures++
	cb.lastFailureTime = time.Now()

	switch cb.state {
	case CircuitHalfOpen:
		cb.state = CircuitOpen
	case CircuitClosed:
		if cb.failures >= cb.config.MaxFailures {
			cb.state = CircuitOpen
		}
	}
}

// GetState returns the current circuit state
func (cb *CircuitBreaker) GetState() CircuitState {
	cb.mutex.RLock()
	defer cb.mutex.RUnlock()
	return cb.state
}

// ============================================================================
// Cache Methods
// ============================================================================

// Get retrieves a cached response
func (c *Cache) Get(key string) (*CacheEntry, bool) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	entry, exists := c.entries[key]
	if !exists || time.Now().After(entry.ExpiresAt) {
		return nil, false
	}
	return entry, true
}

// Set stores a response in the cache
func (c *Cache) Set(key string, response AIAnalysisResponse, usage TokenUsage) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.entries[key] = &CacheEntry{
		Key:        key,
		Response:   response,
		CreatedAt:  time.Now(),
		ExpiresAt:  time.Now().Add(CacheTTL),
		TokenUsage: usage,
	}
}

// Cleanup removes expired entries
func (c *Cache) Cleanup() {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	now := time.Now()
	for key, entry := range c.entries {
		if now.After(entry.ExpiresAt) {
			delete(c.entries, key)
		}
	}
}

// ============================================================================
// Main AI Analysis Method
// ============================================================================

// AnalyzeScan performs AI analysis on scan findings with structured output
func (c *AIClient) AnalyzeScan(ctx context.Context, req AIAnalysisRequest) (*AIAnalysisResponse, error) {
	startTime := time.Now()

	// Generate cache key
	cacheKey := c.generateCacheKey(req)

	// Check cache
	if cached, found := c.cache.Get(cacheKey); found {
		cached.Response.Cached = true
		cached.Response.AnalysisDuration = int(time.Since(startTime).Seconds())
		return &cached.Response, nil
	}

	// Check circuit breaker
	if !c.circuitBreaker.CanExecute() {
		// Circuit is open, use fallback analysis
		return c.fallbackAnalysis(req)
	}

	// Prepare prompts
	systemPrompt := SystemPrompt
	userPrompt, err := BuildAnalysisPrompt(req)
	if err != nil {
		return nil, fmt.Errorf("failed to build prompt: %w", err)
	}

	// Try primary model (Claude)
	var response *AIAnalysisResponse
	var tokenUsage TokenUsage

	if c.anthropicAPIKey != "" && c.circuitBreaker.CanExecute() {
		response, tokenUsage, err = c.callAnthropic(ctx, systemPrompt, userPrompt)
		if err != nil {
			c.circuitBreaker.RecordFailure()
			// Fall through to OpenAI
		} else {
			c.circuitBreaker.RecordSuccess()
			response.AIProvider = string(ProviderAnthropic)
		}
	}

	// Fallback to OpenAI if Anthropic failed or is not available
	if response == nil && c.openaiClient != nil {
		response, tokenUsage, err = c.callOpenAI(ctx, systemPrompt, userPrompt)
		if err != nil {
			c.circuitBreaker.RecordFailure()
			return c.fallbackAnalysis(req)
		}
		c.circuitBreaker.RecordSuccess()
		response.AIProvider = string(ProviderOpenAI)
	}

	// If both failed, use fallback
	if response == nil {
		return c.fallbackAnalysis(req)
	}

	// Set metadata
	response.TokenUsage = tokenUsage
	response.AnalysisDuration = int(time.Since(startTime).Seconds())
	response.Cached = false
	response.RiskLevel = calculateRiskLevel(response.RiskScore)

	// Update token tracking
	c.recordTokenUsage(tokenUsage)

	// Cache the response
	c.cache.Set(cacheKey, *response, tokenUsage)

	return response, nil
}

// callAnthropic calls the Anthropic API with structured output
func (c *AIClient) callAnthropic(ctx context.Context, systemPrompt, userPrompt string) (*AIAnalysisResponse, TokenUsage, error) {
	url := AnthropicAPIURL

	requestBody := map[string]interface{}{
		"model":      c.primaryModel.Name,
		"max_tokens": c.primaryModel.MaxTokens,
		"system":     systemPrompt,
		"messages": []map[string]string{
			{"role": "user", "content": userPrompt},
		},
		"temperature": c.primaryModel.Temperature,
	}

	jsonBody, err := json.Marshal(requestBody)
	if err != nil {
		return nil, TokenUsage{}, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, TokenUsage{}, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", c.anthropicAPIKey)
	req.Header.Set("Anthropic-Version", AnthropicVersion)

	// Execute with retries
	var resp *http.Response
	var lastErr error

	for attempt := 0; attempt < MaxRetries; attempt++ {
		if attempt > 0 {
			delay := BaseRetryDelay * time.Duration(1<<attempt)
			time.Sleep(delay)
		}

		resp, err = http.DefaultClient.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			lastErr = fmt.Errorf("anthropic API error: %d", resp.StatusCode)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			return nil, TokenUsage{}, fmt.Errorf("anthropic API error: %d - %s", resp.StatusCode, string(body))
		}

		break
	}

	if resp == nil {
		return nil, TokenUsage{}, fmt.Errorf("failed after %d retries: %w", MaxRetries, lastErr)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, TokenUsage{}, fmt.Errorf("failed to read response: %w", err)
	}

	// Parse Anthropic response
	var anthropicResp struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		Usage struct {
			InputTokens  int `json:"input_tokens"`
			OutputTokens int `json:"output_tokens"`
		} `json:"usage"`
	}

	if err := json.Unmarshal(body, &anthropicResp); err != nil {
		return nil, TokenUsage{}, fmt.Errorf("failed to parse response: %w", err)
	}

	// Extract JSON from text response
	var analysis AIAnalysisResponse
	for _, content := range anthropicResp.Content {
		if content.Type == "text" {
			parsed, err := ParseAnalysisJSON(content.Text)
			if err != nil {
				return nil, TokenUsage{}, fmt.Errorf("failed to parse analysis: %w", err)
			}
			analysis = *parsed
			break
		}
	}

	// Calculate cost (Claude 3.5 Sonnet pricing)
	inputCost := float64(anthropicResp.Usage.InputTokens) * 3.0 / 1000000    // $3/M input tokens
	outputCost := float64(anthropicResp.Usage.OutputTokens) * 15.0 / 1000000 // $15/M output tokens

	tokenUsage := TokenUsage{
		PromptTokens:     anthropicResp.Usage.InputTokens,
		CompletionTokens: anthropicResp.Usage.OutputTokens,
		TotalTokens:      anthropicResp.Usage.InputTokens + anthropicResp.Usage.OutputTokens,
		CostUSD:          inputCost + outputCost,
	}

	return &analysis, tokenUsage, nil
}

// callOpenAI calls the OpenAI API with structured output
func (c *AIClient) callOpenAI(ctx context.Context, systemPrompt, userPrompt string) (*AIAnalysisResponse, TokenUsage, error) {
	// Add JSON schema instructions to the system prompt
	schemaJSON, _ := json.MarshalIndent(GetAnalysisResponseSchema(), "", "  ")
	enhancedPrompt := systemPrompt + "\n\nYou MUST respond with valid JSON matching this exact schema:\n" + string(schemaJSON)

	req := openai.ChatCompletionRequest{
		Model: c.fallbackModel.Name,
		Messages: []openai.ChatCompletionMessage{
			{
				Role:    openai.ChatMessageRoleSystem,
				Content: enhancedPrompt,
			},
			{
				Role:    openai.ChatMessageRoleUser,
				Content: userPrompt,
			},
		},
		Temperature: float32(c.fallbackModel.Temperature),
		MaxTokens:   c.fallbackModel.MaxTokens,
		ResponseFormat: &openai.ChatCompletionResponseFormat{
			Type: openai.ChatCompletionResponseFormatTypeJSONObject,
		},
	}

	// Execute with retries
	var resp openai.ChatCompletionResponse
	var err error

	for attempt := 0; attempt < MaxRetries; attempt++ {
		if attempt > 0 {
			delay := BaseRetryDelay * time.Duration(1<<attempt)
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return nil, TokenUsage{}, ctx.Err()
			}
		}

		resp, err = c.openaiClient.CreateChatCompletion(ctx, req)
		if err != nil {
			if attempt < MaxRetries-1 {
				continue
			}
			return nil, TokenUsage{}, fmt.Errorf("failed to call OpenAI: %w", err)
		}

		if len(resp.Choices) == 0 {
			if attempt < MaxRetries-1 {
				continue
			}
			return nil, TokenUsage{}, fmt.Errorf("no response from OpenAI")
		}

		break
	}

	// Parse the response
	content := resp.Choices[0].Message.Content
	analysis, parseErr := ParseAnalysisJSON(content)
	if parseErr != nil {
		return nil, TokenUsage{}, fmt.Errorf("failed to parse OpenAI response: %w", parseErr)
	}

	// Calculate cost (GPT-4o pricing)
	inputCost := float64(resp.Usage.PromptTokens) * 2.5 / 1000000       // $2.50/M input tokens
	outputCost := float64(resp.Usage.CompletionTokens) * 10.0 / 1000000 // $10.00/M output tokens

	tokenUsage := TokenUsage{
		PromptTokens:     resp.Usage.PromptTokens,
		CompletionTokens: resp.Usage.CompletionTokens,
		TotalTokens:      resp.Usage.TotalTokens,
		CostUSD:          inputCost + outputCost,
	}

	return analysis, tokenUsage, nil
}

// fallbackAnalysis provides rule-based analysis when AI is unavailable
func (c *AIClient) fallbackAnalysis(req AIAnalysisRequest) (*AIAnalysisResponse, error) {
	// Calculate risk score based on findings
	critical, high, medium, low, info := 0, 0, 0, 0, 0

	for _, f := range req.Findings {
		switch f.Severity {
		case "critical":
			critical++
		case "high":
			high++
		case "medium":
			medium++
		case "low":
			low++
		default:
			info++
		}
	}

	riskScore := CalculateRiskScore(critical, high, medium, low)

	// Convert findings to AI findings
	aiFindings := make([]AIFinding, len(req.Findings))
	for i, f := range req.Findings {
		cvssScore := f.CVSS
		if cvssScore == 0 {
			cvssScore = severityToCVSS(f.Severity)
		}

		aiFindings[i] = AIFinding{
			ID:                f.ID.String(),
			Title:             f.Title,
			Severity:          capitalizeFirst(f.Severity),
			CVSSScore:         cvssScore,
			CVSSVector:        fmt.Sprintf("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:%s/I:%s/A:%s", severityToCIA(f.Severity), severityToCIA(f.Severity), severityToCIA(f.Severity)),
			Description:       f.Description,
			RawEvidence:       fmt.Sprintf("%v", f.Evidence),
			BusinessImpact:    generateBusinessImpact(f),
			Remediation:       f.Remediation,
			RemediationEffort: "Medium",
			References:        f.References,
			ModuleSource:      f.Module,
			OriginalFindingID: f.ID.String(),
			Confidence:        0.7,
		}
	}

	// Generate remediation roadmap
	roadmap := generateRemediationRoadmap(aiFindings)

	return &AIAnalysisResponse{
		ExecutiveSummary:   generateExecutiveSummary(req, riskScore, critical, high, medium, low),
		RiskScore:          riskScore,
		RiskLevel:          calculateRiskLevel(riskScore),
		Findings:           aiFindings,
		RemediationRoadmap: roadmap,
		AIProvider:         string(ProviderFallback),
		TokenUsage:         TokenUsage{},
		Cached:             false,
	}, nil
}

// generateCacheKey creates a cache key for the request
func (c *AIClient) generateCacheKey(req AIAnalysisRequest) string {
	// Create a simplified key based on findings content
	data, _ := json.Marshal(struct {
		Target    string
		Findings  int
		Modules   []string
		TechCount int
	}{
		Target:    req.Target,
		Findings:  len(req.Findings),
		Modules:   req.ModulesRun,
		TechCount: len(req.Technologies),
	})

	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// recordTokenUsage tracks token consumption
func (c *AIClient) recordTokenUsage(usage TokenUsage) {
	c.usageMutex.Lock()
	defer c.usageMutex.Unlock()

	c.tokenUsage.PromptTokens += usage.PromptTokens
	c.tokenUsage.CompletionTokens += usage.CompletionTokens
	c.tokenUsage.TotalTokens += usage.TotalTokens
	c.tokenUsage.CostUSD += usage.CostUSD
}

// GetTokenUsage returns total token usage
func (c *AIClient) GetTokenUsage() TokenUsage {
	c.usageMutex.RLock()
	defer c.usageMutex.RUnlock()
	return c.tokenUsage
}

// ============================================================================
// Helper Functions
// ============================================================================

// CalculateRiskScore calculates the risk score based on findings
func CalculateRiskScore(critical, high, medium, low int) int {
	score := critical*25 + high*10 + medium*4 + low*1
	maxPossible := 100 // Based on max reasonable findings

	if maxPossible == 0 {
		return 0
	}

	riskScore := (score * 100) / maxPossible
	if riskScore > 100 {
		riskScore = 100
	}
	return riskScore
}

// calculateRiskLevel converts risk score to level string
func calculateRiskLevel(score int) string {
	switch {
	case score >= 80:
		return "Critical"
	case score >= 60:
		return "High"
	case score >= 40:
		return "Medium"
	case score >= 20:
		return "Low"
	default:
		return "Informational"
	}
}

// severityToCVSS converts severity to approximate CVSS score
func severityToCVSS(severity string) float64 {
	switch severity {
	case "critical":
		return 9.0
	case "high":
		return 7.5
	case "medium":
		return 5.5
	case "low":
		return 3.5
	default:
		return 0.0
	}
}

// severityToCIA converts severity to CIA impact level
func severityToCIA(severity string) string {
	switch severity {
	case "critical", "high":
		return "H"
	case "medium":
		return "L"
	default:
		return "N"
	}
}

// capitalizeFirst capitalizes the first letter of a string
func capitalizeFirst(s string) string {
	if s == "" {
		return s
	}
	return string(s[0]-32) + s[1:]
}

// generateBusinessImpact generates a business impact description
func generateBusinessImpact(f RawFinding) string {
	switch f.Severity {
	case "critical":
		return "This vulnerability poses a severe risk to the organization. Immediate exploitation could lead to complete system compromise, data breach, or service disruption."
	case "high":
		return "This finding represents a significant security risk that should be prioritized for remediation. Exploitation could result in unauthorized access or data exposure."
	case "medium":
		return "This issue presents a moderate security risk. While not immediately exploitable, it could be combined with other vulnerabilities to achieve a compromise."
	case "low":
		return "This is a minor security concern with limited impact. Should be addressed as part of regular security maintenance."
	default:
		return "Informational finding with no immediate security impact."
	}
}

// generateExecutiveSummary creates an executive summary
func generateExecutiveSummary(req AIAnalysisRequest, riskScore, critical, high, medium, low int) string {
	return fmt.Sprintf(
		"A security assessment was conducted on %s, identifying %d findings across %d severity levels. "+
			"The assessment revealed %d critical and %d high severity vulnerabilities that require immediate attention. "+
			"The overall risk score of %d/%100 indicates a %s risk level.\n\n"+
			"Key recommendations include prioritizing remediation of critical findings, implementing proper security controls, "+
			"and conducting regular security assessments to maintain a strong security posture.",
		req.Target, len(req.Findings), critical+high+medium+low,
		critical, high, riskScore, calculateRiskLevel(riskScore),
	)
}

// generateRemediationRoadmap creates a prioritized remediation plan
func generateRemediationRoadmap(findings []AIFinding) []RemediationStep {
	steps := []RemediationStep{}

	// Group findings by severity
	criticalIDs := []string{}
	highIDs := []string{}
	mediumIDs := []string{}

	for _, f := range findings {
		switch f.Severity {
		case "Critical":
			criticalIDs = append(criticalIDs, f.ID)
		case "High":
			highIDs = append(highIDs, f.ID)
		case "Medium":
			mediumIDs = append(mediumIDs, f.ID)
		}
	}

	priority := 1

	if len(criticalIDs) > 0 {
		steps = append(steps, RemediationStep{
			Priority:   priority,
			FindingIDs: criticalIDs,
			Action:     "Immediately address all critical vulnerabilities",
			Effort:     "High",
			Impact:     "Prevents potential system compromise",
			Category:   "Critical",
		})
		priority++
	}

	if len(highIDs) > 0 {
		steps = append(steps, RemediationStep{
			Priority:   priority,
			FindingIDs: highIDs,
			Action:     "Address high severity vulnerabilities within 30 days",
			Effort:     "Medium",
			Impact:     "Reduces attack surface significantly",
			Category:   "High",
		})
		priority++
	}

	if len(mediumIDs) > 0 {
		steps = append(steps, RemediationStep{
			Priority:   priority,
			FindingIDs: mediumIDs,
			Action:     "Schedule remediation for medium severity issues",
			Effort:     "Medium",
			Impact:     "Improves overall security posture",
			Category:   "Medium",
		})
	}

	return steps
}

package modules

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/redteam/agentic-scanner/pkg/payloads"
	"github.com/redteam/agentic-scanner/pkg/utils"
)

// APIModule performs comprehensive API security testing
type APIModule struct {
	httpClient *utils.SecurityHTTPClient
	wsClient   *websocket.Dialer
	timeout    time.Duration
}

// NewAPIModule creates a new APIModule instance
func NewAPIModule() *APIModule {
	return &APIModule{
		timeout: 90 * time.Second,
		wsClient: &websocket.Dialer{
			HandshakeTimeout: 10 * time.Second,
		},
	}
}

// Name returns the module name
func (m *APIModule) Name() string {
	return "api"
}

// Description returns the module description
func (m *APIModule) Description() string {
	return "API Security Testing - REST endpoint discovery, authentication, IDOR, mass assignment, GraphQL introspection, and WebSocket security"
}

// Category returns the module category
func (m *APIModule) Category() string {
	return "api_security"
}

// SupportedTargetTypes returns the target types this module supports
func (m *APIModule) SupportedTargetTypes() []TargetType {
	return []TargetType{TargetTypeAPI, TargetTypeWeb}
}

// Execute runs the API security module
func (m *APIModule) Execute(ctx context.Context, config ModuleConfig) ModuleResult {
	result := ModuleResult{
		Module:    m.Name(),
		Status:    "running",
		StartedAt: time.Now(),
	}

	// Create HTTP client with timeout
	m.httpClient = utils.NewSecurityHTTPClient(10*time.Second, 10)
	m.httpClient.SetRateLimit(10) // 10 requests per second
	defer m.httpClient.Stop()

	// Create context with 90 second timeout
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()

	findings := []Finding{}
	findingsMu := sync.Mutex{}

	// Create channels for goroutines
	findingChan := make(chan Finding, 100)

	// Collect findings from channel
	go func() {
		for finding := range findingChan {
			findingsMu.Lock()
			findings = append(findings, finding)
			findingsMu.Unlock()
		}
	}()

	// Run tests in parallel
	var wg sync.WaitGroup

	// 1. API Documentation Discovery (Swagger/OpenAPI)
	wg.Add(1)
	go func() {
		defer wg.Done()
		m.discoverAPIDocumentation(ctx, config.Target, findingChan)
	}()

	// 2. Common API Endpoint Discovery
	wg.Add(1)
	go func() {
		defer wg.Done()
		m.discoverAPIEndpoints(ctx, config.Target, findingChan)
	}()

	// 3. Parse robots.txt for API paths
	wg.Add(1)
	go func() {
		defer wg.Done()
		m.parseRobotsTxt(ctx, config.Target, findingChan)
	}()

	// 4. Test Authentication
	wg.Add(1)
	go func() {
		defer wg.Done()
		m.testAuthentication(ctx, config.Target, findingChan)
	}()

	// 5. Test Rate Limiting
	wg.Add(1)
	go func() {
		defer wg.Done()
		m.testRateLimiting(ctx, config.Target, findingChan)
	}()

	// 6. Test Error Handling
	wg.Add(1)
	go func() {
		defer wg.Done()
		m.testErrorHandling(ctx, config.Target, findingChan)
	}()

	// 7. GraphQL Security Testing
	wg.Add(1)
	go func() {
		defer wg.Done()
		m.testGraphQLSecurity(ctx, config.Target, findingChan)
	}()

	// 8. WebSocket Security Testing
	wg.Add(1)
	go func() {
		defer wg.Done()
		m.testWebSocketSecurity(ctx, config.Target, findingChan)
	}()

	// Wait for all tests to complete or context cancellation
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(findingChan)
		close(done)
	}()

	select {
	case <-done:
		// All tests completed
	case <-ctx.Done():
		// Context cancelled or timeout
		result.Error = ctx.Err().Error()
	}

	result.Findings = findings
	result.Status = "completed"
	now := time.Now()
	result.EndedAt = &now

	return result
}

// discoverAPIDocumentation searches for Swagger/OpenAPI documentation
func (m *APIModule) discoverAPIDocumentation(ctx context.Context, target string, findingChan chan<- Finding) {
	for _, path := range payloads.OpenAPIPaths {
		select {
		case <-ctx.Done():
			return
		default:
		}

		testURL := target + path
		resp, err := m.httpClient.Get(testURL, nil)
		if err != nil {
			continue
		}

		if resp.StatusCode == 200 {
			bodyStr := string(resp.Body)

			// Check if it's valid Swagger/OpenAPI
			isSwagger := strings.Contains(bodyStr, `"swagger"`) ||
				strings.Contains(bodyStr, `"openapi"`) ||
				strings.Contains(bodyStr, "Swagger UI") ||
				strings.Contains(bodyStr, `"paths"`)

			if isSwagger && len(resp.Body) > 100 {
				docType := "API Documentation"
				if strings.Contains(path, "swagger") {
					docType = "Swagger"
				} else if strings.Contains(path, "openapi") {
					docType = "OpenAPI"
				}

				evidence := FindingEvidence{
					Request:  resp.RawRequest,
					Response: resp.RawResponse,
					URL:      testURL,
				}

				finding := CreateOpenAPIExposureFinding(m.Name(), testURL, docType, evidence)
				findingChan <- finding
			}
		}
	}
}

// discoverAPIEndpoints brute-forces common API endpoints
func (m *APIModule) discoverAPIEndpoints(ctx context.Context, target string, findingChan chan<- Finding) {
	// Limit concurrent requests
	semaphore := make(chan struct{}, 50)
	var wg sync.WaitGroup

	for _, endpoint := range payloads.CommonAPIEndpoints {
		select {
		case <-ctx.Done():
			wg.Wait()
			return
		default:
		}

		wg.Add(1)
		semaphore <- struct{}{}

		go func(ep string) {
			defer wg.Done()
			defer func() { <-semaphore }()

			testURL := target + ep
			resp, err := m.httpClient.Get(testURL, nil)
			if err != nil {
				return
			}

			// Flag interesting responses
			if resp.StatusCode == 200 || resp.StatusCode == 201 {
				bodyStr := string(resp.Body)
				// Check if it's a real API response (JSON)
				if strings.HasPrefix(bodyStr, "{") || strings.HasPrefix(bodyStr, "[") {
					evidence := FindingEvidence{
						Request:  resp.RawRequest,
						Response: resp.RawResponse,
						URL:      testURL,
					}

					endpointType := "api"
					if strings.Contains(ep, "admin") {
						endpointType = "admin"
					} else if strings.Contains(ep, "internal") {
						endpointType = "internal"
					}

					finding := CreateAPIDiscoveryFinding(m.Name(), testURL, endpointType, evidence)
					findingChan <- finding

					// Test for IDOR on discovered endpoints
					m.testIDOR(ctx, testURL, findingChan)
					// Test for mass assignment
					m.testMassAssignment(ctx, testURL, findingChan)
					// Test HTTP verb tampering
					m.testHTTPVerbTampering(ctx, testURL, findingChan)
				}
			} else if resp.StatusCode == 401 {
				// Protected endpoint - still worth noting
				evidence := FindingEvidence{
					Request:  resp.RawRequest,
					Response: resp.RawResponse,
					URL:      testURL,
					Details: map[string]interface{}{
						"note": "Endpoint requires authentication",
					},
				}
				finding := CreateAPIDiscoveryFinding(m.Name(), testURL, "protected", evidence)
				finding.Severity = SeverityLow
				findingChan <- finding
			}
		}(endpoint)
	}

	wg.Wait()
}

// parseRobotsTxt parses robots.txt for API paths
func (m *APIModule) parseRobotsTxt(ctx context.Context, target string, findingChan chan<- Finding) {
	robotsURL := target + "/robots.txt"
	resp, err := m.httpClient.Get(robotsURL, nil)
	if err != nil || resp.StatusCode != 200 {
		return
	}

	bodyStr := string(resp.Body)
	if !strings.Contains(bodyStr, "User-agent") {
		return
	}

	// Parse Disallow entries for API paths
	apiPattern := regexp.MustCompile(`(?i)^Disallow:\s*(/api/.*)$`)
	scanner := bufio.NewScanner(strings.NewReader(bodyStr))

	for scanner.Scan() {
		line := scanner.Text()
		matches := apiPattern.FindStringSubmatch(line)
		if len(matches) > 1 {
			apiPath := matches[1]
			evidence := FindingEvidence{
				URL:     robotsURL,
				Snippet: line,
				Details: map[string]interface{}{
					"path": apiPath,
				},
			}
			finding := CreateAPIDiscoveryFinding(m.Name(), target+apiPath, "api-from-robots", evidence)
			finding.Severity = SeverityInfo
			findingChan <- finding
		}
	}
}

// testIDOR tests for IDOR vulnerabilities
func (m *APIModule) testIDOR(ctx context.Context, endpoint string, findingChan chan<- Finding) {
	// Check if endpoint has a numeric ID pattern
	idPattern := regexp.MustCompile(`(/\d+)(?:/|$)`)
	if !idPattern.MatchString(endpoint) {
		return
	}

	originalID := idPattern.FindString(endpoint)
	baseURL := idPattern.ReplaceAllString(endpoint, "/")

	for _, testID := range payloads.IDORTestValues {
		select {
		case <-ctx.Done():
			return
		default:
		}

		testURL := baseURL + testID
		resp, err := m.httpClient.Get(testURL, nil)
		if err != nil {
			continue
		}

		// If we get a successful response with a different ID, potential IDOR
		if resp.StatusCode == 200 && testID != originalID {
			bodyStr := string(resp.Body)
			// Check if response looks like valid data
			if len(bodyStr) > 50 && (strings.Contains(bodyStr, "id") ||
				strings.Contains(bodyStr, "name") ||
				strings.Contains(bodyStr, "email")) {
				evidence := FindingEvidence{
					Request:  resp.RawRequest,
					Response: resp.RawResponse,
					URL:      testURL,
				}
				finding := CreateIDORFinding(m.Name(), endpoint, originalID, testID, evidence)
				findingChan <- finding
				return // Report once per endpoint
			}
		}
	}
}

// testMassAssignment tests for mass assignment vulnerabilities
func (m *APIModule) testMassAssignment(ctx context.Context, endpoint string, findingChan chan<- Finding) {
	select {
	case <-ctx.Done():
		return
	default:
	}

	// Test with various mass assignment fields
	testData := map[string]interface{}{
		"name":  "test",
		"email": "test@test.com",
	}

	for _, field := range payloads.MassAssignmentFields {
		testData[field] = true
	}

	jsonData, _ := json.Marshal(testData)
	headers := map[string]string{
		"Content-Type": "application/json",
	}

	// Try POST
	resp, err := m.httpClient.Post(endpoint, headers, jsonData)
	if err != nil {
		return
	}

	// Check if response indicates the field was accepted
	if resp.StatusCode == 200 || resp.StatusCode == 201 {
		bodyStr := string(resp.Body)
		for _, field := range payloads.MassAssignmentFields[:10] { // Check first 10 fields
			if strings.Contains(bodyStr, fmt.Sprintf(`"%s"`, field)) ||
				strings.Contains(bodyStr, fmt.Sprintf(`"%s":true`, field)) {
				evidence := FindingEvidence{
					Request:  resp.RawRequest,
					Response: resp.RawResponse,
					URL:      endpoint,
					Payload:  string(jsonData),
				}
				finding := CreateMassAssignmentFinding(m.Name(), endpoint, field, evidence)
				findingChan <- finding
				return
			}
		}
	}
}

// testHTTPVerbTampering tests for HTTP verb tampering vulnerabilities
func (m *APIModule) testHTTPVerbTampering(ctx context.Context, endpoint string, findingChan chan<- Finding) {
	// First test GET
	getResp, err := m.httpClient.Get(endpoint, nil)
	if err != nil {
		return
	}

	if getResp.StatusCode != 200 {
		return
	}

	// Try PUT on what should be a GET endpoint
	putData := []byte(`{"test":"data"}`)
	headers := map[string]string{
		"Content-Type": "application/json",
	}
	putResp, err := m.httpClient.Put(endpoint, headers, putData)
	if err != nil {
		return
	}

	// If PUT succeeds, potential issue
	if putResp.StatusCode == 200 || putResp.StatusCode == 201 || putResp.StatusCode == 204 {
		evidence := FindingEvidence{
			Request:  putResp.RawRequest,
			Response: putResp.RawResponse,
			URL:      endpoint,
		}
		finding := CreateHTTPVerbTamperingFinding(m.Name(), endpoint, "PUT", putResp.StatusCode, evidence)
		findingChan <- finding
	}

	// Try DELETE
	delResp, err := m.httpClient.Delete(endpoint, nil)
	if err != nil {
		return
	}

	if delResp.StatusCode == 200 || delResp.StatusCode == 204 {
		evidence := FindingEvidence{
			Request:  delResp.RawRequest,
			Response: delResp.RawResponse,
			URL:      endpoint,
		}
		finding := CreateHTTPVerbTamperingFinding(m.Name(), endpoint, "DELETE", delResp.StatusCode, evidence)
		findingChan <- finding
	}
}

// testAuthentication tests API authentication mechanisms
func (m *APIModule) testAuthentication(ctx context.Context, target string, findingChan chan<- Finding) {
	// Test common auth endpoints
	authEndpoints := []string{
		"/api/v1/users",
		"/api/v1/admin",
		"/api/v1/config",
	}

	for _, endpoint := range authEndpoints {
		select {
		case <-ctx.Done():
			return
		default:
		}

		testURL := target + endpoint

		// Test without auth
		resp, err := m.httpClient.Get(testURL, nil)
		if err != nil {
			continue
		}

		if resp.StatusCode == 200 {
			// Endpoint accessible without auth
			evidence := FindingEvidence{
				Request:  resp.RawRequest,
				Response: resp.RawResponse,
				URL:      testURL,
			}
			finding := CreateAPIAuthFinding(m.Name(), testURL, "Endpoint accessible without authentication", evidence)
			findingChan <- finding
		}

		// Test with malformed auth headers
		for headerName, headerValues := range payloads.MalformedAuthHeaders {
			for _, headerValue := range headerValues {
				headers := map[string]string{
					headerName: headerValue,
				}
				resp, err := m.httpClient.Get(testURL, headers)
				if err != nil {
					continue
				}

				// If we get a different response, note it
				if resp.StatusCode == 200 {
					evidence := FindingEvidence{
						Request:  resp.RawRequest,
						Response: resp.RawResponse,
						URL:      testURL,
					}
					finding := CreateAPIAuthFinding(m.Name(), testURL,
						fmt.Sprintf("Endpoint accessible with malformed auth header: %s", headerName), evidence)
					finding.Severity = SeverityMedium
					findingChan <- finding
				}
			}
		}
	}
}

// testRateLimiting tests for rate limiting
func (m *APIModule) testRateLimiting(ctx context.Context, target string, findingChan chan<- Finding) {
	testURL := target + "/api/v1/users"

	// First check if endpoint exists
	resp, err := m.httpClient.Get(testURL, nil)
	if err != nil || resp.StatusCode == 404 {
		// Try alternative endpoint
		testURL = target + "/api/users"
		resp, err = m.httpClient.Get(testURL, nil)
		if err != nil || resp.StatusCode == 404 {
			return
		}
	}

	// Send 50 rapid requests
	requestCount := 50
	rateLimited := false
	start := time.Now()

	for i := 0; i < requestCount; i++ {
		select {
		case <-ctx.Done():
			return
		default:
		}

		resp, err := m.httpClient.Get(testURL, nil)
		if err != nil {
			continue
		}

		// Check for rate limit response
		if resp.StatusCode == 429 {
			rateLimited = true
			break
		}
	}

	elapsed := time.Since(start)

	if !rateLimited {
		evidence := FindingEvidence{
			URL: testURL,
			Details: map[string]interface{}{
				"requests_sent":  requestCount,
				"time_window_ms": elapsed.Milliseconds(),
				"rate_limited":   false,
			},
		}
		finding := CreateAPIRateLimitFinding(m.Name(), testURL, requestCount, elapsed, evidence)
		findingChan <- finding
	}
}

// testErrorHandling tests for verbose error messages
func (m *APIModule) testErrorHandling(ctx context.Context, target string, findingChan chan<- Finding) {
	testURL := target + "/api/v1/users"

	for _, malformedBody := range payloads.MalformedJSONBodies {
		select {
		case <-ctx.Done():
			return
		default:
		}

		headers := map[string]string{
			"Content-Type": "application/json",
		}
		resp, err := m.httpClient.Post(testURL, headers, []byte(malformedBody))
		if err != nil {
			continue
		}

		// Check for verbose error messages
		if resp.StatusCode >= 400 && resp.StatusCode < 500 {
			bodyStr := string(resp.Body)

			verboseIndicators := []string{
				"stack trace",
				"exception",
				"at ",
				".go:",
				"Traceback",
				"File \"",
				"line ",
				"column ",
				"sql",
				"database",
				"syntax error",
			}

			for _, indicator := range verboseIndicators {
				if strings.Contains(strings.ToLower(bodyStr), strings.ToLower(indicator)) {
					evidence := FindingEvidence{
						Request:  resp.RawRequest,
						Response: resp.RawResponse,
						URL:      testURL,
						Payload:  malformedBody,
					}
					finding := CreateAPIVerboseErrorFinding(m.Name(), testURL,
						fmt.Sprintf("Verbose error containing '%s'", indicator), evidence)
					findingChan <- finding
					return
				}
			}
		}
	}
}

// testGraphQLSecurity tests GraphQL endpoints for security issues
func (m *APIModule) testGraphQLSecurity(ctx context.Context, target string, findingChan chan<- Finding) {
	// Common GraphQL endpoints
	graphqlEndpoints := []string{
		"/graphql",
		"/api/graphql",
		"/v1/graphql",
		"/query",
		"/api/query",
	}

	for _, endpoint := range graphqlEndpoints {
		select {
		case <-ctx.Done():
			return
		default:
		}

		graphqlURL := target + endpoint

		// Test if endpoint is GraphQL
		resp, err := m.httpClient.Post(graphqlURL,
			map[string]string{"Content-Type": "application/json"},
			[]byte(`{"query":"{__typename}"}`))
		if err != nil {
			continue
		}

		if !utils.IsValidGraphQLEndpoint(&utils.HTTPResponse{
			StatusCode: resp.StatusCode,
			Headers:    resp.Headers,
			Body:       resp.Body,
		}) {
			continue
		}

		// Create GraphQL client
		client := utils.NewGraphQLClient(graphqlURL, 10*time.Second)

		// Test introspection
		introspectionResult := client.TestIntrospection(ctx, true)
		if introspectionResult.Success {
			evidence := FindingEvidence{
				URL:     graphqlURL,
				Snippet: introspectionResult.RawResponse[:min(len(introspectionResult.RawResponse), 500)],
				Details: map[string]interface{}{
					"types_count":         len(introspectionResult.Types),
					"queries_count":       len(introspectionResult.Queries),
					"mutations_count":     len(introspectionResult.Mutations),
					"subscriptions_count": len(introspectionResult.Subscriptions),
				},
			}
			finding := CreateGraphQLIntrospectionFinding(m.Name(), graphqlURL,
				fmt.Sprintf("Found %d types, %d queries, %d mutations",
					len(introspectionResult.Types),
					len(introspectionResult.Queries),
					len(introspectionResult.Mutations)), evidence)
			findingChan <- finding
		}

		// Test query depth limit
		maxDepth, hasLimit := client.TestQueryDepth(ctx, 20)
		if !hasLimit && maxDepth >= 15 {
			evidence := FindingEvidence{
				URL: graphqlURL,
				Details: map[string]interface{}{
					"max_depth_tested": maxDepth,
					"depth_limit":      hasLimit,
				},
			}
			finding := CreateGraphQLDepthLimitFinding(m.Name(), graphqlURL, maxDepth, evidence)
			findingChan <- finding
		}

		// Test batch queries
		batchResp, err := client.TestBatchQueries(ctx, 5)
		if err == nil && batchResp.Status == 200 {
			evidence := FindingEvidence{
				URL:      graphqlURL,
				Response: batchResp.Raw,
			}
			finding := CreateGraphQLBatchFinding(m.Name(), graphqlURL, 5, evidence)
			findingChan <- finding
		}

		// Test field suggestions
		if client.TestFieldSuggestions(ctx) {
			evidence := FindingEvidence{
				URL: graphqlURL,
			}
			finding := CreateGraphQLFieldSuggestionFinding(m.Name(), graphqlURL, evidence)
			findingChan <- finding
		}

		// Test for injection vulnerabilities
		for _, payload := range payloads.GraphQLInjectionPayloads {
			resp, err := client.Execute(ctx,
				fmt.Sprintf(`{ search(query: "%s") { id } }`, payload), nil)
			if err != nil {
				continue
			}

			if found, errorMsg := utils.IsGraphQLInjectionError(resp); found {
				evidence := FindingEvidence{
					URL:     graphqlURL,
					Snippet: errorMsg,
					Payload: payload,
				}
				finding := CreateGraphQLInjectionFinding(m.Name(), graphqlURL, payload, errorMsg, evidence)
				findingChan <- finding
				break
			}
		}
	}
}

// testWebSocketSecurity tests WebSocket endpoints for security issues
func (m *APIModule) testWebSocketSecurity(ctx context.Context, target string, findingChan chan<- Finding) {
	// Convert HTTP to WS
	parsedURL, err := url.Parse(target)
	if err != nil {
		return
	}

	wsScheme := "ws"
	if parsedURL.Scheme == "https" {
		wsScheme = "wss"
	}

	// Common WebSocket endpoints
	wsEndpoints := []string{
		"/ws",
		"/websocket",
		"/socket",
		"/api/ws",
		"/ws/v1",
	}

	for _, endpoint := range wsEndpoints {
		select {
		case <-ctx.Done():
			return
		default:
		}

		wsURL := wsScheme + "://" + parsedURL.Host + endpoint
		tester := utils.NewWebSocketTester(10 * time.Second)

		// Test basic connection
		result := tester.TestConnection(ctx, wsURL, nil)
		if !result.Connected {
			continue
		}

		// Connection successful - check origin validation
		hasOriginValidation, _ := tester.TestOriginValidation(ctx, wsURL)
		if !hasOriginValidation {
			evidence := FindingEvidence{
				URL: wsURL,
				Details: map[string]interface{}{
					"origin_validation": false,
				},
			}
			finding := CreateWebSocketOriginFinding(m.Name(), wsURL, evidence)
			findingChan <- finding
		}

		// Test authentication
		authResult := tester.TestAuthentication(ctx, wsURL)
		if authResult.Connected && !authResult.AuthRequired {
			evidence := FindingEvidence{
				URL: wsURL,
			}
			finding := CreateWebSocketAuthFinding(m.Name(), wsURL, "No authentication required for WebSocket connection", evidence)
			findingChan <- finding
		}

		// Test XSS through WebSocket
		conn, err := tester.Connect(ctx, wsURL, nil)
		if err != nil {
			continue
		}
		defer conn.Close()

		for _, payload := range payloads.WebSocketXSSPayloads {
			reflected, response, err := conn.TestXSSPayload(payload)
			if err != nil {
				continue
			}

			if reflected && strings.Contains(response, payload) {
				evidence := FindingEvidence{
					URL:      wsURL,
					Payload:  payload,
					Response: response,
				}
				finding := CreateWebSocketXSSFinding(m.Name(), wsURL, payload, evidence)
				findingChan <- finding
				break
			}
		}
	}
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

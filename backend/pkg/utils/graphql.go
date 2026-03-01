// Package utils provides GraphQL security testing utilities
package utils

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// GraphQLClient is a client for GraphQL testing
type GraphQLClient struct {
	httpClient *HTTPClient
	endpoint   string
	timeout    time.Duration
}

// GraphQLRequest represents a GraphQL request
type GraphQLRequest struct {
	Query         string                 `json:"query"`
	Variables     map[string]interface{} `json:"variables,omitempty"`
	OperationName string                 `json:"operationName,omitempty"`
}

// GraphQLResponse represents a GraphQL response
type GraphQLResponse struct {
	Data   json.RawMessage `json:"data"`
	Errors []GraphQLError  `json:"errors"`
	Raw    string          `json:"-"`
	Status int             `json:"-"`
}

// GraphQLError represents a GraphQL error
type GraphQLError struct {
	Message    string                 `json:"message"`
	Locations  []GraphQLErrorLocation `json:"locations,omitempty"`
	Path       []interface{}          `json:"path,omitempty"`
	Extensions map[string]interface{} `json:"extensions,omitempty"`
}

// GraphQLErrorLocation represents error location
type GraphQLErrorLocation struct {
	Line   int `json:"line"`
	Column int `json:"column"`
}

// IntrospectionResult contains the result of an introspection query
type IntrospectionResult struct {
	Success       bool                   `json:"success"`
	Schema        map[string]interface{} `json:"schema,omitempty"`
	Types         []GraphQLType          `json:"types,omitempty"`
	Queries       []GraphQLField         `json:"queries,omitempty"`
	Mutations     []GraphQLField         `json:"mutations,omitempty"`
	Subscriptions []GraphQLField         `json:"subscriptions,omitempty"`
	RawResponse   string                 `json:"raw_response,omitempty"`
	Error         string                 `json:"error,omitempty"`
}

// GraphQLType represents a GraphQL type from introspection
type GraphQLType struct {
	Kind        string         `json:"kind"`
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	Fields      []GraphQLField `json:"fields,omitempty"`
}

// GraphQLField represents a GraphQL field
type GraphQLField struct {
	Name        string              `json:"name"`
	Description string              `json:"description,omitempty"`
	Type        GraphQLTypeRef      `json:"type"`
	Args        []GraphQLInputValue `json:"args,omitempty"`
}

// GraphQLTypeRef represents a GraphQL type reference
type GraphQLTypeRef struct {
	Kind   string          `json:"kind"`
	Name   string          `json:"name,omitempty"`
	OfType *GraphQLTypeRef `json:"ofType,omitempty"`
}

// GraphQLInputValue represents a GraphQL input value
type GraphQLInputValue struct {
	Name         string         `json:"name"`
	Description  string         `json:"description,omitempty"`
	Type         GraphQLTypeRef `json:"type"`
	DefaultValue interface{}    `json:"defaultValue,omitempty"`
}

// NewGraphQLClient creates a new GraphQL client
func NewGraphQLClient(endpoint string, timeout time.Duration) *GraphQLClient {
	return &GraphQLClient{
		httpClient: NewHTTPClient(timeout),
		endpoint:   endpoint,
		timeout:    timeout,
	}
}

// SetEndpoint sets the GraphQL endpoint
func (c *GraphQLClient) SetEndpoint(endpoint string) {
	c.endpoint = endpoint
}

// Execute sends a GraphQL query
func (c *GraphQLClient) Execute(ctx context.Context, query string, variables map[string]interface{}) (*GraphQLResponse, error) {
	req := GraphQLRequest{
		Query:     query,
		Variables: variables,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", c.endpoint, bytes.NewBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(ctx, &HTTPRequest{
		Method: "POST",
		URL:    c.endpoint,
		Headers: map[string]string{
			"Content-Type": "application/json",
			"Accept":       "application/json",
		},
		Body: body,
	})
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	graphResp := &GraphQLResponse{
		Raw:    string(resp.Body),
		Status: resp.StatusCode,
	}

	if err := json.Unmarshal(resp.Body, graphResp); err != nil {
		// Not a valid GraphQL response, but might still be useful
		return graphResp, nil
	}

	return graphResp, nil
}

// TestIntrospection tests if introspection is enabled
func (c *GraphQLClient) TestIntrospection(ctx context.Context, full bool) *IntrospectionResult {
	result := &IntrospectionResult{Success: false}

	query := GraphQLIntrospectionQuery
	if full {
		query = GraphQLFullIntrospectionQuery
	}

	resp, err := c.Execute(ctx, query, nil)
	if err != nil {
		result.Error = err.Error()
		return result
	}

	result.RawResponse = resp.Raw

	if resp.Status != 200 {
		result.Error = fmt.Sprintf("HTTP %d", resp.Status)
		return result
	}

	if len(resp.Errors) > 0 {
		result.Error = resp.Errors[0].Message
		return result
	}

	if resp.Data == nil {
		result.Error = "no data in response"
		return result
	}

	// Parse the introspection data
	var data map[string]interface{}
	if err := json.Unmarshal(resp.Data, &data); err != nil {
		result.Error = err.Error()
		return result
	}

	result.Success = true
	result.Schema = data

	// Extract schema information
	if schema, ok := data["__schema"].(map[string]interface{}); ok {
		// Extract types
		if types, ok := schema["types"].([]interface{}); ok {
			for _, t := range types {
				if typeMap, ok := t.(map[string]interface{}); ok {
					result.Types = append(result.Types, parseGraphQLType(typeMap))
				}
			}
		}

		// Extract queries
		if queryType, ok := schema["queryType"].(map[string]interface{}); ok {
			if fields, ok := queryType["fields"].([]interface{}); ok {
				for _, f := range fields {
					if fieldMap, ok := f.(map[string]interface{}); ok {
						result.Queries = append(result.Queries, parseGraphQLField(fieldMap))
					}
				}
			}
		}

		// Extract mutations
		if mutationType, ok := schema["mutationType"].(map[string]interface{}); ok {
			if fields, ok := mutationType["fields"].([]interface{}); ok {
				for _, f := range fields {
					if fieldMap, ok := f.(map[string]interface{}); ok {
						result.Mutations = append(result.Mutations, parseGraphQLField(fieldMap))
					}
				}
			}
		}

		// Extract subscriptions
		if subscriptionType, ok := schema["subscriptionType"].(map[string]interface{}); ok {
			if fields, ok := subscriptionType["fields"].([]interface{}); ok {
				for _, f := range fields {
					if fieldMap, ok := f.(map[string]interface{}); ok {
						result.Subscriptions = append(result.Subscriptions, parseGraphQLField(fieldMap))
					}
				}
			}
		}
	}

	return result
}

// TestTypeName tests if __typename enumeration is possible
func (c *GraphQLClient) TestTypeName(ctx context.Context) bool {
	resp, err := c.Execute(ctx, GraphQLTypeNameQuery, nil)
	if err != nil {
		return false
	}

	if resp.Status != 200 || len(resp.Errors) > 0 {
		return false
	}

	// Check if response contains __typename
	return strings.Contains(resp.Raw, "__typename")
}

// TestQueryDepth tests the maximum allowed query depth
func (c *GraphQLClient) TestQueryDepth(ctx context.Context, maxDepth int) (int, bool) {
	for depth := 1; depth <= maxDepth; depth++ {
		query := generateDeepQuery(depth)
		resp, err := c.Execute(ctx, query, nil)
		if err != nil {
			return depth - 1, false
		}

		if resp.Status != 200 {
			return depth - 1, true
		}

		for _, e := range resp.Errors {
			if isDepthLimitError(e.Message) {
				return depth - 1, true
			}
		}
	}

	return maxDepth, false
}

// TestBatchQueries tests if batch queries are allowed
func (c *GraphQLClient) TestBatchQueries(ctx context.Context, count int) (*GraphQLResponse, error) {
	queries := make([]GraphQLRequest, count)
	for i := 0; i < count; i++ {
		queries[i] = GraphQLRequest{
			Query: "{ __typename }",
		}
	}

	body, err := json.Marshal(queries)
	if err != nil {
		return nil, err
	}

	httpReq := &HTTPRequest{
		Method: "POST",
		URL:    c.endpoint,
		Headers: map[string]string{
			"Content-Type": "application/json",
			"Accept":       "application/json",
		},
		Body: body,
	}

	resp, err := c.httpClient.Do(ctx, httpReq)
	if err != nil {
		return nil, err
	}

	graphResp := &GraphQLResponse{
		Raw:    string(resp.Body),
		Status: resp.StatusCode,
	}

	// Try to parse as array response
	var arrayResp []json.RawMessage
	if err := json.Unmarshal(resp.Body, &arrayResp); err == nil {
		graphResp.Data = arrayResp[0]
	} else {
		json.Unmarshal(resp.Body, graphResp)
	}

	return graphResp, nil
}

// TestFieldSuggestions checks if field suggestions are enabled
func (c *GraphQLClient) TestFieldSuggestions(ctx context.Context) bool {
	// Send a query with a non-existent field
	query := `query { user { nonExistentField123456 } }`
	resp, err := c.Execute(ctx, query, nil)
	if err != nil {
		return false
	}

	if len(resp.Errors) == 0 {
		return false
	}

	// Check if error message suggests similar fields
	errorMsg := strings.ToLower(resp.Errors[0].Message)
	suggestionKeywords := []string{
		"did you mean",
		"suggest",
		"similar",
		"available",
		"field",
		"try",
	}

	for _, keyword := range suggestionKeywords {
		if strings.Contains(errorMsg, keyword) {
			return true
		}
	}

	return false
}

// IsGraphQLInjectionError checks if an error indicates potential injection vulnerability
func IsGraphQLInjectionError(response *GraphQLResponse) (bool, string) {
	if response == nil || len(response.Errors) == 0 {
		return false, ""
	}

	sqlErrorPatterns := []string{
		"sql",
		"syntax",
		"database",
		"mysql",
		"postgres",
		"sqlite",
		"mongodb",
		"query failed",
		"execution error",
	}

	for _, err := range response.Errors {
		errMsg := strings.ToLower(err.Message)
		for _, pattern := range sqlErrorPatterns {
			if strings.Contains(errMsg, pattern) {
				return true, err.Message
			}
		}
	}

	return false, ""
}

// CalculateQueryDepth calculates the depth of a GraphQL query
func CalculateQueryDepth(query string) int {
	depth := 0
	maxDepth := 0
	inString := false
	stringChar := rune(0)

	for _, char := range query {
		switch char {
		case '"', '\'':
			if !inString {
				inString = true
				stringChar = char
			} else if char == stringChar {
				inString = false
			}
		case '{', '(':
			if !inString {
				depth++
				if depth > maxDepth {
					maxDepth = depth
				}
			}
		case '}', ')':
			if !inString && depth > 0 {
				depth--
			}
		}
	}

	return maxDepth
}

// IsValidGraphQLEndpoint checks if an endpoint appears to be GraphQL
func IsValidGraphQLEndpoint(resp *HTTPResponse) bool {
	// Check content type
	contentType := strings.ToLower(resp.Headers.Get("Content-Type"))
	if strings.Contains(contentType, "application/graphql") {
		return true
	}

	// Check if body contains GraphQL-specific content
	body := string(resp.Body)
	graphqlIndicators := []string{
		`"data":`,
		`"errors":`,
		`__schema`,
		`__typename`,
		`"query"`,
		`"mutation"`,
		`GraphQL`,
	}

	for _, indicator := range graphqlIndicators {
		if strings.Contains(body, indicator) {
			return true
		}
	}

	return false
}

// GraphQLIntrospectionQuery is the standard introspection query
var GraphQLIntrospectionQuery = `
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      name
      kind
      fields {
        name
        type {
          name
          kind
        }
      }
    }
  }
}`

// GraphQLFullIntrospectionQuery is a more complete introspection query
var GraphQLFullIntrospectionQuery = `
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      ...FullType
    }
    directives {
      name
      description
      locations
      args {
        ...InputValue
      }
    }
  }
}

fragment FullType on __Type {
  kind
  name
  description
  fields(includeDeprecated: true) {
    name
    description
    args {
      ...InputValue
    }
    type {
      ...TypeRef
    }
    isDeprecated
    deprecationReason
  }
  inputFields {
    ...InputValue
  }
  interfaces {
    ...TypeRef
  }
  enumValues(includeDeprecated: true) {
    name
    description
    isDeprecated
    deprecationReason
  }
  possibleTypes {
    ...TypeRef
  }
}

fragment InputValue on __InputValue {
  name
  description
  type { ...TypeRef }
  defaultValue
}

fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
              }
            }
          }
        }
      }
    }
  }
}`

// GraphQLTypeNameQuery tests if typename enumeration is possible
var GraphQLTypeNameQuery = `
query {
  __typename
}`

// generateDeepQuery generates a deeply nested query
func generateDeepQuery(depth int) string {
	if depth <= 0 {
		return "{ __typename }"
	}

	var builder strings.Builder
	builder.WriteString("{")
	for i := 0; i < depth; i++ {
		builder.WriteString(" user {")
	}
	builder.WriteString(" id")
	for i := 0; i < depth; i++ {
		builder.WriteString(" }")
	}
	builder.WriteString(" }")
	return builder.String()
}

// isDepthLimitError checks if an error message indicates depth limit
func isDepthLimitError(message string) bool {
	depthLimitPatterns := []string{
		"depth",
		"too deep",
		"nested",
		"complexity",
		"max",
		"limit",
	}

	messageLower := strings.ToLower(message)
	for _, pattern := range depthLimitPatterns {
		if strings.Contains(messageLower, pattern) {
			return true
		}
	}

	return false
}

// parseGraphQLType parses a GraphQL type from map
func parseGraphQLType(data map[string]interface{}) GraphQLType {
	t := GraphQLType{}

	if name, ok := data["name"].(string); ok {
		t.Name = name
	}
	if kind, ok := data["kind"].(string); ok {
		t.Kind = kind
	}
	if desc, ok := data["description"].(string); ok {
		t.Description = desc
	}

	return t
}

// parseGraphQLField parses a GraphQL field from map
func parseGraphQLField(data map[string]interface{}) GraphQLField {
	f := GraphQLField{}

	if name, ok := data["name"].(string); ok {
		f.Name = name
	}
	if desc, ok := data["description"].(string); ok {
		f.Description = desc
	}

	return f
}

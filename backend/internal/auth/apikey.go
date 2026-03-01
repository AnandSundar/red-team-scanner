package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// ============================================================================
// API Key Constants
// ============================================================================

const (
	// APIKeyPrefix is the prefix for all API keys
	APIKeyPrefix = "rt_"
	// APIKeyLength is the length of the random part of the API key (before base64 encoding)
	APIKeyRandomLength = 48
	// APIKeyFullLength is the expected length of a full API key (including prefix)
	APIKeyFullLength = 68 // len("rt_") + base64 encoding of 48 bytes
	// BcryptCost is the cost factor for bcrypt hashing
	BcryptCost = 12
)

// ============================================================================
// API Key Generation
// ============================================================================

// GenerateAPIKey generates a new secure API key
// Returns the full API key (to be shown once to the user) and the hash (to be stored)
func GenerateAPIKey() (string, string, error) {
	// Generate random bytes
	randomBytes := make([]byte, APIKeyRandomLength)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	// Encode to base64 URL-safe encoding (no padding)
	randomPart := base64.RawURLEncoding.EncodeToString(randomBytes)

	// Create full API key with prefix
	fullKey := APIKeyPrefix + randomPart

	// Hash the key using bcrypt
	hash, err := bcrypt.GenerateFromPassword([]byte(fullKey), BcryptCost)
	if err != nil {
		return "", "", fmt.Errorf("failed to hash API key: %w", err)
	}

	return fullKey, string(hash), nil
}

// GenerateAPIKeyWithPrefix generates an API key with a custom prefix
func GenerateAPIKeyWithPrefix(prefix string) (string, string, error) {
	// Validate prefix
	if prefix == "" {
		prefix = APIKeyPrefix
	}
	if !strings.HasSuffix(prefix, "_") {
		prefix += "_"
	}

	// Generate random bytes
	randomBytes := make([]byte, APIKeyRandomLength)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	// Encode to base64 URL-safe encoding (no padding)
	randomPart := base64.RawURLEncoding.EncodeToString(randomBytes)

	// Create full API key with custom prefix
	fullKey := prefix + randomPart

	// Hash the key using bcrypt
	hash, err := bcrypt.GenerateFromPassword([]byte(fullKey), BcryptCost)
	if err != nil {
		return "", "", fmt.Errorf("failed to hash API key: %w", err)
	}

	return fullKey, string(hash), nil
}

// ============================================================================
// API Key Validation
// ============================================================================

// ValidateAPIKey validates an API key against a stored hash
func ValidateAPIKey(apiKey, hash string) error {
	// Check prefix
	if !strings.HasPrefix(apiKey, APIKeyPrefix) {
		return fmt.Errorf("invalid API key format: wrong prefix")
	}

	// Check length
	if len(apiKey) < len(APIKeyPrefix)+10 {
		return fmt.Errorf("invalid API key format: too short")
	}

	// Compare with bcrypt hash
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(apiKey)); err != nil {
		return fmt.Errorf("invalid API key: %w", err)
	}

	return nil
}

// ValidateAPIKeyWithCustomPrefix validates an API key with a custom prefix
func ValidateAPIKeyWithCustomPrefix(apiKey, hash, prefix string) error {
	// Validate prefix
	if prefix == "" {
		prefix = APIKeyPrefix
	}

	// Check prefix
	if !strings.HasPrefix(apiKey, prefix) {
		return fmt.Errorf("invalid API key format: wrong prefix")
	}

	// Compare with bcrypt hash
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(apiKey)); err != nil {
		return fmt.Errorf("invalid API key: %w", err)
	}

	return nil
}

// ============================================================================
// API Key Format Validation
// ============================================================================

// IsValidAPIKeyFormat checks if an API key has valid format (without validating against a hash)
func IsValidAPIKeyFormat(apiKey string) bool {
	// Check prefix
	if !strings.HasPrefix(apiKey, APIKeyPrefix) {
		return false
	}

	// Check length (at least prefix + some random part)
	if len(apiKey) < len(APIKeyPrefix)+10 {
		return false
	}

	// Check for valid base64 characters
	randomPart := apiKey[len(APIKeyPrefix):]
	for _, c := range randomPart {
		if !isBase64URLChar(c) {
			return false
		}
	}

	return true
}

// isBase64URLChar checks if a character is valid for base64 URL encoding
func isBase64URLChar(c rune) bool {
	return (c >= 'A' && c <= 'Z') ||
		(c >= 'a' && c <= 'z') ||
		(c >= '0' && c <= '9') ||
		c == '-' || c == '_'
}

// ============================================================================
// API Key Masking
// ============================================================================

// MaskAPIKey masks an API key for display (shows only first and last few characters)
func MaskAPIKey(apiKey string) string {
	if len(apiKey) <= 12 {
		return "***"
	}

	return apiKey[:6] + "..." + apiKey[len(apiKey)-6:]
}

// MaskAPIKeyHash masks a stored hash (for logging, etc.)
func MaskAPIKeyHash(hash string) string {
	if len(hash) <= 20 {
		return "***"
	}

	return hash[:10] + "..." + hash[len(hash)-10:]
}

// ============================================================================
// API Key Manager
// ============================================================================

// APIKeyManager manages API key operations
type APIKeyManager struct {
	store APIKeyStore
}

// NewAPIKeyManager creates a new API key manager
func NewAPIKeyManager(store APIKeyStore) *APIKeyManager {
	return &APIKeyManager{store: store}
}

// GenerateAndStore generates a new API key and stores it (returns the plain key to user)
func (m *APIKeyManager) GenerateAndStore(ctx context.Context, userID string) (*APIKeyResult, error) {
	// Generate new API key
	plainKey, hash, err := GenerateAPIKey()
	if err != nil {
		return nil, err
	}

	// Store the hash (implementation depends on store interface)
	// This would typically update the user's API key in the database
	// store.UpdateUserAPIKey(userID, hash)

	return &APIKeyResult{
		PlainKey:  plainKey,
		Hash:      hash,
		MaskedKey: MaskAPIKey(plainKey),
		CreatedAt: time.Now(),
	}, nil
}

// Validate validates an API key and returns the associated user
func (m *APIKeyManager) Validate(ctx context.Context, apiKey string) (*User, error) {
	if !IsValidAPIKeyFormat(apiKey) {
		return nil, fmt.Errorf("invalid API key format")
	}

	// Get user by API key from store
	// The store should implement a method to look up user by API key hash
	user, err := m.store.GetUserByAPIKey(ctx, apiKey)
	if err != nil {
		return nil, fmt.Errorf("invalid API key: %w", err)
	}

	return user, nil
}

// Revoke revokes an API key for a user
func (m *APIKeyManager) Revoke(ctx context.Context, userID string) error {
	// Implementation depends on store interface
	// This would typically set the user's API key to null in the database
	return nil
}

// ============================================================================
// API Key Result
// ============================================================================

// APIKeyResult contains the result of generating an API key
type APIKeyResult struct {
	PlainKey  string    `json:"plain_key"`
	Hash      string    `json:"-"` // Never expose this
	MaskedKey string    `json:"masked_key"`
	CreatedAt time.Time `json:"created_at"`
}

// ToResponse converts the result to a response structure (without sensitive data)
func (r *APIKeyResult) ToResponse() map[string]interface{} {
	return map[string]interface{}{
		"api_key":    r.PlainKey, // Only returned once at creation
		"masked_key": r.MaskedKey,
		"created_at": r.CreatedAt,
		"message":    "Store this API key securely. It will not be shown again.",
	}
}

// ============================================================================
// Rate Limiting per API Key
// ============================================================================

// APIKeyRateLimiter handles rate limiting for API keys
type APIKeyRateLimiter struct {
	requests map[string]*APIKeyRequestInfo
	mu       sync.RWMutex
}

// APIKeyRequestInfo tracks request info for an API key
type APIKeyRequestInfo struct {
	Requests    int
	WindowStart time.Time
	LastRequest time.Time
}

// NewAPIKeyRateLimiter creates a new API key rate limiter
func NewAPIKeyRateLimiter() *APIKeyRateLimiter {
	return &APIKeyRateLimiter{
		requests: make(map[string]*APIKeyRequestInfo),
	}
}

// CheckLimit checks if an API key has exceeded its rate limit
func (rl *APIKeyRateLimiter) CheckLimit(apiKey string, limit RateLimit) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	info, exists := rl.requests[apiKey]

	// Reset window if needed (per minute)
	if !exists || now.Sub(info.WindowStart) > time.Minute {
		rl.requests[apiKey] = &APIKeyRequestInfo{
			Requests:    1,
			WindowStart: now,
			LastRequest: now,
		}
		return true
	}

	// Check limit
	if info.Requests >= limit.RequestsPerMinute {
		return false
	}

	// Increment counter
	info.Requests++
	info.LastRequest = now

	return true
}

// Cleanup removes old entries from the rate limiter
func (rl *APIKeyRateLimiter) Cleanup(maxAge time.Duration) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	for key, info := range rl.requests {
		if now.Sub(info.LastRequest) > maxAge {
			delete(rl.requests, key)
		}
	}
}

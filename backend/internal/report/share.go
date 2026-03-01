package report

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
)

// ============================================================================
// Share Token Management
// ============================================================================

const (
	// DefaultShareExpiration is the default duration for share links (30 days)
	DefaultShareExpiration = 30 * 24 * time.Hour

	// MinTokenLength is the minimum length for share tokens
	MinTokenLength = 32

	// MaxTokenLength is the maximum length for share tokens
	MaxTokenLength = 64
)

// ShareToken represents a share token with metadata
type ShareToken struct {
	Token       string     `json:"token"`
	ReportID    uuid.UUID  `json:"report_id"`
	CreatedAt   time.Time  `json:"created_at"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	AccessCount int64      `json:"access_count,omitempty"`
}

// ShareLink represents a complete share link response
type ShareLink struct {
	ShareToken string     `json:"share_token"`
	ShareURL   string     `json:"share_url"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
}

// TokenGenerator generates secure share tokens
type TokenGenerator struct {
	baseURL string
}

// NewTokenGenerator creates a new token generator
func NewTokenGenerator(baseURL string) *TokenGenerator {
	if baseURL == "" {
		baseURL = os.Getenv("APP_BASE_URL")
		if baseURL == "" {
			baseURL = "https://app.redteam.dev"
		}
	}
	return &TokenGenerator{
		baseURL: strings.TrimSuffix(baseURL, "/"),
	}
}

// GenerateToken generates a cryptographically secure random token
func (tg *TokenGenerator) GenerateToken() (string, error) {
	// Generate 32 bytes of random data
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random token: %w", err)
	}

	// Encode to URL-safe base64
	token := base64.URLEncoding.EncodeToString(bytes)

	// Remove padding and ensure minimum length
	token = strings.TrimRight(token, "=")

	return token, nil
}

// GenerateTokenHex generates a hex-encoded random token
func (tg *TokenGenerator) GenerateTokenHex() (string, error) {
	// Generate 32 bytes of random data
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random token: %w", err)
	}

	// Encode to hex
	return hex.EncodeToString(bytes), nil
}

// GenerateTokenWithLength generates a token with a specific length
func (tg *TokenGenerator) GenerateTokenWithLength(length int) (string, error) {
	if length < MinTokenLength {
		length = MinTokenLength
	}
	if length > MaxTokenLength {
		length = MaxTokenLength
	}

	// Calculate bytes needed for the desired length
	// Base64 encoding expands by ~4/3, so we need length * 3/4 bytes
	bytesNeeded := (length * 3) / 4
	if bytesNeeded < 16 {
		bytesNeeded = 16
	}

	bytes := make([]byte, bytesNeeded)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random token: %w", err)
	}

	token := base64.URLEncoding.EncodeToString(bytes)
	token = strings.TrimRight(token, "=")

	// Truncate to desired length if longer
	if len(token) > length {
		token = token[:length]
	}

	return token, nil
}

// CreateShareLink creates a complete share link with token
func (tg *TokenGenerator) CreateShareLink(reportID uuid.UUID, expiresIn time.Duration) (*ShareLink, error) {
	token, err := tg.GenerateToken()
	if err != nil {
		return nil, err
	}

	var expiresAt *time.Time
	if expiresIn > 0 {
		t := time.Now().UTC().Add(expiresIn)
		expiresAt = &t
	}

	shareURL := fmt.Sprintf("%s/share/%s", tg.baseURL, token)

	return &ShareLink{
		ShareToken: token,
		ShareURL:   shareURL,
		ExpiresAt:  expiresAt,
	}, nil
}

// CreateShareLinkWithDays creates a share link with expiration in days
func (tg *TokenGenerator) CreateShareLinkWithDays(reportID uuid.UUID, days int) (*ShareLink, error) {
	expiresIn := time.Duration(days) * 24 * time.Hour
	if days <= 0 {
		expiresIn = DefaultShareExpiration
	}
	return tg.CreateShareLink(reportID, expiresIn)
}

// ValidateToken validates a share token format
func (tg *TokenGenerator) ValidateToken(token string) error {
	if token == "" {
		return fmt.Errorf("token cannot be empty")
	}

	if len(token) < MinTokenLength {
		return fmt.Errorf("token too short: minimum %d characters required", MinTokenLength)
	}

	// Check for valid URL-safe base64 characters
	validChars := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	for _, char := range token {
		if !strings.ContainsRune(validChars, char) {
			return fmt.Errorf("token contains invalid characters")
		}
	}

	return nil
}

// ExtractTokenFromURL extracts the token from a share URL
func (tg *TokenGenerator) ExtractTokenFromURL(shareURL string) (string, error) {
	// Remove base URL prefix if present
	shareURL = strings.TrimSpace(shareURL)

	// Handle different URL formats
	if strings.HasPrefix(shareURL, tg.baseURL) {
		shareURL = strings.TrimPrefix(shareURL, tg.baseURL)
	}

	// Remove leading slash
	shareURL = strings.TrimPrefix(shareURL, "/")

	// Extract token from /share/{token} format
	if strings.HasPrefix(shareURL, "share/") {
		return strings.TrimPrefix(shareURL, "share/"), nil
	}

	// If it's just the token, return it
	if !strings.Contains(shareURL, "/") {
		return shareURL, nil
	}

	return "", fmt.Errorf("invalid share URL format")
}

// FormatShareURL formats a share URL with the base URL
func (tg *TokenGenerator) FormatShareURL(token string) string {
	return fmt.Sprintf("%s/share/%s", tg.baseURL, token)
}

// IsTokenExpired checks if a token has expired
func IsTokenExpired(expiresAt *time.Time) bool {
	if expiresAt == nil {
		return false // No expiration means never expires
	}
	return time.Now().UTC().After(*expiresAt)
}

// GetTokenExpirationDays returns the number of days until expiration
func GetTokenExpirationDays(expiresAt *time.Time) int {
	if expiresAt == nil {
		return -1 // Never expires
	}

	diff := expiresAt.Sub(time.Now().UTC())
	if diff <= 0 {
		return 0
	}
	return int(diff.Hours() / 24)
}

// ============================================================================
// Share Token Store (for in-memory caching)
// ============================================================================

// TokenStore provides storage for share tokens
type TokenStore interface {
	Store(token ShareToken) error
	Get(token string) (*ShareToken, error)
	Delete(token string) error
	IncrementAccessCount(token string) error
}

// MemoryTokenStore is an in-memory token store
type MemoryTokenStore struct {
	tokens map[string]ShareToken
}

// NewMemoryTokenStore creates a new in-memory token store
func NewMemoryTokenStore() *MemoryTokenStore {
	return &MemoryTokenStore{
		tokens: make(map[string]ShareToken),
	}
}

// Store stores a token
func (s *MemoryTokenStore) Store(token ShareToken) error {
	s.tokens[token.Token] = token
	return nil
}

// Get retrieves a token
func (s *MemoryTokenStore) Get(token string) (*ShareToken, error) {
	t, ok := s.tokens[token]
	if !ok {
		return nil, fmt.Errorf("token not found")
	}

	// Check if expired
	if IsTokenExpired(t.ExpiresAt) {
		delete(s.tokens, token)
		return nil, fmt.Errorf("token expired")
	}

	return &t, nil
}

// Delete deletes a token
func (s *MemoryTokenStore) Delete(token string) error {
	delete(s.tokens, token)
	return nil
}

// IncrementAccessCount increments the access count for a token
func (s *MemoryTokenStore) IncrementAccessCount(token string) error {
	t, ok := s.tokens[token]
	if !ok {
		return fmt.Errorf("token not found")
	}
	t.AccessCount++
	s.tokens[token] = t
	return nil
}

// ============================================================================
// Share Token Helper Functions
// ============================================================================

// GenerateShareToken is a convenience function to generate a share token
func GenerateShareToken() (string, error) {
	tg := NewTokenGenerator("")
	return tg.GenerateToken()
}

// GenerateShareTokenHex is a convenience function to generate a hex token
func GenerateShareTokenHex() (string, error) {
	tg := NewTokenGenerator("")
	return tg.GenerateTokenHex()
}

// ValidateShareToken is a convenience function to validate a share token
func ValidateShareToken(token string) error {
	tg := NewTokenGenerator("")
	return tg.ValidateToken(token)
}

// CalculateShareExpiration calculates the expiration time from now
func CalculateShareExpiration(days int) time.Time {
	if days <= 0 {
		days = 30 // Default to 30 days
	}
	return time.Now().UTC().Add(time.Duration(days) * 24 * time.Hour)
}

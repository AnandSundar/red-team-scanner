// Package billing provides Stripe billing integration for subscription management
package billing

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/stripe/stripe-go/v74"
	billingportal "github.com/stripe/stripe-go/v74/billingportal/session"
	checkoutsession "github.com/stripe/stripe-go/v74/checkout/session"
	"github.com/stripe/stripe-go/v74/customer"
	"github.com/stripe/stripe-go/v74/subscription"
	"github.com/stripe/stripe-go/v74/webhook"
)

// ============================================================================
// Subscription Tiers
// ============================================================================

// Tier represents a subscription tier
type Tier string

const (
	// TierFree provides basic scanning capabilities
	TierFree Tier = "free"
	// TierPro provides unlimited scans and API access
	TierPro Tier = "pro"
	// TierTeam provides team collaboration features
	TierTeam Tier = "team"
	// TierEnterprise provides dedicated infrastructure
	TierEnterprise Tier = "enterprise"
)

// IsValid checks if the tier is valid
func (t Tier) IsValid() bool {
	switch t {
	case TierFree, TierPro, TierTeam, TierEnterprise:
		return true
	}
	return false
}

// String returns the string representation of the tier
func (t Tier) String() string {
	return string(t)
}

// Price returns the monthly price for the tier
func (t Tier) Price() string {
	switch t {
	case TierFree:
		return "$0"
	case TierPro:
		return "$49/month"
	case TierTeam:
		return "$199/month"
	case TierEnterprise:
		return "Custom"
	}
	return "Unknown"
}

// ============================================================================
// Tier Features
// ============================================================================

// TierFeatures defines the features available for each tier
type TierFeatures struct {
	MaxScansPerDay  *int     `json:"max_scans_per_day"` // nil means unlimited
	MaxScanDuration int      `json:"max_scan_duration"` // in seconds
	AllowedScopes   []string `json:"allowed_scopes"`    // quick, standard, full
	APIAccess       bool     `json:"api_access"`
	PDFExport       bool     `json:"pdf_export"`
	TeamSeats       int      `json:"team_seats"` // 0 means no team
	SharedHistory   bool     `json:"shared_history"`
	RBAC            bool     `json:"rbac"` // Role-based access control
	PrioritySupport bool     `json:"priority_support"`
	DedicatedInfra  bool     `json:"dedicated_infra"`
	SSO             bool     `json:"sso"`
	SLA             bool     `json:"sla"`
	Watermarked     bool     `json:"watermarked"` // Watermarked reports
}

// GetFeatures returns the features for a tier
func GetFeatures(tier Tier) TierFeatures {
	switch tier {
	case TierFree:
		maxScans := 5
		return TierFeatures{
			MaxScansPerDay:  &maxScans,
			MaxScanDuration: 600, // 10 minutes
			AllowedScopes:   []string{"quick", "standard"},
			APIAccess:       false,
			PDFExport:       false,
			TeamSeats:       1,
			SharedHistory:   false,
			RBAC:            false,
			PrioritySupport: false,
			DedicatedInfra:  false,
			SSO:             false,
			SLA:             false,
			Watermarked:     true,
		}
	case TierPro:
		return TierFeatures{
			MaxScansPerDay:  nil,  // Unlimited
			MaxScanDuration: 1200, // 20 minutes
			AllowedScopes:   []string{"quick", "standard", "full"},
			APIAccess:       true,
			PDFExport:       true,
			TeamSeats:       1,
			SharedHistory:   false,
			RBAC:            false,
			PrioritySupport: false,
			DedicatedInfra:  false,
			SSO:             false,
			SLA:             false,
			Watermarked:     false,
		}
	case TierTeam:
		return TierFeatures{
			MaxScansPerDay:  nil,  // Unlimited
			MaxScanDuration: 1800, // 30 minutes
			AllowedScopes:   []string{"quick", "standard", "full"},
			APIAccess:       true,
			PDFExport:       true,
			TeamSeats:       5,
			SharedHistory:   true,
			RBAC:            true,
			PrioritySupport: true,
			DedicatedInfra:  false,
			SSO:             false,
			SLA:             false,
			Watermarked:     false,
		}
	case TierEnterprise:
		return TierFeatures{
			MaxScansPerDay:  nil,  // Unlimited
			MaxScanDuration: 3600, // 60 minutes
			AllowedScopes:   []string{"quick", "standard", "full"},
			APIAccess:       true,
			PDFExport:       true,
			TeamSeats:       0, // Unlimited/custom
			SharedHistory:   true,
			RBAC:            true,
			PrioritySupport: true,
			DedicatedInfra:  true,
			SSO:             true,
			SLA:             true,
			Watermarked:     false,
		}
	default:
		maxScans := 5
		return TierFeatures{
			MaxScansPerDay:  &maxScans,
			MaxScanDuration: 600,
			AllowedScopes:   []string{"quick", "standard"},
			APIAccess:       false,
			PDFExport:       false,
			TeamSeats:       1,
			SharedHistory:   false,
			RBAC:            false,
			PrioritySupport: false,
			DedicatedInfra:  false,
			SSO:             false,
			SLA:             false,
			Watermarked:     true,
		}
	}
}

// HasFeature checks if a tier has a specific feature
func HasFeature(tier Tier, feature string) bool {
	features := GetFeatures(tier)
	switch feature {
	case "api_access":
		return features.APIAccess
	case "pdf_export":
		return features.PDFExport
	case "full_scope":
		for _, scope := range features.AllowedScopes {
			if scope == "full" {
				return true
			}
		}
		return false
	case "team":
		return features.TeamSeats > 1 || tier == TierEnterprise
	case "shared_history":
		return features.SharedHistory
	case "rbac":
		return features.RBAC
	case "priority_support":
		return features.PrioritySupport
	case "dedicated_infra":
		return features.DedicatedInfra
	case "sso":
		return features.SSO
	case "sla":
		return features.SLA
	default:
		return false
	}
}

// CheckScopeAllowed checks if a scope is allowed for a tier
func CheckScopeAllowed(tier Tier, scope string) bool {
	features := GetFeatures(tier)
	for _, allowed := range features.AllowedScopes {
		if allowed == scope {
			return true
		}
	}
	return false
}

// ============================================================================
// Subscription Status
// ============================================================================

// SubscriptionStatus represents the status of a subscription
type SubscriptionStatus string

const (
	StatusActive   SubscriptionStatus = "active"
	StatusCanceled SubscriptionStatus = "canceled"
	StatusPastDue  SubscriptionStatus = "past_due"
	StatusUnpaid   SubscriptionStatus = "unpaid"
	StatusTrialing SubscriptionStatus = "trialing"
)

// IsActive returns true if the subscription is active
func (s SubscriptionStatus) IsActive() bool {
	switch s {
	case StatusActive, StatusTrialing:
		return true
	}
	return false
}

// String returns the string representation of the status
func (s SubscriptionStatus) String() string {
	return string(s)
}

// ============================================================================
// Subscription Data
// ============================================================================

// Subscription represents a user's subscription
type Subscription struct {
	ID                   uuid.UUID          `json:"id"`
	UserID               uuid.UUID          `json:"user_id"`
	StripeCustomerID     string             `json:"stripe_customer_id,omitempty"`
	StripeSubscriptionID string             `json:"stripe_subscription_id,omitempty"`
	Tier                 Tier               `json:"tier"`
	Status               SubscriptionStatus `json:"status"`
	CurrentPeriodStart   *time.Time         `json:"current_period_start,omitempty"`
	CurrentPeriodEnd     *time.Time         `json:"current_period_end,omitempty"`
	CancelAtPeriodEnd    bool               `json:"cancel_at_period_end"`
	CanceledAt           *time.Time         `json:"canceled_at,omitempty"`
	CreatedAt            time.Time          `json:"created_at"`
	UpdatedAt            time.Time          `json:"updated_at"`
}

// IsValidForUse returns true if the subscription can be used
func (s *Subscription) IsValidForUse() bool {
	if s.Status != StatusActive && s.Status != StatusTrialing {
		return false
	}
	if s.CurrentPeriodEnd != nil && time.Now().After(*s.CurrentPeriodEnd) {
		return false
	}
	return true
}

// GetEffectiveTier returns the effective tier considering grace periods
func (s *Subscription) GetEffectiveTier() Tier {
	// If canceled but still in current period, allow current tier
	if s.CancelAtPeriodEnd && s.CurrentPeriodEnd != nil && time.Now().Before(*s.CurrentPeriodEnd) {
		return s.Tier
	}

	// If past due, give a 3-day grace period
	if s.Status == StatusPastDue && s.CurrentPeriodEnd != nil {
		gracePeriodEnd := s.CurrentPeriodEnd.Add(3 * 24 * time.Hour)
		if time.Now().Before(gracePeriodEnd) {
			return s.Tier
		}
	}

	// Check if subscription is valid
	if !s.IsValidForUse() {
		return TierFree
	}

	return s.Tier
}

// ============================================================================
// Stripe Client
// ============================================================================

// Client wraps the Stripe API client
type Client struct {
	stripeKey     string
	webhookSecret string
	priceIDs      map[Tier]string
	mu            sync.RWMutex
	logger        Logger
}

// Logger interface for logging billing events
type Logger interface {
	Info(msg string, fields map[string]interface{})
	Error(msg string, fields map[string]interface{})
	Warn(msg string, fields map[string]interface{})
}

// defaultLogger implements a no-op logger
type defaultLogger struct{}

func (l *defaultLogger) Info(msg string, fields map[string]interface{})  {}
func (l *defaultLogger) Error(msg string, fields map[string]interface{}) {}
func (l *defaultLogger) Warn(msg string, fields map[string]interface{})  {}

// ClientOption configures the Client
type ClientOption func(*Client)

// WithLogger sets the logger for the client
func WithLogger(logger Logger) ClientOption {
	return func(c *Client) {
		c.logger = logger
	}
}

// WithPriceID sets the price ID for a tier
func WithPriceID(tier Tier, priceID string) ClientOption {
	return func(c *Client) {
		c.priceIDs[tier] = priceID
	}
}

// NewClient creates a new Stripe billing client
func NewClient(opts ...ClientOption) (*Client, error) {
	stripeKey := os.Getenv("STRIPE_SECRET_KEY")
	if stripeKey == "" {
		return nil, fmt.Errorf("STRIPE_SECRET_KEY environment variable is required")
	}

	webhookSecret := os.Getenv("STRIPE_WEBHOOK_SECRET")

	// Set Stripe API key globally
	stripe.Key = stripeKey

	client := &Client{
		stripeKey:     stripeKey,
		webhookSecret: webhookSecret,
		priceIDs:      make(map[Tier]string),
		logger:        &defaultLogger{},
	}

	// Load price IDs from environment
	client.priceIDs[TierPro] = os.Getenv("STRIPE_PRICE_ID_PRO")
	client.priceIDs[TierTeam] = os.Getenv("STRIPE_PRICE_ID_TEAM")

	// Apply options
	for _, opt := range opts {
		opt(client)
	}

	return client, nil
}

// ============================================================================
// Checkout Session Management
// ============================================================================

// CreateCheckoutSessionRequest contains parameters for creating a checkout session
type CreateCheckoutSessionRequest struct {
	UserID            uuid.UUID
	Email             string
	Tier              Tier
	SuccessURL        string
	CancelURL         string
	ClientReferenceID string
}

// CreateCheckoutSession creates a new Stripe Checkout session
func (c *Client) CreateCheckoutSession(ctx context.Context, req CreateCheckoutSessionRequest) (*stripe.CheckoutSession, error) {
	c.logger.Info("Creating checkout session", map[string]interface{}{
		"user_id": req.UserID.String(),
		"tier":    req.Tier.String(),
	})

	priceID, ok := c.priceIDs[req.Tier]
	if !ok || priceID == "" {
		return nil, fmt.Errorf("no price ID configured for tier: %s", req.Tier)
	}

	// Create or retrieve customer
	customerParams := &stripe.CustomerParams{
		Params: stripe.Params{
			Context: ctx,
			Metadata: map[string]string{
				"user_id": req.UserID.String(),
			},
		},
		Email: stripe.String(req.Email),
	}

	cust, err := customer.New(customerParams)
	if err != nil {
		c.logger.Error("Failed to create customer", map[string]interface{}{
			"error": err.Error(),
		})
		return nil, fmt.Errorf("failed to create customer: %w", err)
	}

	// Create checkout session
	params := &stripe.CheckoutSessionParams{
		Params: stripe.Params{
			Context: ctx,
		},
		Customer:   stripe.String(cust.ID),
		Mode:       stripe.String(string(stripe.CheckoutSessionModeSubscription)),
		SuccessURL: stripe.String(req.SuccessURL),
		CancelURL:  stripe.String(req.CancelURL),
		LineItems: []*stripe.CheckoutSessionLineItemParams{
			{
				Price:    stripe.String(priceID),
				Quantity: stripe.Int64(1),
			},
		},
		SubscriptionData: &stripe.CheckoutSessionSubscriptionDataParams{
			Metadata: map[string]string{
				"user_id": req.UserID.String(),
				"tier":    req.Tier.String(),
			},
		},
		ClientReferenceID: stripe.String(req.ClientReferenceID),
	}

	session, err := checkoutsession.New(params)
	if err != nil {
		c.logger.Error("Failed to create checkout session", map[string]interface{}{
			"error": err.Error(),
		})
		return nil, fmt.Errorf("failed to create checkout session: %w", err)
	}

	c.logger.Info("Checkout session created", map[string]interface{}{
		"session_id":  session.ID,
		"customer_id": cust.ID,
	})

	return session, nil
}

// CreateCustomerPortal creates a customer portal session
func (c *Client) CreateCustomerPortal(ctx context.Context, customerID string, returnURL string) (*stripe.BillingPortalSession, error) {
	c.logger.Info("Creating customer portal", map[string]interface{}{
		"customer_id": customerID,
	})

	params := &stripe.BillingPortalSessionParams{
		Params: stripe.Params{
			Context: ctx,
		},
		Customer:  stripe.String(customerID),
		ReturnURL: stripe.String(returnURL),
	}

	portalSession, err := billingportal.New(params)
	if err != nil {
		c.logger.Error("Failed to create customer portal", map[string]interface{}{
			"error": err.Error(),
		})
		return nil, fmt.Errorf("failed to create customer portal: %w", err)
	}

	return portalSession, nil
}

// ============================================================================
// Subscription Management
// ============================================================================

// GetSubscription retrieves a subscription from Stripe
func (c *Client) GetSubscription(ctx context.Context, subscriptionID string) (*stripe.Subscription, error) {
	params := &stripe.SubscriptionParams{
		Params: stripe.Params{
			Context: ctx,
		},
	}

	sub, err := subscription.Get(subscriptionID, params)
	if err != nil {
		return nil, fmt.Errorf("failed to get subscription: %w", err)
	}

	return sub, nil
}

// CancelSubscription cancels a subscription at period end
func (c *Client) CancelSubscription(ctx context.Context, subscriptionID string) (*stripe.Subscription, error) {
	c.logger.Info("Canceling subscription", map[string]interface{}{
		"subscription_id": subscriptionID,
	})

	params := &stripe.SubscriptionParams{
		Params: stripe.Params{
			Context: ctx,
		},
		CancelAtPeriodEnd: stripe.Bool(true),
	}

	sub, err := subscription.Update(subscriptionID, params)
	if err != nil {
		c.logger.Error("Failed to cancel subscription", map[string]interface{}{
			"error": err.Error(),
		})
		return nil, fmt.Errorf("failed to cancel subscription: %w", err)
	}

	return sub, nil
}

// ReactivateSubscription reactivates a subscription that was set to cancel
func (c *Client) ReactivateSubscription(ctx context.Context, subscriptionID string) (*stripe.Subscription, error) {
	c.logger.Info("Reactivating subscription", map[string]interface{}{
		"subscription_id": subscriptionID,
	})

	params := &stripe.SubscriptionParams{
		Params: stripe.Params{
			Context: ctx,
		},
		CancelAtPeriodEnd: stripe.Bool(false),
	}

	sub, err := subscription.Update(subscriptionID, params)
	if err != nil {
		c.logger.Error("Failed to reactivate subscription", map[string]interface{}{
			"error": err.Error(),
		})
		return nil, fmt.Errorf("failed to reactivate subscription: %w", err)
	}

	return sub, nil
}

// ============================================================================
// Webhook Handling
// ============================================================================

// WebhookEvent represents a parsed Stripe webhook event
type WebhookEvent struct {
	Type      string
	ID        string
	Data      json.RawMessage
	LiveMode  bool
	CreatedAt time.Time
}

// ConstructEvent constructs and verifies a webhook event
func (c *Client) ConstructEvent(payload []byte, signature string) (*stripe.Event, error) {
	if c.webhookSecret == "" {
		return nil, fmt.Errorf("webhook secret not configured")
	}

	event, err := webhook.ConstructEvent(payload, signature, c.webhookSecret)
	if err != nil {
		c.logger.Error("Failed to construct webhook event", map[string]interface{}{
			"error": err.Error(),
		})
		return nil, fmt.Errorf("failed to verify webhook signature: %w", err)
	}

	return &event, nil
}

// ============================================================================
// Tier from Stripe
// ============================================================================

// TierFromPriceID returns the tier associated with a Stripe price ID
func (c *Client) TierFromPriceID(priceID string) (Tier, bool) {
	for tier, id := range c.priceIDs {
		if id == priceID {
			return tier, true
		}
	}
	return TierFree, false
}

// GetPriceID returns the price ID for a tier
func (c *Client) GetPriceID(tier Tier) string {
	return c.priceIDs[tier]
}

// ============================================================================
// Subscription Helpers
// ============================================================================

// SubscriptionToTier maps a Stripe subscription status to our tier
func SubscriptionToTier(sub *stripe.Subscription) Tier {
	if sub == nil {
		return TierFree
	}

	// Get tier from metadata
	if tierStr, ok := sub.Metadata["tier"]; ok {
		tier := Tier(tierStr)
		if tier.IsValid() {
			return tier
		}
	}

	return TierFree
}

// SubscriptionStatusFromStripe converts Stripe status to our status
func SubscriptionStatusFromStripe(status stripe.SubscriptionStatus) SubscriptionStatus {
	switch status {
	case stripe.SubscriptionStatusActive:
		return StatusActive
	case stripe.SubscriptionStatusCanceled:
		return StatusCanceled
	case stripe.SubscriptionStatusPastDue:
		return StatusPastDue
	case stripe.SubscriptionStatusUnpaid:
		return StatusUnpaid
	case stripe.SubscriptionStatusTrialing:
		return StatusTrialing
	case stripe.SubscriptionStatusIncomplete,
		stripe.SubscriptionStatusIncompleteExpired,
		stripe.SubscriptionStatusPaused:
		return StatusUnpaid
	default:
		return StatusUnpaid
	}
}

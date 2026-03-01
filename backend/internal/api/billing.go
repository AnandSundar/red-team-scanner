package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/stripe/stripe-go/v74"

	"github.com/redteam/agentic-scanner/internal/auth"
	"github.com/redteam/agentic-scanner/internal/billing"
	"github.com/redteam/agentic-scanner/internal/store"
)

// ============================================================================
// Billing Request/Response Types
// ============================================================================

// CheckoutRequest represents a request to create a checkout session
type CheckoutRequest struct {
	Tier       string `json:"tier"`
	SuccessURL string `json:"success_url"`
	CancelURL  string `json:"cancel_url"`
}

// CheckoutResponse represents a checkout session response
type CheckoutResponse struct {
	CheckoutURL string `json:"checkout_url"`
	SessionID   string `json:"session_id"`
}

// PortalResponse represents a customer portal response
type PortalResponse struct {
	PortalURL string `json:"portal_url"`
}

// SubscriptionResponse represents a subscription response
type SubscriptionResponse struct {
	Tier               string               `json:"tier"`
	Status             string               `json:"status"`
	CurrentPeriodStart *time.Time           `json:"current_period_start,omitempty"`
	CurrentPeriodEnd   *time.Time           `json:"current_period_end,omitempty"`
	CancelAtPeriodEnd  bool                 `json:"cancel_at_period_end"`
	Features           billing.TierFeatures `json:"features"`
}

// WebhookEvent represents a Stripe webhook event log entry
type WebhookEvent struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"`
	Processed time.Time `json:"processed"`
	Status    string    `json:"status"`
}

// ============================================================================
// Billing Handler Setup
// ============================================================================

// BillingHandler holds billing-related HTTP handlers
type BillingHandler struct {
	billingClient *billing.Client
	store         *store.DB
	logger        billing.Logger
}

// NewBillingHandler creates a new billing handler
func NewBillingHandler(store *store.DB, logger billing.Logger) (*BillingHandler, error) {
	client, err := billing.NewClient(billing.WithLogger(logger))
	if err != nil {
		return nil, fmt.Errorf("failed to create billing client: %w", err)
	}

	return &BillingHandler{
		billingClient: client,
		store:         store,
		logger:        logger,
	}, nil
}

// ============================================================================
// Subscription Management Handlers
// ============================================================================

// GetSubscriptionHandler handles GET /api/v1/billing/subscription
func (h *BillingHandler) GetSubscriptionHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get user from context
	user := auth.GetUserFromContext(ctx)
	if user == nil {
		respondError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	// Set RLS context
	if err := h.store.SetUserContext(ctx, user.ClerkUserID, user.ID); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to set user context")
		return
	}

	// Get subscription from database
	subscription, err := h.store.GetUserSubscription(ctx, user.ID)
	if err != nil {
		// If no subscription found, return free tier
		subscription = &store.Subscription{
			UserID: user.ID,
			Tier:   string(billing.TierFree),
			Status: string(billing.StatusActive),
		}
	}

	// Get effective tier (considering grace periods)
	tier := billing.Tier(subscription.Tier)
	if subscription.CurrentPeriodEnd != nil && time.Now().After(*subscription.CurrentPeriodEnd) {
		// Subscription expired, fallback to free
		tier = billing.TierFree
	}

	// Build response
	features := billing.GetFeatures(tier)
	response := SubscriptionResponse{
		Tier:               string(tier),
		Status:             subscription.Status,
		CurrentPeriodStart: subscription.CurrentPeriodStart,
		CurrentPeriodEnd:   subscription.CurrentPeriodEnd,
		CancelAtPeriodEnd:  subscription.CancelAtPeriodEnd,
		Features:           features,
	}

	respondJSON(w, http.StatusOK, response)
}

// CreateCheckoutHandler handles POST /api/v1/billing/checkout
func (h *BillingHandler) CreateCheckoutHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get user from context
	user := auth.GetUserFromContext(ctx)
	if user == nil {
		respondError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	// Parse request
	var req CheckoutRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Validate tier
	tier := billing.Tier(req.Tier)
	if !tier.IsValid() {
		respondError(w, http.StatusBadRequest, "Invalid tier")
		return
	}

	// Only allow checkout for paid tiers
	if tier == billing.TierFree {
		respondError(w, http.StatusBadRequest, "Cannot checkout for free tier")
		return
	}

	// Validate URLs
	if req.SuccessURL == "" || req.CancelURL == "" {
		respondError(w, http.StatusBadRequest, "Success and cancel URLs are required")
		return
	}

	// Set RLS context
	if err := h.store.SetUserContext(ctx, user.ClerkUserID, user.ID); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to set user context")
		return
	}

	// Create checkout session
	checkoutReq := billing.CreateCheckoutSessionRequest{
		UserID:            user.ID,
		Email:             user.Email,
		Tier:              tier,
		SuccessURL:        req.SuccessURL,
		CancelURL:         req.CancelURL,
		ClientReferenceID: user.ID.String(),
	}

	session, err := h.billingClient.CreateCheckoutSession(ctx, checkoutReq)
	if err != nil {
		h.logger.Error("Failed to create checkout session", map[string]interface{}{
			"error":   err.Error(),
			"user_id": user.ID.String(),
		})
		respondError(w, http.StatusInternalServerError, "Failed to create checkout session")
		return
	}

	// Log billing event
	h.logBillingEvent(ctx, user.ID, "checkout.session.created", map[string]interface{}{
		"session_id": session.ID,
		"tier":       tier.String(),
	})

	// Return checkout URL
	response := CheckoutResponse{
		CheckoutURL: session.URL,
		SessionID:   session.ID,
	}

	respondJSON(w, http.StatusCreated, response)
}

// CustomerPortalHandler handles GET /api/v1/billing/portal
func (h *BillingHandler) CustomerPortalHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get user from context
	user := auth.GetUserFromContext(ctx)
	if user == nil {
		respondError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	// Set RLS context
	if err := h.store.SetUserContext(ctx, user.ClerkUserID, user.ID); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to set user context")
		return
	}

	// Get subscription to find Stripe customer ID
	subscription, err := h.store.GetUserSubscription(ctx, user.ID)
	if err != nil {
		respondError(w, http.StatusNotFound, "No subscription found")
		return
	}

	if subscription.StripeCustomerID == "" {
		respondError(w, http.StatusBadRequest, "No Stripe customer associated with this account")
		return
	}

	// Get return URL from query parameter or use default
	returnURL := r.URL.Query().Get("return_url")
	if returnURL == "" {
		returnURL = os.Getenv("APP_URL") + "/settings/billing"
	}

	// Create portal session
	portalSession, err := h.billingClient.CreateCustomerPortal(ctx, subscription.StripeCustomerID, returnURL)
	if err != nil {
		h.logger.Error("Failed to create customer portal", map[string]interface{}{
			"error":       err.Error(),
			"user_id":     user.ID.String(),
			"customer_id": subscription.StripeCustomerID,
		})
		respondError(w, http.StatusInternalServerError, "Failed to create customer portal")
		return
	}

	// Log billing event
	h.logBillingEvent(ctx, user.ID, "customer.portal.created", map[string]interface{}{
		"portal_session_id": portalSession.ID,
	})

	// Return portal URL
	response := PortalResponse{
		PortalURL: portalSession.URL,
	}

	respondJSON(w, http.StatusOK, response)
}

// ============================================================================
// Stripe Webhook Handler
// ============================================================================

// StripeWebhookHandler handles POST /api/v1/webhooks/stripe
func (h *BillingHandler) StripeWebhookHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Read request body
	payload, err := io.ReadAll(r.Body)
	if err != nil {
		h.logger.Error("Failed to read webhook body", map[string]interface{}{
			"error": err.Error(),
		})
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	// Verify webhook signature
	signature := r.Header.Get("Stripe-Signature")
	event, err := h.billingClient.ConstructEvent(payload, signature)
	if err != nil {
		h.logger.Error("Failed to verify webhook signature", map[string]interface{}{
			"error": err.Error(),
		})
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Log the event
	h.logger.Info("Received Stripe webhook", map[string]interface{}{
		"event_type": event.Type,
		"event_id":   event.ID,
	})

	// Process the event based on type
	switch event.Type {
	case "checkout.session.completed":
		h.handleCheckoutSessionCompleted(ctx, event)
	case "customer.subscription.updated":
		h.handleSubscriptionUpdated(ctx, event)
	case "customer.subscription.deleted":
		h.handleSubscriptionDeleted(ctx, event)
	case "invoice.payment_failed":
		h.handleInvoicePaymentFailed(ctx, event)
	case "customer.subscription.created":
		h.handleSubscriptionCreated(ctx, event)
	default:
		h.logger.Info("Unhandled webhook event type", map[string]interface{}{
			"event_type": event.Type,
		})
	}

	// Acknowledge receipt
	w.WriteHeader(http.StatusOK)
}

// handleCheckoutSessionCompleted processes checkout.session.completed events
func (h *BillingHandler) handleCheckoutSessionCompleted(ctx context.Context, event *stripe.Event) {
	var session stripe.CheckoutSession
	if err := json.Unmarshal(event.Data.Raw, &session); err != nil {
		h.logger.Error("Failed to unmarshal checkout session", map[string]interface{}{
			"error": err.Error(),
		})
		return
	}

	// Extract user ID from client reference ID or metadata
	userIDStr := session.ClientReferenceID
	if userIDStr == "" {
		userIDStr = session.Metadata["user_id"]
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.logger.Error("Failed to parse user ID from session", map[string]interface{}{
			"error": err.Error(),
		})
		return
	}

	// Get subscription details from Stripe
	if session.Subscription == nil {
		h.logger.Error("No subscription in checkout session", map[string]interface{}{
			"session_id": session.ID,
		})
		return
	}

	stripeSub, err := h.billingClient.GetSubscription(ctx, session.Subscription.ID)
	if err != nil {
		h.logger.Error("Failed to get subscription from Stripe", map[string]interface{}{
			"error":           err.Error(),
			"subscription_id": session.Subscription.ID,
		})
		return
	}

	// Determine tier from subscription
	tier := billing.SubscriptionToTier(stripeSub)
	status := billing.SubscriptionStatusFromStripe(stripeSub.Status)

	// Create or update subscription in database
	periodStart := time.Unix(stripeSub.CurrentPeriodStart, 0)
	periodEnd := time.Unix(stripeSub.CurrentPeriodEnd, 0)

	subParams := store.CreateSubscriptionParams{
		UserID:               userID,
		StripeCustomerID:     session.Customer.ID,
		StripeSubscriptionID: stripeSub.ID,
		Tier:                 string(tier),
		Status:               string(status),
		CurrentPeriodStart:   &periodStart,
		CurrentPeriodEnd:     &periodEnd,
	}

	if _, err := h.store.CreateSubscription(ctx, subParams); err != nil {
		h.logger.Error("Failed to create subscription", map[string]interface{}{
			"error":   err.Error(),
			"user_id": userID.String(),
		})
		return
	}

	// Update user's tier
	if _, err := h.store.UpdateUserTier(ctx, store.UpdateUserTierParams{
		ID:   userID,
		Tier: string(tier),
	}); err != nil {
		h.logger.Error("Failed to update user tier", map[string]interface{}{
			"error":   err.Error(),
			"user_id": userID.String(),
		})
	}

	// Log billing event
	h.logBillingEvent(ctx, userID, event.Type, map[string]interface{}{
		"session_id":      session.ID,
		"subscription_id": stripeSub.ID,
		"customer_id":     session.Customer.ID,
		"tier":            tier.String(),
	})
}

// handleSubscriptionUpdated processes customer.subscription.updated events
func (h *BillingHandler) handleSubscriptionUpdated(ctx context.Context, event *stripe.Event) {
	var stripeSub stripe.Subscription
	if err := json.Unmarshal(event.Data.Raw, &stripeSub); err != nil {
		h.logger.Error("Failed to unmarshal subscription", map[string]interface{}{
			"error": err.Error(),
		})
		return
	}

	// Find subscription in database
	sub, err := h.store.GetSubscriptionByStripeID(ctx, stripeSub.ID)
	if err != nil {
		h.logger.Error("Failed to find subscription", map[string]interface{}{
			"error":           err.Error(),
			"subscription_id": stripeSub.ID,
		})
		return
	}

	// Update subscription status
	status := billing.SubscriptionStatusFromStripe(stripeSub.Status)
	periodStart := time.Unix(stripeSub.CurrentPeriodStart, 0)
	periodEnd := time.Unix(stripeSub.CurrentPeriodEnd, 0)

	updateParams := store.UpdateSubscriptionParams{
		ID:                 sub.ID,
		Status:             string(status),
		CurrentPeriodStart: &periodStart,
		CurrentPeriodEnd:   &periodEnd,
		CancelAtPeriodEnd:  stripeSub.CancelAtPeriodEnd,
	}

	if stripeSub.CanceledAt > 0 {
		canceledAt := time.Unix(stripeSub.CanceledAt, 0)
		updateParams.CanceledAt = &canceledAt
	}

	if _, err := h.store.UpdateSubscription(ctx, updateParams); err != nil {
		h.logger.Error("Failed to update subscription", map[string]interface{}{
			"error":           err.Error(),
			"subscription_id": stripeSub.ID,
		})
		return
	}

	// Update user's tier if subscription is no longer active
	if !status.IsActive() {
		if _, err := h.store.UpdateUserTier(ctx, store.UpdateUserTierParams{
			ID:   sub.UserID,
			Tier: string(billing.TierFree),
		}); err != nil {
			h.logger.Error("Failed to update user tier", map[string]interface{}{
				"error":   err.Error(),
				"user_id": sub.UserID.String(),
			})
		}
	}

	// Log billing event
	h.logBillingEvent(ctx, sub.UserID, event.Type, map[string]interface{}{
		"subscription_id":      stripeSub.ID,
		"status":               status.String(),
		"cancel_at_period_end": stripeSub.CancelAtPeriodEnd,
	})
}

// handleSubscriptionDeleted processes customer.subscription.deleted events
func (h *BillingHandler) handleSubscriptionDeleted(ctx context.Context, event *stripe.Event) {
	var stripeSub stripe.Subscription
	if err := json.Unmarshal(event.Data.Raw, &stripeSub); err != nil {
		h.logger.Error("Failed to unmarshal subscription", map[string]interface{}{
			"error": err.Error(),
		})
		return
	}

	// Find subscription in database
	sub, err := h.store.GetSubscriptionByStripeID(ctx, stripeSub.ID)
	if err != nil {
		h.logger.Error("Failed to find subscription", map[string]interface{}{
			"error":           err.Error(),
			"subscription_id": stripeSub.ID,
		})
		return
	}

	// Cancel subscription in database
	if _, err := h.store.CancelSubscription(ctx, sub.ID); err != nil {
		h.logger.Error("Failed to cancel subscription", map[string]interface{}{
			"error":           err.Error(),
			"subscription_id": stripeSub.ID,
		})
		return
	}

	// Downgrade user to free tier
	if _, err := h.store.UpdateUserTier(ctx, store.UpdateUserTierParams{
		ID:   sub.UserID,
		Tier: string(billing.TierFree),
	}); err != nil {
		h.logger.Error("Failed to update user tier", map[string]interface{}{
			"error":   err.Error(),
			"user_id": sub.UserID.String(),
		})
	}

	// Log billing event
	h.logBillingEvent(ctx, sub.UserID, event.Type, map[string]interface{}{
		"subscription_id": stripeSub.ID,
	})
}

// handleInvoicePaymentFailed processes invoice.payment_failed events
func (h *BillingHandler) handleInvoicePaymentFailed(ctx context.Context, event *stripe.Event) {
	var invoice stripe.Invoice
	if err := json.Unmarshal(event.Data.Raw, &invoice); err != nil {
		h.logger.Error("Failed to unmarshal invoice", map[string]interface{}{
			"error": err.Error(),
		})
		return
	}

	if invoice.Subscription == nil {
		return
	}

	// Find subscription in database
	sub, err := h.store.GetSubscriptionByStripeID(ctx, invoice.Subscription.ID)
	if err != nil {
		h.logger.Error("Failed to find subscription", map[string]interface{}{
			"error":           err.Error(),
			"subscription_id": invoice.Subscription.ID,
		})
		return
	}

	// Update subscription status to past_due
	if _, err := h.store.UpdateSubscription(ctx, store.UpdateSubscriptionParams{
		ID:     sub.ID,
		Status: string(billing.StatusPastDue),
	}); err != nil {
		h.logger.Error("Failed to update subscription status", map[string]interface{}{
			"error":           err.Error(),
			"subscription_id": invoice.Subscription.ID,
		})
	}

	// Log billing event
	h.logBillingEvent(ctx, sub.UserID, event.Type, map[string]interface{}{
		"subscription_id": invoice.Subscription.ID,
		"invoice_id":      invoice.ID,
	})
}

// handleSubscriptionCreated processes customer.subscription.created events
func (h *BillingHandler) handleSubscriptionCreated(ctx context.Context, event *stripe.Event) {
	// Usually handled by checkout.session.completed, but log for completeness
	h.logger.Info("Subscription created", map[string]interface{}{
		"event_id": event.ID,
	})
}

// ============================================================================
// Helper Methods
// ============================================================================

// logBillingEvent logs a billing event for audit purposes
func (h *BillingHandler) logBillingEvent(ctx context.Context, userID uuid.UUID, eventType string, data map[string]interface{}) {
	eventData, _ := json.Marshal(data)

	event := store.BillingEvent{
		UserID:    userID,
		EventType: eventType,
		EventData: eventData,
	}

	if err := h.store.CreateBillingEvent(ctx, event); err != nil {
		h.logger.Error("Failed to log billing event", map[string]interface{}{
			"error": err.Error(),
		})
	}
}

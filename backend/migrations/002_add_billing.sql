-- =============================================================================
-- Red Team Scanner - Billing Migration
-- Phase 16: Stripe Billing Integration
-- =============================================================================

-- =============================================================================
-- Subscriptions Table
-- =============================================================================
CREATE TABLE IF NOT EXISTS subscriptions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    stripe_customer_id TEXT,
    stripe_subscription_id TEXT UNIQUE,
    tier TEXT NOT NULL DEFAULT 'free' CHECK (tier IN ('free', 'pro', 'team', 'enterprise')),
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'canceled', 'past_due', 'unpaid', 'trialing')),
    current_period_start TIMESTAMPTZ,
    current_period_end TIMESTAMPTZ,
    cancel_at_period_end BOOLEAN NOT NULL DEFAULT false,
    canceled_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- =============================================================================
-- Billing Events Audit Log
-- =============================================================================
CREATE TABLE IF NOT EXISTS billing_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    stripe_event_id TEXT UNIQUE,
    event_type TEXT NOT NULL,
    event_data JSONB NOT NULL DEFAULT '{}',
    processed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- =============================================================================
-- Daily Scan Usage Tracking (for tier enforcement)
-- =============================================================================
CREATE TABLE IF NOT EXISTS daily_scan_usage (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    scan_date DATE NOT NULL DEFAULT CURRENT_DATE,
    scan_count INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(user_id, scan_date)
);

-- =============================================================================
-- Indexes for Performance
-- =============================================================================

-- Subscription indexes
CREATE INDEX IF NOT EXISTS idx_subscriptions_user ON subscriptions(user_id);
CREATE INDEX IF NOT EXISTS idx_subscriptions_stripe_customer ON subscriptions(stripe_customer_id);
CREATE INDEX IF NOT EXISTS idx_subscriptions_stripe_sub ON subscriptions(stripe_subscription_id);
CREATE INDEX IF NOT EXISTS idx_subscriptions_status ON subscriptions(status);
CREATE INDEX IF NOT EXISTS idx_subscriptions_period_end ON subscriptions(current_period_end);

-- Billing events indexes
CREATE INDEX IF NOT EXISTS idx_billing_events_user ON billing_events(user_id);
CREATE INDEX IF NOT EXISTS idx_billing_events_stripe_event ON billing_events(stripe_event_id);
CREATE INDEX IF NOT EXISTS idx_billing_events_type ON billing_events(event_type);
CREATE INDEX IF NOT EXISTS idx_billing_events_created ON billing_events(created_at DESC);

-- Daily usage indexes
CREATE INDEX IF NOT EXISTS idx_daily_scan_usage_user ON daily_scan_usage(user_id);
CREATE INDEX IF NOT EXISTS idx_daily_scan_usage_date ON daily_scan_usage(scan_date);
CREATE INDEX IF NOT EXISTS idx_daily_scan_usage_user_date ON daily_scan_usage(user_id, scan_date);

-- =============================================================================
-- Triggers for Updated At
-- =============================================================================

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Trigger for subscriptions
DROP TRIGGER IF EXISTS update_subscriptions_updated_at ON subscriptions;
CREATE TRIGGER update_subscriptions_updated_at
    BEFORE UPDATE ON subscriptions
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Trigger for daily_scan_usage
DROP TRIGGER IF EXISTS update_daily_scan_usage_updated_at ON daily_scan_usage;
CREATE TRIGGER update_daily_scan_usage_updated_at
    BEFORE UPDATE ON daily_scan_usage
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- =============================================================================
-- Function to Get or Create Daily Usage Record
-- =============================================================================
CREATE OR REPLACE FUNCTION get_or_create_daily_usage(p_user_id UUID, p_date DATE)
RETURNS UUID AS $$
DECLARE
    v_usage_id UUID;
BEGIN
    -- Try to get existing record
    SELECT id INTO v_usage_id
    FROM daily_scan_usage
    WHERE user_id = p_user_id AND scan_date = p_date;
    
    -- If not found, create new record
    IF v_usage_id IS NULL THEN
        INSERT INTO daily_scan_usage (user_id, scan_date, scan_count)
        VALUES (p_user_id, p_date, 0)
        RETURNING id INTO v_usage_id;
    END IF;
    
    RETURN v_usage_id;
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- Function to Increment Daily Scan Count
-- =============================================================================
CREATE OR REPLACE FUNCTION increment_daily_scan_count(p_user_id UUID)
RETURNS INTEGER AS $$
DECLARE
    v_new_count INTEGER;
BEGIN
    INSERT INTO daily_scan_usage (user_id, scan_date, scan_count)
    VALUES (p_user_id, CURRENT_DATE, 1)
    ON CONFLICT (user_id, scan_date)
    DO UPDATE SET 
        scan_count = daily_scan_usage.scan_count + 1,
        updated_at = NOW()
    RETURNING scan_count INTO v_new_count;
    
    RETURN v_new_count;
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- Function to Check Scan Limit for User
-- =============================================================================
CREATE OR REPLACE FUNCTION check_scan_limit(p_user_id UUID, p_tier TEXT)
RETURNS BOOLEAN AS $$
DECLARE
    v_daily_count INTEGER;
    v_max_scans INTEGER;
BEGIN
    -- Define max scans per tier
    v_max_scans := CASE p_tier
        WHEN 'free' THEN 5
        WHEN 'pro' THEN NULL  -- Unlimited
        WHEN 'team' THEN NULL  -- Unlimited
        WHEN 'enterprise' THEN NULL  -- Unlimited
        ELSE 5
    END;
    
    -- If unlimited, allow
    IF v_max_scans IS NULL THEN
        RETURN true;
    END IF;
    
    -- Get current day's scan count
    SELECT COALESCE(scan_count, 0) INTO v_daily_count
    FROM daily_scan_usage
    WHERE user_id = p_user_id AND scan_date = CURRENT_DATE;
    
    -- If no record, count is 0
    IF v_daily_count IS NULL THEN
        v_daily_count := 0;
    END IF;
    
    -- Check if under limit
    RETURN v_daily_count < v_max_scans;
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- Insert Default Free Subscriptions for Existing Users
-- =============================================================================
INSERT INTO subscriptions (user_id, tier, status)
SELECT id, tier, 'active'
FROM users
WHERE NOT EXISTS (
    SELECT 1 FROM subscriptions WHERE subscriptions.user_id = users.id
);

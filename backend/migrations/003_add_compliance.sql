-- Migration: Add compliance tables for audit logging, ToS acceptance, and privacy
-- Phase 17: Compliance & Legal Layer

-- Enable required extensions if not already enabled
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ============================================================================
-- AUDIT LOGS TABLE
-- ============================================================================
-- Stores immutable audit logs for compliance and security
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    event_type TEXT NOT NULL,
    event_data JSONB,
    target TEXT,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Add comment explaining table purpose
COMMENT ON TABLE audit_logs IS 'Immutable audit logs for compliance, security events, and user actions';
COMMENT ON COLUMN audit_logs.event_type IS 'Type of audit event: scan_initiated, scan_completed, scan_cancelled, report_generated, report_shared, auth_confirmed, tier_changed, api_key_created, api_key_revoked, block_attempt, etc.';
COMMENT ON COLUMN audit_logs.event_data IS 'JSON object containing event-specific data';
COMMENT ON COLUMN audit_logs.target IS 'The target resource (e.g., scan target, report ID)';

-- Indexes for audit log queries
CREATE INDEX idx_audit_logs_user ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_created ON audit_logs(created_at);
CREATE INDEX idx_audit_logs_event ON audit_logs(event_type);
CREATE INDEX idx_audit_logs_user_event ON audit_logs(user_id, event_type);
CREATE INDEX idx_audit_logs_target ON audit_logs(target);

-- Partitioning for audit logs (optional, for high volume)
-- This helps with retention and query performance
-- Partition by month for efficient cleanup
CREATE TABLE audit_logs_2024_01 PARTITION OF audit_logs
    FOR VALUES FROM ('2024-01-01') TO ('2024-02-01');

-- Row Level Security (RLS) for audit logs
-- Users can only see their own audit logs (except admins)
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;

CREATE POLICY audit_logs_user_isolation ON audit_logs
    FOR SELECT
    USING (
        user_id = current_setting('app.current_user_uuid')::UUID
        OR current_setting('app.is_admin')::boolean = true
    );

-- Audit log retention function
CREATE OR REPLACE FUNCTION cleanup_old_audit_logs()
RETURNS void AS $$
BEGIN
    DELETE FROM audit_logs
    WHERE created_at < NOW() - INTERVAL '90 days';
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- TERMS OF SERVICE ACCEPTANCE TABLE
-- ============================================================================
-- Tracks user acceptance of Terms of Service
CREATE TABLE tos_acceptances (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE UNIQUE,
    version TEXT NOT NULL,
    accepted_at TIMESTAMPTZ DEFAULT NOW(),
    ip_address INET,
    user_agent TEXT,
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Add comments
COMMENT ON TABLE tos_acceptances IS 'Tracks which users have accepted the Terms of Service and when';
COMMENT ON COLUMN tos_acceptances.version IS 'Version of ToS that was accepted';

-- Indexes for ToS queries
CREATE INDEX idx_tos_user ON tos_acceptances(user_id);
CREATE INDEX idx_tos_version ON tos_acceptances(version);
CREATE INDEX idx_tos_accepted_at ON tos_acceptances(accepted_at);

-- RLS for ToS acceptances
ALTER TABLE tos_acceptances ENABLE ROW LEVEL SECURITY;

CREATE POLICY tos_acceptances_user_isolation ON tos_acceptances
    FOR ALL
    USING (user_id = current_setting('app.current_user_uuid')::UUID);

-- Trigger to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_tos_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_tos_acceptance_timestamp
    BEFORE UPDATE ON tos_acceptances
    FOR EACH ROW
    EXECUTE FUNCTION update_tos_timestamp();

-- ============================================================================
-- USER CONSENT TABLE (GDPR/CCPA)
-- ============================================================================
-- Tracks user consent for various data processing activities
CREATE TABLE user_consents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    consent_type TEXT NOT NULL,
    granted BOOLEAN NOT NULL DEFAULT false,
    granted_at TIMESTAMPTZ,
    withdrawn_at TIMESTAMPTZ,
    ip_address INET,
    user_agent TEXT,
    version TEXT NOT NULL DEFAULT '1.0',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(user_id, consent_type)
);

-- Add comments
COMMENT ON TABLE user_consents IS 'Tracks user consent for GDPR and CCPA compliance';
COMMENT ON COLUMN user_consents.consent_type IS 'Type of consent: marketing, analytics, third_party_sharing, data_processing';
COMMENT ON COLUMN user_consents.granted IS 'Whether consent is currently granted';

-- Indexes for consent queries
CREATE INDEX idx_consents_user ON user_consents(user_id);
CREATE INDEX idx_consents_type ON user_consents(consent_type);
CREATE INDEX idx_consents_granted ON user_consents(user_id, consent_type, granted);

-- RLS for consents
ALTER TABLE user_consents ENABLE ROW LEVEL SECURITY;

CREATE POLICY user_consents_user_isolation ON user_consents
    FOR ALL
    USING (user_id = current_setting('app.current_user_uuid')::UUID);

-- Trigger for updated_at
CREATE TRIGGER update_user_consents_timestamp
    BEFORE UPDATE ON user_consents
    FOR EACH ROW
    EXECUTE FUNCTION update_tos_timestamp();

-- ============================================================================
-- DATA DELETION REQUESTS TABLE (GDPR/CCPA)
-- ============================================================================
-- Tracks data deletion requests for compliance
CREATE TABLE data_deletion_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    request_id TEXT NOT NULL UNIQUE,
    reason TEXT,
    status TEXT NOT NULL DEFAULT 'pending', -- pending, processing, completed, failed
    requested_at TIMESTAMPTZ DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    ip_address INET,
    processed_by UUID REFERENCES users(id) ON DELETE SET NULL
);

-- Add comments
COMMENT ON TABLE data_deletion_requests IS 'Tracks GDPR/CCPA data deletion requests';
COMMENT ON COLUMN data_deletion_requests.status IS 'Request status: pending, processing, completed, failed';

-- Indexes for deletion requests
CREATE INDEX idx_deletion_user ON data_deletion_requests(user_id);
CREATE INDEX idx_deletion_status ON data_deletion_requests(status);
CREATE INDEX idx_deletion_requested_at ON data_deletion_requests(requested_at);

-- RLS for deletion requests
ALTER TABLE data_deletion_requests ENABLE ROW LEVEL SECURITY;

CREATE POLICY data_deletion_user_isolation ON data_deletion_requests
    FOR ALL
    USING (user_id = current_setting('app.current_user_uuid')::UUID);

-- ============================================================================
-- DATA EXPORT REQUESTS TABLE (GDPR/CCPA)
-- ============================================================================
-- Tracks data export requests for compliance
CREATE TABLE data_export_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    request_id TEXT NOT NULL UNIQUE,
    formats TEXT[] NOT NULL DEFAULT ARRAY['json'], -- json, csv, pdf
    status TEXT NOT NULL DEFAULT 'pending', -- pending, processing, ready, expired
    download_url TEXT,
    download_expires_at TIMESTAMPTZ,
    requested_at TIMESTAMPTZ DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    ip_address INET
);

-- Add comments
COMMENT ON TABLE data_export_requests IS 'Tracks GDPR/CCPA data portability/export requests';
COMMENT ON COLUMN data_export_requests.formats IS 'Requested export formats: json, csv, pdf';

-- Indexes for export requests
CREATE INDEX idx_export_user ON data_export_requests(user_id);
CREATE INDEX idx_export_status ON data_export_requests(status);
CREATE INDEX idx_export_requested_at ON data_export_requests(requested_at);

-- RLS for export requests
ALTER TABLE data_export_requests ENABLE ROW LEVEL SECURITY;

CREATE POLICY data_export_user_isolation ON data_export_requests
    FOR ALL
    USING (user_id = current_setting('app.current_user_uuid')::UUID);

-- ============================================================================
-- BLOCK ATTEMPTS TABLE
-- ============================================================================
-- Logs blocked scan attempts for security monitoring
CREATE TABLE block_attempts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    target TEXT NOT NULL,
    reason TEXT NOT NULL,
    ip_address INET,
    user_agent TEXT,
    attempted_at TIMESTAMPTZ DEFAULT NOW()
);

-- Add comments
COMMENT ON TABLE block_attempts IS 'Logs blocked scan attempts for security and compliance';

-- Indexes for block attempts
CREATE INDEX idx_blocks_user ON block_attempts(user_id);
CREATE INDEX idx_blocks_target ON block_attempts(target);
CREATE INDEX idx_blocks_attempted_at ON block_attempts(attempted_at);
CREATE INDEX idx_blocks_reason ON block_attempts(reason);

-- RLS for block attempts
ALTER TABLE block_attempts ENABLE ROW LEVEL SECURITY;

CREATE POLICY block_attempts_user_isolation ON block_attempts
    FOR SELECT
    USING (
        user_id = current_setting('app.current_user_uuid')::UUID
        OR current_setting('app.is_admin')::boolean = true
    );

-- ============================================================================
-- AUTHORIZATION CONFIRMATIONS TABLE
-- ============================================================================
-- Detailed authorization confirmations for legal protection
CREATE TABLE authorization_confirmations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    scan_job_id UUID REFERENCES scan_jobs(id) ON DELETE CASCADE,
    confirmed BOOLEAN NOT NULL DEFAULT false,
    confirmed_at TIMESTAMPTZ,
    ip_address INET,
    user_agent TEXT,
    legal_basis TEXT DEFAULT 'explicit_authorization_checkbox',
    scope_description TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Add comments
COMMENT ON TABLE authorization_confirmations IS 'Stores legal authorization confirmations for scans';
COMMENT ON COLUMN authorization_confirmations.legal_basis IS 'Legal basis for authorization (e.g., explicit_checkbox)';

-- Indexes for authorizations
CREATE INDEX idx_auth_user ON authorization_confirmations(user_id);
CREATE INDEX idx_auth_scan ON authorization_confirmations(scan_job_id);
CREATE INDEX idx_auth_confirmed_at ON authorization_confirmations(confirmed_at);

-- RLS for authorizations
ALTER TABLE authorization_confirmations ENABLE ROW LEVEL SECURITY;

CREATE POLICY authorization_confirmations_user_isolation ON authorization_confirmations
    FOR ALL
    USING (user_id = current_setting('app.current_user_uuid')::UUID);

-- ============================================================================
-- HELPER FUNCTIONS
-- ============================================================================

-- Function to check if user has accepted current ToS
CREATE OR REPLACE FUNCTION has_user_accepted_tos(
    p_user_id UUID,
    p_version TEXT DEFAULT '1.0.0'
)
RETURNS BOOLEAN AS $$
DECLARE
    v_accepted BOOLEAN;
BEGIN
    SELECT EXISTS (
        SELECT 1 FROM tos_acceptances
        WHERE user_id = p_user_id
        AND version = p_version
    ) INTO v_accepted;
    
    RETURN COALESCE(v_accepted, false);
END;
$$ LANGUAGE plpgsql STABLE;

-- Function to get user's ToS status
CREATE OR REPLACE FUNCTION get_user_tos_status(
    p_user_id UUID,
    p_current_version TEXT DEFAULT '1.0.0'
)
RETURNS TABLE (
    accepted BOOLEAN,
    current_version TEXT,
    accepted_version TEXT,
    up_to_date BOOLEAN,
    accepted_at TIMESTAMPTZ
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        ta.id IS NOT NULL as accepted,
        p_current_version as current_version,
        ta.version as accepted_version,
        ta.version = p_current_version as up_to_date,
        ta.accepted_at
    FROM (SELECT 1) AS dummy
    LEFT JOIN tos_acceptances ta ON ta.user_id = p_user_id;
END;
$$ LANGUAGE plpgsql STABLE;

-- Function to check if user can perform scan (has accepted ToS)
CREATE OR REPLACE FUNCTION can_user_scan(p_user_id UUID)
RETURNS BOOLEAN AS $$
BEGIN
    RETURN has_user_accepted_tos(p_user_id);
END;
$$ LANGUAGE plpgsql STABLE;

-- Function to get audit log statistics
CREATE OR REPLACE FUNCTION get_audit_stats(
    p_user_id UUID DEFAULT NULL,
    p_days INTEGER DEFAULT 30
)
RETURNS TABLE (
    event_type TEXT,
    event_count BIGINT
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        al.event_type,
        COUNT(*) as event_count
    FROM audit_logs al
    WHERE al.created_at >= NOW() - (p_days || ' days')::INTERVAL
    AND (p_user_id IS NULL OR al.user_id = p_user_id)
    GROUP BY al.event_type
    ORDER BY event_count DESC;
END;
$$ LANGUAGE plpgsql STABLE;

-- ============================================================================
-- VIEWS FOR COMPLIANCE REPORTING
-- ============================================================================

-- View for audit log summary
CREATE VIEW audit_log_summary AS
SELECT 
    DATE_TRUNC('day', created_at) as date,
    event_type,
    COUNT(*) as event_count
FROM audit_logs
GROUP BY DATE_TRUNC('day', created_at), event_type
ORDER BY date DESC, event_count DESC;

-- View for compliance overview
CREATE VIEW compliance_overview AS
SELECT 
    u.id as user_id,
    u.clerk_user_id,
    u.tier,
    u.created_at as user_created_at,
    ta.accepted_at as tos_accepted_at,
    ta.version as tos_version,
    ta.accepted_at IS NOT NULL as has_accepted_tos,
    (SELECT COUNT(*) FROM audit_logs al WHERE al.user_id = u.id) as audit_log_count,
    (SELECT COUNT(*) FROM scan_jobs sj WHERE sj.user_id = u.id) as scan_count,
    (SELECT COUNT(*) FROM block_attempts ba WHERE ba.user_id = u.id) as block_attempt_count
FROM users u
LEFT JOIN tos_acceptances ta ON ta.user_id = u.id;

-- ============================================================================
-- MIGRATION COMPLETION
-- ============================================================================

-- Add migration record
INSERT INTO schema_migrations (version, description, applied_at)
VALUES (
    '003_add_compliance',
    'Added compliance tables: audit_logs, tos_acceptances, user_consents, data_deletion_requests, data_export_requests, block_attempts, authorization_confirmations',
    NOW()
);

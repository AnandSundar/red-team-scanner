-- =============================================================================
-- Red Team Scanner - Initial Schema Migration
-- Phase 3: Database Layer
-- =============================================================================

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- =============================================================================
-- Enum Types (as CHECK constraints will be used instead for flexibility)
-- =============================================================================

-- Note: Using TEXT with CHECK constraints for enums as per specification

-- =============================================================================
-- Base Tables
-- =============================================================================

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    clerk_user_id TEXT UNIQUE NOT NULL,
    tier TEXT NOT NULL DEFAULT 'free' CHECK (tier IN ('free', 'pro', 'team', 'enterprise')),
    api_key TEXT UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Scan Jobs table
CREATE TABLE IF NOT EXISTS scan_jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    target TEXT NOT NULL,
    target_type TEXT NOT NULL DEFAULT 'domain' CHECK (target_type IN ('domain', 'ip', 'url', 'cidr')),
    scope TEXT NOT NULL DEFAULT 'standard' CHECK (scope IN ('quick', 'standard', 'full')),
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'completed', 'failed', 'cancelled')),
    auth_confirmed BOOLEAN NOT NULL DEFAULT false,
    auth_confirmed_ip TEXT,
    auth_confirmed_at TIMESTAMPTZ,
    custom_headers JSONB DEFAULT '{}',
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    risk_score INTEGER CHECK (risk_score >= 0 AND risk_score <= 100),
    finding_counts JSONB DEFAULT '{"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Findings table
CREATE TABLE IF NOT EXISTS findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_job_id UUID NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
    module TEXT NOT NULL,
    category TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('Critical', 'High', 'Medium', 'Low', 'Informational')),
    cvss_score DECIMAL(3,1) CHECK (cvss_score >= 0.0 AND cvss_score <= 10.0),
    cvss_vector TEXT,
    owasp_standard TEXT,
    owasp_agentic TEXT,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    raw_evidence TEXT,
    business_impact TEXT,
    remediation TEXT,
    remediation_effort TEXT CHECK (remediation_effort IN ('Low', 'Medium', 'High')),
    references JSONB DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Reports table
CREATE TABLE IF NOT EXISTS reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_job_id UUID NOT NULL UNIQUE REFERENCES scan_jobs(id) ON DELETE CASCADE,
    pdf_url TEXT,
    json_url TEXT,
    share_token TEXT UNIQUE,
    share_expires_at TIMESTAMPTZ,
    executive_summary TEXT,
    remediation_roadmap JSONB DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- =============================================================================
-- Indexes for Performance
-- =============================================================================

-- Users indexes
CREATE INDEX IF NOT EXISTS idx_users_clerk_user_id ON users(clerk_user_id);
CREATE INDEX IF NOT EXISTS idx_users_api_key ON users(api_key);

-- Scan Jobs indexes
CREATE INDEX IF NOT EXISTS idx_scan_jobs_user_id ON scan_jobs(user_id);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_status ON scan_jobs(status);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_target ON scan_jobs(target);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_created_at ON scan_jobs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_user_created ON scan_jobs(user_id, created_at DESC);

-- Findings indexes
CREATE INDEX IF NOT EXISTS idx_findings_scan_job_id ON findings(scan_job_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_module ON findings(module);
CREATE INDEX IF NOT EXISTS idx_findings_category ON findings(category);
CREATE INDEX IF NOT EXISTS idx_findings_created_at ON findings(created_at DESC);

-- Reports indexes
CREATE INDEX IF NOT EXISTS idx_reports_scan_job_id ON reports(scan_job_id);
CREATE INDEX IF NOT EXISTS idx_reports_share_token ON reports(share_token);

-- GIN indexes for JSONB columns
CREATE INDEX IF NOT EXISTS idx_scan_jobs_finding_counts ON scan_jobs USING GIN(finding_counts);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_custom_headers ON scan_jobs USING GIN(custom_headers);
CREATE INDEX IF NOT EXISTS idx_findings_references ON findings USING GIN(references);
CREATE INDEX IF NOT EXISTS idx_reports_remediation_roadmap ON reports USING GIN(remediation_roadmap);

-- =============================================================================
-- Row Level Security (RLS) Policies
-- =============================================================================

-- Enable RLS on all tables
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE scan_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE reports ENABLE ROW LEVEL SECURITY;

-- Users RLS policies
CREATE POLICY users_select_own ON users
    FOR SELECT
    USING (clerk_user_id = current_setting('app.current_user_id', true) OR
           id = current_setting('app.current_user_uuid', true)::UUID);

CREATE POLICY users_update_own ON users
    FOR UPDATE
    USING (clerk_user_id = current_setting('app.current_user_id', true));

-- Scan Jobs RLS policies
CREATE POLICY scan_jobs_select_own ON scan_jobs
    FOR SELECT
    USING (user_id = current_setting('app.current_user_uuid', true)::UUID);

CREATE POLICY scan_jobs_insert_own ON scan_jobs
    FOR INSERT
    WITH CHECK (user_id = current_setting('app.current_user_uuid', true)::UUID);

CREATE POLICY scan_jobs_update_own ON scan_jobs
    FOR UPDATE
    USING (user_id = current_setting('app.current_user_uuid', true)::UUID);

CREATE POLICY scan_jobs_delete_own ON scan_jobs
    FOR DELETE
    USING (user_id = current_setting('app.current_user_uuid', true)::UUID);

-- Findings RLS policies (access through scan_jobs)
CREATE POLICY findings_select_own ON findings
    FOR SELECT
    USING (EXISTS (
        SELECT 1 FROM scan_jobs 
        WHERE scan_jobs.id = findings.scan_job_id 
        AND scan_jobs.user_id = current_setting('app.current_user_uuid', true)::UUID
    ));

CREATE POLICY findings_insert_own ON findings
    FOR INSERT
    WITH CHECK (EXISTS (
        SELECT 1 FROM scan_jobs 
        WHERE scan_jobs.id = findings.scan_job_id 
        AND scan_jobs.user_id = current_setting('app.current_user_uuid', true)::UUID
    ));

CREATE POLICY findings_update_own ON findings
    FOR UPDATE
    USING (EXISTS (
        SELECT 1 FROM scan_jobs 
        WHERE scan_jobs.id = findings.scan_job_id 
        AND scan_jobs.user_id = current_setting('app.current_user_uuid', true)::UUID
    ));

CREATE POLICY findings_delete_own ON findings
    FOR DELETE
    USING (EXISTS (
        SELECT 1 FROM scan_jobs 
        WHERE scan_jobs.id = findings.scan_job_id 
        AND scan_jobs.user_id = current_setting('app.current_user_uuid', true)::UUID
    ));

-- Reports RLS policies (access through scan_jobs)
CREATE POLICY reports_select_own ON reports
    FOR SELECT
    USING (EXISTS (
        SELECT 1 FROM scan_jobs 
        WHERE scan_jobs.id = reports.scan_job_id 
        AND scan_jobs.user_id = current_setting('app.current_user_uuid', true)::UUID
    ));

CREATE POLICY reports_insert_own ON reports
    FOR INSERT
    WITH CHECK (EXISTS (
        SELECT 1 FROM scan_jobs 
        WHERE scan_jobs.id = reports.scan_job_id 
        AND scan_jobs.user_id = current_setting('app.current_user_uuid', true)::UUID
    ));

CREATE POLICY reports_update_own ON reports
    FOR UPDATE
    USING (EXISTS (
        SELECT 1 FROM scan_jobs 
        WHERE scan_jobs.id = reports.scan_job_id 
        AND scan_jobs.user_id = current_setting('app.current_user_uuid', true)::UUID
    ));

CREATE POLICY reports_delete_own ON reports
    FOR DELETE
    USING (EXISTS (
        SELECT 1 FROM scan_jobs 
        WHERE scan_jobs.id = reports.scan_job_id 
        AND scan_jobs.user_id = current_setting('app.current_user_uuid', true)::UUID
    ));

-- Public access policy for shared reports (via share_token)
CREATE POLICY reports_public_share ON reports
    FOR SELECT
    USING (share_token IS NOT NULL AND share_expires_at > NOW());

-- =============================================================================
-- Triggers for updated_at functionality
-- =============================================================================

-- Create updated_at trigger function
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Note: scan_jobs, findings, and reports don't have updated_at columns per spec
-- but users table can have one for api_key updates
ALTER TABLE users ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

CREATE TRIGGER update_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- =============================================================================
-- Helper Functions
-- =============================================================================

-- Function to generate API key
CREATE OR REPLACE FUNCTION generate_api_key()
RETURNS TEXT AS $$
BEGIN
    RETURN 'rt_' || encode(gen_random_bytes(32), 'hex');
END;
$$ LANGUAGE plpgsql;

-- Function to generate share token
CREATE OR REPLACE FUNCTION generate_share_token()
RETURNS TEXT AS $$
BEGIN
    RETURN encode(gen_random_bytes(16), 'hex');
END;
$$ LANGUAGE plpgsql;

-- Function to calculate risk score based on findings
CREATE OR REPLACE FUNCTION calculate_risk_score(p_scan_job_id UUID)
RETURNS INTEGER AS $$
DECLARE
    v_score INTEGER := 0;
    v_critical INTEGER;
    v_high INTEGER;
    v_medium INTEGER;
BEGIN
    SELECT 
        COALESCE((finding_counts->>'critical')::INTEGER, 0),
        COALESCE((finding_counts->>'high')::INTEGER, 0),
        COALESCE((finding_counts->>'medium')::INTEGER, 0)
    INTO v_critical, v_high, v_medium
    FROM scan_jobs
    WHERE id = p_scan_job_id;
    
    -- Risk score calculation: critical=25, high=10, medium=3
    v_score := (v_critical * 25) + (v_high * 10) + (v_medium * 3);
    
    -- Cap at 100
    IF v_score > 100 THEN
        v_score := 100;
    END IF;
    
    RETURN v_score;
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- Comments for Documentation
-- =============================================================================

COMMENT ON TABLE users IS 'Application users mapped from Clerk authentication';
COMMENT ON TABLE scan_jobs IS 'Security scan jobs created by users';
COMMENT ON TABLE findings IS 'Security findings discovered during scans';
COMMENT ON TABLE reports IS 'Generated scan reports in various formats';

COMMENT ON COLUMN users.clerk_user_id IS 'External user ID from Clerk authentication service';
COMMENT ON COLUMN users.tier IS 'Subscription tier: free, pro, team, enterprise';
COMMENT ON COLUMN users.api_key IS 'API key for programmatic access';

COMMENT ON COLUMN scan_jobs.target IS 'The target domain, IP, URL, or CIDR to scan';
COMMENT ON COLUMN scan_jobs.target_type IS 'Type of target: domain, ip, url, cidr';
COMMENT ON COLUMN scan_jobs.scope IS 'Scan scope: quick, standard, full';
COMMENT ON COLUMN scan_jobs.auth_confirmed IS 'Whether target ownership has been verified';
COMMENT ON COLUMN scan_jobs.finding_counts IS 'JSON object with counts by severity';

COMMENT ON COLUMN findings.severity IS 'Finding severity: Critical, High, Medium, Low, Informational';
COMMENT ON COLUMN findings.cvss_score IS 'CVSS v3.1 score (0.0-10.0)';
COMMENT ON COLUMN findings.cvss_vector IS 'CVSS v3.1 vector string';
COMMENT ON COLUMN findings.owasp_standard IS 'OWASP Top 10 (2021) category';
COMMENT ON COLUMN findings.owasp_agentic IS 'OWASP Agentic AI category';
COMMENT ON COLUMN findings.remediation_effort IS 'Estimated effort: Low, Medium, High';

COMMENT ON COLUMN reports.share_token IS 'Public share token for report access';
COMMENT ON COLUMN reports.share_expires_at IS 'Expiration time for public share link';
COMMENT ON COLUMN reports.executive_summary IS 'AI-generated executive summary';
COMMENT ON COLUMN reports.remediation_roadmap IS 'Prioritized remediation steps';

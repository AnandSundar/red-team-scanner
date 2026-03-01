-- =============================================================================
-- Red Team Scanner Database Initialization
-- =============================================================================
-- This script is automatically executed when PostgreSQL container starts
-- for the first time. It sets up extensions, users, and initial schema.
-- =============================================================================

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Create application-specific user (separate from postgres superuser)
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'redteam_app') THEN
        CREATE ROLE redteam_app WITH LOGIN PASSWORD 'redteam_app_password';
    END IF;
END
$$;

-- Grant necessary permissions to application user
GRANT CONNECT ON DATABASE redteam TO redteam_app;

-- Create schema if it doesn't exist
CREATE SCHEMA IF NOT EXISTS redteam;

-- Grant schema permissions
GRANT USAGE ON SCHEMA redteam TO redteam_app;
GRANT CREATE ON SCHEMA redteam TO redteam_app;

-- Set default privileges for future objects
ALTER DEFAULT PRIVILEGES IN SCHEMA redteam GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO redteam_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA redteam GRANT USAGE ON SEQUENCES TO redteam_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA redteam GRANT EXECUTE ON FUNCTIONS TO redteam_app;

-- =============================================================================
-- Enum Types
-- =============================================================================

-- Scan status enumeration
CREATE TYPE redteam.scan_status AS ENUM (
    'pending',
    'running',
    'paused',
    'completed',
    'failed',
    'cancelled'
);

-- Scan module types
CREATE TYPE redteam.scan_module AS ENUM (
    'reconnaissance',
    'web_scanning',
    'api_testing',
    'agentic_exploitation',
    'intelligence_gathering'
);

-- Finding severity levels
CREATE TYPE redteam.severity_level AS ENUM (
    'info',
    'low',
    'medium',
    'high',
    'critical'
);

-- Finding confidence levels
CREATE TYPE redteam.confidence_level AS ENUM (
    'low',
    'medium',
    'high',
    'confirmed'
);

-- Report format types
CREATE TYPE redteam.report_format AS ENUM (
    'json',
    'pdf',
    'html',
    'markdown'
);

-- Task queue status
CREATE TYPE redteam.task_status AS ENUM (
    'pending',
    'processing',
    'retrying',
    'completed',
    'failed',
    'archived'
);

-- =============================================================================
-- Base Tables (Initial Structure)
-- =============================================================================

-- Organizations table
CREATE TABLE IF NOT EXISTS redteam.organizations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(100) UNIQUE NOT NULL,
    clerk_org_id VARCHAR(255) UNIQUE,
    settings JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Users table
CREATE TABLE IF NOT EXISTS redteam.users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(255) UNIQUE NOT NULL,
    clerk_user_id VARCHAR(255) UNIQUE,
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    organization_id UUID REFERENCES redteam.organizations(id) ON DELETE SET NULL,
    role VARCHAR(50) DEFAULT 'member',
    settings JSONB DEFAULT '{}',
    last_login_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Scans table
CREATE TABLE IF NOT EXISTS redteam.scans (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    target VARCHAR(512) NOT NULL,
    description TEXT,
    status redteam.scan_status DEFAULT 'pending',
    modules redteam.scan_module[] DEFAULT ARRAY[]::redteam.scan_module[],
    organization_id UUID REFERENCES redteam.organizations(id) ON DELETE CASCADE,
    created_by UUID REFERENCES redteam.users(id) ON DELETE SET NULL,
    started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,
    progress_percent INTEGER DEFAULT 0,
    configuration JSONB DEFAULT '{}',
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Findings table
CREATE TABLE IF NOT EXISTS redteam.findings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID REFERENCES redteam.scans(id) ON DELETE CASCADE,
    title VARCHAR(500) NOT NULL,
    description TEXT,
    severity redteam.severity_level DEFAULT 'info',
    confidence redteam.confidence_level DEFAULT 'medium',
    module redteam.scan_module NOT NULL,
    category VARCHAR(100),
    cwe_id INTEGER,
    cve_id VARCHAR(50),
    cvss_score DECIMAL(3,1),
    evidence JSONB DEFAULT '[]',
    remediation TEXT,
    references JSONB DEFAULT '[]',
    verified BOOLEAN DEFAULT false,
    false_positive BOOLEAN DEFAULT false,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Reports table
CREATE TABLE IF NOT EXISTS redteam.reports (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID REFERENCES redteam.scans(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    format redteam.report_format DEFAULT 'pdf',
    file_path VARCHAR(512),
    file_size BIGINT,
    checksum VARCHAR(64),
    generated_by UUID REFERENCES redteam.users(id) ON DELETE SET NULL,
    settings JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Audit log table
CREATE TABLE IF NOT EXISTS redteam.audit_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID REFERENCES redteam.organizations(id) ON DELETE CASCADE,
    user_id UUID REFERENCES redteam.users(id) ON DELETE SET NULL,
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(100) NOT NULL,
    resource_id UUID,
    details JSONB DEFAULT '{}',
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- =============================================================================
-- Indexes
-- =============================================================================

-- Performance indexes
CREATE INDEX IF NOT EXISTS idx_scans_organization ON redteam.scans(organization_id);
CREATE INDEX IF NOT EXISTS idx_scans_status ON redteam.scans(status);
CREATE INDEX IF NOT EXISTS idx_scans_created_at ON redteam.scans(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON redteam.findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON redteam.findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_module ON redteam.findings(module);
CREATE INDEX IF NOT EXISTS idx_users_organization ON redteam.users(organization_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_organization ON redteam.audit_log(organization_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON redteam.audit_log(created_at DESC);

-- GIN indexes for JSONB columns
CREATE INDEX IF NOT EXISTS idx_scans_configuration ON redteam.scans USING GIN(configuration);
CREATE INDEX IF NOT EXISTS idx_findings_evidence ON redteam.findings USING GIN(evidence);
CREATE INDEX IF NOT EXISTS idx_findings_metadata ON redteam.findings USING GIN(metadata);

-- =============================================================================
-- Row Level Security (RLS) Policies
-- =============================================================================

-- Enable RLS on tables
ALTER TABLE redteam.organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE redteam.users ENABLE ROW LEVEL SECURITY;
ALTER TABLE redteam.scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE redteam.findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE redteam.reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE redteam.audit_log ENABLE ROW LEVEL SECURITY;

-- Create basic RLS policies (these will be refined by the application)
CREATE POLICY organization_isolation ON redteam.organizations
    FOR ALL TO redteam_app
    USING (id = current_setting('app.current_org_id')::UUID);

-- =============================================================================
-- Functions
-- =============================================================================

-- Update timestamp trigger function
CREATE OR REPLACE FUNCTION redteam.update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply update triggers
CREATE TRIGGER update_organizations_updated_at
    BEFORE UPDATE ON redteam.organizations
    FOR EACH ROW EXECUTE FUNCTION redteam.update_updated_at_column();

CREATE TRIGGER update_users_updated_at
    BEFORE UPDATE ON redteam.users
    FOR EACH ROW EXECUTE FUNCTION redteam.update_updated_at_column();

CREATE TRIGGER update_scans_updated_at
    BEFORE UPDATE ON redteam.scans
    FOR EACH ROW EXECUTE FUNCTION redteam.update_updated_at_column();

CREATE TRIGGER update_findings_updated_at
    BEFORE UPDATE ON redteam.findings
    FOR EACH ROW EXECUTE FUNCTION redteam.update_updated_at_column();

-- =============================================================================
-- Initial Data
-- =============================================================================

-- Create default organization
INSERT INTO redteam.organizations (name, slug, settings)
VALUES ('Default Organization', 'default', '{"is_default": true}'::jsonb)
ON CONFLICT (slug) DO NOTHING;

-- Log initialization
INSERT INTO redteam.audit_log (action, resource_type, details)
VALUES ('database_initialized', 'system', '{"version": "1.0.0"}'::jsonb);

-- Grant all table permissions to app user
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA redteam TO redteam_app;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA redteam TO redteam_app;

-- Comment for documentation
COMMENT ON SCHEMA redteam IS 'Red Team Scanner application schema';

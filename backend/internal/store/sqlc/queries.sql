-- =============================================================================
-- Red Team Scanner - SQL Queries for sqlc
-- Phase 3: Database Layer
-- =============================================================================

-- =============================================================================
-- Users Queries
-- =============================================================================

-- name: CreateUser :one
INSERT INTO users (
    clerk_user_id, tier, api_key, created_at
) VALUES (
    $1, $2, $3, NOW()
)
RETURNING *;

-- name: GetUserByID :one
SELECT * FROM users
WHERE id = $1;

-- name: GetUserByClerkID :one
SELECT * FROM users
WHERE clerk_user_id = $1;

-- name: GetUserByAPIKey :one
SELECT * FROM users
WHERE api_key = $1;

-- name: UpdateUserTier :one
UPDATE users
SET tier = $2, updated_at = NOW()
WHERE id = $1
RETURNING *;

-- name: UpdateUserAPIKey :one
UPDATE users
SET api_key = $2, updated_at = NOW()
WHERE id = $1
RETURNING *;

-- name: DeleteUser :exec
DELETE FROM users
WHERE id = $1;

-- =============================================================================
-- Scan Jobs Queries
-- =============================================================================

-- name: CreateScanJob :one
INSERT INTO scan_jobs (
    user_id, target, target_type, scope, status, 
    auth_confirmed, auth_confirmed_ip, custom_headers,
    started_at, completed_at, risk_score, finding_counts
) VALUES (
    $1, $2, $3, $4, $5,
    $6, $7, $8,
    $9, $10, $11, $12
)
RETURNING *;

-- name: GetScanJobByID :one
SELECT * FROM scan_jobs
WHERE id = $1;

-- name: ListScanJobsByUser :many
SELECT * FROM scan_jobs
WHERE user_id = $1
ORDER BY created_at DESC
LIMIT $2 OFFSET $3;

-- name: CountScanJobsByUser :one
SELECT COUNT(*) FROM scan_jobs
WHERE user_id = $1;

-- name: ListScanJobsByUserAndStatus :many
SELECT * FROM scan_jobs
WHERE user_id = $1 AND status = $2
ORDER BY created_at DESC
LIMIT $3 OFFSET $4;

-- name: ListRecentScanJobsByUser :many
SELECT * FROM scan_jobs
WHERE user_id = $1
ORDER BY created_at DESC
LIMIT $2;

-- name: UpdateScanJobStatus :one
UPDATE scan_jobs
SET status = $2
WHERE id = $1
RETURNING *;

-- name: UpdateScanJobStarted :one
UPDATE scan_jobs
SET status = 'running', started_at = NOW()
WHERE id = $1
RETURNING *;

-- name: UpdateScanJobCompleted :one
UPDATE scan_jobs
SET status = 'completed', completed_at = NOW(), risk_score = $2, finding_counts = $3
WHERE id = $1
RETURNING *;

-- name: UpdateScanJobFailed :one
UPDATE scan_jobs
SET status = 'failed', completed_at = NOW()
WHERE id = $1
RETURNING *;

-- name: UpdateScanJobAuthConfirmed :one
UPDATE scan_jobs
SET auth_confirmed = true, auth_confirmed_ip = $2, auth_confirmed_at = NOW()
WHERE id = $1
RETURNING *;

-- name: UpdateScanJobFindingCounts :one
UPDATE scan_jobs
SET finding_counts = $2, risk_score = calculate_risk_score($1)
WHERE id = $1
RETURNING *;

-- name: DeleteScanJob :exec
DELETE FROM scan_jobs
WHERE id = $1;

-- name: DeleteScanJobsByUser :exec
DELETE FROM scan_jobs
WHERE user_id = $1;

-- =============================================================================
-- Findings Queries
-- =============================================================================

-- name: CreateFinding :one
INSERT INTO findings (
    scan_job_id, module, category, severity, cvss_score, cvss_vector,
    owasp_standard, owasp_agentic, title, description, raw_evidence,
    business_impact, remediation, remediation_effort, references
) VALUES (
    $1, $2, $3, $4, $5, $6,
    $7, $8, $9, $10, $11,
    $12, $13, $14, $15
)
RETURNING *;

-- name: CreateFindingsBulk :copyfrom
INSERT INTO findings (
    scan_job_id, module, category, severity, cvss_score, cvss_vector,
    owasp_standard, owasp_agentic, title, description, raw_evidence,
    business_impact, remediation, remediation_effort, references
) VALUES (
    $1, $2, $3, $4, $5, $6,
    $7, $8, $9, $10, $11,
    $12, $13, $14, $15
);

-- name: GetFindingByID :one
SELECT * FROM findings
WHERE id = $1;

-- name: ListFindingsByScanJob :many
SELECT * FROM findings
WHERE scan_job_id = $1
ORDER BY 
    CASE severity
        WHEN 'Critical' THEN 1
        WHEN 'High' THEN 2
        WHEN 'Medium' THEN 3
        WHEN 'Low' THEN 4
        WHEN 'Informational' THEN 5
    END,
    created_at DESC
LIMIT $2 OFFSET $3;

-- name: ListFindingsByScanJobAndSeverity :many
SELECT * FROM findings
WHERE scan_job_id = $1 AND severity = $2
ORDER BY created_at DESC
LIMIT $3 OFFSET $4;

-- name: CountFindingsByScanJob :one
SELECT COUNT(*) FROM findings
WHERE scan_job_id = $1;

-- name: CountFindingsBySeverity :many
SELECT severity, COUNT(*) as count
FROM findings
WHERE scan_job_id = $1
GROUP BY severity
ORDER BY 
    CASE severity
        WHEN 'Critical' THEN 1
        WHEN 'High' THEN 2
        WHEN 'Medium' THEN 3
        WHEN 'Low' THEN 4
        WHEN 'Informational' THEN 5
    END;

-- name: ListFindingsByCategory :many
SELECT * FROM findings
WHERE scan_job_id = $1 AND category = $2
ORDER BY created_at DESC;

-- name: ListFindingsByModule :many
SELECT * FROM findings
WHERE scan_job_id = $1 AND module = $2
ORDER BY created_at DESC;

-- name: UpdateFinding :one
UPDATE findings
SET 
    severity = $2,
    cvss_score = $3,
    cvss_vector = $4,
    title = $5,
    description = $6,
    raw_evidence = $7,
    business_impact = $8,
    remediation = $9,
    remediation_effort = $10
WHERE id = $1
RETURNING *;

-- name: DeleteFinding :exec
DELETE FROM findings
WHERE id = $1;

-- name: DeleteFindingsByScanJob :exec
DELETE FROM findings
WHERE scan_job_id = $1;

-- =============================================================================
-- Reports Queries
-- =============================================================================

-- name: CreateReport :one
INSERT INTO reports (
    scan_job_id, pdf_url, json_url, share_token, share_expires_at,
    executive_summary, remediation_roadmap
) VALUES (
    $1, $2, $3, $4, $5,
    $6, $7
)
RETURNING *;

-- name: GetReportByID :one
SELECT * FROM reports
WHERE id = $1;

-- name: GetReportByScanJobID :one
SELECT * FROM reports
WHERE scan_job_id = $1;

-- name: GetReportByShareToken :one
SELECT * FROM reports
WHERE share_token = $1 AND (share_expires_at IS NULL OR share_expires_at > NOW());

-- name: ListReportsByScanJobs :many
SELECT r.* FROM reports r
INNER JOIN scan_jobs sj ON r.scan_job_id = sj.id
WHERE sj.user_id = $1
ORDER BY r.created_at DESC
LIMIT $2 OFFSET $3;

-- name: UpdateReport :one
UPDATE reports
SET 
    pdf_url = $2,
    json_url = $3,
    executive_summary = $4,
    remediation_roadmap = $5
WHERE id = $1
RETURNING *;

-- name: UpdateReportShareToken :one
UPDATE reports
SET share_token = $2, share_expires_at = $3
WHERE id = $1
RETURNING *;

-- name: RevokeReportShare :one
UPDATE reports
SET share_token = NULL, share_expires_at = NULL
WHERE id = $1
RETURNING *;

-- name: UpdateReportURLs :one
UPDATE reports
SET pdf_url = $2, json_url = $3
WHERE id = $1
RETURNING *;

-- name: DeleteReport :exec
DELETE FROM reports
WHERE id = $1;

-- name: DeleteReportByScanJob :exec
DELETE FROM reports
WHERE scan_job_id = $1;

-- =============================================================================
-- Dashboard & Analytics Queries
-- =============================================================================

-- name: GetUserScanStats :one
SELECT 
    COUNT(*) as total_scans,
    COUNT(*) FILTER (WHERE status = 'completed') as completed_scans,
    COUNT(*) FILTER (WHERE status = 'failed') as failed_scans,
    COUNT(*) FILTER (WHERE status = 'running') as running_scans,
    COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '30 days') as scans_last_30_days
FROM scan_jobs
WHERE user_id = $1;

-- name: GetUserFindingStats :one
SELECT 
    COUNT(*) as total_findings,
    COUNT(*) FILTER (WHERE severity = 'Critical') as critical_count,
    COUNT(*) FILTER (WHERE severity = 'High') as high_count,
    COUNT(*) FILTER (WHERE severity = 'Medium') as medium_count,
    COUNT(*) FILTER (WHERE severity = 'Low') as low_count,
    COUNT(*) FILTER (WHERE severity = 'Informational') as informational_count
FROM findings f
INNER JOIN scan_jobs sj ON f.scan_job_id = sj.id
WHERE sj.user_id = $1;

-- name: GetScansTrendOverTime :many
SELECT 
    DATE(created_at) as date,
    COUNT(*) as scan_count,
    COUNT(*) FILTER (WHERE status = 'completed') as completed_count,
    COUNT(*) FILTER (WHERE status = 'failed') as failed_count
FROM scan_jobs
WHERE user_id = $1 AND created_at > NOW() - INTERVAL '90 days'
GROUP BY DATE(created_at)
ORDER BY date DESC;

-- name: GetFindingsByCategoryStats :many
SELECT 
    category,
    COUNT(*) as count,
    COUNT(*) FILTER (WHERE severity = 'Critical') as critical_count,
    COUNT(*) FILTER (WHERE severity = 'High') as high_count
FROM findings f
INNER JOIN scan_jobs sj ON f.scan_job_id = sj.id
WHERE sj.user_id = $1
GROUP BY category
ORDER BY count DESC;

-- name: GetTopTargets :many
SELECT 
    target,
    COUNT(*) as scan_count,
    MAX(created_at) as last_scanned_at
FROM scan_jobs
WHERE user_id = $1
GROUP BY target
ORDER BY scan_count DESC
LIMIT $2;

-- name: GetRecentCriticalFindings :many
SELECT f.*, sj.target as scan_target
FROM findings f
INNER JOIN scan_jobs sj ON f.scan_job_id = sj.id
WHERE sj.user_id = $1 AND f.severity IN ('Critical', 'High')
ORDER BY f.created_at DESC
LIMIT $2;

-- =============================================================================
-- Search Queries
-- =============================================================================

-- name: SearchScans :many
SELECT * FROM scan_jobs
WHERE user_id = $1 AND (
    target ILIKE $2 OR
    status ILIKE $2
)
ORDER BY created_at DESC
LIMIT $3 OFFSET $4;

-- name: SearchFindings :many
SELECT f.* FROM findings f
INNER JOIN scan_jobs sj ON f.scan_job_id = sj.id
WHERE sj.user_id = $1 AND (
    f.title ILIKE $2 OR
    f.description ILIKE $2 OR
    f.category ILIKE $2 OR
    f.module ILIKE $2
)
ORDER BY f.created_at DESC
LIMIT $3 OFFSET $4;

-- =============================================================================
-- Cleanup Queries
-- =============================================================================

-- name: DeleteOldScanJobs :exec
DELETE FROM scan_jobs
WHERE user_id = $1 AND created_at < $2;

-- name: CleanupExpiredShares :exec
UPDATE reports
SET share_token = NULL, share_expires_at = NULL
WHERE share_expires_at < NOW();

-- =============================================================================
-- Phase 15: Dashboard & History Queries
-- =============================================================================

-- name: GetScanStatistics :one
SELECT 
    COUNT(*) as total_scans,
    COUNT(*) FILTER (WHERE status = 'completed') as completed_scans,
    COUNT(*) FILTER (WHERE status = 'failed') as failed_scans,
    COUNT(*) FILTER (WHERE status IN ('pending', 'queued', 'running')) as active_scans,
    COUNT(*) FILTER (WHERE created_at > DATE_TRUNC('month', NOW())) as scans_this_month,
    COALESCE(AVG(EXTRACT(EPOCH FROM (completed_at - started_at))) FILTER (WHERE completed_at IS NOT NULL AND started_at IS NOT NULL), 0) as avg_duration_seconds,
    MAX(created_at) as last_scan_at
FROM scan_jobs
WHERE user_id = $1;

-- name: GetFindingsBySeverityStats :one
SELECT 
    COUNT(*) FILTER (WHERE severity = 'Critical') as critical,
    COUNT(*) FILTER (WHERE severity = 'High') as high,
    COUNT(*) FILTER (WHERE severity = 'Medium') as medium,
    COUNT(*) FILTER (WHERE severity = 'Low') as low,
    COUNT(*) FILTER (WHERE severity = 'Informational') as informational
FROM findings f
INNER JOIN scan_jobs sj ON f.scan_job_id = sj.id
WHERE sj.user_id = $1;

-- name: GetScanActivity :many
SELECT 
    sj.id,
    sj.target,
    sj.status,
    COALESCE((SELECT COUNT(*) FROM findings f WHERE f.scan_job_id = sj.id), 0) as findings_count,
    COALESCE(sj.risk_score, 0) / 10.0 as risk_score,
    COALESCE(sj.started_at, sj.created_at) as started_at,
    sj.completed_at
FROM scan_jobs sj
WHERE sj.user_id = $1
ORDER BY sj.created_at DESC
LIMIT $2 OFFSET $3;

-- name: GetVulnerabilityTrends :many
WITH date_series AS (
    SELECT generate_series($2::date, $3::date, '1 day'::interval)::date as date
),
daily_findings AS (
    SELECT 
        DATE(f.created_at) as date,
        COUNT(*) FILTER (WHERE f.severity = 'Critical') as critical,
        COUNT(*) FILTER (WHERE f.severity = 'High') as high,
        COUNT(*) FILTER (WHERE f.severity = 'Medium') as medium,
        COUNT(*) FILTER (WHERE f.severity = 'Low') as low,
        COUNT(*) FILTER (WHERE f.severity = 'Informational') as info
    FROM findings f
    INNER JOIN scan_jobs sj ON f.scan_job_id = sj.id
    WHERE sj.user_id = $1
        AND f.created_at BETWEEN $2 AND $3
    GROUP BY DATE(f.created_at)
)
SELECT 
    ds.date::text,
    COALESCE(df.critical, 0) as critical,
    COALESCE(df.high, 0) as high,
    COALESCE(df.medium, 0) as medium,
    COALESCE(df.low, 0) as low,
    COALESCE(df.info, 0) as info
FROM date_series ds
LEFT JOIN daily_findings df ON ds.date = df.date
ORDER BY ds.date ASC;

-- name: GetMostScannedTargets :many
WITH target_stats AS (
    SELECT 
        target,
        COUNT(*) as scan_count,
        MAX(created_at) as last_scanned_at,
        (
            SELECT id FROM scan_jobs 
            WHERE user_id = $1 AND target = sj.target 
            ORDER BY created_at DESC LIMIT 1
        ) as last_scan_id,
        (
            SELECT status FROM scan_jobs 
            WHERE user_id = $1 AND target = sj.target 
            ORDER BY created_at DESC LIMIT 1
        ) as last_scan_status,
        COALESCE(AVG(risk_score) FILTER (WHERE risk_score > 0), 0) / 10.0 as avg_risk_score
    FROM scan_jobs sj
    WHERE user_id = $1
    GROUP BY target
)
SELECT 
    ts.target,
    ts.scan_count,
    ts.last_scanned_at,
    ts.last_scan_id,
    ts.last_scan_status,
    ts.avg_risk_score,
    COALESCE((
        SELECT COUNT(*) 
        FROM findings f 
        WHERE f.scan_job_id = ts.last_scan_id
    ), 0) as total_findings
FROM target_stats ts
ORDER BY ts.scan_count DESC, ts.last_scanned_at DESC
LIMIT $2;

-- name: GetTargetScanHistory :many
SELECT 
    sj.id, sj.user_id, sj.target, sj.target_type, sj.scope, sj.status,
    sj.auth_confirmed, sj.auth_confirmed_ip, sj.auth_confirmed_at,
    sj.custom_headers, sj.started_at, sj.completed_at, sj.risk_score,
    sj.finding_counts, sj.created_at,
    COALESCE((SELECT COUNT(*) FROM findings f WHERE f.scan_job_id = sj.id), 0) as total_findings
FROM scan_jobs sj
WHERE sj.user_id = $1 AND sj.target = $2
ORDER BY sj.created_at DESC
LIMIT $3 OFFSET $4;

-- name: GetScanFindingsForDiff :many
SELECT 
    id, module, category, severity, title, description,
    COALESCE(cvss_score, 0) as cvss_score, COALESCE(remediation, '') as remediation
FROM findings
WHERE scan_job_id = $1
ORDER BY 
    CASE severity
        WHEN 'Critical' THEN 1
        WHEN 'High' THEN 2
        WHEN 'Medium' THEN 3
        WHEN 'Low' THEN 4
        WHEN 'Informational' THEN 5
    END,
    created_at DESC;

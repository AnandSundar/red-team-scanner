export interface Scan {
    id: string;
    target: string;
    status: "pending" | "running" | "completed" | "failed" | "stopped";
    modules: string[];
    depth: number;
    created_at: string;
    started_at?: string;
    completed_at?: string;
}

export interface Finding {
    id: string;
    scan_id: string;
    title: string;
    description: string;
    severity: "critical" | "high" | "medium" | "low" | "info";
    category: string;
    remediation: string;
    created_at: string;
}

export interface Report {
    id: string;
    scan_id: string;
    target: string;
    risk_score: number;
    findings_summary: {
        total: number;
        critical: number;
        high: number;
        medium: number;
        low: number;
    };
}

export interface Module {
    name: string;
    description: string;
    category: string;
}

export interface ScanEvent {
    type: "status" | "finding" | "progress" | "complete" | "error";
    timestamp: string;
    data: unknown;
}

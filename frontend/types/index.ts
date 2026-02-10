export interface Alert {
    id: number;
    rule_id: string;
    severity: "low" | "medium" | "high" | "critical";
    status: "open" | "triaged" | "closed" | "false_positive";
    summary: string;
    evidence: Record<string, any>;
    alert_time: string;
    window_start: string | null;
    window_end: string | null;
    created_at: string;
    updated_at: string;
}

export interface AllowlistEntry {
    id: number;
    entry_type: "ip" | "actor";
    entry_value: string;
    reason: string;
    rule_id: string | null;
    expires_at: string | null;
    created_by: string | null;
    created_at: string;
}

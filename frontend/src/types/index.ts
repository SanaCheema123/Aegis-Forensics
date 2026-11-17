export type Case = { case_id: string; verified: boolean; message: string; audit_events: number | null }
export type Evidence = { id: string; filename: string; sha256: string; case_id: string; type: string; acquired_at_utc: string; scan_count: number; finding_count: number }
export type Scan = { scan_id: string; case_id: string; scanned_at_utc: string; finding_count: number; models: string[] }
export type Finding = { id: string; source: string; severity: string; description: string; rule?: string; model_name?: string; file: string; recommendation?: string; original_csv_record?: number; original_csv_line?: number; original_csv_line_end?: number; ml_score?: number; score_meaning?: string; review_pending: boolean; [key: string]: unknown }
export type Collection<T> = { items: T[]; total: number; page: number; page_size: number }
export type Job = { id: string; case_id: string; status: 'queued'|'running'|'completed'|'failed'|'cancelled'; phase: string; error?: string; result?: Record<string, any>; progress?: { checked: number; total: number }; cancellable: boolean }
export type Settings = { roots: { id: string; label: string }[]; yara_available: boolean; windows_monitoring: boolean; trust_boundary: string; max_upload_mib: number; max_records: number }

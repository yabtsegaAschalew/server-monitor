from __future__ import annotations

"""SQLite DDL for the Phase 3 diagnostic agent tables."""

DIAGNOSTIC_SCHEMA_DDL = """\
CREATE TABLE IF NOT EXISTS cooldown_state (
    anomaly_type      TEXT PRIMARY KEY,
    last_triggered_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ai_call_log (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    anomaly_type      TEXT    NOT NULL,
    provider          TEXT    NOT NULL,
    model             TEXT    NOT NULL,
    prompt_tokens     INTEGER NOT NULL,
    completion_tokens INTEGER NOT NULL,
    total_tokens      INTEGER NOT NULL,
    success           INTEGER NOT NULL,
    error_message     TEXT,
    created_at        TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ai_call_log_time
    ON ai_call_log(created_at);

CREATE TABLE IF NOT EXISTS proposed_remediation_rules (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    anomaly_type     TEXT    NOT NULL,
    metric_type      TEXT    NOT NULL,
    entity_id        TEXT    NOT NULL,
    action_plan_json TEXT    NOT NULL,
    severity         TEXT    NOT NULL,
    status           TEXT    NOT NULL DEFAULT 'pending',
    created_at       TEXT    NOT NULL,
    reviewed_at      TEXT,
    reviewed_by      TEXT
);
CREATE INDEX IF NOT EXISTS idx_proposed_rules_status
    ON proposed_remediation_rules(status);
CREATE INDEX IF NOT EXISTS idx_proposed_rules_anomaly
    ON proposed_remediation_rules(anomaly_type, created_at);
"""

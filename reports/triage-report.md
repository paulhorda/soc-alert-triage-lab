# Authentication alerts

1,231 generated events. 4 alerts. All times are UTC.

| Rule | Time | Priority | Source | Evidence events |
|---|---|---|---|---|
| AUTH-001 | 2026-09-15T14:04:00Z | medium | 203.0.113.42 | 5 |
| AUTH-003 | 2026-09-15T14:08:00Z | high | 203.0.113.42 | 9 |
| AUTH-002 | 2026-09-15T16:05:00Z | medium | 198.51.100.23 | 6 |
| AUTH-001 | 2026-09-15T17:04:00Z | medium | 10.20.0.250 | 5 |

## Review order

Start with AUTH-003: a successful login follows repeated failures. Check the account, MFA and device context before deciding whether access was unauthorized.

AUTH-002 needs a check of the source and affected accounts. The pattern is consistent with spraying, but passwords are not logged.

AUTH-001 can also result from a stale service credential or typing mistakes. One such benign case is included in this sample.

AUTH-001 and AUTH-003 can refer to the same sequence. Alert counts are not incident counts.

## Evidence

[Alert objects](alerts.json) · [Timeline](evidence_timeline.csv) · [Case notes](../docs/incident-walkthrough.md) · [Triage checklist](../docs/triage-runbook.md)

The slow sequence in the sample produces no alert. Scenario labels are stored separately in `data/scenario_labels.json`; the detector does not read them.

# Authentication triage report

> Generated from fictional events. Signals require investigation; this is not evidence of a real intrusion.

![Detection summary](dashboard.svg)

## Alert queue

| Rule | UTC time | Severity | Source | Evidence events |
|---|---|---|---|---|
| AUTH-001 | 2026-09-15T14:04:00Z | medium | 203.0.113.42 | 5 |
| AUTH-003 | 2026-09-15T14:08:00Z | high | 203.0.113.42 | 9 |
| AUTH-002 | 2026-09-15T16:05:00Z | medium | 198.51.100.23 | 6 |
| AUTH-001 | 2026-09-15T17:04:00Z | medium | 10.20.0.250 | 5 |

## Triage interpretation

- AUTH-003 is the first review priority: a successful login follows repeated failures for the same user, source and service. This could be malicious access or a legitimate user recovering from a password problem.
- AUTH-002 identifies failures across distinct users. Password spraying is a hypothesis; the log does not reveal whether the same password was used.
- AUTH-001 alone can arise from a stale service credential or user mistakes. Source ownership, user confirmation and maintenance records are needed.
- AUTH-001 and AUTH-003 can describe the same sequence; alert count is not incident count.

## Evidence and next steps

[Complete alert evidence](alerts.json) · [Evidence timeline](evidence_timeline.csv) · [Incident walkthrough](../docs/incident-walkthrough.md) · [Triage runbook](../docs/triage-runbook.md)

## Evaluation boundary

The generator includes a benign stale-credential case that alerts and a slow cross-user sequence that the short-window rules miss. Ground-truth scenario labels live separately in `data/scenario_labels.json` and are never read by the detector. Passing these fixtures does not establish production precision, recall or readiness.

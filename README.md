# Authentication alert triage

A Python detector for repeated login failures, attempts against multiple accounts and successful logins after failures.

The sample has 1,231 generated events. It produces four alerts: two for the same suspicious sequence, one for a multi-account sequence and one for a stale service credential. [See the report](reports/triage-report.md).

## Rules

| Rule | Condition |
|---|---|
| AUTH-001 | Five failures within ten minutes for the same user, IP and service |
| AUTH-002 | Failures against six different users within ten minutes from the same IP and service |
| AUTH-003 | A success after at least five failures in the preceding fifteen minutes, for the same user, IP and service |

[Thresholds](rules/auth_rules.json) can be changed. Each rule has a thirty-minute cooldown per scope. Alerts include the event IDs that triggered them; later events suppressed by the cooldown are not added to the original alert.

The failure patterns relate to MITRE ATT&CK [Password Guessing](https://attack.mitre.org/techniques/T1110/001/) and [Password Spraying](https://attack.mitre.org/techniques/T1110/003/). The logs alone cannot establish the password used or whether a successful login was unauthorized.

## Run

Python 3.10 or later. No extra packages.

```bash
python3 src/generate_logs.py
python3 src/detect.py
python3 -m unittest discover -s tests -v
```

To use another file with [the same fields](docs/event-schema.md):

```bash
python3 src/detect.py --input events.jsonl --output local-results
```

## Files worth reading

- [detect.py](src/detect.py) — window logic, validation and deduplication.
- [alerts.json](reports/alerts.json) and [evidence_timeline.csv](reports/evidence_timeline.csv) — the results and supporting events.
- [Case notes](docs/incident-walkthrough.md) — eight failures followed by a success.
- [Triage checklist](docs/triage-runbook.md) — what to check before closing or escalating an alert.
- [Tests](tests/test_detection.py) — window boundaries, duplicate events, separate services and known misses.

## What it misses

Slow attempts and attacks spread across multiple sources can stay below the thresholds. A success from a different IP is not correlated. Shared IPs and outdated service passwords can cause benign alerts.

The sample includes both a benign match and a slow sequence that is missed. It has no MFA or device context. This is an offline lab, not a deployed SIEM integration.

[SQL analysis of the same logs](https://github.com/paulhorda/soc-log-analysis).

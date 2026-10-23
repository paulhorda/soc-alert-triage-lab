# Case study: successful login after repeated failures

**Synthetic exercise.** This is a worked interpretation of the generated sample, not a real investigation or employment record.

## Observed facts

- Account: `analyst_demo`; service: `vpn`; source: `203.0.113.42`.
- Eight failures occur from 14:00 through 14:07 UTC on September 15, 2026.
- A success follows at 14:08 UTC for the same account, source and service.
- AUTH-001 triggers on the fifth failure at 14:04 UTC.
- AUTH-003 triggers at 14:08 UTC and references the eight failures plus the success.

The event IDs are `EVT-01201` through `EVT-01209`. Inspect [the raw events](../data/auth_events.jsonl), [alert objects](../reports/alerts.json) and [timeline](../reports/evidence_timeline.csv) to reproduce these observations.

## Hypotheses

1. Someone guessed a valid credential after repeated failures.
2. A legitimate user corrected a password or configuration problem.
3. The source is a shared egress point, so its relationship to the actor needs verification.

The authentication events alone cannot choose between these explanations. A success is not proof of account takeover.

## Proposed next evidence

Verify MFA outcome, device identity, prior successful source history, account privileges and user confirmation. Correlate the resulting session with administrative changes, unusual downloads or other follow-on behavior. Preserve logs and note missing coverage.

## Disposition

**Escalation candidate pending context**, because success after repeated failures merits review. No account has been disabled and no host has been isolated by this project.

## Contrast case: stale service credential

`svc_backup_demo` fails six times from `10.20.0.250` against `backup-console`. The rule correctly detects the repeated-failure pattern. Separate fixture context says the stored password is outdated; that benign explanation is not inferable from the event fields alone. An actual analyst would confirm ownership and the change record before closing the case.

## Known miss

`192.0.2.90` produces failures for eight users over 140 minutes. No ten-minute window contains six users, so AUTH-002 does not trigger. A longer-window detector could help but would require evaluation against shared-source traffic and normal login noise.

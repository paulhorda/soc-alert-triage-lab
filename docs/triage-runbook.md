# Authentication alert triage runbook

This is a proposed workflow for a lab. Follow the organization's authorization and incident-response procedures in an actual environment.

## 1. Validate the signal

Open the alert's evidence IDs in the timeline and original log. Check source, account, service, timestamps, outcome and collection coverage. Confirm whether failure counts represent distinct events rather than duplicate ingestion. Check the configured window and cooldown.

## 2. Establish context

- Is the account a person, privileged user or service account?
- Who owns the source IP? Could it be a VPN, shared NAT, proxy or approved test host?
- Was a password rotated, a scheduled job changed or a user locked out?
- What do MFA, device identity, session details and user confirmation show?
- Is there unusual activity after a successful authentication?

These details are absent from the lab logs. Record them as unknown rather than inventing them.

## 3. Decide a disposition

| Evidence | Proposed next step |
|---|---|
| Failures followed by a success with unknown context | Prioritize identity and session review; correlate related alerts |
| Many users from one source | Check shared-source explanations and attempts across a longer window |
| Confirmed stale service credential, expected source, no suspicious follow-on behavior | Record the operational cause and remediation; consider a narrow, expiring suppression |
| Additional unauthorized-session evidence | Escalate through the response process with the evidence timeline |
| Insufficient telemetry | Keep the conclusion open and request missing evidence |

Blocking sources, disabling accounts and revoking sessions are proposed response options only after appropriate authorization and context. This repository performs none of those actions.

## 4. Record and improve

Record the case time, rule version, evidence IDs, observed facts, hypotheses, missing evidence, disposition and rationale. Revisit thresholds using representative benign and malicious data. Avoid permanently allowlisting a source merely because one alert was benign. Track both nuisance alerts and known blind spots.

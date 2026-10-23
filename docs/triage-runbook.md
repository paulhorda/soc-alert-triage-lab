# Triage checklist

## Check the events

Open the alert's event IDs in the original log. Confirm the account, source, service, timestamps and outcomes. Check for duplicate ingestion or gaps in collection. Review related alerts before treating them as separate incidents.

## Find the missing context

- Is this a person or a service account? Does it have elevated access?
- Who owns the source IP? Is it a shared VPN, proxy or NAT address?
- Was there a password rotation, lockout or scheduled job change?
- Did MFA succeed? Is the device familiar?
- What happened after the successful login?

Record unavailable information as unknown. In this lab, these questions cannot be answered from the authentication records alone.

## Decide what to do next

A success after repeated failures deserves an early review. Failures across many users need a check of source ownership and a wider time range. A stale service credential needs confirmation from its owner before the alert is closed.

If there is evidence of unauthorized access, escalate with the timeline and follow the response procedure. Account suspension or session revocation needs the appropriate authorization; the detector does not perform either action.

## Leave a useful case note

Include the rule, event IDs, observed facts, missing evidence, disposition and reason. If a suppression is justified, keep it specific and give it a review date. Check whether the rule also missed related activity.

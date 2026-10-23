# Case notes: login after repeated failures

Generated lab data, September 15, 2026. All times are UTC.

## Timeline

| Time | Observation |
|---|---|
| 14:00–14:07 | Eight failures for `analyst_demo` from `203.0.113.42`, service `vpn` |
| 14:04 | AUTH-001 triggers on the fifth failure |
| 14:08 | A login succeeds for the same account, source and service; AUTH-003 triggers |

The records are `EVT-01201` through `EVT-01209`. They are included in the [evidence timeline](../reports/evidence_timeline.csv) and [alert objects](../reports/alerts.json).

## Assessment

Review the successful login first. The pattern could be password guessing followed by access, but it could also be a user correcting a password problem. A shared VPN or proxy address would make source attribution less reliable.

There is not enough context to call this an account compromise. The next checks are MFA outcome, device identity, previous logins, user confirmation and activity during the new session. None of that is in this sample.

**Status: needs investigation.** The two alerts describe one sequence and should be reviewed together.

## The benign match

`svc_backup_demo` fails six times from `10.20.0.250` against `backup-console`. The separate scenario notes say that its stored password is outdated. The detector cannot know that; it sees repeated failures. Closing this as an operational issue would require confirmation from the service owner.

## The missed sequence

`192.0.2.90` tries eight accounts over 140 minutes. No ten-minute window contains six different accounts, so AUTH-002 stays quiet. The overall source count is visible in the companion SQL project. A longer detection window would need testing against normal shared-IP traffic.

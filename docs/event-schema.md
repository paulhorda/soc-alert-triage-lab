# Normalized event contract

Each UTF-8 JSONL line is one object. Blank lines are ignored.

| Field | Requirement |
|---|---|
| event_id | Unique non-empty string; duplicate IDs fail the batch |
| timestamp | ISO 8601 UTC timestamp ending in `Z` |
| user | Non-empty normalized account identifier |
| source_ip | Valid IPv4 or IPv6 address |
| outcome | `success` or `failure` |
| service | Non-empty authentication service identifier |

The detector sorts timestamps before processing and groups canonical IP representations. User and service names are case-sensitive; upstream normalization must preserve the identity semantics of the source system. Additional fields are allowed but do not influence rules.

```json
{"event_id":"example-1","timestamp":"2026-09-15T14:00:00Z","user":"demo_user","source_ip":"203.0.113.42","outcome":"failure","service":"vpn"}
```

The format is a lab abstraction, not native Windows, Entra ID, Linux or vendor SIEM telemetry. Real ingestion needs a source-specific mapping and decisions about missing fields, late events, collection completeness and clock skew.

## Evidence and deduplication

Each alert has a deterministic ID derived from its rule and evidence IDs. Evidence is recorded at the qualifying trigger. The cooldown is per rule and full grouping scope, so AUTH-001 does not suppress AUTH-003. The same underlying sequence can produce several alerts; they must not be counted as distinct incidents automatically.

The batch loader keeps all input events in memory; historical keys remain until the run ends. It is not a streaming or bounded-memory detector for large production datasets.

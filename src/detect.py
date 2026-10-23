"""Offline batch detection on a small normalized authentication-event schema."""
import argparse
import csv
import hashlib
import ipaddress
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RULES = {
    'AUTH-001': ('Repeated authentication failures', 'medium', 'T1110.001'),
    'AUTH-002': ('Failures across multiple accounts', 'medium', 'T1110.003'),
    'AUTH-003': ('Successful login after repeated failures', 'high', 'T1110.001'),
}


def parse_time(value):
    if not isinstance(value, str) or not value.endswith('Z'):
        raise ValueError('timestamp must be an ISO 8601 UTC value ending in Z')
    return datetime.fromisoformat(value[:-1]+'+00:00').astimezone(timezone.utc)


def validate_events(events):
    seen = set()
    for event in events:
        for key in ('event_id', 'timestamp', 'user', 'source_ip', 'outcome', 'service'):
            if not isinstance(event.get(key), str) or not event[key].strip():
                raise ValueError(f'Missing or invalid field: {key}')
        if event['event_id'] in seen:
            raise ValueError(f'Duplicate event_id: {event["event_id"]}')
        seen.add(event['event_id'])
        if event['outcome'] not in ('success', 'failure'):
            raise ValueError('outcome must be success or failure')
        parse_time(event['timestamp'])
        ipaddress.ip_address(event['source_ip'])
    return sorted(events, key=lambda e: (parse_time(e['timestamp']), e['event_id']))


def read_events(path):
    events = []
    for line_number, line in enumerate(path.read_text().splitlines(), 1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f'Invalid JSON at line {line_number}') from exc
        if not isinstance(event, dict):
            raise ValueError(f'Event at line {line_number} must be an object')
        events.append(event)
    return validate_events(events)


def detect(events, config=None):
    if config is None:
        config = json.loads((ROOT / 'rules/auth_rules.json').read_text())
    required = ('failure_threshold', 'failure_window_seconds', 'spray_user_threshold', 'spray_window_seconds', 'success_window_seconds', 'alert_cooldown_seconds')
    for key in required:
        if type(config.get(key)) is not int or config[key] <= 0:
            raise ValueError(f'{key} must be a positive integer')
    events = validate_events(events)
    by_identity = defaultdict(list)
    by_source = defaultdict(list)
    last_alert = {}
    alerts = []

    def emit(rule_id, event, evidence, scope):
        now = parse_time(event['timestamp'])
        key = (rule_id,) + scope
        if key in last_alert and (now-last_alert[key]).total_seconds() < config['alert_cooldown_seconds']:
            return
        last_alert[key] = now
        title, severity, technique = RULES[rule_id]
        ids = [item['event_id'] for item in evidence]
        fingerprint = hashlib.sha256((rule_id+'|'+ '|'.join(ids)).encode()).hexdigest()[:12]
        alerts.append({'alert_id': f'AL-{fingerprint}', 'rule_id': rule_id, 'title': title,
                       'severity': severity, 'attack_hypothesis': technique,
                       'detected_at': event['timestamp'], 'window_start': evidence[0]['timestamp'],
                       'source_ip': event['source_ip'], 'service': event['service'],
                       'users': sorted({item['user'] for item in evidence}),
                       'failure_count': sum(item['outcome']=='failure' for item in evidence),
                       'evidence_event_ids': ids})

    def within(history, now, seconds):
        return [event for event in history if 0 <= (now-parse_time(event['timestamp'])).total_seconds() <= seconds]

    for event in events:
        now = parse_time(event['timestamp'])
        # Canonical IP keys prevent alternate IPv6 spellings from splitting one source.
        source_ip = str(ipaddress.ip_address(event['source_ip']))
        pair = (event['service'], source_ip, event['user'])
        source = (event['service'], source_ip)
        by_identity[pair] = within(by_identity[pair], now, max(config['failure_window_seconds'], config['success_window_seconds']))
        by_source[source] = within(by_source[source], now, config['spray_window_seconds'])
        if event['outcome'] == 'failure':
            by_identity[pair].append(event)
            by_source[source].append(event)
            failure_window = within(by_identity[pair], now, config['failure_window_seconds'])
            if len(failure_window) >= config['failure_threshold']:
                emit('AUTH-001', event, failure_window, pair)
            if len({item['user'] for item in by_source[source]}) >= config['spray_user_threshold']:
                emit('AUTH-002', event, by_source[source], source)
        else:
            failures = [item for item in within(by_identity[pair], now, config['success_window_seconds']) if parse_time(item['timestamp']) < now]
            if len(failures) >= config['failure_threshold']:
                emit('AUTH-003', event, failures+[event], pair)
    return alerts


def run(input_path=ROOT / 'data/auth_events.jsonl', output=ROOT / 'reports', rules_path=ROOT / 'rules/auth_rules.json'):
    events = read_events(input_path)
    config = json.loads(rules_path.read_text())
    alerts = detect(events, config)
    output.mkdir(parents=True, exist_ok=True)
    (output / 'alerts.json').write_text(json.dumps(alerts, indent=2)+'\n')
    evidence_ids = {event_id for alert in alerts for event_id in alert['evidence_event_ids']}
    with (output / 'evidence_timeline.csv').open('w', newline='', encoding='utf-8') as stream:
        writer = csv.DictWriter(stream, fieldnames=['event_id','timestamp','user','source_ip','outcome','service'], lineterminator='\n', extrasaction='ignore')
        writer.writeheader()
        writer.writerows(event for event in events if event['event_id'] in evidence_ids)
    summary = {'input_sha256': hashlib.sha256(input_path.read_bytes()).hexdigest(),
               'events': len(events), 'alerts': len(alerts), 'rules': config,
               'by_rule': dict(sorted(Counter(a['rule_id'] for a in alerts).items())),
               'by_severity': dict(sorted(Counter(a['severity'] for a in alerts).items()))}
    (output / 'summary.json').write_text(json.dumps(summary, indent=2)+'\n')
    lines = ['# Authentication alerts', '', f'{len(events):,} generated events. {len(alerts)} alerts. All times are UTC.', '',
             '| Rule | Time | Priority | Source | Evidence events |', '|---|---|---|---|---|']
    for alert in alerts:
        lines.append(f'| {alert["rule_id"]} | {alert["detected_at"]} | {alert["severity"]} | {alert["source_ip"]} | {len(alert["evidence_event_ids"])} |')
    lines += ['', '## Review order', '',
              'Start with AUTH-003: a successful login follows repeated failures. Check the account, MFA and device context before deciding whether access was unauthorized.', '',
              'AUTH-002 needs a check of the source and affected accounts. The pattern is consistent with spraying, but passwords are not logged.', '',
              'AUTH-001 can also result from a stale service credential or typing mistakes. One such benign case is included in this sample.', '',
              'AUTH-001 and AUTH-003 can refer to the same sequence. Alert counts are not incident counts.', '',
              '## Evidence', '',
              '[Alert objects](alerts.json) · [Timeline](evidence_timeline.csv) · [Case notes](../docs/incident-walkthrough.md) · [Triage checklist](../docs/triage-runbook.md)', '',
              'The slow sequence in the sample produces no alert. Scenario labels are stored separately in `data/scenario_labels.json`; the detector does not read them.', '']
    (output / 'triage-report.md').write_text('\n'.join(lines))
    return summary


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, default=ROOT / 'data/auth_events.jsonl')
    parser.add_argument('--output', type=Path, default=ROOT / 'reports')
    parser.add_argument('--rules', type=Path, default=ROOT / 'rules/auth_rules.json')
    args = parser.parse_args()
    print(json.dumps(run(args.input, args.output, args.rules), indent=2))

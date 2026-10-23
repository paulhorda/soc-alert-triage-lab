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


def dashboard(events, alerts):
    counts = Counter(alert['rule_id'] for alert in alerts)
    parts = ['<svg xmlns="http://www.w3.org/2000/svg" width="1080" height="480" viewBox="0 0 1080 480" role="img" aria-labelledby="title desc">',
             '<title id="title">SOC authentication triage lab</title><desc id="desc">Synthetic events with three detection rules and an explicit slow-spray blind spot.</desc>',
             '<rect width="1080" height="480" rx="20" fill="#0b1220"/><g font-family="Arial, sans-serif" fill="#e7edf5">',
             '<text x="40" y="49" font-size="14" fill="#93c5fd">SECURITY OPERATIONS / DETECTION + TRIAGE</text>',
             '<text x="40" y="92" font-size="30" font-weight="700">From authentication events to evidence</text>',
             '<text x="40" y="122" font-size="14" fill="#a8b8cf">Offline portfolio lab · Fictional events · No live systems contacted</text>',
             f'<text x="40" y="185" font-size="28" font-weight="700">{len(events):,} events → {len(alerts)} alerts → analyst review</text>']
    for x, rule_id in zip([40,380,720], RULES):
        title, severity, _ = RULES[rule_id]
        short = {'AUTH-001':'Repeated failures','AUTH-002':'Multiple accounts','AUTH-003':'Success after failures'}[rule_id]
        parts += [f'<rect x="{x}" y="225" width="320" height="130" rx="10" fill="#162236"/>',
                  f'<text x="{x+20}" y="257" font-size="13" fill="#a8b8cf">{rule_id} / {severity.upper()}</text>',
                  f'<text x="{x+20}" y="291" font-size="18">{short}</text>',
                  f'<text x="{x+20}" y="331" font-size="25" fill="#93c5fd">{counts[rule_id]} alert(s)</text>']
    parts += ['<text x="40" y="408" font-size="14" fill="#a8b8cf">A signal is not a verdict. Review user context, MFA, device and follow-on activity.</text>',
              '<text x="40" y="437" font-size="13" fill="#a8b8cf">Includes a benign credential-failure scenario and a deliberately missed slow-spray sequence.</text>', '</g></svg>']
    return '\n'.join(parts)+'\n'


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
    (output / 'dashboard.svg').write_text(dashboard(events, alerts))
    lines = ['# Authentication triage report', '', '> Generated from fictional events. Signals require investigation; this is not evidence of a real intrusion.', '',
             '![Detection summary](dashboard.svg)', '', '## Alert queue', '', '| Rule | UTC time | Severity | Source | Evidence events |', '|---|---|---|---|---|']
    for alert in alerts:
        lines.append(f'| {alert["rule_id"]} | {alert["detected_at"]} | {alert["severity"]} | {alert["source_ip"]} | {len(alert["evidence_event_ids"])} |')
    lines += ['', '## Triage interpretation', '',
              '- AUTH-003 is the first review priority: a successful login follows repeated failures for the same user, source and service. This could be malicious access or a legitimate user recovering from a password problem.',
              '- AUTH-002 identifies failures across distinct users. Password spraying is a hypothesis; the log does not reveal whether the same password was used.',
              '- AUTH-001 alone can arise from a stale service credential or user mistakes. Source ownership, user confirmation and maintenance records are needed.',
              '- AUTH-001 and AUTH-003 can describe the same sequence; alert count is not incident count.', '',
              '## Evidence and next steps', '',
              '[Complete alert evidence](alerts.json) · [Evidence timeline](evidence_timeline.csv) · [Incident walkthrough](../docs/incident-walkthrough.md) · [Triage runbook](../docs/triage-runbook.md)', '',
              '## Evaluation boundary', '',
              'The generator includes a benign stale-credential case that alerts and a slow cross-user sequence that the short-window rules miss. Ground-truth scenario labels live separately in `data/scenario_labels.json` and are never read by the detector. Passing these fixtures does not establish production precision, recall or readiness.', '']
    (output / 'triage-report.md').write_text('\n'.join(lines))
    return summary


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, default=ROOT / 'data/auth_events.jsonl')
    parser.add_argument('--output', type=Path, default=ROOT / 'reports')
    parser.add_argument('--rules', type=Path, default=ROOT / 'rules/auth_rules.json')
    args = parser.parse_args()
    print(json.dumps(run(args.input, args.output, args.rules), indent=2))

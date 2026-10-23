"""Produce fictional authentication events; no network access or attack execution."""
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def generate(destination=ROOT / 'data', seed=42):
    rng = random.Random(seed)
    base = datetime(2026, 9, 15, tzinfo=timezone.utc)
    events = []

    def add(minutes, user, ip, outcome, service='vpn'):
        events.append({'event_id': f'EVT-{len(events)+1:05}',
                       'timestamp': (base+timedelta(minutes=minutes)).isoformat().replace('+00:00', 'Z'),
                       'user': user, 'source_ip': ip, 'outcome': outcome, 'service': service})

    for i in range(1200):
        user = f'employee_{i % 120:03}'
        add(i*.6, user, f'10.20.{i % 4}.{1+i % 200}', 'failure' if rng.random()<.035 else 'success')
    for i in range(8):
        add(840+i, 'analyst_demo', '203.0.113.42', 'failure')
    add(848, 'analyst_demo', '203.0.113.42', 'success')
    for i in range(8):
        add(960+i, f'target_{i:02}', '198.51.100.23', 'failure')
    # Operationally benign fixture still crosses the failure threshold.
    for i in range(6):
        add(1020+i, 'svc_backup_demo', '10.20.0.250', 'failure', 'backup-console')
    # Deliberate blind spot: a slow cross-user sequence falls outside a 10-minute window.
    for i in range(8):
        add(1080+i*20, f'slow_target_{i:02}', '192.0.2.90', 'failure')
    events.sort(key=lambda event: (event['timestamp'], event['event_id']))
    destination.mkdir(parents=True, exist_ok=True)
    (destination / 'auth_events.jsonl').write_text(''.join(json.dumps(e, sort_keys=True)+'\n' for e in events))
    truth = {
        'notice': 'Synthetic fixture labels for manual evaluation only. Not read by the detector.',
        'scenarios': [
            {'source_ip': '203.0.113.42', 'label': 'simulated_suspicious', 'expected_rules': ['AUTH-001', 'AUTH-003'], 'context': 'Repeated failures followed by a success; intent cannot be established from auth telemetry alone.'},
            {'source_ip': '198.51.100.23', 'label': 'simulated_suspicious', 'expected_rules': ['AUTH-002'], 'context': 'Failures across multiple accounts; password values are not logged, so spraying is a hypothesis.'},
            {'source_ip': '10.20.0.250', 'label': 'benign_operational', 'expected_rules': ['AUTH-001'], 'context': 'Fictional backup service has an outdated stored credential; this explanation comes from the fixture, not the raw event fields.'},
            {'source_ip': '192.0.2.90', 'label': 'simulated_slow_spray', 'expected_rules': [], 'context': 'Deliberately missed: eight users over 140 minutes, below the short-window threshold.'}
        ]
    }
    (destination / 'scenario_labels.json').write_text(json.dumps(truth, indent=2)+'\n')
    return len(events)


if __name__ == '__main__':
    print(f'Generated {generate()} fictional events')

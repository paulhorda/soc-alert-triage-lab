import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from detect import detect, read_events, run
from generate_logs import generate


def event(index, seconds, user='demo', ip='203.0.113.10', outcome='failure', service='vpn'):
    return {'event_id': f'E{index:04}', 'timestamp': (datetime(2026,9,15,tzinfo=timezone.utc)+timedelta(seconds=seconds)).isoformat().replace('+00:00','Z'),
            'user': user, 'source_ip': ip, 'outcome': outcome, 'service': service}


class DetectionTests(unittest.TestCase):
    def test_failure_threshold_and_inclusive_boundary(self):
        self.assertEqual(detect([event(i,i*100) for i in range(4)]), [])
        alerts = detect([event(i,i*150) for i in range(5)])
        self.assertEqual([a['rule_id'] for a in alerts], ['AUTH-001'])
        self.assertEqual(alerts[0]['failure_count'], 5)

    def test_outside_failure_window(self):
        self.assertEqual(detect([event(i,i*151) for i in range(5)]), [])

    def test_spray_counts_distinct_users(self):
        self.assertNotIn('AUTH-002', [a['rule_id'] for a in detect([event(i,i) for i in range(8)])])
        alerts = detect([event(i,i,user=f'u{i}') for i in range(6)])
        self.assertEqual([a['rule_id'] for a in alerts], ['AUTH-002'])

    def test_success_correlation_has_correct_identity_and_source(self):
        failures = [event(i,i*60) for i in range(5)]
        alerts = detect(failures+[event(6,300,outcome='success')])
        self.assertIn('AUTH-003', [a['rule_id'] for a in alerts])
        self.assertNotIn('AUTH-003', [a['rule_id'] for a in detect(failures+[event(6,300,user='other',outcome='success')])])
        self.assertNotIn('AUTH-003', [a['rule_id'] for a in detect(failures+[event(6,300,ip='203.0.113.11',outcome='success')])])

    def test_success_correlation_window_boundary(self):
        failures = [event(i,i*60) for i in range(5)]
        self.assertIn('AUTH-003', [a['rule_id'] for a in detect(failures+[event(6,900,outcome='success')])])
        self.assertNotIn('AUTH-003', [a['rule_id'] for a in detect(failures+[event(6,901,outcome='success')])])

    def test_same_time_failure_not_before_success(self):
        events = [event(i,0) for i in range(5)] + [event(9,0,outcome='success')]
        self.assertNotIn('AUTH-003', [a['rule_id'] for a in detect(events)])

    def test_service_boundaries_do_not_mix(self):
        events = [event(i,i,service='vpn' if i<3 else 'ssh') for i in range(5)]
        self.assertEqual(detect(events), [])

    def test_shuffled_events_produce_identical_alerts(self):
        events = [event(i,i*60) for i in range(8)]
        self.assertEqual(detect(events), detect(list(reversed(events))))

    def test_duplicate_events_are_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Duplicate event_id'):
            detect([event(1,0),event(1,0)])

    def test_cooldown_limits_repeated_alerts_but_allows_new_burst(self):
        first = [event(i,i*60) for i in range(8)]
        second = [event(i+10,2100+i*60) for i in range(5)]
        alerts = detect(first+second)
        self.assertEqual([a['rule_id'] for a in alerts], ['AUTH-001','AUTH-001'])

    def test_equivalent_ipv6_sources_are_combined(self):
        events = [event(i,i,ip='2001:db8::1' if i%2 else '2001:0db8:0:0:0:0:0:1') for i in range(5)]
        self.assertEqual(len(detect(events)), 1)

    def test_invalid_outcome_and_timestamp_are_rejected(self):
        with self.assertRaisesRegex(ValueError, 'outcome'):
            detect([event(1,0,outcome='unknown')])
        malformed = event(1,0)
        malformed['timestamp'] = '2026-09-15T10:00:00'
        with self.assertRaisesRegex(ValueError, 'timestamp'):
            detect([malformed])

    def test_no_events_no_alerts(self):
        self.assertEqual(detect([]), [])

    def test_slow_spray_is_documented_blind_spot(self):
        self.assertEqual(detect([event(i,i*1200,user=f'u{i}') for i in range(8)]), [])

    def test_generated_scenarios_and_report_reproducibility(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            generate(root/'data')
            events = read_events(root/'data/auth_events.jsonl')
            alerts = detect(events)
            labels = json.loads((root/'data/scenario_labels.json').read_text())
            for scenario in labels['scenarios']:
                self.assertEqual(sorted(a['rule_id'] for a in alerts if a['source_ip']==scenario['source_ip']), sorted(scenario['expected_rules']))
            event_ids = {e['event_id'] for e in events}
            self.assertTrue(all(set(a['evidence_event_ids']) <= event_ids for a in alerts))
            run(root/'data/auth_events.jsonl', root/'one')
            # No labels needed to generate detections or reports.
            (root/'data/scenario_labels.json').unlink()
            run(root/'data/auth_events.jsonl', root/'two')
            for path in (root/'one').iterdir():
                self.assertEqual(path.read_bytes(), (root/'two'/path.name).read_bytes())


if __name__ == '__main__':
    unittest.main()

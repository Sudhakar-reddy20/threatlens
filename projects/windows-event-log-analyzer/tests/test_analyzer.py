import tempfile
import unittest
from pathlib import Path
import xml.etree.ElementTree as ET

from analyzer import detect_alerts, parse_event, parse_export, write_reports


NS = "http://schemas.microsoft.com/win/2004/08/events/event"


def make_event(event_id, minute, ip="192.0.2.80", username="analyst"):
    return ET.fromstring(f"""<Event xmlns="{NS}">
      <System><EventID>{event_id}</EventID>
      <TimeCreated SystemTime="2026-11-01T10:{minute:02d}:00.000Z"/>
      <EventRecordID>{minute}</EventRecordID><Channel>Security</Channel>
      <Computer>LAB-WIN01</Computer></System>
      <EventData><Data Name="TargetUserName">{username}</Data>
      <Data Name="IpAddress">{ip}</Data><Data Name="LogonType">3</Data></EventData>
    </Event>""")


class AnalyzerTests(unittest.TestCase):
    def test_parse_failed_logon(self):
        event = parse_event(make_event(4625, 0))
        self.assertEqual(event.event_id, 4625)
        self.assertEqual(event.username, "analyst")
        self.assertEqual(event.source_ip, "192.0.2.80")
        self.assertEqual(event.logon_type, "3")

    def test_parse_successful_logon(self):
        event = parse_event(make_event(4624, 1))
        self.assertEqual(event.event_id, 4624)

    def test_malformed_event_without_system_is_ignored(self):
        self.assertIsNone(parse_event(ET.fromstring("<Event/>")))

    def test_repeated_failures_trigger_alert(self):
        events = [parse_event(make_event(4625, i)) for i in range(5)]
        alerts = detect_alerts(events)
        self.assertEqual([a.rule_id for a in alerts], ["WELA-001"])

    def test_success_after_failures_triggers_correlation(self):
        events = [parse_event(make_event(4625, i)) for i in range(5)]
        events.append(parse_event(make_event(4624, 5)))
        alerts = detect_alerts(events)
        self.assertIn("WELA-002", [a.rule_id for a in alerts])

    def test_distinct_bursts_generate_distinct_alerts(self):
        events = [parse_event(make_event(4625, i)) for i in range(5)]
        events += [parse_event(make_event(4625, 30 + i)) for i in range(5)]
        alerts = [a for a in detect_alerts(events) if a.rule_id == "WELA-001"]
        self.assertEqual(len(alerts), 2)

    def test_audit_clear_event_is_flagged(self):
        event = parse_event(make_event(1102, 0))
        alerts = detect_alerts([event])
        self.assertEqual(alerts[0].rule_id, "WELA-005")

    def test_user_creation_event_is_flagged(self):
        event = parse_event(make_event(4720, 0, username="new-user"))
        alerts = detect_alerts([event])
        self.assertEqual(alerts[0].rule_id, "WELA-003")

    def test_invalid_threshold_is_rejected(self):
        with self.assertRaises(ValueError):
            detect_alerts([], failure_threshold=0)

    def test_reports_are_written(self):
        events = [parse_event(make_event(4625, i)) for i in range(5)]
        alerts = detect_alerts(events)
        with tempfile.TemporaryDirectory() as directory:
            json_path, csv_path = write_reports(alerts, Path(directory))
            self.assertTrue(json_path.is_file())
            self.assertTrue(csv_path.is_file())

    def test_export_xml_is_parsed(self):
        sample = Path(__file__).parents[1] / "sample_logs" / "security-events.xml"
        events, unsupported = parse_export(sample)
        self.assertEqual(len(events), 8)
        self.assertEqual(unsupported, 0)


if __name__ == "__main__":
    unittest.main()

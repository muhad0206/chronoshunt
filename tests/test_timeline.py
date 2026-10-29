"""
ChronosHunt Automated Unit Tests
Validates multi-artifact normalization, chronological time-sorting,
adversary dwell-time math, and MITRE kill-chain mapping.
"""

import unittest
from app.core.normalizer import ArtifactNormalizer
from app.core.correlator import TimelineCorrelator


class TestChronosHunt(unittest.TestCase):
    def test_sysmon_normalization(self):
        raw = {
            "timestamp": "2026-10-29T10:15:00.000Z",
            "EventID": 1,
            "Image": "C:\\Windows\\System32\\vssadmin.exe",
            "CommandLine": "vssadmin.exe delete shadows /all /quiet",
            "ParentImage": "C:\\Windows\\System32\\cmd.exe",
            "host": "DC-01",
            "user": "CORP\\admin"
        }
        event = ArtifactNormalizer.normalize(raw)
        self.assertEqual(event.artifact_type, "SYSMON_PROC")
        self.assertEqual(event.kill_chain_phase, "IMPACT")
        self.assertEqual(event.mitre_id, "T1490")
        self.assertTrue(event.is_adversary_pivot)

    def test_prefetch_normalization(self):
        raw = {
            "timestamp": "2026-10-29T10:18:00.000Z",
            "source_type": "PREFETCH",
            "executable": "PROCDUMP.EXE",
            "run_count": 1,
            "host": "WEB-01"
        }
        event = ArtifactNormalizer.normalize(raw)
        self.assertEqual(event.artifact_type, "PREFETCH")
        self.assertTrue(event.is_adversary_pivot)
        self.assertIn("T1003.001", event.mitre_id)

    def test_dwell_time_calculation(self):
        e1 = ArtifactNormalizer.normalize({
            "timestamp": "2026-10-29T12:00:00Z",
            "source_type": "SYSMON_PROC",
            "Image": "winword.exe",
            "CommandLine": "winword.exe /n invoice.doc"
        })
        e2 = ArtifactNormalizer.normalize({
            "timestamp": "2026-10-29T12:15:30Z",
            "source_type": "SYSMON_PROC",
            "Image": "procdump.exe",
            "CommandLine": "procdump.exe -ma lsass.exe"
        })
        case = TimelineCorrelator.correlate(
            case_id="TEST-01",
            case_name="Test Intrusion",
            threat_actor="Test Actor",
            target_org="Acme",
            incident_type="Test",
            events=[e2, e1]  # Passed out of order to verify sorting
        )
        self.assertEqual(case.dwell_time_seconds, 930)  # 15 mins 30 secs = 930s
        self.assertEqual(case.dwell_time_formatted, "15m 30s")
        # Ensure chronological order was restored
        self.assertEqual(case.timeline_events[0].process_name, "winword.exe")
        self.assertEqual(case.timeline_events[1].process_name, "procdump.exe")


if __name__ == "__main__":
    unittest.main()

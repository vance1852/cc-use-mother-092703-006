from __future__ import annotations

import unittest
from pathlib import Path

from env_response.acceptance import run


ROOT = Path(__file__).resolve().parents[1]


class EnvAcceptanceTests(unittest.TestCase):
    def test_offline_acceptance(self) -> None:
        result = run(ROOT)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["final_state"], "closed")
        self.assertEqual(result["evidence_count"], 4)
        self.assertEqual(result["assessment_revisions"], 4)
        self.assertEqual(result["directions"], ["initial", "expanded", "narrowed", "unchanged"])
        self.assertEqual(result["resumed_zone_ids"], ["zone-a1", "zone-a2"])
        self.assertEqual(result["schema"]["missing_tables"], [])
        self.assertEqual(result["schema"]["schema_version"], "1")
        self.assertTrue(result["audit"]["valid"])


if __name__ == "__main__":
    unittest.main()

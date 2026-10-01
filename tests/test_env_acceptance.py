from __future__ import annotations

import unittest
from pathlib import Path

from env_response.acceptance import run


ROOT = Path(__file__).resolve().parents[1]


class AcceptanceTests(unittest.TestCase):
    def test_offline_acceptance(self) -> None:
        result = run(ROOT)
        self.assertEqual(result["status"], "ok")
        # 三份材料依次产生证据版本，复测扩大、第三方维持。
        self.assertEqual(result["assessments"]["retest"]["added_zones"], ["zone-c"])
        # 并发现场记录按来源编号去重，重传不重复入库。
        self.assertEqual(result["field_records"]["concurrent"]["deduped_count"], 1)
        # 修复任务完成时措施仍未解除。
        self.assertEqual(result["state_after_tasks"], "remediating")
        self.assertEqual(result["active_measures_before_review"], 2)
        self.assertIsNotNone(result["closure_blocked_reason"])
        # 第一次复核驳回，第二次授权通过后才关闭并解除措施。
        self.assertEqual(result["first_review"]["verdict"], "rejected")
        self.assertEqual(result["final_review"]["verdict"], "approved")
        self.assertEqual(result["closed_state"], "closed")
        self.assertEqual(result["remaining_todos"], 0)
        self.assertTrue(result["audit"]["valid"])
        self.assertGreaterEqual(result["timeline_events"], 10)


if __name__ == "__main__":
    unittest.main()

import unittest

from night_market_foundation.acceptance import run


class AcceptanceTest(unittest.TestCase):
    def test_offline_acceptance(self):
        result = run()
        self.assertEqual("ok", result["status"])
        self.assertTrue(result["audit_valid"])
        self.assertFalse(result["first_replayed"])
        self.assertTrue(result["second_replayed"])
        self.assertEqual(1, result["records"])
        self.assertGreater(result["incident_history_events"], 0)
        self.assertTrue(result["restart_audit_valid"])
        self.assertEqual(1, result["restart_open_actions"])
        self.assertEqual(0, result["unowned_open_actions"])
        self.assertTrue(result["restart_replay"])


if __name__ == "__main__":
    unittest.main()

import unittest
from canlog import inspect,parse_lines

class CanLogTests(unittest.TestCase):
    def test_parse_and_unknown(self):
        frames=parse_lines(["(0.0) can0#123#AA","0.1,0x7ff,"]); report=inspect(frames,[0x123])
        self.assertEqual(report["frames"],2); self.assertEqual(report["unknown_ids"],[0x7FF]); self.assertEqual(report["empty_payloads"],1)

    def test_burst_uses_timestamp_order_for_unsorted_logs(self):
        # A frame at 0 s and one at 10 s are not a 1-second burst even when
        # the log lines arrive in reverse order.
        frames=parse_lines(["10.0,0x123,AA", "0.0,0x123,BB"])
        self.assertEqual(inspect(frames, burst_threshold=1, window_seconds=1.0)["bursts"], [])

    def test_parse_standard_candump_format(self):
        frames = parse_lines(["(12.345678) can0 18DAF110#10203040"])
        self.assertEqual(frames, [{"timestamp": 12.345678, "id": 0x18DAF110, "data": "10203040"}])

    def test_parse_verbose_candump_format(self):
        frames = parse_lines(["(12.345678) can0 18DAF110 [4] 10 20 30 40"])
        self.assertEqual(frames, [{"timestamp": 12.345678, "id": 0x18DAF110, "data": "10203040"}])

    def test_verbose_candump_rejects_dlc_mismatch(self):
        with self.assertRaisesRegex(ValueError, "declared DLC"):
            parse_lines(["(0.0) can0 123 [2] AA"])

    def test_rejects_ids_outside_can_arbitration_range(self):
        for line in ("(0.0) can0 100000000#AA", "0.0,0x100000000,AA", "0.0,-1,AA"):
            with self.assertRaisesRegex(ValueError, "invalid CAN arbitration ID"):
                parse_lines([line])

if __name__=="__main__": unittest.main()

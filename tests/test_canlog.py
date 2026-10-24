import unittest
from canlog import inspect,parse_lines

class CanLogTests(unittest.TestCase):
    def test_parse_and_unknown(self):
        frames=parse_lines(["(0.0) can0#123#AA","0.1,0x7ff,"]); report=inspect(frames,[0x123])
        self.assertEqual(report["frames"],2); self.assertEqual(report["unknown_ids"],[0x7FF]); self.assertEqual(report["empty_payloads"],1)
if __name__=="__main__": unittest.main()

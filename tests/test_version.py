"""版本比较单元测试：epoch 优先级、超 64 位整数、波浪号、前导零、缺省 revision。"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from cvematch import compare_versions as cmp


class TestEpoch(unittest.TestCase):
    def test_epoch_priority_over_upstream(self):
        self.assertGreater(cmp("2:1.0", "1:999.999"), 0)
        self.assertLess(cmp("1:9.9", "2:0.1"), 0)

    def test_missing_epoch_is_zero(self):
        self.assertEqual(cmp("0:1.0", "1.0"), 0)
        self.assertLess(cmp("1.0", "1:0.1"), 0)

    def test_large_epoch(self):
        self.assertGreater(cmp("10:1.0", "9:1.0"), 0)


class TestUpstream(unittest.TestCase):
    def test_leading_zeros_ignored(self):
        self.assertEqual(cmp("1.01", "1.1"), 0)
        self.assertEqual(cmp("1.000", "1.0"), 0)
        self.assertLess(cmp("1.02", "1.10"), 0)

    def test_tilde_sorts_before_everything(self):
        self.assertLess(cmp("1.0~rc1", "1.0"), 0)
        self.assertGreater(cmp("1.0~rc1", "1.0~"), 0)  # 段结束 < 字母
        self.assertLess(cmp("1.0~~", "1.0~"), 0)
        self.assertLess(cmp("1.0~rc1", "1.0~rc2"), 0)
        self.assertGreater(cmp("1.0~", "0.9"), 0)

    def test_letters_before_other_chars(self):
        self.assertLess(cmp("1.0a", "1.0+"), 0)
        self.assertGreater(cmp("1.0+", "1.0~"), 0)  # ~ 最小
        self.assertLess(cmp("1.0a", "1.0b"), 0)

    def test_end_of_segment_between_tilde_and_letter(self):
        self.assertLess(cmp("1.0", "1.0a"), 0)
        self.assertLess(cmp("1.0", "1.0+dfsg"), 0)  # 段结束 < 其他字符

    def test_bigint_beyond_64bit(self):
        big1 = "1." + "9" * 40
        big2 = "1.1" + "0" * 40
        self.assertLess(cmp(big1, big2), 0)
        self.assertEqual(cmp("1." + "0" * 30 + "7", "1.7"), 0)
        self.assertGreater(cmp("2:" + "9" * 50 + ".0", "1:0.0"), 0)

    def test_numeric_beats_empty_segment(self):
        self.assertGreater(cmp("1.0.1", "1.0"), 0)


class TestRevision(unittest.TestCase):
    def test_missing_revision_is_zero(self):
        self.assertEqual(cmp("1.0", "1.0-0"), 0)
        self.assertEqual(cmp("1.0", "1.0-00"), 0)
        self.assertLess(cmp("1.0", "1.0-1"), 0)

    def test_revision_uses_last_hyphen(self):
        self.assertEqual(cmp("1.0-2-3", "1.0-2-3"), 0)
        self.assertLess(cmp("1.0-2-3", "1.0-2-10"), 0)
        # upstream 含连字符时按最后一个切分
        self.assertLess(cmp("1.0-1-1", "1.0-2-0"), 0)

    def test_revision_compared_after_upstream(self):
        self.assertLess(cmp("1.0-99", "1.1-0"), 0)

    def test_revision_tilde(self):
        self.assertLess(cmp("1.0-1~exp1", "1.0-1"), 0)


class TestEqualityOfEquivalentStrings(unittest.TestCase):
    def test_semantically_equal_strings(self):
        self.assertEqual(cmp("1.01", "1.1"), 0)
        self.assertEqual(cmp("0:1.0", "1.0-0"), 0)
        self.assertEqual(cmp("1.0a", "1.0a0"), 0)


if __name__ == "__main__":
    unittest.main()

import unittest

from cvematch import compare_versions


def sign(x):
    return (x > 0) - (x < 0)


class TestCompareVersions(unittest.TestCase):
    def assert_order(self, a, b, want):
        self.assertEqual(sign(compare_versions(a, b)), want, (a, b))
        self.assertEqual(sign(compare_versions(b, a)), -want, (b, a))

    def test_epoch_priority(self):
        self.assert_order("2:1.0", "1:99.99", 1)
        self.assert_order("1:0.1", "0:9.9", 1)
        self.assert_order("0:1.0", "1.0", 0)  # 缺省 epoch 为零
        self.assert_order("1:1.0-2", "1:1.0-3", -1)

    def test_big_integers_beyond_64bit(self):
        big_lo = "1." + "7" * 60
        big_hi = "1." + "8" * 60
        self.assert_order(big_lo, big_hi, -1)
        self.assert_order("1." + "9" * 60, "1." + "1" + "0" * 60, -1)
        self.assert_order("1." + "0" * 30 + "5", "1.5", 0)
        self.assert_order("1.0-" + "3" * 50, "1.0-" + "3" * 49, 1)

    def test_tilde(self):
        self.assert_order("1.0~rc1", "1.0", -1)
        self.assert_order("1.0~rc1", "1.0~rc2", -1)
        self.assert_order("1.0~", "1.0", -1)
        self.assert_order("1.0~~", "1.0~", -1)
        self.assert_order("1.0~rc1-1", "1.0-1", -1)

    def test_leading_zeros(self):
        self.assert_order("1.01", "1.1", 0)
        self.assert_order("1.001", "1.1", 0)
        self.assert_order("1.010", "1.9", 1)
        self.assert_order("1.0-01", "1.0-1", 0)

    def test_default_revision(self):
        self.assert_order("1.0", "1.0-0", 0)
        self.assert_order("1.0", "1.0-1", -1)
        self.assert_order("1.0-0", "1.0-00", 0)
        self.assert_order("1.0~rc1", "1.0~rc1-0", 0)

    def test_non_digit_ordering(self):
        # 段结束 < ASCII字母 < 其他字符
        self.assert_order("1.0", "1.0a", -1)
        self.assert_order("1.0a", "1.0+", -1)
        self.assert_order("1.0+", "1.0~", 1)  # 波浪号最小
        self.assert_order("1.0A", "1.0a", -1)  # 同类按 ASCII

    def test_revision_compared_after_upstream(self):
        self.assert_order("1.0-99", "1.1-1", -1)
        self.assert_order("1.0-2", "1.0-10", -1)
        self.assert_order("1.0-rc1", "1.0-1", 1)  # 'r' 是字母,大于数字段结束

    def test_semantic_equality(self):
        for a, b in [("1.01", "1.1"), ("1.0", "1.0-0"), ("0:1.0", "1.0"),
                     ("1:1.0", "1:1.0-0"), ("2.0", "2.0-00")]:
            self.assertEqual(compare_versions(a, b), 0, (a, b))


if __name__ == "__main__":
    unittest.main()

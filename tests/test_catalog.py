"""目录与扫描测试：开闭边界、语义相等边界、空区间、CVE 去重、流式产出。"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from cvematch import build_catalog, scan


def run(cat, obs):
    return list(scan(cat, iter(obs)))


class TestBounds(unittest.TestCase):
    def test_open_closed_corners(self):
        # 区间 (1.0, 2.0]：下端开、上端闭
        cat = build_catalog([("p", "CVE-A", "1.0", False, "2.0", True)])
        self.assertEqual(run(cat, [("r", "p", "1.0")])[0][1], set())
        self.assertEqual(run(cat, [("r", "p", "1.0-0")])[0][1], set())  # 语义相等仍不命中
        self.assertEqual(run(cat, [("r", "p", "1.0-1")])[0][1], {"CVE-A"})
        self.assertEqual(run(cat, [("r", "p", "2.0")])[0][1], {"CVE-A"})
        self.assertEqual(run(cat, [("r", "p", "2.0-0")])[0][1], {"CVE-A"})
        self.assertEqual(run(cat, [("r", "p", "2.0-0.1")])[0][1], set())

    def test_semantically_equal_bound_one_side_open(self):
        # 下界 1.01 开区间：语义相等的 1.1 不得命中，1.1-0 也不得命中
        cat = build_catalog([("p", "CVE-B", "1.01", False, None, False)])
        self.assertEqual(run(cat, [("r", "p", "1.1")])[0][1], set())
        self.assertEqual(run(cat, [("r", "p", "1.1-0")])[0][1], set())
        self.assertEqual(run(cat, [("r", "p", "1.1-00")])[0][1], set())
        self.assertEqual(run(cat, [("r", "p", "1.1-0.0")])[0][1], {"CVE-B"})  # 0.0 > 0
        self.assertEqual(run(cat, [("r", "p", "1.1~")])[0][1], set())
        self.assertEqual(run(cat, [("r", "p", "1.1-1")])[0][1], {"CVE-B"})
        # 上界 1.1 开区间：1.10 不命中（1.10 > 1.1），1.09 命中
        cat2 = build_catalog([("p", "CVE-C", None, False, "1.1", False)])
        self.assertEqual(run(cat2, [("r", "p", "1.1")])[0][1], set())
        self.assertEqual(run(cat2, [("r", "p", "1.10")])[0][1], set())
        self.assertEqual(run(cat2, [("r", "p", "1.09")])[0][1], set())  # 09 = 9 > 1
        self.assertEqual(run(cat2, [("r", "p", "1.0")])[0][1], {"CVE-C"})

    def test_unbounded(self):
        cat = build_catalog([("p", "CVE-U", None, False, None, False)])
        self.assertEqual(run(cat, [("r", "p", "999:1.0~")])[0][1], {"CVE-U"})

    def test_empty_intervals_never_match(self):
        cat = build_catalog([
            ("p", "CVE-E1", "2.0", True, "1.0", True),    # lo > hi
            ("p", "CVE-E2", "1.0", False, "1.0", True),   # 单点但一端开
            ("p", "CVE-E3", "1.0", True, "1.0", False),
            ("p", "CVE-E4", "1.0", False, "1.0", False),
            ("p", "CVE-E5", "1.01", True, "1.1", True),   # 语义相等两端闭 -> 非空
        ])
        hits = run(cat, [("r", "p", "1.0"), ("r2", "p", "1.1")])
        self.assertEqual(hits[0][1], set())
        self.assertEqual(hits[1][1], {"CVE-E5"})

    def test_point_interval(self):
        cat = build_catalog([("p", "CVE-P", "1.0", True, "1.0", True)])
        self.assertEqual(run(cat, [("r", "p", "1.0-0")])[0][1], {"CVE-P"})
        self.assertEqual(run(cat, [("r", "p", "1.0~")])[0][1], set())


class TestMultipleIntervalsPerCve(unittest.TestCase):
    def test_union_semantics_and_dedup(self):
        cat = build_catalog([
            ("p", "CVE-M", "1.0", True, "2.0", True),
            ("p", "CVE-M", "5.0", True, "6.0", True),
        ])
        res = run(cat, [("a", "p", "1.5"), ("b", "p", "3.0"), ("c", "p", "5.5")])
        self.assertEqual(res[0][1], {"CVE-M"})
        self.assertEqual(res[1][1], set())
        self.assertEqual(res[2][1], {"CVE-M"})

    def test_overlapping_same_cve_reported_once(self):
        cat = build_catalog([
            ("p", "CVE-O", "1.0", True, "4.0", True),
            ("p", "CVE-O", "2.0", True, "8.0", True),
            ("p", "CVE-O", "3.0", True, "9.0", True),
        ])
        self.assertEqual(run(cat, [("r", "p", "3.5")])[0][1], {"CVE-O"})

    def test_same_cve_different_packages(self):
        cat = build_catalog([
            ("p1", "CVE-X", "1.0", True, "2.0", True),
            ("p2", "CVE-X", "9.0", True, "10.0", True),
        ])
        self.assertEqual(run(cat, [("r", "p1", "1.5")])[0][1], {"CVE-X"})
        self.assertEqual(run(cat, [("r", "p2", "1.5")])[0][1], set())
        self.assertEqual(run(cat, [("r", "p2", "9.5")])[0][1], {"CVE-X"})


class TestStreaming(unittest.TestCase):
    def test_order_and_empty_results_preserved(self):
        cat = build_catalog([("p", "CVE-1", "1.0", True, "1.0", True)])
        obs = [("r1", "p", "1.0"), ("r2", "p", "2.0"), ("r3", "q", "1.0"), ("r4", "p", "1.0-0")]
        res = run(cat, obs)
        self.assertEqual([r[0] for r in res], ["r1", "r2", "r3", "r4"])
        self.assertEqual(res[0][1], {"CVE-1"})
        self.assertEqual(res[1][1], set())
        self.assertEqual(res[2][1], set())
        self.assertEqual(res[3][1], {"CVE-1"})

    def test_iterator_consumed_lazily(self):
        cat = build_catalog([("p", "CVE-1", None, False, None, False)])
        consumed = []

        def gen():
            for i in range(5):
                consumed.append(i)
                yield (f"r{i}", "p", "1.0")

        it = scan(cat, gen())
        self.assertEqual(consumed, [])  # 尚未消费
        next(it)
        self.assertEqual(consumed, [0])  # 逐条消费，不提前耗尽
        rest = list(it)
        self.assertEqual(len(rest), 4)
        self.assertEqual(consumed, [0, 1, 2, 3, 4])


if __name__ == "__main__":
    unittest.main()

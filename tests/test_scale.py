import random
import unittest

from cvematch import build_catalog, scan


def make_row(package, cve, lower=None, upper=None):
    return {"package": package, "cve": cve, "lower": lower, "upper": upper}


class SparseScaleTest(unittest.TestCase):
    # 50000 个稀疏区间 + 100000 条乱序互异查询,单条至多命中一个 CVE

    N_INTERVALS = 50_000
    N_QUERIES = 100_000

    @classmethod
    def setUpClass(cls):
        # CVE-i 覆盖 [3i.0, 3i+1.0],区间之间留有空隙
        rows = [
            make_row("pkg", "CVE-%d" % i, "%d.0" % (3 * i), "%d.0" % (3 * i + 1))
            for i in range(cls.N_INTERVALS)
        ]
        cls.catalog = build_catalog(rows)
        rng = random.Random(42)
        qs = rng.sample(range(3 * cls.N_INTERVALS), cls.N_QUERIES)
        rng.shuffle(qs)
        cls.observations = [
            ("r%d" % n, "pkg", "%d.5" % q) for n, q in enumerate(qs)
        ]
        cls.expected = [
            frozenset({"CVE-%d" % (q // 3)}) if q % 3 == 0 else frozenset()
            for q in qs
        ]

    def test_results_correct(self):
        got = [hits for _, hits in scan(self.catalog, iter(self.observations))]
        self.assertEqual(got, self.expected)

    def test_cost_not_degenerated(self):
        self.catalog.reset_stats()
        list(scan(self.catalog, iter(self.observations)))
        stats = dict(self.catalog.stats)
        n = self.N_QUERIES
        # 逐条全扫的基线:每条查询 50000 次区间检查
        self.assertLess(stats["interval_checks"], n * 40, stats)
        # 二分定位单元格:每条查询约 log2(100000) 约 17 次版本比较
        self.assertLess(stats["version_comparisons"], n * 32, stats)
        print("\nsparse: %d queries -> %s (avg %.1f cmp, %.1f checks per query)"
              % (n, stats, stats["version_comparisons"] / n,
                 stats["interval_checks"] / n))


class SingleCveOverlapTest(unittest.TestCase):
    # 50000 个区间同属一个 CVE 且覆盖同一查询版本

    def test_merged_away_duplicates(self):
        n = 50_000
        rows = [
            make_row("pkg", "CVE-big", "%d.0" % i, "%d.0" % (2 * n - i))
            for i in range(n)
        ]
        catalog = build_catalog(rows)
        catalog.reset_stats()
        results = list(scan(catalog, iter(("r", "pkg", "%d.0" % n) for _ in range(1000))))
        self.assertEqual(results, [("r", frozenset({"CVE-big"}))] * 1000)
        stats = dict(catalog.stats)
        # 合并后只剩 1 个区间,成本与 50000 个重复区间无关
        self.assertLess(stats["interval_checks"], 1000 * 10, stats)
        self.assertLess(stats["version_comparisons"], 1000 * 10, stats)
        print("\noverlap: 1000 queries over 50000 same-CVE intervals -> %s" % stats)


if __name__ == "__main__":
    unittest.main()

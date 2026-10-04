"""规模测试：验证查询成本没有退化为逐条全扫（看计数器，不只看耗时）。

场景 1：同一包 50000 个稀疏区间，100000 条乱序互异查询，每条至多命中一个 CVE。
场景 2：50000 个区间全部属于同一 CVE 且覆盖同一查询版本。
"""

import os
import random
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from cvematch import build_catalog, scan, stats

N_INTERVALS = 50_000
N_QUERIES = 100_000


def sparse_rows(n):
    # 区间 [i.0, i.50]，相邻区间之间留有间隙 (i.50, i+1.0)
    return [
        ("pkg", f"CVE-{i}", f"{i}.0", True, f"{i}.50", True)
        for i in range(n)
    ]


class TestScaleSparse(unittest.TestCase):
    def test_sparse_intervals_streaming(self):
        rows = sparse_rows(N_INTERVALS)
        cat = build_catalog(rows)

        rng = random.Random(7)
        # 乱序互异查询：一半落在区间内（版本 i.25），一半落在间隙（版本 i.75）
        versions = [
            f"{i % N_INTERVALS}.25" if i < N_INTERVALS else f"{i % N_INTERVALS}.75"
            for i in range(N_QUERIES)
        ]
        rng.shuffle(versions)
        observations = ((f"obs-{i}", "pkg", v) for i, v in enumerate(versions))

        stats.reset()
        results = list(scan(cat, observations))
        self.assertEqual(len(results), N_QUERIES)

        # 正确性抽查：i.25 命中 CVE-i，i.75 不命中
        for record_id, hits in results[:1000]:
            idx = int(record_id.split("-")[1])
            base = versions[idx].split(".")[0]
            if versions[idx].endswith(".25"):
                self.assertEqual(hits, {f"CVE-{base}"})
            else:
                self.assertEqual(hits, set())

        per_query_cmp = stats.version_comparisons / N_QUERIES
        per_query_chk = stats.interval_checks / N_QUERIES
        print(
            f"\n[sparse] 版本比较 {stats.version_comparisons} 次 "
            f"(均值 {per_query_cmp:.1f}/条)，区间检查 {stats.interval_checks} 次 "
            f"(均值 {per_query_chk:.1f}/条)；全扫需 {N_INTERVALS}/条"
        )
        # log2(50000) ≈ 16；给出宽松上界，但远小于逐条全扫的 50000
        self.assertLess(per_query_cmp, 200)
        self.assertLess(per_query_chk, 10)


class TestScaleSingleCve(unittest.TestCase):
    def test_all_intervals_same_cve(self):
        # 50000 个重叠区间同属一个 CVE，全部覆盖版本 "1.0"
        rows = [
            ("pkg", "CVE-ONE", f"0.{i}", True, f"2.{i}", True)
            for i in range(N_INTERVALS)
        ]
        cat = build_catalog(rows)

        stats.reset()
        results = list(scan(cat, iter([(f"q{i}", "pkg", "1.0") for i in range(1000)])))
        self.assertTrue(all(hits == {"CVE-ONE"} for _, hits in results))

        per_query_chk = stats.interval_checks / 1000
        print(
            f"\n[single-cve] 版本比较 {stats.version_comparisons} 次，"
            f"区间检查 {stats.interval_checks} 次 "
            f"(均值 {per_query_chk:.1f}/条)；区间总数 {N_INTERVALS}"
        )
        # 合并后只剩 1 个区间：检查次数与重复区间数量无关
        self.assertLess(per_query_chk, 5)
        self.assertLess(stats.version_comparisons / 1000, 50)


if __name__ == "__main__":
    unittest.main()

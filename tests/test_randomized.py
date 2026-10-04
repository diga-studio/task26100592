"""固定随机种子的小目录，与直接全扫的参考实现逐条对照。

覆盖：无界区间、同 CVE 重叠区间、不同包的同名 CVE。
"""

import os
import random
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from cvematch import build_catalog, compare_versions, scan

SEED = 20261005

UPSTREAM_PARTS = ["1", "2", "10", "01", "0.5", "1.0", "1.0~rc1", "2.0a", "1.0+dfsg", "3"]


def rand_version(rng):
    v = rng.choice(UPSTREAM_PARTS)
    if rng.random() < 0.3:
        v = f"{rng.randint(0, 2)}:{v}"
    if rng.random() < 0.5:
        v = f"{v}-{rng.choice(['0', '1', '2', '1~exp1', '0.0'])}"
    return v


def rand_rows(rng, n):
    rows = []
    pkgs = ["alpha", "beta", "gamma"]
    cves = ["CVE-1", "CVE-2", "CVE-3"]
    for _ in range(n):
        pkg = rng.choice(pkgs)
        cve = rng.choice(cves)
        lo = rand_version(rng) if rng.random() < 0.8 else None
        hi = rand_version(rng) if rng.random() < 0.8 else None
        rows.append((pkg, cve, lo, rng.random() < 0.5, hi, rng.random() < 0.5))
    return rows


def reference_scan(rows, observations):
    """直接全扫的参考实现。"""
    out = []
    for record_id, pkg, version in observations:
        hits = set()
        for rpkg, cve, lo, lo_c, hi, hi_c in rows:
            if rpkg != pkg:
                continue
            if lo is not None:
                c = compare_versions(lo, version)
                if c > 0 or (c == 0 and not lo_c):
                    continue
            if hi is not None:
                c = compare_versions(hi, version)
                if c < 0 or (c == 0 and not hi_c):
                    continue
            hits.add(cve)
        out.append((record_id, hits))
    return out


class TestRandomizedCrossCheck(unittest.TestCase):
    def test_matches_brute_force(self):
        rng = random.Random(SEED)
        rows = rand_rows(rng, 120)
        # 确保特殊结构存在：无界区间、同 CVE 多区间、跨包同名 CVE
        rows.append(("alpha", "CVE-1", None, False, None, False))
        rows.append(("alpha", "CVE-2", "1.0", True, "2.0", True))
        rows.append(("alpha", "CVE-2", "1.5", True, "3.0", True))
        rows.append(("beta", "CVE-2", "1.0", True, "1.0", True))
        cat = build_catalog(rows)
        observations = [
            (f"obs-{i}", rng.choice(["alpha", "beta", "gamma", "delta"]), rand_version(rng))
            for i in range(400)
        ]
        expected = reference_scan(rows, observations)
        actual = list(scan(cat, iter(observations)))
        self.assertEqual(actual, expected)


if __name__ == "__main__":
    unittest.main()

import random
import unittest

from cvematch import build_catalog, compare_versions, scan


def make_row(package, cve, lower=None, upper=None,
             lower_inclusive=True, upper_inclusive=True):
    return {
        "package": package, "cve": cve,
        "lower": lower, "lower_inclusive": lower_inclusive,
        "upper": upper, "upper_inclusive": upper_inclusive,
    }


def reference_scan(rows, observations):
    """直接全扫的参考实现。"""
    out = []
    for record_id, package, version in observations:
        hits = set()
        for row in rows:
            if row["package"] != package:
                continue
            lo, hi = row["lower"], row["upper"]
            if lo is not None:
                c = compare_versions(version, lo)
                if c < 0 or (c == 0 and not row["lower_inclusive"]):
                    continue
            if hi is not None:
                c = compare_versions(version, hi)
                if c > 0 or (c == 0 and not row["upper_inclusive"]):
                    continue
            hits.add(row["cve"])
        out.append((record_id, frozenset(hits)))
    return out


class BoundaryTest(unittest.TestCase):
    def check(self, rows, package, version, want):
        catalog = build_catalog(rows)
        results = list(scan(catalog, iter([("r", package, version)])))
        self.assertEqual(results, [("r", frozenset(want))])

    def test_open_closed_crossing(self):
        rows = [
            make_row("p", "CVE-lo-open", "1.0", "2.0", lower_inclusive=False),
            make_row("p", "CVE-lo-closed", "1.0", "2.0"),
            make_row("p", "CVE-hi-open", "1.0", "2.0", upper_inclusive=False),
            make_row("p", "CVE-hi-closed", "1.0", "2.0"),
            make_row("p", "CVE-both-open", "1.0", "2.0",
                     lower_inclusive=False, upper_inclusive=False),
        ]
        all_cves = {row["cve"] for row in rows}
        self.check(rows, "p", "1.0",
                   {"CVE-lo-closed", "CVE-hi-open", "CVE-hi-closed"})
        self.check(rows, "p", "2.0",
                   {"CVE-lo-open", "CVE-lo-closed", "CVE-hi-closed"})
        self.check(rows, "p", "1.5", all_cves)

    def test_semantically_equal_bound_open_side(self):
        # 上界写作 "1.0-0" 且开放:查询 "1.0"(语义相等)不得命中
        rows = [make_row("p", "CVE-x", "0.5", "1.0-0", upper_inclusive=False)]
        self.check(rows, "p", "1.0", set())
        self.check(rows, "p", "1.0-0", set())
        self.check(rows, "p", "0.9", {"CVE-x"})
        # 下界写作 "1.01" 且开放:查询 "1.1"(语义相等)不得命中
        rows = [make_row("p", "CVE-y", "1.01", "9.9", lower_inclusive=False)]
        self.check(rows, "p", "1.1", set())
        self.check(rows, "p", "1.1-0", set())
        self.check(rows, "p", "1.1-1", {"CVE-y"})
        # 同样的界改为闭合则必须命中
        rows = [make_row("p", "CVE-z", "0.5", "1.0-0")]
        self.check(rows, "p", "1.0", {"CVE-z"})

    def test_empty_intervals_never_match(self):
        rows = [
            make_row("p", "CVE-inverted", "2.0", "1.0"),
            make_row("p", "CVE-point-open", "1.0", "1.0", lower_inclusive=False),
            make_row("p", "CVE-point-open2", "1.0", "1.0", upper_inclusive=False),
            make_row("p", "CVE-point-closed", "1.0", "1.0"),
        ]
        self.check(rows, "p", "1.0", {"CVE-point-closed"})
        self.check(rows, "p", "1.5", set())

    def test_unbounded_and_epoch(self):
        rows = [
            make_row("p", "CVE-all"),
            make_row("p", "CVE-old", None, "1:0.5", upper_inclusive=False),
            make_row("p", "CVE-new", "1:0.5"),
        ]
        self.check(rows, "p", "0:9.9", {"CVE-all", "CVE-old"})
        self.check(rows, "p", "1:0.5", {"CVE-all", "CVE-new"})
        self.check(rows, "p", "2:0.1", {"CVE-all", "CVE-new"})

    def test_same_cve_multiple_intervals_dedup(self):
        rows = [
            make_row("p", "CVE-m", "1.0", "2.0"),
            make_row("p", "CVE-m", "1.5", "3.0"),
            make_row("p", "CVE-m", "5.0", "6.0"),
        ]
        self.check(rows, "p", "1.7", {"CVE-m"})
        self.check(rows, "p", "4.0", set())

    def test_missing_package_yields_empty(self):
        catalog = build_catalog([make_row("p", "CVE-1")])
        results = list(scan(catalog, iter([("r", "nope", "1.0")])))
        self.assertEqual(results, [("r", frozenset())])


class StreamingTest(unittest.TestCase):
    def test_lazy_one_pass(self):
        catalog = build_catalog([make_row("p", "CVE-1", "1.0", "2.0")])
        consumed = []

        def gen():
            for i in range(10):
                consumed.append(i)
                yield (f"r{i}", "p", "1.5")

        it = scan(catalog, gen())
        first = next(it)
        self.assertEqual(first, ("r0", frozenset({"CVE-1"})))
        self.assertEqual(consumed, [0])  # 不提前耗尽迭代器
        rest = list(it)
        self.assertEqual(len(rest), 9)
        self.assertEqual(consumed, list(range(10)))

    def test_dict_observations(self):
        catalog = build_catalog([make_row("p", "CVE-1", "1.0", "2.0")])
        obs = iter([{"id": "x", "package": "p", "version": "1.5"}])
        self.assertEqual(list(scan(catalog, obs)), [("x", frozenset({"CVE-1"}))])


def random_version(rng):
    parts = []
    if rng.random() < 0.3:
        parts.append(str(rng.randint(0, 2)) + ":")
    upstream = []
    for _ in range(rng.randint(1, 4)):
        kind = rng.random()
        if kind < 0.5:
            upstream.append(str(rng.randint(0, 10 ** rng.randint(1, 3))))
        elif kind < 0.7:
            upstream.append(rng.choice([".", "+", "_"]))
        elif kind < 0.85:
            upstream.append(rng.choice(["a", "b", "rc", "alpha", "Z"]))
        else:
            upstream.append("~" + rng.choice(["rc1", "beta", "x"]))
    parts.append("".join(upstream).strip(".") or "0")
    if rng.random() < 0.5:
        parts.append("-" + str(rng.randint(0, 20)))
    return "".join(parts)


class RandomizedCrossCheckTest(unittest.TestCase):
    def test_against_brute_force(self):
        rng = random.Random(20261005)
        packages = ["alpha", "beta", "gamma"]
        cves = ["CVE-100", "CVE-200", "CVE-300"]  # 不同包共享同名 CVE
        rows = []
        for _ in range(300):
            lo = random_version(rng) if rng.random() < 0.8 else None
            hi = random_version(rng) if rng.random() < 0.8 else None
            rows.append(make_row(
                rng.choice(packages), rng.choice(cves), lo, hi,
                lower_inclusive=rng.random() < 0.7,
                upper_inclusive=rng.random() < 0.7,
            ))
        observations = [
            (f"r{i}", rng.choice(packages + ["unknown"]), random_version(rng))
            for i in range(2000)
        ]
        catalog = build_catalog(rows)
        got = list(scan(catalog, iter(observations)))
        want = reference_scan(rows, observations)
        self.assertEqual(got, want)


if __name__ == "__main__":
    unittest.main()

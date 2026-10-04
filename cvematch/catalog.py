"""目录构建与流式扫描。

目录按包名分组；每个包内先把同一 CVE 的区间合并为互不相交的并集，
再对所有合并后的区间建静态区间树（按下界排序的数组 + 子树最大上界）。
查询为点 stab：O(log N + K)，N 为该包合并后区间数，K 为命中的不同 CVE 数。
"""

from functools import cmp_to_key

from .version import compare_versions

__all__ = ["build_catalog", "scan", "stats", "Catalog", "Stats"]


class Stats:
    """查询成本计数器（版本比较次数 / 叶子区间检查次数）。"""

    def __init__(self) -> None:
        self.version_comparisons = 0
        self.interval_checks = 0

    def reset(self) -> None:
        self.version_comparisons = 0
        self.interval_checks = 0


stats = Stats()


def _cmp(a, b):
    stats.version_comparisons += 1
    return compare_versions(a, b)


class _Interval:
    __slots__ = ("lo", "lo_closed", "hi", "hi_closed", "cve")

    def __init__(self, lo, lo_closed, hi, hi_closed, cve=None):
        self.lo = lo
        self.lo_closed = lo_closed
        self.hi = hi
        self.hi_closed = hi_closed
        self.cve = cve

    def is_empty(self):
        if self.lo is None or self.hi is None:
            return False
        c = compare_versions(self.lo, self.hi)
        if c > 0:
            return True
        if c == 0 and not (self.lo_closed and self.hi_closed):
            return True
        return False

    def contains(self, v):
        if self.lo is not None:
            c = _cmp(self.lo, v)
            if c > 0 or (c == 0 and not self.lo_closed):
                return False
        if self.hi is not None:
            c = _cmp(self.hi, v)
            if c < 0 or (c == 0 and not self.hi_closed):
                return False
        return True


def _cmp_bound(a, b):
    """下界排序键：None（-inf）最小；同版本闭区间排前。"""
    if a is None:
        return -1 if b is not None else 0
    if b is None:
        return 1
    return compare_versions(a, b)


def _interval_lo_key(x, y):
    c = _cmp_bound(x.lo, y.lo)
    if c:
        return c
    if x.lo_closed != y.lo_closed:
        return -1 if x.lo_closed else 1
    return 0


def _merge_cve_intervals(intervals):
    """把同一 CVE 的区间合并为互不相交的区间列表。"""
    intervals = sorted(intervals, key=cmp_to_key(_interval_lo_key))
    merged = []
    for iv in intervals:
        if merged:
            last = merged[-1]
            touch = False
            if last.hi is None or iv.lo is None:
                touch = True
            else:
                c = compare_versions(iv.lo, last.hi)
                touch = c < 0 or (c == 0 and (last.hi_closed or iv.lo_closed))
            if touch:
                if last.hi is not None:
                    if iv.hi is None:
                        last.hi, last.hi_closed = None, False
                    else:
                        c = compare_versions(iv.hi, last.hi)
                        if c > 0 or (c == 0 and iv.hi_closed):
                            last.hi, last.hi_closed = iv.hi, iv.hi_closed
                continue
        merged.append(_Interval(iv.lo, iv.lo_closed, iv.hi, iv.hi_closed))
    return merged


class _PkgIndex:
    """单包的静态区间树：按下界排序的数组 + 子树最大上界（None 表示 +inf）。"""

    __slots__ = ("ivs", "max_hi", "_leaf_base")

    def __init__(self, intervals):
        self.ivs = sorted(intervals, key=cmp_to_key(_interval_lo_key))
        n = len(self.ivs)
        size = 1
        while size < n:
            size <<= 1
        self.max_hi = [None] * (2 * size)
        # 叶子存各自上界（_INF 表示 +inf，最大）；内部节点存子树最大上界。
        self._leaf_base = size
        for i, iv in enumerate(self.ivs):
            self.max_hi[size + i] = iv.hi if iv.hi is not None else _INF
        for node in range(size - 1, 0, -1):
            self.max_hi[node] = _max_hi(self.max_hi[2 * node], self.max_hi[2 * node + 1])

    def query(self, version, out):
        if not self.ivs:
            return
        n = len(self.ivs)
        base = self._leaf_base
        stack = [(1, 0, base)]
        while stack:
            node, l, r = stack.pop()
            mh = self.max_hi[node]
            if mh is not _INF and mh is not None and _cmp(mh, version) < 0:
                continue
            first = self.ivs[l].lo if l < n else None
            if l < n and first is not None and _cmp(first, version) > 0:
                continue
            if l >= n:
                continue
            if r - l == 1:
                stats.interval_checks += 1
                iv = self.ivs[l]
                if iv.contains(version):
                    out.add(iv.cve)
                continue
            mid = (l + r) >> 1
            stack.append((2 * node, l, mid))
            stack.append((2 * node + 1, mid, r))


class _Inf:
    pass


_INF = _Inf()


def _max_hi(a, b):
    if a is _INF or b is _INF:
        return _INF
    if a is None:
        return b
    if b is None:
        return a
    return a if compare_versions(a, b) >= 0 else b


class Catalog:
    """按包名索引的只读区间目录。"""

    def __init__(self) -> None:
        self._packages = {}

    def query(self, package, version):
        idx = self._packages.get(package)
        out = set()
        if idx is not None:
            idx.query(version, out)
        return out


def build_catalog(rows) -> Catalog:
    """rows: (package, cve, lower, lower_inclusive, upper, upper_inclusive) 的可迭代对象。

    lower/upper 为版本字符串或 None（表示该方向无界）。空区间被丢弃。
    """
    by_pkg = {}
    for package, cve, lo, lo_closed, hi, hi_closed in rows:
        iv = _Interval(lo, bool(lo_closed), hi, bool(hi_closed))
        if iv.is_empty():
            continue
        by_pkg.setdefault(package, {}).setdefault(cve, []).append(iv)
    catalog = Catalog()
    for package, cve_map in by_pkg.items():
        merged = []
        for cve, ivs in cve_map.items():
            for iv in _merge_cve_intervals(ivs):
                iv.cve = cve
                merged.append(iv)
        catalog._packages[package] = _PkgIndex(merged)
    return catalog


def scan(catalog: Catalog, observations):
    """observations: (record_id, package, version) 的一次性迭代器。

    按输入顺序逐条产出 (record_id, set_of_cve)；无命中也产出空集合。
    """
    for record_id, package, version in observations:
        yield record_id, catalog.query(package, version)

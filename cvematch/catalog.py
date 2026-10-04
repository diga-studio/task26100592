"""CVE 目录构建与流式扫描。

查询结构:每个包内,把所有区间端点版本去重排序,将版本轴压缩为
整数"单元格"(每个端点值一个格、相邻端点间的空隙各一个格)。
区间是否包含某版本只取决于该版本落在哪个单元格,因此开闭边界
语义可以无损地映射为闭整数区间。对每个 CVE 的整数区间先做合并
(消除同 CVE 的重叠重复),再对所有区间建中心区间树,点刺查询
代价 O(log R + K),K 为命中的不同 CVE 数。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import cmp_to_key
from typing import Any, Iterable, Iterator

from .version import compare_versions


# 目录阶段区间:[lower, lower_inclusive, upper, upper_inclusive, cve]
# lower/upper 为 None 表示该方向无界。


def _is_empty(iv: list) -> bool:
    if iv[0] is None or iv[2] is None:
        return False
    c = compare_versions(iv[0], iv[2])
    if c > 0:
        return True
    return c == 0 and not (iv[1] and iv[3])


def _cmp_lower_raw(x: list, y: list) -> int:
    if x[0] is None:
        return 0 if y[0] is None else -1
    if y[0] is None:
        return 1
    c = compare_versions(x[0], y[0])
    if c != 0:
        return c
    return (y[1] > x[1]) - (x[1] > y[1])  # 同一下界,闭端点起始更早


def _merge_version_intervals(ivs: list[list]) -> list[list]:
    """在版本空间合并同一 CVE 的区间(重叠或相接即并)。"""
    merged: list[list] = []
    for iv in sorted(ivs, key=cmp_to_key(_cmp_lower_raw)):
        if merged:
            cur = merged[-1]
            if cur[2] is None:
                continue  # 上一区间上界无界,吞掉后续
            c = -1 if iv[0] is None else compare_versions(iv[0], cur[2])
            if c < 0 or (c == 0 and (iv[1] or cur[3])):
                if iv[2] is None:
                    cur[2], cur[3] = None, True
                else:
                    hc = compare_versions(iv[2], cur[2])
                    if hc > 0:
                        cur[2], cur[3] = iv[2], iv[3]
                    elif hc == 0:
                        cur[3] = cur[3] or iv[3]
                continue
        merged.append(list(iv))
    return merged


def _cell_of(values: list[str], version: str, stats: dict | None = None) -> int:
    """版本所在的单元格编号。

    端点值 values[i] 对应格 2i+1;values[i] 与 values[i+1] 之间的
    空隙对应格 2i+2;最小端点之前为 0,最大端点之后为 2*len(values)。
    """
    lo, hi = 0, len(values)
    while lo < hi:
        mid = (lo + hi) // 2
        if stats is not None:
            stats["version_comparisons"] += 1
        c = compare_versions(version, values[mid])
        if c == 0:
            return 2 * mid + 1
        if c < 0:
            hi = mid
        else:
            lo = mid + 1
    return 2 * lo


class _Node:
    """中心区间树节点,区间为闭整数区间 [lo_cell, hi_cell]。"""

    __slots__ = ("center", "by_lo", "by_hi", "left", "right")

    def __init__(self, center, by_lo, by_hi, left, right):
        self.center = center
        self.by_lo = by_lo
        self.by_hi = by_hi
        self.left = left
        self.right = right


def _build_tree(intervals: list[list]) -> _Node | None:
    """整数闭区间的中心区间树;inside 恒非空,深度 O(log n)。"""
    if not intervals:
        return None
    endpoints = sorted({iv[0] for iv in intervals} | {iv[1] for iv in intervals})
    center = endpoints[len(endpoints) // 2]
    inside, left, right = [], [], []
    for iv in intervals:
        if iv[0] <= center <= iv[1]:
            inside.append(iv)
        elif iv[1] < center:
            left.append(iv)
        else:
            right.append(iv)
    by_lo = sorted(inside, key=lambda iv: iv[0])
    by_hi = sorted(inside, key=lambda iv: -iv[1])
    return _Node(center, by_lo, by_hi, _build_tree(left), _build_tree(right))


def _stab(node: _Node | None, cell: int, hits: set, stats: dict) -> None:
    if node is None:
        return
    if cell == node.center:
        for iv in node.by_lo:
            stats["interval_checks"] += 1
            hits.add(iv[2])
        return
    if cell < node.center:
        for iv in node.by_lo:  # 节点区间上界 >= center > cell,只需查下界
            stats["interval_checks"] += 1
            if iv[0] > cell:
                break
            hits.add(iv[2])
        _stab(node.left, cell, hits, stats)
    else:
        for iv in node.by_hi:  # 节点区间下界 <= center < cell,只需查上界
            stats["interval_checks"] += 1
            if iv[1] < cell:
                break
            hits.add(iv[2])
        _stab(node.right, cell, hits, stats)


def _merge_cells(intervals: list[list]) -> list[list]:
    """合并同一 CVE 的闭整数区间(相邻格可并,因为每个格都有意义)。"""
    intervals.sort(key=lambda iv: iv[0])
    merged: list[list] = []
    for iv in intervals:
        if merged and iv[0] <= merged[-1][1] + 1:
            if iv[1] > merged[-1][1]:
                merged[-1][1] = iv[1]
        else:
            merged.append(list(iv))
    return merged


@dataclass
class _PackageIndex:
    values: list[str]          # 去重排序的端点版本
    tree: _Node | None         # 整数区间中心树


@dataclass
class Catalog:
    """只读目录查询对象。stats 记录查询阶段的版本比较与区间检查次数。"""

    packages: dict = field(default_factory=dict)
    stats: dict = field(default_factory=lambda: {
        "version_comparisons": 0,
        "interval_checks": 0,
    })

    def reset_stats(self) -> None:
        self.stats["version_comparisons"] = 0
        self.stats["interval_checks"] = 0


def build_catalog(rows: Iterable[dict]) -> Catalog:
    """从目录记录构建可查询对象。

    每条记录为 dict,键:package, cve, lower, lower_inclusive, upper,
    upper_inclusive。lower/upper 缺省或为 None 表示该方向无界,
    *_inclusive 缺省为 True。空区间(下界大于上界,或界相等但一侧
    开放)在构建期丢弃,不会命中。
    """
    by_package: dict[str, list[list]] = {}
    for row in rows:
        iv = [
            row.get("lower"),
            bool(row.get("lower_inclusive", True)),
            row.get("upper"),
            bool(row.get("upper_inclusive", True)),
            row["cve"],
        ]
        if not _is_empty(iv):
            by_package.setdefault(row["package"], []).append(iv)

    packages: dict[str, _PackageIndex] = {}
    for package, ivs in by_package.items():
        by_cve_raw: dict[str, list[list]] = {}
        for iv in ivs:
            by_cve_raw.setdefault(iv[4], []).append(iv)
        merged_ivs = [
            iv for cve, group in by_cve_raw.items()
            for iv in _merge_version_intervals(group)
        ]
        values = sorted(
            {v for iv in merged_ivs for v in (iv[0], iv[2]) if v is not None},
            key=cmp_to_key(compare_versions),
        )
        max_cell = 2 * len(values)
        by_cve: dict[str, list[list]] = {}
        for lo, lo_incl, hi, hi_incl, cve in merged_ivs:
            lo_cell = 0 if lo is None else _cell_of(values, lo) + (0 if lo_incl else 1)
            hi_cell = max_cell if hi is None else _cell_of(values, hi) - (0 if hi_incl else 1)
            if lo_cell <= hi_cell:
                by_cve.setdefault(cve, []).append([lo_cell, hi_cell, cve])
        merged: list[list] = []
        for cve, cells in by_cve.items():
            merged.extend(_merge_cells(cells))
        packages[package] = _PackageIndex(values=values, tree=_build_tree(merged))
    return Catalog(packages=packages)


def _parse_observation(obs: Any) -> tuple[Any, str, str]:
    if isinstance(obs, dict):
        return obs["id"], obs["package"], obs["version"]
    record_id, package, version = obs
    return record_id, package, version


def scan(catalog: Catalog, observations: Iterable[Any]) -> Iterator[tuple]:
    """流式扫描上报,逐条产出 (记录标识, 命中的CVE集合)。

    observations 为一次性迭代器,每项为 dict(id/package/version)
    或三元组 (id, package, version)。逐条消费、逐条产出,不缓存
    历史结果,内存只随当前记录及其命中集合增长。
    """
    for obs in observations:
        record_id, package, version = _parse_observation(obs)
        hits: set = set()
        index = catalog.packages.get(package)
        if index is not None and index.tree is not None:
            cell = _cell_of(index.values, version, catalog.stats)
            _stab(index.tree, cell, hits, catalog.stats)
        yield record_id, frozenset(hits)

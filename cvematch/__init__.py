"""离线 CVE 版本匹配库（Debian 版本规则）。"""

from .version import compare_versions
from .catalog import build_catalog, scan, stats, Catalog, Stats

__all__ = [
    "compare_versions",
    "build_catalog",
    "scan",
    "stats",
    "Catalog",
    "Stats",
]

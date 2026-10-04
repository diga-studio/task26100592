"""离线 CVE 版本匹配库(Debian 版本规则)。"""

from .version import compare_versions
from .catalog import Catalog, build_catalog, scan

__all__ = ["compare_versions", "Catalog", "build_catalog", "scan"]

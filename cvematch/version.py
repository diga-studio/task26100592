"""Debian 版本号解析与比较。"""

from __future__ import annotations


def _split(version: str) -> tuple[int, str, str]:
    """拆分为 (epoch, upstream, revision)。"""
    epoch = 0
    rest = version
    if ":" in rest:
        epoch_str, rest = rest.split(":", 1)
        epoch = int(epoch_str)
    if "-" in rest:
        upstream, revision = rest.rsplit("-", 1)
    else:
        upstream, revision = rest, "0"
    return epoch, upstream, revision


def _char_order(ch: str | None) -> int:
    """非数字字符的排序权重:波浪号 < 段结束 < ASCII字母 < 其他字符。"""
    if ch is None:
        return 0
    if ch == "~":
        return -1
    if ("a" <= ch <= "z") or ("A" <= ch <= "Z"):
        return ord(ch)
    return ord(ch) + 256


def _compare_part(a: str, b: str) -> int:
    """按非数字段、数字段交替比较 upstream 或 revision。"""
    i, j = 0, 0
    len_a, len_b = len(a), len(b)
    while i < len_a or j < len_b:
        # 非数字段:逐字符按 _char_order 比较
        while (i < len_a and not a[i].isdigit()) or (j < len_b and not b[j].isdigit()):
            ca = _char_order(a[i]) if i < len_a and not a[i].isdigit() else _char_order(None)
            cb = _char_order(b[j]) if j < len_b and not b[j].isdigit() else _char_order(None)
            if ca != cb:
                return -1 if ca < cb else 1
            if i < len_a and not a[i].isdigit():
                i += 1
            if j < len_b and not b[j].isdigit():
                j += 1
        # 数字段:忽略前导零,先比长度再按字典序(等长数字串字典序即数值序)
        while i < len_a and a[i] == "0":
            i += 1
        while j < len_b and b[j] == "0":
            j += 1
        start_a, start_b = i, j
        while i < len_a and a[i].isdigit():
            i += 1
        while j < len_b and b[j].isdigit():
            j += 1
        num_a, num_b = a[start_a:i], b[start_b:j]
        if len(num_a) != len(num_b):
            return 1 if len(num_a) > len(num_b) else -1
        if num_a != num_b:
            return 1 if num_a > num_b else -1
    return 0


def compare_versions(a: str, b: str) -> int:
    """比较两个 Debian 版本字符串,返回负数、零或正数。"""
    epoch_a, upstream_a, revision_a = _split(a)
    epoch_b, upstream_b, revision_b = _split(b)
    if epoch_a != epoch_b:
        return -1 if epoch_a < epoch_b else 1
    result = _compare_part(upstream_a, upstream_b)
    if result != 0:
        return result
    return _compare_part(revision_a, revision_b)

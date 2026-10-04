"""Debian 版本比较（dpkg 顺序）。

版本由可选 epoch、upstream 和可选 revision 组成：
    [epoch:]upstream[-revision]
epoch 为冒号前的非负整数（缺省为 0）；revision 取最后一个连字符后的部分
（缺省视为字符串 "0"）。依次比较 epoch、upstream、revision。

upstream / revision 按非数字段、数字段交替比较：
  - 非数字段逐字符比较，顺序为：波浪号 < 段结束 < ASCII 字母 < 其他字符，
    同类字符按 ASCII 顺序；
  - 数字段忽略前导零后按整数值比较，空数字段视为零；整数可超过 64 位。
"""

__all__ = ["compare_versions"]


def _char_rank(ch):
    """非数字字符的比较键：~ < 段结束 < 字母 < 其他。"""
    if ch is None:
        return (1,)
    if ch == "~":
        return (0,)
    if ch.isalpha():
        return (2, ord(ch))
    return (3, ord(ch))


def _compare_nondigit(x, y):
    n = max(len(x), len(y))
    for i in range(n):
        ra = _char_rank(x[i] if i < len(x) else None)
        rb = _char_rank(y[i] if i < len(y) else None)
        if ra != rb:
            return -1 if ra < rb else 1
    return 0


def _compare_digit(x, y):
    # 忽略前导零后按整数值比较；空段视为零。用长度+字典序，支持任意大整数。
    a = x.lstrip("0")
    b = y.lstrip("0")
    if len(a) != len(b):
        return -1 if len(a) < len(b) else 1
    if a != b:
        return -1 if a < b else 1
    return 0


def _compare_part(x, y):
    i = 0
    j = 0
    while i < len(x) or j < len(y):
        xi = i
        while xi < len(x) and not x[xi].isdigit():
            xi += 1
        yj = j
        while yj < len(y) and not y[yj].isdigit():
            yj += 1
        r = _compare_nondigit(x[i:xi], y[j:yj])
        if r:
            return r
        i, j = xi, yj
        xi = i
        while xi < len(x) and x[xi].isdigit():
            xi += 1
        yj = j
        while yj < len(y) and y[yj].isdigit():
            yj += 1
        r = _compare_digit(x[i:xi], y[j:yj])
        if r:
            return r
        i, j = xi, yj
    return 0


def _split(version):
    epoch = 0
    rest = version
    head, sep, tail = version.partition(":")
    if sep and head.isdigit():
        epoch = int(head)
        rest = tail
    upstream, sep, revision = rest.rpartition("-")
    if not sep:
        upstream, revision = rest, "0"
    return epoch, upstream, revision


def compare_versions(a: str, b: str) -> int:
    """返回负数、零或正数，表示 a 相对 b 的顺序。"""
    ea, ua, ra = _split(a)
    eb, ub, rb = _split(b)
    if ea != eb:
        return -1 if ea < eb else 1
    r = _compare_part(ua, ub)
    if r:
        return r
    return _compare_part(ra, rb)

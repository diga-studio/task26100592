# cvematch — 离线 CVE 版本匹配库（Debian 版本规则）

纯 Python、零依赖、完全离线。目录建成后只读，包名按字符串精确匹配。

## 接口

```python
from cvematch import compare_versions, build_catalog, scan, stats

compare_versions("1.0~rc1", "1.0")   # -> 负数 / 零 / 正数

catalog = build_catalog([
    # (包名, CVE, 下界或None, 下界是否包含, 上界或None, 上界是否包含)
    ("openssl", "CVE-2024-0001", "1.0", True, "2.0", False),
    ("openssl", "CVE-2024-0001", "3.0", True, None, False),   # 同一 CVE 可有多个区间
])

for record_id, cves in scan(catalog, observations):
    ...  # observations 是 (记录标识, 包名, 版本) 的一次性迭代器
         # 按输入顺序逐条产出 (记录标识, CVE集合)；无命中产出空集合
```

## 版本顺序

版本为 `[epoch:]upstream[-revision]`：epoch 缺省为 0，revision 取最后一个
连字符后的部分、缺省视为 `"0"`。依次比较 epoch、upstream、revision。
upstream/revision 按非数字段、数字段交替比较：非数字段逐字符比较
（`~` < 段结束 < ASCII 字母 < 其他字符，同类按 ASCII）；数字段忽略前导零
按整数值比较（空段为零，支持超 64 位整数）。不使用字符串排序、浮点数或
SemVer。

## 查询成本

建库（R 个目录区间）：

- 按包分组；每个包内先把**同一 CVE 的区间合并**为互不相交的并集
  （O(R·logR)），因此同一 CVE 的大量重叠区间在建库后只剩常数个区间，
  查询成本与这些重复区间的数量无关。
- 合并后的区间按下界排序，建静态区间树（排序数组 + 每个子树的最大上界），
  存储 O(R)。

单条查询（该包合并后 N 个区间，命中 K 个不同 CVE）：

- 沿区间树下降，子树最大上界 < 查询版本或最小下界 > 查询版本时整棵剪枝，
  否则只在叶子做完整开闭边界检查。成本 O(logN + K)。
- 同一 CVE 合并后的区间互不相交，任一版本至多落在其中一个里，因此叶子
  检查次数 = K，不会对同一 CVE 的重复区间做正比于区间数的工作。
- 不命中该包名时 O(1) 返回空集合。

`cvematch.stats` 记录版本比较次数与叶子区间检查次数，规模测试据此验证
成本未退化（50000 区间 / 100000 查询：平均约 57 次比较、0.5 次检查每条，
而逐条全扫需要 50000 次）。

## 流式与内存边界

- `scan` 是生成器：每条上报到达即处理即产出，不提前耗尽、不排序、不保存
  上报迭代器，也不积累任何历史查询缓存。
- 除只读目录（O(R)）外，内存只随当前记录及其结果集合（O(K)）增长。

## 运行测试

```sh
python3 -m unittest discover -s tests -v
```

- `tests/test_version.py`：epoch 优先级、超 64 位整数、波浪号、前导零、
  缺省 revision。
- `tests/test_catalog.py`：开闭边界交叉、语义相等边界一侧开放、空区间、
  同 CVE 去重、流式逐条消费。
- `tests/test_randomized.py`：固定种子小目录与直接全扫参考实现逐条对照
  （含无界区间、同 CVE 重叠区间、跨包同名 CVE）。
- `tests/test_scale.py`：50000 稀疏区间 × 100000 乱序互异查询；50000 个
  同 CVE 重叠区间覆盖同一版本。断言比较/检查计数而非耗时。

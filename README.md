# task26100592
# cvematch:离线 CVE 版本匹配库(Debian 版本规则)

纯标准库 Python 实现,无外部依赖,不启动任何服务。包名按字符串精确
匹配(调用方已完成身份归一化),目录构建后只读。

## 接口

```python
from cvematch import compare_versions, build_catalog, scan

compare_versions("1.0~rc1", "1.0")        # -> 负数

catalog = build_catalog([
    {"package": "openssl", "cve": "CVE-2024-0001",
     "lower": "1.0", "lower_inclusive": True,
     "upper": "2.0", "upper_inclusive": False},
    # lower/upper 缺省或为 None 表示该方向无界;*_inclusive 缺省为 True
])

observations = iter([("rec-1", "openssl", "1.5"), ...])  # 一次性迭代器
for record_id, cves in scan(catalog, observations):
    ...  # cves 为 frozenset,无命中时是空集合;每条输入都有一条输出
```

上报项也可以是 dict:`{"id": ..., "package": ..., "version": ...}`。

## 版本比较(cvematch/version.py)

- 拆分为 epoch、upstream、revision:epoch 取首个冒号前(缺省 0),
  revision 取最后一个连字符后(缺省视为 `"0"`);依次比较三者。
- upstream/revision 按非数字段、数字段交替比较。非数字字符顺序:
  `~` < 段结束 < ASCII 字母 < 其他字符,同类按 ASCII。数字段忽略
  前导零后按数值比较(先比去零后的长度再比字典序),空数字段视为 0。
- 数字段按十进制字符串比较,不转整数,天然支持超 64 位整数;
  不使用浮点、字符串整体排序或 SemVer 规则。

## 目录结构与查询成本(cvematch/catalog.py)

构建(每包独立,O(R log R) 次版本比较、O(R) 额外存储):

1. 丢弃空区间(下界大于上界,或界相等但一侧开放)。
2. 同一 CVE 的区间在版本空间排序后合并重叠/相接区间,得到互不相交
   的区间集——同一 CVE 的大量重复区间在此被压缩,查询成本与其无关。
3. 收集合并后所有端点版本,去重排序为 `values`。版本轴被压缩为整数
   "单元格":端点值与相邻端点间的空隙各占一格。区间是否包含某版本
   只取决于该版本落在哪一格,因此开闭边界语义可无损映射为闭整数区间。
4. 对每个 CVE 的整数区间再合并一次,然后建中心区间树(闭整数区间
   保证每层都有区间覆盖中心,树深 O(log R))。

单条查询 O(log R + K),K 为命中的不同 CVE 数:

- 在 `values` 上二分定位查询版本的单元格:O(log R) 次版本比较。
- 中心区间树点刺:每层只扫描按界排序的命中前缀,检查的区间数
  O(log R + K')。由于每个 CVE 的区间互不相交,一个点最多落在同一
  CVE 的一个区间内,故 K' <= K,不会遍历该包全部区间,也不会随
  重复区间数量增长。

`catalog.stats` 累计查询阶段的 `version_comparisons` 与
`interval_checks`,`catalog.reset_stats()` 清零,供规模测试核对。

## 流式内存边界

`scan` 是生成器:逐条消费上报迭代器、逐条产出结果,不排序、不缓存、
不保存历史。除目录本身(构建后只读,O(R))外,内存只随当前记录及其
命中集合增长,与上报总量无关。

## 测试

```
python3 -m unittest discover -s tests -v
```

- `tests/test_version.py`:epoch 优先级、超 64 位整数、波浪号、
  前导零、缺省 revision、非数字字符顺序、语义相等版本。
- `tests/test_catalog.py`:开闭边界交叉、语义相等界一侧开放不误报、
  空区间、无界区间、同 CVE 多区间去重、不同包同名 CVE、流式惰性;
  固定种子随机目录与直接全扫的参考实现逐条对照。
- `tests/test_scale.py`:50000 稀疏区间 + 100000 条乱序互异查询
  (实测平均约 17 次版本比较/查询,对照逐条全扫的 50000 次);
  50000 个同属一个 CVE 的区间覆盖同一查询版本(合并后每条查询
  仅约 2 次版本比较)。均断言比较/检查次数而非只看耗时。

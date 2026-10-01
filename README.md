# signature-detection-engine-go

本地文件签名检测引擎。规则与待扫描文件全部来自本地文件系统，**不依赖任何外部服务**；
扫描结果可解释（命中规则、字节偏移、各子模式偏移）、可复现（规则集版本 + 文件内容哈希 +
稳定排序）。

## 目录结构

```
cmd/sigscan/          CLI：compile / scan
internal/rules/       规则文件解析、编译、按文件隔离的拒绝原因、版本化原子存储
internal/matcher/     与分块边界无关的流式匹配器
internal/engine/      扫描状态分类、并发批扫、结果缓存与去重
rules/examples.json   规则示例
```

## 规则格式

规则目录下每个 `*.json` 文件是一个独立的规则文档，结构如下：

```json
{
  "rules": [
    {
      "id": "combo-marker",
      "description": "可选说明",
      "match": "all",
      "terms": [
        { "pattern": "deadbeef",        "offset_start": 0, "offset_end": 256 },
        { "pattern": "baadf00d[4]cafe", "offset_start": 0, "offset_end": -1 }
      ]
    }
  ]
}
```

字段语义：

- `id`：规则全局唯一标识（同一文件内、跨文件重复都会被拒绝）。
- `match`：
  - `"all"`（默认）：所有 `terms` 都命中，规则才命中；
  - `"any"`：任一 `term` 命中即可，锚点取**所有**已命中 term 最早偏移的最小值。
- `terms[].pattern`：十六进制字节串，空白会被忽略：
  - `4d 5a` / `4d5a`：具体字节；
  - `??`：单个通配字节；
  - `[n]`：连续 `n`（n ≥ 1）个通配字节，如 `baadf00d[4]cafe`；
  - 非法字符、奇数个 hex 位、`?` 不成对、`[n]` 不闭合或 n=0 都是编译错误。
- `offset_start` / `offset_end`：模式**起始字节**所在的绝对偏移窗口，闭区间；
  `offset_end = -1` 表示无上界；要求 `offset_start >= 0` 且
  `offset_end == -1 || offset_end >= offset_start`。

### 匹配语义（可解释、可复现）

- 每个 term 只记录其**最早**一次匹配偏移；窗口按绝对偏移过滤。
- 每条规则去重后只产生**一个**命中，锚点偏移：
  - `all`：全部 term 命中偏移的最小值；
  - `any`：所有已命中 term 偏移的最小值。
- 命中同时输出每个 term 的 `term_index` 与偏移，便于人工复核。
- 命中列表按 `(offset, rule_id)` 升序输出，与文件遍历顺序、分块大小、并发无关。

### 单文件错误隔离与可区分的拒绝原因

一个规则文件出错只拒绝该文件，其余文件照常编译。拒绝原因（`RejectReason`）包括：

| Reason | 含义 |
| --- | --- |
| `read_error` | 文件/目录不可读 |
| `invalid_json` | JSON 语法错误或存在尾随数据 |
| `empty_rule_set` | 文档中没有任何规则 |
| `invalid_id` | 规则 id 为空或含空白 |
| `invalid_pattern` | pattern 语法非法 |
| `invalid_offset` | 偏移窗口非法 |
| `invalid_match_mode` | `match` 不是 all/any |
| `duplicate_rule_id` | 文件内或跨文件 id 重复 |

### 规则版本与热更新

- 规则集版本是对**所有被接受文件**（文件名 + 规范化 JSON 内容）取 SHA-256 后截取的
  16 位 hex；规则的新增、修改、删除都会改变版本（空规则集为 `0000000000000000`）。
- `rules.Store` 内部用原子指针持有不可变的 `*Compiled`。`Reload` 先构建完整新规则集，
  再一次性替换：
  - 已开始的扫描持有旧快照直到结束，不受重载影响；
  - 重载后的扫描只能看到新规则集，**不存在旧规则残留或新规则漏用**；
  - 删除规则即从重建结果中消失。

## 流式扫描与分块边界无关性

- 匹配器每次喂入一个分块，并保留「最长 pattern − 1」字节的尾部重叠区，因此跨分块的
  pattern 会在下一 chunk 被完整评估且只评估一次。
- 对同一文件，整体读取与任意分块大小（含 1 字节、大于文件长度）产出完全一致的命中集合。
  测试 `TestChunkBoundaryIndependence` 穷举了数据长度内的每一个分块大小；
  `TestChunkSizesProduceIdenticalVerdicts` 从引擎层再次验证。

## 文件扫描状态（互斥、可区分）

| Status | 含义 |
| --- | --- |
| `clean` | 完整读取且无命中 |
| `detected` | 完整读取且有命中 |
| `unreadable` | 打开/stat 失败、目录、非常规文件 |
| `truncated` | 实际读到字节数 < 扫描开始时声明的大小（文件被截断/内容被切断） |
| `modified` | 扫描中大小增长、结束时 size/mtime 变化，或二次哈希与流式哈希不一致（等长原地改写） |
| `scan_error` | 读取过程中的其它 I/O 错误 |

判定流程：流式读取同时计算 SHA-256；读取中发现读入超过初始大小 → `modified`；
读尽但字节数不足 → `truncated`；读完后再次 `stat` 校验 size/mtime，并重新整文件哈希比对，
任一不一致 → `modified`。批处理中一个文件的失败只影响其自身结果，不会中断其它文件。

## 缓存与并发约定

- 缓存键同时绑定**规则集版本**与**文件标识**（绝对路径），缓存条目记录文件指纹
  （size + mtime）；命中前必须校验指纹，且结果中带流式内容 SHA-256。
  - 规则增删改（版本变化）后，旧版本结果绝不会返回；
  - 文件内容变化（size/mtime 变化）后重新扫描；
  - `clean` / `detected` 才入缓存；`unreadable` / `truncated` / `modified` /
    `scan_error` 不缓存，瞬时故障下次自动重试。
- 同一 `(规则版本, 文件)` 的并发扫描会合并（singleflight），只执行一次实际扫描；
  等待方仅在指纹一致时复用结果，否则自行重扫。
- `cache_hit` 字段只用于观测，缓存命中与否不改变 `status`、`hits`、`content_sha256`。
- 并发扫描与规则热更新可同时进行：规则快照不可变、缓存按版本分桶、共享状态由互斥锁保护
  （测试在 `-race` 下运行）。

## CLI

```bash
# 校验/编译规则，打印规则集版本与每个被拒绝文件及原因
go run ./cmd/sigscan compile --rules rules

# 扫描（任意分块大小；结果稳定一致）
go run ./cmd/sigscan scan --rules rules --chunk 4096 --workers 4 file1 file2 ...

# 每个文件一行 JSON（含规则版本、内容哈希、命中明细）
go run ./cmd/sigscan scan --rules rules --json file1 file2 ...
```

扫描正常结束（clean/detected）退出码为 0；存在 `unreadable/truncated/modified/scan_error`
时退出码为 1，便于脚本区分。

## 验证方法

```bash
go vet ./...
go test ./...                       # 功能与确定性测试
CGO_ENABLED=1 go test -race ./...  # 并发/热更新数据竞争检测
```

测试覆盖（单测日志用 `t.Logf` 打印规则集版本、file_id 与命中明细）：

- `internal/rules`：畸形 pattern / JSON / offset / match 模式、重复 id、按文件隔离的拒绝原因；
  规则增删改后的版本变化；原子热更新后旧快照不可变。
- `internal/matcher`：穷举分块大小的边界无关性、通配符（`??` 与 `[n]`）、偏移窗口、
  all/any 聚合、输出顺序稳定。
- `internal/engine`：不同分块大小结果一致；不可读文件与目录的批处理隔离；
  扫描中途截断（`truncated`）与等长改写（`modified`）的区分；
  规则热更新后缓存失效、无旧规则残留；文件内容变化后缓存失效；
  并发扫描叠加并发重载的竞争安全。

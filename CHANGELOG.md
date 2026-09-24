# 更新日志

本项目的所有重要变更都记录在此文件。

格式遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [Unreleased]

## [0.1.0] - 2026-09-24

首个版本。核心主张：**技术能力不稀缺，可验证的授权与留痕才是稀缺的**。

### 新增

- **授权凭证（`src/lib/manifest.mjs`）**
  - 凭证四要素校验：谁授权（授权书编号 + 签署人 + 文档哈希）、授权到哪天（时间窗）、
    授权哪些目标（inScope / outOfScope）、允许与禁止做什么（动作清单）
  - 硬性禁止清单 `NEVER_PERMITTED_ACTIONS`：dos / ddos / destructive / wipe /
    data-exfiltration / exfiltration / ransomware —— 硬编码，任何凭证都不能放行
  - 授权书原件 SHA-256 登记与比对，防止"换一份范围更大的授权书"
  - 范围规则支持精确域名、子域、通配 `*.example.com`、IP、CIDR

- **执行前校验门（`src/lib/gate.mjs`）**
  - 七项判定并返回**完整轨迹**，而不是只有 true/false —— 审计要的是"依据什么判定"
  - 排除规则优先于纳入规则（out-of-scope wins）
  - 时间窗边界包含起止时刻

- **防篡改审计日志（`src/lib/ledger.mjs` + `src/lib/crypto.mjs`）**
  - JSONL 逐行追加，哈希链覆盖每条记录的全部字段
  - 确定性 JSON 序列化（键排序），保证同一内容总是算出同一哈希
  - 可选 HMAC-SHA256：把「篡改可发现」升级为「无密钥不可伪造」
  - 校验失败时精确定位到第几条，并拒绝给出可锚定的链头哈希
  - `recordedAt` 与 `backfilled` 标记，显式区分"事件何时发生"与"何时被记进日志"

- **合规报告（`src/lib/report.mjs`）**
  - Markdown 报告（七章）与机器可读 JSON 报告
  - 越界尝试单独成表 —— 被拒记录是测试纪律的证据
  - 边界声明章节写明三项能力限制，不做过度承诺

- **CLI（`src/index.mjs`）**
  - `hash-doc` / `init` / `check` / `log` / `verify` / `report` / `anchor` / `status`
  - `check` 与 `log` 分离：试判不留痕，留痕必判定
  - 退出码语义化：0 正常 / 1 用法错误 / 2 校验门拒绝 / 3 完整性失败
  - HMAC 密钥只从环境变量读取，不接受命令行参数

- **工程**
  - 零运行时依赖（仅 Node 内置模块），CI 强制校验
  - 133 个测试，含篡改检测、HMAC、表格注入、CLI 端到端
  - CI 五个作业：单元测试与零依赖、端到端闭环、篡改检测负向验证、
    凭证守卫、输入加固
  - 仓库内 git hooks（Conventional Commits）

### 已知限制

- 只处理 IPv4；IPv6 范围规则尚未支持
- `loadLedger` 一次性读入整个日志，超大日志（百万级条目）需改为流式
- 凭证自身不设签名（刻意的取舍，见 `SECURITY.md` §1.4）
- 时间来源是本地系统时钟；不校验可信时间源

[Unreleased]: https://github.com/Frank2673/engagement-ledger/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Frank2673/engagement-ledger/releases/tag/v0.1.0

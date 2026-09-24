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
  - 范围规则支持精确域名、子域、通配 `*.example.com`、IPv4/IPv6、IPv4/IPv6 CIDR
  - IPv6 支持 `::` 压缩、末尾内嵌 IPv4（`::ffff:192.0.2.1`）与 `[方括号]` 目标写法
  - 写错的 IP 直接拒绝，不会掉进域名分支被当成域名放行
    （`999.1.1.1` / `1.2.3.4.5` / `2001:db8:::1`）—— 静默接受错误范围比报错危险得多
  - 跨族一律不匹配：IPv4 目标不会命中 IPv6 网段（反向亦然），
    配置错误不能变成"看起来通过"

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
  - **委托归属校验**：`checkEngagementConsistency()` 检出日志里混入的其它委托记录。
    链完整只说明"内容没被改"，不说明"这些内容都属于这次委托" ——
    共用日志路径或合并日志会让报告的统计与流水把两件事写成一件
  - 预防 + 检测两层：`log` 拒绝向属于另一次委托的日志追加（预防），
    `verify` / `status` / `report` 检出已混入的记录（检测）

- **合规报告（`src/lib/report.mjs`）**
  - Markdown 报告（七章）与机器可读 JSON 报告
  - §3.2 动作流水：按写入顺序列出全部已执行动作与人工备注，
    带执行人、结果与证据指针 —— 授权范围说明「允许做什么」，本表说明「实际做了什么」
  - 缺证据指针的动作会被告警（能否被独立复核取决于有没有证据）
  - 越界尝试单独成表 —— 被拒记录是测试纪律的证据
  - 边界声明章节写明三项能力限制，不做过度承诺

- **CLI（`src/index.mjs`）**
  - `hash-doc` / `init` / `check` / `log` / `verify` / `report` / `anchor` / `status`
  - `check` 与 `log` 分离：试判不留痕，留痕必判定
  - 退出码语义化：0 正常 / 1 用法错误 / 2 校验门拒绝 / 3 完整性失败
  - HMAC 密钥只从环境变量读取，不接受命令行参数

- **工程**
  - 零运行时依赖（仅 Node 内置模块），CI 强制校验
  - 188 个单元测试，含篡改检测、HMAC、表格注入、IPv6、委托归属、CLI 端到端
  - `scripts/verify.mjs` 运营级校验 32 项（端到端闭环 / 篡改检测 / 凭证守卫 /
    委托归属 / 安全红线），本地与 CI 共用同一份代码
  - CI 薄到只剩两条命令：`node --test tests/` 与 `node scripts/verify.mjs`
  - 仓库内 git hooks（Conventional Commits）

### 首次提交的 CI 失败与修正

第一次推送后 CI 两个作业失败。根因**全在 workflow 里的 bash 片段**，与被测代码无关：

- `grep ... || { echo ...; exit 1; fi` —— `{` 与 `fi` 混用，报 syntax error
- 篡改检测作业用了 `a.example.com` / `b.example.com` / `c.example.com` 造日志，
  而这三个域名不在示例凭证的授权范围内 → `log` 正确返回退出码 2 →
  配合 `set -e` 直接中断循环

这两个错误的共同点是：**bash 片段在本地跑不了，只能推上去等 CI 反馈**。
因此把校验逻辑整体搬进 `scripts/verify.mjs`（Node，进程内驱动 CLI）：
本地与 CI 跑同一份代码，一条命令即可在推送前跑完全部 28 项校验。
CI 现在只是一层薄封装。

### 已知限制

- `loadLedger` 一次性读入整个日志，超大日志（百万级条目）需改为流式
- IPv6 带 zone id 的地址（`fe80::1%eth0`）不参与范围判定，一律拒绝
  —— 链路本地地址的作用域取决于接口，写进授权范围没有意义
- 前导零的 IPv4 写法（`010.0.0.1`）被拒绝：不同解析器会按八进制或十进制解释，
  歧义地址不进范围判定
- 凭证自身不设签名（刻意的取舍，见 `SECURITY.md` §1.4）
- 时间来源是本地系统时钟；不校验可信时间源

[Unreleased]: https://github.com/Frank2673/engagement-ledger/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Frank2673/engagement-ledger/releases/tag/v0.1.0

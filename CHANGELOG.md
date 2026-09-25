# 更新日志

本项目的所有重要变更都记录在此文件。

格式遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [Unreleased]

## [0.1.1] - 2026-09-25

文档与元数据一致性修复，不改任何运行时行为。

### 修复

- `LICENSE` 署名 `Frank` → `Frank2673`，与其余仓库对齐
- `SECURITY.md` 引用的 CI 作业 `tamper-detection` **实际不存在**（workflow 只有 `test` / `verify`）
  → 改指向 `scripts/verify.mjs` 的 B 组
- `pull_request_template.md` 从仓库根移到 `.github/`：GitHub 只识别
  `.github/pull_request_template.md` 或根目录全大写的 `PULL_REQUEST_TEMPLATE.md`，
  原位置等于没有 PR 模板（用 `git mv` 保留历史）

### 文档

- README 补 license 徽章，顺序对齐另两仓（CI → License → 零依赖 → 测试 → Node）
- README 许可段补 `© 2026 Frank2673`

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
  - §4.1 窗口外的已执行动作：找出落在授权窗口之外的 action 并标注方向
    （窗口之前 / 窗口之后）。校验门本应拦住它们，所以出现即意味着
    「窗口事后被改动过」或「记录绕过了校验门」—— 两种都需要人工说明
  - 边界声明章节写明三项能力限制，不做过度承诺

- **CLI（`src/index.mjs`）**
  - `hash-doc` / `init` / `check` / `log` / `verify` / `report` / `anchor` / `status`
  - `check` 与 `log` 分离：试判不留痕，留痕必判定
  - 退出码语义化：0 正常 / 1 用法错误 / 2 校验门拒绝 / 3 完整性失败
  - HMAC 密钥只从环境变量读取，不接受命令行参数
  - **证据强制策略**：`log --require-evidence` 或凭证里的 `requireEvidence: true`。
    缺证据时**拒绝写入**（退出码 1，不留半条记录），报错说明策略来源。
    只对"放行并执行"的动作生效 —— 被拒的动作什么都没做，要求证据只会逼人造假凭据。
    报告第 1 章写出当前策略，第 3.2 节的缺证据提示在策略开启时升级措辞

- **授权书登记（`scripts/intake-authorization.mjs` + `docs/authorization-intake.md`）**
  - 一条命令完成：归档副本 + SHA-256 + 生成可直接粘进凭证的两行，
    消掉"手抄 64 位十六进制抄错"这个失败模式
  - 拒绝覆盖已存在的归档副本（覆盖会作废已登记进凭证的哈希）
  - 按载体给出针对性提醒：扫描件每次扫描哈希都不同、`.msg` 建议同时留 `.eml`、
    `.docx` 不适合直接登记（先转 PDF）
  - `--dry-run` 只看不写、`--json` 供程序化处理
  - 操作手册覆盖三种来源（电子签章 PDF / 纸质扫描件 / 邮件授权）、
    客户侧复核命令（`Get-FileHash` / `shasum -a 256`）、授权书变更流程、十类常见错误

- **外部锚定闭环（`verify-anchor` + `anchor --append`）**
  - 在此之前只实现了"写锚定"，没有"验锚定" —— 而**没有校验端的锚定等于没锚定**
  - `anchor --append ANCHORS.txt`：直接写入锚定文件（幂等：同一状态重复锚定会跳过），
    替掉 README 里 `grep | sed >>` 那种手抄管道
  - `verify-anchor`：拿锚定记录逐条比对当前日志，**唯一能发现「整链被重写」的检查**
    - 历史锚定点对不上 → `rewritten`：日志自洽但与外部记录冲突，即整链被重算
    - 锚定条数 > 当前条数 → `rollback`：日志被截断/回滚
    - 前缀自身断裂 → `broken`：不误判为重写
    - 全部匹配且最新锚定 = 当前链头 → 自锚定以来未被改动
  - 链断裂时 `anchor` 拒绝输出锚定行 —— 锚定一份坏链只会把坏数据钉进外部记录
  - 锚定文件解析宽松（忽略注释与说明文字）但对"带标签格式不对"的行报 malformed，
    不静默忽略
  - `checkAnchors()` / `parseAnchors()` 为纯函数，可脱离文件系统测试

- **客户侧复核闭环（`scripts/verify-report.mjs` + `scripts/make-test-pdf.mjs`）**
  - 在此之前，手册只让客户"自己跑 Get-FileHash 再肉眼比对 64 位十六进制" ——
    而让人肉眼比对哈希，成功率约等于零：复核要么变成走过场，要么抄错一位后误判
  - `verify-report.mjs`：从报告里抽出登记的授权书 SHA-256，对客户手上的原件算一遍并比对
    - 一致 → 退出码 0，并附上"这只证明文件相同，不证明授权书本身有效"的边界说明
    - 不一致 → 退出码 3，给出四步排查顺序（中途版本/重新扫描/拿错文件/索要归档副本）
    - 报告没登记哈希 → 专门状态，不误判为一致，并把手上这份的哈希算出来给用户看
    - Markdown 与 `--json` 报告都能解析；解析结果不受报告里其它 64 位哈希（如链头）干扰
  - `make-test-pdf.mjs`：用四十行代码生成**结构完整的真 PDF**作测试夹具
    （%PDF 头 + 对象表 + xref + startxref 指向正确），而不是往 fixtures/ 丢二进制 ——
    二进制夹具看不见、改不动、没法评审
  - 手册第 5 步改为"给他一条命令"，并把手工 Get-FileHash 降级为折叠备选方案
  - 常见错误表新增两条：让客户肉眼比对哈希、用 diff 代替哈希比对

- **工程**
  - 零运行时依赖（仅 Node 内置模块），CI 强制校验
  - 255 个单元测试，含篡改检测、HMAC、表格注入、IPv6、委托归属、窗口合规、
    证据策略、授权书归档、**整链重写攻击实测**、客户侧复核、真实 PDF 夹具、CLI 端到端
  - `scripts/verify.mjs` 运营级校验 40 项（端到端闭环 / 篡改检测与归属 / 凭证守卫 /
    授权书登记闭环 / **整链重写与回滚的锚定实测** / 真实 PDF 客户复核闭环 / 安全红线），
    本地与 CI 共用同一份代码
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
本地与 CI 跑同一份代码，一条命令即可在推送前跑完全部校验（项数随迭代增长，见「工程」一节）。
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

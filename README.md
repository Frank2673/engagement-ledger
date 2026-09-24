# engagement-ledger

> 让「我有授权」这句话，变成一份别人可以核验的证据。

授权凭证校验 + 防篡改审计日志 + 合规报告。零依赖，只用 Node 内置模块。

```
把授权书变成可执行的边界  →  动手前逐项校验  →  越界即拦并留痕  →  交付可核验的合规报告
```

[![CI](https://github.com/Frank2673/engagement-ledger/actions/workflows/ci.yml/badge.svg)](https://github.com/Frank2673/engagement-ledger/actions/workflows/ci.yml)
![零依赖](https://img.shields.io/badge/运行时依赖-0-brightgreen)
![测试](https://img.shields.io/badge/测试-145%20passed-brightgreen)
![Node](https://img.shields.io/badge/node-%3E%3D20-blue)

---

## 它解决什么问题

渗透测试里最危险的一句话是「我有授权」。因为这句话**无法被验证**。它带来三个没人能回答的问题：

| 问题 | 现状 | 本工具的做法 |
| --- | --- | --- |
| 客户怎么知道你只测了授权的资产？ | 靠口头承诺 | 每个动作**执行前**逐项校验，判定轨迹入库 |
| 事后争议时怎么证明某动作当时被允许？ | 靠回忆 | 每份报告附完整校验依据与授权书哈希 |
| 授权书被换过一份范围更大的，谁能发现？ | 没人能 | 授权书原件 SHA-256 登记，`init` 时比对 |

**技术能力不稀缺，可验证的授权与留痕才稀缺。** 这个工具不提升你的攻击能力，
它提升的是你交付物的可信度 —— 而后者才是客户真正付钱买的东西。

---

## 60 秒上手

```bash
git clone https://github.com/Frank2673/engagement-ledger
cd engagement-ledger

# 1. 给授权书原件算个指纹（把结果填进凭证）
node src/index.mjs hash-doc 授权书.pdf

# 2. 用凭证初始化审计日志
node src/index.mjs init --manifest fixtures/demo-engagement.json --ledger demo/ledger.jsonl

# 3. 动手前问一句：这个动作现在能不能做？
node src/index.mjs check --manifest fixtures/demo-engagement.json \
  --target api.example.com --action recon

# 4. 留痕（允许的记为 action，越界的记为 denied —— 两者都写）
node src/index.mjs log --manifest fixtures/demo-engagement.json --ledger demo/ledger.jsonl \
  --target api.example.com --action recon --result "12 endpoints"

# 5. 出报告
node src/index.mjs report --manifest fixtures/demo-engagement.json \
  --ledger demo/ledger.jsonl --stdout
```

只需要 Node ≥ 20，不需要 `npm install`（本项目没有依赖）。

### 实际输出

范围内的动作 —— **放行**：

```console
$ node src/index.mjs log --manifest fixtures/demo-engagement.json --ledger demo/ledger.jsonl \
    --target api.example.com --action recon --result "12 endpoints"

✅ 允许执行

  动作：recon
  目标：api.example.com
  时间：2026-09-15T10:00:00.000Z

校验轨迹：
  ✓ input-complete
  ✓ action-not-hard-forbidden      动作「recon」不在硬性禁止清单内
  ✓ action-not-prohibited          动作未被凭证列为禁止
  ✓ action-permitted               动作「recon」在允许清单内
  ✓ within-time-window             动作时间在授权窗口内
  ✓ target-in-scope                目标命中范围规则「api.example.com」
  ✓ target-not-excluded            目标未被任何排除规则命中

已写入日志：seq=1 hash=4053ed51930a9d5d…
```

越界目标 —— **拦下，并把这次尝试本身留成证据**：

```console
$ node src/index.mjs log --manifest fixtures/demo-engagement.json --ledger demo/ledger.jsonl \
    --target pay.example.com --action scan

⛔ 拒绝执行
  ✗ target-in-scope                目标「pay.example.com」不在 inScope 范围内
  ✗ target-not-excluded            目标「pay.example.com」命中排除规则「pay.example.com」
                                   —— 排除优先级高于纳入

已写入日志：seq=1 hash=0d1446c37aef0262…

⛔ 该动作未被授权，**未执行**，本次尝试已作为拒绝记录留痕。
   被拒记录就是测试纪律的证据 —— 事后无法自证"我没越界"，但日志可以。
```

硬性禁止的动作 —— **任何授权都放行不了**：

```console
$ node src/index.mjs log --manifest fixtures/demo-engagement.json --ledger demo/ledger.jsonl \
    --target api.example.com --action ransomware

  ✗ action-not-hard-forbidden      动作「ransomware」属于硬性禁止项 —— 任何授权都不能放行
```

退出码：`0` 放行 / `1` 用法或运行错误 / `2` 校验门拒绝 / `3` 完整性校验失败。
可以直接嵌进脚本与 CI：`node src/index.mjs check … || echo "越界，已拦下"`。

---

## 三条设计主线

### 一、硬性禁止不随配置放开

`src/lib/manifest.mjs` 里这份清单是**硬编码常量**：

```
dos  ddos  destructive  wipe  data-exfiltration  exfiltration  ransomware
```

凭证把它们写进 `permittedActions` 会在校验阶段直接报错，而不是被"允许"。
理由：一旦这是配置项，判断权就从一个工程常量变成了一个可改的 JSON 文件 ——
把「不得造成服务不可用」这条底线交给一个可改的文件，等于没有底线。

CI 里的 `scripts/check-zero-deps.mjs` 会校验这份清单没有被削弱。

### 二、校验门返回轨迹，不只返回布尔值

审计要回答的不是「当时允许了吗」，而是「当时**依据什么**允许的」。
所以 `evaluateAction()` 返回全部七项判定的通过情况，这些轨迹随记录一起入库：

```
input-complete → action-not-hard-forbidden → action-not-prohibited → action-permitted
→ within-time-window → target-in-scope → target-not-excluded
```

半年后有人问「为什么这个目标当时测了」，答案在日志里，不在你的记忆里。

### 三、能力边界写在报告正文里

一个安全工具最不负责的行为，是让人高估它。所以报告的最后一章固定是边界声明：

- **篡改可发现 ≠ 不可伪造**
- **写入顺序 ≠ 事件顺序**
- **本日志完整 ≠ 全部操作都在日志里**

## 哈希链能做什么、不能做什么

```
记录 N 的 hash = H(记录 N 的全部字段 + 记录 N-1 的 hash)
```

改动第 3 条 → 第 3 条的哈希立刻对不上，校验会告诉你「断在第 3 条」。
但**知道算法的人可以把整条链重算一遍**。所以本工具提供三级强度：

| 强度 | 手段 | 能挡住 | 挡不住 |
| --- | --- | --- | --- |
| 基础 | 纯哈希链 | 改内容、删中间条、换顺序 | 整链重算、截断末尾 |
| 加强 | `HMAC` 密钥 | 上述全部（攻击者无密钥） | 有密钥的人、整份删除 |
| 完整 | **外部锚定** | 上述全部 + 整链替换 | 在工具之外动手（见 `SECURITY.md` §1.3） |

### 外部锚定怎么做（关键一步，别跳过）

哈希链有一个固有缺口：攻击者可以删掉日志、重新生成一份**内容完全自洽**的新链。
解法是把链头哈希钉到日志文件**之外**的地方：

```bash
# 1. 拿到锚定行
node src/index.mjs anchor --ledger demo/ledger.jsonl
#   engagement-ledger 4 fd657521184842bf9aba44806c90488bb1e4738a47c5c08fd149ea01c0634401

# 2. 追加到锚定文件并提交（这个文件只含条数与哈希，不含委托信息，可以进仓库）
node src/index.mjs anchor --ledger demo/ledger.jsonl \
  | grep '^  engagement-ledger' | sed 's/^  //' >> ANCHORS.txt
git add ANCHORS.txt && git commit -m "chore: 锚定审计日志"
```

此后攻击者要伪造日志，就得同时面对 git 的历史 —— 这才真正锁住了链条。

> ⚠️ 只把锚定行打印在同一个终端里，等于没锚定。攻击者重算整链时会顺带重算它。

### 启用 HMAC（可选，客户交付建议开）

```bash
export ENGAGEMENT_LEDGER_KEY='一段足够长的随机密钥'   # 密钥只走环境变量
node src/index.mjs init --manifest engagement.json --ledger ledger.jsonl
node src/index.mjs verify --ledger ledger.jsonl --hmac-key-env ENGAGEMENT_LEDGER_KEY
```

密钥不接受命令行参数 —— 命令行参数在 `ps` / 任务管理器里对同机其他用户可见。
这条约束由 CI 强制（`scripts/check-zero-deps.mjs`）。

---

## 凭证格式

```jsonc
{
  "engagement": {
    "id": "ENG-2026-001",
    "name": "某公司对外服务渗透测试",
    "tester": "Frank",

    "authorization": {
      "reference": "AUTH-2026-001",        // 授权书编号（必填）
      "signedBy": "张三",                   // 签署人（必填）
      "signedTitle": "信息安全负责人",       // 以什么身份签的
      "signedAt": "2026-09-01",
      "document": "授权书.pdf",              // 路径相对凭证文件所在目录
      "documentSha256": "8c0b71f9…"          // node src/index.mjs hash-doc 授权书.pdf
    },

    "window": { "from": "2026-09-01T09:00:00Z", "to": "2026-12-31T18:00:00Z" },

    "scope": {
      "inScope":    ["api.example.com", "*.staging.example.com", "192.0.2.0/28"],
      "outOfScope": ["pay.example.com", "*.example.org"]     // 排除优先
    },

    "permittedActions":  ["recon", "scan", "manual-test"],
    "prohibitedActions": ["dos", "destructive", "data-exfiltration",
                          "persistence", "social-engineering"],
    "emergencyContact": "security@example.com"
  }
}
```

**校验规则**（缺失即报错，不是警告）：`id` / `tester` / `authorization.reference` /
`authorization.signedBy` / `window` / `scope.inScope`（不能为空）。
**只告警不阻断**：缺授权书哈希、缺应急联系人、缺建议禁止项。

范围规则支持：精确域名（含子域）、通配 `*.example.com`、精确 IP、CIDR。
匹配时大小写不敏感、忽略尾部点。

---

## 命令参考

| 命令 | 作用 | 退出码 |
| --- | --- | --- |
| `hash-doc <文件>` | 计算文件 SHA-256，填进凭证 | 0 / 1 |
| `init` | 用凭证初始化日志，写入 genesis 记录并核验授权书 | 0 / 1 |
| `check` | 执行前试判（**不写日志**） | 0 / 2 |
| `log` | 校验 + 记录（拒绝也记录） | 0 / 2 / 1 |
| `verify` | 校验日志哈希链完整性 | 0 / 3 |
| `report` | 生成合规报告（Markdown / JSON） | 0 / 3 |
| `anchor` | 输出外部锚定行 | 0 / 3 |
| `status` | 一页纸概览（授权状态 + 日志摘要） | 0 / 2 / 3 |

通用选项：`--manifest <路径>`（默认 `engagement.json`）、
`--ledger <路径>`（默认 `ledger.jsonl`）、`--hmac-key-env <变量名>`（默认 `ENGAGEMENT_LEDGER_KEY`）。

`check` 与 `log` 是分开的：**试判不留痕，留痕必判定**。
不确定某个目标能不能测时用 `check`，它不会污染日志。

---

## 合规报告长什么样

`report` 输出的 Markdown 有七章：

1. **委托与授权** —— 编号、签署人、窗口、授权书 SHA-256（附复核方法）
2. **授权范围** —— 纳入、排除、允许动作、禁止动作、系统硬性禁止
3. **执行记录统计** —— 条数、允许/拒绝数、涉及目标、补录记录数
4. **越界尝试与被拒记录** —— 单独成表，**这是纪律的证据**
5. **日志完整性** —— 链校验结论 + 链头哈希
6. **外部锚定** —— 为什么要锚定、锚定行、如何操作
7. **边界声明** —— 三项能力限制，不做过度承诺

配合 `--json` 还能产出机器可读版本，供 CI 或客户的合规系统消费。

---

## 项目结构

```
src/
  index.mjs              CLI 入口（8 个子命令）
  lib/
    crypto.mjs           确定性 JSON 序列化 + 哈希 + HMAC
    manifest.mjs         授权凭证校验、范围规则、CIDR 匹配、硬性禁止清单
    gate.mjs             执行前校验门（7 项判定 + 完整轨迹）
    ledger.mjs           哈希链日志：追加、校验、锚定信息
    report.mjs           合规报告（Markdown + JSON）
tests/                   145 个测试，7 个文件
scripts/
  verify.mjs                  运营级校验：本地与 CI 跑同一份代码（28 项）
  check-zero-deps.mjs         零依赖 + 安全红线校验（CI 强制）
  check-report-tables.mjs     报告表格结构校验
  setup-hooks.mjs             启用仓库内 git hooks
fixtures/                示例凭证与示例授权书（虚构数据）
```

## 架构选择：为什么这样分层

**纯函数判定 + IO 分离**。`gate.mjs` 的 `evaluateAction()` 不读文件、不取时间（时间由调用方传入）、
不写日志 —— 它是一个纯函数。带来的好处：

- 可以直接用内存对象测试「某种范围规则会不会放行某个目标」，不用造文件
- 时间可以注入，所以「窗口边界」这类逻辑能被确定性地测试
- 判定逻辑与存储格式解耦，将来换存储不影响判定

`crypto.mjs` 里做**确定性 JSON 序列化**（递归键排序）而不是直接用 `JSON.stringify`：
否则字段顺序一变哈希就变，「篡改」会变成误报。这类误报会直接摧毁工具的可信度。

## 测试

```bash
npm test                                    # 单元测试：node --test tests/
node scripts/verify.mjs                     # 运营级校验：28 项，含负向验证
npm run check                               # 上面全部 + 零依赖红线
node tests/cli.test.mjs                     # 单跑某个文件
```

145 个单元测试，重点覆盖的不是"能存能读"，而是**篡改能不能被发现**：

- 改内容 / 改时间 / 删中间条 / 换顺序 / 改 prevHash —— 逐项验证能检出并定位
- **负向验证**：纯哈希链下"整链重算"确实能伪造成功（承认边界），
  而启用 HMAC 后同样的攻击会失败 —— 两个方向都有断言
- 截断末尾不报错，但 `anchorInfo` 会暴露条数与链头变化（说明为什么必须外部锚定）
- CLI 端到端：init 重复初始化被拒、check 不写日志、越界退出码 2、篡改退出码 3
- 输入加固：目标名含 `|` 时报告表格不被撑破，由 `check-report-tables.mjs` 校验

`scripts/verify.mjs` 是运营级校验，四组共 28 项：端到端闭环、篡改检测、
授权凭证守卫、安全红线。它的设计本身值得说一句 ——

### 为什么校验逻辑不写在 workflow 的 bash 里

本仓库第一次提交的 CI 挂了，两个作业失败，而**原因全在 YAML 里的 bash**：
一个 `{ ...; fi` 括号写成 `}` 与 `fi` 混用，一个用了不在授权范围内的主机名
（`log` 返回退出码 2，配合 `set -e` 直接中断循环）。与被测代码无关。

更根本的问题是：那些 bash 片段**在本地跑不了**（受限环境下 bash 起不来），
于是只能"推上去等 CI 告诉你"，一次反馈一轮往返。

改成 `node scripts/verify.mjs` 之后：

- 本地一条命令跑完全部校验，推之前就知道结果
- 本地与 CI 执行的是同一份代码，不存在"CI 上才有的问题"
- 没有 bash 引号/括号/`set -e` 这一类与被测逻辑无关的失败模式

CI 本身因此薄到只剩两条命令：`node --test tests/` 与 `node scripts/verify.mjs`。

### 守卫的守卫

`verify.mjs` 的 D 组专门验证"守卫本身有效"：
往一份**临时副本**里塞第三方依赖、削掉 `ransomware`、删掉整份禁止清单、
放开裸 `--hmac-key` —— 每一项都必须被 `check-zero-deps.mjs` 抓出来。
**一个永远通过的守卫等于没有守卫**，所以守卫也要被负向验证，
而负向验证必须在副本上做，不能靠临时改真实文件。

---

## 相关仓库

| 仓库 | 一句话 |
| --- | --- |
| [surface-watch](https://github.com/Frank2673/surface-watch) | 攻击面变化监控：基线与差分，只在有变化时告警 |
| [header-forge](https://github.com/Frank2673/header-forge) | 安全响应头即代码：一份策略生成五平台配置并自证 |
| [Frank2673.github.io](https://github.com/Frank2673/Frank2673.github.io) | 个人主页（[线上](https://frank2673.github.io/)） |
| [github-dev-workflow](https://github.com/Frank2673/github-dev-workflow) | 从零建仓到自动化的完整工作流模板 |

## 使用前请读

- [`ETHICS.md`](ETHICS.md) —— 使用边界、使用者责任、开测前必须确认的事
- [`SECURITY.md`](SECURITY.md) —— 本工具自身的威胁模型（它是被攻击对象）

一句话：**这个工具不能替你完成授权判断**。凭证里的范围写错了，它会忠实地按错误范围放行。
凭证必须来自真实的书面授权。

## 许可

[MIT](LICENSE)

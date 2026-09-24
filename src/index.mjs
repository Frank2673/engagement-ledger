#!/usr/bin/env node
/**
 * engagement-ledger CLI
 *
 * 授权凭证与审计日志 —— 让"我有授权"这句话变成可核验的证据链。
 *
 * 子命令：
 *   hash-doc <file>        计算授权文件的 SHA-256（用于凭证登记）
 *   init                   用凭证初始化日志（写入 genesis 记录）
 *   check                  执行前校验（只判定，不记录）
 *   log                    校验 + 记录（拒绝也记录 —— 拒绝本身是纪律证据）
 *   verify                 校验日志完整性
 *   report                 生成合规报告
 *   anchor                 输出外部锚定行
 *   status                 一页纸概览
 *
 * @module index
 */

import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { resolve, basename } from 'node:path';
import { loadManifest, verifyAuthorizationDocument, NEVER_PERMITTED_ACTIONS } from './lib/manifest.mjs';
import { evaluateAction } from './lib/gate.mjs';
import { loadLedger, appendEntry, verifyLedger, anchorInfo, makeEntry, checkEngagementConsistency } from './lib/ledger.mjs';
import { buildReport, buildJsonReport, summarizeLedger } from './lib/report.mjs';
import { fileSha256 } from './lib/crypto.mjs';

const DEFAULT_MANIFEST = 'engagement.json';
const DEFAULT_LEDGER = 'ledger.jsonl';

/* 退出码：0 正常 / 1 用法或运行错误 / 2 校验门拒绝 / 3 完整性失败 */
const EXIT = { OK: 0, ERROR: 1, DENIED: 2, INTEGRITY: 3 };

/** 事件时间与写入时间相差超过这个值，就视为补录并标记 */
const BACKFILL_THRESHOLD_MS = 5 * 60 * 1000;

const HELP = `engagement-ledger —— 授权凭证与防篡改审计日志

用法：
  engagement-ledger <命令> [选项]

命令：
  hash-doc <文件>            计算文件的 SHA-256（登记到凭证的 authorization.documentSha256）
  init                       用凭证初始化日志，写入 genesis 记录
  check                      执行前校验：这次动作现在能不能做（不写日志）
  log                        校验并记录：允许则记为 action，拒绝则记为 decision=denied
  verify                     校验日志哈希链完整性
  report                     生成合规报告（Markdown）
  anchor                     输出外部锚定行（把链头哈希钉到日志之外）
  status                     一页纸概览

通用选项：
  --manifest <路径>          凭证文件（默认 ${DEFAULT_MANIFEST}）
  --ledger <路径>            日志文件（默认 ${DEFAULT_LEDGER}）
  --hmac-key-env <变量名>    从环境变量读取 HMAC 密钥（默认读 ENGAGEMENT_LEDGER_KEY）
                            密钥不进命令行 —— 命令行参数在进程列表里是可见的

check / log 选项：
  --target <目标>            目标域名或 IP
  --action <动作>            动作类型，如 recon / scan / manual-test
  --at <ISO 时间>            动作时间（默认现在）
  --result <结果>            log 专用：执行结果，如 ok / 5 findings
  --evidence <证据>          log 专用：证据指针，如 logs/scan-001.txt
  --actor <执行人>           log 专用：执行人（默认取凭证里的 tester）

report 选项：
  --out <路径>               报告输出路径（默认 compliance-report.md）
  --json <路径>              同时输出机器可读 JSON
  --stdout                   打印到标准输出而不是写文件

示例：
  engagement-ledger hash-doc 授权书.pdf
  engagement-ledger init
  engagement-ledger check --target api.example.com --action recon
  engagement-ledger log --target api.example.com --action recon --result "12 endpoints"
  engagement-ledger verify
  engagement-ledger report --stdout
`;

function main(argv) {
  const { command, positionals, options } = parseArgs(argv);

  if (!command || command === 'help' || command === '--help' || command === '-h') {
    process.stdout.write(HELP);
    return EXIT.OK;
  }

  const manifestPath = resolve(options.manifest || DEFAULT_MANIFEST);
  const ledgerPath = resolve(options.ledger || DEFAULT_LEDGER);

  switch (command) {
    case 'hash-doc':
      return cmdHashDoc(positionals);
    case 'init':
      return cmdInit({ manifestPath, ledgerPath, options });
    case 'check':
      return cmdCheck({ manifestPath, options, record: false, ledgerPath });
    case 'log':
      return cmdLog({ manifestPath, ledgerPath, options });
    case 'verify':
      return cmdVerify({ manifestPath, ledgerPath, options });
    case 'report':
      return cmdReport({ manifestPath, ledgerPath, options });
    case 'anchor':
      return cmdAnchor({ manifestPath, ledgerPath, options });
    case 'status':
      return cmdStatus({ manifestPath, ledgerPath, options });
    default:
      fail(`未知命令：${command}\n\n运行 engagement-ledger --help 查看用法。`);
      return EXIT.ERROR;
  }
}

/* ============================ 命令实现 ============================ */

function cmdHashDoc(positionals) {
  if (positionals.length !== 1) {
    fail('用法：engagement-ledger hash-doc <文件>');
    return EXIT.ERROR;
  }
  const target = resolve(positionals[0]);
  if (!existsSync(target)) {
    fail(`文件不存在：${target}`);
    return EXIT.ERROR;
  }
  const hash = fileSha256(readFileSync(target));
  process.stdout.write(`文件：${target}\n`);
  process.stdout.write(`SHA-256：${hash}\n\n`);
  process.stdout.write(`把它填进凭证：\n`);
  process.stdout.write(`  "authorization": { "documentSha256": "${hash}" }\n`);
  return EXIT.OK;
}

function cmdInit({ manifestPath, ledgerPath, options }) {
  const manifest = loadManifestOrExit(manifestPath);
  if (!manifest) return EXIT.ERROR;
  const hmacKey = readHmacKey(options);

  /* 已初始化过就不重复写 genesis，避免产生"两条创世记录"这种不可解释的状态 */
  const existing = loadLedger(ledgerPath);
  if (existing.length > 0) {
    fail(`日志已存在（${ledgerPath}，${existing.length} 条记录），不重复初始化。\n如需重新开始，请手动移走或删除该文件。`);
    return EXIT.ERROR;
  }

  const docCheck = verifyAuthorizationDocument(manifest);

  const entry = makeEntry({
    seq: 0,
    type: 'genesis',
    actor: manifest.engagement.tester,
    reason: `建立审计日志 · 委托 ${manifest.engagement.id}`,
  });
  entry.engagementId = manifest.engagement.id;
  entry.engagementName = manifest.engagement.name;
  entry.authorizationReference = manifest.engagement.authorization.reference;
  entry.authorizationSha256 = manifest.engagement.authorization.documentSha256 || null;
  entry.window = {
    from: manifest.engagement.window.from.toISOString(),
    to: manifest.engagement.window.to.toISOString(),
  };
  entry.scope = manifest.engagement.scope;
  entry.permittedActions = manifest.engagement.permittedActions;
  entry.prohibitedActions = manifest.engagement.prohibitedActions;
  entry.hardForbidden = NEVER_PERMITTED_ACTIONS;

  const sealed = appendEntry(ledgerPath, entry, { hmacKey });

  process.stdout.write(`✅ 已初始化审计日志\n\n`);
  process.stdout.write(`  委托编号：${manifest.engagement.id}\n`);
  process.stdout.write(`  测试方　：${manifest.engagement.tester}\n`);
  process.stdout.write(`  授权文件：${manifest.engagement.authorization.reference}\n`);
  process.stdout.write(`  授权窗口：${entry.window.from} ~ ${entry.window.to}\n`);
  process.stdout.write(`  日志文件：${ledgerPath}\n`);
  process.stdout.write(`  创世哈希：${sealed.hash}\n`);
  process.stdout.write(`  签名方式：${hmacKey ? '哈希链 + HMAC（无密钥不可伪造）' : '纯哈希链（篡改可发现）'}\n\n`);

  if (!docCheck.ok) {
    process.stdout.write(`⚠️  授权文件核验未通过：${docCheck.reason}\n`);
    process.stdout.write(`   ${docCheck.howTo}\n\n`);
  } else {
    process.stdout.write(`✅ 授权文件核验通过：${docCheck.reason}\n\n`);
  }

  for (const w of manifest.warnings || []) {
    process.stdout.write(`⚠️  ${w}\n`);
  }
  if (manifest.warnings?.length) process.stdout.write('\n');

  process.stdout.write(`下一步：用 check 试判，用 log 记录，用 report 出报告。\n`);
  return EXIT.OK;
}

function cmdCheck({ manifestPath, options, ledgerPath }) {
  const manifest = loadManifestOrExit(manifestPath);
  if (!manifest) return EXIT.ERROR;

  const verdict = evaluateAction(manifest, {
    target: options.target,
    action: options.action,
    at: options.at ? new Date(options.at) : new Date(),
  });

  printVerdict(verdict);
  process.stdout.write(`\n（本次仅为试判，未写入日志${ledgerPath ? '' : ''}。要留痕请用 log 命令。）\n`);
  return verdict.allowed ? EXIT.OK : EXIT.DENIED;
}

function cmdLog({ manifestPath, ledgerPath, options }) {
  const manifest = loadManifestOrExit(manifestPath);
  if (!manifest) return EXIT.ERROR;
  const hmacKey = readHmacKey(options);

  if (!existsSync(ledgerPath)) {
    fail(`日志不存在：${ledgerPath}\n请先运行 engagement-ledger init 初始化。`);
    return EXIT.ERROR;
  }

  /* 预防优于检测：不要往属于另一次委托的日志里追加记录。
     共用日志路径会让报告的统计与流水把两件事写成一件 —— 而报告是要交给客户的。 */
  const existing = loadLedgerOrExit(ledgerPath);
  if (!existing) return EXIT.ERROR;
  const genesis = existing.find((e) => e.type === 'genesis');
  if (genesis?.engagementId && String(genesis.engagementId) !== manifest.engagement.id) {
    fail(
      `日志属于另一次委托，拒绝追加。\n` +
        `     日志建立于：${genesis.engagementId}\n` +
        `     当前凭证是：${manifest.engagement.id}\n` +
        `     请为该委托单独指定 --ledger，不要与另一次委托共用日志文件。`
    );
    return EXIT.ERROR;
  }

  const verdict = evaluateAction(manifest, {
    target: options.target,
    action: options.action,
    at: options.at ? new Date(options.at) : new Date(),
  });

  /* 注意：拒绝也要入库 —— 被拒绝的尝试证明边界是有效的 */
  const entry = makeEntry({
    type: verdict.allowed ? 'action' : 'decision',
    actor: options.actor || manifest.engagement.tester,
    action: verdict.context.action,
    target: verdict.context.target,
    decision: verdict.decision,
    reason: verdict.reason,
    result: verdict.allowed ? options.result || 'executed' : 'not-executed',
    evidence: options.evidence || null,
    checks: verdict.checks,
    timestamp: verdict.context.at,
  });
  entry.engagementId = manifest.engagement.id;

  /* 区分"事件何时发生"（timestamp）与"何时被记进日志"（recordedAt）。
     追加写的日志只能证明写入顺序，不能证明事件顺序 —— 把两者都留下，
     审计方才能看出哪些记录是事后补录的，而不是被动地假设一切按时间发生。 */
  const recordedAt = new Date();
  entry.recordedAt = recordedAt.toISOString();
  const skewMs = Math.abs(recordedAt.getTime() - new Date(verdict.context.at).getTime());
  const isBackfilled = skewMs > BACKFILL_THRESHOLD_MS;
  if (isBackfilled) {
    entry.backfilled = true;
    entry.recordedSkewSeconds = Math.round(skewMs / 1000);
  }

  const sealed = appendEntry(ledgerPath, entry, { hmacKey });

  printVerdict(verdict);
  process.stdout.write(`\n已写入日志：seq=${sealed.seq} hash=${sealed.hash.slice(0, 16)}…\n`);
  if (isBackfilled) {
    process.stdout.write(
      `\n⚠️  补录记录：事件时间与写入时间相差 ${Math.round(skewMs / 60000)} 分钟，已标记 backfilled=true。\n` +
        `   追加写的日志只能证明写入顺序，补录时事件顺序无法由链条本身证明 —— 标记出来比默默写入更诚实。\n`
    );
  }
  if (!verdict.allowed) {
    process.stdout.write(`\n⛔ 该动作未被授权，**未执行**，本次尝试已作为拒绝记录留痕。\n`);
    process.stdout.write(`   这正是审计日志的价值：越界动作在发生前就被拦下。\n`);
    process.stdout.write(`   被拒记录就是测试纪律的证据 —— 事后无法自证"我没越界"，但日志可以。\n`);
  }
  return verdict.allowed ? EXIT.OK : EXIT.DENIED;
}

function cmdVerify({ manifestPath, ledgerPath, options }) {
  const hmacKey = readHmacKey(options);
  const entries = loadLedgerOrExit(ledgerPath);
  if (!entries) return EXIT.ERROR;

  const result = verifyLedger(entries, { hmacKey });

  if (result.ok) {
    process.stdout.write(`✅ 哈希链完整\n\n`);
    process.stdout.write(`  记录条数：${result.count}\n`);
    process.stdout.write(`  链头哈希：${result.headHash}\n`);
    if (result.count) {
      process.stdout.write(`  首条时间：${result.details[0].timestamp}\n`);
      process.stdout.write(`  末条时间：${result.details.at(-1).timestamp}\n`);
    }
    process.stdout.write(`\n最近 5 条：\n`);
    for (const d of result.details.slice(-5)) {
      process.stdout.write(`  [${String(d.seq).padStart(3)}] ${d.timestamp}  ${d.summary}\n`);
    }
    process.stdout.write(`\n提示：链完整只说明"内容没被改"。要覆盖"整份重算替换"，请运行 anchor 并把结果提交进 git。\n`);

    /* 链完整不等于这些记录都属于同一次委托。
       期望的委托编号：优先取凭证；没给凭证就回落到 genesis 记录自己的声明 ——
       这样即使只校验日志本身，也能发现"里面混了别人的记录"。 */
    const expectedId = manifestPath && existsSync(manifestPath)
      ? loadManifestOrExit(manifestPath)?.engagement?.id
      : entries.find((e) => e.type === 'genesis')?.engagementId;

    if (expectedId) {
      const consistency = checkEngagementConsistency(expectedId, entries);
      if (!consistency.ok) {
        process.stdout.write(
          `\n⚠️  委托归属异常：${consistency.foreign.length} 条记录属于别的委托（本委托 ${consistency.expected}）。\n`
        );
        for (const f of consistency.foreign.slice(0, 5)) {
          process.stdout.write(`     [${f.seq}] ${f.action || f.type} → ${f.target || '—'}（属于 ${f.engagementId}）\n`);
        }
        process.stdout.write(`   链本身完整，但这些记录不属于本次委托的证据范围。\n`);
        return EXIT.INTEGRITY;
      }
      if (consistency.untagged.length) {
        process.stdout.write(`\n提示：${consistency.untagged.length} 条记录未标注委托编号，无法自动确认归属。\n`);
      }
    }
    return EXIT.OK;
  }

  process.stdout.write(`❌ 哈希链校验失败\n\n`);
  process.stdout.write(`  断裂位置：第 ${result.brokenAt} 条（seq=${result.details.at(-1)?.seq}）\n`);
  process.stdout.write(`  原因　　：${result.reason}\n\n`);
  process.stdout.write(`  该日志不可作为合规证据使用。请追溯是谁在何时改动了日志文件。\n`);
  return EXIT.INTEGRITY;
}

function cmdReport({ manifestPath, ledgerPath, options }) {
  const manifest = loadManifestOrExit(manifestPath);
  if (!manifest) return EXIT.ERROR;
  const hmacKey = readHmacKey(options);
  const entries = loadLedgerOrExit(ledgerPath);
  if (!entries) return EXIT.ERROR;

  const markdown = buildReport({ manifest, entries, hmacKey });

  if (options.stdout) {
    process.stdout.write(markdown);
  } else {
    const outPath = resolve(options.out || 'compliance-report.md');
    writeFileSync(outPath, markdown, 'utf8');
    process.stdout.write(`✅ 合规报告已生成：${outPath}\n`);
  }

  if (options.json) {
    const jsonPath = resolve(options.json);
    writeFileSync(jsonPath, JSON.stringify(buildJsonReport({ manifest, entries, hmacKey }), null, 2) + '\n', 'utf8');
    process.stdout.write(`✅ 机器可读报告已生成：${jsonPath}\n`);
  }

  const verification = verifyLedger(entries, { hmacKey });
  if (!verification.ok) {
    process.stdout.write(`\n⚠️  注意：日志哈希链校验失败，报告中的完整性一节已标注。\n`);
    return EXIT.INTEGRITY;
  }

  const consistency = checkEngagementConsistency(manifest.engagement.id, entries);
  if (!consistency.ok) {
    process.stdout.write(
      `\n⚠️  注意：${consistency.foreign.length} 条记录属于别的委托，报告第 5.1 节已标注。\n` +
        `   统计数字与动作流水包含了不属于本次委托的内容，纠正前不要交付客户。\n`
    );
    return EXIT.INTEGRITY;
  }
  return EXIT.OK;
}

function cmdAnchor({ manifestPath, ledgerPath, options }) {
  const hmacKey = readHmacKey(options);
  const entries = loadLedgerOrExit(ledgerPath);
  if (!entries) return EXIT.ERROR;

  const info = anchorInfo(entries, { hmacKey });

  process.stdout.write(`锚定信息\n\n`);
  process.stdout.write(`  委托编号：${info.engagementId || '(未初始化)'}\n`);
  process.stdout.write(`  记录条数：${info.entryCount}\n`);
  process.stdout.write(`  链头哈希：${info.headHash || '校验失败，无法锚定'}\n`);
  process.stdout.write(`  起止时间：${info.firstTimestamp} ~ ${info.lastTimestamp}\n`);
  process.stdout.write(`  链状态　：${info.chainOk ? '✅ 完整' : '❌ 断裂'}\n\n`);
  process.stdout.write(`建议锚定行（把它追加到 ANCHORS.txt 并提交进 git）：\n\n`);
  process.stdout.write(`  ${info.anchorLine}\n\n`);
  process.stdout.write(`为什么需要锚定：哈希链能发现"改内容"，但发现不了"整份重算一遍再替换"。\n`);
  process.stdout.write(`把链头哈希提交进 git 之后，改写历史就会与这个 commit 冲突，替换整链即暴露。\n`);

  return info.chainOk ? EXIT.OK : EXIT.INTEGRITY;
}

function cmdStatus({ manifestPath, ledgerPath, options }) {
  if (!existsSync(manifestPath)) {
    fail(`凭证文件不存在：${manifestPath}\n请先创建 ${DEFAULT_MANIFEST}。`);
    return EXIT.ERROR;
  }
  const manifest = loadManifestOrExit(manifestPath);
  if (!manifest) return EXIT.ERROR;

  const eng = manifest.engagement;
  const now = new Date();
  const active = now >= eng.window.from && now <= eng.window.to;

  process.stdout.write(`授权状态\n\n`);
  process.stdout.write(`  委托　　：${eng.id} · ${eng.name}\n`);
  process.stdout.write(`  测试方　：${eng.tester}\n`);
  process.stdout.write(`  授权文件：${eng.authorization.reference}（签署人 ${eng.authorization.signedBy}）\n`);
  process.stdout.write(`  窗口　　：${eng.window.from.toISOString()} ~ ${eng.window.to.toISOString()}\n`);
  process.stdout.write(`  当前状态：${active ? '✅ 授权有效期内' : now < eng.window.from ? '⏳ 尚未开始' : '⌛ 已过期'}\n\n`);

  process.stdout.write(`范围\n\n`);
  for (const r of eng.scope.inScope) process.stdout.write(`  ✅ ${r}\n`);
  for (const r of eng.scope.outOfScope) process.stdout.write(`  ⛔ ${r}（排除，优先级更高）\n`);
  process.stdout.write(`\n  允许动作：${eng.permittedActions.join(', ') || '（未限定）'}\n`);
  process.stdout.write(`  禁止动作：${eng.prohibitedActions.join(', ') || '（未额外声明）'}\n\n`);

  if (!existsSync(ledgerPath)) {
    process.stdout.write(`日志：尚未初始化（运行 engagement-ledger init）\n`);
    return active ? EXIT.OK : EXIT.DENIED;
  }

  const entries = loadLedgerOrExit(ledgerPath);
  if (!entries) return EXIT.ERROR;
  const hmacKey = readHmacKey(options);
  const verification = verifyLedger(entries, { hmacKey });
  const stats = summarizeLedger(entries);

  process.stdout.write(`日志\n\n`);
  process.stdout.write(`  文件　　：${ledgerPath}\n`);
  process.stdout.write(`  记录条数：${stats.total}（允许 ${stats.decisions.allowed} / 拒绝 ${stats.decisions.denied}）\n`);
  process.stdout.write(`  链完整性：${verification.ok ? '✅ 完整' : `❌ 断裂于第 ${verification.brokenAt} 条`}\n`);

  const consistency = checkEngagementConsistency(eng.id, entries);
  process.stdout.write(
    `  委托归属：${consistency.ok ? '✅ 一致' : `❌ ${consistency.foreign.length} 条属于别的委托`}\n`
  );
  process.stdout.write(`  涉及目标：${stats.targetsTouched.length} 个\n`);
  process.stdout.write(`  最近记录：${stats.lastTimestamp || '（无）'}\n`);

  if (stats.timeline.length) {
    process.stdout.write(`\n最近动作（流水见 report）\n\n`);
    for (const a of stats.timeline.slice(-5)) {
      const what = a.type === 'note' ? '（备注）' : a.action;
      process.stdout.write(`  [${a.seq}] ${a.timestamp}  ${what} → ${a.target || '—'}${a.result ? `（${a.result}）` : ''}\n`);
    }
  }

  if (stats.deniedActions.length) {
    process.stdout.write(`\n被拒绝的尝试（纪律证据）\n\n`);
    for (const d of stats.deniedActions.slice(-5)) {
      process.stdout.write(`  [${d.seq}] ${d.action} → ${d.target}\n      ${d.reason}\n`);
    }
  }

  if (!consistency.ok) {
    process.stdout.write(`\n⚠️  日志里混有别的委托的记录，报告会把它标在第 5.1 节。\n`);
    process.stdout.write(`   确认是否与另一次委托共用了日志文件。\n`);
  }

  return verification.ok && consistency.ok && active ? EXIT.OK : EXIT.INTEGRITY;
}

/* ============================ 输出与工具 ============================ */

function printVerdict(verdict) {
  const mark = verdict.allowed ? '✅' : '⛔';
  process.stdout.write(`${mark} ${verdict.allowed ? '允许执行' : '拒绝执行'}\n\n`);
  process.stdout.write(`  动作：${verdict.context.action}\n`);
  process.stdout.write(`  目标：${verdict.context.target}\n`);
  process.stdout.write(`  时间：${verdict.context.at}\n\n`);
  process.stdout.write(`校验轨迹：\n`);
  for (const c of verdict.checks) {
    process.stdout.write(`  ${c.passed ? '✓' : '✗'} ${c.name}\n      ${c.detail}\n`);
  }
  if (!verdict.allowed) {
    process.stdout.write(`\n拒绝依据：${verdict.reason}\n`);
  }
}

function loadManifestOrExit(path) {
  try {
    return loadManifest(path);
  } catch (err) {
    fail(`凭证载入失败：${err.message}`);
    if (err.name === 'ManifestError' && err.issues) {
      for (const issue of err.issues) process.stderr.write(`  - ${issue}\n`);
    }
    return null;
  }
}

function loadLedgerOrExit(path) {
  try {
    return loadLedger(path);
  } catch (err) {
    fail(`日志读取失败：${err.message}`);
    return null;
  }
}

/**
 * HMAC 密钥从环境变量读，不进命令行。
 * 命令行参数在进程列表（ps / 任务管理器）里对同机其他用户可见，密钥不应该出现在那里。
 */
function readHmacKey(options) {
  const varName = options['hmac-key-env'] || 'ENGAGEMENT_LEDGER_KEY';
  const value = process.env[varName];
  return value && value.length > 0 ? value : null;
}

/**
 * 极简参数解析：支持 --flag、--key value、--key=value
 */
function parseArgs(argv) {
  const options = {};
  const positionals = [];
  let command = null;

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];

    if (arg.startsWith('--')) {
      const eq = arg.indexOf('=');
      if (eq !== -1) {
        options[arg.slice(2, eq)] = arg.slice(eq + 1);
      } else {
        const key = arg.slice(2);
        const next = argv[i + 1];
        /* 布尔开关：后面没有值，或下一个也是选项 */
        if (next === undefined || next.startsWith('--')) {
          options[key] = true;
        } else {
          options[key] = next;
          i += 1;
        }
      }
      continue;
    }

    if (command === null) command = arg;
    else positionals.push(arg);
  }

  return { command, positionals, options };
}

function fail(message) {
  process.stderr.write(`✗ ${message}\n`);
}

/* 直接运行时的入口（被 import 时不执行） */
const invoked = process.argv[1] && basename(process.argv[1]).startsWith('index.');
if (invoked) {
  process.exitCode = main(process.argv.slice(2));
}

export { main, parseArgs };

/**
 * 合规报告生成
 *
 * 这份报告面向的读者不是技术团队，而是**客户 / 合规方 / 事后复盘**。
 * 因此它要回答四个问题：
 *   1. 授权是什么（谁授权、授到哪、到什么时候）
 *   2. 实际做了什么（动作清单）
 *   3. 有没有越界（越界尝试与被拒记录 —— 这恰恰是纪律的证明）
 *   4. 日志本身可不可信（链完整性 + 外部锚定）
 *
 * @module lib/report
 */

import { verifyLedger, anchorInfo } from './ledger.mjs';

/**
 * 汇总统计数据
 */
export function summarizeLedger(entries) {
  const stats = {
    total: entries.length,
    byType: {},
    decisions: { allowed: 0, denied: 0 },
    deniedActions: [],
    targetsTouched: [],
    /* 补录记录数：事件时间与写入时间相差较大的条目 */
    backfilledCount: 0,
    firstTimestamp: entries.length ? entries[0].timestamp : null,
    lastTimestamp: entries.length ? entries[entries.length - 1].timestamp : null,
  };

  const targets = new Set();

  for (const entry of entries) {
    stats.byType[entry.type] = (stats.byType[entry.type] || 0) + 1;
    if (entry.backfilled) stats.backfilledCount += 1;

    if (entry.decision === 'allowed') stats.decisions.allowed += 1;
    if (entry.decision === 'denied') {
      stats.decisions.denied += 1;
      stats.deniedActions.push({
        seq: entry.seq,
        timestamp: entry.timestamp,
        action: entry.action,
        target: entry.target,
        reason: entry.reason,
      });
    }
    if (entry.target) targets.add(entry.target);
  }

  stats.targetsTouched = [...targets].sort();
  return stats;
}

/**
 * 生成 Markdown 报告
 *
 * @param {object} options
 * @param {object} options.manifest
 * @param {Array<object>} options.entries
 * @param {string|null} [options.hmacKey]
 * @param {boolean} [options.hashDocuments] 是否提示重新核验授权文件哈希
 * @returns {string}
 */
export function buildReport({ manifest, entries, hmacKey = null }) {
  const eng = manifest.engagement;
  const stats = summarizeLedger(entries);
  const verification = verifyLedger(entries, { hmacKey });
  const anchor = anchorInfo(entries, { hmacKey });
  const now = new Date();

  const lines = [];
  const p = (s = '') => lines.push(s);

  p(`# 授权测试合规报告`);
  p();
  p(`> 本报告由 engagement-ledger 自动生成，数据来源为防篡改审计日志。`);
  p();

  /* ---- 1. 委托与授权 ---- */
  p(`## 1. 委托与授权`);
  p();
  p(`| 项目 | 内容 |`);
  p(`| --- | --- |`);
  p(`| 委托编号 | \`${eng.id}\` |`);
  p(`| 委托名称 | ${eng.name} |`);
  p(`| 测试方 | ${eng.tester} |`);
  p(`| 授权文件 | ${eng.authorization.reference} |`);
  p(`| 签署人 | ${eng.authorization.signedBy}${eng.authorization.signedTitle ? `（${eng.authorization.signedTitle}）` : ''} |`);
  p(`| 授权签署日期 | ${fmt(eng.authorization.signedAt)} |`);
  p(`| 授权窗口 | ${fmt(eng.window.from)} ~ ${fmt(eng.window.to)} |`);
  p(`| 窗口状态 | ${windowStatus(eng.window, now)} |`);
  p();
  if (eng.authorization.documentSha256) {
    p(`授权文件完整性指纹（SHA-256）：`);
    p();
    p('```');
    p(eng.authorization.documentSha256);
    p('```');
    p();
    p(`> 复核方式：对授权文件原件计算 SHA-256，与本值比对。一致则说明本报告所依据的授权文件未被替换。`);
    p();
  } else {
    p(`> ⚠️ 凭证未登记授权文件哈希，无法证明所依据的授权文件未被替换。`);
    p();
  }

  /* ---- 2. 范围 ---- */
  p(`## 2. 授权范围`);
  p();
  p(`**纳入范围（inScope）**`);
  p();
  for (const rule of eng.scope.inScope) p(`- \`${rule}\``);
  p();
  if (eng.scope.outOfScope.length) {
    p(`**明确排除（outOfScope）** —— 排除优先`);
    p();
    for (const rule of eng.scope.outOfScope) p(`- \`${rule}\``);
    p();
  }
  p(`**允许动作**：${eng.permittedActions.length ? eng.permittedActions.map((a) => `\`${a}\``).join('、') : '（未限定）'}`);
  p();
  p(`**明确禁止**：${eng.prohibitedActions.length ? eng.prohibitedActions.map((a) => `\`${a}\``).join('、') : '（未额外声明）'}`);
  p();
  p(`**系统硬性禁止**（任何授权均不可放行）：${(manifest.hardForbidden || []).map((a) => `\`${a}\``).join('、')}`);
  p();

  /* ---- 3. 执行记录 ---- */
  p(`## 3. 执行记录统计`);
  p();
  p(`| 指标 | 数值 |`);
  p(`| --- | --- |`);
  p(`| 日志总条数 | ${stats.total} |`);
  p(`| 判定为允许 | ${stats.decisions.allowed} |`);
  p(`| 判定为拒绝 | ${stats.decisions.denied} |`);
  p(`| 涉及目标数 | ${stats.targetsTouched.length} |`);
  p(`| 按写入顺序的首条 | ${fmt(stats.firstTimestamp)} |`);
  p(`| 按写入顺序的末条 | ${fmt(stats.lastTimestamp)} |`);
  p(`| 事后补录记录 | ${stats.backfilledCount} |`);
  p();
  if (stats.backfilledCount > 0) {
    p(
      `> 本日志有 ${stats.backfilledCount} 条记录的事件时间与写入时间相差超过 5 分钟（标记 \`backfilled\`）。` +
        `追加写的日志只能证明**写入顺序**，不能证明**事件顺序**；这些条目的先后关系应由操作方的其他记录佐证。`
    );
    p();
  }
  if (stats.targetsTouched.length) {
    p(`### 3.1 涉及的目标`);
    p();
    for (const t of stats.targetsTouched) p(`- \`${t}\``);
    p();
  }

  /* ---- 4. 越界尝试（纪律证明）---- */
  p(`## 4. 越界尝试与被拒记录`);
  p();
  if (stats.deniedActions.length === 0) {
    p(`本次委托未出现越界尝试。`);
  } else {
    p(`共 ${stats.deniedActions.length} 次动作被校验门拒绝。**被拒记录是测试纪律的证据**：说明越界动作在发生前就被拦截，未对目标执行。`);
    p();
    p(`| # | 时间 | 动作 | 目标 | 拒绝原因 |`);
    p(`| --- | --- | --- | --- | --- |`);
    for (const d of stats.deniedActions) {
      /* 每个单元格都要转义：目标名来自外部输入，带竖线就会把表格撑破 */
      p(`| ${d.seq} | ${escapeCell(fmt(d.timestamp))} | \`${escapeCell(d.action)}\` | \`${escapeCell(d.target)}\` | ${escapeCell(d.reason)} |`);
    }
  }
  p();

  /* ---- 5. 完整性 ---- */
  p(`## 5. 日志完整性`);
  p();
  if (verification.ok) {
    p(`✅ 哈希链完整：${verification.count} 条记录逐条校验通过，链条无断裂。`);
    p();
    p(`链头哈希（head hash）：`);
    p();
    p('```');
    p(verification.headHash || '(空)');
    p('```');
  } else {
    p(`❌ **哈希链校验失败**：第 ${verification.brokenAt} 条记录（seq=${verification.details.at(-1)?.seq}）不通过。`);
    p();
    p(`原因：${verification.reason}`);
    p();
    p(`**该日志不可作为合规证据使用**，请追溯是谁在何时改动了日志文件。`);
  }
  p();

  /* ---- 6. 锚定 ---- */
  p(`## 6. 外部锚定（防整链替换）`);
  p();
  p(`哈希链能发现"改内容"，但发现不了"整份重算一遍再替换"。要覆盖这一层，需要把链头哈希锚定到日志文件之外的存储：`);
  p();
  p(`1. 提交进 git（每次锚定一个 commit，历史不可改写即证据）`);
  p(`2. 写入独立的只追加存储 / 对象存储（开启版本控制与对象锁）`);
  p(`3. 向可信时间戳服务提交链头哈希`);
  p();
  p(`建议锚定行：`);
  p();
  p('```');
  p(anchor.anchorLine);
  p('```');
  p();
  p(`| 锚定信息 | 值 |`);
  p(`| --- | --- |`);
  p(`| 记录条数 | ${anchor.entryCount} |`);
  p(`| 链头哈希 | \`${anchor.headHash || 'BROKEN'}\` |`);
  if (manifest.anchors && manifest.anchors.length) {
    p(`| 已登记锚定次数 | ${manifest.anchors.length} |`);
  }
  p();

  /* ---- 7. 声明 ---- */
  p(`## 7. 边界声明`);
  p();
  p(`- **篡改可发现 ≠ 不可伪造**：本日志保证"改动会被发现"，不保证"无人能伪造整条链"。启用 HMAC 密钥可提升为"无密钥不可伪造"。`);
  p(`- **写入顺序 ≠ 事件顺序**：追加写的日志天然只能证明"哪条先被写下"，不能单独证明"哪件事先发生"。补录条目已用 \`backfilled\` 标记，但事件先后仍需操作方的其他记录佐证。`);
  p(`- **本日志完整 ≠ 全部操作都在日志里**：链只能证明已记录的内容未被改动；未记录的操作不在本报告的证明范围内。`);
  p(`- 本报告仅覆盖通过本工具记录的动作。经由本工具之外执行的任何操作，均不在本报告的证明范围内。`);
  p(`- 授权范围的最终解释权归授权方所有。测试过程中如对边界存疑，应暂停并书面向授权方确认。`);
  p();
  p(`---`);
  p();
  p(`报告生成时间：${now.toISOString()}`);
  p();

  return lines.join('\n');
}

/**
 * 生成机器可读的 JSON 报告
 */
export function buildJsonReport({ manifest, entries, hmacKey = null }) {
  const verification = verifyLedger(entries, { hmacKey });
  return {
    generatedAt: new Date().toISOString(),
    engagement: {
      id: manifest.engagement.id,
      name: manifest.engagement.name,
      tester: manifest.engagement.tester,
      authorization: {
        reference: manifest.engagement.authorization.reference,
        signedBy: manifest.engagement.authorization.signedBy,
        signedTitle: manifest.engagement.authorization.signedTitle || null,
        signedAt: manifest.engagement.authorization.signedAt,
        documentSha256: manifest.engagement.authorization.documentSha256 || null,
      },
      window: {
        from: manifest.engagement.window.from.toISOString(),
        to: manifest.engagement.window.to.toISOString(),
      },
      scope: manifest.engagement.scope,
      permittedActions: manifest.engagement.permittedActions,
      prohibitedActions: manifest.engagement.prohibitedActions,
      hardForbidden: manifest.hardForbidden || [],
    },
    statistics: summarizeLedger(entries),
    integrity: {
      chainOk: verification.ok,
      count: verification.count,
      brokenAt: verification.brokenAt,
      reason: verification.reason,
      headHash: verification.headHash,
    },
    anchor: anchorInfo(entries, { hmacKey }),
    warnings: manifest.warnings || [],
  };
}

/* ---------- 工具 ---------- */

function fmt(value) {
  if (!value) return '（无）';
  const d = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(d.getTime())) return String(value);
  return d.toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC');
}

function windowStatus(window, now) {
  if (now < window.from) return '⏳ 尚未开始';
  if (now > window.to) return '⌛ 已结束';
  return '✅ 进行中';
}

function escapeCell(text) {
  return String(text ?? '').replace(/\|/g, '\\|').replace(/[\r\n]+/g, ' ');
}

/**
 * 防篡改审计日志（哈希链）
 *
 * 存储格式：JSON Lines（一行一条记录），便于追加、逐行校验、用普通工具查看。
 *
 * 完整性设计：
 *   每条记录的 hash = H(prevHash + 规范化(记录内容))
 *   → 改动任意一条的内容，该条哈希立刻失配，且其后所有记录的 prevHash 链条断裂。
 *   → 校验时能精确指出「第几条开始对不上」。
 *
 * 能力边界（必须说清楚，否则会给人虚假的安全感）：
 *   - 哈希链是 **tamper-evident（篡改可发现）**：改了就能查出来。
 *   - 但它 **不是 tamper-proof（不可伪造）**：知道算法的人可以把整条链重新算一遍。
 *   - 提供 HMAC 密钥可升级为「无密钥不可伪造」（不知道密钥就算不出正确的链）。
 *   - 连"整链替换"也要能发现，必须把链头哈希 **锚定到外部**：提交进 git、
 *     或写入一份独立存储、或做可信时间戳。`ledger anchor` 就是为此设计的。
 *
 * @module lib/ledger
 */

import { readFileSync, writeFileSync, appendFileSync, existsSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { GENESIS_HASH, computeEntryHash, hashEquals } from './crypto.mjs';

/** 记录类型 */
export const ENTRY_TYPES = ['genesis', 'decision', 'action', 'note'];

export class LedgerError extends Error {
  constructor(message) {
    super(message);
    this.name = 'LedgerError';
  }
}

/**
 * 创建一条记录（不计算哈希）
 */
export function makeEntry({
  seq,
  type = 'action',
  actor,
  action = null,
  target = null,
  decision = null,
  reason = null,
  result = null,
  evidence = null,
  checks = null,
  timestamp = new Date().toISOString(),
}) {
  if (!ENTRY_TYPES.includes(type)) {
    throw new LedgerError(`未知记录类型：${type}`);
  }
  const entry = { seq, timestamp, type, actor };
  if (action) entry.action = action;
  if (target) entry.target = target;
  if (decision) entry.decision = decision;
  if (reason) entry.reason = reason;
  if (result) entry.result = result;
  if (evidence) entry.evidence = evidence;
  /* 判定轨迹也入库：审计要的是"当时依据什么判定"，不只是判定结果 */
  if (checks) entry.checks = checks;
  return entry;
}

/**
 * 计算并写入哈希（就地返回新对象，不改原对象）
 */
export function sealEntry(entry, prevHash, hmacKey = null) {
  const sealed = { ...entry, prevHash };
  sealed.hash = computeEntryHash(sealed, prevHash, hmacKey);
  return sealed;
}

/**
 * 载入已存在的日志
 * @param {string} path
 * @returns {Array<object>} 记录数组
 */
export function loadLedger(path) {
  if (!existsSync(path)) return [];
  const text = readFileSync(path, 'utf8');
  const entries = [];

  for (const [i, line] of text.split(/\r?\n/).entries()) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      entries.push(JSON.parse(trimmed));
    } catch (err) {
      throw new LedgerError(`日志第 ${i + 1} 行不是合法 JSON：${err.message}`);
    }
  }
  return entries;
}

/**
 * 追加一条记录并落盘
 *
 * @param {string} path
 * @param {object} entry 不含 hash / prevHash
 * @param {object} options
 * @param {string|null} options.hmacKey
 * @returns {object} 已封口的记录
 */
export function appendEntry(path, entry, options = {}) {
  const entries = loadLedger(path);
  const prevHash = entries.length ? entries[entries.length - 1].hash : GENESIS_HASH;

  const sealed = sealEntry({ ...entry, seq: entries.length }, prevHash, options.hmacKey);

  mkdirSync(dirname(path), { recursive: true });
  appendFileSync(path, JSON.stringify(sealed) + '\n', 'utf8');

  return sealed;
}

/**
 * 校验整条链
 *
 * @param {Array<object>} entries
 * @param {object} options
 * @param {string|null} options.hmacKey
 * @returns {{ok: boolean, count: number, brokenAt: number|null, reason: string|null, headHash: string|null, details: Array}}
 */
export function verifyLedger(entries, options = {}) {
  const details = [];
  let prev = GENESIS_HASH;

  for (const [i, entry] of entries.entries()) {
    /* 1. 序号必须连续（防止"抽掉一条"这种篡改） */
    if (entry.seq !== i) {
      return fail(i, `序号不连续：期望 ${i}，实际 ${entry.seq}（可能被删除或插入过记录）`);
    }

    /* 2. prevHash 必须指向上一条的哈希 */
    if (!hashEquals(entry.prevHash, prev)) {
      return fail(i, `prevHash 与上一条的 hash 不一致（链条在此断裂）`);
    }

    /* 3. 自身哈希必须与内容一致 */
    const expected = computeEntryHash(entry, entry.prevHash, options.hmacKey);
    if (!hashEquals(entry.hash, expected)) {
      const hint = options.hmacKey
        ? '内容被改动，或 HMAC 密钥不匹配'
        : '内容被改动（或该条是用不同密钥签的）';
      return fail(i, `记录哈希与内容不符 —— ${hint}`);
    }

    details.push({
      seq: entry.seq,
      type: entry.type,
      timestamp: entry.timestamp,
      summary: summarize(entry),
      ok: true,
    });
    prev = entry.hash;
  }

  return {
    ok: true,
    count: entries.length,
    brokenAt: null,
    reason: null,
    /* 链头哈希：锚定到外部存储就用它 */
    headHash: entries.length ? entries[entries.length - 1].hash : GENESIS_HASH,
    details,
  };

  function fail(index, reason) {
    details.push({
      seq: entries[index] ? entries[index].seq : index,
      type: entries[index] ? entries[index].type : 'unknown',
      timestamp: entries[index] ? entries[index].timestamp : null,
      summary: entries[index] ? summarize(entries[index]) : '(无法读取)',
      ok: false,
      reason,
    });
    return {
      ok: false,
      count: entries.length,
      brokenAt: index,
      reason,
      headHash: null,
      details,
    };
  }
}

function summarize(entry) {
  switch (entry.type) {
    case 'genesis':
      return `建立日志（委托 ${entry.engagementId || '?'}）`;
    case 'decision':
      return `${entry.decision === 'denied' ? '拒绝' : '允许'} ${entry.action || '?'} → ${entry.target || '?'}`;
    case 'action':
      return `执行 ${entry.action || '?'} → ${entry.target || '?'}${entry.result ? `（${entry.result}）` : ''}`;
    default:
      return entry.reason || entry.type;
  }
}

/**
 * 委托归属一致性校验
 *
 * 每条记录都带 engagementId，但在此之前从没人核对过它们是否一致。
 * 日志里混进另一次委托的记录（复制粘贴、共用日志路径、交接失误）时，
 * 报告的统计与流水会静默地把两件事写成一件 —— 而报告是要交给客户的。
 *
 * 注意：这个检查发现不了「真的在两个目标上做了事却只在日志里写了一个委托」
 * 的情况（那属于工具之外的行为，见 SECURITY.md §1.3）。它只保证：
 * 已记录的内容在委托归属上是自洽的。
 *
 * @param {string} engagementId 本次委托编号
 * @param {Array<object>} entries
 * @returns {{ok: boolean, expected: string, foreign: Array, untagged: Array}}
 */

/* ===================== 外部锚定：写入与校验 ===================== */

/** 锚定行的标签 */
export const ANCHOR_LABEL = 'engagement-ledger';

/** 锚定行格式：<标签> <条数> <链头哈希> */
const ANCHOR_LINE_RE = new RegExp(`^${ANCHOR_LABEL}\\s+(\\d+)\\s+([a-f0-9]{64})$`, 'i');

/**
 * 生成一行锚定记录
 * @param {number} entryCount
 * @param {string} headHash
 */
export function formatAnchorLine(entryCount, headHash) {
  return `${ANCHOR_LABEL} ${entryCount} ${headHash}`;
}

/**
 * 从锚定文件内容里解析出锚定记录
 *
 * 宽松解析：忽略空行、注释行（# 开头）与行内说明文字 ——
 * ANCHORS.txt 是给人看的文件，混进说明文字不该让校验整体失效。
 *
 * @param {string} text
 * @returns {{anchors: Array<{line:number, entryCount:number, headHash:string, raw:string}>, malformed: Array<{line:number, raw:string}>}}
 */
export function parseAnchors(text) {
  const anchors = [];
  const malformed = [];

  for (const [i, rawLine] of String(text ?? '').split(/\r?\n/).entries()) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;

    const m = line.match(ANCHOR_LINE_RE);
    if (!m) {
      /* 含标签但不是合法锚定行的，当作格式错误提示；完全无关的文字忽略 */
      if (line.includes(ANCHOR_LABEL)) malformed.push({ line: i + 1, raw: line });
      continue;
    }
    anchors.push({ line: i + 1, entryCount: Number(m[1]), headHash: m[2].toLowerCase(), raw: line });
  }

  return { anchors, malformed };
}

/**
 * 用外部锚定记录校验当前日志
 *
 * 这是**唯一能发现"整链被重写"的检查** —— 哈希链本身是自洽的，
 * 单看日志永远看不出它被人从头算过一遍。只有把历史锚定点的哈希
 * 与当前日志重新算出来的哈希比对，才能发现改写。
 *
 * 三种结论：
 *   - 历史锚定点对不上 → **整链被重写**（最严重）
 *   - 锚定条数 > 当前条数 → **日志被截断/回滚**
 *   - 全部匹配且最新锚定等于当前链头 → 自锚定以来未被改动
 *   - 全部匹配但当前条数更大 → 锚定之后有新增（正常，但报告应重新锚定）
 *
 * @param {Array<object>} entries 当前日志
 * @param {Array<{entryCount:number, headHash:string}>} anchors 锚定记录
 * @param {object} [options]
 * @param {string|null} [options.hmacKey]
 * @returns {{ok: boolean, checked: number, results: Array, latestCleared: boolean, reasons: string[]}}
 */
export function checkAnchors(entries, anchors, options = {}) {
  const results = [];
  const reasons = [];

  for (const anchor of anchors) {
    const { entryCount, headHash } = anchor;

    if (entryCount > entries.length) {
      results.push({
        ...anchor,
        status: 'rollback',
        detail: `锚定时有 ${entryCount} 条记录，当前只有 ${entries.length} 条 —— 日志被截断或回滚过`,
      });
      reasons.push(`第 ${entryCount} 条的锚定点要求日志至少有 ${entryCount} 条记录，但当前只有 ${entries.length} 条`);
      continue;
    }

    if (entryCount === 0) {
      /* 空日志锚定：链头是创世哈希 */
      const ok = headHash === GENESIS_HASH;
      results.push({
        ...anchor,
        status: ok ? 'match' : 'rewritten',
        detail: ok ? '空日志的锚定点匹配' : `空日志锚定点期望创世哈希，实际要的是 ${headHash}`,
      });
      if (!ok) reasons.push('空日志锚定点不匹配');
      continue;
    }

    /* 对当前日志的前 entryCount 条重算链条，取出那一时刻的链头 */
    const prefix = entries.slice(0, entryCount);
    const verification = verifyLedger(prefix, options);

    if (!verification.ok) {
      results.push({
        ...anchor,
        status: 'broken',
        detail: `前 ${entryCount} 条记录自身校验失败（${verification.reason}）`,
      });
      reasons.push(`前 ${entryCount} 条记录哈希链断裂，无法与锚定点比对`);
      continue;
    }

    if (verification.headHash === headHash) {
      results.push({ ...anchor, status: 'match', detail: `前 ${entryCount} 条记录的链头与锚定一致` });
    } else {
      results.push({
        ...anchor,
        status: 'rewritten',
        detail:
          `前 ${entryCount} 条记录的链头是 ${verification.headHash.slice(0, 16)}…，` +
          `而锚定的是 ${headHash.slice(0, 16)}… —— 这段历史被重写过`,
      });
      reasons.push(
        `锚定点 #${entryCount} 对不上：日志本身自洽（哈希链完整），但与外部锚定记录冲突 —— ` +
          `这是"整链被重算替换"的特征`
      );
    }
  }

  const currentHead = entries.length ? entries[entries.length - 1].hash : GENESIS_HASH;
  const latest = anchors.length ? anchors[anchors.length - 1] : null;
  const latestCleared = Boolean(latest && latest.entryCount === entries.length && latest.headHash === currentHead);

  return {
    ok: reasons.length === 0,
    checked: anchors.length,
    results,
    latestCleared,
    currentCount: entries.length,
    currentHead,
    reasons,
  };
}

/**
 * 委托归属一致性校验
 *
 * 每条记录都带 engagementId，但在此之前从没人核对过它们是否一致。
 * 日志里混进另一次委托的记录（复制粘贴、共用日志路径、交接失误）时，
 * 报告的统计与流水会静默地把两件事写成一件 —— 而报告是要交给客户的。
 *
 * 注意：这个检查发现不了「真的在两个目标上做了事却只在日志里写了一个委托」
 * 的情况（那属于工具之外的行为，见 SECURITY.md §1.3）。它只保证：
 * 已记录的内容在委托归属上是自洽的。
 *
 * @param {string} engagementId 本次委托编号
 * @param {Array<object>} entries
 * @returns {{ok: boolean, expected: string, foreign: Array, untagged: Array}}
 */
export function checkEngagementConsistency(engagementId, entries) {
  const expected = String(engagementId || '');
  const foreign = [];
  const untagged = [];

  for (const entry of entries) {
    const id = entry.engagementId;
    if (!id) {
      /* genesis 之后产生的记录理应带委托编号；不带的多半是手工写入的条目 */
      if (entry.type !== 'genesis') {
        untagged.push({ seq: entry.seq, type: entry.type, timestamp: entry.timestamp });
      }
      continue;
    }
    if (String(id) !== expected) {
      foreign.push({
        seq: entry.seq,
        type: entry.type,
        timestamp: entry.timestamp,
        engagementId: String(id),
        action: entry.action || null,
        target: entry.target || null,
      });
    }
  }

  return { ok: foreign.length === 0, expected, foreign, untagged };
}

/**
 * 锚定信息：给外部存储用的紧凑摘要
 */
export function anchorInfo(entries, options = {}) {
  const verification = verifyLedger(entries, options);
  return {
    engagementId: entries.find((e) => e.type === 'genesis')?.engagementId || null,
    entryCount: entries.length,
    headHash: verification.headHash,
    firstTimestamp: entries.length ? entries[0].timestamp : null,
    lastTimestamp: entries.length ? entries[entries.length - 1].timestamp : null,
    chainOk: verification.ok,
    /* 锚定建议：把下面这行提交进 git，或写入独立存储 */
    anchorLine: `engagement-ledger ${entries.length} ${verification.headHash || 'BROKEN'}`,
  };
}

/** 覆盖写入整份日志（仅用于测试与迁移；正常流程一律 append） */
export function writeLedger(path, entries) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, entries.map((e) => JSON.stringify(e)).join('\n') + '\n', 'utf8');
}

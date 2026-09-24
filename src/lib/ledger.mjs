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

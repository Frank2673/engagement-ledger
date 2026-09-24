/**
 * 哈希与规范化工具
 *
 * 审计日志的完整性取决于一个前提：**同一份内容必须总是算出同一个哈希**。
 * 因此这里实现确定性 JSON 序列化（键排序、去除空白），而不是依赖
 * `JSON.stringify` 的插入顺序 —— 否则字段顺序一变，哈希就变，"篡改"会变成误报。
 *
 * @module lib/crypto
 */

import { createHash, createHmac, timingSafeEqual } from 'node:crypto';

/** 创世哈希：链上第一条记录的 prevHash */
export const GENESIS_HASH = '0'.repeat(64);

/**
 * 确定性 JSON 序列化
 *
 * 规则：对象键按字典序排序；数组保持顺序；不输出空格；
 * undefined 字段被丢弃（避免"有没有这个键"造成哈希歧义）。
 */
export function canonicalJson(value) {
  return JSON.stringify(sortDeep(value));
}

function sortDeep(value) {
  if (Array.isArray(value)) return value.map(sortDeep);
  if (value && typeof value === 'object') {
    const out = {};
    for (const key of Object.keys(value).sort()) {
      const v = value[key];
      if (v === undefined) continue;
      out[key] = sortDeep(v);
    }
    return out;
  }
  return value;
}

/** sha256 十六进制摘要 */
export function sha256Hex(input) {
  const data = Buffer.isBuffer(input) ? input : Buffer.from(String(input), 'utf8');
  return createHash('sha256').update(data).digest('hex');
}

/** HMAC-SHA256 十六进制摘要 */
export function hmacSha256Hex(key, input) {
  const data = Buffer.isBuffer(input) ? input : Buffer.from(String(input), 'utf8');
  return createHmac('sha256', key).update(data).digest('hex');
}

/**
 * 计算一条记录哈希
 *
 * 哈希覆盖：上一条哈希 + 记录全部字段（除 hash 自身）。
 * 因此改动任意一条记录的内容、时间、结果，都会导致该条及其后所有条目的哈希失配。
 *
 * 提供 hmacKey 时使用 HMAC：没有密钥的人无法在有改动的情况下"重新算出一致的新链"，
 * 这把「篡改可发现」升级为「无密钥不可伪造」。
 */
export function computeEntryHash(entry, prevHash, hmacKey = null) {
  const { hash, ...rest } = entry;
  const payload = canonicalJson({ ...rest, prevHash });
  return hmacKey ? hmacSha256Hex(hmacKey, payload) : sha256Hex(payload);
}

/**
 * 恒定时间比较两个十六进制摘要（避免时序侧信道）
 */
export function hashEquals(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');
  if (bufA.length !== bufB.length) return false;
  return timingSafeEqual(bufA, bufB);
}

/**
 * 计算文件的 sha256（用于校验授权书文档未被替换）
 * @param {Buffer} buffer
 */
export function fileSha256(buffer) {
  return sha256Hex(buffer);
}

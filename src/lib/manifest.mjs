/**
 * 授权凭证（Engagement Manifest）
 *
 * 这是整个工具的地基：**没有凭证就没有授权，没有授权就不该有动作**。
 *
 * 凭证不只是"写个范围"，它要能回答审计方的四连问：
 *   1. 谁授权的？（授权书编号 + 签署人 + 文档哈希）
 *   2. 授权到哪一天？（时间窗）
 *   3. 授权哪些目标？（in-scope / out-of-scope）
 *   4. 允许做什么、禁止做什么？（动作白名单 + 黑名单）
 *
 * 其中「授权书文档哈希」是关键设计：把授权书本身也纳入防篡改范围，
 * 避免出现"换了一份范围更大的授权书"这种事。
 *
 * @module lib/manifest
 */

import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve, isAbsolute } from 'node:path';
import { fileSha256 } from './crypto.mjs';

/**
 * 硬性禁止动作：**不可通过配置放行**
 *
 * 有些事在任何授权下都不该由自动化工具去做 —— 把它们设成配置项等于
 * 把判断权交给一个 JSON 文件。这里做成硬编码常量，凭证里写了也会被拒绝，
 * 并且在凭证校验阶段就直接报错。
 */
export const NEVER_PERMITTED_ACTIONS = [
  'dos',
  'ddos',
  'destructive',
  'wipe',
  'data-exfiltration',
  'exfiltration',
  'ransomware',
];

/** 推荐禁止的动作（缺了只告警，不阻断） */
export const RECOMMENDED_PROHIBITED = [
  'dos',
  'destructive',
  'data-exfiltration',
  'persistence',
  'social-engineering',
];

export class ManifestError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ManifestError';
  }
}

/**
 * 加载并校验凭证
 * @param {string} filePath
 * @returns {object} 归一化后的凭证
 */
export function loadManifest(filePath) {
  const abs = isAbsolute(filePath) ? filePath : resolve(process.cwd(), filePath);

  if (!existsSync(abs)) {
    throw new ManifestError(`凭证文件不存在：${abs}`);
  }

  let parsed;
  try {
    parsed = JSON.parse(readFileSync(abs, 'utf8'));
  } catch (err) {
    throw new ManifestError(`凭证文件不是合法 JSON：${err.message}`);
  }

  const manifest = validateManifest(parsed);
  manifest.__path = abs;
  manifest.__dir = dirname(abs);
  return manifest;
}

/**
 * 校验凭证结构（纯函数，供测试直接调用）
 * @param {object} input
 * @returns {object} 归一化凭证
 */
export function validateManifest(input) {
  const problems = [];
  const warnings = [];

  if (!input || typeof input !== 'object') {
    throw new ManifestError('凭证必须是一个对象');
  }

  const eng = input.engagement;
  if (!eng || typeof eng !== 'object') {
    throw new ManifestError('缺少 engagement 段');
  }

  /* ---- 身份与授权 ---- */
  const id = str(eng.id);
  if (!id) problems.push('缺少 engagement.id（委托编号，用于关联授权书与报告）');

  const tester = str(eng.tester);
  if (!tester) problems.push('缺少 engagement.tester（执行人，审计需要知道"谁做的"）');

  const auth = eng.authorization;
  if (!auth || typeof auth !== 'object') {
    problems.push('缺少 engagement.authorization 段 —— 没有授权就不该有动作');
  } else {
    if (!str(auth.reference)) {
      problems.push('缺少 authorization.reference（授权书编号、邮件日期等可追溯凭据）');
    }
    if (!str(auth.signedBy)) {
      problems.push('缺少 authorization.signedBy（授权人）');
    }
    const docHash = str(auth.documentSha256);
    if (docHash) {
      if (!/^[a-f0-9]{64}$/i.test(docHash)) {
        problems.push('authorization.documentSha256 必须是 64 位十六进制 sha256');
      }
    } else if (str(auth.document)) {
      warnings.push(
        'authorization.document 已指定但缺少 documentSha256 —— 无法证明授权书本身未被替换，建议用 `ledger hash-doc <文件>` 生成后填入'
      );
    } else {
      warnings.push(
        '未提供授权书文档与 documentSha256：审计时只能依赖 reference 文本，建议补充文档哈希'
      );
    }
  }

  /* ---- 时间窗 ---- */
  const win = eng.window;
  let windowNormalized = null;
  if (!win || typeof win !== 'object') {
    problems.push('缺少 engagement.window（授权时间窗）—— 授权通常有明确起止时间');
  } else {
    const from = parseTime(win.from);
    const to = parseTime(win.to);
    if (!from) problems.push(`window.from 不是合法时间：${win.from}`);
    if (!to) problems.push(`window.to 不是合法时间：${win.to}`);
    if (from && to && from.getTime() >= to.getTime()) {
      problems.push('window.from 必须早于 window.to');
    }
    if (from && to) windowNormalized = { from, to };
  }

  /* ---- 范围 ---- */
  const scope = eng.scope;
  let inScope = [];
  let outOfScope = [];
  if (!scope || typeof scope !== 'object') {
    problems.push('缺少 engagement.scope 段');
  } else {
    inScope = toStrArray(scope.inScope);
    outOfScope = toStrArray(scope.outOfScope);
    if (inScope.length === 0) problems.push('scope.inScope 不能为空（没有目标范围等于没有授权）');
    for (const rule of [...inScope, ...outOfScope]) {
      if (!isValidScopeRule(rule)) {
        problems.push(`范围规则格式不合法：${rule}（支持域名、*.example.com 通配、IP、CIDR）`);
      }
    }
  }

  /* ---- 动作 ---- */
  const permitted = toStrArray(eng.permittedActions).map((a) => a.toLowerCase());
  const prohibited = toStrArray(eng.prohibitedActions).map((a) => a.toLowerCase());

  const hardViolations = permitted.filter((a) => NEVER_PERMITTED_ACTIONS.includes(a));
  if (hardViolations.length) {
    problems.push(
      `以下动作属于硬性禁止项，不允许出现在 permittedActions 中：${hardViolations.join(', ')}\n` +
        '     （这类动作在任何授权下都不应由自动化工具执行，因此不做成配置项）'
    );
  }

  const missingRecommended = RECOMMENDED_PROHIBITED.filter((a) => !prohibited.includes(a));
  if (missingRecommended.length) {
    warnings.push(
      `建议在 prohibitedActions 中显式列入：${missingRecommended.join(', ')}（显式声明比默认沉默更适合审计）`
    );
  }

  /* ---- 应急联系人 ---- */
  if (!str(eng.emergencyContact)) {
    warnings.push('缺少 emergencyContact（出事时对方联系不上你，是常见的事故升级原因）');
  }

  if (problems.length) {
    throw new ManifestError(`凭证校验失败：\n   - ${problems.join('\n   - ')}`);
  }

  return {
    version: input.version || 1,
    engagement: {
      id,
      /* 委托名称：报告标题栏要用，缺省回落到 id 以免报告里出现 undefined */
      name: str(eng.name) || id,
      client: str(eng.client) || null,
      tester,
      authorization: {
        reference: str(auth.reference),
        signedBy: str(auth.signedBy),
        /* 以什么身份签署的：审计报告里"谁授权"要能落到职位上 */
        signedTitle: str(auth.signedTitle) || null,
        signedAt: str(auth.signedAt) || null,
        document: str(auth.document) || null,
        documentSha256: str(auth.documentSha256) || null,
      },
      window: windowNormalized,
      scope: { inScope, outOfScope },
      permittedActions: permitted,
      prohibitedActions: prohibited,
      emergencyContact: str(eng.emergencyContact) || null,
      notes: str(eng.notes) || null,
    },
    /* 硬性禁止清单随凭证一起下发，报告与校验门都用它，避免两处各写一份 */
    hardForbidden: [...NEVER_PERMITTED_ACTIONS],
    warnings,
  };
}

/**
 * 校验授权书文档哈希
 *
 * 这是"证明你依据的授权书没被换过"的关键一步。
 */
export function verifyAuthorizationDocument(manifest) {
  const auth = manifest.engagement.authorization;
  const howTo = '用 `engagement-ledger hash-doc <授权书文件>` 生成哈希并填入 authorization.documentSha256';

  if (!auth.document || !auth.documentSha256) {
    return {
      checked: false,
      ok: false,
      reason: '凭证未包含授权书文档或哈希，无法自动核验',
      howTo,
    };
  }

  const docPath = isAbsolute(auth.document)
    ? auth.document
    : resolve(manifest.__dir || process.cwd(), auth.document);

  if (!existsSync(docPath)) {
    return {
      checked: false,
      ok: false,
      reason: `授权书文档不存在：${docPath}`,
      howTo: '把授权书放到该路径，或修正 authorization.document 指向',
      path: docPath,
    };
  }

  const actual = fileSha256(readFileSync(docPath));
  const ok = actual.toLowerCase() === auth.documentSha256.toLowerCase();

  return {
    checked: true,
    ok,
    expected: auth.documentSha256,
    actual,
    path: docPath,
    reason: ok
      ? `授权书内容与登记哈希一致（${actual.slice(0, 16)}…）`
      : `授权书内容与登记哈希**不一致**：登记 ${auth.documentSha256.slice(0, 16)}… / 实际 ${actual.slice(0, 16)}…`,
    howTo: ok ? null : '核对该授权书是否被替换或修改过；确认无误后重新登记哈希',
  };
}

/* ------------------------------- 辅助函数 ------------------------------- */

function str(v) {
  return typeof v === 'string' && v.trim() ? v.trim() : '';
}

function toStrArray(v) {
  if (!Array.isArray(v)) return [];
  return v.map((x) => String(x).trim()).filter(Boolean);
}

function parseTime(v) {
  if (!v) return null;
  const d = new Date(String(v));
  return Number.isNaN(d.getTime()) ? null : d;
}

/**
 * 范围规则：域名、*.domain、IPv4/IPv6、IPv4/IPv6 CIDR
 *
 * IPv6 必须支持 —— 只做 IPv4 的"范围强制"在双栈环境里会因为"写不进去"
 * 而被绕过：使用者把 IPv6 目标写在注释里，然后照测。工具的边界要能表达
 * 真实环境里存在的东西，否则它会被绕过，而不是被遵守。
 */
export function isValidScopeRule(rule) {
  const r = String(rule).trim();
  if (!r) return false;

  if (r.startsWith('*.')) return /^\*\.[a-z0-9.-]+\.[a-z]{2,}$/i.test(r);

  /* CIDR：地址部分必须是合法字面量，前缀长度必须在family 范围内 */
  if (r.includes('/')) {
    const idx = r.lastIndexOf('/');
    const addr = r.slice(0, idx);
    const bits = r.slice(idx + 1);
    const bytes = ipToBytes(addr);
    if (!bytes) return false;
    if (!/^\d{1,3}$/.test(bits)) return false;
    const n = Number(bits);
    return n >= 0 && n <= bytes.length * 8;
  }

  if (ipToBytes(r)) return true;

  /* 长得像 IP 但不是合法 IP（999.1.1.1、1.2.3.4.5、2001:db8::zz）必须直接拒绝，
     绝不能让它们掉进域名分支被当成域名放行 ——
     「把范围写错」而工具静默接受，是这类工具最危险的失败方式。 */
  if (looksLikeIp(r)) return false;

  return /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/i.test(r);
}

/** 粗略判断"这是想写一个 IP"：有冒号，或整体是点分数字 */
function looksLikeIp(s) {
  if (s.includes(':')) return true;
  return /^\d+(\.\d+)*$/.test(s);
}

/**
 * 判断目标是否匹配某条范围规则
 * 支持：精确域名、子域（*.example.com 与 example.com 都覆盖 api.example.com）、
 *       精确 IPv4/IPv6、IPv4/IPv6 CIDR
 */
export function matchesScopeRule(rule, target) {
  const r = String(rule).trim().toLowerCase();
  const t = normalizeTarget(target);

  if (!r || !t) return false;

  /* CIDR（v4 与 v6 都走这里） */
  if (r.includes('/')) {
    return ipInCidr(t, r);
  }

  /* 纯 IP 字面量：按字节比较，容忍不同写法（::1 与 0:0:0:0:0:0:0:1） */
  if (ipToBytes(r)) {
    return ipEquals(r, t);
  }

  /* 通配子域 */
  if (r.startsWith('*.')) {
    const base = r.slice(2);
    return t === base || t.endsWith('.' + base);
  }

  /* 普通域名：精确或其子域 */
  return t === r || t.endsWith('.' + r);
}

/**
 * CIDR 判定，IPv4 与 IPv6 通用
 *
 * 两个地址必须同族 —— 拿 v4 地址去匹配 v6 网段是配置错误，
 * 这里返回 false 而不是"尽力而为"，避免产生看起来通过其实没校验的结果。
 */
export function ipInCidr(ip, cidr) {
  const idx = String(cidr).lastIndexOf('/');
  if (idx === -1) return false;

  const netBytes = ipToBytes(String(cidr).slice(0, idx));
  const ipBytes = ipToBytes(ip);
  if (!netBytes || !ipBytes) return false;
  if (netBytes.length !== ipBytes.length) return false;

  const bitsStr = String(cidr).slice(idx + 1);
  if (!/^\d{1,3}$/.test(bitsStr)) return false;
  const bits = Number(bitsStr);
  if (bits < 0 || bits > ipBytes.length * 8) return false;

  const fullBytes = Math.floor(bits / 8);
  for (let i = 0; i < fullBytes; i++) {
    if (ipBytes[i] !== netBytes[i]) return false;
  }

  const restBits = bits % 8;
  if (restBits > 0) {
    const mask = (0xff << (8 - restBits)) & 0xff;
    if ((ipBytes[fullBytes] & mask) !== (netBytes[fullBytes] & mask)) return false;
  }

  return true;
}

/* ------------------------- IP 解析 ------------------------- */

/** 目标归一化：小写、去尾点、去 IPv6 方括号 */
export function normalizeTarget(value) {
  let t = String(value ?? '').trim().toLowerCase();
  if (t.startsWith('[') && t.endsWith(']')) t = t.slice(1, -1);
  return t.replace(/\.$/, '');
}

/**
 * 把 IP 字面量解析成字节数组；不是合法 IP 时返回 null
 * IPv4 → 4 字节；IPv6 → 16 字节（支持 :: 压缩与末尾内嵌 IPv4）
 */
export function ipToBytes(value) {
  const s = normalizeTarget(value);
  if (!s) return null;
  if (s.includes('%')) return null;            // 带 zone id 的地址不参与范围判定
  if (s.includes(':')) return ipv6ToBytes(s);
  return ipv4ToBytes(s);
}

function ipv4ToBytes(s) {
  const parts = s.split('.');
  if (parts.length !== 4) return null;
  const bytes = [];
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const n = Number(part);
    if (n > 255) return null;
    /* 前导零在 inet_aton 里是八进制，这里直接拒绝，避免 "010.0.0.1" 这类歧义写法 */
    if (part.length > 1 && part.startsWith('0')) return null;
    bytes.push(n);
  }
  return bytes;
}

function ipv6ToBytes(s) {
  let work = s;

  /* 末尾内嵌 IPv4（::ffff:192.0.2.1）先换成两个十六进制组 */
  const embedded = work.match(/^(.*:)(\d{1,3}(?:\.\d{1,3}){3})$/);
  if (embedded) {
    const v4 = ipv4ToBytes(embedded[2]);
    if (!v4) return null;
    const hi = ((v4[0] << 8) | v4[1]).toString(16);
    const lo = ((v4[2] << 8) | v4[3]).toString(16);
    work = `${embedded[1]}${hi}:${lo}`;
  }

  let head;
  let tail;
  if (work.includes('::')) {
    if (work.indexOf('::') !== work.lastIndexOf('::')) return null;   // 只能压缩一次
    const [h, t] = work.split('::');
    head = h ? h.split(':') : [];
    tail = t ? t.split(':') : [];
    /* :: 至少要代表一组 0，所以两侧组数之和不能超过 7 */
    if (head.length + tail.length > 7) return null;
  } else {
    head = work.split(':');
    tail = [];
    if (head.length !== 8) return null;
  }

  const groups = [...head, ...Array(8 - head.length - tail.length).fill('0'), ...tail];
  if (groups.length !== 8) return null;

  const bytes = [];
  for (const g of groups) {
    if (!/^[0-9a-f]{1,4}$/.test(g)) return null;
    const n = parseInt(g, 16);
    bytes.push((n >> 8) & 0xff, n & 0xff);
  }
  return bytes;
}

/** 两个 IP 字面量是否指向同一地址（容忍不同写法，但不跨族） */
export function ipEquals(a, b) {
  const x = ipToBytes(a);
  const y = ipToBytes(b);
  if (!x || !y) return false;
  if (x.length !== y.length) return false;
  return x.every((byte, i) => byte === y[i]);
}

/* 供 CLI 使用：计算任意文件的 sha256 以便填入凭证 */
export { fileSha256 };
export const __dirname = dirname(fileURLToPath(import.meta.url));

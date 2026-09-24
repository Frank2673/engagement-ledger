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

/** 范围规则：域名、*.domain、IP、CIDR */
export function isValidScopeRule(rule) {
  const r = String(rule).trim();
  if (!r) return false;
  if (r.startsWith('*.')) return /^\*\.[a-z0-9.-]+\.[a-z]{2,}$/i.test(r);
  if (/^\d{1,3}(\.\d{1,3}){3}\/\d{1,2}$/.test(r)) {
    const [ip, bits] = r.split('/');
    return Number(bits) <= 32 && ip.split('.').every((o) => Number(o) <= 255);
  }
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(r)) {
    return r.split('.').every((o) => Number(o) <= 255);
  }
  return /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/i.test(r);
}

/**
 * 判断目标是否匹配某条范围规则
 * 支持：精确域名、子域（*.example.com 与 example.com 都覆盖 api.example.com）、
 *       精确 IP、CIDR
 */
export function matchesScopeRule(rule, target) {
  const r = String(rule).trim().toLowerCase();
  const t = String(target).trim().toLowerCase().replace(/\.$/, '');

  if (!r || !t) return false;

  /* CIDR */
  if (r.includes('/')) {
    return ipInCidr(t, r);
  }

  /* 纯 IP：精确匹配 */
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(r)) {
    return r === t;
  }

  /* 通配子域 */
  if (r.startsWith('*.')) {
    const base = r.slice(2);
    return t === base || t.endsWith('.' + base);
  }

  /* 普通域名：精确或其子域 */
  return t === r || t.endsWith('.' + r);
}

/** IPv4 CIDR 判定 */
export function ipInCidr(ip, cidr) {
  const [net, bitsStr] = cidr.split('/');
  const bits = Number(bitsStr);
  if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(ip) || !/^\d{1,3}(\.\d{1,3}){3}$/.test(net)) return false;
  if (bits < 0 || bits > 32) return false;

  const toInt = (s) => s.split('.').reduce((acc, o) => (acc << 8) + Number(o), 0) >>> 0;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;

  return (toInt(ip) & mask) === (toInt(net) & mask);
}

/* 供 CLI 使用：计算任意文件的 sha256 以便填入凭证 */
export { fileSha256 };
export const __dirname = dirname(fileURLToPath(import.meta.url));

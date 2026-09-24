#!/usr/bin/env node
/**
 * 客户侧复核：拿报告 + 授权书原件，验证两者是否对应
 *
 * 为什么需要这个脚本：报告里写着 SHA-256，客户"应该"自己算一遍再比对 ——
 * 但让人肉眼比对 64 位十六进制，成功率约等于零。于是要么不算，要么抄错，
 * 复核环节就变成了走过场。
 *
 * 这个脚本把复核变成两条命令：一条比对，一条给出结论与退出码。
 * 客户不需要理解哈希，只需要知道退出码是不是 0。
 *
 * 用法：
 *   node scripts/verify-report.mjs <报告文件> <授权书原件> [--json]
 *
 * 退出码：0 一致 / 3 不一致 / 1 用法或读取错误
 */

import { readFileSync, existsSync, statSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { resolve } from 'node:path';

/** 从 Markdown 报告里抽出登记哈希与委托信息 */
export function parseReportHash(text) {
  const content = String(text ?? '');

  /* 标题行之后最近的代码块内容 —— 报告第 1 章的指纹就写在那里 */
  const marker = content.indexOf('授权文件完整性指纹');
  if (marker !== -1) {
    const after = content.slice(marker);
    const fence = after.match(/```\s*\n([0-9a-f]{64})\s*\n```/i);
    if (fence) {
      return {
        hash: fence[1].toLowerCase(),
        engagementId: pick(content, /委托编号\s*\|\s*`?([^`|\n]+?)`?\s*\|/),
        reference: pick(content, /授权文件\s*\|\s*([^|\n]+?)\s*\|/),
        source: 'markdown',
      };
    }
  }

  /* 兜底：报告里任何一处独立的 64 位十六进制（要求首尾有明确边界，避免误取链头哈希） */
  const numbered = content.match(/登记\s*([0-9a-f]{64})/i);
  if (numbered) return { hash: numbered[1].toLowerCase(), engagementId: null, reference: null, source: 'markdown-loose' };

  return null;
}

/** 从 JSON 报告里抽 */
export function parseJsonReportHash(text) {
  try {
    const json = JSON.parse(text);
    const hash = json?.engagement?.authorization?.documentSha256;
    if (typeof hash === 'string' && /^[0-9a-f]{64}$/i.test(hash)) {
      return {
        hash: hash.toLowerCase(),
        engagementId: json.engagement.id ?? null,
        reference: json.engagement.authorization.reference ?? null,
        source: 'json',
      };
    }
  } catch {
    /* 不是 JSON，交给 Markdown 解析 */
  }
  return null;
}

function pick(text, re) {
  const m = text.match(re);
  return m ? m[1].trim() : null;
}

/** 计算文件 SHA-256 */
export function hashFile(path) {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

/** 核心比对逻辑（纯函数便于测试） */
export function compareReportToDocument(reportText, documentHash) {
  const registered = parseJsonReportHash(reportText) || parseReportHash(reportText);

  if (!registered) {
    return { ok: false, status: 'no-hash-in-report', registered: null, actual: documentHash };
  }

  const actual = String(documentHash).toLowerCase();
  return {
    ok: actual === registered.hash,
    status: actual === registered.hash ? 'match' : 'mismatch',
    registered: registered.hash,
    actual,
    engagementId: registered.engagementId,
    reference: registered.reference,
    source: registered.source,
  };
}

/* ------------------------------- CLI ------------------------------- */

function main(args) {
  const positional = args.filter((a) => !a.startsWith('--'));
  const asJson = args.includes('--json');

  if (positional.length !== 2) {
    process.stderr.write(
      '用法：node scripts/verify-report.mjs <报告文件> <授权书原件> [--json]\n\n' +
        '作用：核对报告里登记的 SHA-256 与手上的授权书原件是否一致。\n' +
        '      退出码 0 = 一致；3 = 不一致；1 = 用法或读取错误。\n'
    );
    return 1;
  }

  const [reportArg, docArg] = positional;
  const reportPath = resolve(reportArg);
  const docPath = resolve(docArg);

  for (const [label, p] of [['报告文件', reportPath], ['授权书原件', docPath]]) {
    if (!existsSync(p)) {
      process.stderr.write(`✗ ${label}不存在：${p}\n`);
      return 1;
    }
    if (statSync(p).isDirectory()) {
      process.stderr.write(`✗ ${label}是一个目录：${p}\n`);
      return 1;
    }
  }

  const reportText = readFileSync(reportPath, 'utf8');
  const actual = hashFile(docPath);
  const result = compareReportToDocument(reportText, actual);

  if (asJson) {
    process.stdout.write(JSON.stringify({ report: reportPath, document: docPath, ...result }, null, 2) + '\n');
    return result.ok ? 0 : 3;
  }

  const w = (s = '') => process.stdout.write(s + '\n');

  if (result.status === 'no-hash-in-report') {
    w('❌ 报告里找不到登记的授权书哈希');
    w();
    w('   可能原因：凭证没填 authorization.documentSha256，或这份报告不是本工具生成的。');
    w(`   本文件的 SHA-256 是：${actual}`);
    w();
    w('   没有登记哈希的报告无法复核"授权书是否被换过" —— 请向交付方索取完整报告。');
    return 3;
  }

  w(result.ok ? '✅ 一致：报告所依据的授权书，就是你手上这一份' : '❌ 不一致：报告所依据的授权书，不是你手上这一份');
  w();
  if (result.engagementId) w(`  委托编号　：${result.engagementId}`);
  if (result.reference) w(`  授权文件　：${result.reference}`);
  w(`  报告登记值：${result.registered}`);
  w(`  你手上这份：${result.actual}`);
  w();

  if (result.ok) {
    w('结论：这份报告所引用的授权书与你的原件逐字节相同，授权范围描述可信。');
    w('      注意：这只证明"文件相同"，不证明授权书本身有效 —— 那由你方判断。');
  } else {
    w('**请先不要采信这份报告。** 依次排查：');
    w('  1. 你手上的是否为最终签署版？（常见于中途版本被拿去用）');
    w('  2. 文件是否被重新扫描、另存、补签名或加水印 —— 任何重新生成都会改变哈希');
    w('  3. 是否用错了文件（例如同名草稿）');
    w('  4. 以上都排除后，向交付方索要其归档副本，直接比对两份文件');
    w();
    w('  运行 diff 比对内容只能看差异，无法证明"是不是同一份"——哈希才是判据。');
  }

  return result.ok ? 0 : 3;
}

if (process.argv[1] && /verify-report\.mjs$/.test(process.argv[1])) {
  process.exitCode = main(process.argv.slice(2));
}

export { main as runVerifyReportCli };

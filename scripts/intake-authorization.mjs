#!/usr/bin/env node
/**
 * 授权书接收与登记
 *
 * 这个脚本只做一件事：把"授权书原件 → 归档副本 → SHA-256 → 凭证片段"这条链
 * 变成一条命令，从而消掉两个真实的失败模式：
 *   1. 手抄哈希抄错（64 位十六进制，肉眼校对必错）
 *   2. 登记之后再动过原件（重新扫描、阅读器另存、补签名）
 *
 * 它**不判断**授权书是否有效 —— 真实性与授权效力只有授权方能确认。
 * 详细流程见 docs/authorization-intake.md。
 *
 * 逻辑导出为 intakeAuthorization()，CLI 只是一层包装：
 * 这样它既能被人用命令行跑，也能被 tests/ 与 scripts/verify.mjs 直接调用。
 *
 * 用法：
 *   node scripts/intake-authorization.mjs <源文件> [选项]
 *
 * 选项：
 *   --dir <目录>    归档目录（默认 authorization/）
 *   --as <文件名>   归档副本的文件名（默认沿用源文件名）
 *   --json          输出机器可读结果
 *   --dry-run       只计算哈希与给出建议，不复制文件
 */

import { copyFileSync, existsSync, mkdirSync, statSync, readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { resolve, basename, extname, relative } from 'node:path';

const HELP = `授权书接收与登记

用法：
  node scripts/intake-authorization.mjs <源文件> [--dir authorization] [--as 名称.pdf] [--dry-run] [--json]

作用：
  把源文件复制成一份不可再生的"归档副本"，算出它的 SHA-256，
  并直接给出可以粘进凭证的字段 —— 避免手抄 64 位哈希出错。

  它会拒绝覆盖已存在的归档副本：覆盖会作废已经登记进凭证的哈希。
`;

/**
 * 按扩展名给针对性建议：不同载体的"不可再生"要求不一样
 */
export const ADVICE = {
  '.pdf': [
    'PDF 可以被"另存为"再生成。归档副本固定后，不要用阅读器另存、不要补签名、不要加水印。',
    '若原 PDF 是扫描件，每次重新扫描都会得到不同的哈希 —— 只能以这一次的归档副本为准。',
  ],
  '.eml': ['保留 .eml 的好处是完整头部（发件人、时间、Message-ID）都在文件里，可作为授权来源的凭据。'],
  '.msg': ['.msg 是 Outlook 私有格式；建议同时导出一份 .eml 或 PDF 作为长期归档，避免依赖特定客户端打开。'],
  '.png': ['图片型授权书建议连同原始邮件或签署记录一起归档 —— 图片本身无法自证来源。'],
  '.jpg': ['图片型授权书建议连同原始邮件或签署记录一起归档 —— 图片本身无法自证来源。'],
  '.jpeg': ['图片型授权书建议连同原始邮件或签署记录一起归档 —— 图片本身无法自证来源。'],
  '.docx': [
    '⚠️ 可编辑文档不适合直接登记：任何一次"另存为"都会改变哈希。',
    '建议先定稿并转为 PDF（有条件时用 PDF/A），再对 PDF 做归档与登记。',
  ],
  '.txt': ['纯文本授权很少见；若来自邮件正文，请同时保留 .eml 以固定头部信息。'],
};

/**
 * 归档一份授权书并算出登记信息
 *
 * @param {object} input
 * @param {string} input.source 源文件路径
 * @param {string} [input.dir] 归档目录（默认 authorization）
 * @param {string|null} [input.as] 归档副本文件名（默认沿用源文件名）
 * @param {boolean} [input.dryRun] 只算哈希不复制
 * @param {string} [input.cwd] 相对路径的基准目录
 * @returns {{ok: boolean, error?: string, source?: string, archive?: string, relativePath?: string, bytes?: number, sha256?: string, advice?: string[]}}
 */
export function intakeAuthorization({ source, dir = 'authorization', as = null, dryRun = false, cwd = process.cwd() }) {
  if (!source) {
    return { ok: false, error: '缺少源文件路径' };
  }

  const sourcePath = resolve(cwd, source);
  if (!existsSync(sourcePath)) {
    return { ok: false, error: `源文件不存在：${sourcePath}` };
  }
  if (statSync(sourcePath).isDirectory()) {
    return { ok: false, error: `源文件是一个目录：${sourcePath}` };
  }

  const ext = extname(sourcePath).toLowerCase();
  const archivePath = resolve(cwd, dir, as || basename(sourcePath));

  /* 归档副本必须是一份新文件：覆盖会把已登记的哈希作废 */
  if (!dryRun && existsSync(archivePath)) {
    return {
      ok: false,
      error:
        `归档副本已存在，拒绝覆盖：${archivePath}\n\n` +
        `  覆盖会作废已经登记进凭证的哈希。如果这是同一份授权书，请直接使用现有副本；\n` +
        `  如果授权书确实更新了，请换一个文件名（例如加日期后缀）并走变更流程 ——\n` +
        `  见 docs/authorization-intake.md「授权书变更」一节。`,
    };
  }

  if (!dryRun) {
    mkdirSync(resolve(cwd, dir), { recursive: true });
    copyFileSync(sourcePath, archivePath);
  }

  const bytes = readFileSync(dryRun ? sourcePath : archivePath);
  const sha256 = createHash('sha256').update(bytes).digest('hex');
  const relativePath = relative(cwd, archivePath).split('\\').join('/');

  return {
    ok: true,
    source: sourcePath,
    archive: archivePath,
    relativePath,
    bytes: bytes.length,
    sha256,
    advice: ADVICE[ext] || [`未识别的文件类型 ${ext || '(无扩展名)'}：请确认它是一份不再变动的最终版本。`],
  };
}

/* ------------------------------- CLI ------------------------------- */

function main(args) {
  if (args.length === 0 || args.includes('--help') || args.includes('-h')) {
    process.stdout.write(HELP);
    return args.length === 0 ? 1 : 0;
  }

  const source = args.find((a) => !a.startsWith('--'));
  const value = (name, fallback) => {
    const i = args.indexOf(name);
    if (i === -1) return fallback;
    const v = args[i + 1];
    return v && !v.startsWith('--') ? v : fallback;
  };

  const dryRun = args.includes('--dry-run');
  const asJson = args.includes('--json');

  const result = intakeAuthorization({
    source,
    dir: value('--dir', 'authorization'),
    as: value('--as', null),
    dryRun,
  });

  if (!result.ok) {
    process.stderr.write(`✗ ${result.error}\n`);
    return 1;
  }

  if (asJson) {
    process.stdout.write(
      JSON.stringify(
        {
          source: result.source,
          archive: result.archive,
          relativePath: result.relativePath,
          dryRun,
          bytes: result.bytes,
          sha256: result.sha256,
          document: result.relativePath,
          documentSha256: result.sha256,
        },
        null,
        2
      ) + '\n'
    );
    return 0;
  }

  const out = [];
  const w = (s = '') => out.push(s);

  w(`${dryRun ? '（试运行，未复制文件）' : '✅ 已归档授权书'}`);
  w();
  w(`  源文件　：${result.source}`);
  w(`  归档副本：${result.archive}`);
  w(`  大小　　：${result.bytes.toLocaleString('en-US')} 字节`);
  w(`  SHA-256 ：${result.sha256}`);
  w();
  w(`把下面两行填进凭证的 engagement.authorization：`);
  w();
  w(`    "document": "${result.relativePath}",`);
  w(`    "documentSha256": "${result.sha256}"`);
  w();
  w(`  路径按「相对凭证文件所在目录」解析 —— 凭证与 authorization/ 同级时，`);
  w(`  上面这行可直接用；不同层级请自行调整。`);
  w();
  w(`登记后立刻核验：`);
  w();
  w(`    node src/index.mjs init --manifest engagement.json --ledger ledger.jsonl`);
  w(`    → 期望看到「✅ 授权文件核验通过」；`);
  w(`      看到「授权文件核验未通过」说明填错了哈希或文件被换过，不要继续。`);
  w();
  w(`⚠️ 从现在起，这一份归档副本就是"被登记的那一份"：`);
  w(`   不要重新扫描、不要用阅读器另存、不要补签名或加水印 —— 任何重新生成`);
  w(`   都会改变哈希，让凭证对不上。请把它存到可靠位置（加密存储 / 受控目录）并备份。`);
  w();
  for (const line of result.advice) w(`· ${line}`);
  w();
  w(`提醒：本工具只固定"这份文件此后没被改过"，不判断授权书本身的真实性与`);
  w(`效力 —— 那只有授权方能确认。详见 docs/authorization-intake.md。`);

  process.stdout.write(out.join('\n') + '\n');
  return 0;
}

if (process.argv[1] && /intake-authorization\.mjs$/.test(process.argv[1])) {
  process.exitCode = main(process.argv.slice(2));
}

export { main as runIntakeCli };

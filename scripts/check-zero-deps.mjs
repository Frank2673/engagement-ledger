#!/usr/bin/env node
/**
 * 零依赖与安全红线自检
 *
 * "零依赖"对本项目不只是洁癖：一个决定"这次动作能不能做"的工具，
 * 如果自身带着几十个传递依赖，就等于把授权判定交给了供应链。
 * 因此由 CI 强制校验，而不是只在 README 里写一句。
 *
 * 校验逻辑导出为纯函数 runChecks(root)，好处有两个：
 *   1. 可在任意目录上运行（负向验证时指向一份临时副本，不动真实仓库）
 *   2. 本地校验脚本与 CI 共用同一份代码 ——
 *      写在 YAML 里的 bash 片段本地跑不了，出了错只能靠推上去等 CI 告诉你
 *
 * 用法：node scripts/check-zero-deps.mjs [仓库根目录]
 */

import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import { join, resolve, dirname, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

export const DEFAULT_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

const SCAN_DIRS = ['src', 'tests', 'scripts'];
const IMPORT_RE = /(?:^|\n)\s*(?:import|export)[^\n]*?from\s+['"]([^'"]+)['"]/g;

/** 红线：这些动作不允许从硬性禁止清单里消失 */
export const REQUIRED_FORBIDDEN = ['dos', 'ddos', 'destructive', 'ransomware', 'data-exfiltration'];

/**
 * 在指定目录上执行全部校验
 * @param {string} root 仓库根目录
 * @returns {{problems: string[], fileCount: number}}
 */
export function runChecks(root = DEFAULT_ROOT) {
  const problems = [];

  const pkgPath = join(root, 'package.json');
  if (!existsSync(pkgPath)) {
    return { problems: [`找不到 package.json：${pkgPath}`], fileCount: 0 };
  }

  const pkg = JSON.parse(readFileSync(pkgPath, 'utf8'));
  for (const field of ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']) {
    const names = Object.keys(pkg[field] || {});
    if (names.length) problems.push(`package.json 的 ${field} 存在依赖：${names.join(', ')}`);
  }

  function walk(dir) {
    const abs = join(root, dir);
    if (!existsSync(abs)) return [];
    const out = [];
    for (const entry of readdirSync(abs)) {
      const full = join(abs, entry);
      if (statSync(full).isDirectory()) out.push(...walk(join(dir, entry)));
      else if (/\.(mjs|js)$/.test(entry)) out.push(full);
    }
    return out;
  }

  let fileCount = 0;
  for (const dir of SCAN_DIRS) {
    for (const file of walk(dir)) {
      fileCount++;
      const source = readFileSync(file, 'utf8');
      let match;
      IMPORT_RE.lastIndex = 0;
      while ((match = IMPORT_RE.exec(source)) !== null) {
        const spec = match[1];
        if (!spec.startsWith('.') && !spec.startsWith('/') && !spec.startsWith('node:')) {
          problems.push(`${relative(root, file)} 引用了非内置模块：${spec}`);
        }
      }
    }
  }

  if (existsSync(join(root, 'node_modules'))) {
    problems.push('存在 node_modules 目录 —— 零依赖项目不应有它');
  }

  /* ---- 项目专属红线：判定权与密钥不允许被设计成可绕过的东西 ---- */

  const cryptoPath = join(root, 'src', 'lib', 'crypto.mjs');
  if (existsSync(cryptoPath) && /\bMath\.random\b/.test(readFileSync(cryptoPath, 'utf8'))) {
    problems.push('src/lib/crypto.mjs 使用了 Math.random() —— 审计相关的随机性必须来自 node:crypto');
  }

  const manifestPath = join(root, 'src', 'lib', 'manifest.mjs');
  const manifestSource = existsSync(manifestPath) ? readFileSync(manifestPath, 'utf8') : null;
  const forbiddenBlock = manifestSource && manifestSource.match(/NEVER_PERMITTED_ACTIONS\s*=\s*\[([\s\S]*?)\]/);
  if (!forbiddenBlock) {
    problems.push('找不到 NEVER_PERMITTED_ACTIONS 清单 —— 硬性禁止项是这个工具的安全底线，不允许被删掉');
  } else {
    const missing = REQUIRED_FORBIDDEN.filter((a) => !forbiddenBlock[1].includes(`'${a}'`));
    if (missing.length) problems.push(`硬性禁止清单被削弱，缺少：${missing.join(', ')}`);
  }

  const cliPath = join(root, 'src', 'index.mjs');
  /* HMAC 密钥只能从环境变量读；接受命令行参数会把密钥暴露在进程列表里 */
  if (existsSync(cliPath) && /options\['hmac-key'\]/.test(readFileSync(cliPath, 'utf8'))) {
    problems.push("src/index.mjs 接受裸 --hmac-key 命令行参数 —— 命令行参数在进程列表里可见，密钥必须走环境变量");
  }

  return { problems, fileCount };
}

/* 直接运行时作为 CLI 使用 */
if (process.argv[1] && /check-zero-deps\.mjs$/.test(process.argv[1])) {
  const root = process.argv[2] ? resolve(process.argv[2]) : DEFAULT_ROOT;
  const { problems, fileCount } = runChecks(root);

  console.log(`扫描 ${fileCount} 个源文件（${root}）`);
  if (problems.length === 0) {
    console.log('✅ 零依赖与安全红线校验通过');
    process.exit(0);
  }

  console.error('❌ 校验失败：');
  for (const p of problems) console.error(`   - ${p}`);
  process.exit(1);
}

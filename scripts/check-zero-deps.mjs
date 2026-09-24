#!/usr/bin/env node
/**
 * 零依赖自检
 *
 * "零依赖"对本项目不只是洁癖：一个决定"这次动作能不能做"的工具，
 * 如果自身带着几十个传递依赖，就等于把授权判定交给了供应链。
 * 因此由 CI 强制校验，而不是只在 README 里写一句。
 */

import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import { join, resolve, dirname, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const SCAN_DIRS = ['src', 'tests', 'scripts'];
const problems = [];

const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'));
for (const field of ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']) {
  const names = Object.keys(pkg[field] || {});
  if (names.length) problems.push(`package.json 的 ${field} 存在依赖：${names.join(', ')}`);
}

function walk(dir) {
  const abs = join(ROOT, dir);
  if (!existsSync(abs)) return [];
  const out = [];
  for (const entry of readdirSync(abs)) {
    const full = join(abs, entry);
    if (statSync(full).isDirectory()) out.push(...walk(join(dir, entry)));
    else if (/\.(mjs|js)$/.test(entry)) out.push(full);
  }
  return out;
}

const IMPORT_RE = /(?:^|\n)\s*(?:import|export)[^\n]*?from\s+['"]([^'"]+)['"]/g;
let fileCount = 0;

for (const dir of SCAN_DIRS) {
  for (const file of walk(dir)) {
    fileCount++;
    const source = readFileSync(file, 'utf8');
    let match;
    while ((match = IMPORT_RE.exec(source)) !== null) {
      const spec = match[1];
      if (!spec.startsWith('.') && !spec.startsWith('/') && !spec.startsWith('node:')) {
        problems.push(`${relative(ROOT, file)} 引用了非内置模块：${spec}`);
      }
    }
  }
}

if (existsSync(join(ROOT, 'node_modules'))) {
  problems.push('存在 node_modules 目录 —— 零依赖项目不应有它');
}

/* ---- 项目专属红线：不能把"判定权"或"密钥"设计成可绕过的东西 ---- */

const CRYPTO = join(ROOT, 'src', 'lib', 'crypto.mjs');
const cryptoSource = readFileSync(CRYPTO, 'utf8');
if (/\bMath\.random\b/.test(cryptoSource)) {
  problems.push('src/lib/crypto.mjs 使用了 Math.random() —— 审计相关的随机性必须来自 node:crypto');
}

const MANIFEST = join(ROOT, 'src', 'lib', 'manifest.mjs');
const manifestSource = readFileSync(MANIFEST, 'utf8');
const forbiddenBlock = manifestSource.match(/NEVER_PERMITTED_ACTIONS\s*=\s*\[([\s\S]*?)\]/);
if (!forbiddenBlock) {
  problems.push('找不到 NEVER_PERMITTED_ACTIONS 清单 —— 硬性禁止项是这个工具的安全底线，不允许被删掉');
} else {
  const required = ['dos', 'ddos', 'destructive', 'ransomware', 'data-exfiltration'];
  const listed = forbiddenBlock[1];
  const missing = required.filter((a) => !listed.includes(`'${a}'`));
  if (missing.length) {
    problems.push(`硬性禁止清单被削弱，缺少：${missing.join(', ')}`);
  }
}

const CLI = join(ROOT, 'src', 'index.mjs');
const cliSource = readFileSync(CLI, 'utf8');
/* HMAC 密钥只能从环境变量读；接受命令行参数会把密钥暴露在进程列表里 */
if (/options\['hmac-key'\]/.test(cliSource)) {
  problems.push("src/index.mjs 接受裸 --hmac-key 命令行参数 —— 命令行参数在进程列表里可见，密钥必须走环境变量");
}

console.log(`扫描 ${fileCount} 个源文件`);
if (problems.length === 0) {
  console.log('✅ 零依赖与安全红线校验通过');
  process.exit(0);
}

console.error('❌ 校验失败：');
for (const p of problems) console.error(`   - ${p}`);
process.exit(1);

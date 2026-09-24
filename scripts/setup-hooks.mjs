#!/usr/bin/env node
/**
 * 启用仓库内的 git hooks
 *
 * 把 core.hooksPath 指向 .githooks —— 这样 hooks 随仓库分发、可被评审，
 * 而不是停在每个人本地的 .git/hooks 里（那部分不进版本控制，等于没有）。
 */

import { execFileSync } from 'node:child_process';
import { chmodSync, existsSync, readdirSync } from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const HOOKS_DIR = join(ROOT, '.githooks');

if (!existsSync(join(ROOT, '.git'))) {
  console.error('✗ 当前目录不是 git 仓库，先运行 git init');
  process.exit(1);
}

if (!existsSync(HOOKS_DIR)) {
  console.error(`✗ 找不到 hooks 目录：${HOOKS_DIR}`);
  process.exit(1);
}

/* 可执行位在 Windows 上无意义，但在 Linux/macOS 与 CI 上是必需的 */
for (const name of readdirSync(HOOKS_DIR)) {
  try {
    chmodSync(join(HOOKS_DIR, name), 0o755);
  } catch {
    /* Windows 上 chmod 是空操作，忽略 */
  }
}

execFileSync('git', ['config', 'core.hooksPath', '.githooks'], { cwd: ROOT, stdio: 'inherit' });

console.log('✅ 已启用仓库内 git hooks（core.hooksPath = .githooks）');
console.log('   commit-msg：强制 Conventional Commits 提交信息规范');
console.log('   跳过校验：git commit --no-verify');

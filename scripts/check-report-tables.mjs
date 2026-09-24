#!/usr/bin/env node
/**
 * 报告表格结构校验
 *
 * 报告里的目标名、拒绝原因都来自外部输入。如果它们含竖线且未被转义，
 * Markdown 表格会被撑破 —— 表面上是排版问题，实际是报告不可信：
 * 一个被撑破的表格，读的人无法确定哪一格对应哪一列，也就无法据以追责。
 *
 * 这个脚本按 Markdown 规则正确解析转义竖线（\| 不算分隔符），
 * 逐个表格检查每行的单元格数是否与表头一致。
 *
 * 用法：node scripts/check-report-tables.mjs <报告文件> [更多文件…]
 */

import { readFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';

/** 按 Markdown 规则把一行切成单元格（\| 是转义，不是分隔符） */
export function splitRow(row) {
  let line = row.trim();
  if (line.startsWith('|')) line = line.slice(1);
  if (line.endsWith('|') && !line.endsWith('\\|')) line = line.slice(0, -1);

  const cells = [];
  let current = '';
  for (let i = 0; i < line.length; i++) {
    if (line[i] === '\\' && line[i + 1] === '|') {
      current += '|';
      i += 1;
      continue;
    }
    if (line[i] === '|') {
      cells.push(current.trim());
      current = '';
      continue;
    }
    current += line[i];
  }
  cells.push(current.trim());
  return cells;
}

function isSeparatorRow(row) {
  return /^\|[\s:|-]+\|$/.test(row.trim());
}

/**
 * 校验一份 Markdown 里的全部表格
 * @returns {Array<{startLine:number, expected:number, actual:number, row:string}>}
 */
export function checkTables(markdown) {
  const lines = markdown.split(/\r?\n/);
  const problems = [];

  let i = 0;
  while (i < lines.length) {
    const line = lines[i];
    const isTableRow = line.trim().startsWith('|') && line.trim().endsWith('|');
    const nextIsSeparator = i + 1 < lines.length && isSeparatorRow(lines[i + 1]);

    if (isTableRow && nextIsSeparator) {
      const headerCells = splitRow(line).length;
      let j = i + 2;
      while (j < lines.length && lines[j].trim().startsWith('|') && lines[j].trim().endsWith('|')) {
        const actual = splitRow(lines[j]).length;
        if (actual !== headerCells) {
          problems.push({ startLine: i + 1, expected: headerCells, actual, row: lines[j] });
        }
        j += 1;
      }
      i = j;
      continue;
    }
    i += 1;
  }

  return problems;
}

/* 直接运行时作为 CLI 使用 */
if (process.argv[1] && /check-report-tables\.mjs$/.test(process.argv[1])) {
  const files = process.argv.slice(2).map((f) => resolve(f));

  if (files.length === 0) {
    console.error('用法：node scripts/check-report-tables.mjs <报告文件> [更多文件…]');
    process.exit(1);
  }

  let failures = 0;
  for (const file of files) {
    if (!existsSync(file)) {
      console.error(`✗ 文件不存在：${file}`);
      failures += 1;
      continue;
    }
    const problems = checkTables(readFileSync(file, 'utf8'));
    if (problems.length === 0) {
      console.log(`✅ ${file}：表格结构一致`);
    } else {
      failures += 1;
      console.error(`❌ ${file}：发现 ${problems.length} 处表格结构异常`);
      for (const p of problems) {
        console.error(`   第 ${p.startLine} 行起的表格：表头 ${p.expected} 列，该行 ${p.actual} 列`);
        console.error(`   ${p.row.slice(0, 120)}`);
      }
    }
  }

  process.exit(failures === 0 ? 0 : 1);
}

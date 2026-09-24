/**
 * 单元测试：报告表格结构校验脚本
 *
 * 这个脚本本身是个"守卫"，守卫失效比没有守卫更危险（会给人虚假的通过感），
 * 所以它自己也要被负向验证：能发现问题，且不误报正常表格。
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { splitRow, checkTables } from '../scripts/check-report-tables.mjs';

test('splitRow 按 Markdown 规则切分普通行', () => {
  assert.deepEqual(splitRow('| a | b | c |'), ['a', 'b', 'c']);
});

test('splitRow 把 \\| 当作内容而不是分隔符', () => {
  assert.deepEqual(splitRow('| a\\|b | c |'), ['a|b', 'c']);
});

test('splitRow 处理行尾缺失的竖线', () => {
  assert.deepEqual(splitRow('| a | b'), ['a', 'b']);
});

test('splitRow 保留空单元格', () => {
  assert.deepEqual(splitRow('| a |  | c |'), ['a', '', 'c']);
});

test('正常表格不报问题', () => {
  const md = [
    '| 项目 | 内容 |',
    '| --- | --- |',
    '| 编号 | ENG-001 |',
    '| 名称 | 示例 |',
  ].join('\n');
  assert.deepEqual(checkTables(md), []);
});

test('列数不对齐的表格被发现', () => {
  const md = [
    '| a | b |',
    '| --- | --- |',
    '| 1 | 2 | 3 |',
  ].join('\n');

  const problems = checkTables(md);
  assert.equal(problems.length, 1);
  assert.equal(problems[0].expected, 2);
  assert.equal(problems[0].actual, 3);
  assert.equal(problems[0].startLine, 1);
});

test('未转义的竖线会被识别为错位（正是我们要拦的情形）', () => {
  /* 目标名 evil.com|injected 未转义 → 该行多出一列 */
  const md = [
    '| # | 目标 | 原因 |',
    '| --- | --- | --- |',
    '| 1 | `evil.com|injected` | 越界 |',
  ].join('\n');

  const problems = checkTables(md);
  assert.equal(problems.length, 1);
  assert.equal(problems[0].actual, 4);
});

test('转义之后的同一个表格不再报问题', () => {
  const md = [
    '| # | 目标 | 原因 |',
    '| --- | --- | --- |',
    '| 1 | `evil.com\\|injected` | 越界 |',
  ].join('\n');
  assert.deepEqual(checkTables(md), []);
});

test('多个表格分别校验，行号准确', () => {
  const md = [
    '| a | b |',
    '| --- | --- |',
    '| 1 | 2 |',
    '',
    '正文段落',
    '',
    '| x | y |',
    '| --- | --- |',
    '| 1 | 2 | 3 |',
  ].join('\n');

  const problems = checkTables(md);
  assert.equal(problems.length, 1);
  assert.equal(problems[0].startLine, 7);
});

test('没有表格时返回空（不误报）', () => {
  assert.deepEqual(checkTables('# 标题\n\n段落文字。\n'), []);
});

test('表格外的普通竖线不触发（要求同时存在分隔行）', () => {
  const md = '| 这不是表格\n| 只是普通文本\n';
  assert.deepEqual(checkTables(md), []);
});

test('中文表头与内容正常', () => {
  const md = [
    '| 指标 | 数值 |',
    '| --- | --- |',
    '| 日志总条数 | 5 |',
    '| 判定为拒绝 | 2 |',
  ].join('\n');
  assert.deepEqual(checkTables(md), []);
});

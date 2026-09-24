/**
 * 单元测试：外部锚定的写入与校验
 *
 * 这是**唯一能发现"整链被重写"的检查**，所以测试必须是攻击导向的：
 * 造一条自洽的假链（verify 会通过），再看锚定能不能抓住它。
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  makeEntry,
  sealEntry,
  parseAnchors,
  checkAnchors,
  formatAnchorLine,
  verifyLedger,
  ANCHOR_LABEL,
} from '../src/lib/ledger.mjs';
import { GENESIS_HASH, computeEntryHash } from '../src/lib/crypto.mjs';

/** 造一条长度为 n 的合法链 */
function chain(n) {
  const entries = [];
  let prev = GENESIS_HASH;
  for (let i = 0; i < n; i++) {
    const sealed = sealEntry(
      makeEntry({ seq: i, type: i === 0 ? 'genesis' : 'action', actor: 'alice', action: 'scan', target: `t${i}.example.com` }),
      prev
    );
    entries.push(sealed);
    prev = sealed.hash;
  }
  return entries;
}

/** 攻击：把整条链从头重算一遍（知道算法的人能做到） */
function rewriteChain(entries) {
  let prev = GENESIS_HASH;
  for (const entry of entries) {
    entry.prevHash = prev;
    entry.hash = computeEntryHash(entry, prev);
    prev = entry.hash;
  }
  return entries;
}

/* ------------------------- 锚定行格式 ------------------------- */

test('formatAnchorLine 产出固定格式', () => {
  assert.equal(formatAnchorLine(4, 'a'.repeat(64)), `${ANCHOR_LABEL} 4 ${'a'.repeat(64)}`);
});

/* ------------------------- 解析 ------------------------- */

test('parseAnchors 解析正常行并记录行号', () => {
  const text = [
    '# 锚定记录',
    '',
    `${ANCHOR_LABEL} 4 ${'a'.repeat(64)}`,
    `  ${ANCHOR_LABEL} 9 ${'b'.repeat(64)}  `,
  ].join('\n');

  const { anchors, malformed } = parseAnchors(text);
  assert.equal(anchors.length, 2);
  assert.deepEqual(anchors.map((a) => a.entryCount), [4, 9]);
  assert.equal(anchors[0].line, 3, '应记录原始行号，便于定位');
  assert.deepEqual(malformed, []);
});

test('parseAnchors 忽略注释、空行与无关说明文字', () => {
  const text = `# 这是给人看的文件\n说明：每行一条锚定记录\n\n正文段落\n${ANCHOR_LABEL} 1 ${'c'.repeat(64)}\n`;
  const { anchors, malformed } = parseAnchors(text);

  assert.equal(anchors.length, 1, '只有带标签且格式正确的行才算锚定');
  assert.deepEqual(malformed, [], '无关文字不该被当成格式错误');
});

test('parseAnchors 把带标签但格式不对的行报为 malformed（不静默忽略）', () => {
  const { anchors, malformed } = parseAnchors(`${ANCHOR_LABEL} 4 notahash\n${ANCHOR_LABEL} abc ${'d'.repeat(64)}\n`);

  assert.equal(anchors.length, 0);
  assert.equal(malformed.length, 2);
  assert.deepEqual(malformed.map((m) => m.line), [1, 2]);
});

test('parseAnchors 大小写不敏感，哈希统一小写', () => {
  const { anchors } = parseAnchors(`${ANCHOR_LABEL} 2 ${'A'.repeat(64)}`);
  assert.equal(anchors[0].headHash, 'a'.repeat(64));
});

test('parseAnchors 对空输入不抛异常', () => {
  assert.deepEqual(parseAnchors('').anchors, []);
  assert.deepEqual(parseAnchors(null).anchors, []);
  assert.deepEqual(parseAnchors(undefined).anchors, []);
});

/* ------------------------- 校验：正常 ------------------------- */

test('锚定点与当前链头一致时通过，并标记 latestCleared', () => {
  const entries = chain(4);
  const anchors = [{ entryCount: 4, headHash: entries[3].hash, line: 1 }];

  const r = checkAnchors(entries, anchors);
  assert.equal(r.ok, true);
  assert.equal(r.checked, 1);
  assert.equal(r.latestCleared, true, '最新锚定与当前链头一致');
  assert.equal(r.results[0].status, 'match');
  assert.equal(r.currentCount, 4);
});

test('历史锚定点全部匹配、但之后有新记录时通过（latestCleared=false）', () => {
  const entries = chain(6);
  /* 在第 4 条时锚定过 */
  const anchors = [{ entryCount: 4, headHash: entries[3].hash, line: 1 }];

  const r = checkAnchors(entries, anchors);
  assert.equal(r.ok, true);
  assert.equal(r.results[0].status, 'match', '前 4 条没被动过');
  assert.equal(r.latestCleared, false, '当前有 6 条，还没锚定到最新状态');
  assert.equal(r.currentCount, 6);
});

test('多个锚定点逐条比对（历史 + 最新）', () => {
  const entries = chain(6);
  const anchors = [
    { entryCount: 2, headHash: entries[1].hash, line: 1 },
    { entryCount: 4, headHash: entries[3].hash, line: 2 },
    { entryCount: 6, headHash: entries[5].hash, line: 3 },
  ];

  const r = checkAnchors(entries, anchors);
  assert.equal(r.ok, true);
  assert.equal(r.checked, 3);
  assert.equal(r.latestCleared, true);
});

/* ------------------------- 校验：攻击 ------------------------- */

test('**整链重写会被锚定抓住** —— 而 verify 单看日志会通过（核心能力）', () => {
  const entries = chain(4);
  const anchor = { entryCount: 4, headHash: entries[3].hash, line: 1 };

  /* 攻击者掩改第 1 条，然后把整条链重算一遍 */
  entries[1].target = 'evil.com';
  rewriteChain(entries);

  /* 关键对照：单看日志，链条完全自洽 —— verify 会放行 */
  assert.equal(verifyLedger(entries).ok, true, '重算后的链必须自洽（这正是攻击成立的前提）');

  /* 与外部锚定比对才能发现 */
  const r = checkAnchors(entries, [anchor]);
  assert.equal(r.ok, false);
  assert.equal(r.results[0].status, 'rewritten');
  assert.match(r.results[0].detail, /这段历史被重写过/);
  assert.match(r.reasons[0], /整链被重算替换/);
});

test('只重写被掩改条目之后的部分，同样会被锚定抓住', () => {
  const entries = chain(6);
  const anchor = { entryCount: 6, headHash: entries[5].hash, line: 1 };

  /* 只改第 3 条并重算它之后的（第 0-2 条保持原样） */
  entries[3].target = 'evil.com';
  let prev = entries[2].hash;
  for (let i = 3; i < entries.length; i++) {
    entries[i].prevHash = prev;
    entries[i].hash = computeEntryHash(entries[i], prev);
    prev = entries[i].hash;
  }

  const r = checkAnchors(entries, [anchor]);
  assert.equal(r.ok, false);
  assert.equal(r.results[0].status, 'rewritten');
});

test('截断末尾（回滚）会被发现 —— 锚定条数大于当前条数', () => {
  const entries = chain(6);
  const anchors = [{ entryCount: 6, headHash: entries[5].hash, line: 1 }];

  const truncated = entries.slice(0, 4);   // 砍掉最后两条
  const r = checkAnchors(truncated, anchors);

  assert.equal(r.ok, false);
  assert.equal(r.results[0].status, 'rollback');
  assert.match(r.results[0].detail, /被截断或回滚/);
  assert.match(r.reasons[0], /当前只有 4 条/);
});

test('空日志锚定点（创世哈希）能正确比对', () => {
  assert.equal(checkAnchors([], [{ entryCount: 0, headHash: GENESIS_HASH, line: 1 }]).ok, true);

  const r = checkAnchors([], [{ entryCount: 0, headHash: 'f'.repeat(64), line: 1 }]);
  assert.equal(r.ok, false);
  assert.equal(r.results[0].status, 'rewritten');
});

test('前缀自身断裂时给出 broken 而不是误判为重写', () => {
  const entries = chain(4);
  const anchor = { entryCount: 4, headHash: entries[3].hash, line: 1 };

  /* 只改内容不重算 —— 链条自己就断了 */
  entries[1].target = 'evil.com';

  const r = checkAnchors(entries, [anchor]);
  assert.equal(r.ok, false);
  assert.equal(r.results[0].status, 'broken');
  assert.match(r.results[0].detail, /自身校验失败/);
});

test('无锚定记录时判为失败 —— 没有锚定就没有发现整链重写的手段', () => {
  const entries = chain(4);
  const r = checkAnchors(entries, []);

  assert.equal(r.ok, true, 'checkAnchors 本身没有可报的冲突');
  assert.equal(r.checked, 0);
  assert.equal(r.latestCleared, false, '但也不该被当成"已锚定"');
});

test('currentHead 在空日志时回落到创世哈希', () => {
  assert.equal(checkAnchors([], []).currentHead, GENESIS_HASH);
});

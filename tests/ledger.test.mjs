/**
 * 单元测试：防篡改审计日志
 *
 * 这组测试的重点不是"能存能读"，而是**篡改能不能被发现** ——
 * 包括"改内容""删一条""换顺序""整链重算"这四类真实攻击。
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  makeEntry,
  sealEntry,
  appendEntry,
  loadLedger,
  verifyLedger,
  anchorInfo,
  writeLedger,
  checkEngagementConsistency,
  LedgerError,
} from '../src/lib/ledger.mjs';
import { GENESIS_HASH, computeEntryHash } from '../src/lib/crypto.mjs';

function tmpLedger() {
  const dir = mkdtempSync(join(tmpdir(), 'el-ledger-'));
  return { path: join(dir, 'ledger.jsonl'), cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

/** 造一条长度为 n 的合法链 */
function sealChain(n, { hmacKey = null } = {}) {
  const entries = [];
  let prev = GENESIS_HASH;
  for (let i = 0; i < n; i++) {
    const sealed = sealEntry(
      makeEntry({ seq: i, type: i === 0 ? 'genesis' : 'action', actor: 'alice', action: 'scan', target: `t${i}.example.com`, result: 'ok' }),
      prev,
      hmacKey
    );
    entries.push(sealed);
    prev = sealed.hash;
  }
  return entries;
}

/* ------------------------- 基本读写 ------------------------- */

test('载入不存在的日志返回空数组（首次运行不是错误）', () => {
  const { path, cleanup } = tmpLedger();
  try {
    assert.deepEqual(loadLedger(path), []);
  } finally {
    cleanup();
  }
});

test('appendEntry 依次追加并自动带上 seq 与 prevHash', () => {
  const { path, cleanup } = tmpLedger();
  try {
    const first = appendEntry(path, makeEntry({ seq: 0, type: 'genesis', actor: 'alice' }));
    const second = appendEntry(path, makeEntry({ seq: 0, type: 'action', actor: 'alice', action: 'scan', target: 'a.example.com' }));

    assert.equal(first.seq, 0);
    assert.equal(first.prevHash, GENESIS_HASH);
    assert.equal(second.seq, 1, 'seq 应由追加顺序决定，而不是调用方传入');
    assert.equal(second.prevHash, first.hash);
  } finally {
    cleanup();
  }
});

test('落盘格式是 JSONL：一行一条，可逐行查看', () => {
  const { path, cleanup } = tmpLedger();
  try {
    appendEntry(path, makeEntry({ seq: 0, type: 'genesis', actor: 'alice' }));
    appendEntry(path, makeEntry({ seq: 0, type: 'action', actor: 'alice', action: 'scan', target: 'a.example.com' }));

    const lines = readFileSync(path, 'utf8').trim().split('\n');
    assert.equal(lines.length, 2);
    for (const line of lines) assert.doesNotThrow(() => JSON.parse(line));
  } finally {
    cleanup();
  }
});

test('未知记录类型被拒绝（避免日志里出现无法解释的条目）', () => {
  assert.throws(() => makeEntry({ seq: 0, type: 'whatever', actor: 'alice' }), LedgerError);
});

test('日志行不是合法 JSON 时报错并指出行号', () => {
  const { path, cleanup } = tmpLedger();
  try {
    writeFileSync(path, '{"ok":true}\nnot json\n', 'utf8');
    assert.throws(() => loadLedger(path), /第 2 行/);
  } finally {
    cleanup();
  }
});

/* ------------------------- 完整性 ------------------------- */

test('完整链条校验通过，并给出链头哈希', () => {
  const entries = sealChain(5);
  const result = verifyLedger(entries);

  assert.equal(result.ok, true);
  assert.equal(result.count, 5);
  assert.equal(result.headHash, entries[4].hash);
  assert.equal(result.brokenAt, null);
  assert.equal(result.details.length, 5);
});

test('空日志视为完整（链头为创世哈希）', () => {
  const result = verifyLedger([]);
  assert.equal(result.ok, true);
  assert.equal(result.count, 0);
  assert.equal(result.headHash, GENESIS_HASH);
});

test('篡改记录内容会被发现，并精确指出是第几条', () => {
  const entries = sealChain(5);
  entries[2].target = 'evil.com';  // 悄悄改掉第 3 条的目标

  const result = verifyLedger(entries);
  assert.equal(result.ok, false);
  assert.equal(result.brokenAt, 2);
  assert.match(result.reason, /记录哈希与内容不符/);
});

test('篡改记录时间也会被发现', () => {
  const entries = sealChain(3);
  entries[1].timestamp = '2020-01-01T00:00:00.000Z';
  assert.equal(verifyLedger(entries).brokenAt, 1);
});

test('删掉中间一条会被发现（seq 不连续）', () => {
  const entries = sealChain(5);
  entries.splice(2, 1);  // 抽掉第 3 条

  const result = verifyLedger(entries);
  assert.equal(result.ok, false);
  assert.equal(result.brokenAt, 2);
  assert.match(result.reason, /序号不连续/);
});

test('删除末尾一条不会报错但条数变少 —— 所以必须外部锚定', () => {
  const entries = sealChain(5);
  const truncated = entries.slice(0, 4);

  /* 截断后的链本身是自洽的：这正是"链完整"不足以证明"记录齐全"的原因 */
  assert.equal(verifyLedger(truncated).ok, true);
  assert.equal(verifyLedger(truncated).count, 4);

  /* 锚定信息里的条数与链头哈希会把这件事暴露出来 */
  const anchored = anchorInfo(entries);
  const afterTruncate = anchorInfo(truncated);
  assert.notEqual(anchored.headHash, afterTruncate.headHash);
  assert.notEqual(anchored.entryCount, afterTruncate.entryCount);
});

test('交换两条记录的顺序会被发现', () => {
  const entries = sealChain(4);
  [entries[1], entries[2]] = [entries[2], entries[1]];
  assert.equal(verifyLedger(entries).ok, false);
});

test('把某条的 prevHash 指向别处会被发现', () => {
  const entries = sealChain(3);
  entries[2].prevHash = GENESIS_HASH;
  assert.equal(verifyLedger(entries).ok, false);
  assert.match(verifyLedger(entries).reason, /prevHash/);
});

test('不提供密钥时，整链重算可以伪造 —— 这是纯哈希链的能力边界', () => {
  const entries = sealChain(3);
  entries[1].target = 'evil.com';

  /* 攻击者知道算法，于是把该条及其后所有条重新算一遍 */
  let prev = GENESIS_HASH;
  for (const entry of entries) {
    entry.prevHash = prev;
    entry.hash = computeEntryHash(entry, prev);
    prev = entry.hash;
  }

  assert.equal(verifyLedger(entries).ok, true, '纯哈希链无法阻止重算 —— 设计如此，必须靠外部锚定覆盖');
});

test('启用 HMAC 后，无密钥的重算会失败', () => {
  const key = 'super-secret-key';
  const entries = sealChain(3, { hmacKey: key });
  entries[1].target = 'evil.com';

  /* 真实攻击形态：不动第 0 条，只从被改那条往后重算。
     攻击者不知道密钥，只能用普通 sha256 —— 于是第 1 条就对不上。 */
  let prev = entries[0].hash;
  for (let i = 1; i < entries.length; i++) {
    entries[i].prevHash = prev;
    entries[i].hash = computeEntryHash(entries[i], prev);   // 无密钥
    prev = entries[i].hash;
  }

  const result = verifyLedger(entries, { hmacKey: key });
  assert.equal(result.ok, false);
  assert.equal(result.brokenAt, 1);
  assert.match(result.reason, /HMAC 密钥不匹配/);
});

test('启用 HMAC 后，连"整链推倒重来"也会在第 0 条暴露', () => {
  const key = 'super-secret-key';
  const entries = sealChain(3, { hmacKey: key });
  entries[1].target = 'evil.com';

  /* 更激进：全部重算，包括创世条 */
  let prev = GENESIS_HASH;
  for (const entry of entries) {
    entry.prevHash = prev;
    entry.hash = computeEntryHash(entry, prev);
    prev = entry.hash;
  }

  const result = verifyLedger(entries, { hmacKey: key });
  assert.equal(result.ok, false);
  assert.equal(result.brokenAt, 0, '第一条就签名不对，攻击无法收敛');
});

test('启用 HMAC 后，用错密钥校验会失败并给出对应提示', () => {
  const entries = sealChain(3, { hmacKey: 'right-key' });
  const result = verifyLedger(entries, { hmacKey: 'wrong-key' });

  assert.equal(result.ok, false);
  assert.equal(result.brokenAt, 0);
  assert.match(result.reason, /HMAC 密钥不匹配/);
});

test('未提供密钥去校验 HMAC 签过的链会失败（而不是误判通过）', () => {
  const entries = sealChain(3, { hmacKey: 'key' });
  const result = verifyLedger(entries);
  assert.equal(result.ok, false);
  assert.match(result.reason, /不同密钥签的/);
});

test('校验失败时不返回链头哈希（避免把坏链的哈希锚定出去）', () => {
  const entries = sealChain(3);
  entries[1].target = 'evil.com';
  assert.equal(verifyLedger(entries).headHash, null);
});

test('校验轨迹按顺序列出每条记录摘要，便于人工复核', () => {
  const entries = sealChain(3);
  const result = verifyLedger(entries);

  assert.equal(result.details[0].summary, '建立日志（委托 ?）');
  assert.equal(result.details[1].summary, '执行 scan → t1.example.com（ok）');
  assert.equal(result.details[0].ok, true);
});

test('拒绝记录在摘要里明确标注为"拒绝"', () => {
  const entries = sealChain(1);
  const denied = sealEntry(
    makeEntry({ seq: 1, type: 'decision', actor: 'alice', action: 'ransomware', target: 'evil.com', decision: 'denied' }),
    entries[0].hash
  );
  entries.push(denied);

  const result = verifyLedger(entries);
  assert.equal(result.ok, true);
  assert.equal(result.details[1].summary, '拒绝 ransomware → evil.com');
});

/* ------------------------- 锚定 ------------------------- */

test('anchorInfo 产出可直接提交进 git 的锚定行', () => {
  const entries = sealChain(4);
  const info = anchorInfo(entries);

  assert.equal(info.entryCount, 4);
  assert.equal(info.chainOk, true);
  assert.equal(info.anchorLine, `engagement-ledger 4 ${entries[3].hash}`);
});

test('anchorInfo 在链断裂时把链头标为 BROKEN', () => {
  const entries = sealChain(3);
  entries[0].actor = 'mallory';
  const info = anchorInfo(entries);

  assert.equal(info.chainOk, false);
  assert.equal(info.headHash, null);
  assert.match(info.anchorLine, /BROKEN/);
});

test('anchorInfo 从 genesis 记录里取出委托编号', () => {
  const entries = sealChain(1);
  entries[0].engagementId = 'ENG-001';
  assert.equal(anchorInfo(entries).engagementId, 'ENG-001');
});

/* ------------------------- 文件往返 ------------------------- */

test('写盘再读回，校验结果不变（序列化不破坏链）', () => {
  const { path, cleanup } = tmpLedger();
  try {
    const entries = sealChain(6);
    writeLedger(path, entries);

    const reloaded = loadLedger(path);
    assert.equal(reloaded.length, 6);
    assert.equal(verifyLedger(reloaded).ok, true);
    assert.deepEqual(reloaded.map((e) => e.hash), entries.map((e) => e.hash));
  } finally {
    cleanup();
  }
});

test('逐条追加后整体校验通过（真实使用路径）', () => {
  const { path, cleanup } = tmpLedger();
  try {
    appendEntry(path, makeEntry({ seq: 0, type: 'genesis', actor: 'alice' }));
    appendEntry(path, makeEntry({ seq: 0, type: 'action', actor: 'alice', action: 'recon', target: 'a.example.com', result: 'ok' }));
    appendEntry(path, makeEntry({ seq: 0, type: 'action', actor: 'alice', action: 'scan', target: 'b.example.com', result: '3 findings' }));

    const result = verifyLedger(loadLedger(path));
    assert.equal(result.ok, true);
    assert.equal(result.count, 3);
  } finally {
    cleanup();
  }
});

test('直接改文件里的内容后校验失败（端到端的篡改发现）', () => {
  const { path, cleanup } = tmpLedger();
  try {
    const e0 = appendEntry(path, makeEntry({ seq: 0, type: 'genesis', actor: 'alice' }));
    appendEntry(path, makeEntry({ seq: 0, type: 'action', actor: 'alice', action: 'recon', target: 'a.example.com', result: 'ok' }));

    const lines = readFileSync(path, 'utf8').trim().split('\n');
    const tampered = JSON.parse(lines[1]);
    tampered.target = 'someone-elses.com';   // 手动改一行
    lines[1] = JSON.stringify(tampered);
    writeFileSync(path, lines.join('\n') + '\n', 'utf8');

    const result = verifyLedger(loadLedger(path));
    assert.equal(result.ok, false);
    assert.equal(result.brokenAt, 1);
    /* 第一条仍然是对的，说明定位精确 */
    assert.equal(result.details[0].ok, true);
    assert.equal(e0.seq, 0);
  } finally {
    cleanup();
  }
});

test('判定轨迹随记录一起入库（审计可复核"当时依据什么"）', () => {
  const { path, cleanup } = tmpLedger();
  try {
    const checks = [
      { name: 'target-in-scope', passed: true, detail: '命中范围规则 example.com' },
      { name: 'action-permitted', passed: true, detail: '动作在允许清单内' },
    ];
    appendEntry(path, makeEntry({ seq: 0, type: 'genesis', actor: 'alice' }));
    appendEntry(path, makeEntry({ seq: 0, type: 'action', actor: 'alice', action: 'scan', target: 'a.example.com', checks }));

    const reloaded = loadLedger(path);
    assert.deepEqual(reloaded[1].checks, checks);
    assert.equal(verifyLedger(reloaded).ok, true, '带轨迹的记录同样可校验');
  } finally {
    cleanup();
  }
});

test('中文内容在哈希链里往返无损（UTF-8 编码稳定）', () => {
  const { path, cleanup } = tmpLedger();
  try {
    appendEntry(path, makeEntry({ seq: 0, type: 'genesis', actor: '张三' }));
    appendEntry(path, makeEntry({ seq: 0, type: 'note', actor: '张三', reason: '与甲方确认范围边界：支付系统不测' }));

    const reloaded = loadLedger(path);
    assert.equal(reloaded[1].reason, '与甲方确认范围边界：支付系统不测');
    assert.equal(verifyLedger(reloaded).ok, true);
  } finally {
    cleanup();
  }
});

/* ------------------------- 委托归属一致性 ------------------------- */

test('全部记录属于同一委托时判定一致', () => {
  const entries = [
    { seq: 0, type: 'genesis', engagementId: 'ENG-1', timestamp: 't0' },
    { seq: 1, type: 'action', engagementId: 'ENG-1', timestamp: 't1' },
  ];
  const r = checkEngagementConsistency('ENG-1', entries);
  assert.equal(r.ok, true);
  assert.deepEqual(r.foreign, []);
});

test('混入别的委托的记录会被发现（链完整也照样检出）', () => {
  const entries = [
    { seq: 0, type: 'genesis', engagementId: 'ENG-1', timestamp: 't0' },
    { seq: 1, type: 'action', engagementId: 'ENG-1', action: 'recon', target: 'a.com' },
    { seq: 2, type: 'action', engagementId: 'ENG-2', action: 'scan', target: 'b.com', timestamp: 't2' },
  ];

  const r = checkEngagementConsistency('ENG-1', entries);
  assert.equal(r.ok, false);
  assert.equal(r.foreign.length, 1);
  assert.equal(r.foreign[0].seq, 2);
  assert.equal(r.foreign[0].engagementId, 'ENG-2');
  assert.equal(r.foreign[0].target, 'b.com');
  assert.equal(r.expected, 'ENG-1');
});

test('委托编号按字符串比较（数字与字符串同值不算冲突）', () => {
  const entries = [{ seq: 0, type: 'action', engagementId: 12345 }];
  assert.equal(checkEngagementConsistency('12345', entries).ok, true);
});

test('未标注委托编号的记录进 untagged，不判为不一致', () => {
  const entries = [
    { seq: 0, type: 'genesis', engagementId: 'ENG-1' },
    { seq: 1, type: 'note', timestamp: 't1' },
  ];
  const r = checkEngagementConsistency('ENG-1', entries);
  assert.equal(r.ok, true, '未标注不等于属于别人');
  assert.equal(r.untagged.length, 1);
  assert.equal(r.untagged[0].seq, 1);
});

test('genesis 缺少编号时不进 untagged（它是建立日志的那条）', () => {
  const entries = [{ seq: 0, type: 'genesis' }];
  assert.deepEqual(checkEngagementConsistency('ENG-1', entries).untagged, []);
});

test('空日志视为一致', () => {
  const r = checkEngagementConsistency('ENG-1', []);
  assert.equal(r.ok, true);
  assert.deepEqual(r.foreign, []);
});

test('单条记录属于别的委托也判为不一致（边界：1 条也不能放过）', () => {
  const entries = [{ seq: 0, type: 'action', engagementId: 'OTHER' }];
  assert.equal(checkEngagementConsistency('ENG-1', entries).ok, false);
});

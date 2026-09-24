/**
 * 单元测试：合规报告
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { validateManifest } from '../src/lib/manifest.mjs';
import { makeEntry, sealEntry } from '../src/lib/ledger.mjs';
import { summarizeLedger, buildReport, buildJsonReport } from '../src/lib/report.mjs';
import { GENESIS_HASH } from '../src/lib/crypto.mjs';

function manifest() {
  return validateManifest({
    engagement: {
      id: 'ENG-001',
      name: '示例委托',
      tester: 'alice',
      authorization: {
        reference: 'AUTH-001',
        signedBy: 'bob',
        signedTitle: 'CISO',
        signedAt: '2026-09-01',
        documentSha256: 'a'.repeat(64),
      },
      window: { from: '2026-09-01T00:00:00Z', to: '2026-12-31T00:00:00Z' },
      scope: { inScope: ['example.com'], outOfScope: ['pay.example.com'] },
      permittedActions: ['recon', 'scan'],
      prohibitedActions: ['dos', 'destructive', 'data-exfiltration', 'persistence', 'social-engineering'],
      emergencyContact: 'bob@example.com',
    },
  });
}

/** 造一组合法记录：genesis + 允许 + 拒绝 */
function entries() {
  const list = [];
  let prev = GENESIS_HASH;
  const push = (entry) => {
    const sealed = sealEntry(entry, prev);
    list.push(sealed);
    prev = sealed.hash;
  };

  const genesis = makeEntry({ seq: 0, type: 'genesis', actor: 'alice', reason: '建立审计日志 · 委托 ENG-001' });
  genesis.engagementId = 'ENG-001';
  push(genesis);

  push(makeEntry({ seq: 1, type: 'action', actor: 'alice', action: 'recon', target: 'api.example.com', decision: 'allowed', result: '12 endpoints', timestamp: '2026-09-02T10:00:00.000Z' }));
  push(makeEntry({ seq: 2, type: 'action', actor: 'alice', action: 'scan', target: 'staging.example.com', decision: 'allowed', result: '3 findings', timestamp: '2026-09-02T11:00:00.000Z' }));
  push(makeEntry({
    seq: 3, type: 'decision', actor: 'alice', action: 'scan', target: 'pay.example.com',
    decision: 'denied', reason: '目标「pay.example.com」命中排除规则「pay.example.com」—— 排除优先级高于纳入',
    result: 'not-executed', timestamp: '2026-09-02T12:00:00.000Z',
  }));

  return list;
}

/** 改动过某条之后重新封整条链（测试里让"被改过的链"仍然自洽） */
function reseal(list) {
  let prev = GENESIS_HASH;
  return list.map((entry, i) => {
    const { hash, ...rest } = entry;
    const sealed = sealEntry({ ...rest, seq: i }, prev);
    prev = sealed.hash;
    return sealed;
  });
}

/* ------------------------- 统计 ------------------------- */

test('summarizeLedger 统计条数、判定与目标', () => {
  const stats = summarizeLedger(entries());
  assert.equal(stats.total, 4);
  assert.equal(stats.byType.genesis, 1);
  assert.equal(stats.byType.action, 2);
  assert.equal(stats.byType.decision, 1);
  assert.equal(stats.decisions.allowed, 2);
  assert.equal(stats.decisions.denied, 1);
  assert.deepEqual(stats.targetsTouched, ['api.example.com', 'pay.example.com', 'staging.example.com']);
});

test('summarizeLedger 空日志不报错', () => {
  const stats = summarizeLedger([]);
  assert.equal(stats.total, 0);
  assert.equal(stats.decisions.denied, 0);
  assert.deepEqual(stats.targetsTouched, []);
});

test('被拒记录带出拒绝原因（报告要能解释为什么拒）', () => {
  const stats = summarizeLedger(entries());
  assert.equal(stats.deniedActions.length, 1);
  assert.equal(stats.deniedActions[0].target, 'pay.example.com');
  assert.match(stats.deniedActions[0].reason, /排除规则/);
});

/* ------------------------- 动作流水 ------------------------- */

test('summarizeLedger 收集已执行动作进流水（不含 genesis 与被拒）', () => {
  const stats = summarizeLedger(entries());

  assert.equal(stats.timeline.length, 2, '应只有两条已执行动作');
  assert.deepEqual(stats.timeline.map((a) => a.action), ['recon', 'scan']);
  assert.deepEqual(stats.timeline.map((a) => a.target), ['api.example.com', 'staging.example.com']);
  assert.equal(stats.timeline.every((a) => a.type === 'action'), true);
});

test('流水条目带出执行人、结果与证据指针', () => {
  const list = entries();
  const { hash, ...rest } = list[1];
  const withEvidence = reseal([...list.slice(0, 1), { ...rest, evidence: 'logs/recon-001.txt' }, list[2], list[3]]);

  const first = summarizeLedger(withEvidence).timeline[0];
  assert.equal(first.actor, 'alice');
  assert.equal(first.result, '12 endpoints');
  assert.equal(first.evidence, 'logs/recon-001.txt');
});

test('备注条目也进流水，但不冒充测试动作', () => {
  const list = entries();
  list.push(makeEntry({ seq: 4, type: 'note', actor: 'alice', reason: '与甲方确认：支付系统不测', timestamp: '2026-09-02T13:00:00.000Z' }));
  const rebuilt = reseal(list);

  const stats = summarizeLedger(rebuilt);
  assert.equal(stats.timeline.length, 3);
  assert.equal(stats.timeline.at(-1).type, 'note');
  assert.equal(stats.timeline.at(-1).action, null);
});

test('报告含动作流水一节，列出每个动作与证据', () => {
  const list = entries();
  list[1].evidence = 'logs/recon-001.txt';
  const md = buildReport({ manifest: manifest(), entries: reseal(list) });

  assert.ok(md.includes('### 3.2 动作流水'));
  assert.ok(md.includes('| # | 事件时间 | 执行人 | 动作 | 目标 | 结果 | 证据 |'));
  assert.ok(md.includes('`recon`'));
  assert.ok(md.includes('`api.example.com`'));
  assert.ok(md.includes('12 endpoints'));
  assert.ok(md.includes('`logs/recon-001.txt`'));
  /* 被拒的尝试不应混进流水（它属于第 4 章） */
  const timelineStart = md.indexOf('### 3.2 动作流水');
  const chapter4 = md.indexOf('## 4. 越界尝试与被拒记录');
  assert.ok(timelineStart < chapter4);
  assert.ok(!md.slice(timelineStart, chapter4).includes('pay.example.com'));
});

test('有动作缺证据指针时给出提示（证据决定能否独立复核）', () => {
  const md = buildReport({ manifest: manifest(), entries: entries() });
  assert.ok(md.includes('未附证据指针'));
  assert.match(md, /决定这条记录能否被独立复核/);
});

test('全部动作都带证据时不出现缺证据提示', () => {
  const list = entries();
  list[1].evidence = 'a.txt';
  list[2].evidence = 'b.txt';
  const md = buildReport({ manifest: manifest(), entries: reseal(list) });

  assert.ok(!md.includes('未附证据指针'));
});

test('补录条目在流水里带 ⚠️ 标记', () => {
  const list = entries();
  list[1].backfilled = true;
  const md = buildReport({ manifest: manifest(), entries: reseal(list) });

  assert.ok(md.includes('⚠️'));
  assert.ok(md.includes('标记表示该条为补录'));
});

test('没有任何已执行动作时报告给出说明而不是空表', () => {
  const only = entries().filter((e) => e.type === 'genesis' || e.decision === 'denied');
  const md = buildReport({ manifest: manifest(), entries: reseal(only) });

  assert.ok(md.includes('尚未记录任何已执行的动作'));
  assert.ok(!md.includes('| # | 事件时间 | 执行人 | 动作 | 目标 | 结果 | 证据 |'));
});

test('动作流水进 JSON 报告，可供下游系统消费', () => {
  const json = buildJsonReport({ manifest: manifest(), entries: entries() });
  assert.equal(json.statistics.timeline.length, 2);
  assert.equal(json.statistics.timeline[0].action, 'recon');
  assert.doesNotThrow(() => JSON.parse(JSON.stringify(json)));
});

/* ------------------------- Markdown 报告 ------------------------- */

test('报告包含七个必备章节', () => {
  const md = buildReport({ manifest: manifest(), entries: entries() });
  for (const heading of [
    '# 授权测试合规报告',
    '## 1. 委托与授权',
    '## 2. 授权范围',
    '## 3. 执行记录统计',
    '## 4. 越界尝试与被拒记录',
    '## 5. 日志完整性',
    '## 6. 外部锚定（防整链替换）',
    '## 7. 边界声明',
  ]) {
    assert.ok(md.includes(heading), `缺少章节：${heading}`);
  }
});

test('报告写出授权依据（编号、签署人、窗口、文档哈希）', () => {
  const md = buildReport({ manifest: manifest(), entries: entries() });
  assert.ok(md.includes('AUTH-001'));
  assert.ok(md.includes('bob'));
  assert.ok(md.includes('CISO'));
  assert.ok(md.includes('a'.repeat(64)), '应写出授权文件哈希');
});

test('报告把被拒尝试单列成表 —— 被拒是纪律的证据', () => {
  const md = buildReport({ manifest: manifest(), entries: entries() });
  assert.ok(md.includes('| # | 时间 | 动作 | 目标 | 拒绝原因 |'));
  assert.ok(md.includes('pay.example.com'));
  assert.ok(md.includes('被拒记录是测试纪律的证据'));
});

test('无越界尝试时报告给出"未出现越界尝试"而不是空表', () => {
  const only = entries().filter((e) => e.decision !== 'denied');
  const md = buildReport({ manifest: manifest(), entries: reseal(only) });

  assert.ok(md.includes('未出现越界尝试'));
  assert.ok(!md.includes('| # | 时间 | 动作 | 目标 | 拒绝原因 |'));
});

test('报告给出链完整性结论与链头哈希', () => {
  const list = entries();
  const md = buildReport({ manifest: manifest(), entries: list });
  assert.ok(md.includes('✅ 哈希链完整'));
  assert.ok(md.includes(list.at(-1).hash));
});

test('链断裂时报告显式标注不可作为证据', () => {
  const list = entries();
  list[1].target = 'someone-elses.com';
  const md = buildReport({ manifest: manifest(), entries: list });

  assert.ok(md.includes('❌ **哈希链校验失败**'));
  assert.ok(md.includes('不可作为合规证据使用'));
  assert.ok(md.includes('第 1 条'));
});

test('报告写明能力边界：篡改可发现 ≠ 不可伪造', () => {
  const md = buildReport({ manifest: manifest(), entries: entries() });
  assert.ok(md.includes('篡改可发现 ≠ 不可伪造'));
  assert.ok(md.includes('HMAC'));
  assert.ok(md.includes('本报告仅覆盖通过本工具记录的动'));
});

test('报告给出可直接提交 git 的锚定行', () => {
  const list = entries();
  const md = buildReport({ manifest: manifest(), entries: list });
  assert.ok(md.includes(`engagement-ledger ${list.length} ${list.at(-1).hash}`));
});

test('缺少文档哈希时报告显式告警', () => {
  const m = manifest();
  m.engagement.authorization.documentSha256 = null;
  const md = buildReport({ manifest: m, entries: entries() });
  assert.ok(md.includes('无法证明所依据的授权文件未被替换'));
});

test('报告列出排除规则并说明排除优先', () => {
  const md = buildReport({ manifest: manifest(), entries: entries() });
  assert.ok(md.includes('明确排除（outOfScope）'));
  assert.ok(md.includes('pay.example.com'));
  assert.ok(md.includes('排除优先'));
});

test('报告列出硬性禁止动作（说明不随配置放开）', () => {
  const md = buildReport({ manifest: manifest(), entries: entries() });
  assert.ok(md.includes('系统硬性禁止'));
  assert.ok(md.includes('ransomware'));
});

test('报告里的管道符被转义，不破坏表格结构', () => {
  const list = entries();
  /* 把被拒原因改含竖线后重新封链，验证表格单元格做了转义 */
  const { hash, ...rest } = list[3];
  rest.reason = '原因里含 | 竖线';
  const resealed = sealEntry(rest, list[2].hash);
  const rebuilt = [...list.slice(0, 3), resealed];

  const md = buildReport({ manifest: manifest(), entries: rebuilt });
  assert.ok(md.includes('原因里含 \\| 竖线'));
});

test('报告统计补录记录并在有补录时给出说明', () => {
  const list = entries();
  list[2].backfilled = true;
  list[2].recordedSkewSeconds = 86400;
  const rebuilt = reseal(list);

  assert.equal(summarizeLedger(rebuilt).backfilledCount, 1);

  const md = buildReport({ manifest: manifest(), entries: rebuilt });
  assert.ok(md.includes('| 事后补录记录 | 1 |'));
  assert.ok(md.includes('不能证明**事件顺序**'));
  assert.ok(md.includes('✅ 哈希链完整'), '重封后链条应仍然自洽');
});

test('无补录时不出现补录说明', () => {
  const md = buildReport({ manifest: manifest(), entries: entries() });
  assert.ok(md.includes('| 事后补录记录 | 0 |'));
  assert.ok(!md.includes('这些条目的先后关系应由操作方的其他记录佐证'));
});

test('边界声明写明"写入顺序 ≠ 事件顺序"与"日志完整 ≠ 全部操作都在日志里"', () => {
  const md = buildReport({ manifest: manifest(), entries: entries() });
  assert.ok(md.includes('写入顺序 ≠ 事件顺序'));
  assert.ok(md.includes('本日志完整 ≠ 全部操作都在日志里'));
  assert.ok(md.includes('按写入顺序的首条'));
});

/* ------------------------- JSON 报告 ------------------------- */

test('JSON 报告可被解析且字段齐全', () => {
  const json = buildJsonReport({ manifest: manifest(), entries: entries() });

  assert.equal(json.engagement.id, 'ENG-001');
  assert.equal(json.statistics.total, 4);
  assert.equal(json.integrity.chainOk, true);
  assert.equal(json.anchor.entryCount, 4);
  assert.equal(json.engagement.hardForbidden.includes('ransomware'), true);
  assert.ok(json.generatedAt);
  /* 必须能被 JSON 序列化（供 CI 消费） */
  assert.doesNotThrow(() => JSON.parse(JSON.stringify(json)));
});

test('JSON 报告在链断裂时反映真实状态', () => {
  const list = entries();
  list[2].target = 'evil.com';
  const json = buildJsonReport({ manifest: manifest(), entries: list });

  assert.equal(json.integrity.chainOk, false);
  assert.equal(json.integrity.brokenAt, 2);
  assert.equal(json.anchor.headHash, null);
});

test('JSON 报告的授权窗口是 ISO 字符串（可跨语言消费）', () => {
  const json = buildJsonReport({ manifest: manifest(), entries: entries() });
  assert.match(json.engagement.window.from, /^\d{4}-\d{2}-\d{2}T/);
});

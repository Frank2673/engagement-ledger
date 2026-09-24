/**
 * 端到端测试：CLI
 *
 * 直接调用 main() 而不是起子进程 —— 在受限环境里 spawn 会被拦，
 * 而且这里要测的是命令逻辑，不是进程启动。
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { main } from '../src/index.mjs';
import { fileSha256 } from '../src/lib/crypto.mjs';
import { appendEntry } from '../src/lib/ledger.mjs';

const AUTH_DOC = '授权书内容（测试用）\n';

/** 造一个隔离的委托目录 */
function sandbox(engId = 'ENG-001') {
  const dir = mkdtempSync(join(tmpdir(), 'el-cli-'));
  const authPath = join(dir, 'authorization.txt');
  writeFileSync(authPath, AUTH_DOC, 'utf8');

  const manifestPath = join(dir, 'engagement.json');
  writeFileSync(
    manifestPath,
    JSON.stringify({
      engagement: {
        id: engId,
        name: '测试委托',
        tester: 'alice',
        authorization: {
          reference: 'AUTH-001',
          signedBy: 'bob',
          signedTitle: 'CISO',
          document: 'authorization.txt',
          documentSha256: fileSha256(Buffer.from(AUTH_DOC, 'utf8')),
        },
        window: { from: '2026-09-01T00:00:00Z', to: '2026-12-31T18:00:00Z' },
        scope: { inScope: ['example.com', '192.0.2.0/28'], outOfScope: ['pay.example.com'] },
        permittedActions: ['recon', 'scan'],
        prohibitedActions: ['dos', 'destructive', 'data-exfiltration', 'persistence', 'social-engineering'],
        emergencyContact: 'bob@example.com',
      },
    }),
    'utf8'
  );

  const ledgerPath = join(dir, 'ledger.jsonl');
  return {
    dir,
    manifestPath,
    ledgerPath,
    authPath,
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
  };
}

/** 在进程内运行 CLI 并捕获输出 */
function run(argv) {
  const out = [];
  const err = [];
  const origOut = process.stdout.write;
  const origErr = process.stderr.write;
  process.stdout.write = (chunk) => { out.push(String(chunk)); return true; };
  process.stderr.write = (chunk) => { err.push(String(chunk)); return true; };
  let code;
  try {
    code = main(argv);
  } finally {
    process.stdout.write = origOut;
    process.stderr.write = origErr;
  }
  return { code, stdout: out.join(''), stderr: err.join('') };
}

const AT = '2026-09-15T12:00:00Z';

/* ------------------------- 基础 ------------------------- */

test('--help 打印用法并返回 0', () => {
  const { code, stdout } = run(['--help']);
  assert.equal(code, 0);
  assert.ok(stdout.includes('engagement-ledger'));
  assert.ok(stdout.includes('hash-doc'));
});

test('未知命令返回 1 并提示查看用法', () => {
  const { code, stderr } = run(['frobnicate']);
  assert.equal(code, 1);
  assert.match(stderr, /未知命令/);
});

test('hash-doc 算出的哈希与已知值一致', () => {
  const sb = sandbox();
  try {
    const { code, stdout } = run(['hash-doc', sb.authPath]);
    assert.equal(code, 0);
    assert.ok(stdout.includes(fileSha256(Buffer.from(AUTH_DOC, 'utf8'))));
    assert.ok(stdout.includes('documentSha256'), '应提示字段名，便于复制进凭证');
  } finally {
    sb.cleanup();
  }
});

test('hash-doc 指向不存在的文件时返回 1', () => {
  const { code, stderr } = run(['hash-doc', join(tmpdir(), 'definitely-not-here-12345.txt')]);
  assert.equal(code, 1);
  assert.match(stderr, /文件不存在/);
});

/* ------------------------- init ------------------------- */

test('init 写入 genesis 记录并核验授权文件', () => {
  const sb = sandbox();
  try {
    const { code, stdout } = run(['init', '--manifest', sb.manifestPath, '--ledger', sb.ledgerPath]);
    assert.equal(code, 0);
    assert.ok(stdout.includes('已初始化审计日志'));
    assert.ok(stdout.includes('ENG-001'));
    assert.ok(stdout.includes('纯哈希链'), '未提供密钥时应说明这是纯哈希链');
    assert.ok(stdout.includes('✅ 授权文件核验通过'));

    const entries = readFileSync(sb.ledgerPath, 'utf8').trim().split('\n').map((l) => JSON.parse(l));
    assert.equal(entries.length, 1);
    assert.equal(entries[0].type, 'genesis');
    assert.equal(entries[0].engagementId, 'ENG-001');
    assert.equal(entries[0].prevHash, '0'.repeat(64));
  } finally {
    sb.cleanup();
  }
});

test('init 在日志已存在时拒绝重复初始化（避免两条创世记录）', () => {
  const sb = sandbox();
  try {
    run(['init', '--manifest', sb.manifestPath, '--ledger', sb.ledgerPath]);
    const { code, stderr } = run(['init', '--manifest', sb.manifestPath, '--ledger', sb.ledgerPath]);

    assert.equal(code, 1);
    assert.match(stderr, /不重复初始化/);
    /* 关键：日志没有被写坏 */
    assert.equal(readFileSync(sb.ledgerPath, 'utf8').trim().split('\n').length, 1);
  } finally {
    sb.cleanup();
  }
});

test('凭证缺少授权段时 init 失败并给出可操作的原因', () => {
  const sb = sandbox();
  try {
    writeFileSync(sb.manifestPath, JSON.stringify({ engagement: { id: 'X', tester: 'y' } }), 'utf8');
    const { code, stderr } = run(['init', '--manifest', sb.manifestPath, '--ledger', sb.ledgerPath]);
    assert.equal(code, 1);
    assert.match(stderr, /凭证载入失败/);
    assert.ok(!existsSync(sb.ledgerPath), '失败时不应产生半个日志文件');
  } finally {
    sb.cleanup();
  }
});

test('凭证声明的授权书被换过时 init 明确告警', () => {
  const sb = sandbox();
  try {
    writeFileSync(sb.authPath, '被人改过的授权书\n', 'utf8');
    const { code, stdout } = run(['init', '--manifest', sb.manifestPath, '--ledger', sb.ledgerPath]);
    assert.equal(code, 0, 'init 仍然成功，但必须显式告警');
    assert.ok(stdout.includes('授权文件核验未通过'));
    assert.ok(stdout.includes('不一致'));
  } finally {
    sb.cleanup();
  }
});

/* ------------------------- check ------------------------- */

test('check 允许时不写日志（试判与留痕分离）', () => {
  const sb = sandbox();
  try {
    run(['init', '--manifest', sb.manifestPath, '--ledger', sb.ledgerPath]);
    const before = readFileSync(sb.ledgerPath, 'utf8');

    const { code, stdout } = run(['check', '--manifest', sb.manifestPath, '--ledger', sb.ledgerPath, '--target', 'api.example.com', '--action', 'recon', '--at', AT]);
    assert.equal(code, 0);
    assert.ok(stdout.includes('✅ 允许执行'));
    assert.ok(stdout.includes('仅'));
    assert.equal(readFileSync(sb.ledgerPath, 'utf8'), before, 'check 不应改动日志');
  } finally {
    sb.cleanup();
  }
});

test('check 拒绝时返回退出码 2（供脚本判断）', () => {
  const sb = sandbox();
  try {
    run(['init', '--manifest', sb.manifestPath, '--ledger', sb.ledgerPath]);
    const { code, stdout } = run(['check', '--manifest', sb.manifestPath, '--ledger', sb.ledgerPath, '--target', 'evil.com', '--action', 'recon', '--at', AT]);

    assert.equal(code, 2);
    assert.ok(stdout.includes('⛔ 拒绝执行'));
    assert.ok(stdout.includes('target-in-scope'));
    assert.ok(stdout.includes('拒绝依据'));
  } finally {
    sb.cleanup();
  }
});

test('check 打印完整校验轨迹（每一项通过与否都可见）', () => {
  const sb = sandbox();
  try {
    run(['init', '--manifest', sb.manifestPath, '--ledger', sb.ledgerPath]);
    const { stdout } = run(['check', '--manifest', sb.manifestPath, '--ledger', sb.ledgerPath, '--target', 'example.com', '--action', 'scan', '--at', AT]);
    for (const name of ['input-complete', 'action-not-hard-forbidden', 'action-not-prohibited', 'action-permitted', 'within-time-window', 'target-in-scope', 'target-not-excluded']) {
      assert.ok(stdout.includes(name), `轨迹缺少 ${name}`);
    }
  } finally {
    sb.cleanup();
  }
});

/* ------------------------- log ------------------------- */

test('log 允许时写入 action 记录', () => {
  const sb = sandbox();
  try {
    run(['init', '--manifest', sb.manifestPath, '--ledger', sb.ledgerPath]);
    const { code } = run(['log', '--manifest', sb.manifestPath, '--ledger', sb.ledgerPath, '--target', 'api.example.com', '--action', 'recon', '--result', '12 endpoints', '--evidence', 'logs/recon.txt', '--at', AT]);
    assert.equal(code, 0);

    const entries = readFileSync(sb.ledgerPath, 'utf8').trim().split('\n').map((l) => JSON.parse(l));
    assert.equal(entries.length, 2);
    const logged = entries[1];
    assert.equal(logged.type, 'action');
    assert.equal(logged.decision, 'allowed');
    assert.equal(logged.result, '12 endpoints');
    assert.equal(logged.evidence, 'logs/recon.txt');
    assert.equal(logged.action, 'recon');
    assert.equal(logged.target, 'api.example.com');
    assert.ok(Array.isArray(logged.checks) && logged.checks.length === 7, '判定轨迹应一并入库');
  } finally {
    sb.cleanup();
  }
});

test('log 拒绝时同样入库，并把结果标为 not-executed', () => {
  const sb = sandbox();
  try {
    run(['init', '--manifest', sb.manifestPath, '--ledger', sb.ledgerPath]);
    const { code, stdout } = run(['log', '--manifest', sb.manifestPath, '--ledger', sb.ledgerPath, '--target', 'pay.example.com', '--action', 'scan', '--at', AT]);

    assert.equal(code, 2);
    assert.ok(stdout.includes('未执行'));
    assert.ok(stdout.includes('纪律'));

    const entries = readFileSync(sb.ledgerPath, 'utf8').trim().split('\n').map((l) => JSON.parse(l));
    const denied = entries.at(-1);
    assert.equal(denied.type, 'decision');
    assert.equal(denied.decision, 'denied');
    assert.equal(denied.result, 'not-executed');
    assert.match(denied.reason, /排除规则/);
  } finally {
    sb.cleanup();
  }
});

test('log 在日志未初始化时拒绝执行（不允许绕过 init）', () => {
  const sb = sandbox();
  try {
    const { code, stderr } = run(['log', '--manifest', sb.manifestPath, '--ledger', sb.ledgerPath, '--target', 'example.com', '--action', 'scan', '--at', AT]);
    assert.equal(code, 1);
    assert.match(stderr, /请先运行 engagement-ledger init/);
    assert.ok(!existsSync(sb.ledgerPath));
  } finally {
    sb.cleanup();
  }
});

test('多次 log 形成连续链条并校验通过', () => {
  const sb = sandbox();
  try {
    run(['init', '--manifest', sb.manifestPath, '--ledger', sb.ledgerPath]);
    run(['log', '--manifest', sb.manifestPath, '--ledger', sb.ledgerPath, '--target', 'api.example.com', '--action', 'recon', '--at', AT]);
    run(['log', '--manifest', sb.manifestPath, '--ledger', sb.ledgerPath, '--target', 'example.com', '--action', 'scan', '--at', AT]);
    run(['log', '--manifest', sb.manifestPath, '--ledger', sb.ledgerPath, '--target', 'evil.com', '--action', 'scan', '--at', AT]);

    const { code, stdout } = run(['verify', '--ledger', sb.ledgerPath]);
    assert.equal(code, 0);
    assert.ok(stdout.includes('哈希链完整'));
    assert.ok(stdout.includes('记录条数：4'));
  } finally {
    sb.cleanup();
  }
});

/* ------------------------- verify ------------------------- */

test('verify 在日志被篡改后返回 3 并指出位置', () => {
  const sb = sandbox();
  try {
    run(['init', '--manifest', sb.manifestPath, '--ledger', sb.ledgerPath]);
    /* 先记一条越界被拒的记录 */
    run(['log', '--manifest', sb.manifestPath, '--ledger', sb.ledgerPath, '--target', 'evil.com', '--action', 'scan', '--at', AT]);

    /* 手改日志：把越界目标改成范围内的，试图掩盖曾经尝试越界 */
    const lines = readFileSync(sb.ledgerPath, 'utf8').trim().split('\n');
    const tampered = JSON.parse(lines[1]);
    assert.equal(tampered.target, 'evil.com');
    tampered.target = 'api.example.com';
    lines[1] = JSON.stringify(tampered);
    writeFileSync(sb.ledgerPath, lines.join('\n') + '\n', 'utf8');

    const { code, stdout } = run(['verify', '--ledger', sb.ledgerPath]);
    assert.equal(code, 3);
    assert.ok(stdout.includes('哈希链校验失败'));
    assert.ok(stdout.includes('不可作为合规证据使用'));
  } finally {
    sb.cleanup();
  }
});

test('verify 提示链完整不等于记录齐全（需外部锚定）', () => {
  const sb = sandbox();
  try {
    run(['init', '--manifest', sb.manifestPath, '--ledger', sb.ledgerPath]);
    const { stdout } = run(['verify', '--ledger', sb.ledgerPath]);
    assert.ok(stdout.includes('anchor'));
  } finally {
    sb.cleanup();
  }
});

/* ------------------------- HMAC ------------------------- */

test('通过环境变量启用 HMAC，密钥不出现在命令行里', () => {
  const sb = sandbox();
  const varName = 'EL_TEST_KEY';
  process.env[varName] = 'test-secret-key';
  try {
    const { stdout } = run(['init', '--manifest', sb.manifestPath, '--ledger', sb.ledgerPath, '--hmac-key-env', varName]);
    assert.ok(stdout.includes('哈希链 + HMAC'));

    /* 带密钥校验通过 */
    assert.equal(run(['verify', '--ledger', sb.ledgerPath, '--hmac-key-env', varName]).code, 0);
    /* 不带密钥校验失败 —— 说明确实签了 */
    assert.equal(run(['verify', '--ledger', sb.ledgerPath]).code, 3);
  } finally {
    delete process.env[varName];
    sb.cleanup();
  }
});

/* ------------------------- report / anchor / status ------------------------- */

test('report 写出 Markdown 文件并包含越界记录', () => {
  const sb = sandbox();
  try {
    run(['init', '--manifest', sb.manifestPath, '--ledger', sb.ledgerPath]);
    run(['log', '--manifest', sb.manifestPath, '--ledger', sb.ledgerPath, '--target', 'api.example.com', '--action', 'recon', '--result', 'ok', '--at', AT]);
    run(['log', '--manifest', sb.manifestPath, '--ledger', sb.ledgerPath, '--target', 'pay.example.com', '--action', 'scan', '--at', AT]);

    const outPath = join(sb.dir, 'report.md');
    const { code, stdout } = run(['report', '--manifest', sb.manifestPath, '--ledger', sb.ledgerPath, '--out', outPath]);
    assert.equal(code, 0);
    assert.ok(stdout.includes('合规报告已生成'));

    const md = readFileSync(outPath, 'utf8');
    assert.ok(md.includes('# 授权测试合规报告'));
    assert.ok(md.includes('越界尝试与被拒记录'));
    assert.ok(md.includes('pay.example.com'));
    assert.ok(md.includes('AUTH-001'));
    assert.ok(md.includes('CISO'), '报告应写出签署人身份');
  } finally {
    sb.cleanup();
  }
});

test('report --stdout 打到标准输出且不落文件', () => {
  const sb = sandbox();
  try {
    run(['init', '--manifest', sb.manifestPath, '--ledger', sb.ledgerPath]);
    const { code, stdout } = run(['report', '--manifest', sb.manifestPath, '--ledger', sb.ledgerPath, '--stdout']);
    assert.equal(code, 0);
    assert.ok(stdout.includes('# 授权测试合规报告'));
    assert.ok(!existsSync(join(sb.dir, 'compliance-report.md')));
  } finally {
    sb.cleanup();
  }
});

test('report --json 产出可被程序消费的结构化报告', () => {
  const sb = sandbox();
  try {
    run(['init', '--manifest', sb.manifestPath, '--ledger', sb.ledgerPath]);
    run(['log', '--manifest', sb.manifestPath, '--ledger', sb.ledgerPath, '--target', 'evil.com', '--action', 'scan', '--at', AT]);

    const jsonPath = join(sb.dir, 'report.json');
    const { code } = run(['report', '--manifest', sb.manifestPath, '--ledger', sb.ledgerPath, '--out', join(sb.dir, 'r.md'), '--json', jsonPath]);
    assert.equal(code, 0);

    const json = JSON.parse(readFileSync(jsonPath, 'utf8'));
    assert.equal(json.engagement.id, 'ENG-001');
    assert.equal(json.integrity.chainOk, true);
    assert.equal(json.statistics.decisions.denied, 1);
  } finally {
    sb.cleanup();
  }
});

test('report 在链断裂时返回 3 并在报告里标注', () => {
  const sb = sandbox();
  try {
    run(['init', '--manifest', sb.manifestPath, '--ledger', sb.ledgerPath]);
    const lines = readFileSync(sb.ledgerPath, 'utf8').trim().split('\n');
    const genesis = JSON.parse(lines[0]);
    genesis.actor = 'mallory';
    writeFileSync(sb.ledgerPath, JSON.stringify(genesis) + '\n', 'utf8');

    const { code, stdout } = run(['report', '--manifest', sb.manifestPath, '--ledger', sb.ledgerPath, '--stdout']);
    assert.equal(code, 3);
    assert.ok(stdout.includes('哈希链校验失败'));
    assert.ok(stdout.includes('不可作为合规证据使用'));
  } finally {
    sb.cleanup();
  }
});

test('anchor 输出可提交 git 的锚定行与原因说明', () => {
  const sb = sandbox();
  try {
    run(['init', '--manifest', sb.manifestPath, '--ledger', sb.ledgerPath]);
    const { code, stdout } = run(['anchor', '--ledger', sb.ledgerPath]);
    assert.equal(code, 0);
    assert.match(stdout, /engagement-ledger 1 [a-f0-9]{64}/);
    assert.ok(stdout.includes('ANCHORS.txt'), '应给出具体落点');
    assert.ok(stdout.includes('整份重算'));
  } finally {
    sb.cleanup();
  }
});

test('anchor 在链断裂时返回 3 且不给出可锚定的哈希', () => {
  const sb = sandbox();
  try {
    run(['init', '--manifest', sb.manifestPath, '--ledger', sb.ledgerPath]);
    const genesis = JSON.parse(readFileSync(sb.ledgerPath, 'utf8').trim());
    genesis.timestamp = '2020-01-01T00:00:00.000Z';
    writeFileSync(sb.ledgerPath, JSON.stringify(genesis) + '\n', 'utf8');

    const { code, stdout } = run(['anchor', '--ledger', sb.ledgerPath]);
    assert.equal(code, 3);
    assert.ok(stdout.includes('校验失败，无法锚定'));
    assert.ok(stdout.includes('BROKEN'));
  } finally {
    sb.cleanup();
  }
});

test('status 给出一页纸概览', () => {
  const sb = sandbox();
  try {
    run(['init', '--manifest', sb.manifestPath, '--ledger', sb.ledgerPath]);
    run(['log', '--manifest', sb.manifestPath, '--ledger', sb.ledgerPath, '--target', 'pay.example.com', '--action', 'scan', '--at', AT]);

    const { code, stdout } = run(['status', '--manifest', sb.manifestPath, '--ledger', sb.ledgerPath]);
    assert.equal(code, 0);
    assert.ok(stdout.includes('授权状态'));
    assert.ok(stdout.includes('ENG-001'));
    assert.ok(stdout.includes('授权有效期内'));
    assert.ok(stdout.includes('⛔ pay.example.com（排除，优先级更高）'));
    assert.ok(stdout.includes('被拒绝的尝试（纪律证据）'));
  } finally {
    sb.cleanup();
  }
});

test('status 在日志缺失时说明尚未初始化', () => {
  const sb = sandbox();
  try {
    const { stdout } = run(['status', '--manifest', sb.manifestPath, '--ledger', sb.ledgerPath]);
    assert.ok(stdout.includes('尚未初始化'));
  } finally {
    sb.cleanup();
  }
});

test('log 记录 recordedAt，区分事件时间与写入时间', () => {
  const sb = sandbox();
  try {
    run(['init', '--manifest', sb.manifestPath, '--ledger', sb.ledgerPath]);
    run(['log', '--manifest', sb.manifestPath, '--ledger', sb.ledgerPath, '--target', 'example.com', '--action', 'scan', '--at', AT]);

    const logged = JSON.parse(readFileSync(sb.ledgerPath, 'utf8').trim().split('\n')[1]);
    assert.equal(logged.timestamp, '2026-09-15T12:00:00.000Z', 'timestamp 是事件时间');
    assert.ok(logged.recordedAt, 'recordedAt 是写入时间');
    assert.match(logged.recordedAt, /^\d{4}-\d{2}-\d{2}T/);
  } finally {
    sb.cleanup();
  }
});

test('补录记录被标记 backfilled 并给出提示', () => {
  const sb = sandbox();
  try {
    run(['init', '--manifest', sb.manifestPath, '--ledger', sb.ledgerPath]);
    /* AT 是 2026-09-15，与"现在"相差远超 5 分钟 */
    const { stdout } = run(['log', '--manifest', sb.manifestPath, '--ledger', sb.ledgerPath, '--target', 'example.com', '--action', 'scan', '--at', AT]);

    assert.ok(stdout.includes('补录记录'));
    assert.ok(stdout.includes('写入顺序'));

    const logged = JSON.parse(readFileSync(sb.ledgerPath, 'utf8').trim().split('\n')[1]);
    assert.equal(logged.backfilled, true);
    assert.equal(typeof logged.recordedSkewSeconds, 'number');
    assert.ok(logged.recordedSkewSeconds > 300);
  } finally {
    sb.cleanup();
  }
});

test('刚发生的动作不算补录（不误标）', () => {
  const sb = sandbox();
  try {
    run(['init', '--manifest', sb.manifestPath, '--ledger', sb.ledgerPath]);
    const { stdout } = run(['log', '--manifest', sb.manifestPath, '--ledger', sb.ledgerPath, '--target', 'example.com', '--action', 'scan']);

    assert.ok(!stdout.includes('补录记录'));
    const logged = JSON.parse(readFileSync(sb.ledgerPath, 'utf8').trim().split('\n')[1]);
    assert.equal(logged.backfilled, undefined);
  } finally {
    sb.cleanup();
  }
});

/* ------------------------- 委托归属 ------------------------- */

test('log 拒绝向属于另一次委托的日志追加记录', () => {
  const a = sandbox('ENG-AAA');
  const b = sandbox('ENG-BBB');
  try {
    run(['init', '--manifest', a.manifestPath, '--ledger', a.ledgerPath]);

    const r = run(['log', '--manifest', b.manifestPath, '--ledger', a.ledgerPath,
      '--target', 'example.com', '--action', 'scan', '--at', AT]);

    assert.equal(r.code, 1, '应拒绝追加');
    assert.match(r.stderr, /日志属于另一次委托/);
    assert.match(r.stderr, /ENG-AAA/, '应指出日志实际所属');
    assert.match(r.stderr, /ENG-BBB/, '应指出当前凭证');
    /* 关键：被拒时日志未被改动 */
    assert.equal(readFileSync(a.ledgerPath, 'utf8').trim().split('\n').length, 1);
  } finally {
    a.cleanup();
    b.cleanup();
  }
});

test('report 检出已混入的其它委托记录（第 5.1 节）并返回 3', () => {
  const a = sandbox('ENG-AAA');
  try {
    run(['init', '--manifest', a.manifestPath, '--ledger', a.ledgerPath]);

    /* 模拟日志被合并 / 由旧版本写入的情形：直接追加一条属于别的委托的记录 */
    appendEntry(a.ledgerPath, {
      seq: 0, type: 'action', actor: 'someone', action: 'scan', target: 'other.example.com',
      decision: 'allowed', result: 'merged', timestamp: '2026-09-14T00:00:00.000Z',
      engagementId: 'ENG-OTHER',
    });

    /* 链本身是完整的 —— 这正是这个检查存在的理由 */
    assert.equal(run(['verify', '--ledger', a.ledgerPath]).code, 3, 'verify 应报归属异常');

    const r = run(['report', '--manifest', a.manifestPath, '--ledger', a.ledgerPath, '--stdout']);
    assert.equal(r.code, 3);
    assert.match(r.stdout, /委托归属异常/);
    assert.match(r.stdout, /ENG-OTHER/);
    assert.match(r.stdout, /不属于本次委托的证据范围/);
    assert.match(r.stdout, /不可直接交付客户/);
  } finally {
    a.cleanup();
  }
});

test('status 显示委托归属并给出处理提示', () => {
  const a = sandbox('ENG-AAA');
  try {
    run(['init', '--manifest', a.manifestPath, '--ledger', a.ledgerPath]);
    appendEntry(a.ledgerPath, {
      seq: 0, type: 'action', actor: 'x', action: 'scan', target: 'other.com',
      decision: 'allowed', timestamp: '2026-09-14T00:00:00.000Z', engagementId: 'ENG-OTHER',
    });

    const r = run(['status', '--manifest', a.manifestPath, '--ledger', a.ledgerPath]);
    assert.equal(r.code, 3);
    assert.match(r.stdout, /委托归属：❌/);
    assert.match(r.stdout, /混有别的委托的记录/);
  } finally {
    a.cleanup();
  }
});

test('归属一致时 status/report/verify 都正常通过', () => {
  const sb = sandbox();
  try {
    run(['init', '--manifest', sb.manifestPath, '--ledger', sb.ledgerPath]);
    run(['log', '--manifest', sb.manifestPath, '--ledger', sb.ledgerPath,
      '--target', 'example.com', '--action', 'scan', '--at', AT]);

    assert.equal(run(['verify', '--ledger', sb.ledgerPath, '--manifest', sb.manifestPath]).code, 0);
    assert.equal(run(['status', '--manifest', sb.manifestPath, '--ledger', sb.ledgerPath]).code, 0);
    assert.equal(run(['report', '--manifest', sb.manifestPath, '--ledger', sb.ledgerPath, '--stdout']).code, 0);
  } finally {
    sb.cleanup();
  }
});

test('status 列出最近动作（流水入口）', () => {
  const sb = sandbox();
  try {
    run(['init', '--manifest', sb.manifestPath, '--ledger', sb.ledgerPath]);
    run(['log', '--manifest', sb.manifestPath, '--ledger', sb.ledgerPath,
      '--target', 'example.com', '--action', 'scan', '--result', '3 findings', '--at', AT]);

    const r = run(['status', '--manifest', sb.manifestPath, '--ledger', sb.ledgerPath]);
    assert.match(r.stdout, /最近动作/);
    assert.match(r.stdout, /scan → example\.com（3 findings）/);
  } finally {
    sb.cleanup();
  }
});

/* ------------------------- 窗口合规 ------------------------- */

test('report 检出发生在授权窗口之外的已执行动作并返回 3', () => {
  const sb = sandbox();
  try {
    run(['init', '--manifest', sb.manifestPath, '--ledger', sb.ledgerPath]);
    run(['log', '--manifest', sb.manifestPath, '--ledger', sb.ledgerPath,
      '--target', 'example.com', '--action', 'scan', '--at', AT]);

    /* 模拟"窗口事后被改动过"或"绕过了校验门写进来的记录" */
    appendEntry(sb.ledgerPath, {
      seq: 0, type: 'action', actor: 'alice', action: 'recon', target: 'example.com',
      decision: 'allowed', result: 'late', timestamp: '2027-03-01T00:00:00.000Z',
      engagementId: 'ENG-001',
    });

    const r = run(['report', '--manifest', sb.manifestPath, '--ledger', sb.ledgerPath, '--stdout']);
    assert.equal(r.code, 3, `应返回 3，实际 ${r.code}`);
    assert.match(r.stdout, /### 4\.1 ⚠️ 发生在授权窗口之外的已执行动作/);
    assert.match(r.stdout, /窗口之后/);
    assert.match(r.stdout, /2027-03-01/);
  } finally {
    sb.cleanup();
  }
});

test('窗口内的动作不会触发 4.1 节', () => {
  const sb = sandbox();
  try {
    run(['init', '--manifest', sb.manifestPath, '--ledger', sb.ledgerPath]);
    run(['log', '--manifest', sb.manifestPath, '--ledger', sb.ledgerPath,
      '--target', 'example.com', '--action', 'scan', '--at', AT]);

    const r = run(['report', '--manifest', sb.manifestPath, '--ledger', sb.ledgerPath, '--stdout']);
    assert.equal(r.code, 0);
    assert.ok(!r.stdout.includes('发生在授权窗口之外的已执行动作'));
  } finally {
    sb.cleanup();
  }
});

/* ------------------------- 参数解析 ------------------------- */

test('--key=value 与 --key value 两种写法都支持', () => {
  const sb = sandbox();
  try {
    run(['init', '--manifest', sb.manifestPath, '--ledger', sb.ledgerPath]);
    const a = run(['check', `--manifest=${sb.manifestPath}`, `--ledger=${sb.ledgerPath}`, '--target=example.com', '--action=scan', `--at=${AT}`]);
    const b = run(['check', '--manifest', sb.manifestPath, '--ledger', sb.ledgerPath, '--target', 'example.com', '--action', 'scan', '--at', AT]);
    assert.equal(a.code, 0);
    assert.equal(b.code, 0);
  } finally {
    sb.cleanup();
  }
});

test('非法 JSON 凭证给出可读错误而不是堆栈', () => {
  const sb = sandbox();
  try {
    writeFileSync(sb.manifestPath, '{ broken json', 'utf8');
    const { code, stderr } = run(['init', '--manifest', sb.manifestPath, '--ledger', sb.ledgerPath]);
    assert.equal(code, 1);
    assert.match(stderr, /不是合法 JSON/);
    assert.ok(!stderr.includes('at Object.'), '不应把堆栈抛给用户');
  } finally {
    sb.cleanup();
  }
});

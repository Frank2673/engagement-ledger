#!/usr/bin/env node
/**
 * 运营级校验（本地与 CI 共用同一份代码）
 *
 * 为什么不写在 workflow 的 bash 片段里：
 * 那些片段在本地跑不了（受限环境下 bash 起不来），于是只能"推上去等 CI 告诉你"。
 * 本项目上一次提交就是这样挂掉的 —— 两个失败全出在 YAML 里的 bash 语法与用法上，
 * 与被测代码无关。把校验搬进 Node 脚本后，同一条命令在本地和 CI 的结果必然一致。
 *
 * 校验内容分四组：
 *   A. 端到端闭环：授权 → 放行 → 拦截 → 自证 → 报告
 *   B. 篡改检测：改内容 / 删记录 / HMAC
 *   C. 授权凭证守卫：四种坏凭证必须被拒
 *   D. 安全红线：守卫本身必须有效（负向验证）
 *
 * 用法：node scripts/verify.mjs [--artifacts <目录>]
 */

import { mkdtempSync, rmSync, writeFileSync, readFileSync, cpSync, existsSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';

import { main } from '../src/index.mjs';
import { runChecks, DEFAULT_ROOT } from './check-zero-deps.mjs';
import { checkTables } from './check-report-tables.mjs';
import { appendEntry } from '../src/lib/ledger.mjs';
import { intakeAuthorization } from './intake-authorization.mjs';
import { computeEntryHash, GENESIS_HASH } from '../src/lib/crypto.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

/** 可选的证据输出目录：CI 用它把生成的报告与日志传成构建产物 */
const artifactsIndex = process.argv.indexOf('--artifacts');
const ARTIFACTS = artifactsIndex !== -1 && process.argv[artifactsIndex + 1]
  ? resolve(process.argv[artifactsIndex + 1])
  : null;

if (ARTIFACTS) mkdirSync(ARTIFACTS, { recursive: true });

/* ============================ 基础设施 ============================ */

const results = [];

function check(name, fn) {
  try {
    fn();
    results.push({ name, ok: true });
    process.stdout.write(`  ✅ ${name}\n`);
  } catch (err) {
    results.push({ name, ok: false, error: err.message });
    process.stdout.write(`  ❌ ${name}\n     ${err.message.split('\n').join('\n     ')}\n`);
  }
}

function group(title) {
  process.stdout.write(`\n${title}\n`);
}

/** 在进程内驱动 CLI 并捕获输出（不起子进程，任何环境都能跑） */
function runCli(argv) {
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

const AT = '2026-09-15T10:00:00Z';

/** 造一个隔离的委托目录（复制示例凭证与授权书） */
function makeEngagement(tag) {
  const dir = mkdtempSync(join(tmpdir(), `el-verify-${tag}-`));
  cpSync(join(ROOT, 'fixtures', 'demo-engagement.json'), join(dir, 'engagement.json'));
  cpSync(join(ROOT, 'fixtures', 'demo-authorization.md'), join(dir, 'demo-authorization.md'));
  return {
    dir,
    manifest: join(dir, 'engagement.json'),
    ledger: join(dir, 'ledger.jsonl'),
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
  };
}

function logLines(path) {
  return readFileSync(path, 'utf8').trim().split('\n').map((l) => JSON.parse(l));
}

/* ============================ A. 端到端闭环 ============================ */

const A = makeEngagement('a');

group('A. 端到端闭环');

check('A1 用凭证初始化日志，并核验授权书未被替换', () => {
  const r = runCli(['init', '--manifest', A.manifest, '--ledger', A.ledger]);
  assert.equal(r.code, 0, `init 应成功，实际退出码 ${r.code}\n${r.stderr}`);
  assert.match(r.stdout, /已初始化审计日志/);
  assert.match(r.stdout, /授权文件核验通过/);
  assert.match(r.stdout, /纯哈希链/, '未提供密钥时应说明这是纯哈希链');

  const entries = logLines(A.ledger);
  assert.equal(entries.length, 1);
  assert.equal(entries[0].type, 'genesis');
  assert.equal(entries[0].prevHash, '0'.repeat(64));
});

check('A2 范围内的动作放行（退出码 0）', () => {
  const r = runCli(['log', '--manifest', A.manifest, '--ledger', A.ledger,
    '--target', 'api.example.com', '--action', 'recon', '--result', '12 endpoints',
    '--evidence', 'logs/recon-001.txt', '--at', AT]);
  assert.equal(r.code, 0, `应放行，实际退出码 ${r.code}\n${r.stdout}`);
  assert.match(r.stdout, /✅ 允许执行/);

  const last = logLines(A.ledger).at(-1);
  assert.equal(last.decision, 'allowed');
  assert.equal(last.type, 'action');
  assert.equal(last.evidence, 'logs/recon-001.txt');
  assert.ok(Array.isArray(last.checks) && last.checks.length === 7, '判定轨迹应一并入库');
});

check('A3 越界目标被拦下并留痕（退出码 2）', () => {
  const r = runCli(['log', '--manifest', A.manifest, '--ledger', A.ledger,
    '--target', 'pay.example.com', '--action', 'scan', '--at', AT]);
  assert.equal(r.code, 2, `应拒绝，实际退出码 ${r.code}`);
  assert.match(r.stdout, /排除优先级高于纳入/);
  assert.match(r.stdout, /未执行/);

  const last = logLines(A.ledger).at(-1);
  assert.equal(last.decision, 'denied');
  assert.equal(last.result, 'not-executed');
});

check('A4 硬性禁止动作任何授权都放行不了（退出码 2）', () => {
  const r = runCli(['log', '--manifest', A.manifest, '--ledger', A.ledger,
    '--target', 'api.example.com', '--action', 'ransomware', '--at', AT]);
  assert.equal(r.code, 2);
  assert.match(r.stdout, /硬性禁止项/);
});

check('A5 授权窗口之外的动作用 check 试判即被拒，且不写日志', () => {
  const before = readFileSync(A.ledger, 'utf8');
  const r = runCli(['check', '--manifest', A.manifest, '--ledger', A.ledger,
    '--target', 'api.example.com', '--action', 'recon', '--at', '2027-01-01T00:00:00Z']);
  assert.equal(r.code, 2);
  assert.match(r.stdout, /超出授权窗口/);
  assert.equal(readFileSync(A.ledger, 'utf8'), before, 'check 不应改动日志');
});

check('A6 日志哈希链校验通过', () => {
  const r = runCli(['verify', '--ledger', A.ledger]);
  assert.equal(r.code, 0, r.stdout);
  assert.match(r.stdout, /哈希链完整/);
});

check('A7 anchor 输出格式正确的锚定行', () => {
  const r = runCli(['anchor', '--ledger', A.ledger]);
  assert.equal(r.code, 0);
  assert.match(r.stdout, /^ {2}engagement-ledger \d+ [a-f0-9]{64}$/m, '锚定行格式不符');
  assert.match(r.stdout, /ANCHORS\.txt/, '应给出具体落点');
});

check('A8 合规报告内容齐全且表格结构一致', () => {
  const out = join(A.dir, 'report.md');
  const r = runCli(['report', '--manifest', A.manifest, '--ledger', A.ledger, '--out', out]);
  assert.equal(r.code, 0, r.stdout);

  const md = readFileSync(out, 'utf8');
  for (const needle of ['# 授权测试合规报告', '### 3.2 动作流水', '越界尝试与被拒记录',
    'pay.example.com', 'logs/recon-001.txt', '✅ 哈希链完整',
    '篡改可发现 ≠ 不可伪造', '外部锚定', '边界声明', 'AUTH-2026-DEMO-001']) {
    assert.ok(md.includes(needle), `报告缺少：${needle}`);
  }
  /* 报告里绝不能出现 undefined —— 那意味着某个字段没被规范化 */
  assert.ok(!md.includes('undefined'), '报告里出现了 undefined，说明有字段未被规范化');

  const problems = checkTables(md);
  assert.equal(problems.length, 0, `报告表格结构异常 ${problems.length} 处`);
});

check('A9 JSON 报告统计正确，可供程序消费', () => {
  const out = join(A.dir, 'report.json');
  const r = runCli(['report', '--manifest', A.manifest, '--ledger', A.ledger,
    '--out', join(A.dir, 'r2.md'), '--json', out]);
  assert.equal(r.code, 0);

  const json = JSON.parse(readFileSync(out, 'utf8'));
  assert.equal(json.statistics.decisions.denied, 2, '应记录 2 次拒绝');
  assert.equal(json.statistics.decisions.allowed, 1, '应记录 1 次允许');
  assert.equal(json.integrity.chainOk, true);
  assert.equal(json.engagement.id, 'ENG-2026-DEMO-001');
  assert.ok(json.engagement.hardForbidden.includes('ransomware'));
});

check('A10 status 给出一页纸概览', () => {
  const r = runCli(['status', '--manifest', A.manifest, '--ledger', A.ledger]);
  assert.equal(r.code, 0, r.stdout);
  assert.match(r.stdout, /授权状态/);
  assert.match(r.stdout, /被拒绝的尝试（纪律证据）/);
});

check('A11 IPv6 目标按范围放行/拦截，方括号写法也能识别', () => {
  const inScope = runCli(['check', '--manifest', A.manifest,
    '--target', '2001:db8::1', '--action', 'scan', '--at', AT]);
  assert.equal(inScope.code, 0, `IPv6 范围内目标应放行\n${inScope.stdout}`);

  const bracketed = runCli(['check', '--manifest', A.manifest,
    '--target', '[2001:db8::1]', '--action', 'scan', '--at', AT]);
  assert.equal(bracketed.code, 0, '带方括号的 IPv6 也应识别');

  const outOfScope = runCli(['check', '--manifest', A.manifest,
    '--target', '2001:db9::1', '--action', 'scan', '--at', AT]);
  assert.equal(outOfScope.code, 2, 'IPv6 范围外目标应被拦下');
  assert.match(outOfScope.stdout, /不在 inScope/);
});

check('A12 凭证里写错的 IP 不会被静默当成域名放行', () => {
  const C2 = makeEngagement('a12');
  try {
    const manifest = JSON.parse(readFileSync(C2.manifest, 'utf8'));
    manifest.engagement.scope.inScope = ['999.1.1.1'];
    writeFileSync(C2.manifest, JSON.stringify(manifest), 'utf8');

    const r = runCli(['init', '--manifest', C2.manifest, '--ledger', C2.ledger]);
    assert.notEqual(r.code, 0, '非法 IP 范围规则必须被拒绝');
    assert.match(r.stderr, /范围规则格式不合法/);
  } finally {
    C2.cleanup();
  }
});

/* 把这次闭环产出的真实证据留一份（CI 会传成构建产物供人工查看） */
if (ARTIFACTS) {
  for (const f of ['ledger.jsonl', 'report.md', 'report.json']) {
    const src = join(A.dir, f);
    if (existsSync(src)) cpSync(src, join(ARTIFACTS, f));
  }
}

A.cleanup();

/* ============================ B. 篡改检测 ============================ */

group('\nB. 篡改检测（负向验证：必须能发现问题）');

check('B1 改动一条记录的内容会被检出', () => {
  const S = makeEngagement('b1');
  try {
    runCli(['init', '--manifest', S.manifest, '--ledger', S.ledger]);
    runCli(['log', '--manifest', S.manifest, '--ledger', S.ledger,
      '--target', 'pay.example.com', '--action', 'scan', '--at', AT]);

    /* 把越界目标改成范围内的，试图掩盖曾经尝试越界 */
    const lines = readFileSync(S.ledger, 'utf8').trim().split('\n');
    const e = JSON.parse(lines[1]);
    assert.equal(e.target, 'pay.example.com');
    e.target = 'api.example.com';
    lines[1] = JSON.stringify(e);
    writeFileSync(S.ledger, lines.join('\n') + '\n', 'utf8');

    const r = runCli(['verify', '--ledger', S.ledger]);
    assert.equal(r.code, 3, `应检出篡改，实际退出码 ${r.code}`);
    assert.match(r.stdout, /哈希链校验失败/);
    assert.match(r.stdout, /不可作为合规证据使用/);
  } finally {
    S.cleanup();
  }
});

check('B2 删掉中间一条记录会被检出（序号不连续）', () => {
  const S = makeEngagement('b2');
  try {
    runCli(['init', '--manifest', S.manifest, '--ledger', S.ledger]);
    /* 这三个目标都在示例凭证的授权范围内 */
    for (const t of ['api.example.com', 'staging.example.com', '192.0.2.5']) {
      const r = runCli(['log', '--manifest', S.manifest, '--ledger', S.ledger,
        '--target', t, '--action', 'recon', '--at', AT]);
      assert.equal(r.code, 0, `${t} 应在授权范围内，实际退出码 ${r.code}`);
    }

    const lines = readFileSync(S.ledger, 'utf8').trim().split('\n');
    assert.equal(lines.length, 4);
    lines.splice(2, 1);
    writeFileSync(S.ledger, lines.join('\n') + '\n', 'utf8');

    const r = runCli(['verify', '--ledger', S.ledger]);
    assert.equal(r.code, 3);
    assert.match(r.stdout, /序号不连续/);
  } finally {
    S.cleanup();
  }
});

check('B3 链断裂时 anchor 拒绝给出可锚定的哈希', () => {
  const S = makeEngagement('b3');
  try {
    runCli(['init', '--manifest', S.manifest, '--ledger', S.ledger]);
    const genesis = JSON.parse(readFileSync(S.ledger, 'utf8').trim());
    genesis.timestamp = '2020-01-01T00:00:00.000Z';
    writeFileSync(S.ledger, JSON.stringify(genesis) + '\n', 'utf8');

    const r = runCli(['anchor', '--ledger', S.ledger]);
    assert.equal(r.code, 3);
    /* 链坏时不给出锚定行 —— 锚定一份坏链只会把坏数据钉进外部记录 */
    assert.match(r.stdout, /链已断裂，不给出锚定行/);
    assert.match(r.stdout, /锚定一份坏链只会把坏数据钉进外部记录/);
    assert.ok(!/^ {2}engagement-ledger \d+ [a-f0-9]{64}$/m.test(r.stdout), '不应输出任何可用锚定行');
  } finally {
    S.cleanup();
  }
});

check('B4 HMAC 生效：带密钥通过，不带密钥失败', () => {
  const S = makeEngagement('b4');
  const varName = 'EL_VERIFY_KEY';
  process.env[varName] = 'verify-secret-key';
  try {
    const init = runCli(['init', '--manifest', S.manifest, '--ledger', S.ledger, '--hmac-key-env', varName]);
    assert.equal(init.code, 0);
    assert.match(init.stdout, /哈希链 \+ HMAC/, '应说明启用了 HMAC');

    const withKey = runCli(['verify', '--ledger', S.ledger, '--hmac-key-env', varName]);
    assert.equal(withKey.code, 0, withKey.stdout);

    const withoutKey = runCli(['verify', '--ledger', S.ledger]);
    assert.equal(withoutKey.code, 3, '不带密钥校验 HMAC 链却通过了 —— 签名失效');
  } finally {
    delete process.env[varName];
    S.cleanup();
  }
});

check('B5 补录记录被标记（区分事件时间与写入时间）', () => {
  const S = makeEngagement('b5');
  try {
    runCli(['init', '--manifest', S.manifest, '--ledger', S.ledger]);
    const r = runCli(['log', '--manifest', S.manifest, '--ledger', S.ledger,
      '--target', 'api.example.com', '--action', 'recon', '--at', AT]);
    assert.match(r.stdout, /补录记录/);

    const last = logLines(S.ledger).at(-1);
    assert.equal(last.backfilled, true);
    assert.ok(last.recordedAt, 'recordedAt 必须存在');
  } finally {
    S.cleanup();
  }
});

check('B6 log 拒绝向属于另一次委托的日志追加记录（预防）', () => {
  const A = makeEngagement('b6a');
  const B = makeEngagement('b6b');
  try {
    /* 把第二份凭证的委托编号改掉，模拟"两次委托共用一个日志路径" */
    const second = JSON.parse(readFileSync(B.manifest, 'utf8'));
    second.engagement.id = 'ENG-OTHER-999';
    writeFileSync(B.manifest, JSON.stringify(second), 'utf8');

    runCli(['init', '--manifest', A.manifest, '--ledger', A.ledger]);
    const before = readFileSync(A.ledger, 'utf8');

    const r = runCli(['log', '--manifest', B.manifest, '--ledger', A.ledger,
      '--target', 'api.example.com', '--action', 'recon', '--at', AT]);

    assert.equal(r.code, 1, `应拒绝追加，实际退出码 ${r.code}`);
    assert.match(r.stderr, /日志属于另一次委托/);
    assert.match(r.stderr, /ENG-OTHER-999/, '应指出当前凭证的编号');
    assert.equal(readFileSync(A.ledger, 'utf8'), before, '被拒时日志不得被改动');
  } finally {
    A.cleanup();
    B.cleanup();
  }
});

check('B7 已混入的其它委托记录会被检出（检测）', () => {
  const S = makeEngagement('b7');
  try {
    runCli(['init', '--manifest', S.manifest, '--ledger', S.ledger]);

    /* 模拟日志被合并、或由旧版本 / 外部工具写入的情形 */
    appendEntry(S.ledger, {
      seq: 0, type: 'action', actor: 'someone', action: 'scan', target: 'other.example.com',
      decision: 'allowed', result: 'merged', timestamp: '2026-09-14T00:00:00.000Z',
      engagementId: 'ENG-OTHER',
    });

    /* 链本身是完整的 —— 这正是该检查存在的理由 */
    const verify = runCli(['verify', '--ledger', S.ledger]);
    assert.equal(verify.code, 3, `verify 应报归属异常，实际退出码 ${verify.code}`);
    assert.match(verify.stdout, /委托归属异常/);

    const report = runCli(['report', '--manifest', S.manifest, '--ledger', S.ledger, '--stdout']);
    assert.equal(report.code, 3);
    assert.match(report.stdout, /### 5\.1 ⚠️ 委托归属异常/);
    assert.match(report.stdout, /ENG-OTHER/);
    assert.match(report.stdout, /不可直接交付客户/);
  } finally {
    S.cleanup();
  }
});

check('B8 落在授权窗口之外的已执行动作会被检出', () => {
  const S = makeEngagement('b8');
  try {
    runCli(['init', '--manifest', S.manifest, '--ledger', S.ledger]);
    runCli(['log', '--manifest', S.manifest, '--ledger', S.ledger,
      '--target', 'api.example.com', '--action', 'recon', '--at', AT]);

    /* 校验门本应拦住窗口外的动作，所以这条记录只能是"窗口事后被改动过"
       或"绕过了校验门写进来的" —— 两种都必须让审计方看见 */
    appendEntry(S.ledger, {
      seq: 0, type: 'action', actor: 'alice', action: 'scan', target: 'api.example.com',
      decision: 'allowed', result: 'late', timestamp: '2027-03-01T00:00:00.000Z',
      engagementId: 'ENG-2026-DEMO-001',
    });

    const report = runCli(['report', '--manifest', S.manifest, '--ledger', S.ledger, '--stdout']);
    assert.equal(report.code, 3, `应返回 3，实际 ${report.code}`);
    assert.match(report.stdout, /### 4\.1 ⚠️ 发生在授权窗口之外的已执行动作/);
    assert.match(report.stdout, /窗口之后/);
    assert.match(report.stdout, /绕过了校验门被写进来/);

    /* 反向确认：窗口内的动作不触发该节 */
    const clean = makeEngagement('b8-clean');
    try {
      runCli(['init', '--manifest', clean.manifest, '--ledger', clean.ledger]);
      runCli(['log', '--manifest', clean.manifest, '--ledger', clean.ledger,
        '--target', 'api.example.com', '--action', 'recon', '--at', AT]);
      const ok = runCli(['report', '--manifest', clean.manifest, '--ledger', clean.ledger, '--stdout']);
      assert.equal(ok.code, 0, `窗口内动作不应触发告警，实际 ${ok.code}`);
      assert.ok(!ok.stdout.includes('发生在授权窗口之外的已执行动作'), '不应出现 4.1 节');
    } finally {
      clean.cleanup();
    }
  } finally {
    S.cleanup();
  }
});

check('B9 整链重写：verify 会通过，但锚定能抓住（核心能力实测）', () => {
  const S = makeEngagement('b9');
  try {
    const anchorsPath = join(S.dir, 'ANCHORS.txt');

    /* 1. 建一份含"越界被拒"记录的日志，并锚定 */
    runCli(['init', '--manifest', S.manifest, '--ledger', S.ledger]);
    runCli(['log', '--manifest', S.manifest, '--ledger', S.ledger,
      '--target', 'api.example.com', '--action', 'recon', '--evidence', 'logs/a.txt', '--at', AT]);
    runCli(['log', '--manifest', S.manifest, '--ledger', S.ledger,
      '--target', 'pay.example.com', '--action', 'scan', '--at', AT]);

    const anchored = runCli(['anchor', '--ledger', S.ledger, '--append', anchorsPath]);
    assert.equal(anchored.code, 0, anchored.stderr);
    assert.match(anchored.stdout, /已追加锚定行/);

    /* 幂等：同一状态重复锚定不该把文件撑大 */
    const again = runCli(['anchor', '--ledger', S.ledger, '--append', anchorsPath]);
    assert.match(again.stdout, /已经锚定过/);
    assert.equal(readFileSync(anchorsPath, 'utf8').trim().split('\n').length, 1);

    /* 2. 攻击前：锚定校验通过，且链头一致 */
    const before = runCli(['verify-anchor', '--ledger', S.ledger, '--anchors', anchorsPath]);
    assert.equal(before.code, 0, before.stdout);
    assert.match(before.stdout, /最新锚定与当前链头完全一致/);

    /* 3. 攻击：掩改越界记录，然后把整条链从头重算 —— 攻击者知道算法 */
    const entries = logLines(S.ledger);
    const victim = entries.find((e) => e.decision === 'denied');
    assert.ok(victim, '应存在一条被拒记录作为掩改目标');
    victim.target = 'api.example.com';
    victim.decision = 'allowed';
    victim.result = 'executed';

    let prev = GENESIS_HASH;
    for (const entry of entries) {
      entry.prevHash = prev;
      entry.hash = computeEntryHash(entry, prev);
      prev = entry.hash;
    }
    writeFileSync(S.ledger, entries.map((e) => JSON.stringify(e)).join('\n') + '\n', 'utf8');

    /* 4. 关键对照：单看日志，链条完全自洽 —— verify 放行 */
    const chainOnly = runCli(['verify', '--ledger', S.ledger]);
    assert.equal(chainOnly.code, 0, '重算后的链必须自洽（这正是攻击成立的前提）');
    assert.match(chainOnly.stdout, /哈希链完整/);

    /* 5. 与外部锚定比对才抓得住 —— 这才是锚定存在的全部理由 */
    const caught = runCli(['verify-anchor', '--ledger', S.ledger, '--anchors', anchorsPath]);
    assert.equal(caught.code, 3, `锚定应抓住整链重写，实际 ${caught.code}`);
    assert.match(caught.stdout, /这段历史被重写过/);
    assert.match(caught.stdout, /整链被重算替换的特征|整条链被重新算过一遍/);
    assert.match(caught.stdout, /核对 git 历史/);
  } finally {
    S.cleanup();
  }
});

check('B10 末尾截断（回滚）会被锚定发现', () => {
  const S = makeEngagement('b10');
  try {
    const anchorsPath = join(S.dir, 'ANCHORS.txt');
    runCli(['init', '--manifest', S.manifest, '--ledger', S.ledger]);
    for (const t of ['api.example.com', 'staging.example.com', '192.0.2.5']) {
      const r = runCli(['log', '--manifest', S.manifest, '--ledger', S.ledger,
        '--target', t, '--action', 'recon', '--evidence', 'logs/x.txt', '--at', AT]);
      assert.equal(r.code, 0, `${t} 应在授权范围内`);
    }
    runCli(['anchor', '--ledger', S.ledger, '--append', anchorsPath]);

    /* 砍掉最后两条 —— 截断后的链本身依然自洽 */
    const lines = readFileSync(S.ledger, 'utf8').trim().split('\n');
    writeFileSync(S.ledger, lines.slice(0, -2).join('\n') + '\n', 'utf8');

    const chainOnly = runCli(['verify', '--ledger', S.ledger]);
    assert.equal(chainOnly.code, 0, '截断后链条仍自洽 —— 单看日志发现不了');

    const caught = runCli(['verify-anchor', '--ledger', S.ledger, '--anchors', anchorsPath]);
    assert.equal(caught.code, 3);
    assert.match(caught.stdout, /被截断或回滚/);
  } finally {
    S.cleanup();
  }
});

check('B11 锚定文件缺失或无效时明确报错，不静默通过', () => {
  const S = makeEngagement('b11');
  try {
    runCli(['init', '--manifest', S.manifest, '--ledger', S.ledger]);

    /* 文件不存在 */
    const missing = runCli(['verify-anchor', '--ledger', S.ledger, '--anchors', join(S.dir, 'nope.txt')]);
    assert.equal(missing.code, 1, '缺文件应报用法错误');
    assert.match(missing.stderr, /找不到锚定文件/);

    /* 文件存在但没有可用锚定记录 */
    const emptyPath = join(S.dir, 'empty.txt');
    writeFileSync(emptyPath, '# 只有注释\n无关说明文字\n', 'utf8');
    const empty = runCli(['verify-anchor', '--ledger', S.ledger, '--anchors', emptyPath]);
    assert.equal(empty.code, 3, '没有锚定等于没有发现整链重写的手段');
    assert.match(empty.stdout, /没有任何可用的锚定记录/);
    assert.match(empty.stdout, /单看日志永远看不出/);
  } finally {
    S.cleanup();
  }
});

check('B12 链断裂时不给出锚定行（不把坏数据钉进外部记录）', () => {
  const S = makeEngagement('b12');
  try {
    runCli(['init', '--manifest', S.manifest, '--ledger', S.ledger]);
    const genesis = JSON.parse(readFileSync(S.ledger, 'utf8').trim());
    genesis.actor = 'mallory';
    writeFileSync(S.ledger, JSON.stringify(genesis) + '\n', 'utf8');

    const anchorsPath = join(S.dir, 'ANCHORS.txt');
    const r = runCli(['anchor', '--ledger', S.ledger, '--append', anchorsPath]);
    assert.equal(r.code, 3);
    assert.match(r.stdout, /不给出锚定行/);
    assert.ok(!existsSync(anchorsPath), '不应写出任何锚定行');
  } finally {
    S.cleanup();
  }
});

/* ============================ C. 授权凭证守卫 ============================ */

group('\nC. 授权凭证守卫（坏凭证必须被拒绝）');
const BAD_MANIFESTS = [
  {
    name: '缺少 authorization 段',
    expect: /authorization/,
    body: { engagement: { id: 'X', tester: 't', window: { from: '2026-01-01T00:00:00Z', to: '2026-12-31T00:00:00Z' }, scope: { inScope: ['a.example.com'] } } },
  },
  {
    name: '把硬性禁止动作写进 permittedActions',
    expect: /硬性禁止/,
    body: { engagement: { id: 'X', tester: 't', authorization: { reference: 'R', signedBy: 'S' }, window: { from: '2026-01-01T00:00:00Z', to: '2026-12-31T00:00:00Z' }, scope: { inScope: ['a.example.com'] }, permittedActions: ['ransomware'] } },
  },
  {
    name: 'inScope 为空',
    expect: /inScope/,
    body: { engagement: { id: 'X', tester: 't', authorization: { reference: 'R', signedBy: 'S' }, window: { from: '2026-01-01T00:00:00Z', to: '2026-12-31T00:00:00Z' }, scope: { inScope: [] } } },
  },
  {
    name: '缺少时间窗',
    expect: /window/,
    body: { engagement: { id: 'X', tester: 't', authorization: { reference: 'R', signedBy: 'S' }, scope: { inScope: ['a.example.com'] } } },
  },
  {
    name: 'documentSha256 格式非法',
    expect: /64 位十六进制/,
    body: { engagement: { id: 'X', tester: 't', authorization: { reference: 'R', signedBy: 'S', documentSha256: 'abc' }, window: { from: '2026-01-01T00:00:00Z', to: '2026-12-31T00:00:00Z' }, scope: { inScope: ['a.example.com'] } } },
  },
];

const C = mkdtempSync(join(tmpdir(), 'el-verify-c-'));
try {
  for (const [i, bad] of BAD_MANIFESTS.entries()) {
    check(`C${i + 1} ${bad.name} —— 必须被拒绝`, () => {
      const p = join(C, `bad-${i}.json`);
      writeFileSync(p, JSON.stringify(bad.body), 'utf8');
      const ledger = join(C, `never-${i}.jsonl`);

      const r = runCli(['init', '--manifest', p, '--ledger', ledger]);
      assert.notEqual(r.code, 0, '坏凭证竟然通过了');
      assert.match(r.stderr, bad.expect, `报错未指向原因（期望匹配 ${bad.expect}）`);
      assert.ok(!existsSync(ledger), '凭证校验失败却产生了日志文件');
    });
  }

  check(`C${BAD_MANIFESTS.length + 1} 授权书被换过时必须告警（但 init 仍可完成）`, () => {
    const S = makeEngagement('c6');
    try {
      writeFileSync(join(S.dir, 'demo-authorization.md'), '被人改过的授权书\n', 'utf8');
      const r = runCli(['init', '--manifest', S.manifest, '--ledger', S.ledger]);
      assert.equal(r.code, 0, 'init 不应因此失败');
      assert.match(r.stdout, /授权文件核验未通过/);
      assert.match(r.stdout, /不一致/);
    } finally {
      S.cleanup();
    }
  });

  check(`C${BAD_MANIFESTS.length + 2} 证据强制策略：缺证据拒绝记录、被拒动作不受影响`, () => {
    const S = makeEngagement('c7');
    try {
      const m = JSON.parse(readFileSync(S.manifest, 'utf8'));
      m.engagement.requireEvidence = true;
      writeFileSync(S.manifest, JSON.stringify(m), 'utf8');

      runCli(['init', '--manifest', S.manifest, '--ledger', S.ledger]);

      /* 放行但缺证据 → 拒绝写盘 */
      const before = readFileSync(S.ledger, 'utf8');
      const blocked = runCli(['log', '--manifest', S.manifest, '--ledger', S.ledger,
        '--target', 'api.example.com', '--action', 'recon', '--at', AT]);
      assert.equal(blocked.code, 1, `缺证据应被拒，实际 ${blocked.code}`);
      assert.match(blocked.stderr, /要求每个已执行动作都附证据/);
      assert.equal(readFileSync(S.ledger, 'utf8'), before, '策略不满足时不得写入');

      /* 带证据 → 正常放行 */
      const ok = runCli(['log', '--manifest', S.manifest, '--ledger', S.ledger,
        '--target', 'api.example.com', '--action', 'recon', '--evidence', 'logs/recon.txt', '--at', AT]);
      assert.equal(ok.code, 0, `带证据应放行，实际 ${ok.code}`);

      /* 被拒的动作不需要证据（否则会逼人给"没发生的事"造凭据） */
      const denied = runCli(['log', '--manifest', S.manifest, '--ledger', S.ledger,
        '--target', 'pay.example.com', '--action', 'scan', '--at', AT]);
      assert.equal(denied.code, 2, `越界动作应记为拒绝，实际 ${denied.code}`);

      /* 报告要把策略写出来，并指出缺证据条目 */
      const report = runCli(['report', '--manifest', S.manifest, '--ledger', S.ledger, '--stdout']);
      assert.equal(report.code, 0);
      assert.match(report.stdout, /每个已执行动作都必须附证据指针/);
      assert.match(report.stdout, /logs\/recon\.txt/);
    } finally {
      S.cleanup();
    }
  });

  check(`C${BAD_MANIFESTS.length + 3} 授权书归档脚本与 init 核验能串成闭环`, () => {
    const S = makeEngagement('c8');
    try {
      /* 1. 用 intake 脚本归档源文件，拿到可直接填进凭证的两行 */
      const intake = intakeAuthorization({
        source: join(S.dir, 'demo-authorization.md'),
        dir: 'authorization',
        as: 'AUTH-2026-DEMO-001.md',
        cwd: S.dir,
      });
      assert.equal(intake.ok, true, `归档应成功：${intake.error}`);
      assert.equal(intake.relativePath, 'authorization/AUTH-2026-DEMO-001.md');

      /* 2. 把结果填进凭证（这正是脚本存在的意义：不靠手抄） */
      const m = JSON.parse(readFileSync(S.manifest, 'utf8'));
      m.engagement.authorization.document = intake.relativePath;
      m.engagement.authorization.documentSha256 = intake.sha256;
      writeFileSync(S.manifest, JSON.stringify(m), 'utf8');

      /* 3. init 必须核验通过 */
      const ok = runCli(['init', '--manifest', S.manifest, '--ledger', S.ledger]);
      assert.equal(ok.code, 0, ok.stderr);
      assert.match(ok.stdout, /授权文件核验通过/);

      /* 4. 重复归档到同名必须被拒（覆盖会作废已登记的哈希） */
      const again = intakeAuthorization({
        source: join(S.dir, 'demo-authorization.md'),
        dir: 'authorization',
        as: 'AUTH-2026-DEMO-001.md',
        cwd: S.dir,
      });
      assert.equal(again.ok, false, '重复归档到同名必须被拒');
      assert.match(again.error, /拒绝覆盖/);

      /* 5. 归档副本被动过之后，核验必须报不一致。
            用同一个沙箱目录下的另一个 ledger —— 凭证里的 document 是相对路径，
            换到别的目录就会变成"文档不存在"，那是另一种情形，不是这里要验的。 */
      writeFileSync(join(S.dir, intake.relativePath), '被人替换过的授权书\n', 'utf8');
      const tamperedLedger = join(S.dir, 'tampered-ledger.jsonl');
      const bad = runCli(['init', '--manifest', S.manifest, '--ledger', tamperedLedger]);
      assert.equal(bad.code, 0, 'init 仍应成功（核验是告警不是阻断）');
      assert.match(bad.stdout, /授权文件核验未通过/);
      assert.match(bad.stdout, /不一致/);
    } finally {
      S.cleanup();
    }
  });
} finally {
  rmSync(C, { recursive: true, force: true });
}

/* ============================ D. 安全红线（守卫的守卫） ============================ */

group('\nD. 安全红线（守卫本身必须有效 —— 一个永远通过的守卫等于没有守卫）');

/** 造一份仓库副本，便于在不碰真实文件的前提下做负向验证 */
function makeRepoCopy(tag, mutate) {
  const dir = mkdtempSync(join(tmpdir(), `el-repo-${tag}-`));
  cpSync(join(ROOT, 'package.json'), join(dir, 'package.json'));
  cpSync(join(ROOT, 'src'), join(dir, 'src'), { recursive: true });
  if (mutate) mutate(dir);
  return dir;
}

check('D1 真实仓库本身通过全部红线校验', () => {
  const { problems, fileCount } = runChecks(DEFAULT_ROOT);
  assert.ok(fileCount > 0, '没有扫描到任何源文件，校验形同虚设');
  assert.deepEqual(problems, [], `发现问题：\n${problems.join('\n')}`);
});

check('D2 引入第三方依赖必须被检出', () => {
  const dir = makeRepoCopy('d2', (d) => {
    writeFileSync(join(d, 'src', '__probe.mjs'), "import lodash from 'lodash';\nexport default lodash;\n", 'utf8');
  });
  try {
    const { problems } = runChecks(dir);
    assert.ok(problems.some((p) => p.includes('lodash')), `未检出第三方依赖，实际问题：${JSON.stringify(problems)}`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

check('D3 削弱硬性禁止清单必须被检出', () => {
  const dir = makeRepoCopy('d3', (d) => {
    const p = join(d, 'src', 'lib', 'manifest.mjs');
    writeFileSync(p, readFileSync(p, 'utf8').replace("  'ransomware',\n", ''), 'utf8');
  });
  try {
    const { problems } = runChecks(dir);
    assert.ok(problems.some((p) => p.includes('ransomware')), `未检出清单被削弱，实际问题：${JSON.stringify(problems)}`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

check('D4 删除整份硬性禁止清单必须被检出', () => {
  const dir = makeRepoCopy('d4', (d) => {
    const p = join(d, 'src', 'lib', 'manifest.mjs');
    writeFileSync(p, readFileSync(p, 'utf8').replace(/export const NEVER_PERMITTED_ACTIONS = \[/, 'export const RENAMED = ['), 'utf8');
  });
  try {
    const { problems } = runChecks(dir);
    assert.ok(problems.some((p) => p.includes('NEVER_PERMITTED_ACTIONS')), `未检出清单被删，实际问题：${JSON.stringify(problems)}`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

check('D5 允许裸 --hmac-key 命令行参数必须被检出', () => {
  const dir = makeRepoCopy('d5', (d) => {
    const p = join(d, 'src', 'index.mjs');
    writeFileSync(p, readFileSync(p, 'utf8') + "\n/* probe */\nconst leak = options['hmac-key'];\n", 'utf8');
  });
  try {
    const { problems } = runChecks(dir);
    assert.ok(problems.some((p) => p.includes('hmac-key')), `未检出密钥可走命令行，实际问题：${JSON.stringify(problems)}`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

check('D6 报告表格守卫能发现未转义的竖线', () => {
  const broken = [
    '| # | 目标 | 原因 |',
    '| --- | --- | --- |',
    '| 1 | `evil.com|injected` | 越界 |',
  ].join('\n');
  const problems = checkTables(broken);
  assert.equal(problems.length, 1, '未转义的竖线未被检出');
  assert.equal(problems[0].actual, 4);

  const fixed = broken.replace('evil.com|injected', 'evil.com\\|injected');
  assert.deepEqual(checkTables(fixed), [], '转义后仍误报');
});

check('D7 报告表格守卫不会误报正常表格', () => {
  const normal = [
    '| 指标 | 数值 |',
    '| --- | --- |',
    '| 日志总条数 | 5 |',
  ].join('\n');
  assert.deepEqual(checkTables(normal), []);
});

/* ============================ 汇总 ============================ */

const passed = results.filter((r) => r.ok).length;
const failed = results.filter((r) => !r.ok);

process.stdout.write(`\n${'='.repeat(60)}\n`);
if (failed.length === 0) {
  process.stdout.write(`✅ 运营级校验全部通过：${passed} 项\n`);
  process.exit(0);
}

process.stdout.write(`❌ 运营级校验失败：${passed} 通过 / ${failed.length} 失败\n\n`);
for (const f of failed) {
  process.stdout.write(`  ✗ ${f.name}\n    ${f.error.split('\n').join('\n    ')}\n`);
}
process.exit(1);

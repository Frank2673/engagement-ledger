/**
 * 单元测试：执行前校验门
 *
 * 这是本项目最该被测试覆盖的部分 —— 它决定"能不能动手"。
 * 判错方向的两个后果都很严重：放行了越界动作（真出事），
 * 或拦掉了授权内的动作（工具变得不可用从而被绕过）。
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { validateManifest } from '../src/lib/manifest.mjs';
import { evaluateAction } from '../src/lib/gate.mjs';

function manifest(overrides = {}) {
  return validateManifest({
    engagement: {
      id: 'ENG-001',
      tester: 'alice',
      authorization: { reference: 'AUTH-001', signedBy: 'bob' },
      window: { from: '2026-03-01T00:00:00Z', to: '2026-03-31T18:00:00Z' },
      scope: {
        inScope: ['example.com', '192.0.2.0/28'],
        outOfScope: ['pay.example.com'],
      },
      permittedActions: ['recon', 'scan', 'manual-test'],
      prohibitedActions: ['dos', 'destructive', 'data-exfiltration', 'persistence', 'social-engineering'],
      emergencyContact: 'bob@example.com',
      ...overrides,
    },
  });
}

const IN_WINDOW = new Date('2026-03-15T12:00:00Z');

test('授权内的动作放行', () => {
  const v = evaluateAction(manifest(), { target: 'api.example.com', action: 'recon', at: IN_WINDOW });
  assert.equal(v.allowed, true);
  assert.equal(v.decision, 'allowed');
  assert.equal(v.checks.every((c) => c.passed), true);
});

test('判定结果携带完整轨迹 —— 审计要的是"依据什么判定"', () => {
  const v = evaluateAction(manifest(), { target: 'example.com', action: 'scan', at: IN_WINDOW });
  const names = v.checks.map((c) => c.name);
  assert.deepEqual(names, [
    'input-complete',
    'action-not-hard-forbidden',
    'action-not-prohibited',
    'action-permitted',
    'within-time-window',
    'target-in-scope',
    'target-not-excluded',
  ]);
  assert.equal(v.context.engagementId, 'ENG-001');
  assert.equal(v.context.authorizationReference, 'AUTH-001');
});

test('范围内目标放行（含子域与 CIDR）', () => {
  for (const target of ['example.com', 'api.example.com', 'deep.api.example.com', '192.0.2.7']) {
    const v = evaluateAction(manifest(), { target, action: 'scan', at: IN_WINDOW });
    assert.equal(v.allowed, true, `${target} 应在范围内`);
  }
});

/* ------------------------- IPv6 ------------------------- */

test('IPv6 目标在范围内时放行', () => {
  const m = manifest({ scope: { inScope: ['2001:db8::/32', '::1'], outOfScope: [] } });

  for (const target of ['2001:db8::1', '2001:db8:ffff::a', '[2001:db8::1]', '::1']) {
    const v = evaluateAction(m, { target, action: 'scan', at: IN_WINDOW });
    assert.equal(v.allowed, true, `${target} 应在 IPv6 范围内`);
  }

  /* 归一化后目标不含方括号 */
  const bracketed = evaluateAction(m, { target: '[2001:db8::1]', action: 'scan', at: IN_WINDOW });
  assert.equal(bracketed.context.target, '2001:db8::1');
});

test('IPv6 范围外目标被拒绝', () => {
  const m = manifest({ scope: { inScope: ['2001:db8::/32'], outOfScope: [] } });

  const v = evaluateAction(m, { target: '2001:db9::1', action: 'scan', at: IN_WINDOW });
  assert.equal(v.allowed, false);
  assert.match(v.reason, /不在 inScope/);
});

test('IPv6 排除规则同样优先', () => {
  const m = manifest({ scope: { inScope: ['2001:db8::/32'], outOfScope: ['2001:db8:bad::/48'] } });

  assert.equal(evaluateAction(m, { target: '2001:db8:1::1', action: 'scan', at: IN_WINDOW }).allowed, true);
  const denied = evaluateAction(m, { target: '2001:db8:bad::1', action: 'scan', at: IN_WINDOW });
  assert.equal(denied.allowed, false);
  assert.match(denied.reason, /排除/);
});

test('跨族不匹配：IPv4 目标不会命中 IPv6 网段', () => {
  const m = manifest({ scope: { inScope: ['::/0'], outOfScope: [] } });
  const v = evaluateAction(m, { target: '192.0.2.1', action: 'scan', at: IN_WINDOW });
  assert.equal(v.allowed, false, '::/0 不能覆盖 v4 目标');
});

test('凭证里的非法 IPv6 范围规则会被 validateManifest 拦下', () => {
  assert.throws(
    () => manifest({ scope: { inScope: ['2001:db8:::1'], outOfScope: [] } }),
    /范围规则格式不合法/
  );
});

test('范围外目标被拒绝，并以"不在 inScope"为主因', () => {
  const v = evaluateAction(manifest(), { target: 'evil.com', action: 'scan', at: IN_WINDOW });
  assert.equal(v.allowed, false);
  assert.equal(v.decision, 'denied');
  assert.match(v.reason, /不在 inScope/);
});

test('排除规则优先于纳入规则（out-of-scope wins）', () => {
  const v = evaluateAction(manifest(), { target: 'pay.example.com', action: 'scan', at: IN_WINDOW });
  assert.equal(v.allowed, false);
  assert.match(v.reason, /排除规则/);
  /* 拒绝原因应指出这是排除命中，而不是"不在范围"这种含混说法 */
  const excluded = v.checks.find((c) => c.name === 'target-not-excluded');
  assert.equal(excluded.passed, false);
  assert.match(excluded.detail, /排除优先级高于纳入/);
});

test('排除规则同样覆盖其子域', () => {
  const v = evaluateAction(manifest(), { target: 'api.pay.example.com', action: 'scan', at: IN_WINDOW });
  assert.equal(v.allowed, false);
});

test('超出时间窗被拒绝', () => {
  const before = evaluateAction(manifest(), { target: 'example.com', action: 'scan', at: new Date('2026-02-28T23:59:59Z') });
  assert.equal(before.allowed, false);
  assert.match(before.reason, /超出授权窗口/);

  const after = evaluateAction(manifest(), { target: 'example.com', action: 'scan', at: new Date('2026-04-01T00:00:01Z') });
  assert.equal(after.allowed, false);

  /* 边界包含：窗口起止时刻本身算在内 */
  const atStart = evaluateAction(manifest(), { target: 'example.com', action: 'scan', at: new Date('2026-03-01T00:00:00Z') });
  assert.equal(atStart.allowed, true);
  const atEnd = evaluateAction(manifest(), { target: 'example.com', action: 'scan', at: new Date('2026-03-31T18:00:00Z') });
  assert.equal(atEnd.allowed, true);
});

test('硬性禁止动作即使写进凭证也拦不住 —— 由校验门二次兜底', () => {
  /* 绕过凭证校验，手工构造一份把 dos 列入允许清单的凭证对象 */
  const forged = manifest();
  forged.engagement.permittedActions = ['dos', 'recon'];
  forged.engagement.prohibitedActions = [];

  const v = evaluateAction(forged, { target: 'example.com', action: 'dos', at: IN_WINDOW });
  assert.equal(v.allowed, false);
  const hard = v.checks.find((c) => c.name === 'action-not-hard-forbidden');
  assert.equal(hard.passed, false);
  assert.match(hard.detail, /硬性禁止/);
});

test('凭证禁止清单命中也拒绝', () => {
  const v = evaluateAction(manifest(), { target: 'example.com', action: 'persistence', at: IN_WINDOW });
  assert.equal(v.allowed, false);
  assert.match(v.reason, /prohibitedActions/);
});

test('不在允许清单内的动作拒绝，并列出允许项', () => {
  const v = evaluateAction(manifest(), { target: 'example.com', action: 'bruteforce', at: IN_WINDOW });
  assert.equal(v.allowed, false);
  const check = v.checks.find((c) => c.name === 'action-permitted');
  assert.equal(check.passed, false);
  assert.match(check.detail, /recon, scan, manual-test/);
});

test('允许清单为空时不额外限制（仅受禁止项约束）', () => {
  const m = manifest({ permittedActions: [] });
  const allowed = evaluateAction(m, { target: 'example.com', action: 'anything-safe', at: IN_WINDOW });
  assert.equal(allowed.allowed, true);
  const denied = evaluateAction(m, { target: 'example.com', action: 'destructive', at: IN_WINDOW });
  assert.equal(denied.allowed, false);
});

test('动作大小写不敏感（防止大小写绕过白名单）', () => {
  const v = evaluateAction(manifest(), { target: 'example.com', action: 'SCAN', at: IN_WINDOW });
  assert.equal(v.allowed, true);
  assert.equal(v.context.action, 'scan');

  const bad = evaluateAction(manifest(), { target: 'example.com', action: 'DoS', at: IN_WINDOW });
  assert.equal(bad.allowed, false);
});

test('目标大小写与尾点归一化', () => {
  const v = evaluateAction(manifest(), { target: 'API.Example.COM.', action: 'scan', at: IN_WINDOW });
  assert.equal(v.allowed, true);
  assert.equal(v.context.target, 'api.example.com');
});

test('目标或动作缺失直接拒绝，不静默通过', () => {
  const noTarget = evaluateAction(manifest(), { target: '', action: 'scan', at: IN_WINDOW });
  assert.equal(noTarget.allowed, false);
  assert.match(noTarget.reason, /动作或目标为空/);

  const noAction = evaluateAction(manifest(), { target: 'example.com', action: null, at: IN_WINDOW });
  assert.equal(noAction.allowed, false);
});

test('多项失败时全部记录在轨迹里，主因合并展示', () => {
  const v = evaluateAction(manifest(), { target: 'evil.com', action: 'ransomware', at: new Date('2026-05-01T00:00:00Z') });
  assert.equal(v.allowed, false);
  const failed = v.checks.filter((c) => !c.passed).map((c) => c.name);
  assert.ok(failed.includes('action-not-hard-forbidden'));
  assert.ok(failed.includes('within-time-window'));
  assert.ok(failed.includes('target-in-scope'));
  assert.match(v.reason, /；/);
});

test('判定是纯函数：同一输入两次调用结果一致', () => {
  const m = manifest();
  const a = evaluateAction(m, { target: 'example.com', action: 'scan', at: IN_WINDOW });
  const b = evaluateAction(m, { target: 'example.com', action: 'scan', at: IN_WINDOW });
  assert.deepEqual(a, b);
});

test('判定不修改凭证（无副作用）', () => {
  const m = manifest();
  const snapshot = JSON.stringify(m, (k, v) => (v instanceof Date ? v.toISOString() : v));
  evaluateAction(m, { target: 'evil.com', action: 'ransomware', at: IN_WINDOW });
  const after = JSON.stringify(m, (k, v) => (v instanceof Date ? v.toISOString() : v));
  assert.equal(after, snapshot);
});

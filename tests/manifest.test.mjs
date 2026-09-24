/**
 * 单元测试：授权凭证校验
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  validateManifest,
  isValidScopeRule,
  matchesScopeRule,
  ipInCidr,
  ipToBytes,
  ipEquals,
  normalizeTarget,
  NEVER_PERMITTED_ACTIONS,
  ManifestError,
} from '../src/lib/manifest.mjs';

/** 一份最小合法凭证 */
function base(overrides = {}) {
  return {
    engagement: {
      id: 'ENG-001',
      tester: 'alice',
      authorization: { reference: 'AUTH-001', signedBy: 'bob' },
      window: { from: '2026-03-01T00:00:00Z', to: '2026-03-31T00:00:00Z' },
      scope: { inScope: ['api.example.com', '192.0.2.0/28'], outOfScope: ['pay.example.com'] },
      permittedActions: ['recon', 'scan'],
      prohibitedActions: ['dos', 'destructive', 'data-exfiltration', 'persistence', 'social-engineering'],
      emergencyContact: 'bob@example.com',
      ...overrides,
    },
  };
}

test('最小合法凭证通过校验', () => {
  const m = validateManifest(base());
  assert.equal(m.engagement.id, 'ENG-001');
  assert.equal(m.engagement.tester, 'alice');
  assert.deepEqual(m.engagement.permittedActions, ['recon', 'scan']);
  assert.equal(m.engagement.window.from instanceof Date, true);
  assert.equal(m.engagement.window.to instanceof Date, true);
});

test('凭证未提供 name 时回落到 id（报告里不该出现 undefined）', () => {
  const withName = validateManifest(base({ name: '示例委托' }));
  assert.equal(withName.engagement.name, '示例委托');

  const withoutName = validateManifest(base());
  assert.equal(withoutName.engagement.name, 'ENG-001');
});

test('凭证带回硬性禁止清单（报告与校验门共用一份）', () => {
  const m = validateManifest(base());
  assert.deepEqual(m.hardForbidden, NEVER_PERMITTED_ACTIONS);
});

test('requireEvidence 默认为 false，显式 true 时保留', () => {
  assert.equal(validateManifest(base()).engagement.requireEvidence, false);
  assert.equal(validateManifest(base({ requireEvidence: true })).engagement.requireEvidence, true);
});

test('requireEvidence 只认布尔 true（避免字符串 "false" 被当成真）', () => {
  assert.equal(validateManifest(base({ requireEvidence: 'true' })).engagement.requireEvidence, false);
  assert.equal(validateManifest(base({ requireEvidence: 1 })).engagement.requireEvidence, false);
  assert.equal(validateManifest(base({ requireEvidence: false })).engagement.requireEvidence, false);
});

test('缺少授权段直接报错 —— 没有授权就没有动作', () => {
  const input = base();
  delete input.engagement.authorization;
  assert.throws(() => validateManifest(input), /authorization/);
});

test('缺少授权书编号或签署人报错', () => {
  const noRef = base();
  noRef.engagement.authorization = { signedBy: 'bob' };
  assert.throws(() => validateManifest(noRef), /reference/);

  const noSigner = base();
  noSigner.engagement.authorization = { reference: 'AUTH-001' };
  assert.throws(() => validateManifest(noSigner), /signedBy/);
});

test('缺少时间窗报错', () => {
  const input = base();
  delete input.engagement.window;
  assert.throws(() => validateManifest(input), /window/);
});

test('window.from 晚于 to 报错', () => {
  const input = base({ window: { from: '2026-04-01T00:00:00Z', to: '2026-03-01T00:00:00Z' } });
  assert.throws(() => validateManifest(input), /早于/);
});

test('inScope 为空报错 —— 空范围等于没有授权', () => {
  const input = base();
  input.engagement.scope = { inScope: [], outOfScope: [] };
  assert.throws(() => validateManifest(input), /inScope/);
});

test('非法范围规则报错', () => {
  const input = base();
  input.engagement.scope.inScope = ['not a domain!'];
  assert.throws(() => validateManifest(input), /范围规则格式不合法/);
});

test('硬性禁止动作不允许出现在 permittedActions（不可通过配置放行）', () => {
  for (const action of ['dos', 'ddos', 'ransomware', 'data-exfiltration']) {
    const input = base();
    input.engagement.permittedActions = [action];
    assert.throws(
      () => validateManifest(input),
      /硬性禁止/,
      `${action} 应被拒绝`
    );
  }
});

test('建议禁止项缺失只告警不阻断', () => {
  const input = base({ prohibitedActions: [] });
  const m = validateManifest(input);
  assert.ok(m.warnings.some((w) => w.includes('prohibitedActions')));
});

test('缺少应急联系人只告警', () => {
  const input = base({ emergencyContact: undefined });
  const m = validateManifest(input);
  assert.ok(m.warnings.some((w) => w.includes('emergencyContact')));
});

test('documentSha256 必须是 64 位十六进制', () => {
  const input = base();
  input.engagement.authorization.documentSha256 = 'abc';
  assert.throws(() => validateManifest(input), /64 位十六进制/);

  const ok = base();
  ok.engagement.authorization.documentSha256 = 'a'.repeat(64);
  assert.doesNotThrow(() => validateManifest(ok));
});

test('未提供文档哈希时给出告警（不阻断，但审计会缺一环）', () => {
  const m = validateManifest(base());
  assert.ok(m.warnings.some((w) => w.includes('documentSha256')));
});

test('动作统一小写，避免大小写绕过白名单', () => {
  const input = base({ permittedActions: ['Recon', 'SCAN'] });
  const m = validateManifest(input);
  assert.deepEqual(m.engagement.permittedActions, ['recon', 'scan']);
});

test('ManifestError 带类型名，便于调用方分流', () => {
  try {
    validateManifest({});
    assert.fail('应该抛错');
  } catch (err) {
    assert.equal(err.name, 'ManifestError');
    assert.ok(err instanceof ManifestError);
  }
});

/* ------------------------- 范围规则 ------------------------- */

test('isValidScopeRule 接受域名 / 通配 / IP / CIDR', () => {
  for (const ok of ['example.com', 'api.example.com', '*.example.com', '192.0.2.1', '10.0.0.0/8']) {
    assert.equal(isValidScopeRule(ok), true, `${ok} 应合法`);
  }
});

test('isValidScopeRule 拒绝空串、非法字符、越界 IP', () => {
  for (const bad of ['', '  ', 'http://example.com', 'example', '999.1.1.1', '10.0.0.0/33', '*example.com']) {
    assert.equal(isValidScopeRule(bad), false, `${bad} 应非法`);
  }
});

test('matchesScopeRule：普通域名覆盖自身与子域', () => {
  assert.equal(matchesScopeRule('example.com', 'example.com'), true);
  assert.equal(matchesScopeRule('example.com', 'api.example.com'), true);
  assert.equal(matchesScopeRule('example.com', 'notexample.com'), false);
  /* 关键：example.com 不应匹配 example.com.evil.net */
  assert.equal(matchesScopeRule('example.com', 'example.com.evil.net'), false);
});

test('matchesScopeRule：通配符只覆盖子域', () => {
  assert.equal(matchesScopeRule('*.example.com', 'api.example.com'), true);
  assert.equal(matchesScopeRule('*.example.com', 'a.b.example.com'), true);
  assert.equal(matchesScopeRule('*.example.com', 'example.com'), true);
  assert.equal(matchesScopeRule('*.example.com', 'other.com'), false);
});

test('matchesScopeRule：大小写与尾点归一化', () => {
  assert.equal(matchesScopeRule('Example.COM', 'API.example.com'), true);
  assert.equal(matchesScopeRule('example.com', 'api.example.com.'), true);
});

test('matchesScopeRule：CIDR 与精确 IP', () => {
  assert.equal(matchesScopeRule('192.0.2.0/28', '192.0.2.5'), true);
  assert.equal(matchesScopeRule('192.0.2.0/28', '192.0.2.20'), false);
  assert.equal(matchesScopeRule('192.0.2.1', '192.0.2.1'), true);
  assert.equal(matchesScopeRule('192.0.2.1', '192.0.2.2'), false);
});

test('ipInCidr：边界值与异常输入', () => {
  assert.equal(ipInCidr('10.0.0.1', '10.0.0.0/8'), true);
  assert.equal(ipInCidr('10.255.255.255', '10.0.0.0/8'), true);
  assert.equal(ipInCidr('11.0.0.1', '10.0.0.0/8'), false);
  /* /32 只等于自身 */
  assert.equal(ipInCidr('10.0.0.1', '10.0.0.1/32'), true);
  assert.equal(ipInCidr('10.0.0.2', '10.0.0.1/32'), false);
  /* /0 覆盖全部 */
  assert.equal(ipInCidr('8.8.8.8', '0.0.0.0/0'), true);
  /* 非法输入不抛异常，只返回 false */
  assert.equal(ipInCidr('not-an-ip', '10.0.0.0/8'), false);
  assert.equal(ipInCidr('10.0.0.1', '10.0.0.0/99'), false);
});

/* ------------------------- IP 解析 ------------------------- */

test('ipToBytes：IPv4 解析与拒绝歧义写法', () => {
  assert.deepEqual(ipToBytes('192.0.2.1'), [192, 0, 2, 1]);
  assert.deepEqual(ipToBytes('0.0.0.0'), [0, 0, 0, 0]);
  assert.equal(ipToBytes('256.0.0.1'), null);
  assert.equal(ipToBytes('192.0.2'), null);
  assert.equal(ipToBytes('192.0.2.1.5'), null);
  /* 前导零在部分实现里按八进制解析，歧义地址直接拒绝 */
  assert.equal(ipToBytes('010.0.0.1'), null);
  assert.equal(ipToBytes('192.0.2.-1'), null);
});

test('ipToBytes：IPv6 完整写法与 :: 压缩', () => {
  assert.deepEqual(ipToBytes('2001:db8:0:0:0:0:0:1'), [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
  /* :: 压缩展开后必须与完整写法一致 */
  assert.deepEqual(ipToBytes('2001:db8::1'), ipToBytes('2001:db8:0:0:0:0:0:1'));
  assert.deepEqual(ipToBytes('::1'), [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
  assert.deepEqual(ipToBytes('::'), new Array(16).fill(0));
  assert.equal(ipToBytes('::1').length, 16);
});

test('ipToBytes：IPv6 内嵌 IPv4', () => {
  assert.deepEqual(ipToBytes('::ffff:192.0.2.1'), ipToBytes('::ffff:c000:201'));
  assert.equal(ipToBytes('::ffff:192.0.2.1').length, 16);
});

test('ipToBytes：非法 IPv6 被拒绝而不是尽力解析', () => {
  for (const bad of ['2001:db8:::1', '2001:db8::1::2', 'gggg::1', '1:2:3:4:5:6:7:8:9', 'fe80::1%eth0', '::ffff:999.0.0.1']) {
    assert.equal(ipToBytes(bad), null, `${bad} 应被拒绝`);
  }
});

test('ipToBytes：空值与域名返回 null（不能把域名当 IP）', () => {
  for (const notIp of ['', '  ', 'example.com', 'api.example.com', null, undefined]) {
    assert.equal(ipToBytes(notIp), null);
  }
});

test('ipEquals：同一地址的不同写法视为相等，不同族不相等', () => {
  assert.equal(ipEquals('::1', '0:0:0:0:0:0:0:1'), true);
  assert.equal(ipEquals('2001:DB8::1', '2001:db8::1'), true);
  assert.equal(ipEquals('::ffff:192.0.2.1', '::ffff:c000:201'), true);
  assert.equal(ipEquals('::1', '::2'), false);
  /* v4 与 v6 永不相等 —— 不能让 ::ffff:1.2.3.4 匹配 1.2.3.4 */
  assert.equal(ipEquals('192.0.2.1', '::ffff:192.0.2.1'), false);
});

/* ------------------------- IPv6 范围规则 ------------------------- */

test('isValidScopeRule 接受 IPv6 与 IPv6 CIDR', () => {
  for (const ok of ['2001:db8::1', '::1', 'fe80::', '2001:db8::/32', '::/0', '2001:db8::1/128']) {
    assert.equal(isValidScopeRule(ok), true, `${ok} 应合法`);
  }
});

test('isValidScopeRule 拒绝非法 IPv6 与越界前缀', () => {
  for (const bad of ['2001:db8:::1', 'gggg::1', '2001:db8::/129', '::/999', '2001:db8::/abc']) {
    assert.equal(isValidScopeRule(bad), false, `${bad} 应非法`);
  }
});

test('写错的 IP 不会被当成域名放行（静默接受比报错更危险）', () => {
  for (const bad of ['999.1.1.1', '1.2.3.4.5', '2001:db8::zz', '10.0.0.1/33']) {
    assert.equal(isValidScopeRule(bad), false, `${bad} 必须被拒绝，不能掉进域名分支`);
  }
});

test('matchesScopeRule：IPv6 精确匹配', () => {
  assert.equal(matchesScopeRule('2001:db8::1', '2001:db8::1'), true);
  assert.equal(matchesScopeRule('2001:db8::1', '2001:db8::2'), false);
  /* 规则与目标写法不同但地址相同 */
  assert.equal(matchesScopeRule('2001:db8::1', '2001:0db8:0000:0000:0000:0000:0000:0001'), true);
  /* 带方括号的目标也应能匹配 */
  assert.equal(matchesScopeRule('2001:db8::1', '[2001:db8::1]'), true);
  assert.equal(matchesScopeRule('::1', '[::1]'), true);
});

test('matchesScopeRule：IPv6 CIDR', () => {
  assert.equal(matchesScopeRule('2001:db8::/32', '2001:db8::1'), true);
  assert.equal(matchesScopeRule('2001:db8::/32', '2001:db8:ffff::1'), true);
  assert.equal(matchesScopeRule('2001:db8::/32', '2001:db9::1'), false);
  /* /128 只等于自身 */
  assert.equal(matchesScopeRule('2001:db8::1/128', '2001:db8::1'), true);
  assert.equal(matchesScopeRule('2001:db8::1/128', '2001:db8::2'), false);
  /* /0 覆盖全部 v6，但不覆盖 v4（不跨族） */
  assert.equal(matchesScopeRule('::/0', '2001:db8::1'), true);
  assert.equal(matchesScopeRule('::/0', '192.0.2.1'), false);
});

test('ipInCidr：跨族一律 false（配置错误不能变成"看起来通过"）', () => {
  assert.equal(ipInCidr('192.0.2.1', '2001:db8::/32'), false);
  assert.equal(ipInCidr('2001:db8::1', '192.0.2.0/24'), false);
});

test('域名规则不会匹配 IP 目标，反之亦然', () => {
  assert.equal(matchesScopeRule('example.com', '192.0.2.1'), false);
  assert.equal(matchesScopeRule('192.0.2.1', 'example.com'), false);
  assert.equal(matchesScopeRule('2001:db8::1', 'example.com'), false);
});

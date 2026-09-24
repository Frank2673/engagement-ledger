/**
 * 单元测试：哈希与规范化
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  GENESIS_HASH,
  canonicalJson,
  sha256Hex,
  hmacSha256Hex,
  computeEntryHash,
  hashEquals,
} from '../src/lib/crypto.mjs';

test('GENESIS_HASH 是 64 个 0', () => {
  assert.equal(GENESIS_HASH, '0'.repeat(64));
  assert.equal(GENESIS_HASH.length, 64);
});

test('canonicalJson 对键顺序不敏感', () => {
  const a = canonicalJson({ b: 1, a: 2, c: { z: 1, y: 2 } });
  const b = canonicalJson({ c: { y: 2, z: 1 }, a: 2, b: 1 });
  assert.equal(a, b);
  assert.equal(a, '{"a":2,"b":1,"c":{"y":2,"z":1}}');
});

test('canonicalJson 丢弃 undefined 但不丢弃 null', () => {
  const withUndef = canonicalJson({ a: 1, b: undefined });
  const without = canonicalJson({ a: 1 });
  assert.equal(withUndef, without);

  assert.notEqual(canonicalJson({ a: null }), canonicalJson({}));
});

test('canonicalJson 保持数组顺序（顺序是内容的一部分）', () => {
  assert.notEqual(canonicalJson({ a: [1, 2] }), canonicalJson({ a: [2, 1] }));
});

test('canonicalJson 递归处理嵌套结构', () => {
  const out = canonicalJson({ list: [{ b: 1, a: 2 }] });
  assert.equal(out, '{"list":[{"a":2,"b":1}]}');
});

test('sha256Hex 对相同输入稳定，对不同输入不同', () => {
  assert.equal(sha256Hex('abc'), sha256Hex('abc'));
  assert.notEqual(sha256Hex('abc'), sha256Hex('abd'));
  assert.equal(sha256Hex('abc').length, 64);
});

test('hmacSha256Hex 依赖密钥', () => {
  const a = hmacSha256Hex('key1', 'payload');
  const b = hmacSha256Hex('key2', 'payload');
  assert.notEqual(a, b);
  /* 同一密钥 + 同一输入必须稳定，否则校验会误报 */
  assert.equal(a, hmacSha256Hex('key1', 'payload'));
  assert.equal(a.length, 64);
});

test('computeEntryHash 忽略 hash 字段（否则无法自洽）', () => {
  const base = { seq: 0, type: 'action', actor: 'tester' };
  const withHash = { ...base, hash: 'deadbeef' };
  assert.equal(
    computeEntryHash(base, GENESIS_HASH),
    computeEntryHash(withHash, GENESIS_HASH)
  );
});

test('computeEntryHash 覆盖 prevHash（链条不可拼接）', () => {
  const entry = { seq: 1, type: 'action', actor: 'tester' };
  assert.notEqual(
    computeEntryHash(entry, GENESIS_HASH),
    computeEntryHash(entry, 'a'.repeat(64))
  );
});

test('computeEntryHash 覆盖全部字段（任意字段改动都会改变哈希）', () => {
  const first = computeEntryHash({ seq: 0, actor: 'alice' }, GENESIS_HASH);
  const second = computeEntryHash({ seq: 0, actor: 'bob' }, GENESIS_HASH);
  assert.notEqual(first, second);
});

test('computeEntryHash 提供密钥时使用 HMAC', () => {
  const entry = { seq: 0, actor: 'alice' };
  const plain = computeEntryHash(entry, GENESIS_HASH);
  const keyed = computeEntryHash(entry, GENESIS_HASH, 'secret');
  assert.notEqual(plain, keyed);
  assert.equal(keyed, computeEntryHash(entry, GENESIS_HASH, 'secret'));
});

test('hashEquals 处理相等、不等与类型异常', () => {
  assert.equal(hashEquals('abc', 'abc'), true);
  assert.equal(hashEquals('abc', 'abd'), false);
  assert.equal(hashEquals('abc', 'abcd'), false);
  assert.equal(hashEquals(undefined, 'abc'), false);
  assert.equal(hashEquals(null, null), false);
  assert.equal(hashEquals(123, 123), false);
});

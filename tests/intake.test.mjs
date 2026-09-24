/**
 * 单元测试：授权书接收与登记
 *
 * 这个脚本的价值在于消掉"手抄哈希抄错"与"登记后再动过原件"两类失败，
 * 所以测试重点不是"能复制文件"，而是：哈希算得对、拒绝覆盖、试运行不留痕、
 * 以及在源文件缺失 / 是目录时给出可读错误而不是崩栈。
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync, readFileSync, existsSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { intakeAuthorization, ADVICE } from '../scripts/intake-authorization.mjs';
import { fileSha256 } from '../src/lib/crypto.mjs';

const CONTENT = '授权书内容（测试用）\n第二行\n';

function sandbox() {
  const dir = mkdtempSync(join(tmpdir(), 'el-intake-'));
  const source = join(dir, 'AUTH-001.txt');
  writeFileSync(source, CONTENT, 'utf8');
  return { dir, source, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

test('正常归档：复制文件并给出正确的 SHA-256', () => {
  const sb = sandbox();
  try {
    const r = intakeAuthorization({ source: sb.source, dir: 'authorization', cwd: sb.dir });

    assert.equal(r.ok, true);
    assert.equal(existsSync(r.archive), true, '归档副本必须存在');
    assert.equal(readFileSync(r.archive, 'utf8'), CONTENT, '副本内容与源一致');
    assert.equal(r.sha256, fileSha256(Buffer.from(CONTENT, 'utf8')));
    assert.equal(r.bytes, Buffer.byteLength(CONTENT, 'utf8'));
  } finally {
    sb.cleanup();
  }
});

test('归档路径以正斜杠给出（可直接粘进 JSON）', () => {
  const sb = sandbox();
  try {
    const r = intakeAuthorization({ source: sb.source, dir: 'authorization', cwd: sb.dir });
    assert.equal(r.relativePath, 'authorization/AUTH-001.txt');
    assert.ok(!r.relativePath.includes('\\'), 'JSON 里不该出现反斜杠');
  } finally {
    sb.cleanup();
  }
});

test('--as 可以指定归档文件名（便于按授权书编号命名）', () => {
  const sb = sandbox();
  try {
    const r = intakeAuthorization({ source: sb.source, dir: 'authorization', as: 'AUTH-2026-001.txt', cwd: sb.dir });
    assert.equal(r.relativePath, 'authorization/AUTH-2026-001.txt');
    assert.equal(r.sha256, fileSha256(Buffer.from(CONTENT, 'utf8')), '改名不改变内容哈希');
  } finally {
    sb.cleanup();
  }
});

test('拒绝覆盖已存在的归档副本（覆盖会作废已登记的哈希）', () => {
  const sb = sandbox();
  try {
    const first = intakeAuthorization({ source: sb.source, dir: 'authorization', cwd: sb.dir });
    assert.equal(first.ok, true);

    /* 换一份内容再归档到同一个名字 */
    const other = join(sb.dir, 'AUTH-001-changed.txt');
    writeFileSync(other, '改过的授权书\n', 'utf8');

    const second = intakeAuthorization({ source: other, dir: 'authorization', as: 'AUTH-001.txt', cwd: sb.dir });
    assert.equal(second.ok, false);
    assert.match(second.error, /拒绝覆盖/);
    assert.match(second.error, /作废已经登记进凭证的哈希/);
    assert.match(second.error, /授权书变更/);

    /* 关键：原有副本没有被改动 */
    assert.equal(readFileSync(first.archive, 'utf8'), CONTENT);
  } finally {
    sb.cleanup();
  }
});

test('--dry-run 只算哈希，不产生任何文件', () => {
  const sb = sandbox();
  try {
    const r = intakeAuthorization({ source: sb.source, dir: 'authorization', dryRun: true, cwd: sb.dir });

    assert.equal(r.ok, true);
    assert.equal(r.sha256, fileSha256(Buffer.from(CONTENT, 'utf8')), '哈希仍应算对');
    assert.ok(!existsSync(join(sb.dir, 'authorization')), '试运行不应创建目录');
  } finally {
    sb.cleanup();
  }
});

test('dry-run 不检查覆盖（它本来就不写盘）', () => {
  const sb = sandbox();
  try {
    intakeAuthorization({ source: sb.source, dir: 'authorization', cwd: sb.dir });
    const dry = intakeAuthorization({ source: sb.source, dir: 'authorization', dryRun: true, cwd: sb.dir });
    assert.equal(dry.ok, true, '试运行不该因为已存在而报错');
  } finally {
    sb.cleanup();
  }
});

test('源文件不存在时返回可读错误而不是抛异常', () => {
  const sb = sandbox();
  try {
    const r = intakeAuthorization({ source: join(sb.dir, 'nope.pdf'), cwd: sb.dir });
    assert.equal(r.ok, false);
    assert.match(r.error, /源文件不存在/);
  } finally {
    sb.cleanup();
  }
});

test('源文件是目录时被拒绝', () => {
  const sb = sandbox();
  try {
    mkdirSync(join(sb.dir, 'somedir'));
    const r = intakeAuthorization({ source: join(sb.dir, 'somedir'), cwd: sb.dir });
    assert.equal(r.ok, false);
    assert.match(r.error, /是一个目录/);
  } finally {
    sb.cleanup();
  }
});

test('缺少源文件参数时返回错误而不是崩栈', () => {
  const r = intakeAuthorization({ source: undefined });
  assert.equal(r.ok, false);
  assert.match(r.error, /缺少源文件路径/);
});

test('未知扩展名给出通用提醒（不静默通过）', () => {
  const sb = sandbox();
  try {
    const weird = join(sb.dir, '授权书.xyz');
    writeFileSync(weird, CONTENT, 'utf8');
    const r = intakeAuthorization({ source: weird, dir: 'authorization', cwd: sb.dir });

    assert.equal(r.ok, true);
    assert.equal(r.advice.length, 1);
    assert.match(r.advice[0], /未识别的文件类型/);
  } finally {
    sb.cleanup();
  }
});

test('已知扩展名给出针对性建议（docx 提醒不能直接登记）', () => {
  const sb = sandbox();
  try {
    const docx = join(sb.dir, 'AUTH.docx');
    writeFileSync(docx, CONTENT, 'utf8');
    const r = intakeAuthorization({ source: docx, dir: 'authorization', cwd: sb.dir });

    assert.equal(r.advice.length, 2);
    assert.match(r.advice[0], /可编辑文档不适合直接登记/);
    assert.match(r.advice[1], /转为 PDF/);
  } finally {
    sb.cleanup();
  }
});

test('ADVICE 覆盖邮件与扫描件这两类最需要提醒的载体', () => {
  assert.ok(ADVICE['.eml'][0].includes('发件人'), '邮件要提醒保留头部');
  assert.ok(ADVICE['.msg'][0].includes('.eml'), '.msg 要提醒转 eml');
  assert.ok(ADVICE['.pdf'][1].includes('重新扫描'), 'PDF 要提醒扫描件不可重现');
  for (const ext of ['.jpg', '.png']) {
    assert.ok(ADVICE[ext][0].includes('无法自证来源'), '图片要提醒来源问题');
  }
});

test('内容不同则哈希不同（登记能区分两份不同的授权书）', () => {
  const sb = sandbox();
  try {
    const a = intakeAuthorization({ source: sb.source, dir: 'auth-a', cwd: sb.dir });
    const changed = join(sb.dir, 'AUTH-002.txt');
    writeFileSync(changed, CONTENT + '追加了一个字的差别\n', 'utf8');
    const b = intakeAuthorization({ source: changed, dir: 'auth-b', cwd: sb.dir });

    assert.notEqual(a.sha256, b.sha256);
  } finally {
    sb.cleanup();
  }
});

test('二进制内容也能正确归档与哈希', () => {
  const sb = sandbox();
  try {
    const bin = join(sb.dir, '扫描件.png');
    const bytes = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x00, 0xff, 0xfe, 0x01]);
    writeFileSync(bin, bytes);

    const r = intakeAuthorization({ source: bin, dir: 'authorization', cwd: sb.dir });
    assert.equal(r.ok, true);
    assert.equal(r.sha256, fileSha256(bytes));
    assert.deepEqual(readFileSync(r.archive), bytes, '二进制内容必须逐字节一致');
  } finally {
    sb.cleanup();
  }
});

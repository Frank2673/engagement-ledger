/**
 * 单元测试：客户侧复核 + 测试夹具 PDF 生成
 *
 * 客户侧复核这个环节的价值全在"让人真能跑"：
 * 如果脚本自己解析不出报告里的哈希、或对"报告没登记哈希"这种情形含糊过去，
 * 客户就会退回肉眼比对 64 位十六进制 —— 那等于没有复核。
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  parseReportHash,
  parseJsonReportHash,
  compareReportToDocument,
  hashFile,
} from '../scripts/verify-report.mjs';
import { buildPdf, looksLikeValidPdf } from '../scripts/make-test-pdf.mjs';
import { validateManifest } from '../src/lib/manifest.mjs';
import { buildReport, buildJsonReport } from '../src/lib/report.mjs';
import { GENESIS_HASH } from '../src/lib/crypto.mjs';

const HASH = 'a1b2c3d4'.repeat(8);   // 64 位

function sandbox() {
  const dir = mkdtempSync(join(tmpdir(), 'el-vr-'));
  return { dir, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

/** 造一份真实报告（走完整 buildReport，而不是手写 markdown） */
function realReports(docSha = HASH) {
  const manifest = validateManifest({
    engagement: {
      id: 'ENG-001',
      name: '示例委托',
      tester: 'alice',
      authorization: { reference: 'AUTH-001', signedBy: 'bob', documentSha256: docSha },
      window: { from: '2026-09-01T00:00:00Z', to: '2026-12-31T00:00:00Z' },
      scope: { inScope: ['example.com'], outOfScope: [] },
      permittedActions: ['recon'],
      prohibitedActions: ['dos', 'destructive', 'data-exfiltration', 'persistence', 'social-engineering'],
      emergencyContact: 'bob@example.com',
    },
  });
  const entries = [];
  return {
    markdown: buildReport({ manifest, entries }),
    json: JSON.stringify(buildJsonReport({ manifest, entries })),
  };
}

/* ------------------------- 报告哈希解析 ------------------------- */

test('从真实 Markdown 报告里解析出登记哈希', () => {
  const { markdown } = realReports();
  const parsed = parseReportHash(markdown);

  assert.ok(parsed, '应能解析');
  assert.equal(parsed.hash, HASH);
  assert.equal(parsed.engagementId, 'ENG-001');
  assert.equal(parsed.reference, 'AUTH-001');
});

test('解析结果不受报告里其它 64 位哈希干扰（例如链头哈希）', () => {
  const { markdown } = realReports();
  const parsed = parseReportHash(markdown);

  /* 报告里还有链头哈希与锚定行，解析出来的必须是授权书的那一个 */
  assert.equal(parsed.hash, HASH);
  assert.notEqual(parsed.hash, GENESIS_HASH);
});

test('从 JSON 报告里解析出登记哈希', () => {
  const { json } = realReports();
  const parsed = parseJsonReportHash(json);
  assert.equal(parsed.hash, HASH);
  assert.equal(parsed.source, 'json');
});

test('非 JSON 文本不会让 JSON 解析器抛异常', () => {
  assert.equal(parseJsonReportHash('# 这是 markdown'), null);
  assert.equal(parseJsonReportHash(''), null);
});

test('报告里没有登记哈希时返回 null（不猜）', () => {
  assert.equal(parseReportHash('# 某份报告\n\n没有指纹信息。\n'), null);
  assert.equal(parseReportHash(''), null);
  assert.equal(parseReportHash(null), null);
});

/* ------------------------- 比对 ------------------------- */

test('哈希一致时判为 match', () => {
  const { markdown } = realReports();
  const r = compareReportToDocument(markdown, HASH);

  assert.equal(r.ok, true);
  assert.equal(r.status, 'match');
  assert.equal(r.registered, HASH);
  assert.equal(r.actual, HASH);
});

test('大小写不同的哈希视为一致（登记时可能写成大写）', () => {
  const { markdown } = realReports();
  assert.equal(compareReportToDocument(markdown, HASH.toUpperCase()).ok, true);
});

test('改动一个 bit 就判为 mismatch（哈希的判据性）', () => {
  const { markdown } = realReports();
  const changed = HASH.slice(0, -1) + (HASH.endsWith('a') ? 'b' : 'a');

  const r = compareReportToDocument(markdown, changed);
  assert.equal(r.ok, false);
  assert.equal(r.status, 'mismatch');
  assert.notEqual(r.registered, r.actual);
});

test('报告里没有登记哈希时给出专门状态，不误判为一致', () => {
  const r = compareReportToDocument('# 无指纹报告\n', HASH);
  assert.equal(r.ok, false);
  assert.equal(r.status, 'no-hash-in-report');
  assert.equal(r.actual, HASH, '仍应把手上这份的哈希算出来给用户看');
});

test('JSON 报告优先于 Markdown 解析（同一内容两条路径结果一致）', () => {
  const { markdown, json } = realReports();
  assert.equal(compareReportToDocument(json, HASH).ok, true);
  assert.equal(compareReportToDocument(markdown, HASH).ok, true);
});

/* ------------------------- 端到端：真实 PDF ------------------------- */

test('测试夹具 PDF 结构完整（有 %PDF 头、xref、startxref 指向正确）', () => {
  const pdf = buildPdf({ pages: 3 });

  assert.ok(pdf.length > 500);
  assert.equal(pdf.toString('latin1').startsWith('%PDF-1.4'), true);
  assert.equal(looksLikeValidPdf(pdf), true, 'xref 偏移必须指向真正的 xref');
});

test('looksLikeValidPdf 能识别坏文件（不误判）', () => {
  assert.equal(looksLikeValidPdf(Buffer.from('这不是 PDF')), false);
  assert.equal(looksLikeValidPdf(Buffer.from('%PDF-1.4\n但没有 xref 与 EOF')), false);
  /* 头部对、但 startxref 指向越界 */
  assert.equal(looksLikeValidPdf(Buffer.from('%PDF-1.4\nstartxref\n999999\n%%EOF\n')), false);
});

test('不同页数产出不同内容（夹具可参数化，不是写死的二进制）', () => {
  const a = buildPdf({ pages: 1 });
  const b = buildPdf({ pages: 5 });
  assert.notEqual(a.length, b.length);
  assert.equal(looksLikeValidPdf(a) && looksLikeValidPdf(b), true);
});

test('对真实 PDF 走通"归档 → 报告 → 客户复核"闭环', () => {
  const sb = sandbox();
  try {
    /* 执行人侧：生成并归档一份真实 PDF */
    const pdfPath = join(sb.dir, 'AUTH-001.pdf');
    writeFileSync(pdfPath, buildPdf({ pages: 2 }));
    const docHash = hashFile(pdfPath);

    /* 客户侧：拿同一份文件复核报告 */
    const { markdown } = realReports(docHash);
    const same = compareReportToDocument(markdown, hashFile(pdfPath));
    assert.equal(same.ok, true, '同一份文件必须判为一致');

    /* 客户拿的是被改过 1 bit 的版本 */
    const tampered = Buffer.from(readFileSync(pdfPath));
    tampered[50] ^= 0x01;
    const tamperedPath = join(sb.dir, 'AUTH-001-tampered.pdf');
    writeFileSync(tamperedPath, tampered);

    const different = compareReportToDocument(markdown, hashFile(tamperedPath));
    assert.equal(different.ok, false, '改 1 bit 必须判为不一致');
    assert.equal(different.status, 'mismatch');
  } finally {
    sb.cleanup();
  }
});

test('hashFile 对二进制逐字节敏感（PDF 里的 1 bit 改动会被发现）', () => {
  const sb = sandbox();
  try {
    const a = join(sb.dir, 'a.pdf');
    const b = join(sb.dir, 'b.pdf');
    const buf = buildPdf({ pages: 1 });

    writeFileSync(a, buf);
    const changed = Buffer.from(buf);
    changed[changed.length - 5] ^= 0x01;   // 改末尾附近 1 bit
    writeFileSync(b, changed);

    assert.notEqual(hashFile(a), hashFile(b));
  } finally {
    sb.cleanup();
  }
});

#!/usr/bin/env node
/**
 * 生成一份**真正的 PDF** 作为测试夹具
 *
 * 为什么不放一个二进制 PDF 进 fixtures/：二进制夹具看不见、改不动、也没法评审。
 * 用四十行代码生成，任何人都能读懂它是什么、验证它是不是真的 PDF。
 *
 * 不引第三方库：PDF 的基本结构很简单，xref 偏移量自己算。
 * 生成的产物有正确的 %PDF 头、对象表、xref 与 startxref，任何阅读器都能打开。
 *
 * 用法：
 *   node scripts/make-test-pdf.mjs <输出路径> [页数]
 */

import { writeFileSync } from 'node:fs';

/**
 * 构造一份多页 PDF
 * @param {object} [options]
 * @param {number} [options.pages] 页数
 * @returns {Buffer}
 */
export function buildPdf({ pages = 3 } = {}) {
  const objects = [];
  const push = (body) => {
    objects.push(body);
    return objects.length; // 对象号从 1 开始
  };

  /* 每页画三行说明文字（Helvetica 基础字体，无需嵌入） */
  const textForPage = (i) =>
    `BT /F1 18 Tf 72 720 Td (Penetration Test Authorization - Page ${i + 1} of ${pages}) Tj ET\n` +
    `BT /F1 11 Tf 72 690 Td (AUTH-2026-DEMO-001  signed 2026-09-01) Tj ET\n` +
    `BT /F1 11 Tf 72 670 Td (In scope: api.example.com  staging.example.com  192.0.2.0/28) Tj ET\n`;

  const fontId = push('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>');

  const contentIds = [];
  for (let i = 0; i < pages; i++) {
    const stream = textForPage(i);
    contentIds.push(push(`<< /Length ${Buffer.byteLength(stream, 'latin1')} >>\nstream\n${stream}endstream`));
  }

  /* 页树对象号要先确定（Page 对象里要引用它），然后回填 */
  const pagesObjectId = objects.length + pages + 1;
  const pageIds = [];
  for (let i = 0; i < pages; i++) {
    pageIds.push(
      push(
        `<< /Type /Page /Parent ${pagesObjectId} 0 R /MediaBox [0 0 612 792] ` +
          `/Resources << /Font << /F1 ${fontId} 0 R >> >> /Contents ${contentIds[i]} 0 R >>`
      )
    );
  }
  objects[pagesObjectId - 1] = `<< /Type /Pages /Kids [${pageIds.map((id) => `${id} 0 R`).join(' ')}] /Count ${pages} >>`;

  const catalogId = push(`<< /Type /Catalog /Pages ${pagesObjectId} 0 R >>`);

  let pdf = '%PDF-1.4\n%\xE2\xE3\xCF\xD3\n';   // 第二行是二进制标记，让工具按二进制处理
  const offsets = [];

  for (const [i, body] of objects.entries()) {
    offsets.push(Buffer.byteLength(pdf, 'latin1'));
    pdf += `${i + 1} 0 obj\n${body}\nendobj\n`;
  }

  const xrefOffset = Buffer.byteLength(pdf, 'latin1');
  pdf += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
  for (const off of offsets) {
    pdf += `${String(off).padStart(10, '0')} 00000 n \n`;
  }
  pdf += `trailer\n<< /Size ${objects.length + 1} /Root ${catalogId} 0 R >>\nstartxref\n${xrefOffset}\n%%EOF\n`;

  return Buffer.from(pdf, 'latin1');
}

/**
 * 检查一份缓冲内容看起来是不是结构完整的 PDF
 * （不是完整解析器，只验证关键结构存在且自洽 —— 够用来确认夹具真是 PDF）
 */
export function looksLikeValidPdf(buffer) {
  const s = buffer.toString('latin1');
  if (!s.startsWith('%PDF-')) return false;
  if (!s.trimEnd().endsWith('%%EOF')) return false;

  const m = s.match(/startxref\s+(\d+)\s*%%EOF\s*$/);
  if (!m) return false;

  const offset = Number(m[1]);
  return offset > 0 && offset < buffer.length && s.slice(offset, offset + 4) === 'xref';
}

if (process.argv[1] && /make-test-pdf\.mjs$/.test(process.argv[1])) {
  const out = process.argv[2];
  if (!out) {
    process.stderr.write('用法：node scripts/make-test-pdf.mjs <输出路径> [页数]\n');
    process.exit(1);
  }
  const pages = Number(process.argv[3] || 3);
  const buffer = buildPdf({ pages });
  writeFileSync(out, buffer);
  process.stdout.write(`已生成 ${out}（${pages} 页，${buffer.length} 字节，结构校验：${looksLikeValidPdf(buffer) ? '通过' : '失败'}）\n`);
}

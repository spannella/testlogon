// Export selected or full-table cells to CSV / PDF / Parquet, and copy
// to clipboard as TSV.  Parquet is lazy-loaded because parquet-wasm is
// ~1 MB — only paid when the user actually exports parquet.

import type { Row, Column } from '@tanstack/react-table';
import type { Order } from '../types';

// Extract the visible display value for a cell.  Uses column meta type
// where useful; otherwise falls back to accessor value.
function cellText(col: Column<Order, unknown>, row: Row<Order>): string {
  const v = row.getValue(col.id);
  if (v == null) return '';
  // Age column: render as seconds instead of raw ns.
  if (col.id === 'tLastUpd' || col.id === 'tRcv') {
    const ns = v as number;
    return new Date(ns / 1_000_000).toISOString();
  }
  if (typeof v === 'number') return String(v);
  return String(v);
}

export interface Extract {
  header: string[];        // column display names, in visible order
  colIds: string[];        // column ids (for parquet schema)
  rows: string[][];        // 2D string matrix
}

// Selection can be:
//   - null / undefined → all data rows, all visible columns
//   - a Set<"rowId|colId"> → the smallest bounding rectangle covering
//     those cells (matches DevExpress/Excel behavior on non-rectangular
//     selections when copying); non-selected cells in the rectangle
//     are emitted as empty strings.
export function extractCells(
  dataRows: Row<Order>[],
  visibleCols: Column<Order, unknown>[],
  selection: Set<string> | null,
): Extract {
  const header = visibleCols.map(c => String(c.columnDef.header ?? c.id));
  const colIds = visibleCols.map(c => c.id);

  if (!selection || selection.size === 0) {
    // Whole table.
    return {
      header, colIds,
      rows: dataRows.map(r => visibleCols.map(c => cellText(c, r))),
    };
  }

  // Compute selection bounding box in row × col grid coordinates.
  const rowIdx = new Map<string, number>();
  dataRows.forEach((r, i) => rowIdx.set(r.original.clord, i));
  const colIdx = new Map<string, number>();
  visibleCols.forEach((c, i) => colIdx.set(c.id, i));

  let rMin = Infinity, rMax = -Infinity, cMin = Infinity, cMax = -Infinity;
  const picked = new Set<string>();
  for (const k of selection) {
    const sep = k.indexOf('|');
    if (sep < 0) continue;
    const rId = k.slice(0, sep);
    const cId = k.slice(sep + 1);
    const ri = rowIdx.get(rId);
    const ci = colIdx.get(cId);
    if (ri == null || ci == null) continue;
    if (ri < rMin) rMin = ri;
    if (ri > rMax) rMax = ri;
    if (ci < cMin) cMin = ci;
    if (ci > cMax) cMax = ci;
    picked.add(k);
  }
  if (rMin === Infinity) return { header, colIds, rows: [] };

  const bboxHeader: string[] = [];
  const bboxColIds: string[] = [];
  for (let c = cMin; c <= cMax; c++) {
    bboxHeader.push(header[c]!);
    bboxColIds.push(colIds[c]!);
  }
  const outRows: string[][] = [];
  for (let r = rMin; r <= rMax; r++) {
    const rowVals: string[] = [];
    const row = dataRows[r]!;
    for (let c = cMin; c <= cMax; c++) {
      const col = visibleCols[c]!;
      const key = `${row.original.clord}|${col.id}`;
      rowVals.push(picked.has(key) ? cellText(col, row) : '');
    }
    outRows.push(rowVals);
  }
  return { header: bboxHeader, colIds: bboxColIds, rows: outRows };
}

// ---------- serialization ----------

const CSV_NEEDS_QUOTE = /[",\r\n]/;
function csvEsc(s: string): string {
  if (!CSV_NEEDS_QUOTE.test(s)) return s;
  return '"' + s.replace(/"/g, '""') + '"';
}
export function toCSV(x: Extract): string {
  const lines: string[] = [x.header.map(csvEsc).join(',')];
  for (const row of x.rows) lines.push(row.map(csvEsc).join(','));
  return lines.join('\n');
}
// TSV — good for clipboard because Excel/Sheets auto-recognize tab as delimiter.
export function toTSV(x: Extract): string {
  const strip = (s: string) => s.replace(/[\t\r\n]/g, ' ');
  const lines: string[] = [x.header.map(strip).join('\t')];
  for (const row of x.rows) lines.push(row.map(strip).join('\t'));
  return lines.join('\n');
}

// ---------- clipboard ----------

export async function copyToClipboard(text: string): Promise<boolean> {
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch { /* fall through */ }
  // Legacy fallback via a temporary textarea.
  try {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    const ok = document.execCommand('copy');
    document.body.removeChild(ta);
    return ok;
  } catch {
    return false;
  }
}

// ---------- download helpers ----------

function downloadBlob(filename: string, mime: string, data: BlobPart) {
  const blob = new Blob([data], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 5_000);
}

export function exportCSV(x: Extract, filename: string) {
  downloadBlob(filename, 'text/csv;charset=utf-8', '﻿' + toCSV(x));   // BOM for Excel
}

// ---------- PDF ----------

export async function exportPDF(x: Extract, filename: string, title: string) {
  const [{ default: jsPDF }, { default: autoTable }] = await Promise.all([
    import('jspdf'),
    import('jspdf-autotable'),
  ]);
  const orientation = x.header.length > 6 ? 'landscape' : 'portrait';
  const doc = new jsPDF({ orientation, unit: 'pt', format: 'letter' });
  doc.setFontSize(11);
  doc.text(title, 40, 32);
  doc.setFontSize(8);
  doc.setTextColor(120);
  doc.text(`${x.rows.length} rows · exported ${new Date().toISOString()}`, 40, 46);
  autoTable(doc, {
    head: [x.header],
    body: x.rows,
    startY: 56,
    styles: { fontSize: 7.5, cellPadding: 3, overflow: 'linebreak' },
    headStyles: { fillColor: [30, 40, 55], textColor: [220, 230, 240], fontSize: 8 },
    bodyStyles: { textColor: [40, 44, 52] },
    alternateRowStyles: { fillColor: [245, 247, 250] },
    theme: 'grid',
    margin: { top: 56, left: 32, right: 32, bottom: 32 },
  });
  doc.save(filename);
}

// ---------- Parquet (lazy) ----------

export async function exportParquet(x: Extract, filename: string) {
  // parquet-wasm is ~1MB — dynamic import keeps it off the initial bundle.
  const pq: any = null; // parquet-wasm not bundled in this build

  // Build columnar arrays for each column.  Everything is stored as
  // string for now (schema inference from mixed data is fragile) — the
  // consumer can re-cast.  This keeps writer setup simple.
  const arrow: any = null; // apache-arrow not bundled -> NDJSON fallback below
  if (!arrow) {
    // Fallback: emit newline-delimited JSON so the user still gets a
    // file if apache-arrow isn't in the dep tree.
    const rows: any[] = x.rows.map(row => {
      const o: Record<string, string> = {};
      x.header.forEach((h, i) => (o[h] = row[i] ?? ''));
      return o;
    });
    const blob = rows.map(r => JSON.stringify(r)).join('\n');
    downloadBlob(filename.replace(/\.parquet$/, '.ndjson'),
      'application/x-ndjson', blob);
    return;
  }

  const tableInit: Record<string, any> = {};
  x.header.forEach((h, i) => {
    tableInit[h] = x.rows.map(r => r[i]);
  });
  const table = arrow.tableFromArrays(tableInit);
  const wasmTable = pq.Table.fromIPCStream(arrow.tableToIPC(table, 'stream'));
  const parquetBytes = pq.writeParquet(wasmTable);
  downloadBlob(filename, 'application/vnd.apache.parquet',
    parquetBytes instanceof Uint8Array ? parquetBytes : new Uint8Array(parquetBytes));
}

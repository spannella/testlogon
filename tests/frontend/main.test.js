import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { JSDOM } from 'jsdom';

function loadUiDom() {
  const html = readFileSync(new URL('../../app/static/index.html', import.meta.url), 'utf8');
  const dom = new JSDOM(html, {
    runScripts: 'outside-only',
    url: 'http://localhost/',
  });

  dom.window.__SKIP_BOOT__ = true;
  dom.window.fetch = async () => {
    throw new Error('fetch should not be called during frontend unit tests');
  };

  const script = readFileSync(new URL('../../app/static/main.js', import.meta.url), 'utf8');
  dom.window.eval(script);
  return dom;
}

test('escapeHtml escapes reserved characters', () => {
  const dom = loadUiDom();
  const { escapeHtml } = dom.window;
  assert.equal(
    escapeHtml('<div class="x">&\"\'</div>'),
    '&lt;div class=&quot;x&quot;&gt;&amp;&quot;&#39;&lt;/div&gt;'
  );
});

test('fmtBytes formats sizes with expected precision', () => {
  const dom = loadUiDom();
  const { fmtBytes } = dom.window;
  assert.equal(fmtBytes(0), '0 B');
  assert.equal(fmtBytes(1024), '1 KB');
  assert.equal(fmtBytes(1536), '1.5 KB');
});

test('fmtDurSec renders human readable durations', () => {
  const dom = loadUiDom();
  const { fmtDurSec } = dom.window;
  assert.equal(fmtDurSec(59), '59s');
  assert.equal(fmtDurSec(3661), '1h 1m 1s');
});

test('fmtMoney adds currency and sign', () => {
  const dom = loadUiDom();
  const { fmtMoney } = dom.window;
  assert.equal(fmtMoney(1234, 'usd'), '12.34 USD');
  assert.equal(fmtMoney(-250, 'eur'), '-2.50 EUR');
});

test('modalShow and modalClose manage modal lifecycle', () => {
  const dom = loadUiDom();
  const { modalShow, modalClose, document } = dom.window;

  modalShow({
    title: 'Test Modal',
    bodyHtml: '<p>Body</p>',
    actions: [{ text: 'Ok', onClick: () => {} }],
  });

  const modal = document.querySelector('.modal-backdrop');
  assert.ok(modal);
  assert.equal(document.querySelectorAll('.modal-backdrop').length, 1);

  modalClose();
  assert.equal(document.querySelectorAll('.modal-backdrop').length, 0);
});

test('parseHttpError returns status codes when present', () => {
  const dom = loadUiDom();
  const { parseHttpError } = dom.window;
  assert.equal(parseHttpError('403: Forbidden'), 403);
  assert.equal(parseHttpError('Boom'), null);
});


test('isEditableImageFile supports mime type and extension checks', () => {
  const dom = loadUiDom();
  const { isEditableImageFile } = dom.window;
  assert.equal(isEditableImageFile({ type: 'file', name: 'photo.bin', content_type: 'image/png' }), true);
  assert.equal(isEditableImageFile({ type: 'file', name: 'photo.JPG', content_type: '' }), true);
  assert.equal(isEditableImageFile({ type: 'file', name: 'notes.txt', content_type: 'text/plain' }), false);
});

test('_fileMgrEditorNormalizeRect creates positive bounded rectangles', () => {
  const dom = loadUiDom();
  const { _fileMgrEditorNormalizeRect } = dom.window;
  assert.equal(
    JSON.stringify(_fileMgrEditorNormalizeRect({ x: 80, y: 40 }, { x: 10, y: 5 }, 100, 80)),
    JSON.stringify({ x: 10, y: 5, w: 70, h: 35 })
  );
  assert.equal(
    JSON.stringify(_fileMgrEditorNormalizeRect({ x: -20, y: -5 }, { x: 120, y: 90 }, 100, 80)),
    JSON.stringify({ x: 0, y: 0, w: 100, h: 80 })
  );
test('renderFileMgrList shows video poster when preview is ready', () => {
  const dom = loadUiDom();
  const { renderFileMgrList, document } = dom.window;
  renderFileMgrList([
    {
      type: 'file',
      name: 'clip.mp4',
      path: '/clip.mp4',
      size: 1024,
      preview_kind: 'video',
      preview_status: 'ready',
      poster_url: 'https://cdn.example/clip.webp',
    },
  ]);

  const img = document.querySelector('#filemgrTable tbody .filemgr-preview img');
  assert.ok(img);
  assert.equal(img.getAttribute('src'), 'https://cdn.example/clip.webp');
  assert.equal(img.getAttribute('alt'), 'Video preview poster');
});

test('renderFileMgrList shows audio waveform when preview is ready', () => {
  const dom = loadUiDom();
  const { renderFileMgrList, document } = dom.window;
  renderFileMgrList([
    {
      type: 'file',
      name: 'audio.mp3',
      path: '/audio.mp3',
      size: 1024,
      preview_kind: 'audio',
      preview_status: 'ready',
      waveform_url: 'https://cdn.example/audio.png',
    },
  ]);

  const img = document.querySelector('#filemgrTable tbody .filemgr-preview img');
  assert.ok(img);
  assert.equal(img.getAttribute('src'), 'https://cdn.example/audio.png');
  assert.equal(img.getAttribute('alt'), 'Audio waveform preview');
});

test('renderFileMgrList shows deterministic fallback for non-ready media preview states', () => {
  const dom = loadUiDom();
  const { renderFileMgrList, document } = dom.window;
  renderFileMgrList([
    {
      type: 'file',
      name: 'audio.mp3',
      path: '/audio.mp3',
      size: 1024,
      preview_kind: 'audio',
      preview_status: 'unsupported',
    },
  ]);

  const fallback = document.querySelector('#filemgrTable tbody .filemgr-preview-fallback');
  assert.ok(fallback);
  assert.equal(fallback.textContent.trim(), 'Audio preview unsupported');
});

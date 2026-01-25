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

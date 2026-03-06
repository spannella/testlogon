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
});
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


test('mountTroubleshootingMessage maps stable codes to actionable copy', () => {
  const dom = loadUiDom();
  const { mountTroubleshootingMessage } = dom.window;
  const message = mountTroubleshootingMessage({ last_error_code: 'sftp_destination_not_allowed' });
  assert.equal(message, 'Destination violates outbound policy. Update host or allowlist policy.');
});

test('refreshFileMgrMounts renders mount actions and status', async () => {
  const dom = loadUiDom();
  const { refreshFileMgrMounts, document } = dom.window;
  dom.window.apiGet = async () => ({
    items: [{
      id: 'm1',
      host: 'sftp.example.com',
      port: 22,
      remote_root: '/',
      read_only: true,
      status: 'degraded',
      last_error_code: 'sftp_network_error',
      last_error_message: 'network issue',
      last_tested_at: null,
    }],
  });

  await refreshFileMgrMounts();
  const row = document.querySelector('#filemgrMountList [data-mount-id="m1"]');
  assert.ok(row);
  assert.equal(row.querySelectorAll('button[data-action]').length, 5);
  assert.ok(row.textContent.includes('Read-only'));
  assert.ok(row.textContent.includes('Troubleshooting:'));
});


test('renderFileMgrList shows External grouping at mount namespace', async () => {
  const dom = loadUiDom();
  const { renderFileMgrList, refreshFileMgrMounts, setFileMgrPath, document } = dom.window;
  dom.window.apiGet = async () => ({
    items: [{ id: 'm1', host: 'sftp.example.com', port: 22, remote_root: '/', read_only: false, status: 'healthy' }],
  });
  await refreshFileMgrMounts();
  setFileMgrPath('/mounts/');
  renderFileMgrList([]);
  const header = document.querySelector('#filemgrTable tbody tr td[colspan="6"]');
  assert.ok(header);
  assert.ok(header.textContent.includes('External'));
});

test('renderFileMgrList shows write unsupported affordance for read-only mount rows', async () => {
  const dom = loadUiDom();
  const { renderFileMgrList, refreshFileMgrMounts, setFileMgrPath, document } = dom.window;
  dom.window.apiGet = async () => ({
    items: [{ id: 'm1', host: 'sftp.example.com', port: 22, remote_root: '/', read_only: true, status: 'healthy' }],
  });
  await refreshFileMgrMounts();
  setFileMgrPath('/mounts/m1/');
  renderFileMgrList([
    { type: 'file', name: 'readonly.txt', path: '/mounts/m1/readonly.txt', size: 3, updated_at: '' },
  ]);
  const actionsCell = document.querySelector('#filemgrTable tbody tr td:last-child');
  assert.ok(actionsCell);
  assert.equal(actionsCell.textContent.includes('Write unsupported'), true);
});


test('renderFileMgrMounts includes mock-files action for dev inspection', async () => {
  const dom = loadUiDom();
  const { refreshFileMgrMounts, document } = dom.window;
  dom.window.apiGet = async () => ({
    items: [{ id: 'm1', host: 'sftp.example.com', port: 22, remote_root: '/', read_only: false, status: 'healthy' }],
  });
  await refreshFileMgrMounts();
  const btn = document.querySelector('#filemgrMountList [data-mount-id="m1"] button[data-action="mock-files"]');
  assert.ok(btn);
});


test('openMockFilesModal supports breadcrumb, folder drill-down, up, refresh, and remembered path', async () => {
  const dom = loadUiDom();
  const { openMockFilesModal, modalClose, document } = dom.window;
  const calls = [];
  dom.window.apiGet = async (url) => {
    const u = new URL(`http://localhost${url}`);
    const path = u.searchParams.get('path') || '/';
    calls.push(path);
    if (path === '/') {
      return {
        mount_id: 'm1',
        owner: 'u1',
        backend: 'mock',
        path: '/',
        items: [{ name: 'team', path: '/team/', type: 'folder', size: 0, modified_at: 1 }],
        limit: 200,
        cursor: null,
      };
    }
    if (path === '/team/') {
      return {
        mount_id: 'm1',
        owner: 'u1',
        backend: 'mock',
        path: '/team/',
        items: [{ name: 'nested.txt', path: '/team/nested.txt', type: 'file', size: 1, modified_at: 1 }],
        limit: 200,
        cursor: null,
      };
    }
    throw new Error(`unexpected path ${path}`);
  };

  await openMockFilesModal('m1', '/');
  const openBtn = document.querySelector('[data-mock-folder-path="/team/"]');
  assert.ok(openBtn);
  openBtn.click();
  await new Promise((r) => setTimeout(r, 0));

  const upBtn = document.getElementById('filemgrMockUpBtn');
  assert.ok(upBtn);
  upBtn.click();
  await new Promise((r) => setTimeout(r, 0));

  const refreshBtn = document.getElementById('filemgrMockRefreshBtn');
  assert.ok(refreshBtn);
  refreshBtn.click();
  await new Promise((r) => setTimeout(r, 0));

  const rootCrumb = document.querySelector('[data-mock-breadcrumb-path="/"]');
  if (rootCrumb) {
    rootCrumb.click();
    await new Promise((r) => setTimeout(r, 0));
  }

  // Navigate into /team/ again and ensure subsequent open remembers path.
  const openBtnAgain = document.querySelector('[data-mock-folder-path="/team/"]');
  assert.ok(openBtnAgain);
  openBtnAgain.click();
  await new Promise((r) => setTimeout(r, 0));

  modalClose();
  await openMockFilesModal('m1');
  assert.equal(calls[calls.length - 1], '/team/');
  assert.ok(calls.includes('/'));
  assert.ok(calls.includes('/team/'));
});


test('openMockFilesModal supports sort/filter controls and copy helpers', async () => {
  const dom = loadUiDom();
  const { openMockFilesModal, document } = dom.window;
  const calls = [];
  dom.window.apiGet = async (url) => {
    calls.push(url);
    return {
      mount_id: 'm1',
      owner: 'u1',
      backend: 'mock',
      path: '/',
      filesystem_path: '/tmp/filemgr-sftp-mock/u1/m1',
      items: [
        { name: 'b.txt', path: '/b.txt', type: 'file', size: 20, modified_at: 2 },
        { name: 'a', path: '/a/', type: 'folder', size: 0, modified_at: 1 },
      ],
      limit: 200,
      cursor: null,
    };
  };
  let copied = '';
  dom.window.navigator.clipboard = { writeText: async (v) => { copied = v; } };

  await openMockFilesModal('m1', '/');
  const sortBy = document.getElementById('filemgrMockSortBy');
  const filterType = document.getElementById('filemgrMockFilterType');
  assert.ok(sortBy);
  assert.ok(filterType);

  filterType.value = 'file';
  filterType.dispatchEvent(new dom.window.Event('change'));
  await new Promise((r) => setTimeout(r, 0));

  sortBy.value = 'size';
  sortBy.dispatchEvent(new dom.window.Event('change'));
  await new Promise((r) => setTimeout(r, 0));

  const rows = [...document.querySelectorAll('.modal .list .list-item .mono')].map((el) => el.textContent);
  assert.ok(rows.some((v) => v.includes('/b.txt')));
  assert.equal(rows.some((v) => v.includes('/a/')), false);

  const copyMountBtn = document.getElementById('filemgrMockCopyMountPathBtn');
  const copyFsBtn = document.getElementById('filemgrMockCopyFsPathBtn');
  assert.ok(copyMountBtn);
  assert.ok(copyFsBtn);
  copyFsBtn.click();
  await new Promise((r) => setTimeout(r, 0));
  assert.equal(copied, '/tmp/filemgr-sftp-mock/u1/m1');
  assert.ok(calls.length >= 1);
});

test('openMockFilesModal shows remediation copy for common mock browser errors', async () => {
  const dom = loadUiDom();
  const { openMockFilesModal, document } = dom.window;
  dom.window.apiGet = async () => {
    throw '404: {"code":"mock_path_not_found","message":"mock path not found","path":"/missing"}';
  };

  await openMockFilesModal('m1', '/missing');
  const modalText = document.querySelector('.modal .modal-body').textContent;
  assert.ok(modalText.includes('Path not found in mock filesystem'));
  assert.ok(modalText.includes('create the folder/file'));
  const copyBtn = document.getElementById('filemgrMockErrCopyMountPathBtn');
  assert.ok(copyBtn);
});

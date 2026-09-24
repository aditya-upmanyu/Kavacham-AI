/* ====================================================================
   KAVACHAM LAB — EVIDENCE DETAIL (Phase 6, Sections 22 & 23)
   Renders the custody chain and performs a real integrity check.
   INTEGRITY VERIFIED is only ever shown when the server reports hashes
   actually matched; otherwise MISMATCH / UNAVAILABLE is shown.
   ==================================================================== */
(function () {
  'use strict';

  var esc = window.LAB.esc;
  var fmtTs = window.LAB.fmtTs;
  var REF = window.__LAB_EVD_REF__;

  var view = document.getElementById('evd-view');
  var loading = document.getElementById('evd-loading');
  var errorHost = document.getElementById('evd-error');
  var verifyHost = document.getElementById('evd-verify-result');
  var current = null;

  function fmtSize(n) {
    if (n === null || n === undefined) return '—';
    if (n < 1024) return n + ' B';
    if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
    return (n / 1048576).toFixed(2) + ' MB';
  }

  function integrityBadge(state) {
    var cls = 'lab-badge-amber';
    if (state === 'VERIFIED' || state === 'INTEGRITY VERIFIED') cls = 'lab-badge-green';
    else if (state === 'INTEGRITY MISMATCH') cls = 'lab-badge-red';
    else if (state === 'UNVERIFIED') cls = 'lab-badge-gray';
    return '<span class="lab-badge ' + cls + '">' + esc(state || 'UNVERIFIED') + '</span>';
  }

  /* ---------------- Load ---------------- */
  function load() {
    loading.hidden = false;
    view.hidden = true;
    errorHost.hidden = true;

    fetch('/lab/api/evidence/' + encodeURIComponent(REF), {
      headers: { 'Accept': 'application/json' }, credentials: 'same-origin'
    })
      .then(function (res) {
        return res.json().then(function (body) {
          if (!res.ok || body.success !== true) {
            var e = (body && body.error) || {};
            throw { code: e.code || 'REQUEST_FAILED',
                    message: e.message || 'The evidence record could not be retrieved.' };
          }
          return body.data.evidence;
        });
      })
      .then(function (ev) {
        current = ev;
        render(ev);
        loading.hidden = true;
        errorHost.hidden = true;
        view.hidden = false;
      })
      .catch(function (err) {
        loading.hidden = true;
        errorHost.hidden = false;
        window.LAB.renderError(errorHost,
          (err && err.code) || 'NETWORK_ERROR',
          (err && err.message) || 'The evidence record could not be retrieved.',
          { label: 'RETRY', onClick: load });
      });
  }

  /* ---------------- Render ---------------- */
  function render(ev) {
    document.title = ev.evidence_ref + ' — KAVACHAM LAB';
    document.getElementById('ev-ref').textContent = ev.evidence_ref;
    document.getElementById('ev-type').textContent = ev.evidence_type;
    document.getElementById('ev-integrity').innerHTML =
      integrityBadge(ev.integrity_state);
    document.getElementById('ev-title').textContent = ev.title;
    document.getElementById('ev-acquired').textContent =
      fmtTs(ev.acquired_at) + ' UTC';
    document.getElementById('ev-source').textContent = ev.source;
    document.getElementById('ev-case').textContent =
      ev.case ? ev.case.case_ref : 'Unattached';

    document.getElementById('ev-counts').innerHTML = [
      ['SHA-256 PRESENT', ev.sha256 ? 'YES' : 'NO'],
      ['SIZE', fmtSize(ev.size_bytes)],
      ['STORED ORIGINAL', ev.stored ? (ev.stored_file_exists ? 'PRESENT' : 'MISSING') : 'N/A'],
      ['CUSTODY EVENTS', ev.custody.length],
      ['CHAIN', ev.custody_verification.ok ? 'VERIFIED' : 'BROKEN'],
      ['LINKED ANALYSES', ev.analyses.length]
    ].map(function (p) {
      return '<div class="lab-strip-item"><span class="lab-label">' + esc(p[0]) +
        '</span><span class="lab-strip-value">' + esc(String(p[1])) + '</span></div>';
    }).join('');

    renderMeta(ev);
    renderCustody(ev);
    renderContent(ev);
    renderAnalyses(ev);
  }

  function renderMeta(ev) {
    var rows = [
      ['EVIDENCE ID', ev.evidence_ref, true],
      ['TYPE', ev.evidence_type, false],
      ['ORIGINAL FILENAME', ev.original_filename || '—', true],
      ['SHA-256', ev.sha256, true],
      ['SHA-1', ev.sha1, true],
      ['MD5', ev.md5, true],
      ['MIME TYPE', ev.mime_type || '—', true],
      ['SIZE', fmtSize(ev.size_bytes), true],
      ['EXTENSION', ev.extension || '—', true],
      ['SOURCE', ev.source, false],
      ['ACQUIRED', fmtTs(ev.acquired_at) + ' UTC', true],
      ['INTEGRITY STATE', ev.integrity_state, false],
      ['STORED ORIGINAL', ev.stored
        ? (ev.stored_file_exists ? 'Present' : 'Missing')
        : 'Not applicable (text evidence)', false],
      ['CASE', ev.case ? ev.case.case_ref : 'Unattached', true]
    ];
    if (ev.notes) rows.push(['NOTES', ev.notes, false]);

    document.getElementById('ev-meta').innerHTML = rows.map(function (r) {
      return '<dt>' + esc(r[0]) + '</dt><dd' + (r[2] ? ' class="lab-mono"' : '') +
        '>' + esc(String(r[1])) + '</dd>';
    }).join('');
  }

  /* ---------------- Chain of custody (Section 22) ---------------- */
  function renderCustody(ev) {
    var host = document.getElementById('ev-custody');
    var count = document.getElementById('ev-custody-count');
    var v = ev.custody_verification || {};

    if (count) {
      count.textContent = ev.custody.length + ' EVENT' +
        (ev.custody.length === 1 ? '' : 'S') +
        (v.ok ? ' · CHAIN VERIFIED' : ' · CHAIN BROKEN');
    }

    if (!ev.custody.length) {
      host.innerHTML = '';
      host.appendChild(window.LAB.emptyState('—', 'NO CUSTODY EVENTS',
        'No chain of custody has been recorded for this item.', null));
      return;
    }

    var chainAlert = v.ok
      ? '<div class="lab-alert is-success" style="margin-bottom:12px;">' +
        '<span class="lab-alert-icon">✓</span><div>' +
        '<div class="lab-alert-title">CUSTODY CHAIN VERIFIED</div>' +
        '<div>' + esc(v.detail || '') + '</div></div></div>'
      : '<div class="lab-alert is-critical" style="margin-bottom:12px;">' +
        '<span class="lab-alert-icon">!</span><div>' +
        '<div class="lab-alert-title">CUSTODY CHAIN BROKEN</div>' +
        '<div>' + esc(v.detail || 'Hash chain verification failed.') + '</div>' +
        (v.broken_at ? '<div class="lab-provenance" style="margin-top:6px;">' +
          'BROKEN AT LINK ' + v.broken_at + '</div>' : '') +
        '</div></div>';

    host.innerHTML = chainAlert + '<ol class="lab-timeline">' +
      ev.custody.map(function (c) {
        return '<li class="lab-timeline-item">' +
          '<div class="lab-timeline-marker" aria-hidden="true"></div>' +
          '<div class="lab-timeline-body">' +
          '<div class="lab-row tight">' +
          '<span class="lab-badge lab-badge-blue">' + esc(c.action) + '</span>' +
          '<span class="lab-mono lab-xs lab-dim">' +
          esc(fmtTs(c.created_at)) + ' UTC</span></div>' +
          (c.details ? '<div class="lab-xs lab-dim" style="margin-top:4px;">' +
            esc(c.details) + '</div>' : '') +
          '<div class="lab-provenance" style="margin-top:6px;">' +
          esc(c.actor || 'analyst') + '</div>' +
          '<div class="lab-mono lab-xs lab-dim" style="margin-top:4px;' +
          'overflow-wrap:anywhere;">entry ' +
          esc(String(c.entry_hash).slice(0, 32)) + '…</div>' +
          '</div></li>';
      }).join('') + '</ol>';
  }

  /* ---------------- Stored content ---------------- */
  function renderContent(ev) {
    var host = document.getElementById('ev-content');
    if (ev.content_text) {
      host.innerHTML = '<div class="lab-panel-body">' +
        '<pre class="lab-evidence-pre">' + esc(ev.content_text) + '</pre></div>';
      return;
    }
    if (ev.stored) {
      host.innerHTML = '<div class="lab-panel-body">' +
        '<p class="lab-dim lab-sm">Original bytes stored and hash-confirmed at ' +
        'acquisition. Use VERIFY INTEGRITY to recompute the digest.</p>' +
        '<div class="lab-provenance" style="margin-top:9px;">' +
        esc(ev.mime_type || 'unknown') + '</div></div>';
      return;
    }
    host.innerHTML = '';
    host.appendChild(window.LAB.emptyState('—', 'NO STORED CONTENT',
      'This record holds metadata only.', null));
  }

  function renderAnalyses(ev) {
    var host = document.getElementById('ev-analyses');
    if (!ev.analyses.length) {
      host.innerHTML = '';
      host.appendChild(window.LAB.emptyState('—', 'NO LINKED ANALYSES',
        'No analysis has been run against this evidence.', null));
      return;
    }
    host.innerHTML = '<div class="lab-table-wrap"><table class="lab-table">' +
      '<thead><tr><th scope="col">Analysis</th><th scope="col">Type</th>' +
      '<th scope="col">Verdict</th><th scope="col">Created</th></tr></thead><tbody>' +
      ev.analyses.map(function (a) {
        return '<tr><td class="lab-mono lab-strong">' + esc(a.analysis_ref) + '</td>' +
          '<td><span class="lab-badge">' + esc(a.analysis_type) + '</span></td>' +
          '<td>' + (a.verdict
            ? '<span class="lab-badge lab-badge-amber">' + esc(a.verdict) + '</span>'
            : '—') + '</td>' +
          '<td class="lab-mono lab-xs">' + esc(fmtTs(a.created_at)) + '</td></tr>';
      }).join('') + '</tbody></table></div>';
  }

  /* ---------------- Integrity verification (Section 23) ---------------- */
  document.getElementById('ev-verify').addEventListener('click', function () {
    var btn = this;
    btn.disabled = true;
    btn.textContent = 'VERIFYING…';

    fetch('/lab/api/evidence/' + encodeURIComponent(REF) + '/verify', {
      method: 'POST',
      headers: { 'Accept': 'application/json' },
      credentials: 'same-origin'
    })
      .then(function (res) {
        return res.json().then(function (body) {
          if (!res.ok || body.success !== true) {
            var e = (body && body.error) || {};
            throw { code: e.code || 'VERIFY_FAILED',
                    message: e.message || 'Integrity could not be verified.' };
          }
          return body.data.verification;
        });
      })
      .then(function (v) {
        showVerification(v);
        window.LAB.toast('Integrity checked', v.status, v.status === 'INTEGRITY VERIFIED'
          ? 'success' : 'warning');
        load();
      })
      .catch(function (err) {
        verifyHost.innerHTML = '<div class="lab-alert is-critical">' +
          '<span class="lab-alert-icon">!</span><div>' +
          '<div class="lab-alert-title">VERIFICATION INTERRUPTED</div>' +
          '<div>' + esc((err && err.message) ||
            'Integrity could not be verified.') + '</div>' +
          '<div class="lab-provenance" style="margin-top:6px;">' +
          esc((err && err.code) || 'VERIFY_FAILED') + '</div></div></div>';
      })
      .then(function () {
        btn.disabled = false;
        btn.textContent = 'VERIFY INTEGRITY';
      });
  });

  function showVerification(v) {
    var matched = v.current_sha256 && v.original_sha256 === v.current_sha256;
    var cls = v.status === 'INTEGRITY VERIFIED' ? 'is-success'
      : v.status === 'INTEGRITY MISMATCH' ? 'is-critical' : 'is-warning';
    var icon = v.status === 'INTEGRITY VERIFIED' ? '✓'
      : v.status === 'INTEGRITY MISMATCH' ? '!' : '?';

    verifyHost.innerHTML =
      '<div class="lab-panel"><div class="lab-panel-head">' +
      '<h2 class="lab-section-title">INTEGRITY RESULT</h2>' +
      '<span class="lab-badge ' +
      (v.status === 'INTEGRITY VERIFIED' ? 'lab-badge-green'
        : v.status === 'INTEGRITY MISMATCH' ? 'lab-badge-red' : 'lab-badge-amber') +
      '">' + esc(v.status) + '</span></div>' +
      '<div class="lab-panel-body">' +
      '<div class="lab-alert ' + cls + '" style="margin-bottom:12px;">' +
      '<span class="lab-alert-icon">' + icon + '</span><div>' +
      '<div class="lab-alert-title">' + esc(v.status) + '</div>' +
      '<div>' + esc(v.detail) + '</div></div></div>' +
      '<dl class="lab-kv">' +
      '<dt>ORIGINAL SHA-256</dt><dd class="lab-mono" style="overflow-wrap:anywhere;">' +
      esc(v.original_sha256) + '</dd>' +
      '<dt>CURRENT SHA-256</dt><dd class="lab-mono" style="overflow-wrap:anywhere;">' +
      esc(v.current_sha256 || 'NOT COMPUTABLE') + '</dd>' +
      '<dt>HASHES MATCH</dt><dd>' + (matched ? 'YES' : 'NO') + '</dd>' +
      '<dt>CHECKED</dt><dd class="lab-mono">' +
      esc(fmtTs(v.checked_at)) + ' UTC</dd>' +
      '</dl></div></div>';
  }

  load();
})();

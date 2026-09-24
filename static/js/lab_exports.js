/* ====================================================================
   KAVACHAM LAB — Export Center + Evidence Manifest (Sections 43/70/BG)
   Lists real export packages, creates new ones, renders the manifest
   table and verifies package integrity (stored SHA-256 vs recomputed).
   ==================================================================== */
(function () {
  'use strict';

  /* ---------------- shared state ---------------- */
  var exportsList = [];

  /* ---------------- export center ---------------- */
  var listBody = document.getElementById('exports-list-body');
  var listFoot = document.getElementById('exports-list-foot');
  var listTs = document.getElementById('exports-ts');
  var genPanel = document.getElementById('exports-generate');
  var caseSel = document.getElementById('exports-case');
  var submitBtn = document.getElementById('exports-submit');
  var statusEl = document.getElementById('exports-status');

  function caseOptions() {
    fetch('/lab/api/cases?limit=200', { headers: { 'Accept': 'application/json' } })
      .then(function (r) { return r.json(); })
      .then(function (b) {
        if (!b || !b.data || !b.data.items) return;
        caseSel.innerHTML = '<option value="">Select a case…</option>' +
          b.data.items.map(function (c) {
            return '<option value="' + LAB.esc(c.case_ref) + '">' +
              LAB.esc(c.case_ref) + ' — ' + LAB.esc(c.title || '') + '</option>';
          }).join('');
        caseSel.disabled = false;
      })
      .catch(function () {});
  }

  function toggleGenerate(open) {
    if (!genPanel) return;
    genPanel.hidden = !open;
    if (open) { caseOptions(); caseSel.disabled = true; }
  }

  function refreshExports() {
    fetch('/lab/api/exports', { headers: { 'Accept': 'application/json' } })
      .then(function (r) { return r.json(); })
      .then(function (b) {
        if (!b || b.success !== true || !b.data) {
          LAB.renderError(listBody, (b && b.error && b.error.code) || 'EXPORTS_UNAVAILABLE',
            (b && b.error && b.error.message) || 'Export packages could not be listed.');
          if (listFoot) listFoot.textContent = '';
          return;
        }
        exportsList = b.data.items || [];
        if (listTs) listTs.textContent = exportsList.length + ' package(s)';
        if (!exportsList.length) {
          listBody.innerHTML = '';
          listBody.appendChild(LAB.emptyState('0', 'NO EXPORT PACKAGES',
            'Export a case to build a verifiable investigation package.'));
          if (listFoot) listFoot.textContent = '';
          return;
        }
        var html = '<div class="lab-table-wrap"><table class="lab-table"><thead><tr>' +
          '<th scope="col">Export</th><th scope="col">Case</th><th scope="col">Report</th>' +
          '<th scope="col">Items</th><th scope="col">SHA-256</th><th scope="col">Created</th>' +
          '<th scope="col"></th></tr></thead><tbody>';
        exportsList.forEach(function (x) {
          html += '<tr>' +
            '<td class="lab-mono lab-strong">' + LAB.esc(x.export_ref) + '</td>' +
            '<td class="lab-mono">' + LAB.esc(x.case_ref) + '</td>' +
            '<td class="lab-mono">' + LAB.esc(x.report_ref || '—') + '</td>' +
            '<td class="lab-mono">' + x.item_count + '</td>' +
            '<td class="lab-mono lab-dim">' + LAB.esc((x.sha256 || '').slice(0, 16)) + '…</td>' +
            '<td class="lab-mono">' + (LAB.fmtTs(x.created_at) || x.created_at) + '</td>' +
            '<td><a class="lab-link" href="/lab/reports/manifest?export=' + encodeURIComponent(x.export_ref) +
            '">Manifest</a></td></tr>';
        });
        html += '</tbody></table></div>';
        listBody.innerHTML = html;
        if (listFoot) listFoot.textContent = '';
      })
      .catch(function () {
        LAB.renderError(listBody, 'EXPORTS_UNAVAILABLE', 'Export packages could not be listed.', {
          label: 'Retry', onClick: refreshExports
        });
        if (listFoot) listFoot.textContent = '';
      });
  }

  function createExport() {
    var caseRef = caseSel.value;
    if (!caseRef) return;
    submitBtn.disabled = true;
    if (statusEl) statusEl.textContent = 'Building package…';
    fetch('/lab/api/cases/' + encodeURIComponent(caseRef) + '/export', {
      method: 'POST',
      headers: { 'Accept': 'application/json' }
    })
      .then(function (r) { return r.json(); })
      .then(function (b) {
        if (!b || b.success !== true || !b.data) {
          var err = b && b.error ? b.error : { code: 'EXPORT_FAILED', message: 'Export failed.' };
          LAB.toast('ERROR', err.code + ' — ' + err.message, 'error');
          if (statusEl) statusEl.textContent = '';
          return;
        }
        LAB.toast('PACKAGE CREATED', b.data.export_ref + ' · sha256 ' + b.data.sha256.slice(0, 12) + '…', 'success');
        toggleGenerate(false);
        refreshExports();
      })
      .catch(function () {
        LAB.toast('ERROR', 'Export failed.', 'error');
        if (statusEl) statusEl.textContent = '';
      })
      .finally(function () { submitBtn.disabled = true; });
  }

  /* ---------------- manifest page ---------------- */
  var selEl = document.getElementById('manifest-export');
  var metaEl = document.getElementById('manifest-meta');
  var countEl = document.getElementById('manifest-count');
  var bodyEl = document.getElementById('manifest-body');
  var footEl = document.getElementById('manifest-foot');
  var verifyBtn = document.getElementById('manifest-verify');
  var verifyPanel = document.getElementById('manifest-verify-result');
  var verifyBody = document.getElementById('manifest-verify-body');

  function setVerifyBtn() {
    if (verifyBtn) verifyBtn.disabled = !selEl || !selEl.value;
  }

  function loadSelector() {
    if (!selEl) return;
    fetch('/lab/api/exports', { headers: { 'Accept': 'application/json' } })
      .then(function (r) { return r.json(); })
      .then(function (b) {
        if (!b || b.success !== true || !b.data) return;
        exportsList = b.data.items || [];
        selEl.innerHTML = '<option value="">Select an export package…</option>' +
          exportsList.map(function (x) {
            return '<option value="' + LAB.esc(x.export_ref) + '">' +
              LAB.esc(x.export_ref) + ' — ' + LAB.esc(x.case_ref) + '</option>';
          }).join('');
        // prefill from ?export=
        var wanted = '';
        try { wanted = new URLSearchParams(window.location.search).get('export') || ''; } catch (e) {}
        if (wanted) selEl.value = wanted;
        setVerifyBtn();
        if (selEl.value) loadManifest(selEl.value);
      })
      .catch(function () {});
  }

  function loadManifest(exportRef) {
    if (metaEl) metaEl.textContent = 'Loading ' + exportRef + '…';
    fetch('/lab/api/exports/' + encodeURIComponent(exportRef),
      { headers: { 'Accept': 'application/json' } })
      .then(function (r) { return r.json(); })
      .then(function (b) {
        if (!b || b.success !== true || !b.data) {
          var err = b && b.error ? b.error : { code: 'EXPORT_UNAVAILABLE', message: 'Package unavailable.' };
          LAB.renderError(bodyEl, err.code, err.message);
          if (metaEl) metaEl.textContent = '';
          return;
        }
        var d = b.data;
        if (metaEl) metaEl.textContent = 'case ' + d.case_ref + ' · report ' +
          (d.report_ref || '—') + ' · created ' + (LAB.fmtTs(d.created_at) || d.created_at);
        var manifest = d.manifest && d.manifest.evidence_manifest
          ? d.manifest.evidence_manifest : [];
        if (countEl) countEl.textContent = manifest.length + ' row(s)';
        if (!manifest.length) {
          bodyEl.innerHTML = '';
          bodyEl.appendChild(LAB.emptyState('0', 'EMPTY MANIFEST',
            'No analysis records exist in this package\u2019s manifest.'));
          return;
        }
        var html = '<div class="lab-table-wrap"><table class="lab-table"><thead><tr>' +
          '<th scope="col">Export</th><th scope="col">Case</th><th scope="col">Evidence</th>' +
          '<th scope="col">Analysis</th><th scope="col">SHA-256</th><th scope="col">Acquired</th>' +
          '<th scope="col">Analysed</th><th scope="col">Engine</th><th scope="col">Result</th>' +
          '</tr></thead><tbody>';
        manifest.forEach(function (m) {
          html += '<tr>' +
            '<td class="lab-mono">' + LAB.esc(m.export_id || '—') + '</td>' +
            '<td class="lab-mono">' + LAB.esc(m.case_id || '—') + '</td>' +
            '<td class="lab-mono">' + LAB.esc(m.evidence_id || '—') + '</td>' +
            '<td class="lab-mono">' + LAB.esc(m.analysis_id || '—') + '</td>' +
            '<td class="lab-mono lab-dim">' + LAB.esc(m.sha256 || '—') + '</td>' +
            '<td class="lab-mono">' + LAB.esc(m.acquisition_time || '—') + '</td>' +
            '<td class="lab-mono">' + LAB.esc(m.analysis_time || '—') + '</td>' +
            '<td class="lab-mono">' + LAB.esc(m.engine || '—') + '</td>' +
            '<td>' + LAB.esc(m.result || '—') + '</td></tr>';
        });
        html += '</tbody></table></div>';
        bodyEl.innerHTML = html;
        if (footEl) footEl.hidden = true;
      })
      .catch(function () {
        LAB.renderError(bodyEl, 'EXPORT_UNAVAILABLE', 'The package could not be read.', {
          label: 'Retry', onClick: function () { loadManifest(exportRef); }
        });
      });
  }

  function verify(exportRef) {
    if (!exportRef) return;
    verifyPanel.hidden = false;
    verifyBody.innerHTML = '<div class="lab-skeleton lab-skeleton-line" style="width:60%;"></div>' +
      '<p class="lab-xs lab-dim" style="margin-top:8px;">Recomputing package SHA-256…</p>';
    fetch('/lab/api/exports/' + encodeURIComponent(exportRef) + '/verify', {
      method: 'POST', headers: { 'Accept': 'application/json' }
    })
      .then(function (r) { return r.json(); })
      .then(function (b) {
        if (!b || b.success !== true || !b.data) {
          var err = b && b.error ? b.error : { code: 'VERIFY_FAILED', message: 'Verification failed.' };
          verifyBody.innerHTML = '<span class="lab-badge lab-badge-red">VERIFY ERROR</span>' +
            ' <span class="lab-sm">' + LAB.esc(err.message) + '</span>';
          return;
        }
        var v = b.data;
        var badge = v.status === 'VERIFIED'
          ? '<span class="lab-badge lab-badge-green">' + LAB.esc(v.status) + '</span>'
          : '<span class="lab-badge lab-badge-red">' + LAB.esc(v.status) + '</span>';
        verifyBody.innerHTML = badge +
          '<p class="lab-sm" style="margin:8px 0 0;">' + LAB.esc(v.message) + '</p>' +
          '<p class="lab-xs lab-dim lab-mono" style="margin:4px 0 0;">stored    ' +
          LAB.esc(v.stored_sha256 || '—') + '<br/>recomputed ' + LAB.esc(v.recomputed_sha256 || '—') + '</p>';
      })
      .catch(function () {
        verifyBody.innerHTML = '<span class="lab-badge lab-badge-red">VERIFY ERROR</span>';
      });
  }

  /* ---------------- bindings ---------------- */
  if (genPanel) {
    var newBtn = document.getElementById('exports-new');
    if (newBtn) newBtn.addEventListener('click', function () { toggleGenerate(!genPanel.hidden); });
    var cancelBtn = document.getElementById('exports-cancel');
    if (cancelBtn) cancelBtn.addEventListener('click', function () { toggleGenerate(false); });
    if (caseSel) caseSel.addEventListener('change', function () { submitBtn.disabled = !caseSel.value; });
    if (submitBtn) submitBtn.addEventListener('click', createExport);
    toggleGenerate(false);
    refreshExports();
  }

  if (selEl) {
    selEl.addEventListener('change', function () {
      setVerifyBtn();
      if (selEl.value) loadManifest(selEl.value);
    });
    if (verifyBtn) verifyBtn.addEventListener('click', function () { verify(selEl.value); });
    loadSelector();
  }
})();
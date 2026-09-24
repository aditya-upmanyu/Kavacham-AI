/* ====================================================================
   KAVACHAM LAB — ANALYSIS WORKBENCH (Phase 7, Sections 29-41)
   Filtered list backed by GET /lab/api/analysis. Every verdict shown
   is whatever the persisted run reports — never synthesised.
   ==================================================================== */
(function () {
  'use strict';

  var esc = window.LAB.esc;
  var fmtTs = window.LAB.fmtTs;

  var els = {
    body: document.getElementById('an-body'),
    foot: document.getElementById('an-foot'),
    total: document.getElementById('an-total'),
    search: document.getElementById('an-search'),
    type: document.getElementById('an-type'),
    status: document.getElementById('an-status'),
    caseRef: document.getElementById('an-case'),
    clear: document.getElementById('an-clear')
  };

  var debounceTimer = null;

  function verdictBadge(verdict) {
    var v = String(verdict || '—').toUpperCase();
    var cls = 'lab-badge-gray';
    if (v === 'SAFE' || v === 'CLEAN' || v === 'NOT_SPAM') {
      cls = 'lab-badge-green';
    } else if (v === 'SUSPICIOUS' || v === 'PARTIAL') {
      cls = 'lab-badge-amber';
    } else if (v.match(/MALICIOUS|HIGH|CRITICAL|BROKEN|MISMATCH/)) {
      cls = 'lab-badge-red';
    } else if (v.match(/UNAVAILABLE|UNKNOWN|NO_/)) {
      cls = 'lab-badge-gray';
    }
    return '<span class="lab-badge ' + cls + '">' + esc(v) + '</span>';
  }

  function statusBadge(status) {
    var cls = status === 'COMPLETE' ? 'lab-badge-green'
      : status === 'PARTIAL' ? 'lab-badge-amber' : 'lab-badge-red';
    return '<span class="lab-badge ' + cls + '">' + esc(status) + '</span>';
  }

  function buildQuery() {
    var p = new URLSearchParams();
    if (els.search && els.search.value.trim()) p.set('q', els.search.value.trim());
    if (els.type && els.type.value) p.set('type', els.type.value);
    if (els.status && els.status.value) p.set('status', els.status.value);
    if (els.caseRef && els.caseRef.value.trim()) p.set('case', els.caseRef.value.trim());
    p.set('limit', '100');
    return p.toString();
  }

  function renderRows(items) {
    if (!items.length) {
      var hasFilter = (els.search.value.trim()) || els.type.value ||
        els.status.value || (els.caseRef.value.trim());
      var empty = window.LAB.emptyState(
        hasFilter ? '?' : '—',
        hasFilter ? 'NO MATCHING ANALYSES' : 'NO ANALYSES RUN',
        hasFilter
          ? 'No analysis run matches the current filter.'
          : 'No analysis has been run yet. Execute one from the evidence vault or the Run Analysis page.',
        hasFilter
          ? { label: 'CLEAR FILTERS', onClick: clearFilters }
          : { label: 'RUN ANALYSIS', onClick: function () { location.href = '/lab/analysis/new'; } }
      );
      els.body.innerHTML = '';
      els.body.appendChild(empty);
      return;
    }

    var rowsHtml = items.map(function (a) {
      return '<tr class="is-clickable" data-ref="' + esc(a.analysis_ref) + '">' +
        '<td><span class="lab-mono lab-strong">' + esc(a.analysis_ref) + '</span>' +
          '<div class="lab-xs lab-dim" style="margin-top:3px;">' +
          esc(fmtTs(a.created_at)) + '</div></td>' +
        '<td><span class="lab-badge lab-badge-blue">' + esc(a.analysis_type) + '</span>' +
          '<div class="lab-xs lab-dim" style="margin-top:3px;">' +
          esc(a.engine_version || '') + '</div></td>' +
        '<td>' + statusBadge(a.status) + '</td>' +
        '<td>' + verdictBadge(a.verdict) + '</td>' +
        '<td><span class="lab-mono lab-xs">' + esc(String(a.risk_score === null || a.risk_score === undefined ? '—' : a.risk_score)) + '</span></td>' +
        '<td><span class="lab-mono lab-xs">' + esc(a.evidence_ref || '—') + '</span></td>' +
        '<td><span class="lab-mono lab-xs">' + esc(a.case_ref || 'Unattached') + '</span></td>' +
        '</tr>';
    }).join('');

    els.body.innerHTML =
      '<div class="lab-table-wrap"><table class="lab-table">' +
      '<thead><tr><th scope="col">Analysis ID</th><th scope="col">Type</th>' +
      '<th scope="col">Status</th><th scope="col">Verdict</th>' +
      '<th scope="col">Risk</th><th scope="col">Evidence</th>' +
      '<th scope="col">Case</th></tr></thead><tbody>' + rowsHtml +
      '</tbody></table></div>';

    Array.prototype.forEach.call(
      els.body.querySelectorAll('tr.is-clickable'),
      function (tr) {
        tr.addEventListener('click', function () {
          location.href = '/lab/analysis/' +
            encodeURIComponent(tr.getAttribute('data-ref'));
        });
      });
  }

  function load() {
    els.foot.textContent = 'Retrieving analysis records…';
    fetch('/lab/api/analysis?' + buildQuery(), {
      headers: { 'Accept': 'application/json' }, credentials: 'same-origin'
    })
      .then(function (res) {
        return res.json().then(function (body) {
          if (!res.ok || body.success !== true) {
            var e = (body && body.error) || {};
            throw { code: e.code || 'REQUEST_FAILED',
                    message: e.message || 'Analysis records could not be retrieved.' };
          }
          return body.data;
        });
      })
      .then(function (data) {
        renderRows(data.items);
        if (els.total) {
          els.total.textContent = data.total + (data.total === 1 ? ' RECORD' : ' RECORDS');
        }
        if (els.foot) {
          els.foot.textContent = data.total === 0
            ? 'No analysis run matches the current filter.'
            : 'Showing ' + data.items.length + ' of ' + data.total;
        }
      })
      .catch(function (err) {
        window.LAB.renderError(els.body, (err && err.code) || 'NETWORK_ERROR',
          (err && err.message) || 'Analysis records could not be retrieved.',
          { label: 'RETRY', onClick: load });
        if (els.foot) els.foot.textContent = 'Analysis records could not be retrieved.';
        if (els.total) els.total.textContent = 'UNAVAILABLE';
      });
  }

  function clearFilters() {
    els.search.value = '';
    els.type.value = '';
    els.status.value = '';
    els.caseRef.value = '';
    load();
  }

  function debouncedLoad() {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(load, 300);
  }

  if (els.search) els.search.addEventListener('input', debouncedLoad);
  if (els.caseRef) els.caseRef.addEventListener('input', debouncedLoad);
  if (els.type) els.type.addEventListener('change', load);
  if (els.status) els.status.addEventListener('change', load);
  if (els.clear) els.clear.addEventListener('click', clearFilters);

  // Prefill from ?q= (IOC "ANALYZE" actions deep-link here)
  var params = new URLSearchParams(location.search);
  if (params.get('q') && els.search) {
    els.search.value = params.get('q');
  }

  load();
})();
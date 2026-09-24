/* ====================================================================
   KAVACHAM LAB — EVIDENCE VAULT (Phase 6, Section 19)
   Filtered list backed by GET /lab/api/evidence. Integrity state is
   whatever the record holds — never synthesised.
   ==================================================================== */
(function () {
  'use strict';

  var esc = window.LAB.esc;
  var fmtTs = window.LAB.fmtTs;

  var els = {
    body: document.getElementById('e-list-body'),
    foot: document.getElementById('e-list-foot'),
    total: document.getElementById('e-total'),
    search: document.getElementById('e-search'),
    type: document.getElementById('e-type'),
    caseRef: document.getElementById('e-case'),
    clear: document.getElementById('e-clear')
  };

  var debounceTimer = null;

  function integrityBadge(state) {
    if (state === 'VERIFIED' || state === 'INTEGRITY VERIFIED') {
      return '<span class="lab-badge lab-badge-green">' + esc(state) + '</span>';
    }
    if (state === 'INTEGRITY MISMATCH') {
      return '<span class="lab-badge lab-badge-red">' + esc(state) + '</span>';
    }
    if (state === 'UNVERIFIED') {
      return '<span class="lab-badge lab-badge-gray">' + esc(state) + '</span>';
    }
    return '<span class="lab-badge lab-badge-amber">' + esc(state || 'UNVERIFIED') + '</span>';
  }

  function fmtSize(n) {
    if (n === null || n === undefined) return '—';
    if (n < 1024) return n + ' B';
    if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
    return (n / 1048576).toFixed(2) + ' MB';
  }

  function buildQuery() {
    var p = new URLSearchParams();
    if (els.search && els.search.value.trim()) p.set('q', els.search.value.trim());
    if (els.type && els.type.value) p.set('type', els.type.value);
    if (els.caseRef && els.caseRef.value.trim()) p.set('case', els.caseRef.value.trim());
    p.set('limit', '100');
    return p.toString();
  }

  function renderRows(items) {
    if (!items.length) {
      var hasFilter = (els.search.value.trim()) || els.type.value ||
        (els.caseRef.value.trim());
      var empty = window.LAB.emptyState(
        hasFilter ? '?' : '—',
        hasFilter ? 'NO MATCHING EVIDENCE' : 'NO EVIDENCE',
        hasFilter
          ? 'No evidence record matches the current filter.'
          : 'No evidence has been acquired into the vault yet.',
        hasFilter
          ? { label: 'CLEAR FILTERS', onClick: clearFilters }
          : { label: 'ACQUIRE EVIDENCE', onClick: function () { location.href = '/lab/evidence/new'; } }
      );
      els.body.innerHTML = '';
      els.body.appendChild(empty);
      return;
    }

    var rows = items.map(function (e) {
      return '<tr class="is-clickable" data-ref="' + esc(e.evidence_ref) + '">' +
        '<td><span class="lab-mono lab-strong">' + esc(e.evidence_ref) + '</span>' +
          '<div class="lab-xs lab-dim" style="margin-top:3px;">acquired ' +
          esc(fmtTs(e.acquired_at)) + '</div></td>' +
        '<td><span class="lab-strong">' + esc(e.title) + '</span>' +
          (e.original_filename
            ? '<div class="lab-xs lab-dim lab-mono" style="margin-top:3px;">' +
              esc(e.original_filename) + '</div>'
            : '') + '</td>' +
        '<td><span class="lab-badge">' + esc(e.evidence_type) + '</span></td>' +
        '<td>' + integrityBadge(e.integrity_state) + '</td>' +
        '<td><span class="lab-mono lab-xs" style="word-break:break-all;">' +
          esc(e.sha256 ? e.sha256.slice(0, 20) + '…' : '—') + '</span></td>' +
        '<td><span class="lab-mono lab-xs">' + esc(fmtSize(e.size_bytes)) + '</span></td>' +
        '<td>' + (e.case_ref
          ? '<span class="lab-mono lab-xs">' + esc(e.case_ref) + '</span>'
          : '<span class="lab-xs lab-dim">Unattached</span>') + '</td>' +
        '</tr>';
    }).join('');

    els.body.innerHTML =
      '<div class="lab-table-wrap"><table class="lab-table">' +
      '<thead><tr>' +
      '<th scope="col">Evidence ID</th><th scope="col">Title</th>' +
      '<th scope="col">Type</th><th scope="col">Integrity</th>' +
      '<th scope="col">SHA-256</th><th scope="col">Size</th>' +
      '<th scope="col">Case</th>' +
      '</tr></thead><tbody>' + rows + '</tbody></table></div>';

    Array.prototype.forEach.call(
      els.body.querySelectorAll('tr.is-clickable'),
      function (tr) {
        tr.addEventListener('click', function () {
          location.href = '/lab/evidence/' + encodeURIComponent(tr.getAttribute('data-ref'));
        });
      });
  }

  function load() {
    els.foot.textContent = 'Retrieving evidence records…';
    fetch('/lab/api/evidence?' + buildQuery(), {
      headers: { 'Accept': 'application/json' }, credentials: 'same-origin'
    })
      .then(function (res) {
        return res.json().then(function (body) {
          if (!res.ok || body.success !== true) {
            var e = (body && body.error) || {};
            throw { code: e.code || 'REQUEST_FAILED',
                    message: e.message || 'Evidence records could not be retrieved.' };
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
            ? 'No evidence record matches the current filter.'
            : 'Showing ' + data.items.length + ' of ' + data.total +
              (data.has_more ? ' (more available — narrow the filter)' : '');
        }
      })
      .catch(function (err) {
        window.LAB.renderError(els.body, (err && err.code) || 'NETWORK_ERROR',
          (err && err.message) || 'Evidence records could not be retrieved.',
          { label: 'RETRY', onClick: load });
        if (els.foot) els.foot.textContent = 'Evidence records could not be retrieved.';
        if (els.total) els.total.textContent = 'UNAVAILABLE';
      });
  }

  function clearFilters() {
    els.search.value = '';
    els.type.value = '';
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
  if (els.clear) els.clear.addEventListener('click', clearFilters);

  load();
})();

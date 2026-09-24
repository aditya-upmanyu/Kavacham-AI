/* ====================================================================
   KAVACHAM LAB — CASE LIST (Phase 5)
   Filtered list backed by GET /lab/api/cases. Section 63: the total is
   whatever the query returns; no synthetic rows.
   ==================================================================== */
(function () {
  'use strict';

  var esc = window.LAB.esc;
  var fmtTs = window.LAB.fmtTs;

  var els = {
    body: document.getElementById('case-list-body'),
    foot: document.getElementById('case-list-foot'),
    total: document.getElementById('case-total'),
    search: document.getElementById('f-search'),
    status: document.getElementById('f-status'),
    priority: document.getElementById('f-priority'),
    type: document.getElementById('f-type'),
    clear: document.getElementById('f-clear')
  };

  var debounceTimer = null;

  var STATUS_BADGE = {
    'OPEN': 'lab-badge-blue',
    'UNDER INVESTIGATION': 'lab-badge-amber',
    'REVIEW': 'lab-badge-amber',
    'RESOLVED': 'lab-badge-green',
    'ARCHIVED': 'lab-badge-gray'
  };
  var PRIORITY_BADGE = {
    'CRITICAL': 'lab-badge-red',
    'HIGH': 'lab-badge-red',
    'MEDIUM': 'lab-badge-amber',
    'LOW': 'lab-badge-gray'
  };

  function buildQuery() {
    var p = new URLSearchParams();
    if (els.search && els.search.value.trim()) p.set('q', els.search.value.trim());
    if (els.status && els.status.value) p.set('status', els.status.value);
    if (els.priority && els.priority.value) p.set('priority', els.priority.value);
    if (els.type && els.type.value) p.set('case_type', els.type.value);
    p.set('limit', '100');
    return p.toString();
  }

  function renderRows(items) {
    if (!items.length) {
      var hasFilter = els.search.value.trim() || els.status.value ||
        els.priority.value || els.type.value;
      var empty = window.LAB.emptyState(
        hasFilter ? '?' : '—',
        hasFilter ? 'NO MATCHING CASES' : 'NO ACTIVE INVESTIGATIONS',
        hasFilter
          ? 'No case record matches the current filter. Clear the filter to see all records.'
          : 'No cases currently require investigation.',
        hasFilter
          ? { label: 'CLEAR FILTERS', onClick: clearFilters }
          : { label: 'CREATE INVESTIGATION', onClick: function () { location.href = '/lab/cases/new'; } }
      );
      els.body.innerHTML = '';
      els.body.appendChild(empty);
      return;
    }

    var rows = items.map(function (c) {
      var statusBadge = STATUS_BADGE[c.status] || 'lab-badge-gray';
      var prioBadge = PRIORITY_BADGE[c.priority] || 'lab-badge-gray';
      return '<tr class="is-clickable" data-ref="' + esc(c.case_ref) + '">' +
        '<td><span class="lab-mono lab-strong">' + esc(c.case_ref) + '</span>' +
          '<div class="lab-xs lab-dim" style="margin-top:3px;">opened ' +
          esc(fmtTs(c.created_at)) + '</div></td>' +
        '<td><span class="lab-strong">' + esc(c.title) + '</span>' +
          (c.description
            ? '<div class="lab-xs lab-dim" style="margin-top:3px;max-width:340px;">' +
              esc(c.description.length > 110 ? c.description.slice(0, 110) + '…' : c.description) +
              '</div>'
            : '') + '</td>' +
        '<td><span class="lab-badge">' + esc(c.case_type) + '</span></td>' +
        '<td><span class="lab-badge ' + prioBadge + '">' + esc(c.priority) + '</span></td>' +
        '<td><span class="lab-badge ' + statusBadge + '">' + esc(c.status) + '</span></td>' +
        '<td><span class="lab-mono lab-xs">' + c.counts.evidence + ' evd · ' +
          c.counts.iocs + ' ioc · ' + c.counts.analyses + ' ana</span></td>' +
        '<td>' + (c.assigned_investigator
          ? '<span class="lab-xs">' + esc(c.assigned_investigator) + '</span>'
          : '<span class="lab-xs lab-dim">Unassigned</span>') + '</td>' +
        '</tr>';
    }).join('');

    els.body.innerHTML =
      '<div class="lab-table-wrap"><table class="lab-table">' +
      '<thead><tr>' +
      '<th scope="col">Case ID</th><th scope="col">Title</th>' +
      '<th scope="col">Type</th><th scope="col">Priority</th>' +
      '<th scope="col">Status</th><th scope="col">Related</th>' +
      '<th scope="col">Investigator</th>' +
      '</tr></thead><tbody>' + rows + '</tbody></table></div>';

    Array.prototype.forEach.call(
      els.body.querySelectorAll('tr.is-clickable'),
      function (tr) {
        tr.addEventListener('click', function () {
          location.href = '/lab/cases/' + encodeURIComponent(tr.getAttribute('data-ref'));
        });
      });
  }

  function load() {
    els.foot.textContent = 'Retrieving case records…';
    fetch('/lab/api/cases?' + buildQuery(), {
      headers: { 'Accept': 'application/json' }, credentials: 'same-origin'
    })
      .then(function (res) {
        return res.json().then(function (body) {
          if (!res.ok || body.success !== true) {
            var e = (body && body.error) || {};
            throw { code: e.code || 'REQUEST_FAILED',
                    message: e.message || 'Case records could not be retrieved.' };
          }
          return body.data;
        });
      })
      .then(function (data) {
        renderRows(data.items);
        if (els.total) els.total.textContent = data.total + (data.total === 1 ? ' RECORD' : ' RECORDS');
        if (els.foot) {
          els.foot.textContent = data.total === 0
            ? 'No case record matches the current filter.'
            : 'Showing ' + data.items.length + ' of ' + data.total +
              (data.has_more ? ' (more available — narrow the filter)' : '');
        }
      })
      .catch(function (err) {
        window.LAB.renderError(els.body, (err && err.code) || 'NETWORK_ERROR',
          (err && err.message) || 'Case records could not be retrieved.',
          { label: 'RETRY', onClick: load });
        if (els.foot) els.foot.textContent = 'Case records could not be retrieved.';
        if (els.total) els.total.textContent = 'UNAVAILABLE';
      });
  }

  function clearFilters() {
    els.search.value = '';
    els.status.value = '';
    els.priority.value = '';
    els.type.value = '';
    load();
  }

  function debouncedLoad() {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(load, 300);
  }

  if (els.search) els.search.addEventListener('input', debouncedLoad);
  [els.status, els.priority, els.type].forEach(function (el) {
    if (el) el.addEventListener('change', load);
  });
  if (els.clear) els.clear.addEventListener('click', clearFilters);

  load();
})();

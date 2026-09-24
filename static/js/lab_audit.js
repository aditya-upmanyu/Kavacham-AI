/* ====================================================================
   KAVACHAM LAB — AUDIT LOG (Phase 5, Section 44)
   Reads GET /lab/api/audit. Read-only: audit records are append-only
   by design and never mutated from the UI.
   ==================================================================== */
(function () {
  'use strict';

  var esc = window.LAB.esc;
  var fmtTs = window.LAB.fmtTs;

  var body = document.getElementById('audit-body');
  var foot = document.getElementById('audit-foot');
  var total = document.getElementById('audit-total');
  var actionSel = document.getElementById('audit-action');
  var refreshBtn = document.getElementById('audit-refresh');

  var ACTION_BADGE = {
    'CASE_CREATED': 'lab-badge-green',
    'CASE_UPDATED': 'lab-badge-blue',
    'NOTE_ADDED': 'lab-badge-blue',
    'EVIDENCE_ADDED': 'lab-badge-amber',
    'EVIDENCE_VERIFIED': 'lab-badge-green'
  };

  /* Pre-filter when arriving from a case's "VIEW AUDIT TRAIL". */
  var preTarget = null;
  try { preTarget = sessionStorage.getItem('lab_audit_target'); } catch (e) {}
  if (preTarget) {
    try { sessionStorage.removeItem('lab_audit_target'); } catch (e) {}
  }

  function buildQuery() {
    var p = new URLSearchParams();
    if (actionSel && actionSel.value) p.set('action', actionSel.value);
    if (preTarget) p.set('target', preTarget);
    p.set('limit', '200');
    return p.toString();
  }

  function render(items) {
    if (!items.length) {
      var filtered = (actionSel && actionSel.value) || preTarget;
      var empty = window.LAB.emptyState(
        filtered ? '?' : '—',
        filtered ? 'NO MATCHING EVENTS' : 'NO AUDIT EVENTS',
        filtered
          ? 'No recorded action matches the current filter.'
          : 'No actions have been recorded in this deployment yet.',
        filtered ? { label: 'CLEAR FILTER', onClick: clearFilters } : null
      );
      body.innerHTML = '';
      body.appendChild(empty);
      return;
    }

    var rows = items.map(function (a) {
      var badgeCls = ACTION_BADGE[a.action] || 'lab-badge-gray';
      return '<tr>' +
        '<td class="lab-mono lab-xs">' + esc(fmtTs(a.created_at)) + ' UTC</td>' +
        '<td><span class="lab-badge ' + badgeCls + '">' + esc(a.action) + '</span></td>' +
        '<td><span class="lab-strong lab-xs">' + esc(a.actor) + '</span></td>' +
        '<td>' + (a.target_ref
          ? '<span class="lab-mono lab-xs">' + esc(a.target_ref) + '</span>'
          : '<span class="lab-xs lab-dim">—</span>') + '</td>' +
        '<td><div class="lab-xs">' + esc(a.detail || '—') + '</div></td>' +
        '<td>' + (a.ip_address
          ? '<span class="lab-mono lab-xs">' + esc(a.ip_address) + '</span>'
          : '<span class="lab-xs lab-dim">local</span>') + '</td>' +
        '</tr>';
    }).join('');

    body.innerHTML = '<div class="lab-table-wrap"><table class="lab-table">' +
      '<thead><tr><th scope="col">Timestamp</th><th scope="col">Action</th>' +
      '<th scope="col">Actor</th><th scope="col">Target</th>' +
      '<th scope="col">Detail</th><th scope="col">Origin</th>' +
      '</tr></thead><tbody>' + rows + '</tbody></table></div>';
  }

  function load() {
    foot.textContent = 'Retrieving audit records…';
    fetch('/lab/api/audit?' + buildQuery(), {
      headers: { 'Accept': 'application/json' }, credentials: 'same-origin'
    })
      .then(function (res) {
        return res.json().then(function (body2) {
          if (!res.ok || body2.success !== true) {
            var e = (body2 && body2.error) || {};
            throw { code: e.code || 'REQUEST_FAILED',
                    message: e.message || 'Audit records could not be retrieved.' };
          }
          return body2.data;
        });
      })
      .then(function (data) {
        render(data.items);
        if (total) {
          total.textContent = data.count + (data.count === 1 ? ' EVENT' : ' EVENTS') +
            (preTarget ? ' FOR ' + preTarget : '');
        }
        if (foot) {
          foot.textContent = 'Showing ' + data.count + ' of ' + data.count +
            ' recorded events. Audit records are append-only.';
        }
      })
      .catch(function (err) {
        window.LAB.renderError(body, (err && err.code) || 'NETWORK_ERROR',
          (err && err.message) || 'Audit records could not be retrieved.',
          { label: 'RETRY', onClick: load });
        if (foot) foot.textContent = 'Audit records could not be retrieved.';
        if (total) total.textContent = 'UNAVAILABLE';
      });
  }

  function clearFilters() {
    if (actionSel) actionSel.value = '';
    preTarget = null;
    load();
  }

  if (actionSel) actionSel.addEventListener('change', load);
  if (refreshBtn) refreshBtn.addEventListener('click', load);

  load();
})();

/* ====================================================================
   KAVACHAM LAB — CROSS-CASE CORRELATION (Phase 8, Section 27)
   IOCs seen in 2+ cases. Presented with precise language: correlation
   is never presented as attribution.
   ==================================================================== */
(function () {
  'use strict';

  var esc = window.LAB.esc;
  var fmtTs = window.LAB.fmtTs;

  var els = {
    body: document.getElementById('corr-body'),
    foot: document.getElementById('corr-foot'),
    total: document.getElementById('corr-total'),
    statement: document.getElementById('corr-statement'),
    note: document.getElementById('corr-note')
  };

  function statusBadge(s) {
    var cls = s === 'OPEN' ? 'lab-badge-blue'
      : s === 'UNDER INVESTIGATION' ? 'lab-badge-amber'
      : s === 'REVIEW' ? 'lab-badge-amber'
      : s === 'RESOLVED' ? 'lab-badge-green'
      : s === 'ARCHIVED' ? 'lab-badge-gray' : 'lab-badge-gray';
    return '<span class="lab-badge ' + cls + '">' + esc(s) + '</span>';
  }

  function render(items) {
    if (!items.length) {
      els.body.innerHTML = '';
      els.body.appendChild(window.LAB.emptyState(
        '≠', 'NO IOC CORRELATIONS',
        'No indicator has been observed across two or more cases yet. ' +
        'IOCs surface in the correlation view as soon as the same value ' +
        'appears in two investigations.', null));
      return;
    }

    var html = items.map(function (c) {
      var casesHtml = c.related_cases.map(function (rc) {
        return '<tr class="is-clickable" data-href="/lab/cases/' +
          encodeURIComponent(rc.case_ref) + '">' +
          '<td class="lab-mono">' + esc(rc.case_ref) + '</td>' +
          '<td>' + esc(rc.title) + '</td>' +
          '<td>' + statusBadge(rc.status) + '</td>' +
          '<td><span class="lab-xs">' + esc(rc.case_type) + '</span></td>' +
          '</tr>';
      }).join('');
      return '<div class="lab-tile" style="margin-bottom:14px;">' +
        '<div style="display:flex;justify-content:space-between;gap:12px;align-items:center;flex-wrap:wrap;">' +
          '<div style="min-width:0;">' +
            '<div class="lab-badge lab-badge-blue" style="margin-bottom:6px;">' +
              esc(c.ioc_type) + '</div> ' +
            '<span class="lab-mono lab-strong" style="word-break:break-all;">' +
              esc(c.value) + '</span>' +
            '<div class="lab-xs lab-dim" style="margin-top:4px;">' +
              esc(c.statement) + '</div>' +
          '</div>' +
          '<div class="lab-badge lab-badge-red">' + c.case_count + ' CASES</div>' +
        '</div>' +
        '<div class="lab-table-wrap" style="margin-top:12px;">' +
          '<table class="lab-table"><thead><tr><th scope="col">Case</th>' +
          '<th scope="col">Title</th><th scope="col">Status</th>' +
          '<th scope="col">Type</th></tr></thead><tbody>' + casesHtml +
          '</tbody></table></div>' +
        '</div>';
    }).join('');

    els.body.innerHTML = '<div class="lab-panel-body">' + html + '</div>';
    Array.prototype.forEach.call(
      els.body.querySelectorAll('tr.is-clickable'),
      function (tr) {
        tr.addEventListener('click', function () {
          location.href = tr.getAttribute('data-href');
        });
      });
  }

  function load() {
    els.foot.textContent = 'Computing correlations…';
    fetch('/lab/api/intel/correlation', {
      headers: { 'Accept': 'application/json' }, credentials: 'same-origin'
    })
      .then(function (res) { return res.json(); })
      .then(function (body) {
        if (!body.success) { throw (body.error || {}); }
        render(body.data.correlations);
        els.total.textContent = body.data.total + ' correlation(s)';
        els.statement.textContent = '“' + body.data.statement + '”';
        els.note.textContent = body.data.note;
        els.foot.textContent = body.data.total
          ? 'Refreshed ' + fmtTs(new Date().toISOString())
          : 'No correlations yet.';
      })
      .catch(function (err) {
        els.body.innerHTML = '';
        els.total.textContent = '—';
        els.foot.textContent = err.message || 'Correlation could not be computed.';
      });
  }

  load();
})();
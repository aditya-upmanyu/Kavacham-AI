/* ====================================================================
   KAVACHAM LAB — DATASET REGISTRY (Section BD)
   Renders only real rows from /lab/api/datasets. Distributions are
   computed from the files themselves; unknown provenance is "—".
   ==================================================================== */
(function () {
  'use strict';

  var esc = window.LAB && window.LAB.esc ? window.LAB.esc : function (s) { return String(s == null ? '' : s); };

  function $(id) { return document.getElementById(id); }

  function dash(v) {
    return (v === null || v === undefined || v === '')
      ? '<span class="lab-dim">—</span>' : esc(String(v));
  }

  fetch('/lab/api/datasets', { headers: { 'Accept': 'application/json' }, credentials: 'same-origin' })
    .then(function (res) {
      return res.json().then(function (body) {
        if (!res.ok || body.success !== true) throw new Error('registry failed');
        return body.data;
      });
    })
    .then(function (data) {
      var sets = data.datasets || [];
      var host = $('datasets-body');
      host.innerHTML = sets.map(function (d) {
        var dist = d.class_distribution || {};
        var distRows = Object.keys(dist).sort().map(function (k) {
          return '<div class="lab-strip-item"><span class="lab-label">' +
            esc(k) + '</span><span class="lab-strip-value">' + dist[k] + '</span></div>';
        }).join('');
        return '<div class="lab-panel-body" style="border-bottom:1px solid var(--lab-line-1);">' +
          '<div class="lab-row tight" style="margin-bottom:8px;">' +
          '<span class="lab-strong">' + esc(d.name) + '</span>' +
          '<span class="lab-mono lab-xs lab-dim">' + esc(d.dataset_id) + '</span>' +
          '<span class="lab-mono lab-xs">' + esc(String(d.row_count)) + ' ROWS</span></div>' +
          '<div class="lab-xs lab-dim" style="margin-bottom:8px;">SOURCE: ' + esc(d.source || '—') +
          ' · LICENSE: ' + esc(d.license || '—') +
          ' · COLUMNS: ' + esc((d.columns || []).join(', ')) + '</div>' +
          '<div class="lab-strip">' +
          '<div class="lab-strip-item"><span class="lab-label">DUPLICATES</span>' +
          '<span class="lab-strip-value">' + esc(String(d.duplicates)) + '</span></div>' +
          '<div class="lab-strip-item"><span class="lab-label">MISSING VALUES</span>' +
          '<span class="lab-strip-value">' + esc(String(d.missing_values)) + '</span></div>' +
          '<div class="lab-strip-item"><span class="lab-label">LICENSE</span>' +
          '<span class="lab-strip-value">' + dash(d.license) + '</span></div></div>' +
          (distRows ? '<div class="lab-xs lab-dim" style="margin:8px 0 4px;">CLASS DISTRIBUTION</div>' +
            '<div class="lab-strip">' + distRows + '</div>' : '') +
          '</div>';
      }).join('') || '<div class="lab-panel-body"><div class="lab-state">' +
        '<div class="lab-state-title">NO DATASETS REGISTERED</div>' +
        '<p class="lab-state-desc">No dataset files were found on disk.</p></div></div>';
      var cnt = $('datasets-count');
      if (cnt) cnt.textContent = sets.length + ' DATASETS';
      var foot = $('datasets-foot');
      if (foot) foot.textContent = 'Profiled from the files themselves; contents never executed.';
    })
    .catch(function () {
      var host = $('datasets-body');
      if (host) host.innerHTML = '<div class="lab-panel-body">' +
        '<div class="lab-state is-error"><div class="lab-state-title">REGISTRY UNAVAILABLE</div></div></div>';
    });
})();

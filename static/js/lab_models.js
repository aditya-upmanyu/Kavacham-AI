/* ====================================================================
   KAVACHAM LAB — MODEL REGISTRY (Section BE)
   Renders only real rows from /lab/api/models. Metrics appear only
   when recorded; otherwise an honest em dash.
   ==================================================================== */
(function () {
  'use strict';

  var esc = window.LAB && window.LAB.esc ? window.LAB.esc : function (s) { return String(s == null ? '' : s); };

  function $(id) { return document.getElementById(id); }

  function num(v, suffix) {
    if (v === null || v === undefined || v === '') return '<span class="lab-dim">—</span>';
    return '<span class="lab-mono">' + esc(String(v)) + (suffix || '') + '</span>';
  }

  fetch('/lab/api/models', { headers: { 'Accept': 'application/json' }, credentials: 'same-origin' })
    .then(function (res) {
      return res.json().then(function (body) {
        if (!res.ok || body.success !== true) throw new Error('registry failed');
        return body.data;
      });
    })
    .then(function (data) {
      var models = data.models || [];
      var tbody = $('models-table');
      var rows = models.map(function (m) {
        return '<tr>' +
          '<td><span class="lab-strong">' + esc(m.name) + '</span>' +
            '<div class="lab-xs lab-dim lab-mono">' + esc(m.model_id) + '</div>' +
            (m.features ? '<div class="lab-xs lab-dim" style="margin-top:3px;">' + esc(m.features) + '</div>' : '') + '</td>' +
          '<td><span class="lab-badge lab-badge-blue">' + esc((m.kind || '').toUpperCase()) + '</span></td>' +
          '<td>' + num(m.accuracy) + '</td>' +
          '<td>' + num(m.precision) + '</td>' +
          '<td>' + num(m.recall) + '</td>' +
          '<td>' + num(m.f1) + '</td>' +
          '<td>' + num(m.false_positive_rate) + '</td>' +
          '<td class="lab-xs lab-mono">' + (m.training_date ? esc(m.training_date.slice(0, 10)) : '<span class="lab-dim">—</span>') + '</td>' +
          '<td class="lab-xs lab-mono lab-dim">' + esc(m.path || '') + '</td></tr>';
      }).join('');
      tbody.innerHTML = rows || '<tr><td colspan="9">' +
        '<div class="lab-state"><div class="lab-state-title">NO MODELS REGISTERED</div>' +
        '<p class="lab-state-desc">No model artifacts were found on disk.</p></div></td></tr>';
      var cnt = $('models-count');
      if (cnt) cnt.textContent = models.length + ' MODELS';
      var foot = $('models-foot');
      if (foot) foot.textContent = 'Metrics come from metrics.json where recorded; blank cells mean unrecorded, not zero.';
    })
    .catch(function () {
      var tbody = $('models-table');
      if (tbody) {
        tbody.innerHTML = '<tr><td colspan="9">' +
          '<div class="lab-state is-error"><div class="lab-state-title">REGISTRY UNAVAILABLE</div></div></td></tr>';
      }
    });
})();

/* ====================================================================
   KAVACHAM LAB — SYSTEM HEALTH (Phase 13, Section BO)
   Renders only real values returned by /lab/api/health.
   Columns: SERVICE / STATUS / LATENCY / LAST CHECK / ERROR /
   CONFIGURATION / DETAIL. Never fabricate a row.
   ==================================================================== */
(function () {
  'use strict';

  var ENDPOINT = '/lab/api/health';
  var esc = window.LAB && window.LAB.esc ? window.LAB.esc : function (s) { return String(s == null ? '' : s); };
  var fmtTs = window.LAB && window.LAB.fmtTs ? window.LAB.fmtTs : function (s) { return s || '—'; };

  function $(id) { return document.getElementById(id); }

  function statusCell(svc) {
    var key = svc.status_key || 'unknown';
    var cls = 'is-operational';
    if (key === 'unavailable') cls = 'is-unavailable';
    else if (key === 'unconfigured') cls = 'is-unconfigured';
    var live = key === 'operational' ? ' is-live' : '';
    return '<span class="lab-status ' + cls + live + '">' + esc(svc.status) + '</span>';
  }

  function latencyCell(svc) {
    if (svc.latency_ms === null || svc.latency_ms === undefined) {
      return '<span class="lab-dim lab-xs">NOT MEASURED</span>';
    }
    var v = svc.latency_ms;
    var txt = v >= 1000 ? (v / 1000).toFixed(2) + ' s' : v.toFixed(2) + ' ms';
    return '<span class="lab-mono lab-xs">' + txt + '</span>';
  }

  function render(report) {
    var tbody = $('health-table');
    var foot = $('health-foot');
    var ts = $('health-ts');
    var sum = $('health-summary');
    if (!tbody) return;

    var services = report.services || [];
    var rows = services.map(function (s) {
      var cfg = (s.configuration === null || s.configuration === undefined || s.configuration === '')
        ? '<span class="lab-dim">—</span>'
        : '<span class="lab-mono lab-xs">' + esc(String(s.configuration)) + '</span>';
      var err = s.error
        ? '<span class="hlth-err lab-xs lab-mono">' + esc(String(s.error)) + '</span>'
        : '<span class="lab-dim">—</span>';
      var checked = s.checked_at ? fmtTs(s.checked_at) + ' UTC' : '—';
      return '<tr>' +
        '<td><span class="lab-strong">' + esc(s.label) + '</span>' +
          '<div class="lab-xs lab-dim lab-mono">' + esc(s.group || '') + ' · ' + esc(s.source || '') + '</div></td>' +
        '<td>' + statusCell(s) + '</td>' +
        '<td>' + latencyCell(s) + '</td>' +
        '<td><span class="lab-xs lab-mono">' + esc(checked) + '</span></td>' +
        '<td>' + err + '</td>' +
        '<td>' + cfg + '</td>' +
        '<td><div class="lab-xs">' + esc(s.detail || '') + '</div>' +
          (s.latency_basis ? '<div class="lab-xs lab-dim" style="margin-top:3px;">basis: ' +
            esc(s.latency_basis) + '</div>' : '') +
        '</td></tr>';
    }).join('');

    tbody.innerHTML = rows || '<tr><td colspan="7">' +
      '<div class="lab-state"><div class="lab-state-title">NO DATA AVAILABLE</div>' +
      '<p class="lab-state-desc">No service checks were returned.</p></div></td></tr>';

    var sm = report.summary || {};
    if (ts) ts.textContent = 'CHECKED ' + fmtTs(report.checked_at) + ' UTC';
    if (sum) sum.textContent = (sm.operational == null ? '—' : sm.operational) + ' / ' +
      (sm.total == null ? '—' : sm.total) + ' OPERATIONAL';
    if (foot) {
      foot.textContent = 'Report generated in ' +
        (report.duration_ms == null ? '—' : report.duration_ms + ' ms') +
        ' · OVERALL: ' + (report.overall_status || '—');
    }
  }

  function load() {
    fetch(ENDPOINT, { headers: { 'Accept': 'application/json' }, credentials: 'same-origin' })
      .then(function (res) {
        return res.json().then(function (body) {
          if (!res.ok || body.success !== true) {
            var e = (body && body.error) || {};
            throw { code: e.code || 'REQUEST_FAILED', message: e.message || 'System health could not be retrieved.' };
          }
          return body.data;
        });
      })
      .then(render)
      .catch(function (err) {
        var msg = (err && err.message) || 'System health could not be retrieved.';
        var code = (err && err.code) || 'NETWORK_ERROR';
        var tbody = $('health-table');
        if (tbody) {
          tbody.innerHTML = '<tr><td colspan="7">' +
            '<div class="lab-state is-error">' +
            '<div class="lab-state-icon">!</div>' +
            '<div class="lab-state-title">SYSTEM HEALTH UNAVAILABLE</div>' +
            '<p class="lab-state-desc">' + esc(msg) + '</p>' +
            '<div class="lab-provenance">ERROR CODE: ' + esc(code) + '</div>' +
            '</div></td></tr>';
        }
        var foot = $('health-foot');
        if (foot) foot.textContent = 'Health data could not be retrieved.';
      });
  }

  var btn = $('health-refresh');
  if (btn) {
    btn.addEventListener('click', function () {
      btn.disabled = true;
      load();
      setTimeout(function () { btn.disabled = false; }, 600);
    });
  }

  load();
})();

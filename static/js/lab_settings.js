/* ====================================================================
   KAVACHAM LAB — SETTINGS (Phase 13, Section BP)
   Renders only real values returned by /lab/api/providers.
   Read-only per the spec: configuration lives in environment
   variables; this surface never displays secrets.
   ==================================================================== */
(function () {
  'use strict';

  var ENDPOINT = '/lab/api/providers';
  var esc = window.LAB && window.LAB.esc ? window.LAB.esc : function (s) { return String(s == null ? '' : s); };

  function $(id) { return document.getElementById(id); }

  function render(data) {
    var tbody = $('settings-table');
    var foot = $('settings-foot');
    var cnt = $('settings-count');
    if (!tbody) return;

    var providers = data.providers || [];
    var rows = providers.map(function (p) {
      var badge = p.configured
        ? '<span class="lab-status is-operational">CONFIGURED</span>'
        : '<span class="lab-status is-unconfigured">NOT CONFIGURED</span>';
      return '<tr>' +
        '<td><span class="lab-strong">' + esc(p.name) + '</span></td>' +
        '<td>' + badge + '</td>' +
        '<td><span class="lab-mono lab-xs">' + esc(p.key_env || '') + '</span></td>' +
        '<td><span class="lab-xs lab-mono lab-dim">' + esc(p.source || '') + '</span></td>' +
        '<td><div class="lab-xs">' + esc(p.note || '') + '</div></td></tr>';
    }).join('');

    tbody.innerHTML = rows || '<tr><td colspan="5">' +
      '<div class="lab-state"><div class="lab-state-title">NO DATA AVAILABLE</div>' +
      '<p class="lab-state-desc">No provider statuses were returned.</p></div></td></tr>';

    if (cnt) cnt.textContent = String(providers.length) + ' PROVIDERS';
    if (foot) foot.textContent = 'Configuration is managed via environment variables; a restart applies changes. Secrets are never displayed here.';
  }

  fetch(ENDPOINT, { headers: { 'Accept': 'application/json' }, credentials: 'same-origin' })
    .then(function (res) {
      return res.json().then(function (body) {
        if (!res.ok || body.success !== true) {
          var e = (body && body.error) || {};
          throw { code: e.code || 'REQUEST_FAILED', message: e.message || 'Provider configuration could not be retrieved.' };
        }
        return body.data;
      });
    })
    .then(render)
    .catch(function (err) {
      var msg = (err && err.message) || 'Provider configuration could not be retrieved.';
      var tbody = $('settings-table');
      if (tbody) {
        tbody.innerHTML = '<tr><td colspan="5">' +
          '<div class="lab-state is-error">' +
          '<div class="lab-state-icon">!</div>' +
          '<div class="lab-state-title">SETTINGS UNAVAILABLE</div>' +
          '<p class="lab-state-desc">' + esc(msg) + '</p></div></td></tr>';
      }
      var foot = $('settings-foot');
      if (foot) foot.textContent = 'Provider data could not be retrieved.';
    });
})();

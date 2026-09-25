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

  /* ---------------- Retention (BR) ---------------- */
  function api(method, url, payload) {
    return fetch(url, {
      method: method,
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
      credentials: 'same-origin',
      body: payload === undefined ? undefined : JSON.stringify(payload),
    }).then(function (res) {
      return res.json().then(function (body) {
        if (!res.ok || body.success !== true) {
          var e = (body && body.error) || {};
          throw { code: e.code || 'REQUEST_FAILED', message: e.message || 'Request failed.' };
        }
        return body.data;
      });
    });
  }

  function loadRetention() {
    api('GET', '/lab/api/settings')
      .then(function (d) {
        var s = (d.settings || {}).retention_days || {};
        var val = $('retention-value');
        if (val) val.textContent = s.value || '—';
        var meta = $('retention-meta');
        if (meta) meta.textContent = 'updated ' + (s.updated_at || '—') + ' by ' + (s.updated_by || '—');
        var st = $('retention-state');
        if (st) st.textContent = 'SECRET SOURCE: ' + (d.secret_source || '—');
      })
      .catch(function () {
        var foot = $('retention-foot');
        if (foot) foot.textContent = 'Retention settings could not be read.';
      });
  }

  function say(msg) {
    var foot = $('retention-foot');
    if (foot) foot.textContent = msg;
  }

  var saveBtn = $('retention-save');
  if (saveBtn) {
    saveBtn.addEventListener('click', function () {
      var v = parseInt(($('retention-input') || {}).value, 10);
      if (!v) { say('Enter a retention window in days (30–3650).'); return; }
      saveBtn.disabled = true;
      api('PATCH', '/lab/api/settings', { key: 'retention_days', value: v })
        .then(function (d) { say('Retention set to ' + d.setting.value + ' days (audited).'); loadRetention(); })
        .catch(function (err) { say((err && err.message) || 'Update failed.'); })
        .then(function () { saveBtn.disabled = false; });
    });
  }

  var prevBtn = $('retention-preview');
  if (prevBtn) {
    prevBtn.addEventListener('click', function () {
      api('GET', '/lab/api/settings/purge-preview')
        .then(function (d) {
          say(d.audit_rows + ' audit row(s) older than ' + d.cutoff.slice(0, 10) +
            ' would be purged. Nothing was deleted.');
        })
        .catch(function (err) { say((err && err.message) || 'Preview failed.'); });
    });
  }

  var purgeBtn = $('retention-purge');
  if (purgeBtn) {
    purgeBtn.addEventListener('click', function () {
      if (!window.confirm('Purge audit rows past retention? This is audited and cannot be undone.')) return;
      purgeBtn.disabled = true;
      api('POST', '/lab/api/settings/purge')
        .then(function (d) { say('Purged ' + d.deleted + ' audit row(s). The purge itself was audited.'); })
        .catch(function (err) { say((err && err.message) || 'Purge failed.'); })
        .then(function () { purgeBtn.disabled = false; });
    });
  }

  loadRetention();

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

/* ====================================================================
   KAVACHAM LAB — COMMAND CENTER (Phase 4)
   Renders only real values returned by /lab/api/command-center.
   Section 63: never fabricate counts, health, latency or timestamps.
   ==================================================================== */
(function () {
  'use strict';

  var ENDPOINT = '/lab/api/command-center';
  var esc = window.LAB ? window.LAB.esc : function (s) { return String(s == null ? '' : s); };
  var fmtTs = window.LAB ? window.LAB.fmtTs : function (s) { return s || '—'; };

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

  /* ---------------- Alerts ---------------- */
  function renderAlerts(alerts) {
    var host = $('cc-alerts');
    if (!host) return;
    if (!alerts || !alerts.length) {
      host.innerHTML =
        '<div class="lab-alert is-success">' +
        '<span class="lab-alert-icon">✓</span>' +
        '<div><div class="lab-alert-title">NO OPERATIONAL ALERTS</div>' +
        '<div>All monitored services responded within expected parameters at the last health check.</div>' +
        '</div></div>';
      return;
    }
    host.innerHTML = alerts.map(function (a) {
      var sev = a.severity === 'critical' ? 'is-critical'
              : a.severity === 'warning' ? 'is-warning' : 'is-info';
      var icon = a.severity === 'critical' ? '!' : a.severity === 'warning' ? '▲' : 'i';
      return '<div class="lab-alert ' + sev + '" style="margin-bottom:8px;">' +
        '<span class="lab-alert-icon">' + icon + '</span>' +
        '<div><div class="lab-alert-title">' + esc(a.title) + '</div>' +
        '<div>' + esc(a.message) + '</div>' +
        '<div class="lab-provenance" style="margin-top:6px;">' + esc(a.error_code || '') +
        ' · ' + esc(a.source || '') + '</div>' +
        '</div></div>';
    }).join('');
  }

  /* ---------------- Summary strip ---------------- */
  function renderSummary(data) {
    var host = $('cc-summary');
    if (!host) return;
    var h = data.health.summary || {};
    var counts = data.counts || {};

    function item(label, value, cls) {
      return '<div class="lab-strip-item">' +
        '<span class="lab-label">' + esc(label) + '</span>' +
        '<span class="lab-strip-value' + (cls ? ' ' + cls : '') + '">' + value + '</span>' +
        '</div>';
    }

    var casesVal, evdVal;
    if (counts.persistence_available) {
      casesVal = counts.active_cases === null ? 'UNAVAILABLE' : String(counts.active_cases);
      evdVal = counts.evidence_records === null ? 'UNAVAILABLE' : String(counts.evidence_records);
    } else {
      casesVal = '<span class="lab-dim">NOT CONFIGURED</span>';
      evdVal = '<span class="lab-dim">NOT CONFIGURED</span>';
    }

    host.innerHTML =
      item('SERVICES OPERATIONAL', String(h.operational == null ? '—' : h.operational)) +
      item('SERVICES UNAVAILABLE', String(h.unavailable == null ? '—' : h.unavailable),
           h.unavailable > 0 ? 'lab-state-crit' : '') +
      item('NOT CONFIGURED', String(h.unconfigured == null ? '—' : h.unconfigured)) +
      item('ACTIVE CASES', casesVal) +
      item('EVIDENCE RECORDS', evdVal);
  }

  /* ---------------- Health table ---------------- */
  function renderHealth(health) {
    var tbody = $('cc-health-table');
    var foot = $('cc-health-foot');
    var ts = $('cc-health-ts');
    if (!tbody) return;

    var services = health.services || [];
    var rows = services.map(function (s) {
      return '<tr>' +
        '<td><span class="lab-strong">' + esc(s.label) + '</span>' +
          '<div class="lab-xs lab-dim lab-mono">' + esc(s.source || '') + '</div></td>' +
        '<td>' + statusCell(s) + '</td>' +
        '<td>' + latencyCell(s) + '</td>' +
        '<td><div class="lab-xs">' + esc(s.detail || '') + '</div>' +
          (s.latency_basis ? '<div class="lab-xs lab-dim" style="margin-top:3px;">basis: ' +
            esc(s.latency_basis) + '</div>' : '') +
          (s.error ? '<div class="lab-xs" style="color:#F08A8A;margin-top:3px;">' +
            esc(s.error) + '</div>' : '') +
        '</td></tr>';
    }).join('');

    tbody.innerHTML = rows || '<tr><td colspan="4">' +
      '<div class="lab-state"><div class="lab-state-title">NO DATA AVAILABLE</div>' +
      '<p class="lab-state-desc">No service checks were returned.</p></div></td></tr>';

    if (ts) ts.textContent = 'CHECKED ' + fmtTs(health.checked_at) + ' UTC';
    if (foot) {
      var s = health.summary || {};
      foot.textContent = 'Report generated in ' +
        (health.duration_ms != null ? health.duration_ms.toFixed(2) + ' ms' : '—') +
        ' · ' + (s.operational || 0) + ' operational · ' +
        (s.unavailable || 0) + ' unavailable · ' +
        (s.unconfigured || 0) + ' not configured';
    }
  }

  /* ---------------- Model health ---------------- */
  function renderModel(mh) {
    var body = $('cc-model-body');
    var ts = $('cc-model-ts');
    if (!body) return;

    if (!mh || !mh.available) {
      body.innerHTML = '<div class="lab-panel-body">' +
        '<div class="lab-state is-unavailable" style="min-height:120px;padding:22px 16px;">' +
        '<div class="lab-state-icon">?</div>' +
        '<div class="lab-state-title">MODEL METRICS UNAVAILABLE</div>' +
        '<p class="lab-state-desc">Loaded model metrics could not be read. ' +
        'Model loaded: ' + (mh && mh.loaded ? 'yes' : 'no') + '.</p>' +
        '</div></div>';
      if (ts) ts.textContent = '—';
      return;
    }

    function pct(v) {
      if (v === null || v === undefined) return '—';
      var n = Number(v);
      if (isNaN(n)) return '—';
      return n <= 1 ? (n * 100).toFixed(2) + '%' : n.toFixed(2) + '%';
    }

    var rows = [
      ['MODEL', mh.model_name || '—', true],
      ['VERSION', mh.model_version || '—', true],
      ['DECISION THRESHOLD', mh.decision_threshold != null
        ? (Number(mh.decision_threshold) * 100).toFixed(1) + '%' : '—', true],
      ['ACCURACY', pct(mh.accuracy), false],
      ['PRECISION', pct(mh.precision), false],
      ['RECALL', pct(mh.recall), false],
      ['F1 SCORE', pct(mh.f1_score), false],
      ['FALSE POSITIVE RATE', pct(mh.false_positive_rate), false],
      ['HARD-TEST SPAM RECALL', pct(mh.hard_test_spam_recall), false]
    ];

    body.innerHTML = '<div class="lab-panel-body">' +
      '<dl class="lab-kv">' + rows.map(function (r) {
        return '<dt>' + esc(r[0]) + '</dt><dd' +
          (r[2] ? ' class="lab-mono"' : '') + '>' + esc(r[1]) + '</dd>';
      }).join('') + '</dl>' +
      '<div class="lab-provenance" style="margin-top:11px;">' + esc(mh.source || '') + '</div>' +
      '</div>';

    if (ts) ts.textContent = 'TRAINED ' + (mh.trained_at ? fmtTs(mh.trained_at) : '—');
  }

  /* ---------------- Active investigations (honest empty state) ---------------- */
  function renderCases(counts) {
    var body = $('cc-cases-body');
    var count = $('cc-cases-count');
    if (!body) return;

    if (!counts || !counts.persistence_available) {
      body.innerHTML = '<div class="lab-panel-body">' +
        '<div class="lab-state is-unavailable" style="min-height:140px;">' +
        '<div class="lab-state-icon">?</div>' +
        '<div class="lab-state-title">DATABASE NOT CONFIGURED</div>' +
        '<p class="lab-state-desc">Case records are unavailable because the ' +
        'persistence layer has not been configured for this deployment. ' +
        'No case data is being reported.</p></div></div>';
      if (count) count.textContent = 'NO DATA AVAILABLE';
      return;
    }

    if (counts.active_cases === null) {
      body.innerHTML = '<div class="lab-panel-body">' +
        '<div class="lab-state is-error" style="min-height:140px;">' +
        '<div class="lab-state-icon">!</div>' +
        '<div class="lab-state-title">COUNT UNAVAILABLE</div>' +
        '<p class="lab-state-desc">The case count query failed.</p></div></div>';
      if (count) count.textContent = 'UNAVAILABLE';
      return;
    }

    if (counts.active_cases === 0) {
      var empty = window.LAB.emptyState('—', 'NO ACTIVE INVESTIGATIONS',
        'No cases currently require investigation.', null);
      body.innerHTML = '';
      body.appendChild(empty);
      if (count) count.textContent = '0 OPEN';
      return;
    }

    if (count) count.textContent = counts.active_cases + ' OPEN';
    body.innerHTML = '<div class="lab-panel-body"><p class="lab-dim lab-sm">' +
      esc(String(counts.active_cases)) + ' active case(s) recorded.</p></div>';
  }

  /* ---------------- Recent analyses ---------------- */
  function renderRecent(recent) {
    var body = $('cc-recent-body');
    var count = $('cc-recent-count');
    if (!body) return;

    if (!recent || recent.available === false) {
      body.innerHTML = '<div class="lab-panel-body">' +
        '<div class="lab-state is-unavailable" style="min-height:140px;">' +
        '<div class="lab-state-icon">?</div>' +
        '<div class="lab-state-title">NO DATA AVAILABLE</div>' +
        '<p class="lab-state-desc">No analysis history is present in this session.</p>' +
        '</div></div>';
      if (count) count.textContent = 'NO DATA AVAILABLE';
      return;
    }

    var items = recent.items || [];
    if (!items.length) {
      body.innerHTML = '';
      body.appendChild(window.LAB.emptyState('—', 'NO RECENT ANALYSES',
        'No emails have been analysed in this session yet.', null));
      if (count) count.textContent = '0 RECORDS';
      return;
    }

    if (count) count.textContent = items.length + ' RECORDS';

    var rows = items.map(function (it) {
      var cls = String(it.classification || '').toUpperCase();
      var badge = cls === 'SPAM' ? 'lab-badge-red'
                : cls === 'HAM' ? 'lab-badge-green' : 'lab-badge-gray';
      return '<tr>' +
        '<td><span class="lab-strong lab-truncate" style="display:block;max-width:230px;">' +
          esc(it.subject) + '</span></td>' +
        '<td><span class="lab-badge ' + badge + '">' + esc(cls || '—') + '</span></td>' +
        '<td><span class="lab-mono lab-xs">' +
          (it.risk_score == null ? '—' : esc(String(it.risk_score))) + '</span></td>' +
        '<td><span class="lab-mono lab-xs">' + esc(fmtTs(it.timestamp)) + '</span></td>' +
        '</tr>';
    }).join('');

    body.innerHTML = '<div class="lab-table-wrap"><table class="lab-table">' +
      '<thead><tr><th scope="col">Subject</th><th scope="col">Class</th>' +
      '<th scope="col">Risk</th><th scope="col">Time</th></tr></thead>' +
      '<tbody>' + rows + '</tbody></table></div>';
  }

  /* ---------------- Load ---------------- */
  function load() {
    fetch(ENDPOINT, { headers: { 'Accept': 'application/json' }, credentials: 'same-origin' })
      .then(function (res) {
        return res.json().then(function (body) {
          if (!res.ok || body.success !== true) {
            var e = (body && body.error) || {};
            throw { code: e.code || 'REQUEST_FAILED', message: e.message || 'Command Center data could not be retrieved.' };
          }
          return body.data;
        });
      })
      .then(function (data) {
        renderAlerts(data.alerts);
        renderSummary(data);
        renderHealth(data.health);
        renderModel(data.model_health);
        renderCases(data.counts);
        renderRecent(data.recent_analyses);
        if (window.LAB) window.LAB.refreshHeaderHealth();
      })
      .catch(function (err) {
        /* Section 54 — calm, operational error with a real error code. */
        var code = (err && err.code) || 'NETWORK_ERROR';
        var msg = (err && err.message) || 'Command Center data could not be retrieved.';
        ['cc-alerts', 'cc-health-table'].forEach(function (id) {
          var el = $(id);
          if (!el) return;
          el.innerHTML = '';
          var wrap = document.createElement('div');
          wrap.className = 'lab-state is-error';
          wrap.innerHTML =
            '<div class="lab-state-icon">!</div>' +
            '<div class="lab-state-title">COMMAND CENTER UNAVAILABLE</div>' +
            '<p class="lab-state-desc">' + esc(msg) + '</p>' +
            '<div class="lab-provenance">ERROR CODE: ' + esc(code) + '</div>';
          el.appendChild(wrap);
        });
        var foot = $('cc-health-foot');
        if (foot) foot.textContent = 'Health data could not be retrieved.';
      });
  }

  var btn = $('cc-refresh');
  if (btn) {
    btn.addEventListener('click', function () {
      btn.disabled = true;
      load();
      setTimeout(function () { btn.disabled = false; }, 600);
    });
  }

  load();
})();

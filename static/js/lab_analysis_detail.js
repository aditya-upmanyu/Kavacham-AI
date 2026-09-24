/* ====================================================================
   KAVACHAM LAB — ANALYSIS DETAIL (Phase 7, Sections 40 & 41)
   Renders the persisted analysis record: transparency metadata,
   stages actually performed, findings, and the raw engine payload.
   ==================================================================== */
(function () {
  'use strict';

  var esc = window.LAB.esc;
  var fmtTs = window.LAB.fmtTs;
  var REF = window.__LAB_AN_REF__;

  var loading = document.getElementById('an-loading');
  var errorHost = document.getElementById('an-error');
  var view = document.getElementById('an-view');

  function verdictBadge(v) {
    var verdict = String(v || '—').toUpperCase();
    var cls = 'lab-badge-gray';
    if (verdict.match(/SAFE|CLEAN/)) cls = 'lab-badge-green';
    else if (verdict.match(/SUSPICIOUS|PARTIAL/)) cls = 'lab-badge-amber';
    else if (verdict.match(/MALICIOUS|HIGH|CRITICAL/)) cls = 'lab-badge-red';
    return '<span class="lab-badge ' + cls + '">' + esc(verdict) + '</span>';
  }

  function statusBadge(status) {
    var cls = status === 'COMPLETE' ? 'lab-badge-green'
      : status === 'PARTIAL' ? 'lab-badge-amber' : 'lab-badge-red';
    return '<span class="lab-badge ' + cls + '">' + esc(status) + '</span>';
  }

  function load() {
    loading.hidden = false;
    view.hidden = true;
    errorHost.hidden = true;

    fetch('/lab/api/analysis/' + encodeURIComponent(REF), {
      headers: { 'Accept': 'application/json' }, credentials: 'same-origin'
    })
      .then(function (res) {
        return res.json().then(function (body) {
          if (!res.ok || body.success !== true) {
            var e = (body && body.error) || {};
            throw { code: e.code || 'REQUEST_FAILED',
                    message: e.message || 'The analysis record could not be retrieved.' };
          }
          return body.data.analysis;
        });
      })
      .then(function (an) {
        render(an);
        loading.hidden = true;
        errorHost.hidden = true;
        view.hidden = false;
      })
      .catch(function (err) {
        loading.hidden = true;
        errorHost.hidden = false;
        window.LAB.renderError(errorHost,
          (err && err.code) || 'NETWORK_ERROR',
          (err && err.message) || 'The analysis record could not be retrieved.',
          { label: 'RETRY', onClick: load });
      });
  }

  function render(an) {
    document.title = an.analysis_ref + ' — KAVACHAM LAB';
    document.getElementById('an-ref').textContent = an.analysis_ref;
    document.getElementById('an-type').textContent = an.analysis_type;
    document.getElementById('an-status').innerHTML = statusBadge(an.status);
    document.getElementById('an-verdict-badge').innerHTML = verdictBadge(an.verdict);
    document.getElementById('an-title').textContent =
      (an.type_info && an.type_info.label) || an.analysis_type;
    document.getElementById('an-evidence').textContent =
      an.evidence ? (an.evidence.evidence_ref + ' · ' + an.evidence.evidence_type) : '—';
    document.getElementById('an-case').textContent =
      an.case ? an.case.case_ref : 'Unattached';
    document.getElementById('an-created').textContent =
      fmtTs(an.created_at) + ' UTC';

    document.getElementById('an-counts').innerHTML = [
      ['VERDICT', an.verdict || '—'],
      ['RISK SCORE', an.risk_score === null || an.risk_score === undefined ? '—' : String(an.risk_score)],
      ['CONFIDENCE', an.confidence === null || an.confidence === undefined ? 'n/a' : String(an.confidence)],
      ['FINDINGS', (an.findings || []).length],
      ['STAGES', ((an.payload && an.payload.stages) || []).length],
      ['ENGINE', an.engine_version || '—']
    ].map(function (p) {
      return '<div class="lab-strip-item"><span class="lab-label">' + esc(p[0]) +
        '</span><span class="lab-strip-value">' + esc(String(p[1])) + '</span></div>';
    }).join('');

    renderMeta(an);
    renderStages(an);
    renderFindings(an);
    renderPayload(an);
  }

  function renderMeta(an) {
    var rows = [
      ['ANALYSIS ID', an.analysis_ref, true],
      ['TYPE', an.analysis_type, false],
      ['TYPE LABEL', (an.type_info && an.type_info.label) || '—', false],
      ['STATUS', an.status, false],
      ['VERDICT', an.verdict || '—', false],
      ['RISK SCORE', String(an.risk_score === null || an.risk_score === undefined ? '—' : an.risk_score), true],
      ['CONFIDENCE', an.confidence === null || an.confidence === undefined ? '—' : String(an.confidence) + '%', true],
      ['ENGINE', an.engine_version || '—', true],
      ['EVIDENCE', an.evidence ? an.evidence.evidence_ref : '—', true],
      ['EVIDENCE TYPE', an.evidence ? an.evidence.evidence_type : '—', false],
      ['CASE', an.case ? an.case.case_ref : 'Unattached', true],
      ['CREATED', fmtTs(an.created_at) + ' UTC', true]
    ];
    document.getElementById('an-meta').innerHTML = rows.map(function (r) {
      return '<dt>' + esc(r[0]) + '</dt><dd' + (r[2] ? ' class="lab-mono"' : '') +
        '>' + esc(String(r[1])) + '</dd>';
    }).join('');
  }

  function renderStages(an) {
    var host = document.getElementById('an-stages');
    var stages = ((an.payload && an.payload.stages) || []);
    if (!stages.length) {
      host.innerHTML = '<li class="lab-timeline-item">' +
        '<div class="lab-timeline-marker" aria-hidden="true"></div>' +
        '<div class="lab-timeline-body"><span class="lab-badge lab-badge-gray">NO STAGES</span>' +
        '<div class="lab-xs lab-dim" style="margin-top:4px;">This run did not record stages.</div>' +
        '</div></li>';
      return;
    }
    host.innerHTML = stages.map(function (s, i) {
      var icon = s.status === 'done' ? '✓' : (s.status === 'unavailable' ? '!' : '–');
      var cls = s.status === 'done' ? 'lab-badge-green'
        : s.status === 'unavailable' ? 'lab-badge-amber' : 'lab-badge-gray';
      return '<li class="lab-timeline-item">' +
        '<div class="lab-timeline-marker" aria-hidden="true"></div>' +
        '<div class="lab-timeline-body">' +
        '<div class="lab-row tight">' +
        '<span class="lab-badge ' + cls + '">' + esc(icon + ' ' + s.status.toUpperCase()) + '</span>' +
        '<span class="lab-strong lab-xs">' + esc(s.name) + '</span></div>' +
        (s.detail ? '<div class="lab-xs lab-dim" style="margin-top:4px;">' +
          esc(s.detail) + '</div>' : '') +
        '</div></li>';
    }).join('');
  }

  function renderFindings(an) {
    var host = document.getElementById('an-findings');
    var findings = an.findings || [];
    if (!findings.length) {
      host.innerHTML = '';
      host.appendChild(window.LAB.emptyState('—', 'NO FINDINGS',
        'This analysis run reported no findings.', null));
      return;
    }
    var sevCls = {
      critical: 'lab-badge-red', high: 'lab-badge-red',
      medium: 'lab-badge-amber', low: 'lab-badge-gray', none: 'lab-badge-gray'
    };
    host.innerHTML = '<div class="lab-table-wrap"><table class="lab-table">' +
      '<thead><tr><th scope="col">Type</th><th scope="col">Severity</th>' +
      '<th scope="col">Title</th><th scope="col">Detail</th>' +
      '<th scope="col">Source</th></tr></thead><tbody>' +
      findings.map(function (f) {
        return '<tr><td><span class="lab-badge lab-badge-blue">' +
          esc((f.finding_type || 'indicator').toUpperCase()) + '</span></td>' +
          '<td><span class="lab-badge ' + (sevCls[f.severity] || 'lab-badge-gray') + '">' +
          esc(String(f.severity || 'low').toUpperCase()) + '</span></td>' +
          '<td class="lab-strong">' + esc(f.title || '—') + '</td>' +
          '<td class="lab-xs">' + esc(f.detail || '—') + '</td>' +
          '<td><span class="lab-mono lab-xs">' + esc(f.source || '—') + '</span></td>' +
          '</tr>';
      }).join('') + '</tbody></table></div>';
  }

  function renderPayload(an) {
    var host = document.getElementById('an-payload');
    var sources = document.getElementById('an-sources');
    sources.textContent = an.source && an.source.length ? an.source : '—';
    var payload = an.payload || {};
    var mini = {};
    ['verdict', 'sources', 'engine_version'].forEach(function (k) {
      if (k in payload && payload[k] !== undefined && payload[k] !== null) {
        mini[k] = payload[k];
      }
    });
    var analysis = payload.analysis || {};
    var keys = ['analyzed', 'intel', 'hash_type', 'hash_value', 'local_matches',
                'url_count', 'url_sub_analysis', 'size_bytes', 'extension',
                'mime_type', 'blocked_content', 'decoded', 'domain',
                'registrable_domain', 'structure_risk', 'structure_score',
                'findings'];
    keys.forEach(function (k) {
      if (analysis && analysis[k] !== undefined && analysis[k] !== null) {
        mini[k] = analysis[k];
      }
    });
    if (!Object.keys(mini).length && analysis) {
      mini.raw = analysis;
    }
    host.textContent = JSON.stringify(mini, null, 2) || '—';
  }

  load();
})();
/* ====================================================================
   KAVACHAM LAB — Risk Assessment controller (Phase 9, Sections AZ/BA)
   Loads the real risk register, then the evidence-first assessment for
   a selected case. No fabricated scores: everything comes from the
   backend which computes from stored analyses/findings/IOCs only.
   ==================================================================== */
(function () {
  'use strict';

  var regBody = document.getElementById('risk-register-body');
  var detBody = document.getElementById('risk-detail-body');
  var detRef = document.getElementById('risk-detail-ref');
  var filterEl = document.getElementById('risk-filter');
  var totalEl = document.getElementById('risk-total');
  var tsEl = document.getElementById('risk-register-ts');
  var engineMeta = document.getElementById('risk-engine-meta');

  var register = [];   // cached register items
  var selectedRef = null;
  var currentDetail = null;

  var SEV_CLASS = { high: 'is-high', medium: 'is-medium', low: 'is-low', info: 'is-info', warning: 'is-medium' };

  /* ---------------- helpers ---------------- */
  function badge(level) {
    var cls = 'is-muted';
    if (level === 'LOW') cls = 'is-low';
    else if (level === 'SUSPICIOUS') cls = 'is-suspicious';
    else if (level === 'HIGH') cls = 'is-high';
    return '<span class="risk-badge ' + cls + '">' + LAB.esc(level) + '</span>';
  }

  function dot(level) {
    var cls = 'is-muted';
    if (level === 'LOW') cls = 'is-low';
    else if (level === 'SUSPICIOUS') cls = 'is-suspicious';
    else if (level === 'HIGH') cls = 'is-high';
    return '<span class="risk-level-dot ' + cls + '" title="' + LAB.esc(level) + '"></span>';
  }

  function fill(level, score) {
    var cls = 'is-muted';
    if (level === 'LOW') cls = 'is-low';
    else if (level === 'SUSPICIOUS') cls = 'is-suspicious';
    else if (level === 'HIGH') cls = 'is-high';
    return '<div class="risk-cell-track"><div class="risk-cell-fill ' + cls + '" style="width:' + score + '%"></div></div>';
  }

  function kv(label, value) {
    return '<div class="risk-kv"><div class="rk-label">' + LAB.esc(label) +
      '</div><div class="rk-value">' + (value === null || value === undefined ? '—' : value) + '</div></div>';
  }

  function chips(values) {
    return (values || []).map(function (v) { return '<span class="lab-chip">' + LAB.esc(v) + '</span>'; }).join('');
  }

  /* ---------------- register ---------------- */
  function renderFiltered() {
    var q = (filterEl.value || '').trim().toLowerCase();
    if (!regBody) return;
    var rows = register.filter(function (c) {
      return !q || c.case_ref.toLowerCase().indexOf(q) !== -1 ||
        (c.title || '').toLowerCase().indexOf(q) !== -1;
    });

    if (!rows.length) {
      regBody.innerHTML = '';
      var empty = LAB.emptyState('0', q ? 'NO MATCHING CASES' : 'NO CASES ASSESSED',
        q ? 'No case matches the current filter.' :
          'Creation of a case and running analyses will populate the register.');
      regBody.appendChild(empty);
      return;
    }

    var html = '<div class="lab-table-wrap"><table class="lab-table">' +
      '<thead><tr><th scope="col">Case</th><th scope="col">Type</th>' +
      '<th scope="col">Analyses</th><th scope="col">Verified IOC</th>' +
      '<th scope="col">Risk</th><th scope="col">Level</th></tr></thead><tbody>';
    rows.forEach(function (c) {
      var sel = c.case_ref === selectedRef ? ' is-selected' : '';
      html += '<tr class="risk-row' + sel + '" data-ref="' + LAB.esc(c.case_ref) + '" tabindex="0" ' +
        'aria-label="Assess ' + LAB.esc(c.case_ref) + '">' +
        '<td><div class="lab-strong lab-mono">' + LAB.esc(c.case_ref) + '</div>' +
        '<div class="lab-xs lab-dim">' + LAB.esc(c.title || '') + '</div></td>' +
        '<td>' + LAB.esc(c.case_type) + '</td>' +
        '<td class="lab-mono">' + c.analysis_count + '</td>' +
        '<td class="lab-mono">' + c.verified_ioc_count + '</td>' +
        '<td><div class="risk-cell-bar"><span class="lab-mono">' + c.risk_score + '</span>' +
        fill(c.risk_level, c.risk_score) + '</div></td>' +
        '<td>' + dot(c.risk_level) + ' ' + LAB.esc(c.risk_level) + '</td>' +
        '</tr>';
    });
    html += '</tbody></table></div>';
    regBody.innerHTML = html;

    regBody.querySelectorAll('.risk-row').forEach(function (row) {
      row.addEventListener('click', function () { selectCase(row.getAttribute('data-ref')); });
      row.addEventListener('keydown', function (e) {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          selectCase(row.getAttribute('data-ref'));
        }
      });
    });
  }

  function renderRegister(data) {
    register = data.items || [];
    if (totalEl) totalEl.textContent = (register.length ? register.length : '0') + ' case(s)';
    if (tsEl) tsEl.textContent = 'COMPUTED ' + (LAB.fmtTs(data.computed_at) || '—');
    if (engineMeta) engineMeta.textContent = (data.engine || 'risk-engine') + ' v' + (data.engine_version || '?');
    renderFiltered();
  }

  /* ---------------- detail ---------------- */
  function findingCard(f) {
    var sev = String(f.severity || '').toLowerCase();
    var sevCls = SEV_CLASS[sev] || 'is-low';
    var evHtml = f.evidence && f.evidence.length ? chips(f.evidence) : '<span class="lab-dim">No direct evidence reference recorded.</span>';
    return '<div class="risk-finding ' + sevCls + '">' +
      '<div class="risk-finding-head">' +
      '<span class="risk-finding-title">' + LAB.esc(f.what || 'Finding') + '</span>' +
      (f.analysis_ref ? '<span class="risk-finding-ref">' + LAB.esc(f.analysis_ref) + '</span>' : '') +
      '<span class="risk-badge ' + (sevCls === 'is-high' ? 'is-high' : (sevCls === 'is-medium' ? 'is-suspicious' : 'is-muted')) + '">' +
      LAB.esc(f.severity || 'INFO') + '</span></div>' +
      '<dl>' +
      (f.why ? '<dt>WHY</dt><dd>' + LAB.esc(f.why) + '</dd>' : '') +
      '<dt>EVIDENCE</dt><dd>' + evHtml + '</dd>' +
      '<dt>SOURCE</dt><dd>' + chips(f.source) + '</dd>' +
      '<dt>IMPACT</dt><dd>' + LAB.esc(f.impact || '') + '</dd>' +
      '<dt>LIMITATION</dt><dd>' + LAB.esc(f.limitation || '') + '</dd>' +
      '</dl></div>';
  }

  function renderDetail(d) {
    if (detRef) detRef.textContent = d.case.case_ref;
    var scoreNum = d.risk_score;
    var markerPos = Math.max(2, Math.min(98, scoreNum)); // keep marker inside the track

    var html = '';
    html += '<div class="risk-score-strip">' +
      '<span class="risk-score-big ' + (d.risk_level === 'HIGH' ? 'is-high' : d.risk_level === 'SUSPICIOUS' ? 'is-suspicious' : 'is-low') + '">' +
      scoreNum + '</span>' +
      badge(d.risk_level);
    if (d.primary_classification) {
      html += '<span class="lab-badge lab-badge-blue">' + LAB.esc(d.primary_classification) + '</span>';
    }
    html += '<span class="lab-badge lab-mono">' + LAB.esc(d.case.case_type) + '</span></div>';

    html += '<div class="risk-scale-marker" data-score="' + scoreNum + '" style="margin-bottom:22px;">' +
      '<span style="left:' + markerPos + '%;"></span></div>';

    // components
    html += '<div class="risk-kv-grid" style="margin-bottom:16px;">' +
      kv('HIGHEST ANALYSIS', d.components.highest) +
      kv('MEAN ANALYSIS', d.components.mean) +
      kv('VERIFIED IOC', d.components.verified_count) +
      kv('OBSERVED IOC', d.components.observed_count) +
      kv('ANALYSES', d.components.analysis_count) +
      kv('ACTIVE ANALYSES', d.components.active_count) +
      '</div>';

    // explanations
    if (d.explanations && d.explanations.length) {
      html += '<h3 class="lab-section-title" style="margin:14px 0 8px;">EXPLANATION</h3><ul class="lab-list" style="margin:0 0 6px 18px;">';
      d.explanations.forEach(function (e) { html += '<li>' + LAB.esc(e) + '</li>'; });
      html += '</ul>';
    }

    // limitations
    if (d.limitations && d.limitations.length) {
      html += '<h3 class="lab-section-title" style="margin:14px 0 8px;">LIMITATIONS</h3>';
      html += '<p class="lab-dim lab-sm" style="margin:0 0 14px;">' +
        d.limitations.map(LAB.esc).join('<br/>') + '</p>';
    }

    // findings
    html += '<h3 class="lab-section-title" style="margin:14px 0 8px;">EVIDENCE-FIRST FINDINGS</h3>';
    if (d.findings && d.findings.length) {
      d.findings.forEach(function (f) { html += findingCard(f); });
    } else {
      html += '<p class="lab-dim lab-sm">No findings contribute to this score yet — ' +
        'run analyses against this case\u2019s evidence to populate findings.</p>';
    }

    // per-analysis assessments
    if (d.analyses && d.analyses.length) {
      html += '<h3 class="lab-section-title" style="margin:16px 0 8px;">CONTRIBUTING ANALYSES</h3>';
      html += '<div class="lab-table-wrap"><table class="lab-table"><thead><tr>' +
        '<th scope="col">Analysis</th><th scope="col">Type</th><th scope="col">Verdict</th>' +
        '<th scope="col">Score</th><th scope="col">Level</th><th scope="col">Classification</th></tr></thead><tbody>';
      d.analyses.slice().reverse().forEach(function (a) {
        html += '<tr>' +
          '<td class="lab-mono">' + LAB.esc(a.analysis_ref) + '</td>' +
          '<td>' + LAB.esc(a.analysis_type) + '</td>' +
          '<td>' + LAB.esc(a.verdict || '—') + '</td>' +
          '<td class="lab-mono">' + a.risk_score + '</td>' +
          '<td>' + dot(a.risk_level) + ' ' + LAB.esc(a.risk_level) + '</td>' +
          '<td>' + LAB.esc(a.classification) + '</td></tr>';
      });
      html += '</tbody></table></div>';
    }

    html += '<div class="risk-provenance-line">' +
      'ENGINE ' + LAB.esc(d.engine) + ' v' + LAB.esc(d.engine_version) +
      ' · FORMULA ' + LAB.esc(d.formula || '') +
      ' · COMPUTED ' + (LAB.fmtTs(d.computed_at) || '—') + ' UTC' +
      '</div>';

    detBody.innerHTML = html;
  }

  function selectCase(caseRef, fromUser) {
    if (!caseRef) return;
    selectedRef = caseRef;
    if (regBody) renderFiltered(); // highlight selection
    if (detRef) detRef.textContent = caseRef;
    detBody.innerHTML = '<div class="lab-panel-body"><div class="lab-skeleton lab-skeleton-line" style="width:60%;"></div>' +
      '<div class="lab-skeleton lab-skeleton-line" style="width:80%;"></div>' +
      '<div class="lab-skeleton lab-skeleton-line" style="width:50%;"></div>' +
      '<p class="lab-xs lab-dim" style="margin-top:10px;">Computing assessment from stored records…</p></div>';

    fetch('/lab/api/risk?case=' + encodeURIComponent(caseRef), { headers: { 'Accept': 'application/json' } })
      .then(function (res) { return res.json(); })
      .then(function (body) {
        if (!body || body.success !== true || !body.data) {
          var err = body && body.error ? body.error : { code: 'RISK_UNAVAILABLE', message: 'Assessment unavailable.' };
          LAB.renderError(detBody, err.code, err.message);
          return;
        }
        currentDetail = body.data;
        renderDetail(body.data);
        if (fromUser) {
          try { window.history.replaceState(null, '', '/lab/risk?case=' + encodeURIComponent(caseRef)); } catch (e) {}
        }
      })
      .catch(function () {
        LAB.renderError(detBody, 'RISK_UNAVAILABLE', 'The assessment could not be retrieved.', {
          label: 'Retry', onClick: function () { selectCase(caseRef, fromUser); }
        });
      });
  }

  /* ---------------- boot ---------------- */
  function boot(params) {
    fetch('/lab/api/risk', { headers: { 'Accept': 'application/json' } })
      .then(function (res) { return res.json(); })
      .then(function (body) {
        if (!body || body.success !== true || !body.data) {
          LAB.renderError(regBody, (body && body.error && body.error.code) || 'RISK_UNAVAILABLE',
            (body && body.error && body.error.message) || 'The risk register could not be retrieved.');
          return;
        }
        renderRegister(body.data);
        // prefill from ?case=
        var requested = ((params.case || params.get && params.get('case')) || '').toString().trim();
        var item = register.filter(function (c) { return c.case_ref === requested; })[0];
        if (item) selectCase(item.case_ref, true);
        else if (register.length) selectCase(register[0].case_ref, false);
      })
      .catch(function () {
        LAB.renderError(regBody, 'RISK_UNAVAILABLE', 'The risk register could not be retrieved.', {
          label: 'Retry', onClick: boot
        });
      });
  }

  if (filterEl) {
    filterEl.addEventListener('input', renderFiltered);
  }

  var params;
  try { params = new URLSearchParams(window.location.search); } catch (e) { params = window.location.search || ''; }
  boot(params);
})();
/* ====================================================================
   KAVACHAM LAB — RUN ANALYSIS (Phase 7, Sections 29-41)
   Select evidence + analysis type -> POST /lab/api/analysis.
   Compatibility is enforced server-side; the form mirrors the real
   evidence-type matrix so incompatible pairs are rejected early.
   ==================================================================== */
(function () {
  'use strict';

  var esc = window.LAB.esc;
  var fmtTs = window.LAB.fmtTs;

  var reg = {};
  try {
    reg = JSON.parse(document.getElementById('ra-ref').textContent) || {};
  } catch (e) { reg = {}; }

  var form = document.getElementById('run-analysis-form');
  var selEvidence = document.getElementById('ra-evidence');
  var selType = document.getElementById('ra-type');
  var typeHint = document.getElementById('ra-type-hint');
  var compat = document.getElementById('ra-compat');
  var compatText = document.getElementById('ra-compat-text');
  var submit = document.getElementById('ra-submit');
  var statusText = document.getElementById('ra-status-text');
  var errorHost = document.getElementById('ra-error');
  var resultHost = document.getElementById('ra-result');

  var evidenceList = [];

  function setError(id, msg) {
    var el = document.getElementById('err-' + id);
    if (!el) return;
    if (msg) {
      el.textContent = msg;
      el.hidden = false;
    } else {
      el.hidden = true;
    }
  }

  function compatible(info) {
    var allowed = info && info.evidence_types;
    return allowed && allowed.indexOf(evidenceType()) !== -1;
  }

  function evidenceType() {
    var ev = evidenceList[selEvidence.value] || {};
    return ev.evidence_type || '';
  }

  function currentTypeInfo() {
    return (reg.registry || {})[selType.value] || null;
  }

  function syncTypeHint() {
    var info = currentTypeInfo();
    if (info) {
      typeHint.textContent = info.description || '';
      typeHint.hidden = false;
    } else {
      typeHint.textContent = '';
      typeHint.hidden = true;
    }
  }

  function syncCompatibility() {
    if (!selEvidence.value || !selType.value) {
      compat.hidden = true;
      submit.disabled = false;
      return;
    }
    if (compatible(currentTypeInfo())) {
      compat.hidden = true;
      submit.disabled = false;
      setError('ra-type', null);
    } else {
      var info = currentTypeInfo() || {};
      compat.hidden = false;
      compatText.textContent = 'Evidence type "' + evidenceType() +
        '" is not compatible with ' + (info.label || selType.value) +
        '. Compatible evidence types: ' + (info.evidence_types || []).join(', ') + '.';
      submit.disabled = true;
      setError('ra-type', 'Incompatible evidence / analysis type pair.');
    }
  }

  function loadEvidence() {
    fetch('/lab/api/evidence?limit=200', {
      headers: { 'Accept': 'application/json' }, credentials: 'same-origin'
    })
      .then(function (res) { return res.json(); })
      .then(function (body) {
        if (!body || body.success !== true) throw new Error('EVIDENCE_LOAD_FAILED');
        evidenceList = {};
        var items = (body.data && body.data.items) || [];
        selEvidence.innerHTML = '<option value="">— SELECT EVIDENCE —</option>';
        items.forEach(function (ev) {
          evidenceList[ev.evidence_ref] = ev;
          var opt = document.createElement('option');
          opt.value = ev.evidence_ref;
          opt.textContent = ev.evidence_ref + ' · ' + ev.evidence_type +
            ' · ' + ev.title;
          selEvidence.appendChild(opt);
        });
        if (!items.length) {
          selEvidence.innerHTML =
            '<option value="">— NO EVIDENCE IN VAULT —</option>';
        }
      })
      .catch(function () {
        selEvidence.innerHTML =
          '<option value="">— COULD NOT LOAD EVIDENCE —</option>';
      });
  }

  function verdictBadge(verdict) {
    var v = String(verdict || '—').toUpperCase();
    var cls = 'lab-badge-gray';
    if (v.match(/SAFE|CLEAN/)) cls = 'lab-badge-green';
    else if (v.match(/SUSPICIOUS|PARTIAL/)) cls = 'lab-badge-amber';
    else if (v.match(/MALICIOUS|HIGH|CRITICAL/)) cls = 'lab-badge-red';
    return '<span class="lab-badge ' + cls + '">' + esc(v) + '</span>';
  }

  function showResult(an) {
    resultHost.innerHTML =
      '<div class="lab-panel">' +
      '<div class="lab-panel-head">' +
      '<h2 class="lab-section-title">ANALYSIS COMPLETED</h2>' +
      '<span class="lab-badge lab-badge-green">' + esc(an.status) + '</span>' +
      '</div>' +
      '<div class="lab-panel-body">' +
      '<dl class="lab-kv">' +
      '<dt>ANALYSIS ID</dt><dd class="lab-mono">' + esc(an.analysis_ref) + '</dd>' +
      '<dt>TYPE</dt><dd>' + esc(an.analysis_type) + '</dd>' +
      '<dt>VERDICT</dt><dd>' + verdictBadge(an.verdict) + '</dd>' +
      '<dt>RISK SCORE</dt><dd class="lab-mono">' +
      esc(String(an.risk_score === null || an.risk_score === undefined ? '—' : an.risk_score)) + '</dd>' +
      '<dt>EVIDENCE</dt><dd class="lab-mono">' + esc(an.evidence ? an.evidence.evidence_ref : '—') + '</dd>' +
      '<dt>CASE</dt><dd class="lab-mono">' + esc(an.case ? an.case.case_ref : 'Unattached') + '</dd>' +
      '<dt>FINDINGS</dt><dd class="lab-mono">' + (an.findings || []).length + '</dd>' +
      '<dt>CREATED</dt><dd class="lab-mono">' + esc(fmtTs(an.created_at)) + '</dd>' +
      '</dl>' +
      '<div class="lab-row tight" style="margin-top:16px;">' +
      '<a class="lab-btn lab-btn-primary lab-btn-sm" href="/lab/analysis/' +
      encodeURIComponent(an.analysis_ref) + '">OPEN ANALYSIS RECORD</a>' +
      '<a class="lab-btn lab-btn-sm" href="/lab/analysis">WORKBENCH</a>' +
      '</div>' +
      '</div></div>';
    window.LAB.toast('Analysis complete', an.analysis_ref + ' -> ' + an.verdict,
      an.status === 'COMPLETE' ? 'success' : 'info');
  }

  function submitRun(e) {
    e.preventDefault();
    if (!selEvidence.value) {
      setError('ra-evidence', 'Select an evidence record to analyze.');
      return;
    }
    if (!selType.value) {
      setError('ra-type', 'Select an analysis type.');
      return;
    }
    if (submit.disabled) return;

    submit.disabled = true;
    submit.textContent = 'RUNNING…';
    statusText.textContent = 'Starting ' + selType.value + ' analysis…';
    if (errorHost) errorHost.innerHTML = '';
    if (resultHost) resultHost.innerHTML = '';

    fetch('/lab/api/analysis', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify({
        evidence_ref: selEvidence.value,
        analysis_type: selType.value
      })
    })
      .then(function (res) {
        return res.json().then(function (body) {
          if (!res.ok || body.success !== true) {
            var err = (body && body.error) || {};
            throw { code: err.code || 'REQUEST_FAILED',
                    message: err.message || 'The analysis could not be completed.',
                    status: res.status };
          }
          return body.data;
        });
      })
      .then(function (data) {
        showResult(data.analysis);
        statusText.textContent = 'Completed.';
      })
      .catch(function (err) {
        statusText.textContent = 'Failed.';
        if (errorHost) {
          window.LAB.renderError(errorHost,
            (err && err.code) || 'NETWORK_ERROR',
            (err && err.message) || 'The analysis could not be completed.');
        }
      })
      .then(function () {
        submit.disabled = false;
        submit.textContent = 'RUN ANALYSIS';
      });
  }

  form.addEventListener('submit', submitRun);
  selType.addEventListener('change', function () {
    syncTypeHint();
    syncCompatibility();
  });
  selEvidence.addEventListener('change', syncCompatibility);

  syncTypeHint();
  loadEvidence();
})();
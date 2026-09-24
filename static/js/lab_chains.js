/* ====================================================================
   KAVACHAM LAB — ATTACK CHAINS (Phase 8, Section 28)
   Evidence-backed stages. Every rendered stage cites the evidence
   (and analysis, where available) that supports it. When the vault
   cannot support a chain, that is reported honestly.
   ==================================================================== */
(function () {
  'use strict';

  var esc = window.LAB.esc;

  var els = {
    caseSel: document.getElementById('chain-case'),
    reload: document.getElementById('chain-reload'),
    body: document.getElementById('chain-body'),
    foot: document.getElementById('chain-foot'),
    stateLabel: document.getElementById('chain-state')
  };

  function riskBadge(risk) {
    if (!risk) { return ''; }
    var cls = risk >= 50 ? 'lab-badge-red' : risk >= 20 ? 'lab-badge-amber' : 'lab-badge-gray';
    return ' <span class="lab-badge ' + cls + '">RISK ' + esc(risk) + '</span>';
  }

  function render(chain) {
    if (!chain || !chain.length) {
      els.body.innerHTML = '';
      els.stateLabel.textContent = 'INSUFFICIENT EVIDENCE';
      els.body.appendChild(window.LAB.emptyState(
        '⨯', 'NO ATTACK CHAIN',
        'Insufficient evidence to infer an attack chain for this case. ' +
        'Chains are only rendered from relationships that existing evidence ' +
        'and analysis actually support.', null));
      els.foot.textContent = 'No chain derivable; evidence-backed stages only.';
      return;
    }

    var steps = chain.map(function (s, idx) {
      var ev = (s.evidence_refs || []).length
        ? s.evidence_refs.map(function (r) {
            return '<a class="lab-link lab-mono lab-xs" href="/lab/evidence/' +
              encodeURIComponent(r) + '">' + esc(r) + '</a>';
          }).join(' ')
        : '<span class="lab-xs lab-dim">(case-level)</span>';
      var an = (s.analysis_refs || []).length
        ? '<div class="lab-xs lab-dim" style="margin-top:4px;">analysis: ' +
          s.analysis_refs.map(function (r) {
            return '<a class="lab-link lab-mono" href="/lab/analysis/' +
              encodeURIComponent(r) + '">' + esc(r) + '</a>';
          }).join(', ') + '</div>'
        : '';
      var arrow = idx < chain.length - 1
        ? '<div class="lab-chain-arrow" aria-hidden="true">↓</div>' : '';
      return '<div class="lab-chain-step">' +
        '<div class="lab-chain-step-head">' +
          '<span class="lab-chain-seq">' + String(idx + 1).padStart(2, '0') + '</span>' +
          '<span class="lab-chain-label lab-strong">' + esc(s.label) + '</span>' +
          riskBadge(s.risk) +
        '</div>' +
        '<div class="lab-xs lab-dim" style="margin-top:5px;">supporting evidence: ' +
          ev + '</div>' + an +
        '</div>' + arrow;
    }).join('');

    els.body.innerHTML = '<div class="lab-panel-body"><div class="lab-chain">' +
      steps + '</div></div>';
    els.foot.textContent = chain.length + ' stage(s) — every stage is backed by real evidence.';
    els.stateLabel.textContent = chain.length + ' STAGES · EVIDENCE-BACKED';
  }

  function loadCases() {
    return fetch('/lab/api/intel/attack-chain', {
      headers: { 'Accept': 'application/json' }, credentials: 'same-origin'
    })
      .then(function (res) { return res.json(); })
      .then(function (body) {
        if (!body.success) { throw (body.error || {}); }
        var cases = body.data.cases || [];
        els.caseSel.innerHTML = '<option value="">SELECT CASE…</option>' +
          cases.map(function (c) {
            return '<option value="' + esc(c.case_ref) + '">' + esc(c.case_ref) +
              ' — ' + esc(c.title) + ' (' + c.evidence_count + ' ev)</option>';
          }).join('');
        return cases;
      });
  }

  function loadChain(caseRef) {
    els.foot.textContent = 'Deriving evidence-backed chain…';
    els.body.innerHTML =
      '<div class="lab-panel-body">' +
      '<div class="lab-skeleton lab-skeleton-line" style="width:70%;"></div>' +
      '<div class="lab-skeleton lab-skeleton-line" style="width:50%;"></div>' +
      '<div class="lab-skeleton lab-skeleton-line" style="width:62%;"></div>' +
      '</div>';
    fetch('/lab/api/intel/attack-chain?case=' + encodeURIComponent(caseRef), {
      headers: { 'Accept': 'application/json' }, credentials: 'same-origin'
    })
      .then(function (res) { return res.json(); })
      .then(function (body) {
        if (!body.success) { throw (body.error || {}); }
        els.stateLabel.textContent = '';
        if (body.data.note) {
          els.foot.textContent = body.data.note;
        }
        render(body.data.chain || []);
      })
      .catch(function (err) {
        els.body.innerHTML = '';
        els.stateLabel.textContent = 'UNAVAILABLE';
        els.foot.textContent = err.message || 'Chain could not be derived.';
      });
  }

  els.caseSel.addEventListener('change', function () {
    if (els.caseSel.value) { loadChain(els.caseSel.value); }
  });
  els.reload.addEventListener('click', function () {
    loadCases().then(function () {
      if (els.caseSel.value) { loadChain(els.caseSel.value); }
    });
  });

  loadCases().then(function (cases) {
    if (cases && cases.length) {
      els.caseSel.value = cases[0].case_ref;
      loadChain(cases[0].case_ref);
    } else {
      els.body.innerHTML = '';
      els.body.appendChild(window.LAB.emptyState(
        '—', 'NO CASES',
        'Create an investigation first; chains require a case with evidence.',
        { label: 'NEW INVESTIGATION', onClick: function () { location.href = '/lab/cases/new'; } }
      ));
      els.foot.textContent = 'No cases available.';
    }
  }).catch(function (err) {
    els.foot.textContent = err.message || 'Cases could not be loaded.';
  });
})();
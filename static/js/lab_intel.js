/* ====================================================================
   KAVACHAM LAB — IOC INTELLIGENCE (Phase 8, Sections 26-27)
   Catalogue, search, sync, status workflow, add-to-case and detail
   provenance, all backed by /lab/api/intel/iocs. No synthesized IOCs.
   ==================================================================== */
(function () {
  'use strict';

  var esc = window.LAB.esc;
  var fmtTs = window.LAB.fmtTs;
  var toast = window.LAB.toast;

  var els = {
    body: document.getElementById('ioc-body'),
    foot: document.getElementById('ioc-foot'),
    total: document.getElementById('ioc-total'),
    search: document.getElementById('ioc-search'),
    type: document.getElementById('ioc-type'),
    status: document.getElementById('ioc-status'),
    caseRef: document.getElementById('ioc-case'),
    clear: document.getElementById('ioc-clear'),
    sync: document.getElementById('ioc-sync'),
    modal: document.getElementById('ioc-modal'),
    modalBody: document.getElementById('ioc-modal-body'),
    modalX: document.getElementById('ioc-modal-x')
  };

  var debounceTimer = null;
  var current = null;

  function typeBadge(t) {
    return '<span class="lab-badge lab-badge-blue">' + esc(t) + '</span>';
  }

  function statusBadge(s) {
    var cls = s === 'VERIFIED' ? 'lab-badge-green'
      : s === 'FALSE_POSITIVE' ? 'lab-badge-red' : 'lab-badge-gray';
    return '<span class="lab-badge ' + cls + '">' + esc(s) + '</span>';
  }

  function sevBadge(s) {
    var v = String(s || 'UNKNOWN').toUpperCase();
    var cls = v === 'CRITICAL' || v === 'HIGH' ? 'lab-badge-red'
      : v === 'MEDIUM' ? 'lab-badge-amber' : 'lab-badge-gray';
    return '<span class="lab-badge ' + cls + '">' + esc(v) + '</span>';
  }

  function buildQuery() {
    var p = new URLSearchParams();
    if (els.search && els.search.value.trim()) p.set('q', els.search.value.trim());
    if (els.type && els.type.value) p.set('type', els.type.value);
    if (els.status && els.status.value) p.set('status', els.status.value);
    if (els.caseRef && els.caseRef.value.trim()) p.set('case', els.caseRef.value.trim());
    p.set('limit', '200');
    return p.toString();
  }

  function copyValue(value, e) {
    e.stopPropagation();
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(value).then(function () {
        toast('Copied', 'Indicator value copied to clipboard.', 'info');
      }).catch(function () { fallbackCopy(value, e); });
    } else {
      fallbackCopy(value, e);
    }
  }

  function fallbackCopy(value, e) {
    var ta = document.createElement('textarea');
    ta.value = value;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand('copy'); toast('Copied', 'Indicator value copied.', 'info'); }
    catch (err) { toast('Copy failed', 'Your browser blocked clipboard access.', 'error'); }
    document.body.removeChild(ta);
  }

  function analyzeValue(value, e) {
    e.stopPropagation();
    location.href = '/lab/analysis?q=' + encodeURIComponent(value);
  }

  function openDetail(iocId, e) {
    if (e) e.stopPropagation();
    els.modal.hidden = false;
    els.modalBody.innerHTML =
      '<div class="lab-panel-body">' +
      '<div class="lab-skeleton lab-skeleton-line" style="width:60%;"></div>' +
      '<div class="lab-skeleton lab-skeleton-line" style="width:80%;"></div>' +
      '<div class="lab-skeleton lab-skeleton-line" style="width:45%;"></div>' +
      '</div>';
    fetch('/lab/api/intel/iocs/' + encodeURIComponent(iocId), {
      headers: { 'Accept': 'application/json' }, credentials: 'same-origin'
    })
      .then(function (res) { return res.json(); })
      .then(function (body) {
        if (!body.success) { throw (body.error || {}); }
        renderDetail(body.data.ioc);
      })
      .catch(function (err) {
        els.modalBody.innerHTML = window.LAB.renderError
          ? window.LAB.renderError('', err.code || 'IOC_READ_FAILED',
              err.message || 'Indicator could not be retrieved.')
          : '<p class="lab-state-text">' + esc(err.message || 'Request failed') + '</p>';
      });
  }

  function closeModal() { els.modal.hidden = true; current = null; }

  function renderDetail(ioc) {
    current = ioc;
    var intel = ioc.intel && ioc.intel.configured
      ? (ioc.intel.verdict
          ? '<span class="lab-badge ' +
            (String(ioc.intel.verdict).match(/malicious/i) ? 'lab-badge-red' : 'lab-badge-green') +
            '">' + esc(ioc.intel.verdict) + '</span>' +
            (ioc.intel.note ? ' <span class="lab-xs lab-dim">' + esc(ioc.intel.note) + '</span>' : '')
          : '<span class="lab-badge lab-badge-gray">NO DATA</span> ' +
            (ioc.intel.note ? '<span class="lab-xs lab-dim">' + esc(ioc.intel.note) + '</span>' : ''))
      : '<span class="lab-badge lab-badge-gray">NOT CONFIGURED</span> ' +
        '<span class="lab-xs lab-dim">VirusTotal intel unavailable on this deployment.</span>';

    var cases = (ioc.related_cases || []).length
      ? '<table class="lab-table"><thead><tr><th scope="col">Case</th><th scope="col">Title</th>' +
        '<th scope="col">Status</th><th scope="col">Type</th></tr></thead><tbody>' +
        (ioc.related_cases.map(function (c) {
          return '<tr class="is-clickable" data-href="/lab/cases/' +
            encodeURIComponent(c.case_ref) + '"><td class="lab-mono">' +
            esc(c.case_ref) + '</td><td>' + esc(c.title) + '</td><td>' +
            statusBadge(c.status) + '</td><td><span class="lab-xs">' +
            esc(c.case_type) + '</span></td></tr>';
        }).join('')) + '</tbody></table>'
      : '<p class="lab-state-text">No cases currently link this indicator.</p>';

    var evidence = (ioc.related_evidence || []).length
      ? '<ul class="lab-list">' + ioc.related_evidence.slice(0, 8).map(function (e) {
          return '<li><a class="lab-link" href="/lab/evidence/' +
            encodeURIComponent(e.evidence_ref) + '"><span class="lab-mono">' +
            esc(e.evidence_ref) + '</span></a> <span class="lab-xs lab-dim">' +
            esc(e.evidence_type) + ' — ' + esc(e.title) + '</span></li>';
        }).join('') + '</ul>'
        + (ioc.evidence_total > 8
           ? '<p class="lab-xs lab-dim">…and ' + (ioc.evidence_total - 8) + ' more.</p>' : '')
      : '<p class="lab-state-text">No evidence record contains this value.</p>';

    var analyses = (ioc.related_analyses || []).length
      ? '<ul class="lab-list">' + ioc.related_analyses.slice(0, 6).map(function (a) {
          return '<li><a class="lab-link" href="/lab/analysis/' +
            encodeURIComponent(a.analysis_ref) + '"><span class="lab-mono">' +
            esc(a.analysis_ref) + '</span></a> <span class="lab-xs lab-dim">' +
            esc(a.analysis_type) + ' → ' + esc(a.verdict) +
            ' (risk ' + esc(a.risk_score) + ')</span></li>';
        }).join('') + '</ul>'
      : '<p class="lab-state-text">No analysis run yet references this value.</p>';

    els.modalBody.innerHTML =
      '<div style="display:flex;justify-content:space-between;gap:12px;align-items:flex-start;">' +
        '<div style="min-width:0;"><div class="lab-mono lab-strong" style="word-break:break-all;">' +
          esc(ioc.value) + '</div>' +
          '<div style="margin-top:6px;">' + typeBadge(ioc.ioc_type) + ' ' +
          statusBadge(ioc.status) + ' ' + sevBadge(ioc.derived_severity) + '</div></div>' +
        '<div style="flex:0 0 auto;display:flex;gap:8px;">' +
          '<button class="lab-btn lab-btn-sm" data-act="copy">COPY</button>' +
          '<button class="lab-btn lab-btn-sm" data-act="analyze">ANALYZE</button>' +
        '</div>' +
      '</div>' +
      '<dl class="lab-dl" style="margin-top:14px;">' +
        '<dt>SOURCE</dt><dd class="lab-mono lab-xs">' + esc(ioc.source || '—') + '</dd>' +
        '<dt>STATUS</dt><dd><select class="lab-select lab-select-sm" id="ioc-status-edit">' +
          '<option value="OBSERVED"' + (ioc.status === 'OBSERVED' ? ' selected' : '') + '>OBSERVED</option>' +
          '<option value="VERIFIED"' + (ioc.status === 'VERIFIED' ? ' selected' : '') + '>VERIFIED</option>' +
          '<option value="FALSE_POSITIVE"' + (ioc.status === 'FALSE_POSITIVE' ? ' selected' : '') + '>FALSE POSITIVE</option>' +
        '</select></dd>' +
        '<dt>FIRST OBSERVED</dt><dd class="lab-mono lab-xs">' + esc(fmtTs(ioc.first_seen)) + '</dd>' +
        '<dt>LAST OBSERVED</dt><dd class="lab-mono lab-xs">' + esc(fmtTs(ioc.last_seen)) + '</dd>' +
        '<dt>RISK (analysis-derived)</dt><dd class="lab-mono lab-xs">' +
          (ioc.risk ? esc(String(ioc.risk)) : '—') + '</dd>' +
        '<dt>THREAT INTELLIGENCE</dt><dd>' + intel + '</dd>' +
      '</dl>' +
      '<h4 class="lab-subsection" style="margin:16px 0 8px;">RELATED CASES (' + ioc.case_count + ')</h4>' + cases +
      '<h4 class="lab-subsection" style="margin:16px 0 8px;">RELATED EVIDENCE (' + ioc.evidence_total + ')</h4>' + evidence +
      '<h4 class="lab-subsection" style="margin:16px 0 8px;">ANALYSES</h4>' + analyses +
      '<h4 class="lab-subsection" style="margin:16px 0 8px;">ADD TO CASE</h4>' +
      '<div class="lab-filter-row">' +
        '<div class="lab-field" style="margin-bottom:0;flex:1 1 200px;">' +
          '<input class="lab-input mono" id="ioc-add-case" type="search" placeholder="KAV-CASE-…" autocomplete="off" />' +
        '</div>' +
        '<div class="lab-field" style="margin-bottom:0;flex:0 0 auto;">' +
          '<button class="lab-btn lab-btn-primary lab-btn-sm" id="ioc-add-btn" type="button">ADD TO CASE</button>' +
        '</div>' +
      '</div>';

    var statusSel = document.getElementById('ioc-status-edit');
    statusSel.addEventListener('change', function () {
      fetch('/lab/api/intel/iocs/' + ioc.ioc_id, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({ status: statusSel.value })
      })
        .then(function (res) { return res.json(); })
        .then(function (body) {
          if (!body.success) { throw (body.error || {}); }
          toast('Status updated', 'Indicator marked ' + statusSel.value + '.', 'info');
          ioc.status = statusSel.value;
          load(true);
        })
        .catch(function (err) {
          toast('Update failed', err.message || 'Status could not be set.', 'error');
        });
    });

    var addBtn = document.getElementById('ioc-add-btn');
    var addInput = document.getElementById('ioc-add-case');
    addBtn.addEventListener('click', function () {
      var ref = (addInput.value || '').trim();
      if (!ref) { toast('Case required', 'Enter a KAV-CASE-… reference.', 'error'); return; }
      fetch('/lab/api/intel/iocs/' + ioc.ioc_id + '/cases', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({ case_ref: ref })
      })
        .then(function (res) { return res.json(); })
        .then(function (body) {
          if (!body.success) { throw (body.error || {}); }
          toast('Linked', 'Indicator linked to ' + ref + '.', 'info');
          openDetail(ioc.ioc_id);
          load(true);
        })
        .catch(function (err) {
          toast('Link failed', err.message || 'Indicator could not be linked.', 'error');
        });
    });

    var copyBtn = els.modalBody.querySelector('[data-act="copy"]');
    if (copyBtn) {
      copyBtn.addEventListener('click', function () { copyValue(ioc.value, { stopPropagation: function () {} }); });
    }
    var analyzeBtn = els.modalBody.querySelector('[data-act="analyze"]');
    if (analyzeBtn) {
      analyzeBtn.addEventListener('click', function () {
        location.href = '/lab/analysis?q=' + encodeURIComponent(ioc.value);
      });
    }
    Array.prototype.forEach.call(
      els.modalBody.querySelectorAll('tr.is-clickable'),
      function (tr) {
        tr.addEventListener('click', function () {
          location.href = tr.getAttribute('data-href');
        });
      });
  }

  function renderRows(items) {
    if (!items.length) {
      var hasFilter = (els.search.value.trim()) || els.type.value ||
        els.status.value || (els.caseRef.value.trim());
      var empty = window.LAB.emptyState(
        hasFilter ? '?' : '•',
        hasFilter ? 'NO MATCHING INDICATORS' : 'NO INDICATORS OBSERVED',
        hasFilter
          ? 'No indicator matches the current filter.'
          : 'No indicators have been observed yet. Rescan the vault to index '
            + 'the values present in case and evidence records.',
        hasFilter
          ? { label: 'CLEAR FILTERS', onClick: clearFilters }
          : { label: 'RESCAN VAULT', onClick: function () { syncVault(); } }
      );
      els.body.innerHTML = '';
      els.body.appendChild(empty);
      return;
    }

    var rowsHtml = items.map(function (i) {
      var caseLabel = i.case_count
        ? '<a class="lab-link lab-mono lab-xs" href="/lab/intel/iocs?case=' +
          encodeURIComponent(i.related_cases[0]) + '">' + esc(i.related_cases[0]) +
          (i.case_count > 1 ? ' +' + (i.case_count - 1) : '') + '</a>'
        : '<span class="lab-xs lab-dim">unlinked</span>';
      return '<tr class="is-clickable" data-id="' + i.ioc_id + '">' +
        '<td>' + typeBadge(i.ioc_type) + '</td>' +
        '<td><span class="lab-mono lab-strong" style="word-break:break-all;">' +
          esc(i.value) + '</span>' +
          '<div class="lab-xs lab-dim" style="margin-top:3px;">' +
          esc(fmtTs(i.last_seen)) + '</div></td>' +
        '<td>' + statusBadge(i.status) + '</td>' +
        '<td>' + sevBadge(i.derived_severity) + '</td>' +
        '<td>' + caseLabel + '</td>' +
        '<td><span class="lab-xs lab-dim">' + (i.evidence_count || 0) + '</span></td>' +
        '<td><button class="lab-btn lab-btn-xs" data-copy="' + esc(i.value) +
          '">COPY</button> <button class="lab-btn lab-btn-xs" data-analyze="' +
          esc(i.value) + '">ANALYZE</button></td>' +
        '</tr>';
    }).join('');

    els.body.innerHTML =
      '<div class="lab-table-wrap"><table class="lab-table">' +
      '<thead><tr><th scope="col">Type</th><th scope="col">Value</th>' +
      '<th scope="col">Status</th><th scope="col">Severity</th>' +
      '<th scope="col">Cases</th><th scope="col">Evidence</th>' +
      '<th scope="col">Actions</th></tr></thead><tbody>' + rowsHtml +
      '</tbody></table></div>';

    Array.prototype.forEach.call(
      els.body.querySelectorAll('tr.is-clickable'),
      function (tr) {
        tr.addEventListener('click', function () {
          openDetail(tr.getAttribute('data-id'));
        });
      });
    Array.prototype.forEach.call(
      els.body.querySelectorAll('[data-copy]'),
      function (btn) {
        btn.addEventListener('click', function (e) {
          copyValue(btn.getAttribute('data-copy'), e);
        });
      });
    Array.prototype.forEach.call(
      els.body.querySelectorAll('[data-analyze]'),
      function (btn) {
        btn.addEventListener('click', function (e) {
          analyzeValue(btn.getAttribute('data-analyze'), e);
        });
      });
  }

  function clearFilters() {
    els.search.value = '';
    els.type.value = '';
    els.status.value = '';
    els.caseRef.value = '';
    load();
  }

  function load(silent) {
    if (!silent) { els.foot.textContent = 'Retrieving indicators…'; }
    fetch('/lab/api/intel/iocs?' + buildQuery(), {
      headers: { 'Accept': 'application/json' }, credentials: 'same-origin'
    })
      .then(function (res) { return res.json(); })
      .then(function (body) {
        if (!body.success) { throw (body.error || {}); }
        renderRows(body.data.items);
        els.total.textContent = body.data.total + ' indicator(s)';
        els.foot.textContent = 'IOC ledger current as of ' + fmtTs(new Date().toISOString());
      })
      .catch(function (err) {
        els.body.innerHTML = '';
        els.total.textContent = '—';
        els.foot.textContent = (err.message || 'Indicators could not be retrieved.') +
          ' The vault may be empty; rescan to index observed values.';
      });
  }

  function syncVault() {
    var btn = els.sync;
    btn.disabled = true;
    btn.textContent = 'SCANNING…';
    fetch('/lab/api/intel/sync', {
      method: 'POST', headers: { 'Accept': 'application/json' },
      credentials: 'same-origin'
    })
      .then(function (res) { return res.json(); })
      .then(function (body) {
        if (!body.success) { throw (body.error || {}); }
        toast('Vault rescanned',
          body.data.created + ' new indicator(s), ' + body.data.observations +
          ' observations indexed.', 'info');
        load();
      })
      .catch(function (err) {
        toast('Sync failed', err.message || 'Vault could not be rescanned.', 'error');
      })
      .finally(function () {
        btn.disabled = false;
        btn.textContent = '⟳ RESCAN VAULT';
      });
  }

  function wire() {
    els.clear.addEventListener('click', function () { clearFilters(); });
    els.sync.addEventListener('click', function () { syncVault(); });
    els.modalX.addEventListener('click', function () { closeModal(); });
    els.modal.addEventListener('click', function (e) {
      if (e.target === els.modal) { closeModal(); }
    });
    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape' && !els.modal.hidden) { closeModal(); }
    });

    function schedule() {
      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(function () { load(); }, 280);
    }
    [els.search, els.type, els.status, els.caseRef].forEach(function (el) {
      el.addEventListener('input', schedule);
      if (el.tagName === 'SELECT') { el.addEventListener('change', schedule); }
    });

    var params = new URLSearchParams(location.search);
    if (params.get('case')) { els.caseRef.value = params.get('case'); }
  }

  wire();
  load();
})();
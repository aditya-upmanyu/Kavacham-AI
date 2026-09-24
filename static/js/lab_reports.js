/* ====================================================================
   KAVACHAM LAB — Investigation Reports (Phase 10/11, Sections 42/69/BF)
   Reports center: list + generate. Report document: renders the
   persisted BF 15-section content, with PDF (print), JSON and IOC CSV.
   Everything rendered comes from stored records via the backend.
   ==================================================================== */
(function () {
  'use strict';

  var REPORT_REF = window.__LAB_REPORT_REF__ || '';

  /* ---------------- reports center ---------------- */
  var listBody = document.getElementById('reports-list-body');
  var listFoot = document.getElementById('reports-list-foot');
  var listTs = document.getElementById('reports-ts');
  var genPanel = document.getElementById('reports-generate');
  var caseSel = document.getElementById('reports-case');
  var submitBtn = document.getElementById('reports-submit');
  var statusEl = document.getElementById('reports-generate-status');

  function caseOptions() {
    fetch('/lab/api/cases?limit=200', { headers: { 'Accept': 'application/json' } })
      .then(function (r) { return r.json(); })
      .then(function (b) {
        if (!b || !b.data || !b.data.items) return;
        caseSel.innerHTML = '<option value="">Select a case…</option>' +
          b.data.items.map(function (c) {
            return '<option value="' + LAB.esc(c.case_ref) + '">' +
              LAB.esc(c.case_ref) + ' — ' + LAB.esc(c.title || '') + '</option>';
          }).join('');
        caseSel.disabled = false;
      })
      .catch(function () { /* leave disabled; user can retry by reopening */ });
  }

  function toggleGenerate(open) {
    if (!genPanel) return;
    genPanel.hidden = !open;
    if (open) {
      caseOptions();
      caseSel.disabled = true;
    }
  }

  function refresh() {
    fetch('/lab/api/reports', { headers: { 'Accept': 'application/json' } })
      .then(function (r) { return r.json(); })
      .then(function (b) {
        if (!b || b.success !== true || !b.data) {
          LAB.renderError(listBody, (b && b.error && b.error.code) || 'REPORTS_UNAVAILABLE',
            (b && b.error && b.error.message) || 'Reports could not be listed.');
          if (listFoot) listFoot.textContent = '';
          return;
        }
        var items = b.data.items || [];
        if (listTs) listTs.textContent = items.length + ' report(s)';
        if (!items.length) {
          listBody.innerHTML = '';
          listBody.appendChild(LAB.emptyState('0', 'NO REPORTS GENERATED',
            'Generate a report to build the BF 15-section investigation document.'));
          if (listFoot) listFoot.textContent = '';
          return;
        }
        var html = '<div class="lab-table-wrap"><table class="lab-table"><thead><tr>' +
          '<th scope="col">Report</th><th scope="col">Case</th><th scope="col">Format</th>' +
          '<th scope="col">Status</th><th scope="col">Generated</th><th scope="col"></th></tr></thead><tbody>';
        items.forEach(function (r) {
          html += '<tr>' +
            '<td class="lab-mono lab-strong">' + LAB.esc(r.report_ref) + '</td>' +
            '<td>' + LAB.esc(r.case_ref) + '</td>' +
            '<td class="lab-mono">' + LAB.esc(r.format) + '</td>' +
            '<td>' + LAB.esc(r.status) + '</td>' +
            '<td class="lab-mono">' + (LAB.fmtTs(r.created_at) || r.created_at) + '</td>' +
            '<td><a class="lab-link" href="/lab/reports/' + encodeURIComponent(r.report_ref) + '">Open</a></td>' +
            '</tr>';
        });
        html += '</tbody></table></div>';
        listBody.innerHTML = html;
        if (listFoot) listFoot.textContent = '';
      })
      .catch(function () {
        LAB.renderError(listBody, 'REPORTS_UNAVAILABLE', 'Reports could not be listed.', {
          label: 'Retry', onClick: refresh
        });
        if (listFoot) listFoot.textContent = '';
      });
  }

  function generate() {
    var caseRef = caseSel.value;
    if (!caseRef) return;
    submitBtn.disabled = true;
    if (statusEl) statusEl.textContent = 'Generating…';
    fetch('/lab/api/reports', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
      body: JSON.stringify({ case_ref: caseRef })
    })
      .then(function (r) { return r.json(); })
      .then(function (b) {
        if (!b || b.success !== true || !b.data) {
          var err = b && b.error ? b.error : { code: 'GENERATION_FAILED', message: 'Report generation failed.' };
          LAB.toast('ERROR', err.code + ' — ' + err.message, 'error');
          if (statusEl) statusEl.textContent = '';
          return;
        }
        LAB.toast('REPORT GENERATED', b.data.report_ref, 'success');
        toggleGenerate(false);
        refresh();
        var doc = document.createElement('a');
        doc.href = '/lab/reports/' + encodeURIComponent(b.data.report_ref);
        doc.target = '_blank';
        doc.click();
      })
      .catch(function () {
        LAB.toast('ERROR', 'Report generation failed.', 'error');
        if (statusEl) statusEl.textContent = '';
      })
      .finally(function () { submitBtn.disabled = true; });
  }

  /* ---------------- report document ---------------- */
  var docEl = document.getElementById('report-doc');
  var docBody = document.getElementById('doc-body');
  var docCover = document.getElementById('doc-cover');
  var docLoading = document.getElementById('report-doc-loading');
  var docSubtitle = document.getElementById('report-doc-subtitle');

  function escTable(headers, rows, emptyText) {
    if (!rows || !rows.length) return '<p class="lab-dim lab-sm">' + (emptyText || 'No records.') + '</p>';
    var html = '<div class="lab-table-wrap"><table class="lab-table"><thead><tr>';
    headers.forEach(function (h) { html += '<th scope="col">' + LAB.esc(h) + '</th>'; });
    html += '</tr></thead><tbody>';
    rows.forEach(function (row) {
      html += '<tr>' + headers.map(function (h) {
        var v = row[h] !== undefined && row[h] !== null && row[h] !== '' ? String(row[h]) : '—';
        return '<td>' + LAB.esc(v) + '</td>';
      }).join('') + '</tr>';
    });
    html += '</tbody></table></div>';
    return html;
  }

  function docSection(title, inner) {
    return '<section class="lab-doc-section">' +
      '<h2>' + LAB.esc(title) + '</h2>' + inner + '</section>';
  }

  function renderDocument(c) {
    docSubtitle.textContent = c.case.case_ref + ' — ' + c.case.title +
      ' · generated by ' + c.report_metadata.engine + ' v' + c.report_metadata.engine_version;

    docCover.innerHTML =
      '<div class="lab-doc-cover-title">KAVACHAM LAB — INVESTIGATION REPORT</div>' +
      '<div class="lab-doc-cover-ref lab-mono">' + LAB.esc(c.report_ref || c.case.case_ref) + '</div>' +
      '<div class="lab-doc-cover-field"><span>Case</span><b class="lab-mono">' + LAB.esc(c.case.case_ref) + '</b></div>' +
      '<div class="lab-doc-cover-field"><span>Title</span><b>' + LAB.esc(c.case.title || '—') + '</b></div>' +
      '<div class="lab-doc-cover-field"><span>Type</span><b>' + LAB.esc(c.case.case_type) + '</b></div>' +
      '<div class="lab-doc-cover-field"><span>Status</span><b>' + LAB.esc(c.case.status) + '</b></div>' +
      '<div class="lab-doc-cover-field"><span>Priority</span><b>' + LAB.esc(c.case.priority) + '</b></div>' +
      '<div class="lab-doc-cover-field"><span>Opened</span><b class="lab-mono">' + LAB.esc(c.case.opened_at) + '</b></div>' +
      '<div class="lab-doc-cover-field"><span>Generated</span><b class="lab-mono">' + LAB.esc(c.report_metadata.generated_at) + '</b></div>';

    var html = '';

    // 1. Case Summary
    var cs = c.case_summary || {};
    html += docSection('Case Summary',
      escTable(['Case', 'Type', 'Status', 'Priority', 'Investigator', 'Updated'],
        [{ Case: cs.case_ref, Type: cs.case_type, Status: cs.status,
           Priority: cs.priority, Investigator: cs.assigned_investigator || '—',
           Updated: LAB.fmtTs(cs.created_at) || cs.created_at }]) +
      '<p class="lab-dim lab-sm">Counts — evidence: ' + cs.counts.evidence +
      ', analyses: ' + cs.counts.analyses + ', IOCs: ' + cs.counts.iocs +
      ', timeline events: ' + cs.counts.timeline_events + '.</p>');

    // 2. Executive Summary
    html += docSection('Executive Summary',
      '<ul>' + (c.executive_summary || []).map(function (l) {
        return '<li>' + LAB.esc(l) + '</li>';
      }).join('') + '</ul>');

    // 3. Incident Classification
    var cls = c.incident_classification || {};
    html += docSection('Incident Classification',
      '<p><b>' + LAB.esc(cls.primary || 'UNCLASSIFIED') + '</b></p>' +
      escTable(['Classification', 'Analyses', 'Max Score'], (cls.classifications || []).map(function (x) {
        return { Classification: x.classification, Analyses: x.count, 'Max Score': x.max_score };
      }), 'No non-clean classifications recorded.'));

    // 4. Evidence
    html += docSection('Evidence', escTable(
      ['Evidence', 'Type', 'Title', 'SHA-256', 'Acquired'],
      (c.evidence || []).map(function (e) {
        return { Evidence: e.evidence_ref, Type: e.evidence_type, Title: e.title || '—',
                 'SHA-256': e.sha256 || '—', Acquired: LAB.fmtTs(e.acquired_at) || e.acquired_at };
      }), 'No evidence recorded for this case.'));

    // 5. IOC Table
    html += docSection('IOC Table', escTable(
      ['Type', 'Value', 'Severity', 'Status', 'Source'],
      (c.ioc_table || []).map(function (i) {
        return { Type: i.ioc_type, Value: i.value, Severity: i.severity || '—',
                 Status: i.status || '—', Source: i.source || '—' };
      }), 'No indicators are linked to this case.'));

    // 6. Timeline
    html += docSection('Timeline', escTable(
      ['Occurred', 'Event', 'Title', 'Detail'],
      (c.timeline || []).map(function (t) {
        return { Occurred: t.occurred_at || '—', Event: t.event_type || '—',
                 Title: t.title || '—', Detail: t.detail || '' };
      }), 'No timeline events recorded.'));

    // 7. Technical Findings
    var tf = c.technical_findings || [];
    html += docSection('Technical Findings', tf.length
      ? tf.slice(0, 30).map(function (f) {
          return '<div class="lab-doc-finding"><b>' + LAB.esc(f.severity) + ' — ' +
            LAB.esc(f.title) + '</b><span class="lab-doc-finding-meta lab-mono">' +
            LAB.esc(f.analysis_ref) + (f.evidence_ref ? ' · ' + LAB.esc(f.evidence_ref) : '') +
            '</span><div>' + LAB.esc(f.detail || '') + '</div>' +
            '<span class="lab-dim lab-sm">Source: ' + LAB.esc(f.source || 'local') + '</span></div>';
        }).join('')
      : '<p class="lab-dim lab-sm">No analysis findings recorded.</p>');

    // 8. Threat Intelligence
    var ti = c.threat_intelligence || {};
    html += docSection('Threat Intelligence',
      escTable(['Provider', 'Status'], (ti.providers || []).map(function (p) {
        return { Provider: p.provider, Status: p.status };
      })) +
      '<p class="lab-dim lab-sm">' + LAB.esc(ti.note || '') + '</p>');

    // 9. ML Findings
    html += docSection('ML Findings', escTable(
      ['Analysis', 'Type', 'Verdict', 'Score', 'Confidence', 'Engine', 'Evidence'],
      (c.ml_findings || []).map(function (m) {
        return { Analysis: m.analysis_ref, Type: m.analysis_type, Verdict: m.verdict || '—',
                 Score: m.risk_score, Confidence: m.confidence === null ? '—' : m.confidence,
                 Engine: m.engine_version || '—', Evidence: m.evidence_ref || '—' };
      }), 'No analyses recorded.'));

    // 10. Correlation
    var corr = c.correlation || {};
    var corrRows = Array.isArray(corr) ? corr : (corr.correlations || []);
    html += docSection('Cross-Case Correlation', escTable(
      ['IOC', 'Type', 'Related Cases'],
      corrRows.map(function (x) {
        return { IOC: x.value || x.ioc_id, Type: x.ioc_type || '—',
                 'Related Cases': x.case_count !== undefined ? x.case_count : (x.related_cases || []).length };
      }), 'No cross-case correlation for this case\u2019s indicators.'));

    // 11. Risk Assessment
    var ra = c.risk_assessment || {};
    html += docSection('Risk Assessment',
      '<p><span class="lab-doc-score">' + LAB.esc(String(ra.risk_score)) + '</span> ' +
      '<b>' + LAB.esc(ra.risk_level) + '</b>' +
      (ra.primary_classification ? ' · ' + LAB.esc(ra.primary_classification) : '') + '</p>' +
      '<p class="lab-dim lab-sm">' + (ra.explanations || []).join('<br/>') + '</p>' +
      escTable(['Component', 'Value'], [
        { Component: 'Highest analysis', Value: ra.components.highest },
        { Component: 'Mean analysis', Value: ra.components.mean },
        { Component: 'Verified IOC', Value: ra.components.verified_count },
        { Component: 'Observed IOC', Value: ra.components.observed_count },
      ]));

    // 12. Limitations
    html += docSection('Limitations',
      '<ul>' + (c.limitations || []).map(function (l) {
        return '<li>' + LAB.esc(l) + '</li>';
      }).join('') + '</ul>');

    // 13. Defensive Recommendations
    html += docSection('Defensive Recommendations',
      '<ol>' + (c.defensive_recommendations || []).map(function (r) {
        return '<li>' + LAB.esc(r) + '</li>';
      }).join('') + '</ol>');

    // 14. Evidence Manifest (BG)
    html += docSection('Evidence Manifest', escTable(
      ['Export', 'Evidence', 'Analysis', 'SHA-256', 'Acquired', 'Analysed', 'Engine', 'Result'],
      (c.evidence_manifest || []).map(function (m) {
        return { Export: m.export_id || '—', Evidence: m.evidence_id || '—',
                 Analysis: m.analysis_id || '—', 'SHA-256': m.sha256 || '—',
                 Acquired: m.acquisition_time || '—', Analysed: m.analysis_time || '—',
                 Engine: m.engine || '—', Result: m.result || '—' };
      }), 'No analysis records to manifest.'));

    // 15. Report Metadata
    var rm = c.report_metadata || {};
    html += docSection('Report Metadata',
      '<p class="lab-dim lab-sm">Engine <b class="lab-mono">' + LAB.esc(rm.engine) + '</b> v' +
      LAB.esc(rm.engine_version) + ' · generated ' + LAB.esc(rm.generated_at) +
      ' · sections: ' + LAB.esc((rm.sections || []).join(', ')) + '.</p>');

    docBody.innerHTML = html;
    if (docLoading) docLoading.hidden = true;
    docEl.hidden = false;
  }

  function loadDocument() {
    fetch('/lab/api/reports/' + encodeURIComponent(REPORT_REF),
      { headers: { 'Accept': 'application/json' } })
      .then(function (r) { return r.json(); })
      .then(function (b) {
        if (!b || b.success !== true || !b.data) {
          var err = b && b.error ? b.error : { code: 'REPORT_UNAVAILABLE', message: 'Report unavailable.' };
          LAB.renderError(document.getElementById('report-doc-error'), err.code, err.message);
          if (docLoading) docLoading.hidden = true;
          return;
        }
        if (!b.data.content || b.data.content_available !== true) {
          LAB.renderError(document.getElementById('report-doc-error'),
            'REPORT_CONTENT_UNAVAILABLE', 'The stored report content could not be read.');
          if (docLoading) docLoading.hidden = true;
          return;
        }
        renderDocument(b.data.content);
      })
      .catch(function () {
        LAB.renderError(document.getElementById('report-doc-error'),
          'REPORT_UNAVAILABLE', 'The report could not be loaded.', {
            label: 'Retry', onClick: loadDocument
          });
        if (docLoading) docLoading.hidden = true;
      });
  }

  /* ---------------- bindings ---------------- */
  if (genPanel) {
    var newBtn = document.getElementById('reports-new');
    if (newBtn) newBtn.addEventListener('click', function () { toggleGenerate(!genPanel.hidden); });
    var cancelBtn = document.getElementById('reports-cancel');
    if (cancelBtn) cancelBtn.addEventListener('click', function () { toggleGenerate(false); });
    if (caseSel) caseSel.addEventListener('change', function () { submitBtn.disabled = !caseSel.value; });
    if (submitBtn) submitBtn.addEventListener('click', generate);
    toggleGenerate(false);
    refresh();
  }

  if (docEl) {
    var printBtn = document.getElementById('report-print');
    if (printBtn) printBtn.addEventListener('click', function () { window.print(); });
    var jsonBtn = document.getElementById('report-json');
    if (jsonBtn) jsonBtn.addEventListener('click', function () {
      window.open('/lab/api/reports/' + encodeURIComponent(REPORT_REF), '_blank');
    });
    var csvBtn = document.getElementById('report-csv');
    if (csvBtn) csvBtn.addEventListener('click', function () {
      window.location.href = '/lab/api/reports/' + encodeURIComponent(REPORT_REF) + '/csv';
    });
    loadDocument();
  }
})();
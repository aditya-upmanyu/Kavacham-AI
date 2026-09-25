/* ====================================================================
   KAVACHAM LAB — CASE COMMAND VIEW (Phase 5, Section 18)
   Loads one case via GET /lab/api/cases/:ref and renders header,
   tabs, timeline, IOC, notes, with server-side validated mutations.
   ==================================================================== */
(function () {
  'use strict';

  var esc = window.LAB.esc;
  var fmtTs = window.LAB.fmtTs;
  var REF = window.__LAB_CASE_REF__;

  var view = document.getElementById('case-view');
  var loading = document.getElementById('case-loading');
  var errorHost = document.getElementById('case-error');
  var current = null;

  var STATUS_BADGE = {
    'OPEN': 'lab-badge-blue',
    'UNDER INVESTIGATION': 'lab-badge-amber',
    'REVIEW': 'lab-badge-amber',
    'RESOLVED': 'lab-badge-green',
    'ARCHIVED': 'lab-badge-gray'
  };
  var PRIORITY_BADGE = {
    'CRITICAL': 'lab-badge-red', 'HIGH': 'lab-badge-red',
    'MEDIUM': 'lab-badge-amber', 'LOW': 'lab-badge-gray'
  };
  var RISK_BADGE = { 'HIGH': 'lab-badge-red', 'MEDIUM': 'lab-badge-amber',
                     'LOW': 'lab-badge-green' };

  function badge(text, cls) {
    return '<span class="lab-badge ' + (cls || '') + '">' + esc(text) + '</span>';
  }

  /* ---------------- Load ---------------- */
  function load() {
    loading.hidden = false;
    view.hidden = true;
    errorHost.hidden = true;

    fetch('/lab/api/cases/' + encodeURIComponent(REF), {
      headers: { 'Accept': 'application/json' }, credentials: 'same-origin'
    })
      .then(function (res) {
        return res.json().then(function (body) {
          if (!res.ok || body.success !== true) {
            var e = (body && body.error) || {};
            throw { code: e.code || 'REQUEST_FAILED',
                    message: e.message || 'The case record could not be retrieved.' };
          }
          return body.data.case;
        });
      })
      .then(function (c) {
        current = c;
        render(c);
        loading.hidden = true;
        errorHost.hidden = true;
        view.hidden = false;
      })
      .catch(function (err) {
        loading.hidden = true;
        errorHost.hidden = false;
        window.LAB.renderError(errorHost,
          (err && err.code) || 'NETWORK_ERROR',
          (err && err.message) || 'The case record could not be retrieved.',
          { label: 'RETRY', onClick: load });
      });
  }

  /* ---------------- Header ---------------- */
  function render(c) {
    document.title = c.case_ref + ' — KAVACHAM LAB';
    document.getElementById('cv-ref').textContent = c.case_ref;
    document.getElementById('cv-type').textContent = c.case_type;
    document.getElementById('cv-status').innerHTML =
      badge(c.status, STATUS_BADGE[c.status]);
    document.getElementById('cv-priority').innerHTML =
      badge('PRIORITY ' + c.priority, PRIORITY_BADGE[c.priority]);
    document.getElementById('cv-risk').innerHTML = c.risk_level
      ? badge('RISK ' + c.risk_level, RISK_BADGE[c.risk_level] || 'lab-badge-gray')
      : '';
    document.getElementById('cv-title').textContent = c.title;
    var desc = document.getElementById('cv-desc');
    if (c.description) { desc.textContent = c.description; desc.hidden = false; }
    else desc.hidden = true;

    document.getElementById('cv-created').textContent = fmtTs(c.created_at) + ' UTC';
    document.getElementById('cv-updated').textContent = fmtTs(c.updated_at) + ' UTC';
    document.getElementById('cv-assignee').textContent =
      c.assigned_investigator || 'Unassigned';

    /* Counts strip — all real numbers from the API */
    document.getElementById('cv-counts').innerHTML = [
      ['EVIDENCE', c.counts.evidence],
      ['INDICATORS', c.counts.iocs],
      ['ANALYSES', c.counts.analyses],
      ['NOTES', c.counts.notes],
      ['TIMELINE EVENTS', c.counts.timeline_events],
      ['REPORTS', c.reports ? c.reports.length : 0]
    ].map(function (p) {
      return '<div class="lab-strip-item"><span class="lab-label">' + esc(p[0]) +
        '</span><span class="lab-strip-value">' + p[1] + '</span></div>';
    }).join('');

    renderStatusSelect(c);
    renderMeta(c);
    renderEvidence(c);
    renderTimeline(c);
    renderIocs(c);
    renderEntitiesFromApi(c.case_ref);
    renderChainFromApi(c.case_ref);
    renderAnalyses(c);
    renderNotes(c);
    renderReports(c);
  }

  function renderStatusSelect(c) {
    var sel = document.getElementById('cv-status-select');
    sel.innerHTML = '';
    var currentOpt = document.createElement('option');
    currentOpt.value = c.status;
    currentOpt.textContent = c.status + ' (CURRENT)';
    currentOpt.disabled = true;
    currentOpt.selected = true;
    sel.appendChild(currentOpt);

    if (c.allowed_transitions.length) {
      var grp = document.createElement('optgroup');
      grp.label = 'ALLOWED TRANSITIONS';
      c.allowed_transitions.forEach(function (s) {
        var o = document.createElement('option');
        o.value = s;
        o.textContent = '→ ' + s;
        grp.appendChild(o);
      });
      sel.appendChild(grp);
    } else {
      var none = document.createElement('option');
      none.disabled = true;
      none.textContent = 'NO TRANSITIONS AVAILABLE';
      sel.appendChild(none);
    }
    sel.disabled = !c.allowed_transitions.length;
  }

  function renderMeta(c) {
    var rows = [
      ['CASE ID', c.case_ref, true],
      ['TYPE', c.case_type, false],
      ['STATUS', c.status, false],
      ['PRIORITY', c.priority, false],
      ['RISK LEVEL', c.risk_level || 'Not computed', false],
      ['INVESTIGATOR', c.assigned_investigator || 'Unassigned', false],
      ['OPENED BY', c.created_by || '—', false],
      ['OPENED', fmtTs(c.created_at) + ' UTC', true],
      ['LAST UPDATED', fmtTs(c.updated_at) + ' UTC', true],
      ['CLOSED', c.closed_at ? fmtTs(c.closed_at) + ' UTC' : '—', true]
    ];
    document.getElementById('cv-meta').innerHTML = rows.map(function (r) {
      return '<dt>' + esc(r[0]) + '</dt><dd' + (r[2] ? ' class="lab-mono"' : '') +
        '>' + esc(String(r[1])) + '</dd>';
    }).join('');
  }

  function renderEvidence(c) {
    var host = document.getElementById('cv-evidence');
    if (!c.evidence.length) {
      host.innerHTML = '';
      host.appendChild(window.LAB.emptyState('—', 'NO EVIDENCE',
        'No evidence has been attached to this case.', null));
      return;
    }
    host.innerHTML = '<div class="lab-table-wrap"><table class="lab-table">' +
      '<thead><tr><th scope="col">Evidence ID</th><th scope="col">Type</th>' +
      '<th scope="col">Title</th><th scope="col">SHA-256</th>' +
      '<th scope="col">Integrity</th><th scope="col">Acquired</th></tr></thead><tbody>' +
      c.evidence.map(function (e) {
        return '<tr><td class="lab-mono lab-strong">' + esc(e.evidence_ref) + '</td>' +
          '<td>' + badge(e.evidence_type) + '</td>' +
          '<td>' + esc(e.title) + '</td>' +
          '<td class="lab-mono lab-xs">' + (e.sha256 ? esc(e.sha256.slice(0, 24)) + '…' : '—') + '</td>' +
          '<td>' + badge(e.integrity_state, e.integrity_state === 'VERIFIED'
            ? 'lab-badge-green' : 'lab-badge-amber') + '</td>' +
          '<td class="lab-mono lab-xs">' + esc(fmtTs(e.acquired_at)) + '</td></tr>';
      }).join('') + '</tbody></table></div>';
  }

  function renderTimeline(c) {
    var host = document.getElementById('cv-timeline');
    if (!c.timeline.length) {
      host.innerHTML = '';
      host.appendChild(window.LAB.emptyState('—', 'NO TIMELINE EVENTS',
        'This case has no recorded events.', null));
      return;
    }
    host.innerHTML = '<ol class="lab-timeline">' + c.timeline.map(function (t) {
      return '<li class="lab-timeline-item">' +
        '<div class="lab-timeline-marker" aria-hidden="true"></div>' +
        '<div class="lab-timeline-body">' +
        '<div class="lab-row tight">' +
        '<span class="lab-badge lab-badge-blue">' + esc(t.event_type) + '</span>' +
        '<span class="lab-mono lab-xs lab-dim">' + esc(fmtTs(t.occurred_at)) + ' UTC</span>' +
        '</div>' +
        '<div class="lab-strong" style="margin-top:5px;">' + esc(t.title) + '</div>' +
        (t.detail ? '<div class="lab-xs lab-dim" style="margin-top:3px;">' + esc(t.detail) + '</div>' : '') +
        '<div class="lab-provenance" style="margin-top:6px;">' +
        esc(t.source || 'Analyst Input') + ' · ' + esc(t.actor || 'analyst') + '</div>' +
        '</div></li>';
    }).join('') + '</ol>';
  }

  function renderIocs(c) {
    var host = document.getElementById('cv-iocs');
    if (!c.iocs.length) {
      host.innerHTML = '';
      host.appendChild(window.LAB.emptyState('—', 'NO INDICATORS',
        'No indicators of compromise are linked to this case.', null));
      return;
    }
    host.innerHTML = '<div class="lab-table-wrap"><table class="lab-table">' +
      '<thead><tr><th scope="col">Type</th><th scope="col">Value</th>' +
      '<th scope="col">Severity</th><th scope="col">Source</th>' +
      '<th scope="col">First Seen</th></tr></thead><tbody>' +
      c.iocs.map(function (i) {
        var sevBadge = i.severity === 'HIGH' ? 'lab-badge-red'
          : i.severity === 'MEDIUM' ? 'lab-badge-amber'
          : i.severity === 'LOW' ? 'lab-badge-green' : 'lab-badge-gray';
        return '<tr><td>' + badge(i.ioc_type, 'lab-badge-blue') + '</td>' +
          '<td class="lab-mono lab-xs" style="word-break:break-all;">' + esc(i.value) + '</td>' +
          '<td>' + badge(i.severity, sevBadge) + '</td>' +
          '<td class="lab-xs">' + esc(i.source) + '</td>' +
          '<td class="lab-mono lab-xs">' + esc(fmtTs(i.first_seen)) + '</td></tr>';
      }).join('') + '</tbody></table></div>';
  }

  function renderChainFromApi(ref) {
    var host = document.getElementById('cv-chain');
    fetch('/lab/api/intel/attack-chain?case=' + encodeURIComponent(ref), {
      headers: { 'Accept': 'application/json' }, credentials: 'same-origin'
    })
      .then(function (res) {
        return res.json().then(function (body) {
          if (!res.ok || body.success !== true) {
            var e = (body && body.error) || {};
            throw { message: e.message || 'The attack chain could not be derived.' };
          }
          return body.data;
        });
      })
      .then(function (d) {
        var stages = d.chain || [];
        if (!stages.length) {
          host.innerHTML = '';
          host.appendChild(window.LAB.emptyState('—', 'INSUFFICIENT EVIDENCE',
            d.note || 'Chains are only rendered from relationships that existing evidence and analysis actually support.',
            null));
          return;
        }
        host.innerHTML = '<div class="lab-panel-body"><ol class="lab-timeline">' +
          stages.map(function (s, i) {
            var evs = (s.evidence_refs || []).map(function (r) {
              return '<span class="lab-mono lab-xs">' + esc(r) + '</span>';
            }).join(' ');
            var ans = (s.analysis_refs || []).map(function (r) {
              return '<span class="lab-mono lab-xs">' + esc(r) + '</span>';
            }).join(' ');
            return '<li class="lab-timeline-item">' +
              '<div class="lab-timeline-marker" aria-hidden="true"></div>' +
              '<div class="lab-timeline-body">' +
              '<div class="lab-row tight">' +
              '<span class="lab-badge lab-badge-blue">STAGE ' + (i + 1) + '</span>' +
              '<span class="lab-strong">' + esc(s.label || 'STAGE') + '</span>' +
              (s.risk != null ? '<span class="lab-mono lab-xs lab-dim">RISK ' +
                esc(String(s.risk)) + '</span>' : '') +
              '</div>' +
              (s.kind ? '<div class="lab-xs lab-dim" style="margin-top:4px;">' +
                esc(String(s.kind)) + '</div>' : '') +
              (evs ? '<div class="lab-xs lab-dim" style="margin-top:4px;">EVIDENCE: ' +
                evs + '</div>' : '') +
              (ans ? '<div class="lab-xs lab-dim" style="margin-top:4px;">ANALYSIS: ' +
                ans + '</div>' : '') +
              '</div></li>';
          }).join('') + '</ol>' +
          (d.note ? '<p class="lab-xs lab-dim">' + esc(d.note) + '</p>' : '') + '</div>';
      })
      .catch(function (err) {
        host.innerHTML = '';
        host.appendChild(window.LAB.emptyState('!', 'CHAIN UNAVAILABLE',
          (err && err.message) || 'The attack chain could not be derived.', null));
      });
  }

  function renderEntitiesFromApi(ref) {
    var host = document.getElementById('cv-entities');
    fetch('/lab/api/intel/graph?case=' + encodeURIComponent(ref), {
      headers: { 'Accept': 'application/json' }, credentials: 'same-origin'
    })
      .then(function (res) {
        return res.json().then(function (body) {
          if (!res.ok || body.success !== true) {
            var e = (body && body.error) || {};
            throw { message: e.message || 'Entities could not be loaded.' };
          }
          return body.data.graph || {};
        });
      })
      .then(function (g) {
        var nodes = (g.nodes || []).filter(function (n) {
          return n.type !== 'CASE' && n.type !== 'EVIDENCE';
        });
        if (!nodes.length) {
          host.innerHTML = '';
          host.appendChild(window.LAB.emptyState('—', 'NO ENTITIES',
            'No sender entities or linked indicators exist for this case yet.', null));
          return;
        }
        host.innerHTML = '<div class="lab-table-wrap"><table class="lab-table">' +
          '<thead><tr><th scope="col">Type</th><th scope="col">Value</th>' +
          '<th scope="col">Status</th><th scope="col">Related Evidence</th>' +
          '<th scope="col">Related Cases</th></tr></thead><tbody>' +
          nodes.map(function (n) {
            var rel_e = (n.related_evidence || []).map(function (r) {
              return '<span class="lab-mono lab-xs">' + esc(r) + '</span>';
            }).join(' ');
            var rel_c = (n.related_cases || []).map(function (r) {
              return '<span class="lab-mono lab-xs">' + esc(r) + '</span>';
            }).join(' ');
            return '<tr><td>' + badge(n.type, 'lab-badge-blue') + '</td>' +
              '<td class="lab-mono lab-xs" style="word-break:break-all;">' + esc(n.value) + '</td>' +
              '<td class="lab-xs">' + esc(n.status || '—') + '</td>' +
              '<td class="lab-xs">' + (rel_e || '—') + '</td>' +
              '<td class="lab-xs">' + (rel_c || '—') + '</td></tr>';
          }).join('') + '</tbody></table></div>';
      })
      .catch(function (err) {
        host.innerHTML = '';
        host.appendChild(window.LAB.emptyState('!', 'ENTITIES UNAVAILABLE',
          (err && err.message) || 'Entities could not be loaded.', null));
      });
  }

  function renderAnalyses(c) {
    var host = document.getElementById('cv-analyses');
    if (!c.analyses.length) {
      host.innerHTML = '';
      host.appendChild(window.LAB.emptyState('—', 'NO ANALYSIS RECORDS',
        'No analysis has been attached to this case yet.', null));
      return;
    }
    host.innerHTML = '<div class="lab-table-wrap"><table class="lab-table">' +
      '<thead><tr><th scope="col">Analysis ID</th><th scope="col">Type</th>' +
      '<th scope="col">Verdict</th><th scope="col">Risk</th>' +
      '<th scope="col">Confidence</th><th scope="col">Source</th>' +
      '<th scope="col">Created</th></tr></thead><tbody>' +
      c.analyses.map(function (a) {
        return '<tr><td class="lab-mono lab-strong">' + esc(a.analysis_ref) + '</td>' +
          '<td>' + badge(a.analysis_type) + '</td>' +
          '<td>' + (a.verdict ? badge(a.verdict) : '—') + '</td>' +
          '<td class="lab-mono">' + (a.risk_score == null ? '—' : esc(String(a.risk_score))) + '</td>' +
          '<td class="lab-mono">' + (a.confidence == null ? '—' : esc(String(a.confidence)) + '%') + '</td>' +
          '<td class="lab-xs">' + esc(a.source) + '</td>' +
          '<td class="lab-mono lab-xs">' + esc(fmtTs(a.created_at)) + '</td></tr>';
      }).join('') + '</tbody></table></div>';
  }

  function renderNotes(c) {
    var host = document.getElementById('cv-notes');
    if (!c.notes.length) {
      host.innerHTML = '';
      host.appendChild(window.LAB.emptyState('—', 'NO INVESTIGATION NOTES',
        'No notes have been recorded for this case.', null));
      return;
    }
    host.innerHTML = c.notes.map(function (n) {
      return '<div class="lab-note">' +
        '<div class="lab-row tight" style="margin-bottom:6px;">' +
        '<span class="lab-strong lab-xs">' + esc(n.author) + '</span>' +
        '<span class="lab-mono lab-xs lab-dim">' + esc(fmtTs(n.created_at)) + ' UTC</span>' +
        '</div>' +
        '<div class="lab-note-body">' + esc(n.body) + '</div></div>';
    }).join('');
  }

  function renderReports(c) {
    var host = document.getElementById('cv-reports');
    if (!c.reports.length) {
      host.innerHTML = '';
      host.appendChild(window.LAB.emptyState('—', 'NO REPORTS GENERATED',
        'No investigation report has been generated for this case.', null));
      return;
    }
    host.innerHTML = '<div class="lab-table-wrap"><table class="lab-table">' +
      '<thead><tr><th scope="col">Report ID</th><th scope="col">Title</th>' +
      '<th scope="col">Format</th><th scope="col">Status</th>' +
      '<th scope="col">Created</th></tr></thead><tbody>' +
      c.reports.map(function (r) {
        return '<tr><td class="lab-mono lab-strong">' + esc(r.report_ref) + '</td>' +
          '<td>' + esc(r.title) + '</td><td>' + badge(r.format) + '</td>' +
          '<td>' + badge(r.status, 'lab-badge-green') + '</td>' +
          '<td class="lab-mono lab-xs">' + esc(fmtTs(r.created_at)) + '</td></tr>';
      }).join('') + '</tbody></table></div>';
  }

  /* ---------------- Tabs ---------------- */
  document.getElementById('case-tabs').addEventListener('click', function (e) {
    var btn = e.target.closest('.lab-tab');
    if (!btn) return;
    var tab = btn.getAttribute('data-tab');
    Array.prototype.forEach.call(this.querySelectorAll('.lab-tab'), function (t) {
      var on = t === btn;
      t.classList.toggle('is-active', on);
      t.setAttribute('aria-selected', on ? 'true' : 'false');
    });
    Array.prototype.forEach.call(
      document.querySelectorAll('.lab-tab-panel'),
      function (p) {
        var on = p.getAttribute('data-panel') === tab;
        p.classList.toggle('is-active', on);
        p.hidden = !on;
      });
  });

  /* ---------------- Status transition (server-validated) ------------- */
  document.getElementById('cv-status-select').addEventListener('change', function () {
    var next = this.value;
    if (!next || !current || next === current.status) return;
    var prev = current.status;
    var sel = this;
    sel.disabled = true;

    fetch('/lab/api/cases/' + encodeURIComponent(REF), {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify({ status: next })
    })
      .then(function (res) {
        return res.json().then(function (body) {
          if (!res.ok || body.success !== true) {
            var e = (body && body.error) || {};
            throw { code: e.code || 'UPDATE_FAILED',
                    message: e.message || 'The status could not be changed.' };
          }
          return body.data.case;
        });
      })
      .then(function (c) {
        current = c;
        window.LAB.toast('Status changed', c.case_ref + ' → ' + c.status, 'success');
        render(c);
        window.LAB.refreshHeaderHealth();
      })
      .catch(function (err) {
        sel.value = prev;
        sel.disabled = false;
        window.LAB.toast('Status change refused',
          (err && err.message) || 'The transition was rejected.', 'error');
      });
  });

  /* ---------------- Notes ---------------- */
  document.getElementById('note-form').addEventListener('submit', function (e) {
    e.preventDefault();
    var body = document.getElementById('note-body');
    var errEl = document.getElementById('note-error');
    var text = body.value.trim();

    if (!text) {
      errEl.textContent = 'A note body is required.';
      errEl.hidden = false;
      return;
    }
    errEl.hidden = true;

    fetch('/lab/api/cases/' + encodeURIComponent(REF) + '/notes', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify({ body: text })
    })
      .then(function (res) {
        return res.json().then(function (body2) {
          if (!res.ok || body2.success !== true) {
            var er = (body2 && body2.error) || {};
            throw { code: er.code || 'NOTE_FAILED',
                    message: er.message || 'The note could not be saved.' };
          }
          return body2.data;
        });
      })
      .then(function () {
        body.value = '';
        window.LAB.toast('Note saved', 'Added to the case record and audit trail.', 'success');
        load();
      })
      .catch(function (err) {
        errEl.textContent = (err && err.message) || 'The note could not be saved.';
        errEl.hidden = false;
      });
  });

  /* ---------------- Quick actions ---------------- */
  document.getElementById('qa-copy').addEventListener('click', function () {
    var ref = current ? current.case_ref : REF;
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(ref).then(function () {
        window.LAB.toast('Copied', ref + ' copied to clipboard.', 'success');
      }, function () {
        window.LAB.toast('Copy unavailable', 'Clipboard access was denied.', 'warning');
      });
    } else {
      window.LAB.toast('Copy unavailable', 'Clipboard API not supported.', 'warning');
    }
  });

  document.getElementById('qa-audit').addEventListener('click', function () {
    /* Carry the case ref so the audit page can pre-filter. */
    sessionStorage.setItem('lab_audit_target', current ? current.case_ref : REF);
  });

  load();
})();

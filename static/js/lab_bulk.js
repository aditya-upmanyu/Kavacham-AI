/* ====================================================================
   KAVACHAM LAB — BULK IOC INVESTIGATION (Section AN)
   Paste text -> POST /lab/api/intel/bulk/preview (read-only counts) or
   POST /lab/api/intel/bulk/investigate (opens a real case). Pasted
   content is treated strictly as data. All rendering escaped.
   ==================================================================== */
(function () {
  'use strict';

  var esc = window.LAB && window.LAB.esc ? window.LAB.esc : function (s) { return String(s == null ? '' : s); };

  function $(id) { return document.getElementById(id); }

  var textEl = $('bulk-text');
  var bodyEl = $('bulk-body');
  var countEl = $('bulk-count');
  var footEl = $('bulk-foot');
  if (!textEl || !bodyEl) return;

  function post(url, payload) {
    return fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify(payload),
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

  function renderPreview(d) {
    var names = Object.keys(d.counts || {}).sort();
    if (!d.total) {
      bodyEl.innerHTML = '<div class="lab-panel-body">' +
        '<div class="lab-state"><div class="lab-state-title">NO INDICATORS FOUND</div>' +
        '<p class="lab-state-desc">The pasted text contains no recognizable IPs, domains, URLs, hashes or emails.</p></div></div>';
    } else {
      bodyEl.innerHTML = '<div class="lab-panel-body"><div class="lab-strip">' +
        names.map(function (t) {
          return '<div class="lab-strip-item"><span class="lab-label">' +
            esc(t) + '</span><span class="lab-strip-value">' + d.counts[t] + '</span></div>';
        }).join('') + '</div>' +
        '<div class="lab-table-wrap" style="margin-top:12px;"><table class="lab-table">' +
        '<thead><tr><th scope="col">Type</th><th scope="col">Value</th></tr></thead><tbody>' +
        (d.items || []).map(function (it) {
          return '<tr><td>' + esc(it.ioc_type) + '</td>' +
            '<td class="lab-mono lab-xs" style="word-break:break-all;">' + esc(it.value) + '</td></tr>';
        }).join('') + '</tbody></table></div></div>';
    }
    if (countEl) countEl.textContent = d.total + ' INDICATORS';
    if (footEl) {
      footEl.textContent = d.total + ' indicator(s) extracted' +
        (d.truncated_text ? ' · input truncated at 256 KB' : '') +
        (d.truncated_iocs ? ' · indicator list truncated at 500' : '');
    }
  }

  $('bulk-scan').addEventListener('click', function () {
    var btn = this;
    btn.disabled = true;
    post('/lab/api/intel/bulk/preview', { text: textEl.value })
      .then(renderPreview)
      .catch(function (err) {
        if (footEl) footEl.textContent = (err && err.message) || 'Scan failed.';
      })
      .then(function () { btn.disabled = false; });
  });

  $('bulk-investigate').addEventListener('click', function () {
    var btn = this;
    var text = textEl.value;
    if (!text.trim()) {
      if (footEl) footEl.textContent = 'Paste text before opening an investigation.';
      return;
    }
    btn.disabled = true;
    post('/lab/api/intel/bulk/investigate', { text: text })
      .then(function (d) {
        renderPreview(d);
        if (footEl) {
          footEl.innerHTML = '';
          var span = document.createElement('span');
          span.textContent = 'Case ' + d.case.case_ref + ' opened · ' +
            d.total + ' indicator(s) · ledger now holds ' +
            d.ledger.iocs_total + ' IOCs. ';
          var a = document.createElement('a');
          a.href = '/lab/cases/' + encodeURIComponent(d.case.case_ref);
          a.textContent = 'OPEN CASE →';
          footEl.appendChild(span);
          footEl.appendChild(a);
        }
      })
      .catch(function (err) {
        if (footEl) footEl.textContent = (err && err.message) || 'Investigation failed.';
      })
      .then(function () { btn.disabled = false; });
  });
})();

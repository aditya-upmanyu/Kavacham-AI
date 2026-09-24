/* ====================================================================
   KAVACHAM LAB — NEW INVESTIGATION WIZARD (Phase 5, Section 17)
   5 real steps. Validation runs client-side for UX only; the server
   re-validates every field (Section 56: never trust frontend validation).
   ==================================================================== */
(function () {
  'use strict';

  var esc = window.LAB.esc;
  var TOTAL = 5;
  var step = 1;

  var panes = document.querySelectorAll('.lab-wizard-pane');
  var stepEls = document.querySelectorAll('#wizard-steps .lab-progress-step');
  var btnBack = document.getElementById('w-back');
  var btnNext = document.getElementById('w-next');
  var btnSubmit = document.getElementById('w-submit');
  var stepLabel = document.getElementById('w-step-label');
  var form = document.getElementById('case-form');
  var errorHost = document.getElementById('create-error');

  var f = {
    title: document.getElementById('w-title'),
    type: document.getElementById('w-type'),
    priority: document.getElementById('w-priority'),
    desc: document.getElementById('w-desc'),
    evTitle: document.getElementById('w-evidence-title'),
    evNote: document.getElementById('w-evidence-note'),
    iocs: document.getElementById('w-iocs'),
    assignee: document.getElementById('w-assignee')
  };

  /* ---------------- Step navigation ---------------- */
  function showStep(n) {
    step = Math.max(1, Math.min(TOTAL, n));

    Array.prototype.forEach.call(panes, function (p) {
      var active = Number(p.getAttribute('data-pane')) === step;
      p.classList.toggle('is-active', active);
      p.hidden = !active;
    });

    Array.prototype.forEach.call(stepEls, function (s) {
      var idx = Number(s.getAttribute('data-step'));
      s.classList.toggle('is-active', idx === step);
      s.classList.toggle('is-done', idx < step);
      var dot = s.querySelector('.lab-step-dot');
      if (dot) dot.textContent = idx < step ? '✓' : String(idx);
    });

    btnBack.hidden = step === 1;
    btnNext.hidden = step === TOTAL;
    btnSubmit.hidden = step !== TOTAL;
    stepLabel.textContent = 'STEP ' + step + ' OF ' + TOTAL;

    if (step === TOTAL) buildConfirmation();
    if (step === 3) buildIocPreview();

    var focusable = panes[step - 1] && panes[step - 1].querySelector('input,select,textarea');
    if (focusable && step > 1) focusable.focus();
  }

  /* ---------------- Validation (UX layer only) ---------------- */
  function setError(id, msg) {
    var el = document.getElementById('err-' + id);
    if (!el) return;
    if (msg) {
      el.textContent = msg;
      el.hidden = false;
      var input = document.getElementById('w-' + id);
      if (input) input.style.borderColor = 'var(--lab-red)';
    } else {
      el.hidden = true;
      var i2 = document.getElementById('w-' + id);
      if (i2) i2.style.borderColor = '';
    }
  }

  function validateStep1() {
    var ok = true;
    var title = f.title.value.trim();
    if (!title) { setError('title', 'A case title is required.'); ok = false; }
    else if (title.length > 200) { setError('title', 'Title must be 200 characters or fewer.'); ok = false; }
    else setError('title', null);

    if (!f.type.value) { setError('type', 'Select a case type.'); ok = false; }
    else setError('type', null);
    return ok;
  }

  /* ---------------- IOC parsing (client preview only) ---------------- */
  function parseIocs() {
    return (f.iocs.value || '')
      .split(/\r?\n/)
      .map(function (s) { return s.trim(); })
      .filter(Boolean);
  }

  function classifyIoc(v) {
    var s = v.toLowerCase();
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(s)) return 'IP';
    if (/^https?:\/\//.test(s)) return 'URL';
    if (s.indexOf('@') !== -1 && s.indexOf(' ') === -1) return 'EMAIL';
    if (/^[a-f0-9]{32}$/.test(s)) return 'MD5';
    if (/^[a-f0-9]{40}$/.test(s)) return 'SHA1';
    if (/^[a-f0-9]{64}$/.test(s)) return 'SHA256';
    if (/^[a-z0-9.-]+\.[a-z]{2,}$/.test(s)) return 'DOMAIN';
    return 'OTHER';
  }

  function buildIocPreview() {
    var host = document.getElementById('ioc-preview');
    if (!host) return;
    var list = parseIocs();
    if (!list.length) { host.hidden = true; host.innerHTML = ''; return; }
    host.hidden = false;
    host.innerHTML = '<div class="lab-label" style="margin-bottom:6px;">PARSED INDICATORS (' +
      list.length + ')</div>' + list.map(function (v) {
        return '<div class="lab-ioc-chip"><span class="lab-badge lab-badge-blue">' +
          esc(classifyIoc(v)) + '</span><span class="lab-mono lab-xs">' + esc(v) +
          '</span></div>';
      }).join('');
  }

  /* ---------------- Confirmation summary (Section 17 step 5) -------- */
  function buildConfirmation() {
    var host = document.getElementById('confirm-summary');
    if (!host) return;
    var iocs = parseIocs();
    var rows = [
      ['TITLE', f.title.value.trim(), false],
      ['CASE TYPE', f.type.value, false],
      ['PRIORITY', f.priority.value, false],
      ['DESCRIPTION', f.desc.value.trim() || '—', false],
      ['INITIAL EVIDENCE', f.evTitle.value.trim() || 'None recorded', false],
      ['EVIDENCE NOTE', f.evNote.value.trim() || '—', false],
      ['INDICATORS', iocs.length ? iocs.length + ' line(s)' : 'None', false],
      ['INVESTIGATOR', f.assignee.value.trim() || 'Unassigned', false]
    ];
    host.innerHTML = rows.map(function (r) {
      return '<dt>' + esc(r[0]) + '</dt><dd>' + esc(String(r[1])) + '</dd>';
    }).join('') +
      '<dt>ON CREATION</dt><dd>Generate case ID · record timestamp · ' +
      'write audit event · initialize timeline · link indicators</dd>';
  }

  /* ---------------- Submission ---------------- */
  function collectPayload() {
    return {
      title: f.title.value.trim(),
      case_type: f.type.value,
      priority: f.priority.value,
      description: f.desc.value.trim(),
      assigned_investigator: f.assignee.value.trim(),
      iocs: parseIocs()
    };
  }

  function submit(e) {
    e.preventDefault();
    if (!validateStep1()) { showStep(1); return; }

    btnSubmit.disabled = true;
    btnSubmit.textContent = 'CREATING…';
    if (errorHost) errorHost.innerHTML = '';

    fetch('/lab/api/cases', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify(collectPayload())
    })
      .then(function (res) {
        return res.json().then(function (body) {
          if (!res.ok || body.success !== true) {
            var err = (body && body.error) || {};
            throw { code: err.code || 'REQUEST_FAILED',
                    message: err.message || 'The case could not be created.',
                    status: res.status };
          }
          return body.data;
        });
      })
      .then(function (data) {
        window.LAB.toast('Case created',
          data.case.case_ref + ' opened and audited.', 'success');
        setTimeout(function () {
          location.href = '/lab/cases/' + encodeURIComponent(data.case.case_ref);
        }, 450);
      })
      .catch(function (err) {
        btnSubmit.disabled = false;
        btnSubmit.textContent = 'CREATE CASE';
        if (errorHost) {
          window.LAB.renderError(errorHost,
            (err && err.code) || 'NETWORK_ERROR',
            (err && err.message) || 'The case could not be created.');
        }
        /* Server validation errors belong on step 1. */
        if (err && err.code === 'VALIDATION_FAILED') showStep(1);
      });
  }

  /* ---------------- Wire up ---------------- */
  btnNext.addEventListener('click', function () {
    if (step === 1 && !validateStep1()) return;
    showStep(step + 1);
  });
  btnBack.addEventListener('click', function () { showStep(step - 1); });
  form.addEventListener('submit', submit);

  /* Enter key should not skip steps in textareas */
  form.addEventListener('keydown', function (e) {
    if (e.key === 'Enter' && e.target.tagName !== 'TEXTAREA') {
      e.preventDefault();
      if (step < TOTAL) showStep(step + 1);
    }
  });

  showStep(1);
})();

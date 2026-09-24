/* ====================================================================
   KAVACHAM LAB — EVIDENCE INTAKE (Phase 6, Section 20)
   3 real steps: select type -> provide evidence -> attach & confirm.
   Files are read as base64 client-side; the server independently
   re-validates extension, MIME signature and size (Section 56).
   ==================================================================== */
(function () {
  'use strict';

  var esc = window.LAB.esc;
  var TOTAL = 3;
  var step = 1;

  var ref = {};
  try {
    ref = JSON.parse(document.getElementById('intake-ref').textContent) || {};
  } catch (e) { ref = {}; }

  var panes = document.querySelectorAll('.lab-wizard-pane');
  var stepEls = document.querySelectorAll('#intake-steps .lab-progress-step');
  var btnBack = document.getElementById('i-back');
  var btnNext = document.getElementById('i-next');
  var btnSubmit = document.getElementById('i-submit');
  var stepLabel = document.getElementById('i-step-label');
  var form = document.getElementById('intake-form');
  var errorHost = document.getElementById('intake-error');
  var resultHost = document.getElementById('intake-result');

  var f = {
    type: document.getElementById('i-type'),
    title: document.getElementById('i-title'),
    file: document.getElementById('i-file'),
    text: document.getElementById('i-text'),
    caseRef: document.getElementById('i-case'),
    source: document.getElementById('i-source'),
    notes: document.getElementById('i-notes')
  };

  /* Evidence types whose payload is a file upload vs. pasted text. */
  var FILE_TYPES = ['FILE', 'SCREENSHOT', 'QR_IMAGE'];

  function usesFile() {
    return FILE_TYPES.indexOf(f.type.value) !== -1;
  }

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

    if (step === 2) syncMode();
    if (step === 3) buildConfirmation();

    var focusable = panes[step - 1] &&
      panes[step - 1].querySelector('input,select,textarea');
    if (focusable && step > 1) focusable.focus();
  }

  /* ---------------- File vs text mode ---------------- */
  function syncMode() {
    var isFile = usesFile();
    document.getElementById('mode-file').hidden = !isFile;
    document.getElementById('mode-text').hidden = isFile;
  }

  if (f.type) f.type.addEventListener('change', syncMode);

  /* ---------------- Validation (UX only; server re-validates) -------- */
  function setError(id, msg) {
    var el = document.getElementById('err-' + id);
    if (!el) return;
    if (msg) {
      el.textContent = msg;
      el.hidden = false;
      var input = document.getElementById('i-' + id);
      if (input) input.style.borderColor = 'var(--lab-red)';
    } else {
      el.hidden = true;
      var i2 = document.getElementById('i-' + id);
      if (i2) i2.style.borderColor = '';
    }
  }

  function validateStep1() {
    var ok = true;
    var title = f.title.value.trim();
    if (!title) { setError('i-title', 'An evidence title is required.'); ok = false; }
    else if (title.length > 200) {
      setError('i-title', 'Title must be 200 characters or fewer.'); ok = false;
    } else setError('i-title', null);
    return ok;
  }

  function validateStep2() {
    if (usesFile()) {
      var file = f.file.files && f.file.files[0];
      if (!file) {
        setError('i-file', 'Select a file to acquire.');
        return false;
      }
      var maxBytes = ref.max_bytes || (10 * 1024 * 1024);
      if (file.size > maxBytes) {
        setError('i-file', 'File exceeds the ' + maxBytes.toLocaleString() +
          ' byte evidence limit.');
        return false;
      }
      setError('i-file', null);
      return true;
    }

    var text = (f.text.value || '').trim();
    if (!text) {
      setError('i-text', 'Provide the evidence content.');
      return false;
    }
    setError('i-text', null);
    return true;
  }

  /* ---------------- File preview ---------------- */
  f.file.addEventListener('change', function () {
    var host = document.getElementById('file-preview');
    var file = this.files && this.files[0];
    if (!file) { host.hidden = true; host.innerHTML = ''; return; }

    var ext = (file.name.match(/\.[^.]+$/) || [''])[0].toLowerCase();
    var blocked = (ref.blocked_extensions || []).indexOf(ext) !== -1;
    var maxBytes = ref.max_bytes || (10 * 1024 * 1024);

    host.hidden = false;
    host.innerHTML =
      '<div class="lab-label" style="margin-bottom:6px;">SELECTED FILE</div>' +
      '<div class="lab-ioc-chip"><span class="lab-badge lab-badge-blue">FILE</span>' +
      '<span class="lab-mono lab-xs">' + esc(file.name) + '</span></div>' +
      '<div class="lab-ioc-chip"><span class="lab-badge lab-badge-gray">SIZE</span>' +
      '<span class="lab-mono lab-xs">' + file.size.toLocaleString() + ' bytes</span></div>' +
      '<div class="lab-ioc-chip"><span class="lab-badge lab-badge-gray">TYPE</span>' +
      '<span class="lab-mono lab-xs">' + esc(file.type || 'unknown') + '</span></div>' +
      (blocked
        ? '<div class="lab-alert is-critical" style="margin-top:9px;">' +
          '<span class="lab-alert-icon">!</span><div>' +
          '<div class="lab-alert-title">FILE TYPE BLOCKED</div>' +
          '<div>Files of type ' + esc(ext) + ' are refused and will not be stored.</div>' +
          '</div></div>'
        : '') +
      (file.size > maxBytes
        ? '<div class="lab-alert is-critical" style="margin-top:9px;">' +
          '<span class="lab-alert-icon">!</span><div>' +
          '<div class="lab-alert-title">FILE TOO LARGE</div>' +
          '<div>Exceeds the ' + maxBytes.toLocaleString() + ' byte limit.</div>' +
          '</div></div>'
        : '');

    if (blocked) setError('i-file', 'This file type is refused.');
    else if (file.size > maxBytes) setError('i-file', 'File exceeds the size limit.');
    else setError('i-file', null);
  });

  /* ---------------- Confirmation (Section 20) ---------------- */
  function buildConfirmation() {
    var host = document.getElementById('intake-summary');
    if (!host) return;

    var rows = [
      ['EVIDENCE TYPE', f.type.value, false],
      ['TITLE', f.title.value.trim() || '—', false],
      ['CONTENT', usesFile()
        ? ((f.file.files && f.file.files[0])
            ? f.file.files[0].name + ' (' +
              (f.file.files[0].size.toLocaleString()) + ' bytes)'
            : 'No file selected')
        : ((f.text.value || '').trim().length + ' characters of text'), false],
      ['ATTACH TO CASE', f.caseRef.value.trim() || 'Leave unattached', true],
      ['SOURCE', f.source.value.trim() || 'Analyst Input', false],
      ['NOTES', f.notes.value.trim() || '—', false]
    ];

    host.innerHTML = rows.map(function (r) {
      return '<dt>' + esc(r[0]) + '</dt><dd' + (r[2] ? ' class="lab-mono"' : '') +
        '>' + esc(String(r[1])) + '</dd>';
    }).join('') +
      '<dt>ON ACCEPTANCE</dt><dd>Validate · generate SHA-256 / SHA-1 / MD5 · ' +
      'generate evidence ID · record timestamp · write custody events</dd>';
  }

  /* ---------------- Read file as base64 ---------------- */
  function fileToBase64(file) {
    return new Promise(function (resolve, reject) {
      var reader = new FileReader();
      reader.onerror = function () { reject(new Error('FILE_READ_FAILED')); };
      reader.onload = function () {
        var result = reader.result || '';
        var comma = result.indexOf(',');
        resolve(comma === -1 ? result : result.slice(comma + 1));
      };
      reader.readAsDataURL(file);
    });
  }

  /* ---------------- Submission (Section 20 steps 3-7) ---------------- */
  function submit(e) {
    e.preventDefault();
    if (!validateStep1()) { showStep(1); return; }
    if (!validateStep2()) { showStep(2); return; }

    btnSubmit.disabled = true;
    btnSubmit.textContent = 'ACCEPTING…';
    if (errorHost) errorHost.innerHTML = '';

    var payload = {
      evidence_type: f.type.value,
      title: f.title.value.trim(),
      case_ref: f.caseRef.value.trim() || null,
      source: f.source.value.trim() || 'Analyst Input',
      notes: f.notes.value.trim()
    };

    var prepare;
    if (usesFile()) {
      var file = f.file.files[0];
      payload.filename = file.name;
      prepare = fileToBase64(file).then(function (b64) {
        payload.content_base64 = b64;
      });
    } else {
      payload.content_text = (f.text.value || '').trim();
      prepare = Promise.resolve();
    }

    prepare
      .then(function () {
        return fetch('/lab/api/evidence', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
          credentials: 'same-origin',
          body: JSON.stringify(payload)
        });
      })
      .then(function (res) {
        return res.json().then(function (body) {
          if (!res.ok || body.success !== true) {
            var err = (body && body.error) || {};
            throw { code: err.code || 'REQUEST_FAILED',
                    message: err.message || 'The evidence could not be accepted.',
                    status: res.status };
          }
          return body.data;
        });
      })
      .then(function (data) {
        /* Section 20: EVIDENCE ACCEPTED with real ID, hash and timestamp. */
        showAccepted(data.evidence);
      })
      .catch(function (err) {
        btnSubmit.disabled = false;
        btnSubmit.textContent = 'ACCEPT EVIDENCE';
        if (errorHost) {
          window.LAB.renderError(errorHost,
            (err && err.code) || 'NETWORK_ERROR',
            (err && err.message) || 'The evidence could not be accepted.');
        }
        if (err && (err.code === 'VALIDATION_FAILED')) showStep(1);
        else if (err && (err.code === 'FILE_TOO_LARGE' || err.code === 'FILE_TYPE_BLOCKED')) {
          showStep(2);
        }
      });
  }

  function showAccepted(ev) {
    form.hidden = true;
    document.getElementById('intake-steps').hidden = true;
    if (errorHost) errorHost.hidden = true;

    resultHost.innerHTML =
      '<div class="lab-panel">' +
      '<div class="lab-panel-head">' +
      '<h2 class="lab-section-title">EVIDENCE ACCEPTED</h2>' +
      '<span class="lab-badge lab-badge-green">ACCEPTED</span>' +
      '</div>' +
      '<div class="lab-panel-body">' +
      '<dl class="lab-kv">' +
      '<dt>EVIDENCE ID</dt><dd class="lab-mono">' + esc(ev.evidence_ref) + '</dd>' +
      '<dt>SHA-256</dt><dd class="lab-mono" style="overflow-wrap:anywhere;">' +
      esc(ev.sha256) + '</dd>' +
      '<dt>SHA-1</dt><dd class="lab-mono" style="overflow-wrap:anywhere;">' +
      esc(ev.sha1) + '</dd>' +
      '<dt>MD5</dt><dd class="lab-mono">' + esc(ev.md5) + '</dd>' +
      '<dt>ACQUIRED</dt><dd class="lab-mono">' + esc(window.LAB.fmtTs(ev.acquired_at)) +
      ' UTC</dd>' +
      '<dt>TYPE</dt><dd>' + esc(ev.evidence_type) + '</dd>' +
      '<dt>INTEGRITY</dt><dd>' + esc(ev.integrity_state) + '</dd>' +
      '<dt>CASE</dt><dd class="lab-mono">' +
      esc(ev.case ? ev.case.case_ref : 'Unattached') + '</dd>' +
      '</dl>' +
      '<div class="lab-row tight" style="margin-top:16px;">' +
      '<a class="lab-btn lab-btn-primary lab-btn-sm" href="/lab/evidence/' +
      encodeURIComponent(ev.evidence_ref) + '">OPEN EVIDENCE RECORD</a>' +
      '<a class="lab-btn lab-btn-sm" href="/lab/evidence">RETURN TO VAULT</a>' +
      '<button class="lab-btn lab-btn-sm" type="button" id="accept-another">ACQUIRE ANOTHER</button>' +
      '</div>' +
      '</div></div>';

    window.LAB.toast('Evidence accepted',
      ev.evidence_ref + ' hashed and chained.', 'success');

    document.getElementById('accept-another')
      .addEventListener('click', function () { location.reload(); });
  }

  /* ---------------- Wire up ---------------- */
  btnNext.addEventListener('click', function () {
    if (step === 1 && !validateStep1()) return;
    if (step === 2 && !validateStep2()) return;
    showStep(step + 1);
  });
  btnBack.addEventListener('click', function () { showStep(step - 1); });
  form.addEventListener('submit', submit);

  form.addEventListener('keydown', function (e) {
    if (e.key === 'Enter' && e.target.tagName !== 'TEXTAREA') {
      e.preventDefault();
      if (step < TOTAL) showStep(step + 1);
    }
  });

  syncMode();
  showStep(1);
})();

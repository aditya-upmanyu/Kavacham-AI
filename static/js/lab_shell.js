/* ====================================================================
   KAVACHAM LAB — SHELL CONTROLLER (Phase 3)
   Sidebar, mobile drawer, toasts, header health refresh.
   No fabricated data: header values come from the server-rendered
   health check, and are only updated from real /lab/api/health calls.
   ==================================================================== */
(function () {
  'use strict';

  var shell = document.getElementById('lab-root');
  if (!shell) return;

  var burger = document.getElementById('lab-burger');
  var sidebar = document.getElementById('lab-sidebar');
  var scrim = document.getElementById('lab-scrim');

  /* ---------------- Mobile drawer ---------------- */
  function setDrawer(open) {
    if (!sidebar) return;
    sidebar.classList.toggle('is-open', open);
    if (scrim) scrim.hidden = !open;
    if (burger) burger.setAttribute('aria-expanded', open ? 'true' : 'false');
    document.body.style.overflow = open ? 'hidden' : '';
  }
  function drawerOpen() { return !!(sidebar && sidebar.classList.contains('is-open')); }

  if (burger) {
    burger.addEventListener('click', function () { setDrawer(!drawerOpen()); });
  }
  if (scrim) {
    scrim.addEventListener('click', function () { setDrawer(false); });
  }

  /* Close drawer when a nav link is chosen */
  if (sidebar) {
    sidebar.addEventListener('click', function (e) {
      var link = e.target.closest('a');
      if (link && window.matchMedia('(max-width: 980px)').matches) setDrawer(false);
    });
  }

  /* ---------------- Desktop collapse (Ctrl+B) ---------------- */
  document.addEventListener('keydown', function (e) {
    if ((e.ctrlKey || e.metaKey) && (e.key === 'b' || e.key === 'B')) {
      if (window.matchMedia('(min-width: 981px)').matches) {
        e.preventDefault();
        shell.classList.toggle('is-collapsed');
        try { localStorage.setItem('lab_collapsed', shell.classList.contains('is-collapsed') ? '1' : '0'); } catch (err) {}
      }
    }
    if (e.key === 'Escape' && drawerOpen()) setDrawer(false);
  });

  try {
    if (localStorage.getItem('lab_collapsed') === '1' && window.matchMedia('(min-width: 981px)').matches) {
      shell.classList.add('is-collapsed');
    }
  } catch (err) {}

  /* ---------------- Toasts (Section 54 / 60) ---------------- */
  function toast(title, message, type, ttl) {
    var host = document.getElementById('lab-toasts');
    if (!host) return;
    var el = document.createElement('div');
    el.className = 'lab-toast is-' + (type || 'info');
    var strong = document.createElement('strong');
    strong.textContent = title || '';
    el.appendChild(strong);
    if (message) {
      var span = document.createElement('span');
      span.textContent = message;
      el.appendChild(span);
    }
    host.appendChild(el);
    var life = ttl || 5000;
    setTimeout(function () {
      el.classList.add('is-leaving');
      setTimeout(function () { if (el.parentNode) el.parentNode.removeChild(el); }, 200);
    }, life);
    return el;
  }

  /* ---------------- Correlation id (BZ) ---------------- */
  /* One id per page load; sent as X-Correlation-ID so the backend threads
     it through the request log and echoes it as X-Request-ID. The value is
     random hex — no user data, no secrets. */
  var corrId = 'c' + Math.random().toString(16).slice(2, 10) +
    Date.now().toString(16).slice(-4);

  /* ---------------- Header health refresh (real data only) ---------------- */
  var statusEl = document.getElementById('lab-system-status');
  var lastCheckEl = document.getElementById('lab-last-check');

  function refreshHeaderHealth() {
    return fetch('/lab/api/health', {
      headers: { 'Accept': 'application/json', 'X-Correlation-ID': corrId },
    })
      .then(function (res) { return res.json(); })
      .then(function (body) {
        if (!body || body.success !== true || !body.data) return null;
        var d = body.data;
        if (statusEl) {
          statusEl.textContent = d.overall_status;
          statusEl.setAttribute('data-key', d.overall_status_key);
          statusEl.className = 'lab-status lab-status-dot' +
            (d.overall_status_key === 'operational' ? ' is-live' : '') +
            (d.overall_status_key === 'degraded' ? ' is-warning' : '') +
            (d.overall_status_key === 'unavailable' ? ' is-failure' : '');
        }
        if (lastCheckEl && d.checked_at) {
          lastCheckEl.textContent = d.checked_at.slice(0, 19).replace('T', ' ') + ' UTC';
        }
        return d;
      })
      .catch(function () {
        /* Network failure: report honestly, never fake a status. */
        if (statusEl) {
          statusEl.textContent = 'SERVICE UNAVAILABLE';
          statusEl.className = 'lab-status lab-status-dot is-failure';
          statusEl.setAttribute('data-key', 'unavailable');
        }
        if (lastCheckEl) lastCheckEl.innerHTML = '<span class="lab-state-inline">UNAVAILABLE</span>';
        return null;
      });
  }

  /* ---------------- Public surface for Lab modules ---------------- */
  window.LAB = {
    toast: toast,
    refreshHeaderHealth: refreshHeaderHealth,
    corrId: corrId,
    setDrawer: setDrawer,
    /* Section 49 error rendering — calm, operational, no stack traces */
    renderError: function (target, code, message, action) {
      var el = typeof target === 'string' ? document.getElementById(target) : target;
      if (!el) return;
      el.innerHTML = '';
      var wrap = document.createElement('div');
      wrap.className = 'lab-state is-error';
      var icon = document.createElement('div');
      icon.className = 'lab-state-icon';
      icon.textContent = '!';
      var title = document.createElement('div');
      title.className = 'lab-state-title';
      title.textContent = message ? 'REQUEST INTERRUPTED' : 'ERROR';
      var desc = document.createElement('p');
      desc.className = 'lab-state-desc';
      desc.textContent = message || 'The request could not be completed.';
      wrap.appendChild(icon); wrap.appendChild(title); wrap.appendChild(desc);
      if (code) {
        var codeEl = document.createElement('div');
        codeEl.className = 'lab-provenance';
        codeEl.style.marginTop = '6px';
        codeEl.textContent = 'ERROR CODE: ' + code;
        wrap.appendChild(codeEl);
      }
      if (action) {
        var btn = document.createElement('button');
        btn.className = 'lab-btn lab-btn-sm';
        btn.type = 'button';
        btn.textContent = action.label || 'Retry';
        btn.addEventListener('click', action.onClick);
        wrap.appendChild(btn);
      }
      el.appendChild(wrap);
    },
    /* Section 61 — honest empty state */
    emptyState: function (icon, title, desc, action) {
      var wrap = document.createElement('div');
      wrap.className = 'lab-state';
      var i = document.createElement('div');
      i.className = 'lab-state-icon';
      i.textContent = icon || '—';
      var t = document.createElement('div');
      t.className = 'lab-state-title';
      t.textContent = title;
      var d = document.createElement('p');
      d.className = 'lab-state-desc';
      d.textContent = desc || '';
      wrap.appendChild(i); wrap.appendChild(t); wrap.appendChild(d);
      if (action) {
        var b = document.createElement('button');
        b.className = 'lab-btn lab-btn-primary lab-btn-sm';
        b.type = 'button';
        b.textContent = action.label;
        b.addEventListener('click', action.onClick);
        wrap.appendChild(b);
      }
      return wrap;
    },
    /* Escape user-controlled text before inserting as HTML */
    esc: function (s) {
      if (s === null || s === undefined) return '';
      return String(s).replace(/[&<>"']/g, function (c) {
        return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
      });
    },
    fmtTs: function (iso) {
      if (!iso) return '—';
      try {
        var d = new Date(iso);
        if (isNaN(d.getTime())) return '—';
        function p(n) { return (n < 10 ? '0' : '') + n; }
        return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate()) + ' ' +
               p(d.getHours()) + ':' + p(d.getMinutes()) + ':' + p(d.getSeconds());
      } catch (err) { return '—'; }
    }
  };

  /* Periodic honest refresh of header status */
  refreshHeaderHealth();
  setInterval(refreshHeaderHealth, 60000);
})();

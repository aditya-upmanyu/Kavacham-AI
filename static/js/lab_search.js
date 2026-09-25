/* ====================================================================
   KAVACHAM LAB — GLOBAL COMMAND SEARCH (Section O)
   CTRL+K palette: debounced fetch to /lab/api/search, grouped results,
   full keyboard navigation (up/down/enter/escape), focus restored on
   close. Every result links to a real record — never a dead entry.
   ==================================================================== */
(function () {
  'use strict';

  var esc = window.LAB && window.LAB.esc ? window.LAB.esc : function (s) { return String(s == null ? '' : s); };

  var backdrop = document.getElementById('lab-palette-backdrop');
  var input = document.getElementById('lab-palette-input');
  var results = document.getElementById('lab-palette-results');
  var filtersHost = document.getElementById('lab-palette-filters');
  var openBtn = document.getElementById('lab-search-open');
  if (!backdrop || !input || !results) return;

  var activeFilter = '';
  var items = [];
  var activeIdx = -1;
  var timer = null;
  var lastFocus = null;

  function open() {
    lastFocus = document.activeElement;
    backdrop.hidden = false;
    input.value = '';
    setFilter('', false);
    renderEmpty('Type to search cases, evidence, analyses, IOCs and entities.');
    setTimeout(function () { input.focus(); }, 0);
  }

  function close() {
    backdrop.hidden = true;
    if (timer) { clearTimeout(timer); timer = null; }
    if (lastFocus && lastFocus.focus) lastFocus.focus();
  }

  function isOpen() { return !backdrop.hidden; }

  function setFilter(name, refetch) {
    activeFilter = name || '';
    if (filtersHost) {
      Array.prototype.forEach.call(
        filtersHost.querySelectorAll('button[data-filter]'), function (b) {
          var on = (b.getAttribute('data-filter') || '') === activeFilter;
          b.setAttribute('aria-pressed', on ? 'true' : 'false');
          b.classList.toggle('is-active', on);
        });
    }
    if (refetch !== false) scheduleFetch(0);
  }

  function scheduleFetch(delay) {
    if (timer) clearTimeout(timer);
    timer = setTimeout(fetchResults, delay == null ? 200 : delay);
  }

  function fetchResults() {
    var q = input.value.trim();
    if (!q) {
      renderEmpty('Type to search cases, evidence, analyses, IOCs and entities.');
      return;
    }
    var url = '/lab/api/search?q=' + encodeURIComponent(q) +
      (activeFilter ? '&type=' + encodeURIComponent(activeFilter) : '');
    fetch(url, { headers: { 'Accept': 'application/json' }, credentials: 'same-origin' })
      .then(function (res) {
        return res.json().then(function (body) {
          if (!res.ok || body.success !== true) throw new Error('search failed');
          return body.data;
        });
      })
      .then(render)
      .catch(function () {
        renderEmpty('Search could not be completed. Try again.');
      });
  }

  function renderEmpty(msg) {
    items = [];
    activeIdx = -1;
    results.innerHTML = '<div class="lab-palette-empty">' + esc(msg) + '</div>';
  }

  function render(data) {
    items = [];
    var html = '';
    (data.groups || []).forEach(function (g) {
      if (!g.items || !g.items.length) return;
      html += '<div class="lab-palette-group" role="presentation">' +
        '<div class="lab-palette-group-title">' + esc(g.title) +
        ' <span class="lab-dim">' + g.items.length + '</span></div>';
      g.items.forEach(function (it) {
        var idx = items.length;
        items.push(it);
        html += '<div class="lab-palette-item" role="option" data-idx="' + idx + '"' +
          ' aria-selected="false" tabindex="-1">' +
          '<span class="lab-palette-kind">' + esc((it.kind || '').toUpperCase()) + '</span>' +
          '<span class="lab-palette-label lab-mono">' + esc(it.label) + '</span>' +
          '<span class="lab-palette-sub lab-dim">' + esc(it.sub || '') + '</span>' +
          (it.match === 'exact' ? '<span class="lab-badge lab-badge-green">EXACT</span>' : '') +
          '</div>';
      });
      html += '</div>';
    });
    if (!items.length) {
      renderEmpty('No matches for "' + data.query + '". Nothing fabricated — try a reference, hash, IP, domain or address.');
      return;
    }
    results.innerHTML = html;
    setActive(0);
  }

  function setActive(idx) {
    activeIdx = idx;
    Array.prototype.forEach.call(
      results.querySelectorAll('.lab-palette-item'), function (el) {
        var on = parseInt(el.getAttribute('data-idx'), 10) === idx;
        el.classList.toggle('is-active', on);
        el.setAttribute('aria-selected', on ? 'true' : 'false');
        if (on && el.scrollIntoView) el.scrollIntoView({ block: 'nearest' });
      });
  }

  function activateCurrent() {
    var it = items[activeIdx];
    if (it && it.url) window.location.href = it.url;
  }

  document.addEventListener('keydown', function (e) {
    var mod = e.ctrlKey || e.metaKey;
    if (mod && (e.key === 'k' || e.key === 'K')) {
      e.preventDefault();
      if (isOpen()) close(); else open();
      return;
    }
    if (!isOpen()) return;
    if (e.key === 'Escape') { e.preventDefault(); close(); }
    else if (e.key === 'ArrowDown') { e.preventDefault(); if (items.length) setActive((activeIdx + 1) % items.length); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); if (items.length) setActive((activeIdx - 1 + items.length) % items.length); }
    else if (e.key === 'Enter') { e.preventDefault(); activateCurrent(); }
  });

  input.addEventListener('input', function () { scheduleFetch(200); });

  if (filtersHost) {
    filtersHost.addEventListener('click', function (e) {
      var b = e.target.closest('button[data-filter]');
      if (b) setFilter(b.getAttribute('data-filter') || '');
    });
  }

  results.addEventListener('click', function (e) {
    var el = e.target.closest('.lab-palette-item');
    if (!el) return;
    var it = items[parseInt(el.getAttribute('data-idx'), 10)];
    if (it && it.url) window.location.href = it.url;
  });

  backdrop.addEventListener('click', function (e) {
    if (e.target === backdrop) close();
  });

  if (openBtn) openBtn.addEventListener('click', open);
})();

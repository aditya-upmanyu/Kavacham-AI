/* ====================================================================
   ANVESHAK AI — UI Effects Engine
   --------------------------------------------------------------------
   • Cursor spotlight (desktop, fine pointers only)
   • Reveal-on-scroll with staggered delays
   • Animated count-up for [data-count] numbers
   • Animated metric bars (.metric-bar-fill) on first reveal
   • Confusion matrix pop-in when it enters the viewport
   • 3D perspective tilt for .tilt-card
   • Magnetic hover for .btn-primary
   • Hero entrance classes
   Exposes window.AnveshakEffects for navigation hooks.
   ==================================================================== */

'use strict';

(function () {
  const REDUCED = window.matchMedia &&
    window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  const FINE_POINTER = window.matchMedia &&
    window.matchMedia('(pointer: fine)').matches;

  /* =================================================================
     1. CURSOR SPOTLIGHT
     ================================================================= */
  function initCursorGlow() {
    if (REDUCED || !FINE_POINTER) return;
    if (window.matchMedia && window.matchMedia('(max-width: 768px)').matches) return;

    const glow = document.createElement('div');
    glow.className = 'cursor-glow';
    document.body.appendChild(glow);

    let x = 0, y = 0, tx = 0, ty = 0, on = false, raf = null;

    function tick() {
      x += (tx - x) * 0.14;
      y += (ty - y) * 0.14;
      glow.style.transform = 'translate3d(' + x + 'px,' + y + 'px,0)';
      raf = window.requestAnimationFrame(tick);
    }

    document.addEventListener('pointermove', function (e) {
      tx = e.clientX; ty = e.clientY;
      if (!on) { on = true; x = tx; y = ty; glow.classList.add('is-on'); }
      if (raf === null) raf = window.requestAnimationFrame(tick);
    }, { passive: true });

    document.addEventListener('pointerleave', function () {
      on = false;
      glow.classList.remove('is-on');
    });
  }

  /* =================================================================
     2. REVEAL ON SCROLL
     ================================================================= */
  const REVEAL_SELECTOR = [
    '.card', '.chart-card', '.stat-card', '.metric-card', '.engine-card',
    '.kpi-pill', '.glass-panel', '.comparison-banner', '.confusion-matrix',
    '.gmail-connect-card', '.settings-grid .card', '.page-header',
    '.history-item', '.mode-selector-wrapper', '.privacy-notice'
  ].join(',');

  let observer = null;

  function prepareReveal(root) {
    if (REDUCED) return [];
    const scope = root || document;
    const candidates = scope.querySelectorAll(REVEAL_SELECTOR);
    const fresh = [];

    candidates.forEach(function (el) {
      if (el.dataset.revealReady) return;
      el.dataset.revealReady = '1';
      el.classList.add('reveal-init');

      // Stagger by position among siblings of the same kind
      const parent = el.parentElement;
      let idx = 0;
      if (parent) {
        const sibs = Array.prototype.filter.call(parent.children, function (c) {
          return c.classList && c.classList.contains('reveal-init');
        });
        idx = sibs.indexOf(el);
      }
      const delay = Math.min(idx * 70, 420);
      el.style.setProperty('--reveal-delay', delay + 'ms');
      fresh.push(el);
    });
    return fresh;
  }

  function observe(el) {
    if (!observer) return;
    try { observer.observe(el); } catch (e) { /* noop */ }
  }

  function reveal(el) {
    el.classList.add('reveal-in');
    if (observer) { try { observer.unobserve(el); } catch (e) {} }
    onRevealed(el);
  }

  function onRevealed(el) {
    // Kick off dependent animations
    if (el.querySelector && el.querySelector('.metric-bar-fill')) animateBars(el);
    if (el.classList.contains('confusion-matrix')) el.classList.add('is-live');
    if (el.classList.contains('confusion-matrix') === false) {
      const cm = el.querySelector && el.querySelector('.confusion-matrix');
      if (cm) cm.classList.add('is-live');
    }
    countUpIn(el);
  }

  function initReveal() {
    if (REDUCED) {
      // Still fire bar/number animations without motion
      document.querySelectorAll('.metric-bar-fill').forEach(animateBar);
      document.querySelectorAll('[data-count]').forEach(runCount);
      document.querySelectorAll('.confusion-matrix').forEach(function (m) { m.classList.add('is-live'); });
      return;
    }

    if ('IntersectionObserver' in window) {
      observer = new IntersectionObserver(function (entries) {
        entries.forEach(function (entry) {
          if (entry.isIntersecting) reveal(entry.target);
        });
      }, { threshold: 0.08, rootMargin: '0px 0px -6% 0px' });
    }

    prepareReveal(document).forEach(observe);

    // Fallback: if IO missing, reveal everything
    if (!observer) {
      document.querySelectorAll('.reveal-init').forEach(reveal);
    }
  }

  /* =================================================================
     3. COUNT-UP NUMBERS
     ================================================================= */
  function parseTarget(raw) {
    if (raw === null || raw === undefined) return null;
    const str = String(raw).replace(/[%,\s]/g, '');
    const n = parseFloat(str);
    if (isNaN(n)) return null;
    const decimals = (str.split('.')[1] || '').length;
    return { value: n, decimals: decimals };
  }

  function formatNum(v, decimals) {
    return decimals > 0 ? v.toFixed(decimals) : String(Math.round(v));
  }

  function runCount(el) {
    if (el.dataset.counted) return;
    const parsed = parseTarget(el.dataset.count);
    if (!parsed) return;
    el.dataset.counted = '1';

    const suffix = el.dataset.suffix || '';
    const duration = 1500;
    const start = performance.now();
    const from = 0;

    if (REDUCED) { el.textContent = formatNum(parsed.value, parsed.decimals) + suffix; return; }

    function frame(now) {
      const t = Math.min(1, (now - start) / duration);
      const eased = 1 - Math.pow(1 - t, 3); // easeOutCubic
      const v = from + (parsed.value - from) * eased;
      el.textContent = formatNum(v, parsed.decimals) + suffix;
      if (t < 1) window.requestAnimationFrame(frame);
      else el.textContent = formatNum(parsed.value, parsed.decimals) + suffix;
    }
    window.requestAnimationFrame(frame);
  }

  function countUpIn(scope) {
    if (!scope || !scope.querySelectorAll) return;
    scope.querySelectorAll('[data-count]').forEach(runCount);
    if (scope.matches && scope.matches('[data-count]')) runCount(scope);
  }

  /* =================================================================
     4. METRIC BARS
     ================================================================= */
  function animateBar(bar) {
    if (bar.dataset.barReady) return;
    bar.dataset.barReady = '1';
    const target = bar.style.width;
    if (!target) return;
    bar.dataset.targetWidth = target;
    bar.style.width = '0%';
    // Force reflow so the transition plays
    void bar.offsetWidth;
    window.requestAnimationFrame(function () {
      bar.style.width = bar.dataset.targetWidth;
    });
  }

  function animateBars(scope) {
    if (!scope || !scope.querySelectorAll) return;
    scope.querySelectorAll('.metric-bar-fill').forEach(animateBar);
    if (scope.classList && scope.classList.contains('metric-bar-fill')) animateBar(scope);
  }

  /* =================================================================
     5. 3D TILT CARDS
     ================================================================= */
  function initTilt() {
    if (REDUCED || !FINE_POINTER) return;

    document.addEventListener('pointermove', function (e) {
      const card = e.target.closest ? e.target.closest('.tilt-card') : null;
      if (!card) return;

      const rect = card.getBoundingClientRect();
      const px = (e.clientX - rect.left) / rect.width;
      const py = (e.clientY - rect.top) / rect.height;

      const ry = (px - 0.5) * 9;   // rotateY
      const rx = (0.5 - py) * 7;   // rotateX

      card.classList.add('is-tilting');
      card.style.setProperty('--ry', ry.toFixed(2) + 'deg');
      card.style.setProperty('--rx', rx.toFixed(2) + 'deg');
      card.style.setProperty('--mx', (px * 100).toFixed(1) + '%');
      card.style.setProperty('--my', (py * 100).toFixed(1) + '%');
    }, { passive: true });

    document.addEventListener('pointerout', function (e) {
      const card = e.target.closest ? e.target.closest('.tilt-card') : null;
      if (!card) return;
      if (e.relatedTarget && card.contains(e.relatedTarget)) return;
      card.classList.remove('is-tilting');
      card.style.setProperty('--ry', '0deg');
      card.style.setProperty('--rx', '0deg');
    });
  }

  /* =================================================================
     6. MAGNETIC BUTTONS
     ================================================================= */
  function initMagnetic() {
    if (REDUCED || !FINE_POINTER) return;
    const targets = document.querySelectorAll('.btn-primary, .btn-lg, #check-btn');
    targets.forEach(function (btn) {
      btn.addEventListener('pointermove', function (e) {
        const rect = btn.getBoundingClientRect();
        const mx = e.clientX - rect.left - rect.width / 2;
        const my = e.clientY - rect.top - rect.height / 2;
        btn.style.transform =
          'translate(' + (mx * 0.14).toFixed(1) + 'px,' +
          (my * 0.22 - 2).toFixed(1) + 'px)';
      }, { passive: true });
      btn.addEventListener('pointerleave', function () {
        btn.style.transform = '';
      });
    });
  }

  /* =================================================================
     7. HERO ENTRANCE
     ================================================================= */
  function initHero() {
    const selectors = [
      '#page-dashboard .page-header',
      '.page-title',
      '.page-subtitle'
    ];
    let i = 0;
    document.querySelectorAll(selectors.join(',')).forEach(function (el) {
      if (REDUCED) return;
      el.classList.add('hero-in');
      el.classList.add('d' + Math.min(3, i % 3 + 1));
      i++;
    });
  }

  /* =================================================================
     8. PUBLIC API
     ================================================================= */
  window.AnveshakEffects = {
    /** Reveal any freshly-shown elements inside a container (page switches) */
    revealVisible: function (container) {
      if (REDUCED) return;
      const scope = container || document;
      const pending = scope.querySelectorAll
        ? scope.querySelectorAll('.reveal-init:not(.reveal-in)')
        : [];
      pending.forEach(function (el) {
        const rect = el.getBoundingClientRect();
        const visible = rect.top < window.innerHeight * 0.95 && rect.bottom > 0;
        if (visible) {
          // Small stagger so page transitions feel choreographed
          const idx = Array.prototype.indexOf.call(
            el.parentElement ? el.parentElement.children : [], el);
          el.style.setProperty('--reveal-delay', Math.min(idx * 60, 360) + 'ms');
          reveal(el);
        } else if (observer) {
          observe(el);
        }
      });
    },
    revealAll: function () {
      document.querySelectorAll('.reveal-init').forEach(reveal);
    },
    countUp: runCount,
    refresh: function () {
      const fresh = prepareReveal(document);
      fresh.forEach(observe);
      this.revealVisible(document);
      initMagnetic();
    }
  };

  /* =================================================================
     9. BOOT
     ================================================================= */
  function boot() {
    initCursorGlow();
    initReveal();
    initTilt();
    initHero();
    // Count-ups for elements already on screen (e.g. Gmail stats)
    countUpIn(document);
    initMagnetic();

    // Safety net: after load, anything still hidden but on-screen gets shown
    window.addEventListener('load', function () {
      setTimeout(function () {
        window.AnveshakEffects.revealVisible(document);
      }, 400);
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }
})();

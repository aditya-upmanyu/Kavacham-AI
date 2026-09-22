/* ====================================================================
   ANVESHAK AI — Lightweight Carousel Component
   --------------------------------------------------------------------
   Markup contract (all optional peers are discovered automatically):

     <div class="carousel" data-carousel data-autoplay="5000">
       <button class="carousel-arrow prev">‹</button>
       <div class="carousel-viewport">
         <div class="carousel-track">
           <div class="carousel-slide">…</div>
           <div class="carousel-slide">…</div>
         </div>
       </div>
       <button class="carousel-arrow next">›</button>
       <div class="carousel-dots"></div>
     </div>

   Supports: autoplay (paused on hover), arrow buttons, generated dots,
   touch / pointer swipe, keyboard arrows, reduced-motion friendly.
   ==================================================================== */

'use strict';

(function () {
  const REDUCED = window.matchMedia &&
    window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  const CAROUSEL_SELECTOR = '[data-carousel]';

  const instances = [];

  class Carousel {
    constructor(root) {
      this.root = root;
      this.track = root.querySelector('.carousel-track');
      this.viewport = root.querySelector('.carousel-viewport');
      this.slides = root.querySelectorAll('.carousel-slide');

      if (!this.track || this.slides.length === 0) return;

      this.index = 0;
      this.count = this.slides.length;
      this.autoplayMs = parseInt(root.getAttribute('data-autoplay'), 10) || 0;
      this.timer = null;
      this.swipe = { x0: 0, y0: 0, active: false };

      this.buildDots();
      this.bindArrows();
      this.bindDrag();
      this.bindKeyboard();
      this.bindAutoplay();
      this.go(0, false);

      // Stop autoplay when the carousel is off-screen or hidden
      const self = this;
      if ('IntersectionObserver' in window) {
        const io = new IntersectionObserver(function (entries) {
          const visible = entries.some(function (e) { return e.isIntersecting; });
          if (visible && !REDUCED) self.play();
          else self.pause();
        }, { threshold: 0.15 });
        io.observe(root);
        this._io = io;
      }
    }

    buildDots() {
      const dotsWrap = this.root.querySelector('.carousel-dots');
      if (!dotsWrap) return;
      dotsWrap.innerHTML = '';
      for (let i = 0; i < this.count; i++) {
        const dot = document.createElement('button');
        dot.type = 'button';
        dot.className = 'carousel-dot';
        dot.setAttribute('aria-label', 'Slide ' + (i + 1));
        const self = this;
        dot.addEventListener('click', function () { self.go(i); });
        dotsWrap.appendChild(dot);
      }
      this.dots = dotsWrap.querySelectorAll('.carousel-dot');
    }

    bindArrows() {
      const prev = this.root.querySelector('.carousel-arrow.prev');
      const next = this.root.querySelector('.carousel-arrow.next');
      const self = this;
      if (prev) prev.addEventListener('click', function () { self.prev(); });
      if (next) next.addEventListener('click', function () { self.next(); });
    }

    bindKeyboard() {
      const self = this;
      this.root.setAttribute('tabindex', '0');
      this.root.addEventListener('keydown', function (e) {
        if (e.key === 'ArrowLeft') { self.prev(); e.preventDefault(); }
        else if (e.key === 'ArrowRight') { self.next(); e.preventDefault(); }
      });
    }

    bindDrag() {
      const self = this;
      const vp = this.viewport;

      vp.addEventListener('pointerdown', function (e) {
        self.swipe.x0 = e.clientX;
        self.swipe.y0 = e.clientY;
        self.swipe.active = true;
        self.pause();
      }, { passive: true });

      window.addEventListener('pointermove', function (e) {
        if (!self.swipe.active) return;
        const dx = e.clientX - self.swipe.x0;
        const dy = e.clientY - self.swipe.y0;
        if (Math.abs(dy) > Math.abs(dx) * 1.4) { self.swipe.active = false; return; }
        if (Math.abs(dx) < 30) return;
        self.swipe.active = false;
        dx < 0 ? self.next() : self.prev();
      }, { passive: true });

      window.addEventListener('pointerup', function () {
        self.swipe.active = false;
        self.play();
      }, { passive: true });
    }

    bindAutoplay() {
      const self = this;
      this.root.addEventListener('pointerenter', function () { self.pause(); });
      this.root.addEventListener('pointerleave', function () { self.play(); });
      if (REDUCED || !this.autoplayMs) return;
      this.play();
    }

    play() {
      if (REDUCED || !this.autoplayMs) return;
      this.pause();
      const self = this;
      this.timer = window.setInterval(function () { self.next(); }, this.autoplayMs);
    }
    pause() {
      if (this.timer) { window.clearInterval(this.timer); this.timer = null; }
    }
    destroyAutoplay() {
      this.pause();
      if (this._io) this._io.disconnect();
    }

    go(i, animate) {
      const next = (i + this.count) % this.count;
      this.index = next;
      const step = 100 / this.count;

      if (this.track) {
        this.track.style.transition = animate === false
          ? 'none'
          : 'transform 0.55s cubic-bezier(0.22, 1, 0.36, 1)';
        this.track.style.transform = 'translateX(-' + (next * step) + '%)';
      }

      if (this.dots) {
        this.dots.forEach(function (d, k) {
          d.classList.toggle('active', k === next);
          d.setAttribute('aria-current', k === next ? 'true' : 'false');
        });
      }

      this.root.dispatchEvent(new CustomEvent('carousel:change', { detail: { index: next } }));
    }

    next() { this.go(this.index + 1); }
    prev() { this.go(this.index - 1); }
  }

  function init(root) {
    if (!root) return;
    const el = new Carousel(root);
    if (el.count) instances.push(el);
  }

  function boot() {
    document.querySelectorAll(CAROUSEL_SELECTOR).forEach(init);
  }

  window.AnveshakCarousel = {
    init: init,
    refresh: function () {
      // re-scan for carousels added dynamically
      document.querySelectorAll(CAROUSEL_SELECTOR).forEach(function (root) {
        if (!root.__carouselReady) {
          root.__carouselReady = true;
          init(root);
        }
      });
    }
  };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }
})();
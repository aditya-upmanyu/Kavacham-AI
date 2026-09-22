/* ====================================================================
   ANVESHAK AI — Animated Background Engine (#bg-canvas)
   --------------------------------------------------------------------
   Multi-depth neural node constellation:
     • parallax layers reacting to pointer movement
     • animated links whose opacity follows proximity
     • data pulses travelling along active links
     • soft ambient nebulae drawn in-canvas
   Fully DPI aware, pauses when the tab is hidden, honours
   prefers-reduced-motion (renders one static frame instead).
   ==================================================================== */

'use strict';

(function () {
  const canvas = document.getElementById('bg-canvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d', { alpha: true });
  if (!ctx) return;

  const REDUCED = window.matchMedia &&
    window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  const DPR_MAX = 2;
  const LINK_DIST = 150;      // px (CSS pixels)
  const PULSE_SPEED = 0.55;   // progress per frame

  let W = 0, H = 0, dpr = 1;
  let nodes = [];
  let pulses = [];
  let rafId = null;
  let frame = 0;

  // Pointer (smoothed) — starts centred so nothing is skewed on load
  const pointer = { x: 0, y: 0, tx: 0, ty: 0, active: false };

  const PAL = [
    [0, 212, 255],   // cyan
    [124, 58, 237],  // purple
    [34, 197, 94],   // green
    [99, 102, 241]   // indigo
  ];

  // ---------------------------------------------------------------- sizing
  function resize() {
    dpr = Math.min(window.devicePixelRatio || 1, DPR_MAX);
    W = window.innerWidth;
    H = window.innerHeight;
    canvas.width = Math.floor(W * dpr);
    canvas.height = Math.floor(H * dpr);
    canvas.style.width = W + 'px';
    canvas.style.height = H + 'px';
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    seed();
    if (REDUCED) drawStatic();
  }

  function seed() {
    const target = Math.max(38, Math.min(110, Math.round((W * H) / 16500)));
    nodes = [];
    for (let i = 0; i < target; i++) {
      const depth = 0.35 + Math.random() * 0.85; // parallax depth factor
      nodes.push({
        x: Math.random() * W,
        y: Math.random() * H,
        vx: (Math.random() - 0.5) * (0.16 + depth * 0.22),
        vy: (Math.random() - 0.5) * (0.16 + depth * 0.22),
        r: 0.7 + depth * 1.7,
        depth: depth,
        color: PAL[(Math.random() * PAL.length) | 0],
        tw: Math.random() * Math.PI * 2,   // twinkle phase
        tws: 0.008 + Math.random() * 0.02  // twinkle speed
      });
    }
    pulses = [];
  }

  // ------------------------------------------------------------- pointers
  function onMove(e) {
    pointer.tx = e.clientX;
    pointer.ty = e.clientY;
    if (!pointer.active) {
      pointer.active = true;
      pointer.x = pointer.tx;
      pointer.y = pointer.ty;
      glow(true);
    }
  }
  function onLeave() { pointer.active = false; glow(false); }

  // Cursor spotlight element is created by effects.js — coordinate opacity only
  function glow(on) {
    const g = document.querySelector('.cursor-glow');
    if (g) g.classList.toggle('is-on', !!on && !REDUCED);
  }

  // ---------------------------------------------------------------- draw
  function parallax(node) {
    // Nodes closer to the "camera" (higher depth) shift more
    const dx = (pointer.x - W / 2) * 0.022 * node.depth;
    const dy = (pointer.y - H / 2) * 0.022 * node.depth;
    return { x: node.x + dx, y: node.y + dy };
  }

  function step() {
    frame++;
    ctx.clearRect(0, 0, W, H);

    // smooth pointer follow
    pointer.x += (pointer.tx - pointer.x) * 0.06;
    pointer.y += (pointer.ty - pointer.y) * 0.06;

    // --- update nodes ---
    for (let i = 0; i < nodes.length; i++) {
      const n = nodes[i];
      n.x += n.vx;
      n.y += n.vy;
      n.tw += n.tws;

      if (n.x < -40) n.x = W + 40;
      else if (n.x > W + 40) n.x = -40;
      if (n.y < -40) n.y = H + 40;
      else if (n.y > H + 40) n.y = -40;
    }

    // --- links ---
    const pts = nodes.map(parallax);
    ctx.lineWidth = 0.7;

    for (let i = 0; i < nodes.length; i++) {
      const a = pts[i];
      for (let j = i + 1; j < nodes.length; j++) {
        const b = pts[j];
        const dx = a.x - b.x;
        const dy = a.y - b.y;
        const d2 = dx * dx + dy * dy;
        if (d2 > LINK_DIST * LINK_DIST) continue;

        const d = Math.sqrt(d2);
        const alpha = (1 - d / LINK_DIST) * 0.42 *
          Math.min(nodes[i].depth, nodes[j].depth);

        const c = nodes[i].color;
        ctx.strokeStyle = 'rgba(' + c[0] + ',' + c[1] + ',' + c[2] + ',' + alpha.toFixed(3) + ')';
        ctx.beginPath();
        ctx.moveTo(a.x, a.y);
        ctx.lineTo(b.x, b.y);
        ctx.stroke();

        // occasionally launch a data pulse along a strong link
        if (!REDUCED && alpha > 0.22 && pulses.length < 26 && Math.random() < 0.00035) {
          pulses.push({ ax: a.x, ay: a.y, bx: b.x, by: b.y, t: 0, c: nodes[i].color });
        }
      }
    }

    // --- pulses ---
    for (let k = pulses.length - 1; k >= 0; k--) {
      const p = pulses[k];
      p.t += PULSE_SPEED * 0.02;
      if (p.t >= 1) { pulses.splice(k, 1); continue; }
      const x = p.ax + (p.bx - p.ax) * p.t;
      const y = p.ay + (p.by - p.ay) * p.t;
      const fade = Math.sin(p.t * Math.PI);

      const grad = ctx.createRadialGradient(x, y, 0, x, y, 9);
      grad.addColorStop(0, 'rgba(255,255,255,' + (0.85 * fade).toFixed(3) + ')');
      grad.addColorStop(0.35, 'rgba(' + p.c[0] + ',' + p.c[1] + ',' + p.c[2] + ',' + (0.55 * fade).toFixed(3) + ')');
      grad.addColorStop(1, 'rgba(' + p.c[0] + ',' + p.c[1] + ',' + p.c[2] + ',0)');
      ctx.fillStyle = grad;
      ctx.beginPath();
      ctx.arc(x, y, 9, 0, Math.PI * 2);
      ctx.fill();
    }

    // --- nodes ---
    for (let i = 0; i < nodes.length; i++) {
      const n = nodes[i];
      const p = pts[i];
      const c = n.color;
      const twinkle = 0.55 + Math.sin(n.tw) * 0.35; // 0.2 .. 0.9

      // outer halo
      const halo = ctx.createRadialGradient(p.x, p.y, 0, p.x, p.y, n.r * 6);
      halo.addColorStop(0, 'rgba(' + c[0] + ',' + c[1] + ',' + c[2] + ',' + (0.24 * twinkle).toFixed(3) + ')');
      halo.addColorStop(1, 'rgba(' + c[0] + ',' + c[1] + ',' + c[2] + ',0)');
      ctx.fillStyle = halo;
      ctx.beginPath();
      ctx.arc(p.x, p.y, n.r * 6, 0, Math.PI * 2);
      ctx.fill();

      // core
      ctx.fillStyle = 'rgba(' + c[0] + ',' + c[1] + ',' + c[2] + ',' + (0.55 + twinkle * 0.45).toFixed(3) + ')';
      ctx.beginPath();
      ctx.arc(p.x, p.y, n.r, 0, Math.PI * 2);
      ctx.fill();
    }

    // --- pointer web: connect nearby nodes to the cursor ---
    if (pointer.active) {
      for (let i = 0; i < nodes.length; i++) {
        const p = pts[i];
        const dx = p.x - pointer.x;
        const dy = p.y - pointer.y;
        const d2 = dx * dx + dy * dy;
        if (d2 > 240 * 240) continue;
        const a = (1 - Math.sqrt(d2) / 240) * 0.5;
        ctx.strokeStyle = 'rgba(0,212,255,' + a.toFixed(3) + ')';
        ctx.lineWidth = 0.8;
        ctx.beginPath();
        ctx.moveTo(pointer.x, pointer.y);
        ctx.lineTo(p.x, p.y);
        ctx.stroke();
      }

      const ring = ctx.createRadialGradient(pointer.x, pointer.y, 0, pointer.x, pointer.y, 70);
      ring.addColorStop(0, 'rgba(0,212,255,0.20)');
      ring.addColorStop(1, 'rgba(0,212,255,0)');
      ctx.fillStyle = ring;
      ctx.beginPath();
      ctx.arc(pointer.x, pointer.y, 70, 0, Math.PI * 2);
      ctx.fill();
    }
  }

  function drawStatic() {
    // Single frame for reduced-motion users
    for (let i = 0; i < 1; i++) step();
  }

  function loop() {
    step();
    rafId = window.requestAnimationFrame(loop);
  }

  function start() {
    if (REDUCED) { drawStatic(); return; }
    if (rafId === null) rafId = window.requestAnimationFrame(loop);
  }
  function stop() {
    if (rafId !== null) { window.cancelAnimationFrame(rafId); rafId = null; }
  }

  // ------------------------------------------------------------- wiring
  window.addEventListener('resize', debounce(resize, 150), { passive: true });
  window.addEventListener('pointermove', onMove, { passive: true });
  window.addEventListener('pointerdown', onMove, { passive: true });
  document.addEventListener('pointerleave', onLeave);
  document.addEventListener('visibilitychange', function () {
    document.hidden ? stop() : start();
  });

  function debounce(fn, ms) {
    let t;
    return function () {
      clearTimeout(t);
      t = setTimeout(fn, ms);
    };
  }

  resize();
  start();

  // Expose a tiny API for other modules
  window.AnveshakBackground = { start: start, stop: stop, resize: resize };
})();

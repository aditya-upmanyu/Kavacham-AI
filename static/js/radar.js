/* ====================================================================
   ANVESHAK AI — Live Threat Radar (canvas)
   --------------------------------------------------------------------
   Rotating sweep, pulsing blips and a threat-level driven colour ramp.
   Used by templates that render <canvas id="threat-radar-canvas">.

   Public API:
     window.setRadarThreat(percent)  – 0..100 threat ratio
     window.radarAddBlip(kind)       – 'spam' | 'safe'  (manual ping)
   ==================================================================== */

'use strict';

(function () {
  const canvas = document.getElementById('threat-radar-canvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  if (!ctx) return;

  const REDUCED = window.matchMedia &&
    window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  let size = 240;         // css px (square)
  let cx = 0, cy = 0, R = 0;
  let dpr = 1;
  let threat = 0;         // 0..100
  let targetThreat = 0;
  let sweep = 0;          // radians
  let raf = null;

  // Blip model: angle, ring (0..1), kind, birth time
  const blips = [];
  const MAX_BLIPS = 14;

  function layout() {
    const parent = canvas.parentElement;
    const avail = parent ? parent.clientWidth - 6 : 260;
    size = Math.max(180, Math.min(280, avail));
    dpr = Math.min(window.devicePixelRatio || 1, 2);

    canvas.style.width = size + 'px';
    canvas.style.height = size + 'px';
    canvas.width = Math.floor(size * dpr);
    canvas.height = Math.floor(size * dpr);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

    cx = size / 2;
    cy = size / 2;
    R = size / 2 - 6;
  }

  function seedBlips() {
    blips.length = 0;
    const spamCount = Math.round((threat / 100) * 7);
    const safeCount = 5 - Math.min(5, Math.round((threat / 100) * 3));
    for (let i = 0; i < spamCount; i++) pushBlip('spam', true);
    for (let i = 0; i < safeCount + 2; i++) pushBlip('safe', true);
  }

  function pushBlip(kind, immediate) {
    blips.push({
      a: Math.random() * Math.PI * 2,
      r: 0.25 + Math.random() * 0.7,   // radial position 0..1
      kind: kind,
      born: immediate ? -1 : performance.now(),
      drift: (Math.random() - 0.5) * 0.0006
    });
    if (blips.length > MAX_BLIPS) blips.shift();
  }

  // --------------------------------------------------------------- draw
  function draw(now) {
    ctx.clearRect(0, 0, size, size);
    threat += (targetThreat - threat) * 0.05;

    // Background disc
    const bg = ctx.createRadialGradient(cx, cy, 0, cx, cy, R);
    bg.addColorStop(0, 'rgba(0,212,255,0.06)');
    bg.addColorStop(0.7, 'rgba(6,12,26,0.35)');
    bg.addColorStop(1, 'rgba(4,8,18,0.55)');
    ctx.fillStyle = bg;
    ctx.beginPath();
    ctx.arc(cx, cy, R, 0, Math.PI * 2);
    ctx.fill();

    // Rings
    ctx.lineWidth = 1;
    for (let i = 1; i <= 4; i++) {
      const rr = (R / 4) * i;
      ctx.strokeStyle = 'rgba(0,212,255,' + (i === 4 ? 0.34 : 0.14).toFixed(2) + ')';
      ctx.beginPath();
      ctx.arc(cx, cy, rr, 0, Math.PI * 2);
      ctx.stroke();
    }

    // Cross hairs
    ctx.strokeStyle = 'rgba(0,212,255,0.14)';
    ctx.beginPath();
    ctx.moveTo(cx - R, cy); ctx.lineTo(cx + R, cy);
    ctx.moveTo(cx, cy - R); ctx.lineTo(cx, cy + R);
    ctx.stroke();

    // Diagonal graticule
    ctx.strokeStyle = 'rgba(0,212,255,0.07)';
    for (let k = 0; k < 4; k++) {
      const a = (Math.PI / 4) + (k * Math.PI / 2);
      ctx.beginPath();
      ctx.moveTo(cx, cy);
      ctx.lineTo(cx + Math.cos(a) * R, cy + Math.sin(a) * R);
      ctx.stroke();
    }

    // Sweep
    if (!REDUCED) sweep = (sweep + 0.016) % (Math.PI * 2);
    const sweepGrad = ctx.createConicGradient
      ? ctx.createConicGradient(sweep - 0.9, cx, cy)
      : null;

    if (sweepGrad) {
      sweepGrad.addColorStop(0, 'rgba(0,212,255,0)');
      sweepGrad.addColorStop(0.78, 'rgba(0,212,255,0.02)');
      sweepGrad.addColorStop(0.97, 'rgba(0,212,255,0.30)');
      sweepGrad.addColorStop(1, 'rgba(0,212,255,0)');
      ctx.fillStyle = sweepGrad;
      ctx.beginPath();
      ctx.arc(cx, cy, R, 0, Math.PI * 2);
      ctx.fill();
    } else {
      // Fallback: rotating gradient beam
      ctx.save();
      ctx.translate(cx, cy);
      ctx.rotate(sweep);
      const beam = ctx.createLinearGradient(0, 0, R, 0);
      beam.addColorStop(0, 'rgba(0,212,255,0.28)');
      beam.addColorStop(1, 'rgba(0,212,255,0)');
      ctx.fillStyle = beam;
      ctx.beginPath();
      ctx.moveTo(0, 0);
      ctx.arc(0, 0, R, -0.35, 0);
      ctx.closePath();
      ctx.fill();
      ctx.restore();
    }

    // Sweep leading edge
    ctx.strokeStyle = 'rgba(0,212,255,0.65)';
    ctx.lineWidth = 1.4;
    ctx.beginPath();
    ctx.moveTo(cx, cy);
    ctx.lineTo(cx + Math.cos(sweep) * R, cy + Math.sin(sweep) * R);
    ctx.stroke();

    // Blips
    for (let i = 0; i < blips.length; i++) {
      const b = blips[i];
      b.a += b.drift;

      const bx = cx + Math.cos(b.a) * R * b.r;
      const by = cy + Math.sin(b.a) * R * b.r;
      const spam = b.kind === 'spam';
      const col = spam ? '239,68,68' : '34,197,94';

      // Brighten when the sweep passes over the blip
      let delta = b.a - sweep;
      while (delta < 0) delta += Math.PI * 2;
      while (delta > Math.PI * 2) delta -= Math.PI * 2;
      const lit = Math.max(0, 1 - delta / (Math.PI * 1.5));

      // Ripple every time the sweep hits it
      if (!REDUCED && lit > 0.985 && b.born > 0) b.born = now;

      const age = b.born > 0 ? (now - b.born) / 1600 : 1;
      if (age < 1) {
        ctx.strokeStyle = 'rgba(' + col + ',' + (0.5 * (1 - age)).toFixed(3) + ')';
        ctx.lineWidth = 1.5;
        ctx.beginPath();
        ctx.arc(bx, by, 4 + age * 22, 0, Math.PI * 2);
        ctx.stroke();
      }

      const glowR = 5 + lit * 6;
      const g = ctx.createRadialGradient(bx, by, 0, bx, by, glowR * 3);
      g.addColorStop(0, 'rgba(' + col + ',' + (0.5 + lit * 0.5).toFixed(2) + ')');
      g.addColorStop(0.4, 'rgba(' + col + ',' + (0.18 + lit * 0.3).toFixed(2) + ')');
      g.addColorStop(1, 'rgba(' + col + ',0)');
      ctx.fillStyle = g;
      ctx.beginPath();
      ctx.arc(bx, by, glowR * 3, 0, Math.PI * 2);
      ctx.fill();

      ctx.fillStyle = 'rgba(' + col + ',' + (0.65 + lit * 0.35).toFixed(2) + ')';
      ctx.beginPath();
      ctx.arc(bx, by, 3 + lit * 1.6, 0, Math.PI * 2);
      ctx.fill();
    }

    // Centre core
    const core = ctx.createRadialGradient(cx, cy, 0, cx, cy, 16);
    core.addColorStop(0, 'rgba(0,212,255,0.85)');
    core.addColorStop(1, 'rgba(0,212,255,0)');
    ctx.fillStyle = core;
    ctx.beginPath();
    ctx.arc(cx, cy, 16, 0, Math.PI * 2);
    ctx.fill();

    // Threat arc around the outside
    const threatFrac = threat / 100;
    if (threatFrac > 0.001) {
      const start = -Math.PI / 2;
      ctx.strokeStyle = threatFrac > 0.35
        ? 'rgba(239,68,68,0.85)'
        : 'rgba(34,197,94,0.85)';
      ctx.lineWidth = 3;
      ctx.lineCap = 'round';
      ctx.beginPath();
      ctx.arc(cx, cy, R + 3, start, start + Math.PI * 2 * threatFrac);
      ctx.stroke();
      ctx.lineCap = 'butt';
    }

    // Threat label
    ctx.font = '600 10px "JetBrains Mono", monospace';
    ctx.fillStyle = threat > 35 ? 'rgba(252,165,165,0.9)' : 'rgba(134,239,172,0.9)';
    ctx.textAlign = 'center';
    ctx.fillText('THREAT ' + threat.toFixed(1) + '%', cx, cy + R + 20);
  }

  function loop(now) {
    draw(now || performance.now());
    raf = window.requestAnimationFrame(loop);
  }

  function start() {
    if (raf === null) raf = window.requestAnimationFrame(loop);
  }
  function stop() {
    if (raf !== null) { cancelAnimationFrame(raf); raf = null; }
  }

  // ------------------------------------------------------------- public
  window.setRadarThreat = function (pct) {
    const v = Number(pct);
    if (isNaN(v)) return;
    targetThreat = Math.max(0, Math.min(100, v));
    seedBlips();
  };

  window.radarAddBlip = function (kind) {
    pushBlip(kind === 'spam' ? 'spam' : 'safe', false);
  };

  // ------------------------------------------------------------ wiring
  let rt;
  window.addEventListener('resize', function () {
    clearTimeout(rt);
    rt = setTimeout(function () { layout(); }, 150);
  }, { passive: true });

  document.addEventListener('visibilitychange', function () {
    document.hidden ? stop() : start();
  });

  layout();
  threat = targetThreat = 0;
  seedBlips();
  start();
})();

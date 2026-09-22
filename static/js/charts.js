/* ====================================================================
   ANVESHAK AI — Dashboard Charts & Graphs (Chart.js)
   --------------------------------------------------------------------
   Provides:
     • Threat distribution doughnut        (#chart-distribution)
     • Confidence trend line               (#chart-trend)
     • Model score radar                   (#chart-radar-metrics)
     • Accuracy gauge                      (#chart-gauge-acc)
     • Metrics comparison bar              (#chart-metrics-bar)
     • Dataset split doughnut              (#chart-split)
     • Gmail page: spam/ham doughnut       (#chart-threat-pie)
     • Gmail page: per-email confidence    (#chart-confidence)
     • Gmail page: avg. confidence gauge   (#chart-avg-gauge)

   Gracefully no-ops when Chart.js is unavailable (offline demo).
   ==================================================================== */

'use strict';

(function () {
  if (typeof window.Chart === 'undefined') {
    console.warn('[charts] Chart.js not loaded — charts disabled.');
    window.ANVESHAK_CHARTS = {
      updateIndexDashboard: function () {},
      initPerformance: function () {},
      initGmailDashboard: function () {},
      resizeAll: function () {}
    };
    return;
  }

  const Chart = window.Chart;
  const registry = {};             // canvasId -> Chart instance

  const COLORS = {
    cyan: '#00d4ff',
    cyanSoft: 'rgba(0,212,255,0.35)',
    purple: '#a78bfa',
    indigo: '#818cf8',
    green: '#22c55e',
    greenSoft: 'rgba(34,197,94,0.35)',
    red: '#ef4444',
    redSoft: 'rgba(239,68,68,0.35)',
    amber: '#f59e0b',
    muted: '#8b9ab8',
    grid: 'rgba(255,255,255,0.06)',
    track: 'rgba(255,255,255,0.06)'
  };

  // ------------------------------------------------------------ defaults
  Chart.defaults.color = COLORS.muted;
  Chart.defaults.font.family = "'Inter', -apple-system, BlinkMacSystemFont, sans-serif";
  Chart.defaults.font.size = 11;

  const baseAnimation = { duration: 1400, easing: 'easeOutQuart' };

  function baseTooltip() {
    return {
      backgroundColor: 'rgba(11,17,32,0.96)',
      titleColor: '#e8ecf4',
      bodyColor: '#c5d0e4',
      borderColor: 'rgba(0,212,255,0.3)',
      borderWidth: 1,
      padding: 12,
      cornerRadius: 8,
      displayColors: true,
      boxPadding: 4,
      titleFont: { family: "'JetBrains Mono', monospace", size: 11 },
      bodyFont: { size: 12 }
    };
  }

  function baseLegend(color) {
    return {
      labels: {
        color: color || COLORS.muted,
        boxWidth: 9,
        boxHeight: 9,
        usePointStyle: true,
        pointStyle: 'circle',
        padding: 12,
        font: { size: 11 }
      }
    };
  }

  // Center-text plugin for doughnuts / gauges
  const centerText = {
    id: 'anveshakCenterText',
    afterDraw: function (chart, _args, opts) {
      if (!opts || !opts.render || !opts.text && opts.text !== '' && opts.text !== 0) return;
      const { ctx, chartArea } = chart;
      if (!chartArea) return;
      const x = (chartArea.left + chartArea.right) / 2;
      const y = (chartArea.top + chartArea.bottom) / 2;

      ctx.save();
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';

      if (opts.sub) {
        ctx.font = "600 10px 'JetBrains Mono', monospace";
        ctx.fillStyle = 'rgba(139,154,184,0.85)';
        const subY = y + (opts.size ? opts.size / 2 + 12 : 30);
        ctx.fillText(opts.sub, x, subY);
      }
      ctx.font = (opts.font || "800 30px 'JetBrains Mono', monospace");
      ctx.fillStyle = opts.color || '#e8ecf4';
      ctx.shadowColor = opts.glow || 'rgba(0,212,255,0.6)';
      ctx.shadowBlur = 18;
      ctx.fillText(String(opts.text), x, y - (opts.sub ? 10 : 0));
      ctx.restore();
    }
  };
  Chart.register(centerText);

  // -------------------------------------------------------------- helpers
  function destroy(id) {
    if (registry[id]) {
      try { registry[id].destroy(); } catch (e) {}
      delete registry[id];
    }
  }

  function getCanvas(id) {
    const el = document.getElementById(id);
    return el ? el : null;
  }

  function isHidden(el) {
    // returns true when chart canvas sits inside a display:none ancestor
    let node = el;
    while (node && node !== document) {
      const cs = getComputedStyle(node);
      if (cs.display === 'none' || cs.visibility === 'hidden') return true;
      node = node.parentElement;
    }
    return false;
  }

  // Prevent double RAF re-render races when a page becomes visible
  let resizeTimer = null;
  function scheduleResize() {
    if (resizeTimer) return;
    resizeTimer = window.setTimeout(function () {
      resizeTimer = null;
      Object.keys(registry).forEach(function (id) {
        const inst = registry[id];
        if (inst && inst.canvas && !isHidden(inst.canvas)) inst.resize();
      });
    }, 60);
  }

  function create(id, config) {
    const canvas = getCanvas(id);
    if (!canvas) return null;
    destroy(id);
    const inst = new Chart(canvas, config);
    registry[id] = inst;
    return inst;
  }

  function setEmpty(id, show) {
    const wrap = getCanvas(id);
    if (!wrap) return;
    const parent = wrap.closest('.chart-wrap') || wrap.parentElement;
    if (!parent) return;
    let ov = parent.querySelector('.chart-empty');
    if (show && !ov) {
      ov = document.createElement('div');
      ov.className = 'chart-empty';
      ov.innerHTML =
        '<span class="pulse-dot"></span><strong>Awaiting data</strong>' +
        '<span>Run an analysis to populate this view</span>';
      parent.appendChild(ov);
    } else if (!show && ov) {
      ov.remove();
    }
  }

  function defaultScales(valueSuffix) {
    return {
      r: {
        angleLines: { color: COLORS.grid },
        grid: { color: COLORS.grid },
        pointLabels: { color: COLORS.muted, font: { size: 11 } },
        ticks: {
          backdropColor: 'transparent',
          color: 'rgba(139,154,184,0.7)',
          callback: function (v) { return v + (valueSuffix || ''); },
          stepSize: 25,
          max: 100
        }
      },
      x: {
        grid: { color: COLORS.grid },
        ticks: { color: COLORS.muted, maxRotation: 0, autoSkip: true, maxTicksLimit: 12 }
      },
      y: {
        beginAtZero: true,
        max: 100,
        grid: { color: COLORS.grid },
        ticks: { color: COLORS.muted, callback: function (v) { return v + '%'; } }
      }
    };
  }

  function doughnutConfig(labels, data, colors, centerOpts, extra) {
    return {
      type: 'doughnut',
      data: {
        labels: labels,
        datasets: [{
          data: data,
          backgroundColor: colors,
          borderColor: 'rgba(6,10,20,0.9)',
          borderWidth: 3,
          hoverOffset: 8,
          borderRadius: 4,
          spacing: 2
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: '64%',
        animation: baseAnimation,
        plugins: {
          legend: baseLegend(),
          tooltip: baseTooltip(),
          anveshakCenterText: centerOpts || { render: false }
        }
      }
    };
  }

  function gaugeConfig(value, max, color, centerOpts) {
    const safe = Math.max(0, Math.min(max, value));
    return {
      type: 'doughnut',
      data: {
        labels: ['Score', 'Remainder'],
        datasets: [{
          data: [safe, max - safe],
          backgroundColor: [color, COLORS.track],
          borderWidth: 0,
          borderRadius: 8
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        circumference: 270,
        rotation: -135,
        cutout: '72%',
        animation: Object.assign({}, baseAnimation, {
          onComplete: function () {}
        }),
        plugins: {
          legend: { display: false },
          tooltip: { enabled: false },
          anveshakCenterText: centerOpts || { render: false }
        }
      }
    };
  }

  function lineConfig(labels, data, color, fillColor, opts) {
    const gradId = 'trend' + Math.random().toString(36).slice(2, 7);
    return {
      type: 'line',
      data: {
        labels: labels,
        datasets: [{
          label: opts && opts.label || 'Confidence',
          data: data,
          borderColor: color,
          backgroundColor: fillColor || 'rgba(0,212,255,0.18)',
          fill: true,
          tension: 0.45,
          borderWidth: 2.5,
          pointRadius: 3.5,
          pointHoverRadius: 6,
          pointBackgroundColor: '#0a0e1a',
          pointBorderColor: color,
          pointBorderWidth: 2
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        animation: Object.assign({}, baseAnimation, {
          // draw line progressively when it has > 2 points
          x: { type: 'number', easing: 'easeOutQuart', duration: 1400, from: NaN, delay: 0 },
          y: { type: 'number', easing: 'easeOutQuart', duration: 1400, from: NaN, delay: 0 }
        }),
        interaction: { mode: 'index', intersect: false },
        plugins: {
          legend: { display: !!(opts && opts.legend) },
          tooltip: baseTooltip()
        },
        scales: defaultScales(),
        elements: {
          line: { tension: 0.45 },
          point: { radius: 3.5 }
        }
      }
    };
  }

  function barConfig(labels, datasets, opts) {
    return {
      type: 'bar',
      data: { labels: labels, datasets: datasets },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        animation: baseAnimation,
        plugins: {
          legend: opts && opts.legend ? baseLegend() : { display: false },
          tooltip: baseTooltip()
        },
        scales: Object.assign(defaultScales(), {
          x: {
            grid: { display: false },
            ticks: { color: COLORS.muted, font: { size: 11 } }
          },
          y: {
            beginAtZero: true,
            max: 100,
            grid: { color: COLORS.grid },
            ticks: { color: COLORS.muted, callback: function (v) { return v + '%'; } }
          }
        }),
        borderRadius: 7,
        maxBarThickness: 44
      }
    };
  }

  /* =================================================================
     SPA DASHBOARD (index.html)
     ================================================================= */

  function countsFrom(history) {
    const total = history.length;
    const spam = history.filter(function (h) { return h.classification === 'Spam'; }).length;
    return { total: total, spam: spam, ham: total - spam };
  }

  function updateIndexDashboard(history) {
    history = history || [];
    const counts = countsFrom(history);
    const metrics = (window.FLASK_DATA && window.FLASK_DATA.metrics) || {};

    // Distribution doughnut
    const distData = [counts.ham, counts.spam];
    if (counts.total === 0) {
      setEmpty('chart-distribution', true);
      destroy('chart-distribution');
    } else {
      setEmpty('chart-distribution', false);
      create('chart-distribution', doughnutConfig(
        ['Legitimate', 'Spam'],
        distData,
        [COLORS.greenSoft, COLORS.redSoft],
        {
          render: true,
          text: counts.total,
          sub: 'ANALYSES',
          size: 26,
          font: "800 26px 'JetBrains Mono', monospace",
          color: '#e8ecf4',
          glow: 'rgba(0,212,255,0.5)'
        }
      ));
    }

    // Confidence trend line
    const recent = history.slice(0, 12).reverse();
    if (recent.length < 2) {
      setEmpty('chart-trend', true);
      destroy('chart-trend');
    } else {
      setEmpty('chart-trend', false);
      create('chart-trend', lineConfig(
        recent.map(function (h) {
          const d = new Date(h.timestamp);
          return (isNaN(d.getTime()) ? '—' : d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }));
        }),
        recent.map(function (h) { return Number(h.confidence) || 0; }),
        COLORS.cyan,
        'rgba(0,212,255,0.16)',
        { label: 'Confidence %' }
      ));
    }

    // Model radar
    const radarLabels = ['Accuracy', 'Precision', 'Recall', 'F1 Score', 'FPR Safety'];
    const radarVals = [
      Number(metrics.accuracy) || 99.52,
      Number(metrics.precision) || 100,
      Number(metrics.recall) || 99.03,
      Number(metrics.f1_score) || 99.51,
      100 - (Number(metrics.false_positive_rate) || 0)
    ];
    create('chart-radar-metrics', {
      type: 'radar',
      data: {
        labels: radarLabels,
        datasets: [{
          label: 'Score %',
          data: radarVals,
          borderColor: COLORS.cyan,
          backgroundColor: 'rgba(0,212,255,0.14)',
          borderWidth: 2,
          pointBackgroundColor: COLORS.cyan,
          pointBorderColor: '#0a0e1a',
          pointBorderWidth: 2,
          pointRadius: 4,
          pointHoverRadius: 6,
          fill: true
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        animation: Object.assign({}, baseAnimation, { delay: 200 }),
        plugins: {
          legend: { display: false },
          tooltip: baseTooltip()
        },
        scales: {
          r: {
            angleLines: { color: COLORS.grid },
            grid: { color: COLORS.grid },
            pointLabels: { color: COLORS.muted, font: { size: 11 } },
            ticks: {
              backdropColor: 'transparent',
              color: 'rgba(139,154,184,0.6)',
              callback: function (v) { return v + '%'; },
              stepSize: 25,
              max: 100
            },
            suggestedMin: 0,
            suggestedMax: 100
          }
        }
      }
    });

    // Accuracy gauge
    const acc = Number(metrics.accuracy) || 99.52;
    create('chart-gauge-acc', gaugeConfig(
      acc, 100, 'rgba(0,212,255,0.85)',
      { render: true, text: acc + '%', sub: 'MODEL ACCURACY', size: 30, font: "800 30px 'JetBrains Mono', monospace", color: '#ffffff', glow: 'rgba(0,212,255,0.7)' }
    ));
  }

  /* =================================================================
     MODEL PERFORMANCE PAGE (index.html)
     ================================================================= */
  let performanceBuilt = false;

  function initPerformance(metrics) {
    metrics = metrics || (window.FLASK_DATA && window.FLASK_DATA.metrics) || {};

    const acc = Number(metrics.accuracy) || 99.52;
    const prec = Number(metrics.precision) || 100;
    const rec = Number(metrics.recall) || 99.03;
    const f1 = Number(metrics.f1_score) || 99.51;
    const fpr = Number(metrics.false_positive_rate) || 0;

    create('chart-metrics-bar', barConfig(
      ['Accuracy', 'Precision', 'Recall', 'F1', 'FPR'],
      [{
        data: [acc, prec, rec, f1, fpr],
        backgroundColor: [
          'rgba(0,212,255,0.85)',
          'rgba(99,102,241,0.85)',
          'rgba(167,139,250,0.85)',
          'rgba(34,197,94,0.85)',
          'rgba(239,68,68,0.8)'
        ],
        borderWidth: 0,
        hoverBackgroundColor: [
          COLORS.cyan, COLORS.indigo, COLORS.purple, COLORS.green, COLORS.red
        ]
      }]
    ));

    create('chart-split', doughnutConfig(
      ['Training', 'Validation', 'Test'],
      [
        Number(metrics.training_samples) || 965,
        Number(metrics.validation_samples) || 208,
        Number(metrics.test_samples) || 207
      ],
      ['rgba(0,212,255,0.85)', 'rgba(167,139,250,0.85)', 'rgba(34,197,94,0.85)'],
      {
        render: true,
        text: Number(metrics.dataset_total) || 1380,
        sub: 'SAMPLES',
        size: 24,
        font: "800 24px 'JetBrains Mono', monospace",
        color: '#e8ecf4',
        glow: 'rgba(124,58,237,0.6)'
      }
    ));

    performanceBuilt = true;
    scheduleResize();
  }

  /* =================================================================
     GMAIL DASHBOARD (dashboard.html)
     ================================================================= */
  function initGmailDashboard(data) {
    data = data || window.GMAIL_DASH_DATA || { stats: { total: 0, spam: 0, ham: 0, avg_confidence: 0 } };
    const stats = data.stats || { total: 0, spam: 0, ham: 0, avg_confidence: 0 };
    const emails = data.emails || [];

    // Doughnut
    if (stats.total > 0) {
      setEmpty('chart-threat-pie', false);
      create('chart-threat-pie', doughnutConfig(
        ['Legitimate', 'Spam'],
        [stats.ham, stats.spam],
        [COLORS.greenSoft, COLORS.redSoft],
        {
          render: true,
          text: stats.total,
          sub: 'SCANNED',
          size: 26,
          font: "800 26px 'JetBrains Mono', monospace",
          color: '#e8ecf4',
          glow: 'rgba(34,197,94,0.5)'
        }
      ));
    } else {
      setEmpty('chart-threat-pie', true);
      destroy('chart-threat-pie');
    }

    // Per-email confidence bars
    if (emails.length > 0) {
      setEmpty('chart-confidence', false);
      const labels = emails.map(function (e, i) {
        return '#' + (i + 1);
      });
      const conf = emails.map(function (e) { return Number(e.confidence) || 0; });
      const colors = emails.map(function (e) {
        return e.prediction === 'Spam'
          ? 'rgba(239,68,68,0.85)'
          : 'rgba(34,197,94,0.85)';
      });
      create('chart-confidence', barConfig(labels, [{
        data: conf,
        backgroundColor: colors,
        borderWidth: 0,
        hoverBackgroundColor: colors.map(function (c) { return c; })
      }]));
    } else {
      setEmpty('chart-confidence', true);
      destroy('chart-confidence');
    }

    // Avg confidence gauge
    const avg = Number(stats.avg_confidence) || 0;
    create('chart-avg-gauge', gaugeConfig(
      avg, 100, avg > 85 ? 'rgba(239,68,68,0.85)' : 'rgba(0,212,255,0.85)',
      { render: true, text: avg + '%', sub: 'AVG CONFIDENCE', size: 26, font: "800 26px 'JetBrains Mono', monospace", color: '#ffffff', glow: 'rgba(0,212,255,0.6)' }
    ));
  }

  /* =================================================================
     PUBLIC API
     ================================================================= */
  window.ANVESHAK_CHARTS = {
    updateIndexDashboard: updateIndexDashboard,
    initPerformance: initPerformance,
    ensurePerformance: function () {
      if (!performanceBuilt) initPerformance();
      else scheduleResize();
    },
    initGmailDashboard: initGmailDashboard,
    resizeAll: scheduleResize
  };
})();
/* ====================================================================
   KAVACHAM LAB — ENTITY GRAPH (Phase 8, Section 25)
   Layered SVG: CASE → EVIDENCE → indicators / senders. Every edge and
   attribute is sourced from /lab/api/intel/graph, which only emits
   relationships that real vault links support.
   ==================================================================== */
(function () {
  'use strict';

  var esc = window.LAB.esc;
  var fmtTs = window.LAB.fmtTs;

  var els = {
    caseSel: document.getElementById('graph-case'),
    reload: document.getElementById('graph-reload'),
    canvas: document.getElementById('graph-canvas'),
    foot: document.getElementById('graph-foot'),
    counts: document.getElementById('graph-counts'),
    nodePanel: document.getElementById('graph-node')
  };

  var NS = 'http://www.w3.org/2000/svg';
  var NODE_W = 170;
  var NODE_H = 34;
  var LAYER_GAP = 96;
  var NODE_GAP = 26;
  var PAD = 18;

  var TYPE_COLORS = {
    CASE: '#8ab4f8',
    EVIDENCE: '#5f6b7a',
    URL: '#d18063',
    DOMAIN: '#c792ea',
    IPv4: '#82aaff',
    IPv6: '#82aaff',
    EMAIL: '#7bd88f',
    'SHA-256': '#f78c6c',
    'SHA-1': '#f78c6c',
    MD5: '#f78c6c',
    FILENAME: '#9e9e9e',
    SENDER: '#4ec9b0',
    'REPLY-TO': '#4ec9b0',
    'RETURN-PATH': '#4ec9b0',
    OTHER: '#9e9e9e'
  };

  function el(name, attrs, parent) {
    var node = document.createElementNS(NS, name);
    Object.keys(attrs || {}).forEach(function (k) {
      node.setAttribute(k, attrs[k]);
    });
    if (parent) { parent.appendChild(node); }
    return node;
  }

  function nodeColor(type) {
    return TYPE_COLORS[type] || '#9e9e9e';
  }

  function riskStroke(risk) {
    if (risk >= 50) { return '#ff5370'; }
    if (risk >= 20) { return '#ffcb6b'; }
    return 'rgba(255,255,255,0.25)';
  }

  function truncate(s, n) {
    s = String(s || '');
    return s.length > n ? s.slice(0, n - 1) + '…' : s;
  }

  function renderNodeDetail(node) {
    if (!node) {
      els.nodePanel.innerHTML =
        '<p class="lab-xs lab-dim" style="margin:0;">Select a node on the graph to inspect its real provenance — evidence, cases, analyses and risk.</p>';
      return;
    }
    var analyses = (node.analyses || []).length
      ? '<ul class="lab-list">' + node.analyses.slice(0, 5).map(function (a) {
          return '<li><a class="lab-link lab-mono lab-xs" href="/lab/analysis/' +
            encodeURIComponent(a.analysis_ref || a) + '">' +
            esc(a.analysis_ref || a) + '</a>' +
            (a.analysis_type ? ' <span class="lab-xs lab-dim">' + esc(a.analysis_type) +
              ' → ' + esc(a.verdict) + ' (risk ' + esc(a.risk_score) + ')</span>' : '') +
            '</li>';
        }).join('') + '</ul>'
      : '<p class="lab-xs lab-dim">None yet.</p>';
    var evRefs = (node.related_evidence || []).length
      ? '<ul class="lab-list">' + node.related_evidence.slice(0, 8).map(function (r) {
          return '<li><a class="lab-link lab-mono lab-xs" href="/lab/evidence/' +
            encodeURIComponent(r) + '">' + esc(r) + '</a></li>';
        }).join('') + '</ul>'
      : '<p class="lab-xs lab-dim">None.</p>';
    var cases = (node.related_cases || []).length
      ? '<ul class="lab-list">' + node.related_cases.slice(0, 8).map(function (r) {
          return '<li><a class="lab-link lab-mono lab-xs" href="/lab/cases/' +
            encodeURIComponent(r) + '">' + esc(r) + '</a></li>';
        }).join('') + '</ul>'
      : '<p class="lab-xs lab-dim">None.</p>';

    els.nodePanel.innerHTML =
      '<div class="lab-badge" style="background:' + nodeColor(node.type) + ';color:#06101f;">' +
        esc(node.type) + '</div>' +
      (node.status ? '<div class="lab-xs lab-dim" style="margin-top:6px;">status: ' +
        esc(node.status) + '</div>' : '') +
      '<div class="lab-mono lab-strong" style="word-break:break-all;margin-top:8px;">' +
        esc(node.label) + '</div>' +
      (node.evidence_type ? '<div class="lab-xs lab-dim">' + esc(node.evidence_type) +
        '</div>' : '') +
      '<dl class="lab-dl" style="margin-top:12px;">' +
        '<dt>FIRST SEEN</dt><dd class="lab-mono lab-xs">' + esc(fmtTs(node.first_seen)) + '</dd>' +
        '<dt>LAST SEEN</dt><dd class="lab-mono lab-xs">' + esc(fmtTs(node.last_seen)) + '</dd>' +
        '<dt>RISK (analysis-derived)</dt><dd class="lab-mono lab-xs">' +
          (node.risk ? esc(String(node.risk)) : '—') + '</dd>' +
      '</dl>' +
      '<h4 class="lab-subsection" style="margin:14px 0 6px;">RELATED EVIDENCE (' +
        (node.related_evidence || []).length + ')</h4>' + evRefs +
      '<h4 class="lab-subsection" style="margin:14px 0 6px;">RELATED CASES (' +
        (node.related_cases || []).length + ')</h4>' + cases +
      '<h4 class="lab-subsection" style="margin:14px 0 6px;">ANALYSES</h4>' + analyses;
  }

  function draw(graph) {
    els.canvas.innerHTML = '';
    els.foot.textContent = graph.note || 'Graph from vault relations.';
    els.counts.textContent = graph.node_count + ' nodes · ' + graph.edge_count + ' edges';

    var nodes = graph.nodes || [];
    var edges = graph.edges || [];
    if (!nodes.length) {
      els.canvas.innerHTML = '';
      els.canvas.appendChild(window.LAB.emptyState(
        '∅', 'NO GRAPH DATA',
        'This case has no evidence or linked indicators to draw yet.', null));
      return;
    }

    var layers = {};
    nodes.forEach(function (n) {
      var l = n.type === 'CASE' ? 0 : n.type === 'EVIDENCE' ? 1 : 2;
      (layers[l] = layers[l] || []).push(n);
    });

    var width = Math.max(560, (els.canvas.clientWidth || 900) - PAD * 2);
    var maxRow = 0;
    Object.keys(layers).forEach(function (l) {
      var count = layers[l].length;
      var needed = count * (NODE_W + NODE_GAP) + PAD;
      maxRow = Math.max(maxRow, needed);
    });
    width = Math.max(width, maxRow);
    var height = (Object.keys(layers).length) * LAYER_GAP + PAD * 2 + 30;

    var svg = el('svg', {
      width: width, height: height,
      viewBox: '0 0 ' + width + ' ' + height,
      role: 'img', 'aria-label': 'Entity graph for ' + graph.case_ref
    }, els.canvas);

    var pos = {};
    Object.keys(layers).forEach(function (l) {
      var items = layers[l];
      var rowW = items.length * (NODE_W + NODE_GAP) + NODE_GAP;
      var startX = (width - rowW) / 2 + NODE_GAP;
      items.forEach(function (n, i) {
        pos[n.id] = {
          x: startX + i * (NODE_W + NODE_GAP),
          y: PAD + parseInt(l, 10) * LAYER_GAP
        };
      });
    });

    // edges underneath
    edges.forEach(function (e) {
      var a = pos[e.from];
      var b = pos[e.to];
      if (!a || !b) { return; }
      var ax = a.x + NODE_W / 2, ay = a.y + NODE_H;
      var bx = b.x + NODE_W / 2, by = b.y;
      el('line', {
        x1: ax, y1: ay, x2: bx, y2: by,
        stroke: 'rgba(139,156,175,0.4)', 'stroke-width': 1.2
      }, svg);
      var mx = (ax + bx) / 2, my = (ay + by) / 2;
      el('text', {
        x: mx + 6, y: my - 4, fill: 'rgba(139,156,175,0.85)',
        'font-size': '9', 'font-family': 'JetBrains Mono, monospace'
      }, svg).textContent = e.relation;
      // arrowhead
      var ang = Math.atan2(by - ay, bx - ax);
      var ax2 = bx - 6 * Math.cos(ang), ay2 = by - 6 * Math.sin(ang);
      el('polygon', {
        points: [
          (ax2 - 5 * Math.sin(ang)) + ',' + (ay2 + 5 * Math.cos(ang)),
          (ax2 + 5 * Math.sin(ang)) + ',' + (ay2 - 5 * Math.cos(ang)),
          bx + ',' + by
        ].join(' '),
        fill: 'rgba(139,156,175,0.55)'
      }, svg);
    });

    // nodes on top
    nodes.forEach(function (n) {
      var p = pos[n.id];
      if (!p) { return; }
      var g = el('g', { transform: 'translate(' + p.x + ',' + p.y + ')' }, svg);
      g.style.cursor = 'pointer';
      var rect = el('rect', {
        width: NODE_W, height: NODE_H, rx: 6,
        fill: 'rgba(6,16,31,0.9)',
        stroke: riskStroke(n.risk),
        'stroke-width': n.risk ? 1.8 : 1
      }, g);
      el('rect', {
        x: 0, y: 0, width: 4, height: NODE_H, rx: 2,
        fill: nodeColor(n.type)
      }, g);
      el('text', {
        x: 12, y: 14, fill: nodeColor(n.type),
        'font-size': '9', 'font-family': 'JetBrains Mono, monospace',
        'font-weight': '700'
      }, g).textContent = n.type;
      el('text', {
        x: 12, y: 27, fill: '#e6edf3',
        'font-size': '10', 'font-family': 'JetBrains Mono, monospace'
      }, g).textContent = truncate(n.label, 20);
      g.addEventListener('click', function () { renderNodeDetail(n); });
      rect.setAttribute('tabindex', '0');
      rect.addEventListener('keydown', function (ev) {
        if (ev.key === 'Enter' || ev.key === ' ') { renderNodeDetail(n); }
      });
    });

    renderNodeDetail(null);
  }

  function loadCases() {
    return fetch('/lab/api/intel/graph', {
      headers: { 'Accept': 'application/json' }, credentials: 'same-origin'
    })
      .then(function (res) { return res.json(); })
      .then(function (body) {
        if (!body.success) { throw (body.error || {}); }
        var cases = body.data.cases || [];
        els.caseSel.innerHTML = '<option value="">SELECT CASE…</option>' +
          cases.map(function (c) {
            return '<option value="' + esc(c.case_ref) + '">' + esc(c.case_ref) +
              ' — ' + esc(c.title) + ' (' + (c.evidence_count || 0) + ' ev, ' +
              (c.ioc_count || 0) + ' ioc)</option>';
          }).join('');
        return cases;
      });
  }

  function loadGraph(caseRef) {
    els.foot.textContent = 'Building evidence-backed graph…';
    els.counts.textContent = '—';
    els.canvas.innerHTML =
      '<div class="lab-panel-body">' +
      '<div class="lab-skeleton lab-skeleton-line" style="width:82%;"></div>' +
      '<div class="lab-skeleton lab-skeleton-line" style="width:60%;"></div>' +
      '<div class="lab-skeleton lab-skeleton-line" style="width:70%;"></div>' +
      '</div>';
    fetch('/lab/api/intel/graph?case=' + encodeURIComponent(caseRef), {
      headers: { 'Accept': 'application/json' }, credentials: 'same-origin'
    })
      .then(function (res) { return res.json(); })
      .then(function (body) {
        if (!body.success) { throw (body.error || {}); }
        draw(body.data.graph || body.data);
      })
      .catch(function (err) {
        els.canvas.innerHTML = '';
        els.counts.textContent = '—';
        els.foot.textContent = err.message || 'Graph could not be built.';
      });
  }

  els.caseSel.addEventListener('change', function () {
    if (els.caseSel.value) { loadGraph(els.caseSel.value); }
  });
  els.reload.addEventListener('click', function () {
    loadCases().then(function () {
      if (els.caseSel.value) { loadGraph(els.caseSel.value); }
    });
  });

  loadCases().then(function (cases) {
    if (cases && cases.length) {
      els.caseSel.value = cases[0].case_ref;
      loadGraph(cases[0].case_ref);
    } else {
      els.canvas.innerHTML = '';
      els.canvas.appendChild(window.LAB.emptyState(
        '—', 'NO CASES',
        'Create an investigation first; the graph draws real case, evidence '
        + 'and indicator relations.', null));
      els.foot.textContent = 'No cases available.';
    }
  }).catch(function (err) {
    els.foot.textContent = err.message || 'Cases could not be loaded.';
  });
})();
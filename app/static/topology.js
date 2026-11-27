/* Netrik topology: Internet -> Gateway -> Network segment -> Devices. Segments are bubbles; devices inside them are members.
   Edges between devices exist only where there is evidence: tested reachability, observed traffic, or a restricted-site request. */
(function (root) {
  'use strict';
  var FONT = 'Inter, system-ui, "Segoe UI", sans-serif';
  var C = { ok: '#3fb8a0', new: '#d9a441', stale: '#66758a', unreviewed: '#8b98a9', bad: '#e0605a', info: '#5ea1e6', text: '#dde5ee', mut: '#8593a4',
            bg: '#0a0e13', node: '#101823', sim: '#d9a441', seg: '#3b7bd4' };
  var SP = 116, GAP = 70;

  function icons() { return root.ICONS || {}; }
  function svgUri(name, color, sw) {
    var inner = icons()[name] || icons()['circle-help'] || '';
    var s = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="' + color + '" stroke-width="' + (sw || 1.7) + '" stroke-linecap="round" stroke-linejoin="round">' + inner + '</svg>';
    return 'data:image/svg+xml;utf8,' + encodeURIComponent(s);
  }
  function iconFor(d) {
    var k = (d.kind || '').toLowerCase(), l = d.label || '';
    if (d.type === 'site') return 'globe';
    if (d.vantage || d.type === 'vantage') return 'radar';
    if (d.gateway || k.indexOf('gateway') >= 0) return 'router';
    if (k.indexOf('tv') >= 0 || /\btv\b|webos|bravia|roku|chromecast|firetv|smarttv/i.test(l)) return 'tv';
    if (/\b(ap|access.?point)\b|^ap-|wifi|wlan/i.test(l)) return 'wifi';
    if (k.indexOf('printer') >= 0) return 'printer';
    if (k.indexOf('mobile') >= 0 || /phone|iphone|galaxy|pixel|redmi|oneplus/i.test(l)) return 'smartphone';
    if (k.indexOf('camera') >= 0) return 'cctv';
    if (/srv|server|\bdb\b|-db|database|portal|nas|\bad-/i.test(l) || k.indexOf('linux') >= 0) return /db|database/i.test(l) ? 'database' : 'server';
    if (k.indexOf('network appliance') >= 0) return 'network';
    if (/lap|notebook/i.test(l) || k.indexOf('apple') >= 0) return 'laptop';
    if (k.indexOf('embedded') >= 0) return 'cpu';
    if (k.indexOf('windows') >= 0) return 'monitor';
    return 'circle-help';
  }
  function colorFor(d) {
    if (d.type === 'site') return C.bad;
    if (d.violation || d.sev === 'high') return C.bad;
    if (d.status === 'new') return C.new;
    if (d.status === 'stale') return C.stale;
    if (d.status === 'ok') return C.ok;
    return C.unreviewed;
  }
  function pulseFor(d) {
    if (d.type === 'site' || d.violation || d.sev === 'high') return { f: 4.2, a: 0.55, pad: 9 };
    if (d.status === 'new') return { f: 2.6, a: 0.4, pad: 8 };
    if (d.vantage || d.type === 'vantage') return { f: 1.7, a: 0.3, pad: 11 };
    return null;
  }
  function devNode(d, x, y, extra) {
    var color = colorFor(d), icon = iconFor(d), size = d.gateway ? 68 : ((d.vantage || d.type === 'vantage') ? 62 : 56);
    var nm = /^Unknown device/.test(d.label || '') ? 'Unknown device' : (d.label || '');
    var text = d.type === 'vantage' ? 'Test point\n' + (d.label || '') : d.type === 'site' ? nm + '\nrestricted site' : nm + (d.ip ? '\n' + d.ip : '');
    var data = Object.assign({}, d, { size: size, color: color, img: svgUri(icon, color), icon: icon, text: text, pulse: pulseFor(d) }, extra || {});
    return { group: 'nodes', data: data, position: { x: x, y: y }, classes: 'dev' + (d.type === 'site' ? ' site' : '') };
  }

  /* devices of one segment on concentric rings (centre first when crowded) */
  function ringLayout(n) {
    if (n <= 1) return { pos: [{ x: 0, y: 0 }], r: 0 };
    if (n <= 7) {
      var r = n === 2 ? SP / 2 : SP / (2 * Math.sin(Math.PI / n)), pos = [];
      for (var i = 0; i < n; i++) { var a = -Math.PI / 2 + i * 2 * Math.PI / n; pos.push({ x: r * Math.cos(a), y: r * Math.sin(a) }); }
      return { pos: pos, r: r };
    }
    var out = [{ x: 0, y: 0 }], ring = 1, left = n - 1, maxr = 0;
    while (left > 0) {
      var rr = ring * SP, cap = Math.floor(2 * Math.PI * rr / SP), take = Math.min(cap, left), off = ring % 2 ? -Math.PI / 2 : -Math.PI / 2 + Math.PI / cap;
      for (var j = 0; j < take; j++) { var ang = off + j * 2 * Math.PI / take; out.push({ x: rr * Math.cos(ang), y: rr * Math.sin(ang) }); }
      left -= take; maxr = rr; ring++;
    }
    return { pos: out, r: maxr };
  }

  function build(data) {
    var nodes = data.nodes || [], edges = data.edges || [], el = [];
    var zones = nodes.filter(function (n) { return n.data.type === 'zone'; }).map(function (n) { return n.data; });
    var devs = nodes.filter(function (n) { return n.data.type === 'device'; }).map(function (n) { return n.data; });
    var sites = nodes.filter(function (n) { return n.data.type === 'site'; }).map(function (n) { return n.data; });
    var van = (nodes.filter(function (n) { return n.data.type === 'vantage'; })[0] || {}).data;
    var gateways = devs.filter(function (d) { return d.gateway; });
    var members = {}, meta = {};
    zones.forEach(function (z) { members[z.label] = []; meta[z.label] = z; });
    if (van) (members[van.zone] = members[van.zone] || []).push(van);
    devs.filter(function (d) { return !d.gateway; }).sort(function (a, b) { return (b.vantage ? 1 : 0) - (a.vantage ? 1 : 0) || (a.label || '').localeCompare(b.label || ''); })
        .forEach(function (d) { (members[d.zone] = members[d.zone] || []).push(d); });

    var bubbles = [];
    Object.keys(members).forEach(function (z) {
      var n = members[z].length;
      if (!n) return;
      var L = ringLayout(n), R = Math.max(135, L.r + 92);
      bubbles.push({ zone: z, n: n, L: L, R: R, items: members[z], meta: meta[z] || {} });
    });
    var total = bubbles.reduce(function (s, b) { return s + 2 * b.R; }, 0) + GAP * Math.max(0, bubbles.length - 1), x = -total / 2, byZone = {}, maxR = 0, right = 0;
    bubbles.forEach(function (b) {
      b.cx = x + b.R; b.cy = b.R; x += 2 * b.R + GAP; maxR = Math.max(maxR, b.R); right = Math.max(right, b.cx + b.R); byZone[b.zone] = b;
      var z = b.zone, m = b.meta;
      el.push({ group: 'nodes', data: { id: 'seg:' + z, type: 'segment', d: 2 * b.R, label: z, count: b.n, newc: m.new || 0, issues: m.issues || 0 }, position: { x: b.cx, y: b.cy }, classes: 'struct seg' });
      el.push({ group: 'nodes', data: { id: 'st:' + z, type: 'title', text: z + '\n' + b.items.filter(function (i) { return i.type !== 'vantage'; }).length + ' device' + (b.n === 1 ? '' : 's'), seg: z }, position: { x: b.cx, y: 30 }, classes: 'struct segt' });
      el.push({ group: 'nodes', data: { id: 'sp:' + z, type: 'segport' }, position: { x: b.cx, y: 0 }, classes: 'struct' });
      b.items.forEach(function (d, i) {
        var p = b.L.pos[i], id = d.type === 'vantage' ? 'vantage' : d.id;
        el.push(devNode(d, b.cx + p.x, b.cy + p.y + 8, { id: id }));
      });
    });

    var cx0 = 0, gy = -250;
    if (gateways.length) {
      var step = 210, start = cx0 - (gateways.length - 1) * step / 2;
      gateways.forEach(function (g, i) { el.push(devNode(g, start + i * step, gy)); });
    } else {
      el.push({ group: 'nodes', data: { id: 'gwph', type: 'placeholder', size: 62, color: C.stale, img: svgUri('router', C.stale), icon: 'router', text: 'Gateway\nnot identified', label: 'Gateway (not identified)', kind: 'No gateway device has been observed yet', ph: true },
                position: { x: cx0, y: gy }, classes: 'dev ph' });
    }
    var gids = gateways.length ? gateways.map(function (g) { return g.id; }) : ['gwph'];
    el.push({ group: 'nodes', data: { id: 'internet', type: 'internet', size: 74, color: C.info, img: svgUri('cloud', C.info), icon: 'cloud', text: 'Internet / upstream', label: 'Internet / upstream', kind: 'Upstream network', ph: true, pulse: null },
              position: { x: cx0, y: gy - 215 }, classes: 'dev ph inet' });
    gids.forEach(function (g) { el.push({ group: 'edges', data: { id: 'inet:' + g, source: 'internet', target: g, layer: 'link' }, classes: 'struct' }); });
    bubbles.forEach(function (b, i) {
      el.push({ group: 'edges', data: { id: 'upl:' + b.zone, source: gids[Math.min(gids.length - 1, Math.floor(i * gids.length / bubbles.length))], target: 'sp:' + b.zone, layer: 'link' }, classes: 'struct' });
    });

    sites.forEach(function (s, i) { el.push(devNode(s, right + 280, 40 + i * 140, { id: s.id })); });

    var ids = {};
    el.forEach(function (e) { ids[e.data.id] = true; });
    var nT = 0, nC = 0;
    edges.forEach(function (e) {
      var d = Object.assign({}, e.data);
      if (d.layer === 'tested') { d.arc = (nT % 2 ? 1 : -1) * (70 + (nT % 4) * 28); nT++; }
      if (d.layer === 'configured') { d.source = 'seg:' + d.source.slice(2); d.target = 'seg:' + d.target.slice(2); d.arc = -(150 + nC * 50); nC++; }
      if (d.layer === 'observed') d.arc = ((d.source < d.target) ? 1 : -1) * 45;
      if (d.layer === 'web') d.arc = 60;
      if (ids[d.source] && ids[d.target]) el.push({ group: 'edges', data: d });
    });
    return { elements: el, panels: byZone, bounds: { minX: -total / 2, maxX: Math.max(right + (sites.length ? 400 : 0), total / 2), maxY: 2 * maxR } };
  }

  function styleSheet() {
    return [
      { selector: 'node', style: { 'transition-property': 'opacity', 'transition-duration': '0.35s', 'z-index-compare': 'manual' } },
      { selector: 'edge', style: { 'transition-property': 'opacity', 'transition-duration': '0.35s', 'z-index-compare': 'manual' } },
      { selector: 'node[type="segment"]', style: { shape: 'ellipse', width: 'data(d)', height: 'data(d)', 'background-color': C.seg, 'background-opacity': 0.1, 'border-width': 1.5, 'border-color': C.seg,
        'border-opacity': 0.55, 'underlay-color': C.seg, 'underlay-opacity': 0.07, 'underlay-padding': 18, 'underlay-shape': 'ellipse', 'z-index': 5 } },
      { selector: 'node.seg.hov', style: { 'background-opacity': 0.18, 'border-opacity': 0.95 } },
      { selector: 'node[type="title"]', style: { width: 1, height: 1, 'background-opacity': 0, 'border-width': 0, label: 'data(text)', 'text-wrap': 'wrap', 'text-halign': 'center', 'text-valign': 'center',
        color: '#bcd0ea', 'font-size': 13, 'font-weight': 600, 'font-family': FONT, 'line-height': 1.35, 'z-index': 8 } },
      { selector: 'node[type="segport"]', style: { shape: 'ellipse', width: 11, height: 11, 'background-color': C.info, 'border-width': 2, 'border-color': C.bg, events: 'no', 'z-index': 9 } },
      { selector: 'node.dev', style: { shape: 'ellipse', width: 'data(size)', height: 'data(size)', 'background-color': C.node, 'border-width': 2.5, 'border-color': 'data(color)',
        'background-image': 'data(img)', 'background-fit': 'none', 'background-width': '56%', 'background-height': '56%', 'background-position-x': '50%', 'background-position-y': '50%',
        label: 'data(text)', 'text-wrap': 'wrap', 'text-valign': 'bottom', 'text-margin-y': 8, 'font-size': 11, 'font-family': FONT, color: C.text, 'text-max-width': 118,
        'text-background-color': C.bg, 'text-background-opacity': 0.72, 'text-background-padding': 2, 'text-background-shape': 'roundrectangle',
        'underlay-color': 'data(color)', 'underlay-opacity': 0, 'underlay-padding': 6, 'underlay-shape': 'ellipse', 'z-index': 30 } },
      { selector: 'node.dev[status="stale"]', style: { 'border-style': 'dashed', color: C.mut } },
      { selector: 'node.ph', style: { 'border-style': 'dashed' } },
      { selector: 'edge', style: { width: 1.6, 'curve-style': 'straight', 'line-color': '#2f3d4d', 'z-index': 50, 'target-arrow-shape': 'none', 'font-size': 10, 'font-family': FONT, color: C.mut } },
      { selector: 'edge[layer="link"]', style: { 'line-style': 'dashed', 'line-dash-pattern': [7, 6], 'line-color': C.info, width: 2.2, opacity: 0.8, 'z-index': 6 } },
      { selector: 'edge[layer="tested"]', style: { 'curve-style': 'unbundled-bezier', 'control-point-distances': 'data(arc)', 'control-point-weights': 0.5, 'line-style': 'dashed', 'line-dash-pattern': [8, 6],
        'line-color': C.ok, width: 2, 'target-arrow-shape': 'triangle', 'target-arrow-color': C.ok, label: 'data(label)', color: C.text, 'text-background-color': C.bg, 'text-background-opacity': 0.88, 'text-background-padding': 3 } },
      { selector: 'edge[state="sensitive"]', style: { 'line-color': C.new, 'target-arrow-color': C.new } },
      { selector: 'edge[state="violation"]', style: { 'line-color': C.bad, 'target-arrow-color': C.bad, width: 3.2 } },
      { selector: 'edge[layer="observed"]', style: { 'curve-style': 'unbundled-bezier', 'control-point-distances': 'data(arc)', 'control-point-weights': 0.5, 'line-style': 'dashed', 'line-dash-pattern': [3, 7],
        'line-color': '#7a99c4', width: 1.2, 'target-arrow-shape': 'triangle', 'target-arrow-color': '#7a99c4', 'arrow-scale': 0.7, opacity: 0.38 } },
      { selector: 'edge[layer="configured"]', style: { 'curve-style': 'unbundled-bezier', 'control-point-distances': 'data(arc)', 'control-point-weights': 0.5, 'line-style': 'dashed', 'line-dash-pattern': [11, 6],
        'line-color': C.bad, width: 2.4, 'target-arrow-shape': 'triangle', 'target-arrow-color': C.bad, label: 'data(label)', color: C.bad, 'text-background-color': C.bg, 'text-background-opacity': 0.9, 'text-background-padding': 3 } },
      { selector: 'edge[layer="web"]', style: { 'curve-style': 'unbundled-bezier', 'control-point-distances': 'data(arc)', 'control-point-weights': 0.5, 'line-style': 'dashed', 'line-dash-pattern': [9, 6], 'line-color': C.bad,
        width: 2.6, 'target-arrow-shape': 'triangle', 'target-arrow-color': C.bad, label: 'data(label)', color: C.bad, 'text-background-color': C.bg, 'text-background-opacity': 0.9, 'text-background-padding': 3 } },
      { selector: 'edge[layer="simlink"]', style: { 'line-style': 'dashed', 'line-dash-pattern': [6, 5], 'line-color': C.sim, width: 2.4, events: 'no' } },
      { selector: '.dim', style: { opacity: 0.12 } },
      { selector: '.pre', style: { opacity: 0 } },
      { selector: '.hide', style: { display: 'none' } },
      { selector: 'node.dev.sel', style: { 'border-width': 4.5, 'underlay-opacity': 0.4, 'underlay-padding': 10 } },
      { selector: 'node.dev.match', style: { 'border-width': 4.5, 'border-color': '#ffffff' } },
      { selector: 'node.dev.affected', style: { 'border-color': C.sim, 'border-width': 4.5 } },
      { selector: 'node.simnew', style: { 'border-style': 'dashed', 'border-color': C.sim } }
    ];
  }

  function mount(opts) {
    var el = document.getElementById(opts.container || 'cy');
    var data = JSON.parse(document.getElementById(opts.data || 'graph-data').textContent);
    var tip = document.getElementById('topo-tip'), panel = document.getElementById('panel');
    var reduce = root.matchMedia && root.matchMedia('(prefers-reduced-motion: reduce)').matches;
    var b = build(data);
    var cy = root.cytoscape({ container: el, elements: b.elements, style: styleSheet(), layout: { name: 'preset' }, minZoom: 0.15, maxZoom: 2.8, wheelSensitivity: 0.22, boxSelectionEnabled: false, autoungrabify: true });
    var sim = opts.sim;
    if (sim) {
      (sim.affected || []).forEach(function (id) { var n = cy.getElementById('d' + id); n.addClass('affected'); if (n.nonempty()) n.data('pulse', { f: 3.2, a: 0.55, pad: 10 }); });
      (sim.added || []).forEach(function (a) {
        var p = b.panels[a.zone], bx = p ? p.cx + (p.R + 95) * 0.72 : b.bounds.maxX + 150, by = p ? p.cy + (p.R + 95) * 0.72 : 120;
        cy.add({ group: 'nodes', data: { id: 'simnew', type: 'device', size: 58, color: C.sim, img: svgUri('circle-help', C.sim), text: a.label + '\n(simulated)', status: 'sim', label: a.label, kind: 'Simulated device', zone: a.zone, ip: '', pulse: { f: 3, a: 0.6, pad: 11 } },
                 position: { x: bx, y: by }, classes: 'dev simnew' });
        if (p) {
          cy.add({ group: 'nodes', data: { id: 'simport', type: 'segport' }, position: { x: p.cx + p.R * 0.72, y: p.cy + p.R * 0.72 }, classes: 'struct' });
          cy.add({ group: 'edges', data: { id: 'simlink', source: 'simnew', target: 'simport', layer: 'simlink' }, classes: 'struct' });
        }
      });
    }
    if (!reduce) {
      cy.elements().addClass('pre');
      var order = cy.nodes('.struct').union(cy.nodes('.dev')), i = 0;
      order.forEach(function (n) { setTimeout(function () { n.removeClass('pre'); }, 60 + Math.min(i++, 80) * 14); });
      setTimeout(function () { cy.edges().removeClass('pre'); }, 1000);
    }
    cy.fit(cy.elements(), 40);
    var fitZoom = cy.zoom();
    cy.minZoom(fitZoom * 0.5);

    var st = { paused: reduce, t0: performance.now(), last: 0 };
    var speeds = { link: 18, tested: 34, observed: 14, configured: 22, web: 40 };
    function frame(now) {
      root.requestAnimationFrame(frame);
      if (st.paused || document.hidden || now - st.last < 33) return;
      st.last = now;
      var t = (now - st.t0) / 1000;
      cy.batch(function () {
        cy.edges('[layer="link"],[layer="tested"],[layer="observed"],[layer="configured"],[layer="web"]').forEach(function (e) {
          if (e.hasClass('hide')) return;
          e.style('line-dash-offset', -((t * speeds[e.data('layer')] * (e.data('state') === 'violation' ? 1.6 : 1)) % 1000));
        });
        cy.nodes('.dev').forEach(function (n) {
          var k = n.data('pulse');
          if (!k) return;
          var s = 0.5 + 0.5 * Math.sin(t * k.f);
          n.style({ 'underlay-opacity': k.a * (0.25 + 0.75 * s), 'underlay-padding': 4 + k.pad * s });
        });
      });
    }
    root.requestAnimationFrame(frame);
    var pauseBtn = document.querySelector('[data-act="pause"]');
    function setPaused(p) { st.paused = p; if (pauseBtn) { pauseBtn.setAttribute('aria-pressed', String(p)); pauseBtn.querySelector('span').textContent = p ? 'Play motion' : 'Pause motion'; } }
    setPaused(reduce);

    /* hover: trace a device's connections */
    cy.on('mouseover', 'node.dev', function (ev) {
      var n = ev.target, h = n.closedNeighborhood();
      cy.nodes('.dev').not(h).addClass('dim');
      cy.edges('[layer="tested"],[layer="observed"],[layer="configured"],[layer="web"]').not(h.edges()).addClass('dim');
      el.style.cursor = 'pointer';
      if (tip) {
        var d = n.data(); tip.textContent = '';
        var t1 = document.createElement('b'); t1.textContent = d.label || d.id; tip.appendChild(t1);
        var t2 = document.createElement('div'); t2.className = 'mut'; t2.textContent = [d.kind, d.ip].filter(Boolean).join('  ·  '); tip.appendChild(t2);
        if (d.issues) { var t3 = document.createElement('div'); t3.className = 'tip-bad'; t3.textContent = d.issues + ' open finding' + (d.issues > 1 ? 's' : ''); tip.appendChild(t3); }
        tip.style.display = 'block';
      }
    });
    cy.on('mousemove', 'node.dev', function (ev) { if (!tip) return; var r = el.getBoundingClientRect(), p = ev.renderedPosition; tip.style.left = Math.min(p.x + 18, r.width - 230) + 'px'; tip.style.top = (p.y + 18) + 'px'; });
    cy.on('mouseout', 'node.dev', function () { el.style.cursor = 'default'; if (tip) tip.style.display = 'none'; applyFilters(); });
    cy.on('mouseover', 'node.segt', function (ev) { cy.getElementById('seg:' + ev.target.data('seg')).addClass('hov'); el.style.cursor = 'pointer'; });
    cy.on('mouseout', 'node.segt', function (ev) { cy.getElementById('seg:' + ev.target.data('seg')).removeClass('hov'); el.style.cursor = 'default'; });

    /* details panel */
    function ico(name, color) {
      var s = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
      s.setAttribute('viewBox', '0 0 24 24'); s.setAttribute('fill', 'none'); s.setAttribute('stroke', color); s.setAttribute('stroke-width', '1.7'); s.setAttribute('stroke-linecap', 'round'); s.setAttribute('stroke-linejoin', 'round');
      s.setAttribute('class', 'big-ico'); s.innerHTML = icons()[name] || ''; return s;
    }
    function row(k, v) { var r = document.createElement('div'); r.className = 'kvr'; var a = document.createElement('span'); a.textContent = k; var c = document.createElement('b'); c.textContent = v; r.appendChild(a); r.appendChild(c); return r; }
    function head(icon, color, title, sub) {
      panel.textContent = '';
      var h = document.createElement('div'); h.className = 'ph'; h.appendChild(ico(icon, color));
      var t = document.createElement('div'), h2 = document.createElement('h2'); h2.textContent = title; t.appendChild(h2);
      var s = document.createElement('div'); s.className = 'mut small'; s.textContent = sub || ''; t.appendChild(s); h.appendChild(t); panel.appendChild(h);
    }
    function showDevice(n) {
      var d = n.data(); head(d.icon, d.color, d.label || d.id, d.kind || '');
      if (d.type === 'site') { panel.appendChild(row('Requests seen', String(d.hits))); var a = document.createElement('a'); a.href = '/alerts'; a.className = 'btn sm pri'; a.textContent = 'Review findings'; panel.appendChild(a); return; }
      if (!d.num) { var p = document.createElement('p'); p.className = 'mut'; p.textContent = d.id === 'internet' ? 'Upstream network. Netrik does not scan beyond your authorised ranges.' : (d.kind || ''); panel.appendChild(p); return; }
      fetch('/api/device/' + d.num).then(function (r) { return r.json(); }).then(function (x) {
        panel.appendChild(row('Segment', x.zone)); panel.appendChild(row('IP', x.ip || 'unknown')); panel.appendChild(row('MAC', x.mac || 'unknown')); panel.appendChild(row('Vendor', x.vendor || 'unknown'));
        panel.appendChild(row('Last evidence', x.last_seen)); panel.appendChild(row('Identity confidence', x.confidence)); panel.appendChild(row('Reported by', x.sources.join(', ') || 'nothing recently'));
        var pl = document.createElement('div'); pl.className = 'mut small'; pl.textContent = 'Open ports'; panel.appendChild(pl);
        var ps = document.createElement('div'); ps.className = 'chips';
        if (!x.ports.length) { var none = document.createElement('span'); none.className = 'mut small'; none.textContent = 'none found'; ps.appendChild(none); }
        x.ports.forEach(function (q) { var c = document.createElement('span'); c.className = 'chip'; c.textContent = q.port + ' ' + q.name; ps.appendChild(c); });
        panel.appendChild(ps);
        x.alerts.forEach(function (a) { var l = document.createElement('a'); l.href = '/alerts/' + a.id; l.className = 'pa sev-' + a.severity; l.textContent = a.title; panel.appendChild(l); });
        var o = document.createElement('a'); o.href = '/devices/' + x.id; o.className = 'btn sm pri'; o.textContent = 'Open full profile'; panel.appendChild(o);
      });
    }
    function showSegment(z) {
      var s = cy.getElementById('seg:' + z).data(); head('network', C.seg, z, 'Network segment');
      panel.appendChild(row('Devices', String(s.count))); panel.appendChild(row('New / unapproved', String(s.newc))); panel.appendChild(row('With open findings', String(s.issues)));
      var p = document.createElement('p'); p.className = 'mut small'; p.style.marginTop = '12px'; p.textContent = 'Devices inside the circle belong to this segment by address. Click a device for details.'; panel.appendChild(p);
      var a = document.createElement('a'); a.href = '/devices?zone=' + encodeURIComponent(z); a.className = 'btn sm'; a.textContent = 'List these devices'; panel.appendChild(a);
    }
    cy.on('tap', 'node.dev', function (ev) {
      var n = ev.target; cy.nodes('.sel').removeClass('sel'); n.addClass('sel'); showDevice(n);
      cy.animate({ center: { eles: n }, zoom: Math.max(cy.zoom(), fitZoom * 1.5) }, { duration: reduce ? 0 : 520, easing: 'ease-in-out-cubic' });
    });
    function focusSeg(z) { var seg = cy.getElementById('seg:' + z); if (seg.empty()) return; showSegment(z); cy.animate({ fit: { eles: seg, padding: 50 } }, { duration: reduce ? 0 : 560, easing: 'ease-in-out-cubic' }); }
    cy.on('tap', 'node.segt, node.seg', function (ev) { var z = ev.target.data('seg') || ev.target.data('label'); focusSeg(z); });
    cy.on('tap', function (ev) { if (ev.target === cy) cy.nodes('.sel').removeClass('sel'); });

    /* toolbar: search, status filter, segment focus, layers, camera */
    var statusFilter = 'all';
    function applyFilters() {
      var s = document.getElementById('topo-search'), q = s ? s.value.trim().toLowerCase() : '';
      cy.elements('.dim').removeClass('dim'); cy.nodes('.match').removeClass('match');
      var devs = cy.nodes('.dev').not('.ph'), keep = devs;
      if (statusFilter === 'new') keep = keep.filter(function (n) { return n.data('status') === 'new'; });
      if (statusFilter === 'exposed') keep = keep.filter(function (n) { return n.data('violation') || n.data('issues') > 0 || n.data('type') === 'site'; });
      if (statusFilter === 'stale') keep = keep.filter(function (n) { return n.data('status') === 'stale'; });
      if (q) { var m = devs.filter(function (n) { var d = n.data(); return [d.label, d.ip, d.kind, d.zone].join(' ').toLowerCase().indexOf(q) >= 0; }); m.addClass('match'); keep = keep.intersection(m); }
      if (q || statusFilter !== 'all') { devs.not(keep).addClass('dim'); cy.edges('[layer="tested"],[layer="observed"],[layer="configured"],[layer="web"]').not(keep.connectedEdges()).addClass('dim'); }
      return keep;
    }
    var search = document.getElementById('topo-search');
    if (search) {
      search.addEventListener('input', applyFilters);
      search.addEventListener('keydown', function (e) { if (e.key === 'Enter') { var k = applyFilters(); if (k.nonempty()) cy.animate({ fit: { eles: k.first().union(k.first().neighborhood('node.dev')), padding: 200 } }, { duration: reduce ? 0 : 500 }); } });
    }
    document.querySelectorAll('[data-f]').forEach(function (btn) {
      btn.addEventListener('click', function () { statusFilter = btn.getAttribute('data-f'); document.querySelectorAll('[data-f]').forEach(function (x) { x.classList.toggle('on', x === btn); }); applyFilters(); });
    });
    var segSel = document.getElementById('topo-seg');
    if (segSel) segSel.addEventListener('change', function () { if (segSel.value) focusSeg(segSel.value); else cy.animate({ fit: { eles: cy.elements(), padding: 40 } }, { duration: reduce ? 0 : 500 }); });
    document.querySelectorAll('[data-layer]').forEach(function (cb) {
      function sync() { cy.edges('[layer="' + cb.getAttribute('data-layer') + '"]').not('.struct').toggleClass('hide', !cb.checked); }
      cb.addEventListener('change', sync); sync();
    });
    document.querySelectorAll('[data-act]').forEach(function (btn) {
      btn.addEventListener('click', function () {
        var a = btn.getAttribute('data-act'), dur = reduce ? 0 : 380;
        if (a === 'fit') cy.animate({ fit: { eles: cy.elements(), padding: 40 } }, { duration: dur });
        if (a === 'in') cy.animate({ zoom: cy.zoom() * 1.3, center: { eles: cy.nodes('.sel').nonempty() ? cy.nodes('.sel') : cy.elements() } }, { duration: dur });
        if (a === 'out') cy.animate({ zoom: cy.zoom() / 1.3 }, { duration: dur });
        if (a === 'pause') setPaused(!st.paused);
      });
    });
    return cy;
  }

  root.CatTopo = { build: build, styleSheet: styleSheet, mount: mount, iconFor: iconFor, svgUri: svgUri, colorFor: colorFor };
  if (typeof document !== 'undefined' && root.cytoscape && document.getElementById('cy') && document.getElementById('graph-data')) {
    var simEl = document.getElementById('sim-data');
    mount({ sim: simEl ? JSON.parse(simEl.textContent) : null });
  }
})(typeof window !== 'undefined' ? window : globalThis);

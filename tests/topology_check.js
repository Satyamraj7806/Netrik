// Headless layout and style check of the topology renderer using the bundled Cytoscape. Usage: node tests/topology_check.js graph.json
const fs = require('fs'), path = require('path');
global.window = global;
const root = path.join(__dirname, '..', 'app', 'static');
require(path.join(root, 'icons.js'));
const cytoscape = require(path.join(root, 'cytoscape.min.js')); global.cytoscape = cytoscape;
require(path.join(root, 'topology.js'));
const data = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const warns = []; const ow = console.warn; console.warn = (...a) => warns.push(a.join(' '));
const b = CatTopo.build(data);
const cy = cytoscape({ headless: true, elements: b.elements, style: CatTopo.styleSheet(), layout: { name: 'preset' } });
console.warn = ow;
setTimeout(() => {
  const devs = cy.nodes('.dev'); let nan = 0, overlap = 0; const pts = [];
  cy.nodes().forEach(n => { const p = n.position(); if (!isFinite(p.x) || !isFinite(p.y)) nan++; });
  devs.forEach(n => pts.push(n.position()));
  for (let i = 0; i < pts.length; i++) for (let j = i + 1; j < pts.length; j++) if (Math.hypot(pts[i].x - pts[j].x, pts[i].y - pts[j].y) < 60) overlap++;
  const orphanEdges = cy.edges().filter(e => e.source().empty() || e.target().empty()).length;
  console.log(JSON.stringify({ devices: devs.length, panels: Object.keys(b.panels).length, nan, overlap, orphanEdges, styleWarnings: warns.length, warnings: warns.slice(0, 3),
    icons: [...new Set(devs.map(n => n.data('icon')))] }));
}, 100);

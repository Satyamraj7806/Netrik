(function () {
  'use strict';
  var $ = function (s, r) { return (r || document).querySelector(s); }, $$ = function (s, r) { return Array.prototype.slice.call((r || document).querySelectorAll(s)); };
  var reduce = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  function hms(sec) {
    sec = Math.max(0, Math.round(sec));
    var h = Math.floor(sec / 3600), m = Math.floor(sec % 3600 / 60), s = sec % 60;
    return h ? h + ':' + String(m).padStart(2, '0') + ':' + String(s).padStart(2, '0') : m + ':' + String(s).padStart(2, '0');
  }
  function human(sec) {
    sec = Math.round(sec);
    if (sec < 60) return sec + ' s';
    if (sec < 3600) return Math.floor(sec / 60) + ' min ' + (sec % 60 ? (sec % 60) + ' s' : '');
    return Math.floor(sec / 3600) + ' h ' + Math.floor(sec % 3600 / 60) + ' min';
  }

  /* copy buttons and confirm dialogs */
  document.addEventListener('click', function (e) {
    var b = e.target.closest('[data-copy]');
    if (!b) return;
    var t = $(b.getAttribute('data-copy'));
    if (!t) return;
    var text = t.textContent, done = function () { var o = b.textContent; b.textContent = 'Copied'; setTimeout(function () { b.textContent = o; }, 1200); };
    if (navigator.clipboard && window.isSecureContext) navigator.clipboard.writeText(text).then(done);
    else { var ta = document.createElement('textarea'); ta.value = text; document.body.appendChild(ta); ta.select(); document.execCommand('copy'); ta.remove(); done(); }
  });
  document.addEventListener('submit', function (e) {
    var m = e.target.getAttribute('data-confirm');
    if (m && !window.confirm(m)) { e.preventDefault(); return; }
    var btn = e.submitter || e.target.querySelector('button:not([type=button])');
    if (btn && !e.defaultPrevented) { btn.classList.add('busy'); setTimeout(function () { btn.setAttribute('disabled', ''); }, 0); }
  });
  window.addEventListener('pageshow', function () { $$('.btn.busy').forEach(function (b) { b.classList.remove('busy'); b.removeAttribute('disabled'); }); });

  /* toasts */
  $$('.toast').forEach(function (t) { setTimeout(function () { t.classList.add('out'); setTimeout(function () { t.remove(); }, 320); }, t.classList.contains('err') ? 9000 : 5000); t.addEventListener('click', function () { t.remove(); }); });

  /* count-up numbers */
  $$('.n[data-to]').forEach(function (el) {
    var to = parseInt(el.getAttribute('data-to'), 10) || 0;
    if (reduce || to < 2) { el.textContent = to; return; }
    var t0 = performance.now(), dur = 700;
    (function step(now) { var k = Math.min(1, (now - t0) / dur); el.textContent = Math.round(to * (1 - Math.pow(1 - k, 3))); if (k < 1) requestAnimationFrame(step); })(t0);
  });

  /* scan form + simulator form helpers */
  var kind = $('#scan-kind');
  if (kind) { var sync = function () { var d = kind.value === 'discovery'; $$('[data-portscan]').forEach(function (n) { n.style.display = d ? 'none' : ''; }); }; kind.addEventListener('change', sync); sync(); }
  var sc = $('#sim-scenario');
  if (sc) { var show = function () { $$('[data-for]').forEach(function (n) { n.style.display = n.getAttribute('data-for').split(' ').indexOf(sc.value) >= 0 ? '' : 'none'; }); }; sc.addEventListener('change', show); show(); }

  /* global activity widget: a running scan is visible from every page */
  var act = $('#activity');
  if (act) {
    var poll = function () {
      fetch('/api/activity').then(function (r) { return r.json(); }).then(function (a) {
        if (a.running) {
          act.classList.add('on'); act.href = '/scans/' + a.id;
          $('.t b', act).textContent = a.stage; $('.t span', act).textContent = Math.round(a.percent) + '%';
          $('.mini i', act).style.width = a.percent + '%';
          $('small', act).textContent = (a.remaining_s ? 'about ' + human(a.remaining_s) + ' left in this stage' : 'working') + (a.queued ? ' · ' + a.queued + ' queued' : '');
        } else if (a.queued) {
          act.classList.add('on'); $('.t b', act).textContent = 'Waiting to start'; $('.t span', act).textContent = ''; $('.mini i', act).style.width = '0'; $('small', act).textContent = a.queued + ' scan(s) queued';
        } else act.classList.remove('on');
      }).catch(function () {}).then(function () { setTimeout(poll, 2500); });
    };
    poll();
  }

  /* live scan progress */
  var live = $('#scan-live');
  if (live) {
    var id = live.getAttribute('data-id'), C = 2 * Math.PI * 52, ring = $('.ring .fg', live), pct = $('.ring-txt b', live), bar = $('.bar.big', live), barI = $('.bar.big i', live);
    var stageName = $('.stage b', live), stagePct = $('.stage span', live), eta = $('.eta', live), steps = $('.steps', live), feed = $('.feed', live);
    var elapsedEl = $('[data-m="elapsed"]', live), hostsEl = $('[data-m="hosts"]', live), portsEl = $('[data-m="ports"]', live);
    var base = 0, baseAt = Date.now(), seen = {}, finished = false, shown = 0, target = 0;
    setInterval(function () { if (!finished && elapsedEl) elapsedEl.textContent = hms(base + (Date.now() - baseAt) / 1000); }, 500);
    function render(s) {
      var l = s.live || {}, running = s.status === 'running';
      live.classList.toggle('working', running);
      base = s.elapsed_s || 0; baseAt = Date.now();
      target = l.percent || 0;
      if (s.status === 'queued') {
        stageName.textContent = 'Waiting in the queue'; stagePct.textContent = '';
        eta.textContent = s.queue_pos ? s.queue_pos + ' scan(s) ahead of this one' : 'Starting in a moment';
        bar.classList.add('ind');
      } else {
        stageName.textContent = l.label || 'Starting'; stagePct.textContent = l.indeterminate ? '' : Math.round(l.stage_percent) + '%';
        if (l.indeterminate) { eta.textContent = 'Working: waiting for Nmap to report this stage…'; bar.classList.add('ind'); }
        else {
          bar.classList.remove('ind');
          eta.textContent = l.remaining_s ? 'About ' + human(l.remaining_s) + ' left in this stage' + (l.estimated ? ' (estimated from probe volume)' : '') : (l.stage_percent >= 100 ? 'Stage complete' : 'Calculating time left…');
        }
      }
      if (hostsEl) hostsEl.textContent = l.hosts_up != null ? l.hosts_up + (l.hosts_done ? ' / ' + l.hosts_done + ' done' : '') : '-';
      if (portsEl) portsEl.textContent = (l.feed || []).filter(function (f) { return f.kind === 'port'; }).length || '0';
      if (l.steps) steps.innerHTML = '', l.steps.forEach(function (st) { var li = document.createElement('li'); li.className = st.state; li.textContent = st.label; steps.appendChild(li); });
      (l.feed || []).forEach(function (f) {
        var key = f.t + f.text; if (seen[key]) return; seen[key] = 1;
        var li = document.createElement('li'); li.className = f.kind; var sp = document.createElement('span'); sp.textContent = f.text; var tm = document.createElement('time'); tm.textContent = hms(f.t);
        li.appendChild(sp); li.appendChild(tm); feed.insertBefore(li, feed.firstChild); while (feed.children.length > 9) feed.removeChild(feed.lastChild);
      });
    }
    /* smooth the number between polls so the ring never looks frozen */
    (function tween() { shown += (target - shown) * 0.12; if (Math.abs(target - shown) < 0.05) shown = target;
      pct.textContent = Math.round(shown) + '%'; ring.style.strokeDashoffset = C * (1 - shown / 100); barI.style.width = shown + '%'; requestAnimationFrame(tween); })();
    (function poll() {
      fetch('/api/scans/' + id).then(function (r) { return r.json(); }).then(function (s) {
        render(s);
        if (s.status === 'queued' || s.status === 'running') setTimeout(poll, 1000);
        else { finished = true; target = 100; setTimeout(function () { location.reload(); }, 900); }
      }).catch(function () { setTimeout(poll, 2500); });
    })();
  }
})();
/* generic: <select data-switch> shows only elements whose data-when lists the chosen value */
(function () {
  document.querySelectorAll('select[data-switch]').forEach(function (sel) {
    var scope = sel.closest('form') || document;
    function show() { scope.querySelectorAll('[data-when]').forEach(function (n) { n.style.display = n.getAttribute('data-when').split(' ').indexOf(sel.value) >= 0 ? '' : 'none'; }); }
    sel.addEventListener('change', show); show();
  });
})();

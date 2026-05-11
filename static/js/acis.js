/**
 * ACIS — Real-Time Dashboard JavaScript
 * Handles live metric polling, chart updates, scan triggers
 */

// ── Helpers ──────────────────────────────────────────────────────────────────
function fmtBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024, sizes = ['B','KB','MB','GB','TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

function fmtBps(bps) {
  if (bps < 1024) return bps.toFixed(0) + ' B/s';
  if (bps < 1048576) return (bps/1024).toFixed(1) + ' KB/s';
  return (bps/1048576).toFixed(2) + ' MB/s';
}

function sevClass(sev) {
  const map = { CRITICAL:'sev-CRITICAL', HIGH:'sev-HIGH', MEDIUM:'sev-MEDIUM',
                LOW:'sev-LOW', INFO:'sev-INFO', WARNING:'sev-WARNING',
                AUTH:'sev-AUTH', SCAN:'sev-SCAN' };
  return map[sev] || 'sev-INFO';
}

function showToast(msg, color='var(--cyan)') {
  let t = document.getElementById('acis-toast');
  if (!t) {
    t = document.createElement('div');
    t.id = 'acis-toast';
    t.className = 'acis-toast';
    document.body.appendChild(t);
  }
  t.textContent = msg;
  t.style.borderLeftColor = color;
  t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), 3500);
}

// ── Clock ─────────────────────────────────────────────────────────────────────
function startClock() {
  const el = document.getElementById('live-clock');
  if (!el) return;
  function tick() {
    const now = new Date();
    el.textContent = now.toUTCString().replace(' GMT','') + ' UTC';
  }
  tick();
  setInterval(tick, 1000);
}

// ── Metric Progress bars ──────────────────────────────────────────────────────
function setBar(id, pct, color) {
  const el = document.getElementById(id);
  if (el) { el.style.width = pct + '%'; if (color) el.style.background = color; }
}

function colorForPct(pct) {
  if (pct > 85) return 'var(--red)';
  if (pct > 65) return 'var(--orange)';
  return 'var(--cyan)';
}

// ── Live Metrics Poll ─────────────────────────────────────────────────────────
let metricHistory = { cpu: [], mem: [], recv: [], sent: [] };
const MAX_HIST = 20;

async function pollMetrics() {
  try {
    const r = await fetch('/api/metrics');
    if (!r.ok) return;
    const d = await r.json();

    // CPU
    const cpuEl = document.getElementById('cpu-val');
    const cpuBar = document.getElementById('cpu-bar');
    if (cpuEl) cpuEl.textContent = d.cpu_percent + '%';
    if (cpuBar) { cpuBar.style.width = d.cpu_percent + '%'; cpuBar.style.background = colorForPct(d.cpu_percent); }

    // MEM
    const memEl = document.getElementById('mem-val');
    const memBar = document.getElementById('mem-bar');
    if (memEl) memEl.textContent = d.memory_percent + '%';
    if (memBar) { memBar.style.width = d.memory_percent + '%'; memBar.style.background = colorForPct(d.memory_percent); }

    // DISK
    const diskEl = document.getElementById('disk-val');
    const diskBar = document.getElementById('disk-bar');
    if (diskEl) diskEl.textContent = d.disk_percent + '%';
    if (diskBar) { diskBar.style.width = d.disk_percent + '%'; diskBar.style.background = colorForPct(d.disk_percent); }

    // NET
    const sentEl = document.getElementById('net-sent');
    const recvEl = document.getElementById('net-recv');
    if (sentEl) sentEl.textContent = fmtBytes(d.net_bytes_sent);
    if (recvEl) recvEl.textContent = fmtBytes(d.net_bytes_recv);

    // Uptime
    const uptEl = document.getElementById('uptime-val');
    if (uptEl) {
      const h = Math.floor(d.uptime_seconds / 3600);
      const m = Math.floor((d.uptime_seconds % 3600) / 60);
      uptEl.textContent = h + 'h ' + m + 'm';
    }

    // History for sparklines
    metricHistory.cpu.push(d.cpu_percent);
    metricHistory.mem.push(d.memory_percent);
    if (metricHistory.cpu.length > MAX_HIST) metricHistory.cpu.shift();
    if (metricHistory.mem.length > MAX_HIST) metricHistory.mem.shift();
    updateSparkline('spark-cpu', metricHistory.cpu);
    updateSparkline('spark-mem', metricHistory.mem, 'var(--green)');

  } catch(e) { /* network blip — silent */ }
}

// ── Sparkline ─────────────────────────────────────────────────────────────────
function updateSparkline(containerId, data, color='var(--cyan)') {
  const el = document.getElementById(containerId);
  if (!el) return;
  const max = Math.max(...data, 1);
  el.innerHTML = '';
  data.forEach(v => {
    const bar = document.createElement('div');
    bar.className = 'spark-bar';
    bar.style.height = Math.max(3, (v / max) * 28) + 'px';
    bar.style.background = color;
    el.appendChild(bar);
  });
}

// ── Traffic Poll ──────────────────────────────────────────────────────────────
async function pollTraffic() {
  try {
    const r = await fetch('/api/network_traffic');
    if (!r.ok) return;
    const d = await r.json();
    const sentEl = document.getElementById('traffic-sent');
    const recvEl = document.getElementById('traffic-recv');
    if (sentEl) sentEl.textContent = fmtBps(d.sent_ps);
    if (recvEl) recvEl.textContent = fmtBps(d.recv_ps);

    metricHistory.sent.push(d.sent_ps);
    metricHistory.recv.push(d.recv_ps);
    if (metricHistory.sent.length > MAX_HIST) metricHistory.sent.shift();
    if (metricHistory.recv.length > MAX_HIST) metricHistory.recv.shift();
    updateSparkline('spark-sent', metricHistory.sent, 'var(--green)');
    updateSparkline('spark-recv', metricHistory.recv, 'var(--cyan)');
  } catch(e) {}
}

// ── Latest Alerts (dashboard widget) ─────────────────────────────────────────
async function pollAlerts() {
  try {
    const r = await fetch('/api/alerts');
    if (!r.ok) return;
    const alerts = await r.json();
    const tbody = document.getElementById('alert-tbody');
    if (!tbody) return;
    tbody.innerHTML = '';
    alerts.slice(0, 8).forEach(a => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td class="mono" style="font-size:10px;color:var(--text-dim);white-space:nowrap;">${a.ts}</td>
        <td><span class="sev-badge ${sevClass(a.severity)}">${a.severity}</span></td>
        <td class="mono" style="font-size:10px;color:var(--cyan-dim);">${a.category}</td>
        <td style="font-size:12px;">${a.message}</td>
      `;
      tbody.appendChild(tr);
    });
  } catch(e) {}
}

// ── Threat Scan ───────────────────────────────────────────────────────────────
async function runScan() {
  const overlay = document.getElementById('scan-overlay');
  if (overlay) { overlay.classList.add('active'); }
  try {
    const r = await fetch('/api/scan');
    const d = await r.json();
    showToast(`SCAN COMPLETE — ${d.scanned} finding(s) recorded`);
    if (typeof pollAlerts === 'function') await pollAlerts();
  } catch(e) {
    showToast('Scan error — see console', 'var(--red)');
  } finally {
    if (overlay) overlay.classList.remove('active');
  }
}

// ── Dismiss alert ─────────────────────────────────────────────────────────────
async function dismissAlert(id) {
  await fetch('/api/dismiss_alert/' + id, { method: 'POST' });
  const row = document.getElementById('alert-row-' + id);
  if (row) { row.style.opacity = '0.3'; row.style.textDecoration = 'line-through'; }
  showToast('Alert dismissed');
}

// ── Connection refresh (network page) ────────────────────────────────────────
async function refreshConnections() {
  const tbody = document.getElementById('conn-tbody');
  if (!tbody) return;
  try {
    const r = await fetch('/api/connections');
    const conns = await r.json();
    tbody.innerHTML = '';
    conns.forEach(c => {
      const flagCls = c.flagged ? 'style="background:rgba(255,61,113,0.06);"' : '';
      const risk = c.flagged
        ? `<span class="sev-badge sev-HIGH">⚠ FLAGGED</span>`
        : c.anomaly_score > 30
          ? `<span class="sev-badge sev-MEDIUM">${c.anomaly_score}%</span>`
          : `<span style="font-family:var(--font-mono);font-size:10px;color:var(--green);">✓ NORMAL</span>`;
      const tr = document.createElement('tr');
      tr.setAttribute(flagCls ? 'style' : 'data-x', flagCls ? 'background:rgba(255,61,113,0.06);' : '');
      tr.innerHTML = `
        <td class="mono" style="font-size:10px;color:var(--cyan-dim);">${c.type}/${c.family}</td>
        <td class="mono" style="font-size:11px;">${c.local_addr}</td>
        <td class="mono" style="font-size:11px;color:${c.remote_addr!=='-'?'var(--text-primary)':'var(--text-dim)'};">${c.remote_addr}</td>
        <td class="mono" style="font-size:10px;color:${c.status==='ESTABLISHED'?'var(--green)':c.status==='LISTEN'?'var(--cyan)':'var(--text-dim)'};">${c.status}</td>
        <td class="mono" style="font-size:11px;color:var(--text-dim);">${c.pid||'—'}</td>
        <td style="font-size:12px;color:var(--text-secondary);">${c.process||'—'}</td>
        <td>${risk}</td>
      `;
      if (c.flagged) tr.style.background = 'rgba(255,61,113,0.06)';
      tbody.appendChild(tr);
    });
    showToast(`${conns.length} connections refreshed`);
  } catch(e) {}
}

// ── Init ──────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  startClock();

  // Dashboard polling
  if (document.getElementById('cpu-val')) {
    pollMetrics();
    setInterval(pollMetrics, 3000);
  }
  if (document.getElementById('traffic-sent')) {
    pollTraffic();
    setInterval(pollTraffic, 2000);
  }
  if (document.getElementById('alert-tbody')) {
    pollAlerts();
    setInterval(pollAlerts, 8000);
  }

  // Scan button
  document.querySelectorAll('.scan-btn, #scan-btn').forEach(scanBtn => {
    scanBtn.addEventListener('click', runScan);
  });

  // Refresh connections
  const refreshBtn = document.getElementById('refresh-conn-btn');
  if (refreshBtn) refreshBtn.addEventListener('click', refreshConnections);

  // Core-bar animation
  document.querySelectorAll('[data-pct]').forEach(el => {
    const pct = parseFloat(el.dataset.pct);
    setTimeout(() => { el.style.width = pct + '%'; }, 200);
  });
});

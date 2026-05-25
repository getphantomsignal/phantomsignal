/**
 * NightOwl App Core — Grid Interface Logic
 * SocketIO connection, toast system, and shared utilities
 */

// ── SocketIO Connection ──────────────────────────────────────
let socket = null;
let isConnected = false;

function initSocket() {
  socket = io({ transports: ['websocket', 'polling'], reconnectionAttempts: 10 });

  socket.on('connect', () => {
    isConnected = true;
    setConnectionStatus('online');
  });

  socket.on('disconnect', () => {
    isConnected = false;
    setConnectionStatus('offline');
  });

  socket.on('reconnect_attempt', () => {
    setConnectionStatus('connecting');
  });

  socket.on('ghost_online', (data) => {
    appendTerminalLine('live-terminal', 'NIGHTOWL', data.message, 'system');
  });

  // Global scan event handlers (for any open terminal on page)
  socket.on('terminal_log', (data) => {
    const module = (data.module || 'SYS').toUpperCase().padEnd(12);
    appendTerminalLine('live-terminal', module, data.message, data.level || 'info');
  });

  socket.on('scan_complete', (data) => {
    showToast(
      `Mission complete. Shadow Score: ${data.shadow_score?.toFixed(0)}/100 — ${data.result_count} signals captured.`,
      'success'
    );
  });

  socket.on('scan_failed', (data) => {
    showToast(`Ghost run failed: ${data.error}`, 'error');
  });

  socket.on('module_start', (data) => {
    appendTerminalLine('live-terminal', data.module.toUpperCase(), `Module online — initiating scan...`, 'system');
  });

  socket.on('module_complete', (data) => {
    appendTerminalLine(
      'live-terminal',
      data.module.toUpperCase(),
      `Signal captured: ${data.result_count} result(s)`,
      'success'
    );
    const fill = document.getElementById('progress-fill');
    const pct  = document.getElementById('progress-pct');
    if (fill) fill.style.width = `${data.progress}%`;
    if (pct)  pct.textContent = `${data.progress}%`;
  });
}

function setConnectionStatus(state) {
  const dot  = document.getElementById('connection-dot');
  const text = document.getElementById('connection-status');
  if (!dot || !text) return;
  const states = {
    online:     { cls: 'online',  label: 'GRID ONLINE' },
    offline:    { cls: '',        label: 'SIGNAL LOST' },
    connecting: { cls: '',        label: 'RECONNECTING...' },
  };
  const s = states[state] || states.offline;
  dot.className  = 'status-dot ' + s.cls;
  text.textContent = s.label;
  text.style.color = state === 'online' ? 'var(--neon-green)' : 'var(--text-dim)';
}

// ── Live Feed Terminal ───────────────────────────────────────
function initLiveFeed(scanId) {
  if (!socket) return;
  socket.emit('join_scan', { scan_id: scanId });

  socket.on('scan_complete', (data) => {
    if (data.scan_id === scanId) {
      appendTerminalLine('live-terminal', 'NIGHTOWL',
        `GHOST RUN COMPLETE — Shadow Score: ${data.shadow_score?.toFixed(0)}/100 | Threat: ${data.threat_level?.toUpperCase()}`,
        'success');
      // Reload results after brief delay
      setTimeout(() => { location.reload(); }, 2500);
    }
  });

  socket.on('scan_aborted', (data) => {
    if (data.scan_id === scanId) {
      appendTerminalLine('live-terminal', 'NIGHTOWL', 'GHOST RUN TERMINATED — Signal severed.', 'warning');
      setTimeout(() => { location.reload(); }, 1500);
    }
  });
}

function appendTerminalLine(termId, module, message, level) {
  const term = document.getElementById(termId);
  if (!term) return;

  const line = document.createElement('div');
  line.className = `term-line term-${level || 'info'}`;

  const ts = new Date().toTimeString().slice(0,8);
  line.innerHTML = `
    <span class="term-prompt">[${ts}][${(module || 'SYS').slice(0,10).padEnd(10)}]</span>
    <span class="term-msg">${escapeHtml(message)}</span>
  `;

  term.appendChild(line);

  // Keep last 150 lines
  while (term.children.length > 150) {
    term.removeChild(term.firstChild);
  }
  term.scrollTop = term.scrollHeight;
}

// ── Toast Notifications ──────────────────────────────────────
function showToast(message, type = 'info', duration = 5000) {
  const container = document.getElementById('toast-container');
  if (!container) return;

  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;

  const icons = { success: '✓', error: '✗', warning: '⚠', info: 'ℹ' };
  toast.innerHTML = `<span style="margin-right:0.5rem">${icons[type] || 'ℹ'}</span>${escapeHtml(message)}`;

  container.appendChild(toast);

  setTimeout(() => {
    toast.style.animation = 'none';
    toast.style.transition = 'opacity 0.3s, transform 0.3s';
    toast.style.opacity = '0';
    toast.style.transform = 'translateX(20px)';
    setTimeout(() => toast.remove(), 300);
  }, duration);
}

// ── Utility Functions ────────────────────────────────────────
function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function copyToClipboard(text) {
  navigator.clipboard.writeText(text)
    .then(() => showToast('Copied to clipboard', 'success', 2000))
    .catch(() => showToast('Copy failed', 'error', 2000));
}

function formatBytes(bytes) {
  const units = ['B','KB','MB','GB'];
  let i = 0;
  while (bytes >= 1024 && i < units.length - 1) { bytes /= 1024; i++; }
  return `${bytes.toFixed(1)} ${units[i]}`;
}

function timeAgo(dateStr) {
  if (!dateStr) return '—';
  const diff = Date.now() - new Date(dateStr);
  const m = Math.floor(diff / 60000);
  if (m < 1) return 'just now';
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h/24)}d ago`;
}

// ── Boot Sequence ─────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  initSocket();

  // Auto-dismiss flashes after 6s
  document.querySelectorAll('.flash').forEach(el => {
    setTimeout(() => {
      el.style.transition = 'opacity 0.5s';
      el.style.opacity = '0';
      setTimeout(() => el.remove(), 500);
    }, 6000);
  });

  // Animate stat values counting up
  document.querySelectorAll('.stat-value').forEach(el => {
    const target = parseInt(el.textContent, 10);
    if (!isNaN(target) && target > 0) {
      let current = 0;
      const step = Math.ceil(target / 30);
      const timer = setInterval(() => {
        current = Math.min(current + step, target);
        el.textContent = current.toLocaleString();
        if (current >= target) clearInterval(timer);
      }, 30);
    }
  });

  // Animate shadow score bars
  document.querySelectorAll('.shadow-score-fill').forEach(el => {
    const width = el.style.width;
    el.style.width = '0%';
    setTimeout(() => { el.style.width = width; }, 200);
  });

  document.querySelectorAll('.score-fill').forEach(el => {
    const width = el.style.width;
    el.style.width = '0%';
    setTimeout(() => { el.style.width = width; }, 300);
  });
});

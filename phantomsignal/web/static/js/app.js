/**
 * PhantomSignal App Core — Grid Interface Logic
 * SocketIO connection, toast system, and shared utilities
 */

// ── SocketIO Connection ──────────────────────────────────────
let socket = null;
let isConnected = false;

function initSocket() {
  if (socket) return;                          // idempotent
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

  socket.on('server_ready', (data) => {
    appendTerminalLine('live-terminal', 'PHANTOMSIGNAL', data.message, 'system');
  });

  // Global scan event handlers (for any open terminal on page)
  socket.on('terminal_log', (data) => {
    const module = (data.module || 'SYS').toUpperCase().padEnd(12);
    appendTerminalLine('live-terminal', module, data.message, data.level || 'info');
  });

  socket.on('scan_complete', (data) => {
    showToast(
      `Scan complete. Risk Score: ${data.shadow_score?.toFixed(0)}/100 — ${data.result_count} results found.`,
      'success'
    );
  });

  socket.on('scan_failed', (data) => {
    showToast(`Scan failed: ${data.error}`, 'error');
  });

  socket.on('module_start', (data) => {
    appendTerminalLine('live-terminal', data.module.toUpperCase(), `Running...`, 'system');
  });

  socket.on('module_complete', (data) => {
    appendTerminalLine(
      'live-terminal',
      data.module.toUpperCase(),
      `${data.result_count} result(s) found`,
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
    online:     { cls: 'online',  label: 'ONLINE' },
    offline:    { cls: '',        label: 'OFFLINE' },
    connecting: { cls: '',        label: 'CONNECTING...' },
  };
  const s = states[state] || states.offline;
  dot.className  = 'status-dot ' + s.cls;
  text.textContent = s.label;
  text.style.color = state === 'online' ? 'var(--neon-green)' : 'var(--text-dim)';
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

// ── Theme (Dark default; Light + Neon opt-in) ─────────────────
// 'dark' carries no data-theme attribute (base :root); others set it.
const THEME_META = {
  light: { label: 'Light' },
  dark:  { label: 'Dark' },
  neon:  { label: 'Neon' },
};

function currentTheme() {
  return localStorage.getItem('phantomsignal-theme') || 'dark';
}

function applyTheme(name) {
  if (!THEME_META[name]) name = 'dark';
  if (name === 'dark') document.documentElement.removeAttribute('data-theme');
  else document.documentElement.setAttribute('data-theme', name);
  localStorage.setItem('phantomsignal-theme', name);

  document.querySelectorAll('.theme-seg-btn').forEach((btn) => {
    btn.setAttribute('aria-checked', btn.dataset.themeVal === name ? 'true' : 'false');
  });
}

function cycleTheme() {
  const i = THEMES.indexOf(currentTheme());
  applyTheme(THEMES[(i + 1) % THEMES.length]);
}

// ── Boot Sequence ─────────────────────────────────────────────
// Initialise the socket immediately — scripts on the results page need it
// before DOMContentLoaded fires (socket.io is already loaded by this point).
initSocket();

document.addEventListener('DOMContentLoaded', () => {
  // initSocket() already called above; this is a no-op guard

  // Apply saved theme and wire the segmented control
  applyTheme(currentTheme());
  document.querySelectorAll('.theme-seg-btn').forEach((btn) => {
    btn.addEventListener('click', () => applyTheme(btn.dataset.themeVal));
  });

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

  // Animate risk score bars (.shadow-score-fill = legacy class name for the risk score)
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

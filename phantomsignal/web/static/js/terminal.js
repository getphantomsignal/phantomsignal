/**
 * PhantomSignal Terminal Module — Live Feed Handler
 * Manages real-time scan output via SocketIO
 */

function _setProgress(pct) {
  const fill = document.getElementById('progress-fill');
  const label = document.getElementById('progress-pct');
  if (fill)  fill.style.width  = `${pct}%`;
  if (label) label.textContent = `${pct}%`;
}

function initLiveFeed(scanId) {
  if (typeof socket === 'undefined' || !socket) {
    console.warn('[PhantomSignal] Socket not ready — live feed unavailable');
    return;
  }

  // ── Join the scan room ──────────────────────────────────────
  socket.emit('join_scan', { scan_id: scanId });
  appendTerminalLine('live-terminal', 'PHANTOMSIGNAL', `Scan started — ${scanId.slice(0,8)}...`, 'system');

  // ── Sync state sent by server on room join ──────────────────
  // Server sends current progress so late-joining clients don't start at 0%.
  socket.on('scan_status', (data) => {
    if (data.scan_id !== scanId) return;
    _setProgress(data.progress || 0);
    if (data.progress > 0) {
      appendTerminalLine('live-terminal', 'SYNC', `Progress: ${data.progress}%`, 'system');
    }
  });

  // ── Live log lines from engine ──────────────────────────────
  socket.on('terminal_log', (data) => {
    if (data.scan_id !== scanId) return;
    const level = data.level === 'error'   ? 'error'
                : data.level === 'warning' ? 'warning'
                : data.level === 'success' ? 'success'
                : 'system';
    appendTerminalLine('live-terminal', (data.module || 'SYS').toUpperCase().padEnd(10), data.message, level);
  });

  // ── Module lifecycle events ─────────────────────────────────
  socket.on('module_start', (data) => {
    if (data.scan_id !== scanId) return;
    appendTerminalLine('live-terminal', '>> MODULE', `${data.module.toUpperCase()} — STARTING`, 'system');
  });

  socket.on('module_complete', (data) => {
    if (data.scan_id !== scanId) return;
    appendTerminalLine(
      'live-terminal', '<< MODULE',
      `${data.module.toUpperCase()} COMPLETE — ${data.result_count} result(s) [${data.progress}%]`,
      'success'
    );
    _setProgress(data.progress);
  });

  // ── Scan terminal events ────────────────────────────────────
  socket.on('scan_complete', (data) => {
    if (data.scan_id !== scanId) return;
    _setProgress(100);
    appendTerminalLine('live-terminal', '====', '═'.repeat(50), 'system');
    appendTerminalLine('live-terminal', 'SCAN', 'SCAN COMPLETE', 'success');
    appendTerminalLine('live-terminal', 'SCORE  ', `Risk Score: ${data.shadow_score?.toFixed(0)}/100`, 'success');
    appendTerminalLine('live-terminal', 'THREAT ',
      `Level: ${(data.threat_level || 'unknown').toUpperCase()}`,
      data.threat_level === 'critical' || data.threat_level === 'malicious' ? 'error' : 'success');
    appendTerminalLine('live-terminal', 'RESULTS', `${data.result_count} result(s) saved`, 'success');
    appendTerminalLine('live-terminal', '====', '═'.repeat(50), 'system');
    setTimeout(() => { location.reload(); }, 3000);
  });

  socket.on('scan_failed', (data) => {
    if (data.scan_id !== scanId) return;
    appendTerminalLine('live-terminal', '!! ERROR', `SCAN FAILED: ${data.error}`, 'error');
    setTimeout(() => { location.reload(); }, 2000);
  });

  socket.on('scan_aborted', (data) => {
    if (data.scan_id !== scanId) return;
    appendTerminalLine('live-terminal', 'ABORT', 'Scan stopped by user.', 'warning');
    setTimeout(() => { location.reload(); }, 1500);
  });
}

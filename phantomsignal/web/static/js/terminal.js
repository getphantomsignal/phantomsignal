/**
 * PhantomSignal Terminal Module — Live Feed Handler
 * Manages real-time scan output via SocketIO
 */

function initLiveFeed(scanId) {
  if (typeof socket === 'undefined' || !socket) {
    console.warn('Socket not initialized — live feed unavailable');
    return;
  }

  socket.emit('join_scan', { scan_id: scanId });
  appendTerminalLine('live-terminal', 'OWLSCAN', `Tuned into ghost run ${scanId.slice(0,8)}...`, 'system');

  socket.on('terminal_log', (data) => {
    if (data.scan_id !== scanId) return;
    const level = data.level === 'error' ? 'error'
                : data.level === 'warning' ? 'warning'
                : data.level === 'success' ? 'success'
                : 'system';
    appendTerminalLine('live-terminal', (data.module || 'SYS').toUpperCase().padEnd(10), data.message, level);
  });

  socket.on('module_start', (data) => {
    if (data.scan_id !== scanId) return;
    appendTerminalLine('live-terminal', '>> MODULE', `${data.module.toUpperCase()} — INITIALIZING`, 'system');
  });

  socket.on('module_complete', (data) => {
    if (data.scan_id !== scanId) return;
    appendTerminalLine(
      'live-terminal',
      '<< MODULE',
      `${data.module.toUpperCase()} COMPLETE — ${data.result_count} signal(s) captured [${data.progress}%]`,
      'success'
    );
    const fill = document.getElementById('progress-fill');
    const pct  = document.getElementById('progress-pct');
    if (fill) fill.style.width = `${data.progress}%`;
    if (pct)  pct.textContent = `${data.progress}%`;
  });

  socket.on('scan_complete', (data) => {
    if (data.scan_id !== scanId) return;
    appendTerminalLine('live-terminal', '====', '='.repeat(50), 'system');
    appendTerminalLine('live-terminal', 'MISSION', 'GHOST RUN COMPLETE', 'success');
    appendTerminalLine('live-terminal', 'SCORE  ', `Shadow Score: ${data.shadow_score?.toFixed(0)}/100`, 'success');
    appendTerminalLine('live-terminal', 'THREAT ', `Level: ${(data.threat_level || 'unknown').toUpperCase()}`,
      data.threat_level === 'critical' || data.threat_level === 'malicious' ? 'error' : 'success');
    appendTerminalLine('live-terminal', 'INTEL  ', `${data.result_count} signal(s) archived`, 'success');
    appendTerminalLine('live-terminal', '====', '='.repeat(50), 'system');

    setTimeout(() => { location.reload(); }, 3000);
  });

  socket.on('scan_failed', (data) => {
    if (data.scan_id !== scanId) return;
    appendTerminalLine('live-terminal', '!! ERROR', `GHOST RUN FAILED: ${data.error}`, 'error');
    setTimeout(() => { location.reload(); }, 2000);
  });

  socket.on('scan_aborted', (data) => {
    if (data.scan_id !== scanId) return;
    appendTerminalLine('live-terminal', 'ABORT', 'SIGNAL SEVERED — Ghost run terminated by operator.', 'warning');
    setTimeout(() => { location.reload(); }, 1500);
  });
}

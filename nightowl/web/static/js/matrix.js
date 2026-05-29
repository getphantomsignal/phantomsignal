/**
 * NightOwl Matrix Rain — Digital Ghost Effect
 * Cyberpunk canvas background animation
 */
(function () {
  const canvas = document.getElementById('matrix-canvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');

  const CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#$%^&*()_+-=[]{}|;:,.<>?/\\~`ÆΩΨΦΣΔΓΛΘΞΠабвгдежзийклмноп';
  const KATAKANA = 'アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワヲン';
  const ALL_CHARS = CHARS + KATAKANA;

  let cols, drops, fontSize;

  function resize() {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
    fontSize = 13;
    cols = Math.floor(canvas.width / fontSize);
    drops = new Float32Array(cols).fill(0);
    // Randomize starting positions
    for (let i = 0; i < cols; i++) {
      drops[i] = Math.random() * -canvas.height / fontSize;
    }
  }

  function draw() {
    ctx.fillStyle = 'rgba(10, 10, 15, 0.05)';
    ctx.fillRect(0, 0, canvas.width, canvas.height);

    for (let i = 0; i < cols; i++) {
      const char = ALL_CHARS[Math.floor(Math.random() * ALL_CHARS.length)];
      const x = i * fontSize;
      const y = drops[i] * fontSize;

      // Lead character brighter
      const brightness = Math.random() > 0.97 ? 1.0 : 0.35;
      if (brightness > 0.9) {
        ctx.fillStyle = `rgba(255,255,255,${brightness})`;
      } else {
        ctx.fillStyle = `rgba(0,255,65,${brightness})`;
      }

      ctx.font = `${fontSize}px 'Courier New', monospace`;
      ctx.fillText(char, x, y);

      if (y > canvas.height && Math.random() > 0.975) {
        drops[i] = 0;
      }
      drops[i] += 0.5;
    }
  }

  resize();
  window.addEventListener('resize', resize);

  // Throttle to ~20fps for performance; skip when light theme is active
  let lastTime = 0;
  function loop(timestamp) {
    if (timestamp - lastTime > 50) {
      if (document.documentElement.getAttribute('data-theme') !== 'light') {
        draw();
      }
      lastTime = timestamp;
    }
    requestAnimationFrame(loop);
  }
  requestAnimationFrame(loop);
})();

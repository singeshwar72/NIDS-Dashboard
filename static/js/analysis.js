/* analysis.js — Intrusion Analysis page (minimal; mostly server-rendered) */

'use strict';

// Animate risk score meter on load
document.addEventListener('DOMContentLoaded', () => {
  const fill = document.querySelector('.risk-fill');
  if (fill) {
    const target = parseFloat(fill.style.width);
    fill.style.width = '0%';
    setTimeout(() => { fill.style.width = target + '%'; }, 200);
  }
});

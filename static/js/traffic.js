/* traffic.js — Traffic Monitor page logic */

'use strict';

let trafficPage = 1;
let trafficPageSize = 50;
let trafficFilters = {};

// ------------------------------------------------------------------ //
// Load Traffic
// ------------------------------------------------------------------ //

async function loadTraffic() {
  const tbody = document.getElementById('traffic-tbody');
  if (tbody) tbody.innerHTML = '<tr><td colspan="11" class="text-center text-muted py-4"><span class="spinner-border spinner-border-sm me-2"></span>Loading…</td></tr>';

  const params = new URLSearchParams({
    page: trafficPage,
    page_size: trafficPageSize,
    ...trafficFilters,
  });
  // Remove empty
  for (const [k, v] of [...params.entries()]) {
    if (!v) params.delete(k);
  }

  try {
    const res = await fetch('/api/traffic?' + params);
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const data = await res.json();
    renderTrafficTable(data);
  } catch (e) {
    if (tbody) tbody.innerHTML = '<tr><td colspan="11" class="text-center text-danger py-3">Failed to load traffic records.</td></tr>';
    console.error('Traffic load error:', e);
  }
}

// ------------------------------------------------------------------ //
// Render Table
// ------------------------------------------------------------------ //

function renderTrafficTable(data) {
  const tbody = document.getElementById('traffic-tbody');
  const countEl = document.getElementById('traffic-count');
  if (!tbody) return;

  const records = data.records || [];
  if (countEl) countEl.textContent = `(${(data.total || 0).toLocaleString()} records)`;

  if (!records.length) {
    tbody.innerHTML = '<tr><td colspan="11" class="text-center text-muted py-4">No records found. Load the demo dataset or upload a CSV.</td></tr>';
    renderPagination(data, 'traffic-pagination', 'traffic-pagination-info', (p) => { trafficPage = p; loadTraffic(); });
    return;
  }

  tbody.innerHTML = records.map(r => {
    const cls = r.classification || 'NORMAL';
    const totalBytes = ((r.bytes_sent || 0) + (r.bytes_received || 0)).toLocaleString();
    return `<tr>
      <td class="text-muted small">${(r.timestamp || '').slice(0, 19)}</td>
      <td class="text-cyan">${esc(r.source_ip)}</td>
      <td class="text-cyan">${esc(r.destination_ip)}</td>
      <td>${esc(r.protocol || '–')}</td>
      <td>${r.source_port || '–'}</td>
      <td>${r.destination_port || '–'}</td>
      <td>${Math.round(r.packet_count || 0).toLocaleString()}</td>
      <td>${totalBytes}</td>
      <td>
        <span class="risk-pill" style="color:${riskColor(r.risk_score)}">
          ${(r.risk_score || 0).toFixed(1)}
        </span>
      </td>
      <td><span class="badge ${NIDS.classColor(cls)}">${cls}</span></td>
      <td>
        <a href="/analysis/${r.id}" class="btn btn-xs btn-outline-secondary" title="View Analysis">
          <i class="bi bi-bar-chart-line"></i>
        </a>
        <button class="btn btn-xs btn-outline-secondary ms-1" title="Quick View" onclick="quickView(${r.id})">
          <i class="bi bi-eye"></i>
        </button>
      </td>
    </tr>`;
  }).join('');

  renderPagination(data, 'traffic-pagination', 'traffic-pagination-info', (p) => { trafficPage = p; loadTraffic(); });
}

function riskColor(score) {
  if (score >= 80) return '#f85149';
  if (score >= 60) return '#e3611c';
  if (score >= 40) return '#d29922';
  if (score >= 20) return '#d29922';
  return '#3fb950';
}

// ------------------------------------------------------------------ //
// Quick View Modal
// ------------------------------------------------------------------ //

async function quickView(id) {
  const modal = new bootstrap.Modal(document.getElementById('traffic-detail-modal'));
  const body = document.getElementById('traffic-detail-body');
  body.innerHTML = '<div class="text-center py-3"><span class="spinner-border spinner-border-sm"></span></div>';
  modal.show();

  try {
    const res = await fetch(`/api/traffic/${id}`);
    const r = await res.json();
    if (r.error) { body.innerHTML = `<div class="text-danger">${esc(r.error)}</div>`; return; }

    body.innerHTML = `
      <div class="detail-grid">
        ${detailRow('Source IP', r.source_ip)}
        ${detailRow('Destination IP', r.destination_ip)}
        ${detailRow('Protocol', r.protocol)}
        ${detailRow('Src Port', r.source_port)}
        ${detailRow('Dst Port', r.destination_port)}
        ${detailRow('Packet Count', Math.round(r.packet_count || 0))}
        ${detailRow('Packet Size', r.packet_size + ' bytes')}
        ${detailRow('Duration', (r.duration || 0).toFixed(2) + 's')}
        ${detailRow('Bytes Sent', (r.bytes_sent || 0).toLocaleString())}
        ${detailRow('Bytes Received', (r.bytes_received || 0).toLocaleString())}
        ${detailRow('Connections', r.connection_count)}
        ${detailRow('Risk Score', (r.risk_score || 0).toFixed(2))}
        ${detailRow('Classification', `<span class="badge ${NIDS.classColor(r.classification)}">${r.classification}</span>`)}
        ${detailRow('Attack Type', r.attack_type || 'NONE')}
        ${detailRow('Timestamp', r.timestamp || '–')}
      </div>
      ${r.detection_reason ? `
        <hr style="border-color:#30363d">
        <p class="text-muted small mb-1">Detection Reasons:</p>
        <div style="font-size:12px">${r.detection_reason.split(' | ').map(s => `<div class="reason-item mb-1">${esc(s)}</div>`).join('')}</div>
      ` : ''}
      <div class="mt-3">
        <a href="/analysis/${r.id}" class="btn btn-sm btn-accent">
          <i class="bi bi-bar-chart-line"></i> Full Analysis
        </a>
      </div>`;
  } catch (e) {
    body.innerHTML = '<div class="text-danger">Failed to load record details.</div>';
  }
}

function detailRow(label, value) {
  return `<div class="detail-item">
    <span class="detail-label">${label}</span>
    <span class="detail-value">${value ?? '–'}</span>
  </div>`;
}

// ------------------------------------------------------------------ //
// Pagination Helper
// ------------------------------------------------------------------ //

function renderPagination(data, containerId, infoId, onPage) {
  const container = document.getElementById(containerId);
  const info = document.getElementById(infoId);
  if (!container) return;
  if (info) info.textContent = `Page ${data.page} of ${data.total_pages} · ${(data.total||0).toLocaleString()} records`;

  const prev = data.page > 1;
  const next = data.page < data.total_pages;

  let html = `<button class="btn btn-sm btn-outline-secondary" ${prev ? '' : 'disabled'} id="${containerId}-prev">
    <i class="bi bi-chevron-left"></i>
  </button>`;

  // Show up to 5 page buttons
  const start = Math.max(1, data.page - 2);
  const end = Math.min(data.total_pages, start + 4);
  for (let p = start; p <= end; p++) {
    html += `<button class="btn btn-sm ${p === data.page ? 'btn-accent' : 'btn-outline-secondary'}" data-page="${p}">${p}</button>`;
  }

  html += `<button class="btn btn-sm btn-outline-secondary" ${next ? '' : 'disabled'} id="${containerId}-next">
    <i class="bi bi-chevron-right"></i>
  </button>`;

  container.innerHTML = html;

  container.querySelector(`#${containerId}-prev`)?.addEventListener('click', () => { onPage(data.page - 1); });
  container.querySelector(`#${containerId}-next`)?.addEventListener('click', () => { onPage(data.page + 1); });
  container.querySelectorAll('[data-page]').forEach(btn => {
    btn.addEventListener('click', () => onPage(parseInt(btn.dataset.page)));
  });
}

// ------------------------------------------------------------------ //
// Filters
// ------------------------------------------------------------------ //

function applyFilters() {
  trafficPage = 1;
  trafficFilters = {
    search: document.getElementById('search-ip')?.value.trim() || '',
    classification: document.getElementById('filter-classification')?.value || '',
    protocol: document.getElementById('filter-protocol')?.value || '',
  };
  loadTraffic();
}

function clearFilters() {
  document.getElementById('search-ip').value = '';
  document.getElementById('filter-classification').value = '';
  document.getElementById('filter-protocol').value = '';
  trafficFilters = {};
  trafficPage = 1;
  loadTraffic();
}

document.getElementById('btn-apply-filters')?.addEventListener('click', applyFilters);
document.getElementById('btn-clear-filters')?.addEventListener('click', clearFilters);

document.getElementById('page-size')?.addEventListener('change', e => {
  trafficPageSize = parseInt(e.target.value);
  trafficPage = 1;
  loadTraffic();
});

// Enter to search
document.getElementById('search-ip')?.addEventListener('keydown', e => {
  if (e.key === 'Enter') applyFilters();
});

// Escape helper
function esc(s) {
  if (s === null || s === undefined) return '–';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

function refreshPage() { loadTraffic(); }

loadTraffic();

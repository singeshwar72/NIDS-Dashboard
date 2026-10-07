/* alerts.js — Alert Management page logic */

'use strict';

let alertPage = 1;
let alertPageSize = 50;
let alertFilters = {};

// ------------------------------------------------------------------ //
// Load Alerts
// ------------------------------------------------------------------ //

async function loadAlerts() {
  const tbody = document.getElementById('alerts-tbody');
  if (tbody) tbody.innerHTML = '<tr><td colspan="8" class="text-center text-muted py-4"><span class="spinner-border spinner-border-sm me-2"></span>Loading…</td></tr>';

  const params = new URLSearchParams({
    page: alertPage,
    page_size: alertPageSize,
    ...alertFilters,
  });
  for (const [k, v] of [...params.entries()]) { if (!v) params.delete(k); }

  try {
    const res = await fetch('/api/alerts?' + params);
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const data = await res.json();
    renderAlertsTable(data);
  } catch (e) {
    if (tbody) tbody.innerHTML = '<tr><td colspan="8" class="text-center text-danger">Failed to load alerts.</td></tr>';
    console.error('Alerts load error:', e);
  }
}

// ------------------------------------------------------------------ //
// Render Table
// ------------------------------------------------------------------ //

function renderAlertsTable(data) {
  const tbody = document.getElementById('alerts-tbody');
  const countEl = document.getElementById('alert-count');
  if (!tbody) return;

  const alerts = data.alerts || [];
  if (countEl) countEl.textContent = `(${(data.total || 0).toLocaleString()} alerts)`;

  if (!alerts.length) {
    tbody.innerHTML = '<tr><td colspan="8" class="text-center text-muted py-4">No alerts found.</td></tr>';
    renderAlertsPagination(data);
    return;
  }

  tbody.innerHTML = alerts.map(a => `
    <tr id="alert-row-${a.id}">
      <td class="text-muted small">${(a.timestamp || a.created_at || '').slice(0, 19)}</td>
      <td class="text-cyan">${esc(a.source_ip)}</td>
      <td class="text-cyan">${esc(a.destination_ip)}</td>
      <td>${esc(a.attack_type || 'UNKNOWN')}</td>
      <td><span class="badge ${NIDS.severityColor(a.severity)}">${a.severity || '–'}</span></td>
      <td><span style="color:${riskColor(a.risk_score)};font-weight:600">${(a.risk_score||0).toFixed(1)}</span></td>
      <td><span class="badge ${NIDS.statusColor(a.status)}" id="alert-status-${a.id}">${a.status || 'NEW'}</span></td>
      <td>
        <button class="btn btn-xs btn-outline-secondary" onclick="viewAlert(${a.id})" title="View">
          <i class="bi bi-eye"></i>
        </button>
        ${a.status !== 'ACKNOWLEDGED' ? `
        <button class="btn btn-xs btn-outline-warning ms-1" onclick="updateStatus(${a.id},'ACKNOWLEDGED')" title="Acknowledge">
          <i class="bi bi-check"></i>
        </button>` : ''}
        ${a.status !== 'RESOLVED' ? `
        <button class="btn btn-xs btn-outline-success ms-1" onclick="updateStatus(${a.id},'RESOLVED')" title="Resolve">
          <i class="bi bi-check-all"></i>
        </button>` : ''}
      </td>
    </tr>`
  ).join('');

  renderAlertsPagination(data);
}

function riskColor(score) {
  if (score >= 80) return '#f85149';
  if (score >= 60) return '#e3611c';
  if (score >= 40) return '#d29922';
  return '#3fb950';
}

function renderAlertsPagination(data) {
  const container = document.getElementById('alerts-pagination');
  const info = document.getElementById('alerts-pagination-info');
  if (!container) return;
  if (info) info.textContent = `Page ${data.page} of ${data.total_pages}`;

  let html = `<button class="btn btn-sm btn-outline-secondary" ${data.page > 1 ? '' : 'disabled'} id="alerts-prev">
    <i class="bi bi-chevron-left"></i></button>`;
  const start = Math.max(1, data.page - 2);
  const end = Math.min(data.total_pages, start + 4);
  for (let p = start; p <= end; p++) {
    html += `<button class="btn btn-sm ${p === data.page ? 'btn-accent' : 'btn-outline-secondary'}" data-page="${p}">${p}</button>`;
  }
  html += `<button class="btn btn-sm btn-outline-secondary" ${data.page < data.total_pages ? '' : 'disabled'} id="alerts-next">
    <i class="bi bi-chevron-right"></i></button>`;

  container.innerHTML = html;
  container.querySelector('#alerts-prev')?.addEventListener('click', () => { alertPage--; loadAlerts(); });
  container.querySelector('#alerts-next')?.addEventListener('click', () => { alertPage++; loadAlerts(); });
  container.querySelectorAll('[data-page]').forEach(btn => {
    btn.addEventListener('click', () => { alertPage = parseInt(btn.dataset.page); loadAlerts(); });
  });
}

// ------------------------------------------------------------------ //
// Update Alert Status
// ------------------------------------------------------------------ //

async function updateStatus(id, newStatus) {
  try {
    const res = await fetch(`/api/alerts/${id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status: newStatus }),
    });
    const data = await res.json();
    if (data.success) {
      NIDS.showToast(`Alert #${id} marked as ${newStatus}.`, 'success');
      loadAlerts(); // reload to update action buttons
    } else {
      NIDS.showToast(data.error || 'Update failed.', 'danger');
    }
  } catch (e) {
    NIDS.showToast('Request failed.', 'danger');
  }
}

// ------------------------------------------------------------------ //
// View Alert Detail Modal
// ------------------------------------------------------------------ //

async function viewAlert(id) {
  const modal = new bootstrap.Modal(document.getElementById('alert-detail-modal'));
  const body = document.getElementById('alert-detail-body');
  body.innerHTML = '<div class="text-center py-3"><span class="spinner-border spinner-border-sm"></span></div>';
  modal.show();

  // Find alert in current data
  try {
    const res = await fetch(`/api/alerts?page=1&page_size=1000`);
    const data = await res.json();
    const alert = (data.alerts || []).find(a => a.id === id);
    if (!alert) {
      body.innerHTML = '<div class="text-danger">Alert not found.</div>';
      return;
    }

    body.innerHTML = `
      <div class="detail-grid">
        <div class="detail-item"><span class="detail-label">Alert ID</span><span class="detail-value">#${alert.id}</span></div>
        <div class="detail-item"><span class="detail-label">Timestamp</span><span class="detail-value">${alert.timestamp || alert.created_at || '–'}</span></div>
        <div class="detail-item"><span class="detail-label">Source IP</span><span class="detail-value text-cyan">${esc(alert.source_ip)}</span></div>
        <div class="detail-item"><span class="detail-label">Destination IP</span><span class="detail-value text-cyan">${esc(alert.destination_ip)}</span></div>
        <div class="detail-item"><span class="detail-label">Attack Type</span><span class="detail-value">${esc(alert.attack_type)}</span></div>
        <div class="detail-item"><span class="detail-label">Severity</span><span class="detail-value"><span class="badge ${NIDS.severityColor(alert.severity)}">${alert.severity}</span></span></div>
        <div class="detail-item"><span class="detail-label">Risk Score</span><span class="detail-value" style="color:${riskColor(alert.risk_score)};font-weight:700">${(alert.risk_score||0).toFixed(2)}</span></div>
        <div class="detail-item"><span class="detail-label">Status</span><span class="detail-value"><span class="badge ${NIDS.statusColor(alert.status)}">${alert.status}</span></span></div>
      </div>
      ${alert.description ? `
        <hr style="border-color:#30363d;margin:12px 0">
        <p class="text-muted mb-1" style="font-size:11px;text-transform:uppercase">Description</p>
        <p style="font-size:13px">${esc(alert.description)}</p>
      ` : ''}
      <div class="mt-3 d-flex gap-2">
        ${alert.status !== 'ACKNOWLEDGED' ? `<button class="btn btn-sm btn-outline-warning" onclick="updateStatus(${alert.id},'ACKNOWLEDGED');bootstrap.Modal.getInstance(document.getElementById('alert-detail-modal')).hide()">Acknowledge</button>` : ''}
        ${alert.status !== 'RESOLVED' ? `<button class="btn btn-sm btn-outline-success" onclick="updateStatus(${alert.id},'RESOLVED');bootstrap.Modal.getInstance(document.getElementById('alert-detail-modal')).hide()">Resolve</button>` : ''}
      </div>`;
  } catch (e) {
    body.innerHTML = '<div class="text-danger">Failed to load alert.</div>';
  }
}

// ------------------------------------------------------------------ //
// Filters
// ------------------------------------------------------------------ //

document.getElementById('btn-alert-filter')?.addEventListener('click', () => {
  alertPage = 1;
  alertFilters = {
    search: document.getElementById('alert-search')?.value.trim() || '',
    status: document.getElementById('alert-filter-status')?.value || '',
    severity: document.getElementById('alert-filter-severity')?.value || '',
  };
  loadAlerts();
});

document.getElementById('btn-alert-clear')?.addEventListener('click', () => {
  document.getElementById('alert-search').value = '';
  document.getElementById('alert-filter-status').value = '';
  document.getElementById('alert-filter-severity').value = '';
  alertFilters = {};
  alertPage = 1;
  loadAlerts();
});

document.getElementById('alert-page-size')?.addEventListener('change', e => {
  alertPageSize = parseInt(e.target.value);
  alertPage = 1;
  loadAlerts();
});

document.getElementById('alert-search')?.addEventListener('keydown', e => {
  if (e.key === 'Enter') document.getElementById('btn-alert-filter').click();
});

function esc(s) {
  if (s === null || s === undefined) return '–';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

function refreshPage() { loadAlerts(); }

loadAlerts();

/* dashboard.js — Dashboard page logic */

'use strict';

// Chart instances (kept to allow updates)
let chartClassification = null;
let chartAttackTypes = null;
let chartAlertsTime = null;
let chartRiskDist = null;
let chartTopIPs = null;

// Demo monitoring state
let monitoringInterval = null;
let monitoringRunning = false;

// ------------------------------------------------------------------ //
// KPI
// ------------------------------------------------------------------ //

async function loadKPIs() {
  try {
    const res = await fetch('/api/dashboard-stats');
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const d = await res.json();

    const total = d.total || 0;
    document.getElementById('kpi-total').textContent = total.toLocaleString();
    document.getElementById('kpi-normal').textContent = (d.normal || 0).toLocaleString();
    document.getElementById('kpi-suspicious').textContent = (d.suspicious || 0).toLocaleString();
    document.getElementById('kpi-high').textContent = (d.high_risk || 0).toLocaleString();
    document.getElementById('kpi-critical').textContent = (d.critical || 0).toLocaleString();

    const pct = (v) => total > 0 ? ((v / total) * 100).toFixed(1) + '%' : '–';
    document.getElementById('kpi-normal-pct').textContent = pct(d.normal || 0);
    document.getElementById('kpi-suspicious-pct').textContent = pct(d.suspicious || 0);
    document.getElementById('kpi-high-pct').textContent = pct(d.high_risk || 0);
    document.getElementById('kpi-critical-pct').textContent = pct(d.critical || 0);
  } catch (e) {
    console.error('KPI load error:', e);
  }
}

// ------------------------------------------------------------------ //
// Charts
// ------------------------------------------------------------------ //

const CHART_OPTS = {
  responsive: true,
  maintainAspectRatio: false,
  plugins: {
    legend: { labels: { color: '#8b949e', font: { size: 11 } } },
    tooltip: { backgroundColor: '#1c2230', titleColor: '#e6edf3', bodyColor: '#8b949e', borderColor: '#30363d', borderWidth: 1 },
  },
};

const COLORS = {
  normal:     'rgba(63,185,80,.8)',
  low:        'rgba(210,153,34,.8)',
  suspicious: 'rgba(210,153,34,.85)',
  high:       'rgba(227,97,28,.85)',
  critical:   'rgba(248,81,73,.85)',
  cyan:       'rgba(88,166,255,.8)',
  purple:     'rgba(165,163,255,.8)',
};

function makeChart(id, type, data, extraOpts = {}) {
  const ctx = document.getElementById(id)?.getContext('2d');
  if (!ctx) return null;
  return new Chart(ctx, {
    type,
    data,
    options: { ...CHART_OPTS, ...extraOpts },
  });
}

function updateChartData(chart, labels, data) {
  if (!chart) return;
  chart.data.labels = labels;
  chart.data.datasets[0].data = data;
  chart.update('active');
}

async function loadClassificationChart() {
  try {
    const res = await fetch('/api/chart/classification');
    const d = await res.json();
    const colors = [COLORS.normal, COLORS.suspicious, COLORS.high, COLORS.critical];
    if (!chartClassification) {
      chartClassification = makeChart('chart-classification', 'doughnut', {
        labels: d.labels,
        datasets: [{ data: d.data, backgroundColor: colors, borderColor: '#1c2230', borderWidth: 2 }],
      }, { plugins: { ...CHART_OPTS.plugins, legend: { position: 'bottom', labels: { color: '#8b949e', font: { size: 11 } } } } });
    } else {
      updateChartData(chartClassification, d.labels, d.data);
    }
  } catch (e) { console.error('Classification chart error:', e); }
}

async function loadAttackTypesChart() {
  try {
    const res = await fetch('/api/chart/attack-types');
    const d = await res.json();
    if (!d.labels || !d.labels.length) {
      d.labels = ['No Data'];
      d.data = [1];
    }
    const colors = d.labels.map((_, i) =>
      [COLORS.critical, COLORS.high, COLORS.suspicious, COLORS.low, COLORS.cyan, COLORS.purple][i % 6]
    );
    if (!chartAttackTypes) {
      chartAttackTypes = makeChart('chart-attack-types', 'bar', {
        labels: d.labels,
        datasets: [{ label: 'Count', data: d.data, backgroundColor: colors, borderRadius: 4 }],
      }, {
        plugins: { ...CHART_OPTS.plugins, legend: { display: false } },
        scales: {
          x: { ticks: { color: '#8b949e', font: { size: 10 } }, grid: { color: '#21262d' } },
          y: { ticks: { color: '#8b949e', font: { size: 10 } }, grid: { color: '#21262d' } },
        },
      });
    } else {
      updateChartData(chartAttackTypes, d.labels, d.data);
    }
  } catch (e) { console.error('Attack types chart error:', e); }
}

async function loadAlertsTimeChart() {
  try {
    const res = await fetch('/api/chart/alerts-over-time?days=7');
    const d = await res.json();
    if (!chartAlertsTime) {
      chartAlertsTime = makeChart('chart-alerts-time', 'line', {
        labels: d.labels || [],
        datasets: [{
          label: 'Alerts',
          data: d.data || [],
          borderColor: COLORS.critical,
          backgroundColor: 'rgba(248,81,73,.12)',
          fill: true,
          tension: 0.4,
          pointBackgroundColor: COLORS.critical,
        }],
      }, {
        scales: {
          x: { ticks: { color: '#8b949e', font: { size: 10 } }, grid: { color: '#21262d' } },
          y: { ticks: { color: '#8b949e', font: { size: 10 } }, grid: { color: '#21262d' }, beginAtZero: true },
        },
      });
    } else {
      updateChartData(chartAlertsTime, d.labels, d.data);
    }
  } catch (e) { console.error('Alerts time chart error:', e); }
}

async function loadRiskDistChart() {
  try {
    const res = await fetch('/api/chart/risk-distribution');
    const d = await res.json();
    const colors = [COLORS.normal, COLORS.low, COLORS.suspicious, COLORS.high, COLORS.critical];
    if (!chartRiskDist) {
      chartRiskDist = makeChart('chart-risk-dist', 'bar', {
        labels: d.labels,
        datasets: [{ label: 'Records', data: d.data, backgroundColor: colors, borderRadius: 4 }],
      }, {
        plugins: { ...CHART_OPTS.plugins, legend: { display: false } },
        scales: {
          x: { ticks: { color: '#8b949e', font: { size: 9 } }, grid: { color: '#21262d' } },
          y: { ticks: { color: '#8b949e', font: { size: 10 } }, grid: { color: '#21262d' }, beginAtZero: true },
        },
      });
    } else {
      updateChartData(chartRiskDist, d.labels, d.data);
    }
  } catch (e) { console.error('Risk dist chart error:', e); }
}

async function loadTopIPsChart() {
  try {
    const res = await fetch('/api/chart/top-source-ips?limit=10');
    const d = await res.json();
    if (!chartTopIPs) {
      chartTopIPs = makeChart('chart-top-ips', 'bar', {
        labels: d.labels || [],
        datasets: [{
          label: 'Connections',
          data: d.data || [],
          backgroundColor: COLORS.cyan,
          borderRadius: 4,
        }],
      }, {
        indexAxis: 'y',
        plugins: { ...CHART_OPTS.plugins, legend: { display: false } },
        scales: {
          x: { ticks: { color: '#8b949e', font: { size: 10 } }, grid: { color: '#21262d' }, beginAtZero: true },
          y: { ticks: { color: '#8b949e', font: { size: 10 } }, grid: { color: '#21262d' } },
        },
      });
    } else {
      updateChartData(chartTopIPs, d.labels, d.data);
    }
  } catch (e) { console.error('Top IPs chart error:', e); }
}

// ------------------------------------------------------------------ //
// Load Demo Dataset
// ------------------------------------------------------------------ //

document.getElementById('btn-load-demo')?.addEventListener('click', async () => {
  const btn = document.getElementById('btn-load-demo');
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner-border spinner-border-sm"></span> Loading…';
  try {
    const res = await fetch('/api/demo', { method: 'POST' });
    const data = await res.json();
    if (data.success) {
      NIDS.showToast(
        `Demo loaded: ${data.valid_rows} records processed, ${data.alerts_generated} alerts generated.`,
        'success'
      );
      refreshAll();
    } else {
      NIDS.showToast(data.error || 'Failed to load demo dataset.', 'danger');
    }
  } catch (e) {
    NIDS.showToast('Request failed.', 'danger');
  } finally {
    btn.disabled = false;
    btn.innerHTML = '<i class="bi bi-play-circle-fill"></i> Load Demo Dataset';
  }
});

// ------------------------------------------------------------------ //
// Demo Monitoring
// ------------------------------------------------------------------ //

document.getElementById('btn-start-monitoring')?.addEventListener('click', () => {
  if (monitoringRunning) return;
  monitoringRunning = true;
  document.getElementById('btn-start-monitoring').classList.add('d-none');
  document.getElementById('btn-stop-monitoring').classList.remove('d-none');
  document.getElementById('monitoring-status').textContent = 'Monitoring active — refreshing every 5s';

  monitoringInterval = setInterval(() => {
    refreshAll();
  }, 5000);
});

document.getElementById('btn-stop-monitoring')?.addEventListener('click', () => {
  stopMonitoring();
});

function stopMonitoring() {
  if (monitoringInterval) clearInterval(monitoringInterval);
  monitoringRunning = false;
  monitoringInterval = null;
  document.getElementById('btn-stop-monitoring').classList.add('d-none');
  document.getElementById('btn-start-monitoring').classList.remove('d-none');
  document.getElementById('monitoring-status').textContent = '';
}

// ------------------------------------------------------------------ //
// Refresh All
// ------------------------------------------------------------------ //

async function refreshAll() {
  await Promise.all([
    loadKPIs(),
    loadClassificationChart(),
    loadAttackTypesChart(),
    loadAlertsTimeChart(),
    loadRiskDistChart(),
    loadTopIPsChart(),
  ]);
}

// Expose for topbar global refresh
function refreshPage() { refreshAll(); }

// Initial load
refreshAll();

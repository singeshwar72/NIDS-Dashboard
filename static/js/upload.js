/* upload.js — Dataset Upload page logic */

'use strict';

let selectedFile = null;

// ------------------------------------------------------------------ //
// Drop Zone
// ------------------------------------------------------------------ //

const dropZone = document.getElementById('drop-zone');
const fileInput = document.getElementById('file-input');

dropZone?.addEventListener('click', () => fileInput?.click());

dropZone?.addEventListener('dragover', e => {
  e.preventDefault();
  dropZone.classList.add('drag-over');
});

dropZone?.addEventListener('dragleave', () => dropZone.classList.remove('drag-over'));

dropZone?.addEventListener('drop', e => {
  e.preventDefault();
  dropZone.classList.remove('drag-over');
  const files = e.dataTransfer?.files;
  if (files?.length) handleFileSelect(files[0]);
});

fileInput?.addEventListener('change', () => {
  if (fileInput.files?.length) handleFileSelect(fileInput.files[0]);
});

function handleFileSelect(file) {
  if (!file.name.toLowerCase().endsWith('.csv')) {
    NIDS.showToast('Only CSV files are supported.', 'danger');
    return;
  }
  if (file.size > 10 * 1024 * 1024) {
    NIDS.showToast('File exceeds 10 MB limit.', 'danger');
    return;
  }

  selectedFile = file;
  document.getElementById('file-name-display').textContent = file.name;
  document.getElementById('file-size-display').textContent = formatBytes(file.size);
  document.getElementById('file-info').classList.remove('d-none');
  document.getElementById('upload-result').classList.add('d-none');
  document.getElementById('btn-upload').disabled = false;
}

document.getElementById('btn-remove-file')?.addEventListener('click', () => {
  selectedFile = null;
  if (fileInput) fileInput.value = '';
  document.getElementById('file-info').classList.add('d-none');
  document.getElementById('btn-upload').disabled = true;
  document.getElementById('upload-result').classList.add('d-none');
});

// ------------------------------------------------------------------ //
// Upload
// ------------------------------------------------------------------ //

document.getElementById('btn-upload')?.addEventListener('click', async () => {
  if (!selectedFile) return;

  const btn = document.getElementById('btn-upload');
  const progress = document.getElementById('upload-progress');
  const statusText = document.getElementById('upload-status-text');
  const resultDiv = document.getElementById('upload-result');

  btn.disabled = true;
  progress.classList.remove('d-none');
  resultDiv.classList.add('d-none');
  statusText.textContent = 'Uploading and processing…';

  const formData = new FormData();
  formData.append('file', selectedFile);

  try {
    const res = await fetch('/api/upload', { method: 'POST', body: formData });
    const data = await res.json();

    progress.classList.add('d-none');

    if (data.success) {
      showUploadResult(data);
      NIDS.showToast(`Successfully processed ${data.valid_rows} records.`, 'success');
    } else {
      resultDiv.innerHTML = `<div class="alert alert-danger">${esc(data.error || 'Upload failed.')}</div>`;
      resultDiv.classList.remove('d-none');
      NIDS.showToast(data.error || 'Upload failed.', 'danger');
    }
  } catch (e) {
    progress.classList.add('d-none');
    resultDiv.innerHTML = '<div class="alert alert-danger">Upload request failed. Please try again.</div>';
    resultDiv.classList.remove('d-none');
    NIDS.showToast('Upload failed.', 'danger');
  } finally {
    btn.disabled = false;
  }
});

function showUploadResult(data) {
  const resultDiv = document.getElementById('upload-result');
  const modeColor = data.detection_mode === 'Rule-Based + ML' ? '#a5a3ff' : '#58a6ff';

  resultDiv.innerHTML = `
    <div class="result-card">
      <div class="d-flex align-items-center gap-2 mb-2">
        <i class="bi bi-check-circle-fill text-success"></i>
        <strong>Processing Complete</strong>
        <span class="text-muted small ms-auto">Mode: <span style="color:${modeColor}">${esc(data.detection_mode)}</span></span>
      </div>
      <div class="result-grid">
        <div class="result-item">
          <div class="result-number">${data.total_rows}</div>
          <div class="result-label">Total Rows</div>
        </div>
        <div class="result-item">
          <div class="result-number text-success">${data.valid_rows}</div>
          <div class="result-label">Valid</div>
        </div>
        <div class="result-item">
          <div class="result-number text-danger">${data.invalid_rows}</div>
          <div class="result-label">Invalid</div>
        </div>
        <div class="result-item">
          <div class="result-number" style="color:#3fb950">${data.normal}</div>
          <div class="result-label">Normal</div>
        </div>
        <div class="result-item">
          <div class="result-number" style="color:#d29922">${data.suspicious}</div>
          <div class="result-label">Suspicious</div>
        </div>
        <div class="result-item">
          <div class="result-number" style="color:#e3611c">${data.high_risk}</div>
          <div class="result-label">High Risk</div>
        </div>
        <div class="result-item">
          <div class="result-number" style="color:#f85149">${data.critical}</div>
          <div class="result-label">Critical</div>
        </div>
        <div class="result-item">
          <div class="result-number" style="color:#f85149">${data.alerts_generated}</div>
          <div class="result-label">Alerts</div>
        </div>
      </div>
      <div class="mt-3 d-flex gap-2">
        <a href="/traffic" class="btn btn-sm btn-outline-secondary">
          <i class="bi bi-table"></i> View Traffic
        </a>
        <a href="/alerts" class="btn btn-sm btn-outline-secondary">
          <i class="bi bi-bell"></i> View Alerts
        </a>
        <a href="/dashboard" class="btn btn-sm btn-accent">
          <i class="bi bi-speedometer2"></i> Dashboard
        </a>
      </div>
    </div>`;
  resultDiv.classList.remove('d-none');
}

function formatBytes(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
}

function esc(s) {
  if (!s) return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

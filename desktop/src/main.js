const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

// ── State ──
let currentView = 'scan';
let scanResult = null;
let selectedPath = null;
let ollamaUrl = 'http://localhost:11434';
let statsInterval = null;
let isScanning = false;
let scanAbortController = null;

// ── DOM ready ──
window.addEventListener('DOMContentLoaded', async () => {
  setupNavigation();
  setupScanControls();
  setupSettings();
  await checkOllama();
});

// ── Navigation ──
function setupNavigation() {
  document.querySelectorAll('.nav-item').forEach(item => {
    item.addEventListener('click', () => switchView(item.dataset.view));
  });
}

function switchView(view) {
  currentView = view;
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  document.querySelector(`.nav-item[data-view="${view}"]`).classList.add('active');
  document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
  document.getElementById(`view-${view}`).classList.add('active');
  const titles = { scan: 'Scan', results: 'Results', settings: 'Settings' };
  document.getElementById('view-title').textContent = titles[view] || view;
}

// ── Ollama health check ──
async function checkOllama() {
  const dot = document.getElementById('ollama-dot');
  const status = document.getElementById('ollama-status');
  const setup = document.getElementById('ollama-setup');
  try {
    const ok = await invoke('check_ollama', { url: ollamaUrl });
    dot.className = ok ? 'status-dot online' : 'status-dot offline';
    status.textContent = ok ? 'Ollama connected' : 'Ollama offline';
    setup.style.display = ok ? 'none' : 'block';
    if (ok) loadModels();
  } catch {
    dot.className = 'status-dot offline';
    status.textContent = 'Ollama offline';
    setup.style.display = 'block';
  }
}

let selectedBeamModel = 'torchsight/beam';
let selectedVisionModel = 'llama3.2-vision';

// The 3 official Beam model variants + 1 vision model
const BEAM_MODELS = [
  { id: 'torchsight/beam', label: 'torchsight/beam', quant: 'q4_K_M', size: '~17 GB', desc: 'Default — recommended for most systems' },
  { id: 'torchsight/beam:q8_0', label: 'torchsight/beam:q8_0', quant: 'q8_0', size: '~28 GB', desc: 'Higher accuracy, needs more resources' },
  { id: 'torchsight/beam:f16', label: 'torchsight/beam:f16', quant: 'f16', size: '~54 GB', desc: 'Full precision, datacenter GPUs only' },
];

const VISION_MODELS = [
  { id: 'llama3.2-vision', label: 'llama3.2-vision', size: '~4.9 GB', desc: 'Image analysis and description' },
];

async function loadModels() {
  const beamList = document.getElementById('beam-model-list');
  const visionList = document.getElementById('vision-model-list');

  try {
    const installed = await invoke('list_models', { url: ollamaUrl });

    // Render Beam models
    beamList.innerHTML = BEAM_MODELS.map(m => {
      const isInstalled = installed.some(i => i.startsWith(m.id.split(':')[0]) && (m.id.includes(':') ? i.includes(m.id.split(':')[1]) : true));
      const isSelected = m.id === selectedBeamModel;
      return `
        <div class="model-option${isSelected ? ' selected' : ''}${!isInstalled ? ' not-installed' : ''}" data-model="${esc(m.id)}">
          <div class="model-radio"></div>
          <div style="flex:1">
            <span class="model-name">${esc(m.label)}</span>
            <div style="font-size:10px;color:var(--text-muted);margin-top:2px;">${esc(m.desc)}</div>
          </div>
          <span class="model-size">${isInstalled ? m.size : 'Not installed'}</span>
        </div>
      `;
    }).join('');

    wireModelSelect(beamList, (model) => { selectedBeamModel = model; });

    // Render Vision model
    visionList.innerHTML = VISION_MODELS.map(m => {
      const isInstalled = installed.some(i => i.startsWith(m.id));
      return `
        <div class="model-option selected${!isInstalled ? ' not-installed' : ''}" data-model="${esc(m.id)}">
          <div class="model-radio"></div>
          <div style="flex:1">
            <span class="model-name">${esc(m.label)}</span>
            <div style="font-size:10px;color:var(--text-muted);margin-top:2px;">${esc(m.desc)}</div>
          </div>
          <span class="model-size">${isInstalled ? m.size : 'Not installed'}</span>
        </div>
      `;
    }).join('');

  } catch {
    beamList.innerHTML = '<div class="model-select-loading">Could not connect to Ollama</div>';
    visionList.innerHTML = '';
  }
}

function wireModelSelect(container, onSelect) {
  container.querySelectorAll('.model-option').forEach(el => {
    el.addEventListener('click', () => {
      container.querySelectorAll('.model-option').forEach(o => o.classList.remove('selected'));
      el.classList.add('selected');
      onSelect(el.dataset.model);
    });
  });
}

// ── Scan controls ──
function setupScanControls() {
  document.getElementById('scan-folder-btn').addEventListener('click', pickFolder);
  document.getElementById('drop-zone').addEventListener('click', (e) => {
    if (e.target.id !== 'scan-btn') pickFolder();
  });
  document.getElementById('scan-btn').addEventListener('click', () => {
    if (selectedPath) startScan(selectedPath);
  });
  document.getElementById('new-scan-btn').addEventListener('click', resetScan);
  document.getElementById('export-pdf-btn').addEventListener('click', exportPdf);
}

async function exportPdf() {
  // Stamp the current date/time so the print CSS header can show it
  const el = document.getElementById('results-content');
  if (el) {
    el.setAttribute('data-timestamp', new Date().toLocaleString());
  }
  window.print();
}

function resetScan() {
  selectedPath = null;
  scanResult = null;
  document.getElementById('selected-path').textContent = '';
  document.getElementById('scan-btn').disabled = true;
  document.getElementById('file-list-container').style.display = 'none';
  document.getElementById('results-empty').style.display = '';
  document.getElementById('results-content').style.display = 'none';
  document.getElementById('findings-badge').style.display = 'none';
  switchView('scan');
}

async function pickFolder() {
  try {
    const selected = await window.__TAURI__.dialog.open({
      directory: true, multiple: false, title: 'Select folder to scan',
    });
    if (selected) {
      selectedPath = selected;
      document.getElementById('selected-path').textContent = selected;
      document.getElementById('scan-btn').disabled = false;

      // Immediately list files
      showFileList(selected);
    }
  } catch (err) { console.error('Folder picker error:', err); }
}

async function showFileList(path) {
  const container = document.getElementById('file-list-container');
  container.style.display = 'block';
  container.innerHTML = '<div class="file-list-loading">Scanning directory...</div>';

  try {
    const files = await invoke('list_files', { path });
    if (files.length === 0) {
      container.innerHTML = '<div class="file-list-loading">No files found in directory</div>';
      return;
    }

    // Group by extension
    const extCounts = {};
    let totalSize = 0;
    files.forEach(f => {
      const ext = f.extension || 'no ext';
      extCounts[ext] = (extCounts[ext] || 0) + 1;
      totalSize += f.size;
    });

    const extTags = Object.entries(extCounts)
      .sort((a, b) => b[1] - a[1])
      .map(([ext, count]) => `<span class="ext-tag">.${esc(ext)} <span class="ext-count">${count}</span></span>`)
      .join('');

    const fileRows = files.slice(0, 50).map(f =>
      `<div class="file-list-row">
        <span class="file-list-name">${esc(f.name)}</span>
        <span class="file-list-ext">${esc(f.extension || '—')}</span>
        <span class="file-list-size">${esc(f.size_human)}</span>
      </div>`
    ).join('');

    container.innerHTML = `
      <div class="file-list-header">
        <span class="file-list-count">${files.length} files</span>
        <span class="file-list-total">${formatSize(totalSize)}</span>
      </div>
      <div class="ext-tags">${extTags}</div>
      <div class="file-list-body">${fileRows}</div>
      ${files.length > 50 ? `<div class="file-list-more">+ ${files.length - 50} more files</div>` : ''}
    `;
  } catch (err) {
    container.innerHTML = `<div class="file-list-loading">Error: ${esc(String(err))}</div>`;
  }
}

function formatSize(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
  return (bytes / (1024 * 1024 * 1024)).toFixed(2) + ' GB';
}

// ── Scan state management ──
function setScanningState(active) {
  isScanning = active;
  const app = document.querySelector('.app');
  const indicator = document.getElementById('scan-indicator');
  if (active) {
    app.classList.add('scanning');
    indicator.style.display = 'block';
  } else {
    app.classList.remove('scanning');
    indicator.style.display = 'none';
  }
}

function cleanupScan(statsInt, elapsedInt, unlistenFn) {
  clearInterval(statsInt);
  clearInterval(elapsedInt);
  if (unlistenFn) unlistenFn();
  setScanningState(false);
}

function resetScanView() {
  const scanState = document.getElementById('scan-state');
  const dropZone = document.getElementById('drop-zone');
  scanState.style.display = 'none';
  dropZone.style.display = '';
  selectedPath = null;
  document.getElementById('selected-path').textContent = '';
  document.getElementById('scan-btn').disabled = true;
  document.getElementById('file-list-container').style.display = 'none';
}

// ── Scan execution ──
async function startScan(path) {
  const scanBtn = document.getElementById('scan-btn');
  const scanState = document.getElementById('scan-state');
  const dropZone = document.getElementById('drop-zone');
  const statusText = document.getElementById('scan-status-text');
  const progressFill = document.getElementById('scan-progress-fill');
  const fileLog = document.getElementById('scan-file-log');

  // Lock UI
  setScanningState(true);
  dropZone.style.display = 'none';
  document.getElementById('file-list-container').style.display = 'none';
  scanState.style.display = 'block';
  scanBtn.disabled = true;
  fileLog.innerHTML = '';
  statusText.textContent = 'Starting scan...';
  progressFill.className = 'progress-bar-fill indeterminate';
  progressFill.style.background = '';
  progressFill.style.width = '';

  let cancelled = false;

  // Start system stats polling
  updateStats();
  const localStatsInterval = setInterval(updateStats, 1500);

  // Elapsed timer
  const startTime = Date.now();
  const elapsedEl = document.getElementById('scan-elapsed');
  const localElapsedInterval = setInterval(() => {
    const s = Math.floor((Date.now() - startTime) / 1000);
    const m = Math.floor(s / 60);
    elapsedEl.textContent = m > 0 ? `${m}m ${s % 60}s` : `${s}s`;
  }, 1000);

  // Per-file progress
  const unlisten = await listen('scan-progress', (event) => {
    const msg = event.payload;
    statusText.textContent = msg;
    const entry = document.createElement('div');
    entry.className = 'scan-log-entry';
    if (msg.includes('Scan complete')) entry.classList.add('scan-log-done');
    entry.textContent = msg;
    fileLog.appendChild(entry);
    fileLog.scrollTop = fileLog.scrollHeight;
  });

  // Stop button
  const stopBtn = document.getElementById('stop-scan-btn');
  const stopHandler = () => {
    cancelled = true;
    cleanupScan(localStatsInterval, localElapsedInterval, unlisten);
    statusText.textContent = 'Scan stopped.';
    progressFill.className = 'progress-bar-fill';
    progressFill.style.width = '100%';
    progressFill.style.background = 'var(--medium)';
    setTimeout(() => {
      resetScanView();
    }, 1500);
  };
  stopBtn.addEventListener('click', stopHandler, { once: true });

  try {
    scanResult = await invoke('scan_path', { path });

    if (cancelled) return;
    cleanupScan(localStatsInterval, localElapsedInterval, unlisten);
    stopBtn.removeEventListener('click', stopHandler);

    // Update badge
    const total = scanResult.critical + scanResult.high + scanResult.medium + scanResult.low + scanResult.info;
    const badge = document.getElementById('findings-badge');
    if (total > 0) { badge.textContent = total; badge.style.display = 'block'; }
    else { badge.style.display = 'none'; }

    renderResults(scanResult);
    statusText.textContent = 'Scan complete!';
    progressFill.className = 'progress-bar-fill';
    progressFill.style.width = '100%';

    setTimeout(() => {
      resetScanView();
      switchView('results');
    }, 1200);

  } catch (err) {
    if (cancelled) return;
    cleanupScan(localStatsInterval, localElapsedInterval, unlisten);
    stopBtn.removeEventListener('click', stopHandler);

    statusText.textContent = `Error: ${err}`;
    progressFill.style.background = 'var(--critical)';
    progressFill.className = 'progress-bar-fill';
    progressFill.style.width = '100%';

    const entry = document.createElement('div');
    entry.className = 'scan-log-entry scan-log-error';
    entry.textContent = String(err);
    fileLog.appendChild(entry);

    setTimeout(() => {
      resetScanView();
    }, 5000);
  }
}

async function updateStats() {
  try {
    const stats = await invoke('get_system_stats');
    setGauge('cpu-gauge', stats.cpu_percent, `${stats.cpu_percent.toFixed(0)}%`);
    setGauge('ram-gauge', stats.memory_percent,
      `${stats.memory_used_gb.toFixed(1)} / ${stats.memory_total_gb.toFixed(0)} GB`);
    setGauge('gpu-gauge', stats.gpu_percent,
      `${stats.gpu_mem_used_gb.toFixed(1)} / ${stats.gpu_mem_total_gb.toFixed(0)} GB`);
  } catch { /* ignore */ }
}

function setGauge(id, percent, label) {
  const el = document.getElementById(id);
  if (!el) return;
  const ring = el.querySelector('.gauge-ring-fill');
  const text = el.querySelector('.gauge-value');
  const detail = el.querySelector('.gauge-detail');
  const circumference = 2 * Math.PI * 36; // r=36
  const offset = circumference - (percent / 100) * circumference;
  ring.style.strokeDashoffset = offset;

  // Color based on percentage
  let color = 'var(--safe)';
  if (percent > 80) color = 'var(--critical)';
  else if (percent > 60) color = 'var(--medium)';
  else if (percent > 40) color = 'var(--low)';
  ring.style.stroke = color;

  text.textContent = `${Math.round(percent)}%`;
  if (detail) detail.textContent = label;
}

// ── Render results ──
function renderResults(result) {
  document.getElementById('results-empty').style.display = 'none';
  document.getElementById('results-content').style.display = 'block';

  document.getElementById('stats-grid').innerHTML = `
    <div class="stat-card stat-files"><div class="stat-number">${result.total_files}</div><div class="stat-label">Files</div></div>
    <div class="stat-card stat-critical"><div class="stat-number">${result.critical}</div><div class="stat-label">Critical</div></div>
    <div class="stat-card stat-high"><div class="stat-number">${result.high}</div><div class="stat-label">High</div></div>
    <div class="stat-card stat-medium"><div class="stat-number">${result.medium}</div><div class="stat-label">Medium</div></div>
    <div class="stat-card stat-low"><div class="stat-number">${result.low}</div><div class="stat-label">Low</div></div>
    <div class="stat-card stat-info"><div class="stat-number">${result.info}</div><div class="stat-label">Info</div></div>
    <div class="stat-card stat-clean"><div class="stat-number">${result.clean_files}</div><div class="stat-label">Clean</div></div>
  `;

  const flagged = result.files.filter(f => f.findings.some(fn => fn.severity !== 'info' && fn.category !== 'safe'));
  const clean = result.files.filter(f => !f.findings.some(fn => fn.severity !== 'info' && fn.category !== 'safe'));

  document.getElementById('flagged-files').innerHTML = flagged.length > 0 ? `
    <div class="section-title">Flagged Files</div>
    ${flagged.map(f => renderFileCard(f)).join('')}
  ` : '';

  document.getElementById('clean-files').innerHTML = clean.length > 0 ? `
    <div class="section-title">Clean Files</div>
    ${clean.map(f => {
      const safeDesc = f.findings
        .filter(fn => fn.category === 'safe' && fn.explanation)
        .map(fn => fn.explanation)
        .join(' ');
      return `
        <div class="file-card">
          <div class="file-header">
            <span class="file-path"><span style="color:var(--safe);margin-right:6px;">&#10003;</span>${esc(f.path)}</span>
            <span class="file-meta">${esc(f.kind)}</span>
          </div>
          ${safeDesc ? `<div class="finding"><div class="finding-desc" style="color:var(--safe);">${esc(safeDesc)}</div></div>` : ''}
        </div>
      `;
    }).join('')}
  ` : '';
}

function renderFileCard(file) {
  return `
    <div class="file-card">
      <div class="file-header">
        <span class="file-path">${esc(file.path)}</span>
        <span class="file-meta">${esc(file.kind)}</span>
      </div>
      ${file.findings.filter(f => f.category !== 'safe').map(f => `
        <div class="finding">
          <div class="finding-header">
            <span class="severity-badge severity-${esc(f.severity)}">${esc(f.severity)}</span>
            <span class="category-badge">${esc(f.subcategory || f.category)}</span>
          </div>
          <div class="finding-desc">${esc(f.explanation)}</div>
        </div>
      `).join('')}
    </div>
  `;
}

function esc(str) {
  if (!str) return '';
  return str.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// ── Settings ──
function setupSettings() {
  document.getElementById('ollama-url').addEventListener('change', () => {
    ollamaUrl = document.getElementById('ollama-url').value.trim();
    checkOllama();
  });

  document.getElementById('install-ollama-btn').addEventListener('click', async () => {
    try {
      await window.__TAURI__.opener.openUrl('https://ollama.com/download');
    } catch {
      // fallback
      window.open('https://ollama.com/download', '_blank');
    }
  });
}

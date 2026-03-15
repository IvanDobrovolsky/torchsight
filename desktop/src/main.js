const { invoke } = window.__TAURI__.core;

// ── State ──
let currentView = 'scan';
let scanResult = null;
let selectedPath = null;
let ollamaUrl = 'http://localhost:11434';

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
    item.addEventListener('click', () => {
      switchView(item.dataset.view);
    });
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

  try {
    const ok = await invoke('check_ollama', { url: ollamaUrl });
    if (ok) {
      dot.className = 'status-dot online';
      status.textContent = 'Ollama connected';
      loadModels();
    } else {
      dot.className = 'status-dot offline';
      status.textContent = 'Ollama offline';
    }
  } catch {
    dot.className = 'status-dot offline';
    status.textContent = 'Ollama offline';
  }
}

async function loadModels() {
  try {
    const models = await invoke('list_models', { url: ollamaUrl });
    const list = document.getElementById('model-list');
    const textModel = document.getElementById('text-model').value;
    const visionModel = document.getElementById('vision-model').value;

    if (models.length === 0) {
      list.innerHTML = '<span class="model-tag" style="color: var(--text-muted)">No models installed</span>';
      return;
    }

    list.innerHTML = models.map(m => {
      const isActive = m.includes(textModel.split('/').pop()) || m.includes(visionModel);
      return `<span class="model-tag${isActive ? ' active' : ''}">${escapeHtml(m)}</span>`;
    }).join('');
  } catch {
    // ignore
  }
}

// ── Scan controls ──
function setupScanControls() {
  const scanFolderBtn = document.getElementById('scan-folder-btn');
  const scanBtn = document.getElementById('scan-btn');
  const dropZone = document.getElementById('drop-zone');

  // Folder picker — the only way to select a path
  scanFolderBtn.addEventListener('click', pickFolder);
  dropZone.addEventListener('click', (e) => {
    if (e.target !== scanBtn) pickFolder();
  });

  scanBtn.addEventListener('click', () => {
    if (selectedPath) startScan(selectedPath);
  });
}

async function pickFolder() {
  try {
    const selected = await window.__TAURI__.dialog.open({
      directory: true,
      multiple: false,
      title: 'Select folder to scan',
    });
    if (selected) {
      selectedPath = selected;
      document.getElementById('selected-path').textContent = selected;
      document.getElementById('scan-btn').disabled = false;
    }
  } catch (err) {
    console.error('Folder picker error:', err);
  }
}

async function startScan(path) {
  const progress = document.getElementById('scan-progress');
  const progressStatus = document.getElementById('progress-status');
  const progressFill = document.getElementById('progress-fill');
  const scanBtn = document.getElementById('scan-btn');

  // Show progress
  progress.classList.add('active');
  progressFill.className = 'progress-bar-fill indeterminate';
  progressFill.style.background = '';
  progressStatus.textContent = `Scanning: ${path}`;
  scanBtn.disabled = true;

  try {
    scanResult = await invoke('scan_path', { path });

    // Update badge
    const totalFindings = scanResult.critical + scanResult.high + scanResult.medium + scanResult.low + scanResult.info;
    const badge = document.getElementById('findings-badge');
    if (totalFindings > 0) {
      badge.textContent = totalFindings;
      badge.style.display = 'block';
    } else {
      badge.style.display = 'none';
    }

    // Show results
    renderResults(scanResult);
    progressStatus.textContent = 'Scan complete!';
    progressFill.className = 'progress-bar-fill';
    progressFill.style.width = '100%';

    // Auto-switch to results after a beat
    setTimeout(() => switchView('results'), 800);

  } catch (err) {
    progressStatus.textContent = `Error: ${err}`;
    progressFill.className = 'progress-bar-fill';
    progressFill.style.width = '100%';
    progressFill.style.background = 'var(--critical)';
  } finally {
    scanBtn.disabled = false;
  }
}

// ── Render results ──
function renderResults(result) {
  document.getElementById('results-empty').style.display = 'none';
  document.getElementById('results-content').style.display = 'block';

  // Stats grid
  const statsGrid = document.getElementById('stats-grid');
  statsGrid.innerHTML = `
    <div class="stat-card stat-files">
      <div class="stat-number">${result.total_files}</div>
      <div class="stat-label">Files Scanned</div>
    </div>
    <div class="stat-card stat-critical">
      <div class="stat-number">${result.critical}</div>
      <div class="stat-label">Critical</div>
    </div>
    <div class="stat-card stat-high">
      <div class="stat-number">${result.high}</div>
      <div class="stat-label">High</div>
    </div>
    <div class="stat-card stat-medium">
      <div class="stat-number">${result.medium}</div>
      <div class="stat-label">Medium</div>
    </div>
    <div class="stat-card stat-low">
      <div class="stat-number">${result.low}</div>
      <div class="stat-label">Low</div>
    </div>
    <div class="stat-card stat-info">
      <div class="stat-number">${result.info}</div>
      <div class="stat-label">Info</div>
    </div>
    <div class="stat-card stat-clean">
      <div class="stat-number">${result.clean_files}</div>
      <div class="stat-label">Clean</div>
    </div>
  `;

  // Flagged files
  const flaggedContainer = document.getElementById('flagged-files');
  const flaggedFiles = result.files.filter(f =>
    f.findings.some(fn => fn.severity !== 'info' && fn.category !== 'safe')
  );

  if (flaggedFiles.length > 0) {
    flaggedContainer.innerHTML = `
      <div class="section-title">Flagged Files</div>
      ${flaggedFiles.map(f => renderFileCard(f)).join('')}
    `;
  } else {
    flaggedContainer.innerHTML = '';
  }

  // Clean files
  const cleanContainer = document.getElementById('clean-files');
  const cleanFiles = result.files.filter(f =>
    !f.findings.some(fn => fn.severity !== 'info' && fn.category !== 'safe')
  );

  if (cleanFiles.length > 0) {
    cleanContainer.innerHTML = `
      <div class="section-title">Clean Files</div>
      ${cleanFiles.map(f => `
        <div class="file-card">
          <div class="file-header">
            <span class="file-path">
              <span style="color:var(--safe);margin-right:6px;">&#10003;</span>${escapeHtml(f.path)}
            </span>
            <span class="file-meta">${escapeHtml(f.kind)}</span>
          </div>
        </div>
      `).join('')}
    `;
  } else {
    cleanContainer.innerHTML = '';
  }
}

function renderFileCard(file) {
  const findings = file.findings
    .filter(f => f.category !== 'safe')
    .map(f => `
      <div class="finding">
        <div class="finding-header">
          <span class="severity-badge severity-${escapeHtml(f.severity)}">${escapeHtml(f.severity)}</span>
          <span class="category-badge">${escapeHtml(f.subcategory || f.category)}</span>
        </div>
        <div class="finding-desc">${escapeHtml(f.explanation)}</div>
      </div>
    `).join('');

  return `
    <div class="file-card">
      <div class="file-header">
        <span class="file-path">${escapeHtml(file.path)}</span>
        <span class="file-meta">${escapeHtml(file.kind)}</span>
      </div>
      ${findings}
    </div>
  `;
}

function escapeHtml(str) {
  if (!str) return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// ── Settings ──
function setupSettings() {
  const urlInput = document.getElementById('ollama-url');
  urlInput.addEventListener('change', () => {
    ollamaUrl = urlInput.value.trim();
    checkOllama();
  });
}

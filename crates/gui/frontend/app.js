// AutomateSTIG GUI Application
'use strict';

const API = '/api';
const AUTH_TOKEN = window.__AUTH_TOKEN__ || '';

// ---------------------------------------------------------------------------
// Theme Toggle
// ---------------------------------------------------------------------------
const LIGHT_THEME = {
  '--bg-base': '#f8f9fa', '--bg-surface': '#ffffff', '--bg-elevated': '#f1f3f5',
  '--bg-hover': '#e9ecef', '--bg-active': '#dee2e6', '--border': '#dee2e6',
  '--border-subtle': '#e9ecef', '--text': '#212529', '--text-secondary': '#495057',
  '--text-muted': '#868e96', '--accent-dim': 'rgba(59,130,246,0.08)',
  '--green-dim': 'rgba(34,197,94,0.08)', '--red-dim': 'rgba(239,68,68,0.08)',
  '--yellow-dim': 'rgba(234,179,8,0.08)',
};
const DARK_THEME = {
  '--bg-base': '#0a0e14', '--bg-surface': '#11151c', '--bg-elevated': '#1a1f2e',
  '--bg-hover': '#1e2538', '--bg-active': '#252d3f', '--border': '#2a3040',
  '--border-subtle': '#1e2430', '--text': '#e2e8f0', '--text-secondary': '#94a3b8',
  '--text-muted': '#64748b', '--accent-dim': 'rgba(59,130,246,0.12)',
  '--green-dim': 'rgba(34,197,94,0.12)', '--red-dim': 'rgba(239,68,68,0.12)',
  '--yellow-dim': 'rgba(234,179,8,0.12)',
};

function toggleTheme() {
  const isDark = document.documentElement.style.getPropertyValue('--bg-base') !== LIGHT_THEME['--bg-base'];
  const theme = isDark ? LIGHT_THEME : DARK_THEME;
  Object.entries(theme).forEach(([k, v]) => document.documentElement.style.setProperty(k, v));
  localStorage.setItem('theme', isDark ? 'light' : 'dark');
}

// Restore saved theme.
if (localStorage.getItem('theme') === 'light') {
  Object.entries(LIGHT_THEME).forEach(([k, v]) => document.documentElement.style.setProperty(k, v));
}

// ---------------------------------------------------------------------------
// Keyboard Shortcuts
// ---------------------------------------------------------------------------
document.addEventListener('keydown', (e) => {
  // Escape closes modals.
  if (e.key === 'Escape') {
    const modal = document.querySelector('.modal-overlay');
    if (modal) { modal.remove(); e.preventDefault(); }
  }
  // "/" focuses search (if visible and not already in an input).
  if (e.key === '/' && !['INPUT', 'TEXTAREA', 'SELECT'].includes(document.activeElement?.tagName)) {
    const search = document.querySelector('.search-input');
    if (search) { search.focus(); e.preventDefault(); }
  }
});

// ---------------------------------------------------------------------------
// API Client
// ---------------------------------------------------------------------------
async function api(path, opts = {}) {
  const res = await fetch(`${API}${path}`, {
    headers: {
      'Content-Type': 'application/json',
      'X-Auth-Token': AUTH_TOKEN,
      ...opts.headers,
    },
    ...opts,
  });
  if (opts.raw) return res;
  const data = await res.json();
  if (!data.success) throw new Error(data.error || 'API error');
  return data.data;
}

async function apiUpload(path, file) {
  const form = new FormData();
  form.append('file', file);
  const res = await fetch(`${API}${path}`, {
    method: 'POST',
    body: form,
    headers: { 'X-Auth-Token': AUTH_TOKEN },
  });
  const data = await res.json();
  if (!data.success) throw new Error(data.error || 'Upload failed');
  return data.data;
}

// ---------------------------------------------------------------------------
// Toast Notifications
// ---------------------------------------------------------------------------
function toast(msg, type = 'info') {
  const el = document.createElement('div');
  el.className = `toast ${type}`;
  el.textContent = msg;
  document.getElementById('toasts').appendChild(el);
  setTimeout(() => el.remove(), 4000);
}

// ---------------------------------------------------------------------------
// Confirm Dialog
// ---------------------------------------------------------------------------
function confirmDialog(title, message) {
  return new Promise((resolve) => {
    const overlay = h('div', { className: 'modal-overlay' },
      h('div', { className: 'modal' },
        h('h3', {}, title),
        h('p', {}, message),
        h('div', { className: 'btn-group' },
          h('button', { className: 'btn btn-secondary', onClick: () => { overlay.remove(); resolve(false); } }, 'Cancel'),
          h('button', { className: 'btn btn-danger', onClick: () => { overlay.remove(); resolve(true); } }, 'Confirm'),
        ),
      ),
    );
    document.body.appendChild(overlay);
  });
}

// ---------------------------------------------------------------------------
// Navigation
// ---------------------------------------------------------------------------
document.querySelectorAll('.nav-item').forEach(item => {
  item.addEventListener('click', (e) => {
    e.preventDefault();
    const page = item.dataset.page;
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    item.classList.add('active');
    document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
    document.getElementById(`page-${page}`).classList.add('active');
    loadPage(page);
  });
});

api('/status')
  .then((status) => {
    const el = document.getElementById('app-version');
    if (el && status && status.version) el.textContent = `v${status.version}`;
  })
  .catch(() => {});

function loadPage(page) {
  switch (page) {
    case 'assessments': loadAssessments(); break;
    case 'assets': loadAssetsPage(); break;
    case 'standards': loadStandards(); break;
    case 'findings': loadFindings(); break;
    case 'settings': loadSettings(); break;
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'className') el.className = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2).toLowerCase(), v);
    else el.setAttribute(k, v);
  }
  for (const child of children.flat()) {
    if (child == null || child === true || child === false) continue;
    el.appendChild(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return el;
}

function sevBadge(sev) {
  const cls = sev.includes('I') && !sev.includes('II') && !sev.includes('III') ? 'sev-high'
    : sev.includes('III') ? 'sev-low' : 'sev-med';
  return h('span', { className: `sev ${cls}` }, sev);
}

function statusBadge(status) {
  const cls = status === 'Open' ? 'status-open'
    : status.includes('Not a Finding') ? 'status-naf'
    : status.includes('Not Applicable') ? 'status-na' : 'status-nr';
  return h('span', { className: `status-badge ${cls}` }, status);
}

function complianceColor(pct) {
  return pct >= 95 ? 'green' : pct >= 80 ? 'yellow' : 'red';
}

function setPage(id, ...children) {
  const page = document.getElementById(`page-${id}`);
  page.innerHTML = '';
  children.forEach(c => page.appendChild(c));
}

function loadingState() {
  return h('div', { className: 'loading-state' },
    h('div', { className: 'spinner' }),
    h('div', { className: 'loading-label' }, 'Loading…'),
  );
}

function statCard(label, value, color = '') {
  return h('div', { className: 'stat-card' },
    h('div', { className: 'stat-label' }, label),
    h('div', { className: `stat-value ${color}` }, String(value)),
  );
}

function emptyState(title, desc, action) {
  return h('div', { className: 'empty-state' },
    h('div', { className: 'empty-state-icon' }, '\u{1F4CB}'),
    h('h3', {}, title),
    h('p', {}, desc),
    action || '',
  );
}

function errorCard(msg) {
  return h('div', { className: 'card' },
    h('p', { style: 'color: var(--red)' }, `Error: ${msg}`),
  );
}

function nav(page) {
  const el = document.querySelector(`[data-page="${page}"]`);
  if (el) el.click();
  else console.warn(`nav: unknown page "${page}"`);
}

// ---------------------------------------------------------------------------
// Checklist Detail View
// ---------------------------------------------------------------------------
async function viewChecklist(id) {
  try {
    const cl = await api(`/checklists/${id}`);
    const page = document.getElementById('page-checklists');
    page.innerHTML = '';

    const compColor = complianceColor(cl.compliance_pct);

    page.appendChild(h('div', { className: 'page-header' },
      h('div', { style: 'display: flex; align-items: center; gap: 12px; margin-bottom: 4px' },
        h('button', { className: 'btn btn-secondary btn-sm', onClick: () => nav('assessments') }, '\u2190 Back'),
        h('h1', {}, `${cl.hostname}`),
      ),
      h('p', {}, `${cl.stig_title} (${cl.stig_version})`),
    ));

    page.appendChild(h('div', { className: 'stats-grid' },
      statCard('Total Rules', cl.total, ''),
      statCard('Open', cl.open, cl.open > 0 ? 'red' : 'green'),
      statCard('Not a Finding', cl.not_a_finding, 'green'),
      statCard('Not Applicable', cl.not_applicable, ''),
      statCard('Not Reviewed', cl.not_reviewed, cl.not_reviewed > 0 ? 'yellow' : ''),
      statCard('Compliance', `${(cl.compliance_pct ?? 0).toFixed(1)}%`, compColor),
    ));

    // Severity breakdown
    if (cl.open > 0) {
      page.appendChild(h('div', { className: 'stats-grid', style: 'margin-bottom: 16px' },
        statCard('CAT I Open', cl.cat_i_open, cl.cat_i_open > 0 ? 'red' : 'green'),
        statCard('CAT II Open', cl.cat_ii_open, cl.cat_ii_open > 0 ? 'yellow' : 'green'),
        statCard('CAT III Open', cl.cat_iii_open, cl.cat_iii_open > 0 ? 'yellow' : 'green'),
      ));
    }

    // Findings table
    const rows = cl.findings.map(f =>
      h('tr', {},
        h('td', { className: 'mono' }, f.vuln_id),
        h('td', {}, sevBadge(f.severity)),
        h('td', {}, statusBadge(f.status)),
        h('td', { style: 'max-width: 400px' }, f.title),
        h('td', { style: 'font-size: 0.8rem; color: var(--text-muted); max-width: 300px' },
          f.finding_details || '\u2014'),
      ),
    );

    // Search and filter bar for findings.
    let currentFilter = 'all';
    let currentSearch = '';

    function renderFindings() {
      const filtered = cl.findings.filter(f => {
        if (currentFilter === 'open' && f.status !== 'Open') return false;
        if (currentFilter === 'naf' && !f.status.includes('Not a Finding')) return false;
        if (currentFilter === 'na' && !f.status.includes('Not Applicable')) return false;
        if (currentFilter === 'nr' && !f.status.includes('Not Reviewed')) return false;
        if (currentSearch) {
          const q = currentSearch.toLowerCase();
          return f.vuln_id.toLowerCase().includes(q) || f.title.toLowerCase().includes(q) || f.finding_details.toLowerCase().includes(q);
        }
        return true;
      });
      const tbody = document.getElementById('findings-tbody');
      if (!tbody) return;
      tbody.innerHTML = '';
      filtered.forEach(f => {
        const tr = h('tr', { style: 'cursor: pointer', onClick: () => editFinding(id, f) },
          h('td', { className: 'mono' }, f.vuln_id),
          h('td', {}, sevBadge(f.severity)),
          h('td', {}, statusBadge(f.status)),
          h('td', { style: 'max-width: 400px' }, f.title),
          h('td', { style: 'font-size: 0.8rem; color: var(--text-muted); max-width: 300px' },
            f.finding_details.substring(0, 120) || '\u2014'),
        );
        tbody.appendChild(tr);
      });
      const countEl = document.getElementById('findings-count');
      if (countEl) countEl.textContent = `Findings (${filtered.length}/${cl.findings.length})`;
    }

    page.appendChild(h('div', { className: 'card' },
      h('div', { className: 'card-header' },
        h('h2', { id: 'findings-count' }, `Findings (${cl.findings.length})`),
        h('div', { className: 'btn-group' },
          h('button', { className: 'btn btn-secondary btn-sm', onClick: () => exportCkl(id) }, 'Export CKL'),
          h('button', { className: 'btn btn-secondary btn-sm', onClick: () => exportCklb(id) }, 'Export CKLB'),
          h('button', { className: 'btn btn-secondary btn-sm', onClick: () => pushToStigManager(id, cl.hostname) }, 'Push to STIG-Manager'),
          h('button', { className: 'btn btn-primary btn-sm', onClick: () => reEvaluate(id) }, 'Re-evaluate'),
          h('button', { className: 'btn btn-danger btn-sm', onClick: () => deleteChecklist(id, cl.hostname) }, 'Delete'),
        ),
      ),
      h('div', { className: 'search-bar' },
        h('input', {
          className: 'search-input', type: 'text', placeholder: 'Search Vuln ID, title, or details...',
          onInput: (e) => { currentSearch = e.target.value; renderFindings(); },
        }),
      ),
      h('div', { className: 'filter-bar' },
        ...['all', 'open', 'naf', 'na', 'nr'].map(f => {
          const labels = { all: 'All', open: 'Open', naf: 'Not a Finding', na: 'N/A', nr: 'Not Reviewed' };
          const cls = f === 'all' ? 'active' : '';
          return h('button', {
            className: `filter-pill ${cls}`,
            onClick: (e) => {
              currentFilter = f;
              document.querySelectorAll('.filter-pill').forEach(p => p.className = 'filter-pill');
              e.target.className = `filter-pill ${f === 'open' ? 'active-red' : f === 'naf' ? 'active-green' : 'active'}`;
              renderFindings();
            },
          }, labels[f]);
        }),
      ),
      h('table', { className: 'data-table' },
        h('thead', {},
          h('tr', {},
            h('th', {}, 'Vuln ID'),
            h('th', {}, 'Severity'),
            h('th', {}, 'Status'),
            h('th', {}, 'Title'),
            h('th', {}, 'Details'),
          ),
        ),
        h('tbody', { id: 'findings-tbody' }),
      ),
    ));

    // Initial render of findings.
    renderFindings();

    // Show checklists page
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    document.querySelector('[data-page="assessments"]').classList.add('active');
    document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
    page.classList.add('active');
  } catch (e) {
    toast(e.message, 'error');
  }
}

// ---------------------------------------------------------------------------
// Evaluate Workspace
// ---------------------------------------------------------------------------
async function renderEvaluateWorkspace() {
  const container = document.getElementById('evaluate-workspace');
  if (!container) return;
  container.innerHTML = '';

  try {
    const [benchmarks, assets] = await Promise.all([
      api('/library/benchmarks'),
      api('/assets').catch(() => []),
    ]);

    const options = benchmarks.map(b =>
      h('option', { value: b.id }, `${b.id} (${b.rule_count} rules)`),
    );

    container.appendChild(h('div', { className: 'card', style: 'max-width: 600px' },
      h('div', { className: 'card-header' }, h('h2', {}, 'Run assessment')),
      assets.length > 0 ? h('div', { className: 'form-group' },
        h('label', { className: 'form-label' }, 'Asset (optional)'),
        h('select', { className: 'form-select', id: 'eval-asset',
          onChange: (e) => {
            const a = assets.find(x => x.id === e.target.value);
            const host = document.getElementById('eval-host');
            if (a && host) host.value = a.name;
          } },
          h('option', { value: '' }, 'Manual entry…'),
          ...assets.map(a => h('option', { value: a.id }, `${a.name} (${a.address})`)),
        ),
      ) : null,
      h('div', { className: 'form-group' },
        h('label', { className: 'form-label' }, 'STIG Benchmark'),
        benchmarks.length
          ? h('select', { className: 'form-select', id: 'eval-stig' },
              h('option', { value: '' }, 'Select a benchmark...'),
              ...options,
            )
          : h('p', { style: 'color: var(--text-muted)' },
              'No benchmarks installed. ',
              h('a', { href: '#', onClick: (e) => { e.preventDefault(); nav('standards'); } }, 'Install STIG content first.'),
            ),
      ),
      h('div', { className: 'form-group' },
        h('label', { className: 'form-label' }, 'Target Hostname'),
        h('input', { className: 'form-input', id: 'eval-host', type: 'text', placeholder: 'e.g. webserver01.navy.mil' }),
      ),
      h('div', { className: 'form-group' },
        h('label', { className: 'form-label' }, 'Scan Results (optional)'),
        h('input', { className: 'form-input', id: 'eval-scan', type: 'file', accept: '.xml,.ckl,.cklb,.json' }),
      ),
      h('button', { className: 'btn btn-primary', id: 'eval-btn', onClick: runEvaluation },
        'Run Evaluation',
      ),
    ));

    if (benchmarks.length > 0) {
      const batchOptions = benchmarks.map(b =>
        h('option', { value: b.id }, `${b.id} (${b.rule_count} rules)`),
      );
      container.appendChild(h('div', { className: 'card', style: 'max-width: 600px; margin-top: 20px' },
        h('div', { className: 'card-header' }, h('h2', {}, 'Batch Evaluate')),
        h('p', { style: 'color: var(--text-secondary); margin-bottom: 16px; font-size: 0.9rem' },
          'Evaluate multiple hosts against a single STIG at once.',
        ),
        h('div', { className: 'form-group' },
          h('label', { className: 'form-label' }, 'STIG Benchmark'),
          h('select', { className: 'form-select', id: 'batch-stig' },
            h('option', { value: '' }, 'Select...'), ...batchOptions),
        ),
        h('div', { className: 'form-group' },
          h('label', { className: 'form-label' }, 'Hostnames (one per line)'),
          h('textarea', { className: 'form-input', id: 'batch-hosts', rows: '6',
            style: 'resize: vertical', placeholder: 'server01\nserver02\nserver03' }),
        ),
        h('button', { className: 'btn btn-primary', onClick: runBatchEvaluation }, 'Batch Evaluate'),
      ));
    }

    const remoteScanSection = await loadRemoteScan();
    if (remoteScanSection) container.appendChild(remoteScanSection);
  } catch (e) {
    container.appendChild(errorCard(e.message));
  }
}

async function runEvaluation() {
  const stigId = document.getElementById('eval-stig')?.value;
  const hostname = document.getElementById('eval-host')?.value;
  const assetId = document.getElementById('eval-asset')?.value || null;
  const scanInput = document.getElementById('eval-scan');
  const scanFile = scanInput?.files?.[0];

  if (!stigId) { toast('Select a STIG benchmark', 'error'); return; }
  if (!hostname) { toast('Enter a target hostname', 'error'); return; }

  const btn = document.getElementById('eval-btn');
  btn.textContent = 'Evaluating...';
  btn.disabled = true;

  try {
    let result;
    if (scanFile) {
      // Use multipart upload with scan file.
      const form = new FormData();
      form.append('stig_id', stigId);
      form.append('hostname', hostname);
      form.append('scan', scanFile);
      if (assetId) form.append('asset_id', assetId);
      const res = await fetch(`${API}/evaluate/with-scan`, {
        method: 'POST',
        body: form,
        headers: { 'X-Auth-Token': AUTH_TOKEN },
      });
      const data = await res.json();
      if (!data.success) throw new Error(data.error || 'Evaluation failed');
      result = data.data;
    } else {
      result = await api('/evaluate', {
        method: 'POST',
        body: JSON.stringify({ stig_id: stigId, hostname, asset_id: assetId }),
      });
    }
    toast(`Evaluation complete: ${result.total} rules, ${result.open} open, ${result.compliance_pct?.toFixed(1) || '?'}% compliance`, 'success');
    loadAssessments();
  } catch (e) {
    toast(e.message, 'error');
  } finally {
    btn.textContent = 'Run Evaluation';
    btn.disabled = false;
  }
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// Finding Editor (inline edit on click)
// ---------------------------------------------------------------------------
async function editFinding(checklistId, finding) {
  const statuses = ['NotAFinding', 'Open', 'Not_Applicable', 'Not_Reviewed'];
  const statusLabels = { NotAFinding: 'Not a Finding', Open: 'Open', Not_Applicable: 'Not Applicable', Not_Reviewed: 'Not Reviewed' };
  const currentStatusKey = statuses.find(s =>
    finding.status.replace(/\s/g, '').toLowerCase().includes(s.replace(/_/g, '').toLowerCase())
  ) || 'Not_Reviewed';

  const overlay = h('div', { className: 'modal-overlay' },
    h('div', { className: 'modal', style: 'max-width: 600px' },
      h('h3', {}, `${finding.vuln_id} — ${finding.title.substring(0, 60)}`),
      h('div', { className: 'form-group' },
        h('label', { className: 'form-label' }, 'Status'),
        h('select', { className: 'form-select', id: 'edit-status' },
          ...statuses.map(s => {
            const opt = h('option', { value: s }, statusLabels[s] || s);
            if (s === currentStatusKey) opt.selected = true;
            return opt;
          }),
        ),
      ),
      h('div', { className: 'form-group' },
        h('label', { className: 'form-label' }, 'Finding Details'),
        h('textarea', {
          className: 'form-input', id: 'edit-details', rows: '4',
          style: 'resize: vertical; min-height: 80px',
        }, finding.finding_details || ''),
      ),
      h('div', { className: 'form-group' },
        h('label', { className: 'form-label' }, 'Comments'),
        h('textarea', {
          className: 'form-input', id: 'edit-comments', rows: '3',
          style: 'resize: vertical; min-height: 60px',
        }, finding.comments || ''),
      ),
      h('div', { className: 'btn-group', style: 'justify-content: flex-end' },
        h('button', { className: 'btn btn-secondary', onClick: () => overlay.remove() }, 'Cancel'),
        h('button', { className: 'btn btn-primary', onClick: async () => {
          const status = document.getElementById('edit-status')?.value;
          const details = document.getElementById('edit-details')?.value;
          const comments = document.getElementById('edit-comments')?.value;

          try {
            await api(`/checklists/${checklistId}/findings/${finding.vuln_id}`, {
              method: 'PATCH',
              body: JSON.stringify({ status, finding_details: details, comments }),
            });
            overlay.remove();
            toast('Finding updated', 'success');
            viewChecklist(checklistId); // Reload.
          } catch (e) {
            toast(`Save failed: ${e.message}`, 'error');
          }
        }}, 'Save'),
      ),
    ),
  );
  document.body.appendChild(overlay);
}

// ---------------------------------------------------------------------------
// Remote Scan (SSH)
// ---------------------------------------------------------------------------
async function loadRemoteScan() {
  try {
    const benchmarks = await api('/library/benchmarks');
    const options = benchmarks.map(b =>
      h('option', { value: b.id }, `${b.id} (${b.rule_count} rules)`),
    );

    return h('div', { className: 'card', style: 'margin-top: 20px' },
      h('div', { className: 'card-header' }, h('h2', {}, 'Remote Scan')),
      h('p', { style: 'color: var(--text-secondary); margin-bottom: 16px; font-size: 0.9rem' },
        'Connect to a remote host via SSH to collect data and evaluate.',
      ),
      h('div', { className: 'grid-2' },
        h('div', {},
          h('div', { className: 'form-group' },
            h('label', { className: 'form-label' }, 'Protocol'),
            h('select', { className: 'form-select', id: 'scan-protocol' },
              h('option', { value: 'ssh' }, 'SSH (Linux / Network)'),
            ),
          ),
          h('div', { className: 'form-group' },
            h('label', { className: 'form-label' }, 'Platform'),
            h('select', { className: 'form-select', id: 'scan-platform' },
              h('option', { value: 'linux' }, 'Linux'),
              h('option', { value: 'ontap' }, 'NetApp ONTAP'),
              h('option', { value: 'bsd' }, 'FreeBSD'),
            ),
          ),
          h('div', { className: 'form-group' },
            h('label', { className: 'form-label' }, 'Host'),
            h('input', { className: 'form-input', id: 'scan-host', type: 'text', placeholder: '10.0.1.50' }),
          ),
          h('div', { className: 'form-group' },
            h('label', { className: 'form-label' }, 'Username'),
            h('input', { className: 'form-input', id: 'scan-user', type: 'text', placeholder: 'admin' }),
          ),
          h('div', { className: 'form-group' },
            h('label', { className: 'form-label' }, 'Password'),
            h('input', { className: 'form-input', id: 'scan-pass', type: 'password' }),
          ),
        ),
        h('div', {},
          h('div', { className: 'form-group' },
            h('label', { className: 'form-label' }, 'STIG Benchmark'),
            benchmarks.length
              ? h('select', { className: 'form-select', id: 'scan-stig' },
                  h('option', { value: '' }, 'Select...'), ...options)
              : h('p', { style: 'color: var(--text-muted)' }, 'No benchmarks. Import content first.'),
          ),
          h('div', { className: 'form-group' },
            h('label', { className: 'form-label' }, 'Port (optional)'),
            h('input', { className: 'form-input', id: 'scan-port', type: 'number', placeholder: '22' }),
          ),
          h('button', { className: 'btn btn-primary', style: 'margin-top: 24px', onClick: runRemoteScan }, 'Scan & Evaluate'),
        ),
      ),
    );
  } catch (_) {
    return h('div', {});
  }
}

async function runRemoteScan() {
  const protocol = document.getElementById('scan-protocol')?.value;
  const platform = document.getElementById('scan-platform')?.value || 'linux';
  const host = document.getElementById('scan-host')?.value;
  const user = document.getElementById('scan-user')?.value;
  const pass = document.getElementById('scan-pass')?.value;
  const stigId = document.getElementById('scan-stig')?.value;
  const port = document.getElementById('scan-port')?.value;

  if (!host || !user || !stigId) {
    toast('Fill in host, username, and STIG', 'error');
    return;
  }

  toast(`Scanning ${host} via ${protocol.toUpperCase()}...`, 'info');

  try {
    const result = await api('/scan/ssh', {
      method: 'POST',
      body: JSON.stringify({
        host, username: user, stig_id: stigId, platform,
        port: port ? parseInt(port) : null,
        auth: { type: 'password', password: pass },
      }),
    });
    toast(
      `Scan complete: ${result.checks_executed} checks, ${(result.compliance_pct ?? 0).toFixed(1)}% compliance`,
      'success',
    );
    viewChecklist(result.id);
  } catch (e) {
    toast(`Scan failed: ${e.message}`, 'error');
  }
}

// ---------------------------------------------------------------------------
// Export Helpers
// ---------------------------------------------------------------------------
function exportCkl(id) {
  window.open(`${API}/export/ckl/${id}?token=${AUTH_TOKEN}`, '_blank');
}

function exportCklb(id) {
  window.open(`${API}/export/cklb/${id}?token=${AUTH_TOKEN}`, '_blank');
}

// ---------------------------------------------------------------------------
// Settings Page (STIG-Manager config)
// ---------------------------------------------------------------------------
async function loadSettings() {
  setPage('settings', loadingState());

  let config = {};
  let creds = [];
  await Promise.all([
    api('/stigman/config').then(data => { config = data; }).catch(() => {}),
    api('/credentials').then(data => { creds = Array.isArray(data) ? data : []; }).catch(() => {}),
  ]);

  setPage('settings',
    h('div', { className: 'page-header' },
      h('h1', {}, 'Settings'),
      h('p', {}, 'Configure integrations and application preferences'),
    ),
    h('div', { className: 'card', style: 'max-width: 700px' },
      h('div', { className: 'card-header' },
        h('h2', {}, 'STIG-Manager Integration'),
        config.configured
          ? h('span', { className: 'status-badge status-naf' }, 'Configured')
          : h('span', { className: 'status-badge status-nr' }, 'Not Configured'),
      ),
      h('p', { style: 'color: var(--text-secondary); font-size: 0.9rem; margin-bottom: 20px' },
        'Connect to a STIG-Manager instance to push evaluation results directly. ',
        'Uses OAuth2 Client Credentials flow via Keycloak.',
      ),
      h('div', { className: 'form-group' },
        h('label', { className: 'form-label' }, 'STIG-Manager API URL'),
        h('input', { className: 'form-input', id: 'sm-api-url', type: 'text',
          placeholder: 'https://stigman.example.mil/api', value: config.api_url || '' }),
      ),
      h('div', { className: 'form-group' },
        h('label', { className: 'form-label' }, 'Keycloak Token URL'),
        h('input', { className: 'form-input', id: 'sm-token-url', type: 'text',
          placeholder: 'https://keycloak.example.mil/realms/stigman/protocol/openid-connect/token',
          value: config.token_url || '' }),
      ),
      h('div', { className: 'grid-2' },
        h('div', { className: 'form-group' },
          h('label', { className: 'form-label' }, 'Client ID'),
          h('input', { className: 'form-input', id: 'sm-client-id', type: 'text',
            placeholder: 'automatestig', value: config.client_id || '' }),
        ),
        h('div', { className: 'form-group' },
          h('label', { className: 'form-label' }, 'Client Secret'),
          h('input', { className: 'form-input', id: 'sm-client-secret', type: 'password',
            placeholder: config.has_secret ? '(saved)' : 'Enter secret' }),
        ),
      ),
      h('div', { className: 'form-group' },
        h('label', { className: 'form-label' }, 'Default Collection ID (optional)'),
        h('input', { className: 'form-input', id: 'sm-collection-id', type: 'text',
          placeholder: 'Leave blank to choose each time', value: config.default_collection_id || '' }),
      ),
      h('div', { className: 'form-group', style: 'display: flex; align-items: center; gap: 10px' },
        h('input', { type: 'checkbox', id: 'sm-verify-tls', checked: config.verify_tls !== false }),
        h('label', { for: 'sm-verify-tls', style: 'font-size: 0.9rem; cursor: pointer' }, 'Verify TLS certificates (uncheck for self-signed certs in lab environments)'),
      ),
      h('div', { className: 'btn-group', style: 'margin-top: 24px' },
        h('button', { className: 'btn btn-primary', onClick: saveStigManagerConfig }, 'Save'),
        h('button', { className: 'btn btn-secondary', onClick: testStigManagerConnection }, 'Test Connection'),
      ),
      h('div', { id: 'sm-test-result', style: 'margin-top: 16px' }),
    ),
    h('div', { className: 'card', style: 'max-width: 700px; margin-top: 20px' },
      h('div', { className: 'card-header' },
        h('h2', {}, 'Answer Files'),
      ),
      h('p', { style: 'color: var(--text-secondary); font-size: 0.9rem; margin-bottom: 16px' },
        'Create and manage answer file templates for pre-populating checklist findings.',
      ),
      h('button', { className: 'btn btn-primary', onClick: openAnswerEditor }, 'Open Answer File Editor'),
    ),
    h('div', { className: 'card', style: 'max-width: 700px; margin-top: 20px' },
      h('div', { className: 'card-header' },
        h('h2', {}, `Credentials (${creds.length})`),
        h('button', { className: 'btn btn-secondary btn-sm', onClick: addCredentialDialog }, 'Add Credential'),
      ),
      creds.length > 0
        ? h('table', { className: 'data-table' },
            h('thead', {}, h('tr', {},
              h('th', {}, 'Label'), h('th', {}, 'Type'), h('th', {}, 'Username'), h('th', {}, ''),
            )),
            h('tbody', {}, ...creds.map(c =>
              h('tr', {},
                h('td', { style: 'font-weight: 600' }, c.label),
                h('td', {}, sevBadge(c.credential_type)),
                h('td', {}, c.username || '\u2014'),
                h('td', {},
                  h('button', { className: 'btn btn-danger btn-sm', onClick: () => removeCred(c.id, c.label) }, '\u00D7'),
                ),
              ),
            )),
          )
        : h('p', { style: 'color: var(--text-muted); padding: 16px' }, 'No credentials stored.'),
    ),
  );
}

async function saveStigManagerConfig() {
  const config = {
    api_url: document.getElementById('sm-api-url')?.value || '',
    token_url: document.getElementById('sm-token-url')?.value || '',
    client_id: document.getElementById('sm-client-id')?.value || '',
    client_secret: document.getElementById('sm-client-secret')?.value || '',
    default_collection_id: document.getElementById('sm-collection-id')?.value || null,
    verify_tls: document.getElementById('sm-verify-tls')?.checked !== false,
  };

  // Don't overwrite secret with empty string if placeholder is showing
  if (!config.client_secret) {
    try {
      const existing = await api('/stigman/config');
      if (existing.has_secret) {
        toast('Secret not changed (field was empty)', 'info');
        // We need the secret — for now just warn
      }
    } catch (_) {}
  }

  try {
    await api('/stigman/config', { method: 'POST', body: JSON.stringify(config) });
    toast('STIG-Manager configuration saved', 'success');
    loadSettings();
  } catch (e) {
    toast(`Save failed: ${e.message}`, 'error');
  }
}

async function testStigManagerConnection() {
  const el = document.getElementById('sm-test-result');
  if (el) el.innerHTML = '<span style="color: var(--text-muted)">Testing connection...</span>';

  try {
    const result = await api('/stigman/test', { method: 'POST' });
    el.textContent = '';
    el.appendChild(h('span', { style: 'color: var(--green); font-weight: 600' }, '\u2713 ' + result));
    toast('STIG-Manager connection successful', 'success');
  } catch (e) {
    el.textContent = '';
    el.appendChild(h('span', { style: 'color: var(--red); font-weight: 600' }, '\u2717 ' + e.message));
    toast(`Connection failed: ${e.message}`, 'error');
  }
}

// ---------------------------------------------------------------------------
// Push to STIG-Manager
// ---------------------------------------------------------------------------
async function pushToStigManager(checklistId, hostname) {
  // Check if configured.
  let config;
  try { config = await api('/stigman/config'); } catch (_) {
    toast('STIG-Manager not configured. Go to Settings first.', 'error');
    nav('settings');
    return;
  }
  if (!config.configured) {
    toast('STIG-Manager not configured. Go to Settings first.', 'error');
    nav('settings');
    return;
  }

  // If default collection is set, use it directly.
  if (config.default_collection_id) {
    await doPush(checklistId, hostname, config.default_collection_id);
    return;
  }

  // Otherwise, fetch collections and let user pick via modal.
  toast('Loading collections from STIG-Manager...', 'info');
  try {
    const collections = await api('/stigman/collections');
    if (!collections || collections.length === 0) {
      toast('No collections found in STIG-Manager', 'error');
      return;
    }

    const selectedId = await pickCollection(collections);
    if (!selectedId) return;

    await doPush(checklistId, hostname, selectedId);
  } catch (e) {
    toast(`Failed to list collections: ${e.message}`, 'error');
  }
}

async function doPush(checklistId, hostname, collectionId) {
  toast(`Pushing ${hostname} results to STIG-Manager...`, 'info');
  try {
    const result = await api(`/stigman/push/${checklistId}`, {
      method: 'POST',
      body: JSON.stringify({ collection_id: collectionId }),
    });
    toast(`Pushed ${result.pushed} reviews to STIG-Manager`, 'success');
  } catch (e) {
    toast(`Push failed: ${e.message}`, 'error');
  }
}

async function fetchAllContent() {
  toast('Fetching all STIG content from DISA... this may take a few minutes.', 'info');
  try {
    const result = await api('/disa/fetch-all', { method: 'POST' });
    const el = document.getElementById('content-results');
    if (el) {
      el.innerHTML = '';
      el.appendChild(h('div', { className: 'card', style: 'margin-top: 20px' },
        h('div', { className: 'card-header' },
          h('h2', {}, 'Fetch Results'),
        ),
        h('div', { className: 'stats-grid', style: 'margin-bottom: 16px' },
          statCard('New', result.new_benchmarks, 'green'),
          statCard('Updated', result.updated_benchmarks, 'accent'),
          statCard('Current', result.already_current, ''),
          statCard('Errors', result.errors.length, result.errors.length > 0 ? 'red' : 'green'),
        ),
        ...(result.details.length ? [h('div', { style: 'max-height: 300px; overflow-y: auto' },
          ...result.details.map(d => h('div', { style: 'padding: 4px 0; font-size: 0.85rem; color: var(--text-secondary)' }, d)),
        )] : []),
        ...(result.errors.length ? [h('div', { style: 'margin-top: 12px' },
          ...result.errors.map(e => h('div', { style: 'padding: 4px 0; font-size: 0.85rem; color: var(--red)' }, e)),
        )] : []),
      ));
    }
    toast(`Done! ${result.new_benchmarks} new, ${result.updated_benchmarks} updated.`, 'success');
  } catch (e) {
    toast(`Fetch failed: ${e.message}`, 'error');
  }
}

async function checkForUpdates() {
  toast('Checking DISA for updates...', 'info');
  try {
    const result = await api('/disa/check-updates');
    toast(`${result.available_count} STIGs available, ${result.installed_count} installed locally.`, 'info');
    showAvailableList(result.available_stigs);
  } catch (e) {
    toast(`Check failed: ${e.message}`, 'error');
  }
}

async function browseAvailable() {
  toast('Loading available STIGs from DISA...', 'info');
  try {
    const stigs = await api('/disa/available');
    showAvailableList(stigs);
    toast(`Found ${stigs.length} STIG packages on DISA.`, 'success');
  } catch (e) {
    toast(`Failed to browse: ${e.message}`, 'error');
  }
}

function showAvailableList(stigs) {
  const el = document.getElementById('available-list');
  if (!el) return;
  el.innerHTML = '';

  if (!stigs || stigs.length === 0) {
    el.appendChild(h('p', { style: 'color: var(--text-muted); padding: 20px; text-align: center' },
      'No STIGs found. The DISA site may be unreachable.'));
    return;
  }

  const rows = stigs.map(s =>
    h('tr', {},
      h('td', { style: 'max-width: 400px' }, s.title),
      h('td', {},
        h('button', { className: 'btn btn-primary btn-sm', onClick: () => fetchSingleStig(s) }, 'Download'),
      ),
    ),
  );

  el.appendChild(h('table', { className: 'data-table' },
    h('thead', {}, h('tr', {},
      h('th', {}, 'STIG Package'),
      h('th', {}, 'Action'),
    )),
    h('tbody', {}, ...rows),
  ));
}

async function fetchSingleStig(stig) {
  toast(`Downloading: ${stig.title}...`, 'info');
  try {
    const result = await api('/disa/fetch', {
      method: 'POST',
      body: JSON.stringify({ url: stig.download_url }),
    });
    toast(`Imported: ${result.new_benchmarks} new, ${result.updated_benchmarks} updated.`, 'success');
    result.details.forEach(d => toast(d, 'info'));
  } catch (e) {
    toast(`Download failed: ${e.message}`, 'error');
  }
}

function downloadOfflinePack() {
  toast('Generating offline .stigpack — check your downloads folder. Transfer to air-gapped systems via USB/DVD.', 'info');
  window.open(`${API}/offline-pack?token=${AUTH_TOKEN}`, '_blank');
}

function addAssetDialog() {
  const overlay = h('div', { className: 'modal-overlay' },
    h('div', { className: 'modal', style: 'max-width: 500px' },
      h('h3', {}, 'Add Asset'),
      h('div', { className: 'form-group' },
        h('label', { className: 'form-label' }, 'Name'), h('input', { className: 'form-input', id: 'aa-name', placeholder: 'server01' })),
      h('div', { className: 'form-group' },
        h('label', { className: 'form-label' }, 'Address'), h('input', { className: 'form-input', id: 'aa-addr', placeholder: '10.0.1.50' })),
      h('div', { className: 'grid-2' },
        h('div', { className: 'form-group' },
          h('label', { className: 'form-label' }, 'Platform'),
          h('select', { className: 'form-select', id: 'aa-platform' },
            h('option', { value: 'linux' }, 'Linux'), h('option', { value: 'windows' }, 'Windows'),
            h('option', { value: 'cisco_ios' }, 'Cisco IOS'), h('option', { value: 'generic' }, 'Other'))),
        h('div', { className: 'form-group' },
          h('label', { className: 'form-label' }, 'Protocol'),
          h('select', { className: 'form-select', id: 'aa-proto' },
            h('option', { value: 'ssh' }, 'SSH')))),
      h('div', { className: 'form-group' },
        h('label', { className: 'form-label' }, 'Tags (comma-separated)'),
        h('input', { className: 'form-input', id: 'aa-tags', placeholder: 'production, web-tier' })),
      h('div', { className: 'btn-group', style: 'justify-content: flex-end; margin-top: 16px' },
        h('button', { className: 'btn btn-secondary', onClick: () => overlay.remove() }, 'Cancel'),
        h('button', { className: 'btn btn-primary', onClick: async () => {
          const asset = {
            id: crypto.randomUUID(), name: document.getElementById('aa-name')?.value,
            address: document.getElementById('aa-addr')?.value,
            platform: document.getElementById('aa-platform')?.value,
            protocol: document.getElementById('aa-proto')?.value,
            tags: (document.getElementById('aa-tags')?.value || '').split(',').map(t => t.trim()).filter(t => t),
            assigned_stigs: [], enabled: true, port: null, credential_id: null,
            os_info: null, notes: null, last_evaluated: null, last_compliance_pct: null,
            last_checklist_ids: [], created_at: new Date().toISOString(),
          };
          try { await api('/assets', { method: 'POST', body: JSON.stringify(asset) }); overlay.remove(); toast('Asset added', 'success'); loadAssetsPage(); }
          catch (e) { toast(e.message, 'error'); }
        }}, 'Add'),
      ),
    ),
  );
  document.body.appendChild(overlay);
}

async function bulkAssignStig(assetIds, benchmarks) {
  if (!assetIds.length) return;
  const stigId = await pickBenchmark(benchmarks);
  if (!stigId) return;
  try {
    await api('/assets/bulk-assign-stig', { method: 'POST', body: JSON.stringify({ asset_ids: assetIds, stig_id: stigId }) });
    toast(`Assigned ${stigId} to ${assetIds.length} asset(s)`, 'success');
    loadAssetsPage();
  } catch (e) { toast(e.message, 'error'); }
}

async function bulkAddTag(assetIds) {
  if (!assetIds.length) return;
  const tag = await promptText('Add tag', 'Tag to add to selected assets', 'production');
  if (!tag) return;
  try {
    await api('/assets/bulk-update', { method: 'POST', body: JSON.stringify({ asset_ids: assetIds, add_tag: tag }) });
    toast(`Tagged ${assetIds.length} asset(s)`, 'success');
    loadAssetsPage();
  } catch (e) { toast(e.message, 'error'); }
}

async function bulkSetEnabled(assetIds, enabled) {
  if (!assetIds.length) return;
  try {
    await api('/assets/bulk-update', { method: 'POST', body: JSON.stringify({ asset_ids: assetIds, enabled }) });
    toast(`${enabled ? 'Enabled' : 'Disabled'} ${assetIds.length} asset(s)`, 'success');
    loadAssetsPage();
  } catch (e) { toast(e.message, 'error'); }
}

function pickBenchmark(benchmarks) {
  return new Promise(resolve => {
    if (!benchmarks || !benchmarks.length) { toast('No standards installed', 'error'); resolve(null); return; }
    const overlay = h('div', { className: 'modal-overlay', onClick: (e) => { if (e.target === overlay) { overlay.remove(); resolve(null); } } },
      h('div', { className: 'modal' },
        h('h3', {}, 'Assign standard'),
        h('div', { className: 'stack-list', style: 'margin-top: 12px' },
          ...benchmarks.map(b => h('button', { className: 'action-row', onClick: () => { overlay.remove(); resolve(b.id); } },
            h('div', {}, h('div', { className: 'list-title' }, b.title || b.id), h('div', { className: 'list-subtitle' }, b.id)),
            h('span', { className: 'action-arrow' }, '→'))),
        ),
        h('div', { className: 'btn-group', style: 'justify-content: flex-end; margin-top: 16px' },
          h('button', { className: 'btn btn-secondary', onClick: () => { overlay.remove(); resolve(null); } }, 'Cancel')),
      ),
    );
    document.body.appendChild(overlay);
  });
}

function promptText(title, label, placeholder) {
  return new Promise(resolve => {
    const overlay = h('div', { className: 'modal-overlay', onClick: (e) => { if (e.target === overlay) { overlay.remove(); resolve(null); } } },
      h('div', { className: 'modal' },
        h('h3', {}, title),
        h('div', { className: 'form-group', style: 'margin-top: 12px' },
          h('label', { className: 'form-label' }, label),
          h('input', { className: 'form-input', id: 'prompt-text', placeholder: placeholder || '' })),
        h('div', { className: 'btn-group', style: 'justify-content: flex-end' },
          h('button', { className: 'btn btn-secondary', onClick: () => { overlay.remove(); resolve(null); } }, 'Cancel'),
          h('button', { className: 'btn btn-primary', onClick: () => { const v = document.getElementById('prompt-text')?.value?.trim(); overlay.remove(); resolve(v || null); } }, 'OK')),
      ),
    );
    document.body.appendChild(overlay);
    setTimeout(() => document.getElementById('prompt-text')?.focus(), 50);
  });
}

async function checkStigManagerDiff() {
  let config;
  try { config = await api('/stigman/config'); } catch (_) {
    toast('STIG-Manager not configured. Go to Settings.', 'error'); nav('settings'); return;
  }
  if (!config.configured) {
    toast('STIG-Manager not configured. Go to Settings.', 'error'); nav('settings'); return;
  }

  toast('Checking STIG-Manager for changes...', 'info');
  try {
    const collections = await api('/stigman/collections');
    if (!collections || collections.length === 0) { toast('No collections found', 'error'); return; }

    const selectedId = await pickCollection(collections);
    if (!selectedId) return;

    const diff = await api(`/stigman/diff/${selectedId}`);

    if (!diff.has_changes) {
      toast('Everything is in sync \u2014 no changes detected.', 'success');
      return;
    }

    // Show diff results in a modal.
    const items = [];
    if (diff.new_assets_in_stigman.length > 0) {
      items.push(h('div', { style: 'margin-bottom: 12px' },
        h('h4', { style: 'color: var(--green); margin-bottom: 4px' }, `${diff.new_assets_in_stigman.length} New Assets in STIG-Manager`),
        ...diff.new_assets_in_stigman.map(a => h('div', { style: 'font-size: 0.85rem; padding: 2px 0' }, `+ ${a}`)),
      ));
    }
    if (diff.removed_from_stigman.length > 0) {
      items.push(h('div', { style: 'margin-bottom: 12px' },
        h('h4', { style: 'color: var(--red); margin-bottom: 4px' }, `${diff.removed_from_stigman.length} Removed from STIG-Manager`),
        ...diff.removed_from_stigman.map(a => h('div', { style: 'font-size: 0.85rem; padding: 2px 0' }, `- ${a}`)),
      ));
    }
    if (diff.stig_assignment_changes.length > 0) {
      items.push(h('div', { style: 'margin-bottom: 12px' },
        h('h4', { style: 'color: var(--yellow); margin-bottom: 4px' }, `${diff.stig_assignment_changes.length} STIG Assignment Changes`),
        ...diff.stig_assignment_changes.map(c => h('div', { style: 'font-size: 0.85rem; padding: 2px 0' },
          `${c.asset}: +${c.stigs_added.length} / -${c.stigs_removed.length} STIGs`)),
      ));
    }

    const overlay = h('div', { className: 'modal-overlay' },
      h('div', { className: 'modal', style: 'max-width: 500px' },
        h('h3', {}, 'STIG-Manager Changes Detected'),
        h('p', { style: 'color: var(--text-secondary); margin-bottom: 16px' },
          `Local: ${diff.local_count} assets | STIG-Manager: ${diff.stigman_count} assets`),
        ...items,
        h('div', { className: 'btn-group', style: 'justify-content: flex-end; margin-top: 16px' },
          h('button', { className: 'btn btn-secondary', onClick: () => overlay.remove() }, 'Close'),
          h('button', { className: 'btn btn-primary', onClick: () => { overlay.remove(); syncFromStigManager(); } }, 'Sync Now'),
        ),
      ),
    );
    document.body.appendChild(overlay);
  } catch (e) {
    toast(`Check failed: ${e.message}`, 'error');
  }
}

async function syncFromStigManager() {
  let config;
  try { config = await api('/stigman/config'); } catch (_) {
    toast('STIG-Manager not configured. Go to Settings.', 'error'); nav('settings'); return;
  }
  if (!config.configured) {
    toast('STIG-Manager not configured. Go to Settings.', 'error'); nav('settings'); return;
  }

  toast('Loading collections from STIG-Manager...', 'info');
  try {
    const collections = await api('/stigman/collections');
    if (!collections || collections.length === 0) {
      toast('No collections found', 'error'); return;
    }

    const selectedId = await pickCollection(collections);
    if (!selectedId) return;

    toast('Syncing assets from STIG-Manager...', 'info');
    const result = await api(`/stigman/sync/${selectedId}`, { method: 'POST' });
    toast(`Synced ${result.synced} assets (${result.total_assets} total in inventory)`, 'success');
    result.details.forEach(d => toast(d, 'info'));
    loadAssetsPage();
  } catch (e) {
    toast(`Sync failed: ${e.message}`, 'error');
  }
}

function addCredentialDialog() {
  const overlay = h('div', { className: 'modal-overlay' },
    h('div', { className: 'modal', style: 'max-width: 500px' },
      h('h3', {}, 'Add Credential'),
      h('div', { className: 'form-group' },
        h('label', { className: 'form-label' }, 'Label'), h('input', { className: 'form-input', id: 'ac-label', placeholder: 'Linux admin account' })),
      h('div', { className: 'form-group' },
        h('label', { className: 'form-label' }, 'Type'),
        h('select', { className: 'form-select', id: 'ac-type' },
          h('option', { value: 'password' }, 'Password'), h('option', { value: 'ssh_key' }, 'SSH Key'),
          h('option', { value: 'kerberos' }, 'Kerberos'), h('option', { value: 'token' }, 'Token'))),
      h('div', { className: 'form-group' },
        h('label', { className: 'form-label' }, 'Username'), h('input', { className: 'form-input', id: 'ac-user', placeholder: 'admin' })),
      h('div', { className: 'form-group' },
        h('label', { className: 'form-label' }, 'Password / Key / Token'), h('input', { className: 'form-input', id: 'ac-secret', type: 'password' })),
      h('div', { className: 'btn-group', style: 'justify-content: flex-end; margin-top: 16px' },
        h('button', { className: 'btn btn-secondary', onClick: () => overlay.remove() }, 'Cancel'),
        h('button', { className: 'btn btn-primary', onClick: async () => {
          const type = document.getElementById('ac-type')?.value;
          const cred = {
            id: crypto.randomUUID(), label: document.getElementById('ac-label')?.value,
            credential: type === 'password' ? { type: 'password', username: document.getElementById('ac-user')?.value, password: document.getElementById('ac-secret')?.value }
              : type === 'ssh_key' ? { type: 'ssh_key', username: document.getElementById('ac-user')?.value, private_key: document.getElementById('ac-secret')?.value, passphrase: null }
              : type === 'kerberos' ? { type: 'kerberos', username: document.getElementById('ac-user')?.value, domain: 'DOMAIN', password: document.getElementById('ac-secret')?.value }
              : { type: 'token', token: document.getElementById('ac-secret')?.value, token_type: 'bearer' },
            description: null, created_at: new Date().toISOString(), last_used: null, expires_at: null,
          };
          try { await api('/credentials', { method: 'POST', body: JSON.stringify(cred) }); overlay.remove(); toast('Credential saved', 'success'); loadSettings(); }
          catch (e) { toast(e.message, 'error'); }
        }}, 'Save'),
      ),
    ),
  );
  document.body.appendChild(overlay);
}

async function removeCred(id, label) {
  if (!(await confirmDialog('Delete Credential', `Remove "${label}"?`))) return;
  try { await api(`/credentials/${id}`, { method: 'DELETE' }); toast('Credential removed', 'success'); loadSettings(); }
  catch (e) { toast(e.message, 'error'); }
}

// ---------------------------------------------------------------------------
// Export All ZIP
// ---------------------------------------------------------------------------
function exportAllZip() {
  window.open(`${API}/export/all-zip?token=${AUTH_TOKEN}`, '_blank');
  toast('Exporting all checklists as ZIP...', 'info');
}

// ---------------------------------------------------------------------------
// Re-evaluate
// ---------------------------------------------------------------------------
async function reEvaluate(checklistId) {
  toast('Re-evaluating...', 'info');
  try {
    const result = await api(`/checklists/${checklistId}/re-evaluate`, { method: 'POST' });
    toast(`Re-evaluation complete: ${(result.compliance_pct ?? 0).toFixed(1)}% compliance`, 'success');
    viewChecklist(result.id);
  } catch (e) {
    toast(`Re-evaluation failed: ${e.message}`, 'error');
  }
}

// ---------------------------------------------------------------------------
// Delete Checklist
// ---------------------------------------------------------------------------
async function deleteChecklist(id, hostname) {
  const confirmed = await confirmDialog('Delete Checklist', `Delete the checklist for "${hostname}"? This cannot be undone.`);
  if (!confirmed) return;
  try {
    await api(`/checklists/${id}`, { method: 'DELETE' });
    toast('Checklist deleted', 'success');
    nav('assessments');
  } catch (e) {
    toast(`Delete failed: ${e.message}`, 'error');
  }
}

// ---------------------------------------------------------------------------
// Batch Evaluate (Fix #3)
// ---------------------------------------------------------------------------
async function runBatchEvaluation() {
  const stigId = document.getElementById('batch-stig')?.value;
  const hostsText = document.getElementById('batch-hosts')?.value;
  if (!stigId || !hostsText) { toast('Select a STIG and enter hostnames', 'error'); return; }

  const hostnames = hostsText.split('\n').map(h => h.trim()).filter(h => h.length > 0);
  if (hostnames.length === 0) { toast('Enter at least one hostname', 'error'); return; }

  toast(`Evaluating ${hostnames.length} hosts...`, 'info');
  try {
    const result = await api('/evaluate/batch', {
      method: 'POST',
      body: JSON.stringify({ stig_id: stigId, hostnames }),
    });
    const successes = result.results.filter(r => r.success).length;
    toast(`Batch complete: ${successes}/${result.evaluated} succeeded`, 'success');
    loadAssessments();
  } catch (e) {
    toast(`Batch failed: ${e.message}`, 'error');
  }
}

// ---------------------------------------------------------------------------
// Generate Checks (Fix #7)
// ---------------------------------------------------------------------------
async function generateChecks(benchmarkId) {
  toast(`Generating check pack for ${benchmarkId}...`, 'info');
  try {
    const result = await api(`/library/generate-checks/${benchmarkId}`, { method: 'POST' });
    toast(`Generated: ${result.automated} automated checks (${result.automation_rate} of ${result.total_rules} rules)`, 'success');
  } catch (e) {
    toast(`Generation failed: ${e.message}`, 'error');
  }
}

// ---------------------------------------------------------------------------
// STIG-Manager Collection Picker Modal (Fix #13)
// ---------------------------------------------------------------------------
async function pickCollection(collections) {
  return new Promise((resolve) => {
    const rows = collections.map(c =>
      h('div', {
        style: 'padding: 10px 14px; cursor: pointer; border-radius: var(--radius-sm); transition: background 150ms',
        onMouseover: (e) => e.target.style.background = 'var(--bg-hover)',
        onMouseout: (e) => e.target.style.background = 'transparent',
        onClick: () => { overlay.remove(); resolve(c.collection_id || c.collectionId); },
      },
        h('div', { style: 'font-weight: 600' }, c.name),
        h('div', { style: 'font-size: 0.75rem; color: var(--text-muted)' }, c.description || ''),
      ),
    );
    const overlay = h('div', { className: 'modal-overlay' },
      h('div', { className: 'modal', style: 'max-width: 500px' },
        h('h3', {}, 'Select Collection'),
        h('div', { style: 'max-height: 300px; overflow-y: auto' }, ...rows),
        h('div', { className: 'btn-group', style: 'justify-content: flex-end; margin-top: 16px' },
          h('button', { className: 'btn btn-secondary', onClick: () => { overlay.remove(); resolve(null); } }, 'Cancel'),
        ),
      ),
    );
    document.body.appendChild(overlay);
  });
}

// ---------------------------------------------------------------------------
// Status Bar Update (Fix #10)
// ---------------------------------------------------------------------------
async function updateStatusBar() {
  try {
    const config = await api('/stigman/config');
    const dot = document.getElementById('status-dot');
    const text = document.getElementById('status-text');
    if (config.configured) {
      if (dot) dot.style.background = 'var(--green)';
      if (text) text.textContent = 'Connected';
    } else {
      if (dot) dot.style.background = 'var(--orange)';
      if (text) text.textContent = 'Air-Gapped';
    }
  } catch (_) {
    const dot = document.getElementById('status-dot');
    const text = document.getElementById('status-text');
    if (dot) dot.style.background = 'var(--orange)';
    if (text) text.textContent = 'Air-Gapped';
  }
}

// ---------------------------------------------------------------------------
// Answer File Editor
// ---------------------------------------------------------------------------
async function openAnswerEditor() {
  try {
    const [files, benchmarks] = await Promise.all([api('/answer-files'), api('/library/benchmarks')]);
    const opts = benchmarks.map(b => h('option', { value: b.id }, b.id));
    const overlay = h('div', { className: 'modal-overlay' },
      h('div', { className: 'modal', style: 'max-width: 700px; max-height: 80vh; overflow-y: auto' },
        h('h3', {}, 'Answer File Editor'),
        files.length > 0 ? h('div', { style: 'margin-bottom: 16px' },
          h('h4', { style: 'margin-bottom: 8px' }, `Existing Files (${files.length})`),
          ...files.map(f => h('div', { style: 'padding: 4px 0; font-size: 0.85rem' },
            `${f.name} — ${f.stig_id || 'Any STIG'} (${f.entries} entries)`)),
        ) : null,
        h('h4', { style: 'margin: 12px 0 8px' }, 'Create New'),
        h('div', { className: 'form-group' },
          h('label', { className: 'form-label' }, 'Name'),
          h('input', { className: 'form-input', id: 'af-name', placeholder: 'Site Answers' })),
        h('div', { className: 'form-group' },
          h('label', { className: 'form-label' }, 'Target STIG'),
          h('select', { className: 'form-select', id: 'af-stig' }, h('option', { value: '' }, 'Any'), ...opts)),
        h('div', { className: 'form-group' },
          h('label', { className: 'form-label' }, 'Entries (JSON)'),
          h('textarea', { className: 'form-input', id: 'af-entries', rows: '8', style: 'font-family: monospace; font-size: 0.8rem',
            placeholder: '[{"vuln_id":"V-254239","status":"Not_Applicable","finding_details":"Not used"}]' })),
        h('div', { className: 'btn-group', style: 'justify-content: flex-end; margin-top: 12px' },
          h('button', { className: 'btn btn-secondary', onClick: () => overlay.remove() }, 'Close'),
          h('button', { className: 'btn btn-primary', onClick: async () => {
            const name = document.getElementById('af-name')?.value;
            if (!name) { toast('Enter a name', 'error'); return; }
            let entries; try { entries = JSON.parse(document.getElementById('af-entries')?.value || '[]'); } catch (_) { toast('Invalid JSON', 'error'); return; }
            try {
              const r = await api('/answer-files', { method: 'POST', body: JSON.stringify({ name, stig_id: document.getElementById('af-stig')?.value || null, version: '1.0', description: null, entries }) });
              toast(`Saved: ${r.entries} entries`, 'success'); overlay.remove();
            } catch (e) { toast(e.message, 'error'); }
          }}, 'Save'),
        ),
      ),
    );
    document.body.appendChild(overlay);
  } catch (e) { toast(e.message, 'error'); }
}

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------
loadAssessments();
updateStatusBar();

// ---------------------------------------------------------------------------
// Workflow-first UI overlays
// ---------------------------------------------------------------------------
async function fetchChecklistsWithFindings() {
  const summaries = await api('/checklists');
  return Promise.all(summaries.map(summary =>
    api(`/checklists/${summary.id}`).catch(() => summary),
  ));
}

function flattenFindings(checklists) {
  const rows = [];
  for (const checklist of checklists || []) {
    const findings = checklist.findings || [];
    for (const finding of findings) {
      rows.push({
        checklistId: checklist.id,
        hostname: checklist.hostname || checklist.asset?.hostname || 'Unknown asset',
        benchmark: checklist.stig_title || checklist.title || checklist.stig_id || 'Unknown standard',
        stigId: checklist.stig_id || checklist.stigInfo?.stig_id || '',
        compliance: checklist.compliance_pct,
        vulnId: finding.vuln_id || finding.group_id || 'Unknown',
        title: finding.rule_title || finding.title || 'Untitled finding',
        severity: finding.severity || 'Unknown',
        status: finding.status || 'Not Reviewed',
        comments: finding.comments || '',
        details: finding.finding_details || '',
        evaluatedBy: finding.evaluated_by || '',
        evaluatedAt: finding.evaluated_at || checklist.modified_at || checklist.created_at || '',
      });
    }
  }
  return rows;
}

function severityRank(sev) {
  const value = String(sev || '').toLowerCase();
  if (value.includes('cat iii') || value.includes('low')) return 1;
  if (value.includes('cat ii') || value.includes('medium')) return 2;
  if (value.includes('cat i') || value.includes('high')) return 3;
  return 0;
}

function severityTone(sev) {
  const rank = severityRank(sev);
  return rank === 3 ? 'red' : rank === 2 ? 'yellow' : rank === 1 ? 'green' : 'accent';
}

function actionRow(title, subtitle, onClick) {
  return h('button', { className: 'action-row', onClick },
    h('div', {},
      h('div', { className: 'list-title' }, title),
      h('div', { className: 'list-subtitle' }, subtitle),
    ),
    h('span', { className: 'action-arrow' }, '→'),
  );
}

function openAssessment(assessment) {
  if (assessment.items.length === 1) { viewChecklist(assessment.items[0].id); return; }
  pickChecklistDialog(assessment.items);
}

function pickChecklistDialog(items) {
  const overlay = h('div', { className: 'modal-overlay', onClick: (e) => { if (e.target === overlay) overlay.remove(); } },
    h('div', { className: 'modal' },
      h('h3', {}, 'Open checklist'),
      h('div', { className: 'stack-list', style: 'margin-top: 12px' },
        ...items.map(item => h('button', { className: 'action-row', onClick: () => { overlay.remove(); viewChecklist(item.id); } },
          h('div', {},
            h('div', { className: 'list-title' }, item.stig_title || item.stig_id || 'Checklist'),
            h('div', { className: 'list-subtitle' }, `${(item.compliance_pct || 0).toFixed(1)}% compliant • ${item.open || 0} open`),
          ),
          h('span', { className: 'action-arrow' }, '→'),
        )),
      ),
      h('div', { className: 'btn-group', style: 'justify-content: flex-end; margin-top: 16px' },
        h('button', { className: 'btn btn-secondary', onClick: () => overlay.remove() }, 'Cancel'),
      ),
    ),
  );
  document.body.appendChild(overlay);
}

async function loadAssessments() {
  setPage('assessments', loadingState());

  try {
    const [checklists, assets, benchmarks] = await Promise.all([
      api('/checklists'),
      api('/assets').catch(() => []),
      api('/library/benchmarks').catch(() => []),
    ]);

    const grouped = new Map();
    for (const checklist of checklists) {
      const key = checklist.hostname || checklist.asset?.hostname || 'Imported results';
      if (!grouped.has(key)) grouped.set(key, []);
      grouped.get(key).push(checklist);
    }

    const assessments = [...grouped.entries()].map(([name, items], index) => {
      const standards = [...new Set(items.map(item => item.stig_title || item.stig_id).filter(Boolean))];
      const compliance = items.length ? items.reduce((sum, item) => sum + (item.compliance_pct || 0), 0) / items.length : 0;
      const open = items.reduce((sum, item) => sum + (item.open || 0), 0);
      return { id: `assessment-${index}`, name, items, standards, compliance, open, lastRun: items[0]?.modified_at || items[0]?.created_at || null };
    });

    setPage('assessments',
      h('div', { className: 'page-header page-header-with-actions' },
        h('div', {},
          h('h1', {}, 'Assessments'),
          h('p', {}, 'Manage assessment scope, runs, and outputs as grouped workspaces'),
        ),
        h('div', { className: 'btn-group' },
          h('button', { className: 'btn btn-primary', onClick: () => nav('assets') }, 'New Assessment'),
          h('button', { className: 'btn btn-secondary', onClick: importChecklistFile }, 'Import Existing Results'),
        ),
      ),
      assessments.length
        ? h('div', { className: 'card' },
            h('table', { className: 'data-table' },
              h('thead', {}, h('tr', {},
                h('th', {}, 'Assessment'),
                h('th', {}, 'Scope'),
                h('th', {}, 'Last run'),
                h('th', {}, 'Open findings'),
                h('th', {}, 'Compliance'),
                h('th', {}, 'Status'),
              )),
              h('tbody', {}, ...assessments.map(assessment =>
                h('tr', { style: 'cursor: pointer', tabindex: '0', onClick: () => openAssessment(assessment), onKeydown: (e) => { if (e.key === 'Enter') openAssessment(assessment); } },
                  h('td', {},
                    h('div', { className: 'list-title' }, assessment.name),
                    h('div', { className: 'list-subtitle' }, `${assessment.items.length} checklist${assessment.items.length === 1 ? '' : 's'}`),
                  ),
                  h('td', {}, `${assessment.name !== 'Imported results' ? 1 : assets.length || 0} asset • ${assessment.standards.length} standard${assessment.standards.length === 1 ? '' : 's'}`),
                  h('td', {}, formatDate(assessment.lastRun)),
                  h('td', {}, h('span', { className: `mini-pill mini-pill-${assessment.open ? 'red' : 'green'}` }, assessment.open)),
                  h('td', {}, h('span', { className: `mini-pill mini-pill-${complianceColor(assessment.compliance)}` }, `${assessment.compliance.toFixed(1)}%`)),
                  h('td', {}, h('span', { className: 'mini-pill mini-pill-accent' }, assessment.open ? 'Needs review' : 'Healthy')),
                ),
              )),
            ),
          )
        : emptyState('No assessments yet', 'Assessments group assets, standards, findings, and exports into one workflow.',
            h('button', { className: 'btn btn-primary', onClick: importChecklistFile }, 'Import Results')),
      h('div', { className: 'card' },
        h('div', { className: 'card-header' }, h('h2', {}, 'Recommended flow')),
        h('div', { className: 'stack-list' },
          actionRow('1. Add or review assets', 'Make sure scope and tags reflect the environment you want to assess.', () => nav('assets')),
          actionRow('2. Install standards', 'Load current benchmark content before you run or import assessments.', () => nav('standards')),
          actionRow('3. Import or run results', 'Import checklist files or run evaluations from this page.', () => document.getElementById('evaluate-workspace')?.scrollIntoView({ behavior: 'smooth', block: 'start' })),
        ),
      ),
      h('div', { id: 'evaluate-workspace' }),
    );
    renderEvaluateWorkspace();
  } catch (e) {
    setPage('assessments', errorCard(e.message));
  }
}

async function loadStandards() {
  setPage('standards', loadingState());

  try {
    const [benchmarks] = await Promise.all([
      api('/library/benchmarks').catch(() => []),
    ]);

    const rows = benchmarks.map(benchmark => h('tr', {},
      h('td', {},
        h('div', { className: 'list-title' }, benchmark.title || benchmark.stig_id || benchmark.id),
        h('div', { className: 'list-subtitle' }, benchmark.stig_id || benchmark.id || 'Standard identifier'),
      ),
      h('td', {}, benchmark.platform || 'Unknown'),
      h('td', {}, `${benchmark.version || '—'} / ${benchmark.release || '—'}`),
      h('td', {}, benchmark.rule_count ?? benchmark.rules ?? '—'),
      h('td', {}, formatDate(benchmark.imported_at || benchmark.created_at)),
      h('td', {}, h('button', { className: 'btn btn-secondary btn-sm', onClick: (e) => { e.stopPropagation(); generateChecks(benchmark.id); } }, 'Generate Checks')),
    ));

    setPage('standards',
      h('div', { className: 'page-header page-header-with-actions' },
        h('div', {},
          h('h1', {}, 'Standards'),
          h('p', {}, 'Installed benchmark content, imports, updates, and DISA content operations'),
        ),
        h('div', { className: 'btn-group' },
          h('button', { className: 'btn btn-primary', onClick: importStigpackFile }, 'Import Benchmark Pack'),
          h('button', { className: 'btn btn-secondary', onClick: importDisaZipFile }, 'Import XCCDF ZIP'),
        ),
      ),
      h('div', { className: 'stats-grid' },
        statCard('Installed', benchmarks.length, 'accent'),
        statCard('Available actions', 4, 'accent'),
        statCard('Offline packs', 'Ready', 'green'),
        statCard('Source', 'DISA + local packs', 'accent'),
      ),
      h('div', { className: 'overview-grid' },
        h('div', { className: 'card' },
          h('div', { className: 'card-header' }, h('h2', {}, `Installed standards (${benchmarks.length})`)),
          benchmarks.length
            ? h('table', { className: 'data-table' },
                h('thead', {}, h('tr', {},
                  h('th', {}, 'Standard'),
                  h('th', {}, 'Platform'),
                  h('th', {}, 'Version / Release'),
                  h('th', {}, 'Rules'),
                  h('th', {}, 'Imported'),
                  h('th', {}, ''),
                )),
                h('tbody', {}, ...rows),
              )
            : emptyState('No standards installed', 'Import a benchmark pack or fetch content from DISA to begin.'),
        ),
        h('div', { className: 'card' },
          h('div', { className: 'card-header' }, h('h2', {}, 'Content operations')),
          h('div', { className: 'stack-list' },
            actionRow('Fetch from DISA', 'Download the latest public benchmark content.', fetchAllContent),
            actionRow('Check for updates', 'Compare installed standards with available upstream content.', checkForUpdates),
            actionRow('Browse available content', 'Inspect available DISA packages before importing.', browseAvailable),
            actionRow('Generate offline pack', 'Create a .stigpack for transfer into air-gapped environments.', downloadOfflinePack),
          ),
        ),
      ),
      h('div', { id: 'content-results' }),
      h('div', { id: 'content-available', className: 'card' },
        h('div', { className: 'card-header' }, h('h2', {}, 'Available content')), 
        h('div', { id: 'available-list' },
          h('p', { style: 'color: var(--text-muted); padding: 20px; text-align: center' }, 'Use Check Updates or Browse available content to populate this list.'),
        ),
      ),
    );
  } catch (e) {
    setPage('standards', errorCard(e.message));
  }
}

async function loadFindings() {
  setPage('findings', loadingState());

  try {
    const checklists = await fetchChecklistsWithFindings();
    const findings = flattenFindings(checklists);
    const openOnly = findings.filter(f => String(f.status).toLowerCase() === 'open');
    const rows = (openOnly.length ? openOnly : findings).sort((a, b) => severityRank(b.severity) - severityRank(a.severity));

    setPage('findings',
      h('div', { className: 'page-header page-header-with-actions' },
        h('div', {},
          h('h1', {}, 'Findings'),
          h('p', {}, 'Review and triage checklist results across all imported and generated assessments'),
        ),
        h('div', { className: 'btn-group' },
          h('button', { className: 'btn btn-secondary', onClick: exportAllZip }, 'Export All ZIP'),
        ),
      ),
      rows.length
        ? h('div', { className: 'card' },
            h('table', { className: 'data-table' },
              h('thead', {}, h('tr', {},
                h('th', {}, 'Vuln ID'),
                h('th', {}, 'Title'),
                h('th', {}, 'Severity'),
                h('th', {}, 'Asset'),
                h('th', {}, 'Standard'),
                h('th', {}, 'Status'),
                h('th', {}, 'Updated'),
              )),
              h('tbody', {}, ...rows.map(row =>
                h('tr', { style: 'cursor: pointer', tabindex: '0', onClick: () => viewChecklist(row.checklistId), onKeydown: (e) => { if (e.key === 'Enter') viewChecklist(row.checklistId); } },
                  h('td', {}, row.vulnId),
                  h('td', {},
                    h('div', { className: 'list-title' }, row.title),
                    h('div', { className: 'list-subtitle' }, row.comments || row.details || 'No analyst notes yet'),
                  ),
                  h('td', {}, h('span', { className: `mini-pill mini-pill-${severityTone(row.severity)}` }, row.severity)),
                  h('td', {}, row.hostname),
                  h('td', {}, row.benchmark),
                  h('td', {}, statusBadge(row.status)),
                  h('td', {}, formatDate(row.evaluatedAt)),
                ),
              )),
            ),
          )
        : emptyState('No findings yet', 'Run an assessment or import existing results to review compliance status.',
            h('button', { className: 'btn btn-primary', onClick: importChecklistFile }, 'Import Results')),
    );
  } catch (e) {
    setPage('findings', errorCard(e.message));
  }
}

async function loadAssetsPage() {
  setPage('assets', loadingState());

  try {
    const assets = await api('/assets');
    const benchmarks = await api('/library/benchmarks').catch(() => []);
    const selected = new Set();
    const rows = assets.map(asset => h('tr', {},
      h('td', {}, h('input', { type: 'checkbox', className: 'asset-check', 'data-id': asset.id,
        onChange: (e) => { if (e.target.checked) selected.add(asset.id); else selected.delete(asset.id); updateBulkBar(); } })),
      h('td', {},
        h('div', { className: 'list-title' }, asset.name),
        h('div', { className: 'list-subtitle' }, asset.address),
      ),
      h('td', {}, asset.platform),
      h('td', {}, asset.protocol),
      h('td', {}, asset.tags?.length ? asset.tags.join(', ') : '—'),
      h('td', {}, asset.assigned_stigs?.length || 0),
      h('td', {}, asset.last_compliance_pct != null
        ? h('span', { className: `mini-pill mini-pill-${complianceColor(asset.last_compliance_pct)}` }, `${asset.last_compliance_pct.toFixed(1)}%`)
        : '—'),
      h('td', {}, formatDate(asset.last_evaluated)),
    ));

    function updateBulkBar() {
      const bar = document.getElementById('bulk-bar');
      const count = document.getElementById('bulk-count');
      if (!bar) return;
      bar.style.display = selected.size ? 'block' : 'none';
      if (count) count.textContent = `${selected.size} selected`;
    }

    setPage('assets',
      h('div', { className: 'page-header page-header-with-actions' },
        h('div', {},
          h('h1', {}, `Assets (${assets.length})`),
          h('p', {}, 'Inventory-first view of managed hosts, assigned standards, and current compliance posture'),
        ),
        h('div', { className: 'btn-group' },
          h('button', { className: 'btn btn-primary', onClick: addAssetDialog }, 'Add Asset'),
          h('button', { className: 'btn btn-secondary', onClick: () => nav('settings') }, 'Credentials'),
        ),
      ),
      h('div', { id: 'bulk-bar', className: 'card', style: 'display:none; margin-bottom: 16px; align-items:center' },
        h('div', { className: 'page-header-with-actions' },
          h('div', {}, h('span', { id: 'bulk-count', className: 'list-title' }, '0 selected')),
          h('div', { className: 'btn-group' },
            h('button', { className: 'btn btn-secondary btn-sm', onClick: () => bulkAssignStig([...selected], benchmarks) }, 'Assign STIG'),
            h('button', { className: 'btn btn-secondary btn-sm', onClick: () => bulkAddTag([...selected]) }, 'Add tag'),
            h('button', { className: 'btn btn-secondary btn-sm', onClick: () => bulkSetEnabled([...selected], true) }, 'Enable'),
            h('button', { className: 'btn btn-secondary btn-sm', onClick: () => bulkSetEnabled([...selected], false) }, 'Disable'),
          ),
        ),
      ),
      assets.length
        ? h('div', { className: 'card' },
            h('table', { className: 'data-table' },
              h('thead', {}, h('tr', {},
                h('th', {}, ''),
                h('th', {}, 'Asset'),
                h('th', {}, 'Platform'),
                h('th', {}, 'Protocol'),
                h('th', {}, 'Tags'),
                h('th', {}, 'Standards'),
                h('th', {}, 'Compliance'),
                h('th', {}, 'Last assessed'),
              )),
              h('tbody', {}, ...rows),
            ),
          )
        : emptyState('No assets yet', 'Add systems manually or sync them from STIG-Manager.'),
      h('div', { className: 'overview-grid' },
        h('div', { className: 'card' },
          h('div', { className: 'card-header' }, h('h2', {}, 'Asset actions')),
          h('div', { className: 'stack-list' },
            actionRow('Add asset', 'Register a host for ongoing review and assessment grouping.', addAssetDialog),
            actionRow('Sync from STIG-Manager', 'Bring collections or assets into the local inventory.', syncFromStigManager),
            actionRow('Check STIG-Manager diff', 'See changes before you synchronize inventory.', checkStigManagerDiff),
          ),
        ),
        h('div', { className: 'card' },
          h('div', { className: 'card-header' }, h('h2', {}, 'Credentials')),
          h('div', { className: 'stack-list' },
            actionRow('Manage credentials', 'Stored credentials live under Settings.', () => nav('settings')),
          ),
        ),
      ),
    );
  } catch (e) {
    setPage('assets', errorCard(e.message));
  }
}

function chooseImportFile(accept, handler) {
  const input = h('input', { type: 'file', accept, style: 'display:none' });
  input.addEventListener('change', async (e) => {
    try { await handler(e); }
    finally { input.remove(); }
  });
  document.body.appendChild(input);
  input.click();
}

function importDisaZipFile() {
  chooseImportFile('.zip', handleDisaZipImport);
}

function importChecklistFile() {
  chooseImportFile('.ckl,.cklb,.json', handleChecklistImport);
}

function importStigpackFile() {
  chooseImportFile('.stigpack', handleStigpackImport);
}

async function handleDisaZipImport(e) {
  const file = e.target.files?.[0];
  if (!file) return;
  try {
    const result = await apiUpload('/library/import-disa', file);
    toast(`Imported ${result.imported} benchmark(s)`, 'success');
    nav('standards');
  } catch (err) {
    toast(err.message, 'error');
  }
}

async function handleChecklistImport(e) {
  const file = e.target.files?.[0];
  if (!file) return;
  try {
    const result = await apiUpload('/checklists/import', file);
    toast(`Imported checklist: ${result.hostname} (${result.total} rules)`, 'success');
    nav('findings');
  } catch (err) {
    toast(err.message, 'error');
  }
}

async function handleStigpackImport(e) {
  const file = e.target.files?.[0];
  if (!file) return;
  try {
    const result = await apiUpload('/library/import-stigpack', file);
    toast(`Imported pack: ${result.imported} benchmark(s)`, 'success');
    nav('standards');
  } catch (err) {
    toast(err.message, 'error');
  }
}

function formatDate(value) {
  if (!value) return '—';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? '—' : date.toLocaleString();
}

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
function confirm(title, message) {
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

function loadPage(page) {
  switch (page) {
    case 'dashboard': loadDashboard(); break;
    case 'evaluate': loadEvaluate(); break;
    case 'library': loadLibrary(); break;
    case 'checklists': loadChecklists(); break;
    case 'assets': loadAssets(); break;
    case 'content': loadGetContent(); break;
    case 'import': loadImport(); break;
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
    if (child == null) continue;
    el.appendChild(typeof child === 'string' ? document.createTextNode(child) : child);
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

// ---------------------------------------------------------------------------
// Dashboard
// ---------------------------------------------------------------------------
async function loadDashboard() {
  try {
    const [status, checklists] = await Promise.all([
      api('/status'),
      api('/checklists'),
    ]);

    document.getElementById('app-version').textContent = `v${status.version}`;

    const totalOpen = checklists.reduce((s, c) => s + c.open, 0);
    const totalFindings = checklists.reduce((s, c) => s + c.total, 0);
    const avgCompliance = checklists.length
      ? checklists.reduce((s, c) => s + c.compliance_pct, 0) / checklists.length : 0;

    setPage('dashboard',
      h('div', { className: 'page-header' },
        h('h1', {}, 'Dashboard'),
        h('p', {}, 'Compliance overview across all evaluated assets'),
      ),
      h('div', { className: 'stats-grid' },
        statCard('STIG Benchmarks', status.benchmark_count, 'accent'),
        statCard('Checklists', checklists.length, 'accent'),
        statCard('Open Findings', totalOpen, totalOpen > 0 ? 'red' : 'green'),
        statCard('Avg Compliance', `${avgCompliance.toFixed(1)}%`, complianceColor(avgCompliance)),
      ),
      checklists.length ? h('div', {},
        h('div', { className: 'btn-group', style: 'margin-bottom: 16px' },
          h('button', { className: 'btn btn-secondary btn-sm', onClick: exportAllZip }, 'Export All as ZIP'),
          h('button', { className: 'btn btn-secondary btn-sm', onClick: compareChecklistsDialog }, 'Compare Two'),
        ),
        checklistsTable(checklists),
      ) : emptyState(
        'No Checklists Yet',
        'Import a checklist or run an evaluation to get started.',
        h('div', { className: 'btn-group' },
          h('button', { className: 'btn btn-primary', onClick: () => nav('evaluate') }, 'Evaluate'),
          h('button', { className: 'btn btn-secondary', onClick: () => nav('import') }, 'Import'),
        ),
      ),
    );
  } catch (e) {
    setPage('dashboard', errorCard(e.message));
  }
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
  document.querySelector(`[data-page="${page}"]`).click();
}

// ---------------------------------------------------------------------------
// Checklists Table (reused on dashboard + checklists page)
// ---------------------------------------------------------------------------
function checklistsTable(checklists) {
  const rows = checklists.map(cl => {
    const compColor = complianceColor(cl.compliance_pct);
    return h('tr', { style: 'cursor: pointer', onClick: (e) => { if (e.target.tagName !== 'BUTTON') viewChecklist(cl.id); } },
      h('td', {},
        h('div', { style: 'font-weight: 600' }, cl.hostname),
        h('div', { style: 'font-size: 0.75rem; color: var(--text-muted)' }, cl.stig_id),
      ),
      h('td', {}, cl.stig_version),
      h('td', {},
        h('span', { className: `stat-value ${compColor}`, style: 'font-size: 1.1rem' },
          `${cl.compliance_pct.toFixed(1)}%`),
        h('div', { className: 'progress-bar' },
          h('div', { className: `progress-fill ${compColor}`, style: `width: ${cl.compliance_pct}%` }),
        ),
      ),
      h('td', { style: cl.open > 0 ? 'color: var(--red); font-weight: 600' : 'color: var(--green)' },
        String(cl.open)),
      h('td', { style: 'color: var(--green)' }, String(cl.not_a_finding)),
      h('td', {},
        h('div', { className: 'btn-group' },
          h('button', { className: 'btn btn-secondary btn-sm', onClick: () => exportCkl(cl.id) }, 'CKL'),
          h('button', { className: 'btn btn-secondary btn-sm', onClick: () => exportCklb(cl.id) }, 'CKLB'),
          h('button', { className: 'btn btn-primary btn-sm', onClick: () => pushToStigManager(cl.id, cl.hostname) }, 'Push'),
          h('button', { className: 'btn btn-danger btn-sm', onClick: (e) => { e.stopPropagation(); deleteChecklist(cl.id, cl.hostname); } }, '\u00D7'),
        ),
      ),
    );
  });

  return h('div', { className: 'card' },
    h('div', { className: 'card-header' },
      h('h2', {}, 'Checklists'),
    ),
    h('table', { className: 'data-table' },
      h('thead', {},
        h('tr', {},
          h('th', {}, 'Asset / STIG'),
          h('th', {}, 'Version'),
          h('th', {}, 'Compliance'),
          h('th', {}, 'Open'),
          h('th', {}, 'NaF'),
          h('th', {}, 'Actions'),
        ),
      ),
      h('tbody', {}, ...rows),
    ),
  );
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
        h('button', { className: 'btn btn-secondary btn-sm', onClick: () => loadChecklists() }, '\u2190 Back'),
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
      statCard('Compliance', `${cl.compliance_pct.toFixed(1)}%`, compColor),
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
          h('button', { className: 'btn btn-secondary btn-sm', onClick: () => viewDriftReport(id) }, 'Drift'),
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
    document.querySelector('[data-page="checklists"]').classList.add('active');
    document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
    page.classList.add('active');
  } catch (e) {
    toast(e.message, 'error');
  }
}

// ---------------------------------------------------------------------------
// Checklists Page
// ---------------------------------------------------------------------------
async function loadChecklists() {
  try {
    const checklists = await api('/checklists');
    setPage('checklists',
      h('div', { className: 'page-header' },
        h('h1', {}, 'Checklists'),
        h('p', {}, 'All evaluated STIG checklists'),
      ),
      checklists.length
        ? checklistsTable(checklists)
        : emptyState('No Checklists', 'Evaluate a STIG or import a checklist to get started.'),
    );
  } catch (e) {
    setPage('checklists', errorCard(e.message));
  }
}

// ---------------------------------------------------------------------------
// Library Page
// ---------------------------------------------------------------------------
async function loadLibrary() {
  try {
    const benchmarks = await api('/library/benchmarks');

    const rows = benchmarks.map(b =>
      h('tr', {},
        h('td', {},
          h('div', { style: 'font-weight: 600' }, b.id),
          h('div', { style: 'font-size: 0.75rem; color: var(--text-muted)' }, b.title),
        ),
        h('td', {}, b.version),
        h('td', {}, b.platform),
        h('td', { style: 'font-weight: 600' }, String(b.rule_count)),
        h('td', {},
          h('button', { className: 'btn btn-secondary btn-sm', onClick: () => viewBenchmark(b.id) }, 'View'),
        ),
      ),
    );

    let libSearch = '';
    function renderLibraryTable() {
      const filtered = benchmarks.filter(b => {
        if (!libSearch) return true;
        const q = libSearch.toLowerCase();
        return b.id.toLowerCase().includes(q) || b.title.toLowerCase().includes(q) || b.platform.toLowerCase().includes(q);
      });
      const tbody = document.getElementById('library-tbody');
      if (!tbody) return;
      tbody.innerHTML = '';
      filtered.forEach(b => {
        tbody.appendChild(h('tr', { style: 'cursor: pointer', onClick: () => viewBenchmark(b.id) },
          h('td', {},
            h('div', { style: 'font-weight: 600' }, b.id),
            h('div', { style: 'font-size: 0.75rem; color: var(--text-muted)' }, b.title),
          ),
          h('td', {}, b.version),
          h('td', {}, b.platform),
          h('td', { style: 'font-weight: 600' }, String(b.rule_count)),
        ));
      });
      const countEl = document.getElementById('library-count');
      if (countEl) countEl.textContent = `STIG Library (${filtered.length})`;
    }

    setPage('library',
      h('div', { className: 'page-header' },
        h('h1', { id: 'library-count' }, `STIG Library (${benchmarks.length})`),
        h('p', {}, `${benchmarks.length} benchmark(s) installed`),
      ),
      benchmarks.length ? h('div', { className: 'card' },
        h('div', { className: 'search-bar' },
          h('input', { className: 'search-input', type: 'text', placeholder: 'Search by ID, title, or platform...',
            onInput: (e) => { libSearch = e.target.value; renderLibraryTable(); } }),
        ),
        h('table', { className: 'data-table' },
          h('thead', {},
            h('tr', {},
              h('th', {}, 'Benchmark'),
              h('th', {}, 'Version'),
              h('th', {}, 'Platform'),
              h('th', {}, 'Rules'),
            ),
          ),
          h('tbody', { id: 'library-tbody' }),
        ),
      ) : emptyState(
        'Library Empty',
        'Import STIG content from DISA or a .stigpack file.',
        h('button', { className: 'btn btn-primary', onClick: () => nav('import') }, 'Import Content'),
      ),
    );
    if (benchmarks.length) renderLibraryTable();
  } catch (e) {
    setPage('library', errorCard(e.message));
  }
}

async function viewBenchmark(id) {
  try {
    const b = await api(`/library/benchmarks/${id}`);
    const page = document.getElementById('page-library');
    page.innerHTML = '';

    page.appendChild(h('div', { className: 'page-header' },
      h('div', { style: 'display: flex; align-items: center; gap: 12px; margin-bottom: 4px' },
        h('button', { className: 'btn btn-secondary btn-sm', onClick: () => loadLibrary() }, '\u2190 Back'),
        h('h1', {}, b.title),
        h('button', { className: 'btn btn-primary btn-sm', onClick: () => generateChecks(b.id) }, 'Generate Checks'),
      ),
      h('p', {}, `${b.id} \u2014 V${b.version}R${b.release}`),
    ));

    page.appendChild(h('div', { className: 'stats-grid' },
      statCard('Total Rules', b.rule_count, 'accent'),
      statCard('CAT I (High)', b.cat_i, b.cat_i > 0 ? 'red' : ''),
      statCard('CAT II (Medium)', b.cat_ii, 'yellow'),
      statCard('CAT III (Low)', b.cat_iii, ''),
    ));

    const rows = b.rules.map(r =>
      h('tr', {},
        h('td', { className: 'mono' }, r.vuln_id),
        h('td', {}, sevBadge(r.severity)),
        h('td', {}, r.title),
      ),
    );

    page.appendChild(h('div', { className: 'card' },
      h('div', { className: 'card-header' }, h('h2', {}, `Rules (${b.rule_count})`)),
      h('table', { className: 'data-table' },
        h('thead', {}, h('tr', {},
          h('th', {}, 'Vuln ID'), h('th', {}, 'Severity'), h('th', {}, 'Title'),
        )),
        h('tbody', {}, ...rows),
      ),
    ));
  } catch (e) {
    toast(e.message, 'error');
  }
}

// ---------------------------------------------------------------------------
// Evaluate Page
// ---------------------------------------------------------------------------
async function loadEvaluate() {
  try {
    const benchmarks = await api('/library/benchmarks');

    const options = benchmarks.map(b =>
      h('option', { value: b.id }, `${b.id} (${b.rule_count} rules)`),
    );

    setPage('evaluate',
      h('div', { className: 'page-header' },
        h('h1', {}, 'Evaluate'),
        h('p', {}, 'Run a STIG evaluation against an asset'),
      ),
      h('div', { className: 'card', style: 'max-width: 600px' },
        h('div', { className: 'form-group' },
          h('label', { className: 'form-label' }, 'STIG Benchmark'),
          benchmarks.length
            ? h('select', { className: 'form-select', id: 'eval-stig' },
                h('option', { value: '' }, 'Select a benchmark...'),
                ...options,
              )
            : h('p', { style: 'color: var(--text-muted)' },
                'No benchmarks installed. ',
                h('a', { href: '#', onClick: (e) => { e.preventDefault(); nav('import'); } }, 'Import STIG content first.'),
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
      ),
    );
    // Batch evaluate section (Fix #3).
    const page = document.getElementById('page-evaluate');
    if (benchmarks.length > 0) {
      const batchOptions = benchmarks.map(b =>
        h('option', { value: b.id }, `${b.id} (${b.rule_count} rules)`),
      );
      page.appendChild(h('div', { className: 'card', style: 'max-width: 600px; margin-top: 20px' },
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

    // Add remote scan section.
    const remoteScanSection = await loadRemoteScan();
    if (remoteScanSection) page.appendChild(remoteScanSection);

  } catch (e) {
    setPage('evaluate', errorCard(e.message));
  }
}

async function runEvaluation() {
  const stigId = document.getElementById('eval-stig')?.value;
  const hostname = document.getElementById('eval-host')?.value;
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
        body: JSON.stringify({ stig_id: stigId, hostname }),
      });
    }
    toast(`Evaluation complete: ${result.total} rules, ${result.open} open, ${result.compliance_pct?.toFixed(1) || '?'}% compliance`, 'success');
    nav('checklists');
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
      h('div', { className: 'grid-2' },
        h('div', { className: 'form-group' },
          h('label', { className: 'form-label' }, 'POA&M Milestone'),
          h('input', { className: 'form-input', id: 'edit-poam', type: 'text',
            placeholder: 'e.g., Patch scheduled for next maintenance window',
            value: (finding.comments || '').match(/\[POA&M: (.+?)\]/)?.[1] || '' }),
        ),
        h('div', { className: 'form-group' },
          h('label', { className: 'form-label' }, 'POA&M Target Date'),
          h('input', { className: 'form-input', id: 'edit-poam-date', type: 'date' }),
        ),
      ),
      h('div', { className: 'btn-group', style: 'justify-content: flex-end' },
        h('button', { className: 'btn btn-secondary', onClick: () => overlay.remove() }, 'Cancel'),
        h('button', { className: 'btn btn-primary', onClick: async () => {
          const status = document.getElementById('edit-status')?.value;
          const details = document.getElementById('edit-details')?.value;
          const comments = document.getElementById('edit-comments')?.value;
          const poam = document.getElementById('edit-poam')?.value;
          const poamDate = document.getElementById('edit-poam-date')?.value;

          // Save POA&M if provided.
          if (poam) {
            try { await api(`/checklists/${checklistId}/findings/${finding.vuln_id}/poam`, {
              method: 'PATCH', body: JSON.stringify({ poam_milestone: poam, poam_date: poamDate || null }) }); } catch (_) {}
          }
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
// Remote Scan (SSH/WinRM)
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
        'Connect to a remote host via SSH (Linux/network) or WinRM (Windows) to collect data and evaluate.',
      ),
      h('div', { className: 'grid-2' },
        h('div', {},
          h('div', { className: 'form-group' },
            h('label', { className: 'form-label' }, 'Protocol'),
            h('select', { className: 'form-select', id: 'scan-protocol' },
              h('option', { value: 'ssh' }, 'SSH (Linux / Network)'),
              h('option', { value: 'winrm' }, 'WinRM (Windows)'),
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
            h('input', { className: 'form-input', id: 'scan-port', type: 'number', placeholder: '22 / 5985' }),
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
    let result;
    if (protocol === 'ssh') {
      result = await api('/scan/ssh', {
        method: 'POST',
        body: JSON.stringify({
          host, username: user, stig_id: stigId,
          port: port ? parseInt(port) : null,
          auth: { type: 'password', password: pass },
        }),
      });
    } else {
      result = await api('/scan/winrm', {
        method: 'POST',
        body: JSON.stringify({
          host, username: user, password: pass, stig_id: stigId,
          port: port ? parseInt(port) : null,
        }),
      });
    }
    toast(
      `Scan complete: ${result.checks_executed} checks, ${result.compliance_pct.toFixed(1)}% compliance`,
      'success',
    );
    viewChecklist(result.id);
  } catch (e) {
    toast(`Scan failed: ${e.message}`, 'error');
  }
}

// Import Page
// ---------------------------------------------------------------------------
function loadImport() {
  setPage('import',
    h('div', { className: 'page-header' },
      h('h1', {}, 'Import'),
      h('p', {}, 'Import STIG content, checklists, or .stigpack files'),
    ),
    h('div', { className: 'grid-2' },
      // DISA Import
      h('div', { className: 'card' },
        h('div', { className: 'card-header' }, h('h2', {}, 'DISA STIG Content')),
        h('p', { style: 'color: var(--text-secondary); margin-bottom: 16px; font-size: 0.9rem' },
          'Import XCCDF benchmarks directly from DISA ZIP archives downloaded from cyber.mil.',
        ),
        makeDropZone('disa-drop', 'Drop DISA ZIP or XCCDF XML here', '.zip, .xml files', async (file) => {
          try {
            const result = await apiUpload('/library/import-disa', file);
            toast(`Imported ${result.imported} benchmark(s)`, 'success');
            result.details.forEach(d => toast(d, 'info'));
          } catch (e) { toast(e.message, 'error'); }
        }),
      ),
      // Checklist Import
      h('div', { className: 'card' },
        h('div', { className: 'card-header' }, h('h2', {}, 'Checklist')),
        h('p', { style: 'color: var(--text-secondary); margin-bottom: 16px; font-size: 0.9rem' },
          'Import an existing CKL, CKLB, or JSON checklist file.',
        ),
        makeDropZone('ckl-drop', 'Drop CKL / CKLB / JSON here', '.ckl, .cklb, .json files', async (file) => {
          try {
            const result = await apiUpload('/checklists/import', file);
            toast(`Imported checklist: ${result.hostname} (${result.total} rules)`, 'success');
          } catch (e) { toast(e.message, 'error'); }
        }),
      ),
    ),
    h('div', { className: 'card', style: 'margin-top: 20px' },
      h('div', { className: 'card-header' }, h('h2', {}, '.stigpack Content Pack')),
      h('p', { style: 'color: var(--text-secondary); margin-bottom: 16px; font-size: 0.9rem' },
        'Import a signed .stigpack content pack with benchmarks, answer templates, and remediation scripts.',
      ),
      makeDropZone('pack-drop', 'Drop .stigpack file here', '.stigpack files', async (file) => {
        try {
          const result = await apiUpload('/library/import-stigpack', file);
          toast(`Imported pack: ${result.imported} benchmark(s)`, 'success');
          result.details.forEach(d => toast(d, 'info'));
        } catch (e) { toast(e.message, 'error'); }
      }),
    ),
  );
}

function makeDropZone(id, text, hint, onFile) {
  const zone = h('div', { className: 'drop-zone', id },
    h('div', { className: 'drop-zone-icon' }, '\u{1F4E5}'),
    h('div', { className: 'drop-zone-text' }, text),
    h('div', { className: 'drop-zone-hint' }, hint),
  );

  const input = h('input', { type: 'file', style: 'display:none' });
  zone.appendChild(input);

  zone.addEventListener('click', () => input.click());
  zone.addEventListener('dragover', (e) => { e.preventDefault(); zone.classList.add('dragover'); });
  zone.addEventListener('dragleave', () => zone.classList.remove('dragover'));
  zone.addEventListener('drop', (e) => {
    e.preventDefault();
    zone.classList.remove('dragover');
    if (e.dataTransfer.files.length) onFile(e.dataTransfer.files[0]);
  });
  input.addEventListener('change', () => {
    if (input.files.length) onFile(input.files[0]);
    input.value = '';
  });

  return zone;
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
  let config = {};
  try { config = await api('/stigman/config'); } catch (_) {}

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

// ---------------------------------------------------------------------------
// Get Content Page (DISA auto-download)
// ---------------------------------------------------------------------------
async function loadGetContent() {
  setPage('content',
    h('div', { className: 'page-header' },
      h('h1', {}, 'Get STIG Content'),
      h('p', {}, 'Download the latest STIG benchmarks directly from DISA (public.cyber.mil)'),
    ),
    h('div', { className: 'stats-grid' },
      h('div', { className: 'stat-card', style: 'cursor: pointer', onClick: fetchAllContent },
        h('div', { className: 'stat-label' }, 'Quick Action'),
        h('div', { className: 'stat-value accent', style: 'font-size: 1.2rem' }, 'Get All STIGs'),
        h('div', { className: 'stat-sub' }, 'Download everything from DISA'),
      ),
      h('div', { className: 'stat-card', style: 'cursor: pointer', onClick: checkForUpdates },
        h('div', { className: 'stat-label' }, 'Check'),
        h('div', { className: 'stat-value', style: 'font-size: 1.2rem' }, 'Check Updates'),
        h('div', { className: 'stat-sub' }, 'See what\'s available'),
      ),
      h('div', { className: 'stat-card', style: 'cursor: pointer', onClick: downloadOfflinePack },
        h('div', { className: 'stat-label' }, 'Air-Gapped'),
        h('div', { className: 'stat-value', style: 'font-size: 1.2rem' }, 'Export Pack'),
        h('div', { className: 'stat-sub' }, 'Generate .stigpack for sandbox transfer'),
      ),
    ),
    h('div', { id: 'content-results' }),
    h('div', { id: 'content-available', className: 'card', style: 'margin-top: 20px' },
      h('div', { className: 'card-header' },
        h('h2', {}, 'Available STIGs'),
        h('button', { className: 'btn btn-secondary btn-sm', onClick: browseAvailable }, 'Browse DISA'),
      ),
      h('div', { id: 'available-list' },
        h('p', { style: 'color: var(--text-muted); padding: 20px; text-align: center' },
          'Click "Browse DISA" or "Check Updates" to see available content.'),
      ),
    ),
    h('div', { className: 'card', style: 'margin-top: 20px' },
      h('div', { className: 'card-header' },
        h('h2', {}, 'Auto-Update'),
      ),
      h('p', { style: 'color: var(--text-secondary); font-size: 0.9rem; margin-bottom: 16px' },
        'When enabled, AutomateSTIG checks DISA for new STIG content every 24 hours. ',
        'Disabled by default (air-gapped mode).',
      ),
      h('div', { style: 'display: flex; align-items: center; gap: 12px; padding: 16px; background: var(--bg-base); border-radius: var(--radius-sm)' },
        h('input', { type: 'checkbox', id: 'auto-update-toggle', onChange: async (e) => {
          try {
            await api('/agent/config', {
              method: 'POST',
              body: JSON.stringify({ enabled: e.target.checked, scan_interval_minutes: 1440, targets: [], auto_push_stigman: false, alert_on_new_findings: true, notifications: {} }),
            });
            // Also set the auto_update_enabled flag the server checks.
            // This is stored separately since agent config is a different structure.
            toast(e.target.checked ? 'Auto-update enabled' : 'Auto-update disabled (air-gapped mode)', 'success');
            updateStatusBar();
          } catch (err) { toast(err.message, 'error'); }
        }}),
        h('label', { for: 'auto-update-toggle', style: 'font-size: 0.9rem; cursor: pointer' }, 'Enable background STIG content updates (requires network access)'),
      ),
    ),
  );
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
  toast('Generating offline update pack...', 'info');
  window.open(`${API}/offline-pack?token=${AUTH_TOKEN}`, '_blank');
  setTimeout(() => toast('Offline .stigpack downloaded. Transfer to air-gapped systems via USB/DVD.', 'success'), 2000);
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// Assets Page
// ---------------------------------------------------------------------------
async function loadAssets() {
  try {
    const [assets, creds, schedConfig] = await Promise.all([
      api('/assets'),
      api('/credentials'),
      api('/schedules'),
    ]);

    const schedules = schedConfig.schedules || [];

    // Asset table.
    const rows = assets.map(a => {
      const compColor = a.last_compliance_pct != null ? complianceColor(a.last_compliance_pct) : '';
      return h('tr', { style: 'cursor: pointer', onClick: (e) => { if (e.target.tagName !== 'BUTTON') editAsset(a); } },
        h('td', {},
          h('div', { style: 'font-weight: 600' }, a.name),
          h('div', { style: 'font-size: 0.75rem; color: var(--text-muted)' }, a.address),
        ),
        h('td', {}, a.platform),
        h('td', {}, a.protocol),
        h('td', {},
          a.assigned_stigs.length > 0
            ? h('span', { style: 'font-size: 0.8rem' }, `${a.assigned_stigs.length} STIG(s)`)
            : h('span', { style: 'color: var(--text-muted); font-size: 0.8rem' }, 'None'),
        ),
        h('td', {},
          a.last_compliance_pct != null
            ? h('span', { className: `stat-value ${compColor}`, style: 'font-size: 1rem' }, `${a.last_compliance_pct.toFixed(1)}%`)
            : h('span', { style: 'color: var(--text-muted)' }, '\u2014'),
        ),
        h('td', {},
          h('div', { className: 'btn-group' },
            h('button', { className: 'btn btn-primary btn-sm', onClick: (e) => { e.stopPropagation(); scanAsset(a); } }, 'Scan'),
            h('button', { className: 'btn btn-danger btn-sm', onClick: (e) => { e.stopPropagation(); removeAsset(a.id, a.name); } }, '\u00D7'),
          ),
        ),
      );
    });

    setPage('assets',
      h('div', { className: 'page-header' },
        h('h1', {}, `Assets (${assets.length})`),
        h('p', {}, 'Managed hosts, credentials, and evaluation schedules'),
      ),
      h('div', { className: 'btn-group', style: 'margin-bottom: 20px' },
        h('button', { className: 'btn btn-primary', onClick: addAssetDialog }, 'Add Asset'),
        h('button', { className: 'btn btn-secondary', onClick: addCredentialDialog }, 'Add Credential'),
        h('button', { className: 'btn btn-secondary', onClick: addScheduleDialog }, 'Add Schedule'),
        h('button', { className: 'btn btn-secondary', onClick: syncFromStigManager }, 'Sync from STIG-Manager'),
        h('button', { className: 'btn btn-secondary', onClick: checkStigManagerDiff }, 'Check for SM Updates'),
      ),
      assets.length > 0 ? h('div', { className: 'card' },
        h('div', { className: 'card-header' }, h('h2', {}, 'Asset Inventory')),
        h('table', { className: 'data-table' },
          h('thead', {}, h('tr', {},
            h('th', {}, 'Host'), h('th', {}, 'Platform'), h('th', {}, 'Protocol'),
            h('th', {}, 'STIGs'), h('th', {}, 'Compliance'), h('th', {}, 'Actions'),
          )),
          h('tbody', {}, ...rows),
        ),
      ) : emptyState('No Assets', 'Add hosts to manage and schedule evaluations.'),
      // Credentials section.
      h('div', { className: 'card', style: 'margin-top: 20px' },
        h('div', { className: 'card-header' }, h('h2', {}, `Credentials (${creds.length})`)),
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
      // Schedules section.
      h('div', { className: 'card', style: 'margin-top: 20px' },
        h('div', { className: 'card-header' }, h('h2', {}, `Schedules (${schedules.length})`)),
        schedules.length > 0
          ? h('table', { className: 'data-table' },
              h('thead', {}, h('tr', {},
                h('th', {}, 'Name'), h('th', {}, 'Frequency'), h('th', {}, 'Assets'),
                h('th', {}, 'Next Run'), h('th', {}, 'Last Status'), h('th', {}, ''),
              )),
              h('tbody', {}, ...schedules.map(s =>
                h('tr', {},
                  h('td', { style: 'font-weight: 600' }, s.name),
                  h('td', {}, s.frequency?.type || 'unknown'),
                  h('td', {}, `${(s.asset_ids?.length || 0) + (s.asset_tags?.length || 0)}`),
                  h('td', { style: 'font-size: 0.8rem' }, s.next_run ? new Date(s.next_run).toLocaleString() : '\u2014'),
                  h('td', {},
                    s.last_run_status
                      ? h('span', { style: s.last_run_status.assets_failed > 0 ? 'color: var(--red)' : 'color: var(--green)' },
                          `${s.last_run_status.assets_scanned} scanned, ${s.last_run_status.avg_compliance.toFixed(0)}%`)
                      : h('span', { style: 'color: var(--text-muted)' }, 'Never run'),
                  ),
                  h('td', {},
                    h('div', { className: 'btn-group' },
                      h('button', { className: 'btn btn-primary btn-sm', onClick: () => runScheduleNow(s.id) }, 'Run Now'),
                      h('button', { className: 'btn btn-danger btn-sm', onClick: () => removeSchedule(s.id, s.name) }, '\u00D7'),
                    ),
                  ),
                ),
              )),
            )
          : h('p', { style: 'color: var(--text-muted); padding: 16px' }, 'No schedules configured.'),
      ),
    );
  } catch (e) {
    setPage('assets', errorCard(e.message));
  }
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
            h('option', { value: 'ssh' }, 'SSH'), h('option', { value: 'winrm' }, 'WinRM'),
            h('option', { value: 'winrm_https' }, 'WinRM HTTPS')))),
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
          try { await api('/assets', { method: 'POST', body: JSON.stringify(asset) }); overlay.remove(); toast('Asset added', 'success'); loadAssets(); }
          catch (e) { toast(e.message, 'error'); }
        }}, 'Add'),
      ),
    ),
  );
  document.body.appendChild(overlay);
}

function editAsset(a) { toast(`Editing ${a.name} — click Scan to evaluate`, 'info'); }

async function scanAsset(asset) {
  if (!asset.assigned_stigs.length) { toast('Assign STIGs to this asset first', 'error'); return; }
  toast(`Scanning ${asset.name}...`, 'info');
  // Use the first assigned STIG for now.
  try {
    const endpoint = asset.protocol === 'ssh' ? '/scan/ssh' : '/scan/winrm';
    const body = asset.protocol === 'ssh'
      ? { host: asset.address, stig_id: asset.assigned_stigs[0], username: 'admin', auth: { type: 'password', password: '' }, port: asset.port }
      : { host: asset.address, stig_id: asset.assigned_stigs[0], username: 'Administrator', password: '', port: asset.port };
    toast('Enter credentials in the Evaluate > Remote Scan form for now', 'info');
  } catch (e) { toast(e.message, 'error'); }
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
    loadAssets();
  } catch (e) {
    toast(`Sync failed: ${e.message}`, 'error');
  }
}

async function removeAsset(id, name) {
  if (!(await confirm('Delete Asset', `Remove "${name}" from the inventory?`))) return;
  try { await api(`/assets/${id}`, { method: 'DELETE' }); toast('Asset removed', 'success'); loadAssets(); }
  catch (e) { toast(e.message, 'error'); }
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
          try { await api('/credentials', { method: 'POST', body: JSON.stringify(cred) }); overlay.remove(); toast('Credential saved', 'success'); loadAssets(); }
          catch (e) { toast(e.message, 'error'); }
        }}, 'Save'),
      ),
    ),
  );
  document.body.appendChild(overlay);
}

async function removeCred(id, label) {
  if (!(await confirm('Delete Credential', `Remove "${label}"?`))) return;
  try { await api(`/credentials/${id}`, { method: 'DELETE' }); toast('Credential removed', 'success'); loadAssets(); }
  catch (e) { toast(e.message, 'error'); }
}

function addScheduleDialog() {
  const overlay = h('div', { className: 'modal-overlay' },
    h('div', { className: 'modal', style: 'max-width: 500px' },
      h('h3', {}, 'Add Schedule'),
      h('div', { className: 'form-group' },
        h('label', { className: 'form-label' }, 'Name'), h('input', { className: 'form-input', id: 'as-name', placeholder: 'Weekly Windows scan' })),
      h('div', { className: 'grid-2' },
        h('div', { className: 'form-group' },
          h('label', { className: 'form-label' }, 'Frequency'),
          h('select', { className: 'form-select', id: 'as-freq' },
            h('option', { value: 'daily' }, 'Daily'), h('option', { value: 'weekly' }, 'Weekly'),
            h('option', { value: 'monthly' }, 'Monthly'), h('option', { value: 'once' }, 'One-time'))),
        h('div', { className: 'form-group' },
          h('label', { className: 'form-label' }, 'Run at (UTC hour)'),
          h('input', { className: 'form-input', id: 'as-hour', type: 'number', value: '2', min: '0', max: '23' }))),
      h('div', { className: 'form-group' },
        h('label', { className: 'form-label' }, 'Asset tags (comma-separated)'),
        h('input', { className: 'form-input', id: 'as-tags', placeholder: 'production, windows' })),
      h('div', { className: 'form-group', style: 'display: flex; align-items: center; gap: 10px' },
        h('input', { type: 'checkbox', id: 'as-stigman' }),
        h('label', { for: 'as-stigman' }, 'Auto-push to STIG-Manager')),
      h('div', { className: 'form-group', style: 'display: flex; align-items: center; gap: 10px' },
        h('input', { type: 'checkbox', id: 'as-alert', checked: true }),
        h('label', { for: 'as-alert' }, 'Alert on new CAT I findings')),
      h('div', { className: 'btn-group', style: 'justify-content: flex-end; margin-top: 16px' },
        h('button', { className: 'btn btn-secondary', onClick: () => overlay.remove() }, 'Cancel'),
        h('button', { className: 'btn btn-primary', onClick: async () => {
          const freq = document.getElementById('as-freq')?.value;
          const frequency = freq === 'daily' ? { type: 'daily' }
            : freq === 'weekly' ? { type: 'weekly', days: ['monday'] }
            : freq === 'monthly' ? { type: 'monthly', day_of_month: 1 }
            : { type: 'once' };
          const schedule = {
            id: crypto.randomUUID(), name: document.getElementById('as-name')?.value, description: null,
            asset_ids: [], asset_tags: (document.getElementById('as-tags')?.value || '').split(',').map(t => t.trim()).filter(t => t),
            enabled: true, frequency, run_at_hour: parseInt(document.getElementById('as-hour')?.value) || 2, run_at_minute: 0,
            max_parallel: 5, stagger_seconds: 10, retry_count: 2, retry_delay_seconds: 30,
            post_actions: { push_to_stigman: document.getElementById('as-stigman')?.checked, alert_on_cat_i: document.getElementById('as-alert')?.checked,
              generate_report: false, alert_on_drift: true, alert_below_compliance: null, stigman_collection_id: null },
            last_run: null, last_run_status: null, next_run: null, created_at: new Date().toISOString(),
          };
          try { await api('/schedules', { method: 'POST', body: JSON.stringify(schedule) }); overlay.remove(); toast('Schedule created', 'success'); loadAssets(); }
          catch (e) { toast(e.message, 'error'); }
        }}, 'Create'),
      ),
    ),
  );
  document.body.appendChild(overlay);
}

async function removeSchedule(id, name) {
  if (!(await confirm('Delete Schedule', `Remove schedule "${name}"?`))) return;
  try { await api(`/schedules/${id}`, { method: 'DELETE' }); toast('Schedule removed', 'success'); loadAssets(); }
  catch (e) { toast(e.message, 'error'); }
}

async function runScheduleNow(id) {
  try {
    const result = await api(`/schedules/${id}/run`, { method: 'POST' });
    toast(`Triggered: ${result.assets_matched} assets matched`, 'success');
  } catch (e) { toast(e.message, 'error'); }
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
    toast(`Re-evaluation complete: ${result.compliance_pct.toFixed(1)}% compliance`, 'success');
    viewChecklist(result.id);
  } catch (e) {
    toast(`Re-evaluation failed: ${e.message}`, 'error');
  }
}

// ---------------------------------------------------------------------------
// Compare Checklists
// ---------------------------------------------------------------------------
async function compareChecklistsDialog() {
  try {
    const checklists = await api('/checklists');
    if (checklists.length < 2) { toast('Need at least 2 checklists to compare', 'error'); return; }

    const options = checklists.map(c => h('option', { value: c.id }, `${c.hostname} — ${c.stig_id} (${c.stig_version})`));

    const overlay = h('div', { className: 'modal-overlay' },
      h('div', { className: 'modal', style: 'max-width: 500px' },
        h('h3', {}, 'Compare Checklists'),
        h('div', { className: 'form-group' },
          h('label', { className: 'form-label' }, 'Checklist A'),
          h('select', { className: 'form-select', id: 'cmp-a' }, ...options),
        ),
        h('div', { className: 'form-group' },
          h('label', { className: 'form-label' }, 'Checklist B'),
          h('select', { className: 'form-select', id: 'cmp-b' }, ...options.map(o => o.cloneNode(true))),
        ),
        h('div', { className: 'btn-group', style: 'justify-content: flex-end; margin-top: 16px' },
          h('button', { className: 'btn btn-secondary', onClick: () => overlay.remove() }, 'Cancel'),
          h('button', { className: 'btn btn-primary', onClick: async () => {
            const a = document.getElementById('cmp-a')?.value;
            const b = document.getElementById('cmp-b')?.value;
            if (a === b) { toast('Select two different checklists', 'error'); return; }
            overlay.remove();
            try {
              const result = await api('/checklists/compare', {
                method: 'POST', body: JSON.stringify({ checklist_a: a, checklist_b: b }),
              });
              showComparisonResult(result);
            } catch (e) { toast(e.message, 'error'); }
          }}, 'Compare'),
        ),
      ),
    );
    document.body.appendChild(overlay);
  } catch (e) { toast(e.message, 'error'); }
}

function showComparisonResult(result) {
  const diffRows = result.differences.map(d =>
    h('tr', {},
      h('td', { className: 'mono' }, d.vuln_id),
      h('td', {}, sevBadge(d.severity)),
      h('td', {}, statusBadge(d.status_a)),
      h('td', {}, statusBadge(d.status_b)),
      h('td', { style: 'max-width: 300px' }, d.title),
    ),
  );

  const overlay = h('div', { className: 'modal-overlay' },
    h('div', { className: 'modal', style: 'max-width: 800px; max-height: 80vh; overflow-y: auto' },
      h('h3', {}, 'Checklist Comparison'),
      h('div', { className: 'grid-2', style: 'margin-bottom: 16px' },
        h('div', { className: 'stat-card' },
          h('div', { className: 'stat-label' }, `A: ${result.checklist_a.hostname}`),
          h('div', { className: `stat-value ${complianceColor(result.checklist_a.compliance)}` },
            `${result.checklist_a.compliance.toFixed(1)}%`),
          h('div', { className: 'stat-sub' }, `${result.checklist_a.open} open`),
        ),
        h('div', { className: 'stat-card' },
          h('div', { className: 'stat-label' }, `B: ${result.checklist_b.hostname}`),
          h('div', { className: `stat-value ${complianceColor(result.checklist_b.compliance)}` },
            `${result.checklist_b.compliance.toFixed(1)}%`),
          h('div', { className: 'stat-sub' }, `${result.checklist_b.open} open`),
        ),
      ),
      result.total_differences > 0
        ? h('div', {},
            h('h4', { style: 'margin-bottom: 8px' }, `${result.total_differences} Differences`),
            h('table', { className: 'data-table' },
              h('thead', {}, h('tr', {},
                h('th', {}, 'Vuln ID'), h('th', {}, 'Sev'),
                h('th', {}, 'Status A'), h('th', {}, 'Status B'), h('th', {}, 'Title'),
              )),
              h('tbody', {}, ...diffRows),
            ),
          )
        : h('p', { style: 'color: var(--green); font-weight: 600; padding: 20px; text-align: center' }, 'No differences found — checklists are identical.'),
      h('div', { className: 'btn-group', style: 'justify-content: flex-end; margin-top: 16px' },
        h('button', { className: 'btn btn-secondary', onClick: () => overlay.remove() }, 'Close'),
      ),
    ),
  );
  document.body.appendChild(overlay);
}

// ---------------------------------------------------------------------------
// Delete Checklist
// ---------------------------------------------------------------------------
async function deleteChecklist(id, hostname) {
  const confirmed = await confirm('Delete Checklist', `Delete the checklist for "${hostname}"? This cannot be undone.`);
  if (!confirmed) return;
  try {
    await api(`/checklists/${id}`, { method: 'DELETE' });
    toast('Checklist deleted', 'success');
    loadChecklists();
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
    nav('checklists');
  } catch (e) {
    toast(`Batch failed: ${e.message}`, 'error');
  }
}

// ---------------------------------------------------------------------------
// Drift Report (Fix #5)
// ---------------------------------------------------------------------------
async function viewDriftReport(checklistId) {
  try {
    const drift = await api(`/agent/drift/${checklistId}`);
    const overlay = h('div', { className: 'modal-overlay' },
      h('div', { className: 'modal', style: 'max-width: 600px' },
        h('h3', {}, 'Drift Report'),
        drift.has_changes === false && !drift.new_open
          ? h('p', {}, drift.message || 'No previous checklist found for comparison.')
          : h('div', {},
              h('div', { className: 'stats-grid', style: 'margin-bottom: 16px' },
                statCard('Compliance Delta', `${drift.compliance_delta >= 0 ? '+' : ''}${drift.compliance_delta?.toFixed(1)}%`,
                  drift.compliance_delta >= 0 ? 'green' : 'red'),
                statCard('New Open', drift.new_open?.length || 0, drift.new_open?.length > 0 ? 'red' : 'green'),
                statCard('Newly Resolved', drift.newly_resolved?.length || 0, 'green'),
              ),
              ...(drift.new_open?.length > 0 ? [
                h('h4', { style: 'margin-bottom: 8px; color: var(--red)' }, 'New Open Findings'),
                ...drift.new_open.map(f => h('div', { style: 'padding: 4px 0; font-size: 0.85rem' }, `${f.vuln_id}: ${f.title}`)),
              ] : []),
              ...(drift.newly_resolved?.length > 0 ? [
                h('h4', { style: 'margin: 12px 0 8px; color: var(--green)' }, 'Newly Resolved'),
                ...drift.newly_resolved.map(f => h('div', { style: 'padding: 4px 0; font-size: 0.85rem' }, `${f.vuln_id}: ${f.title}`)),
              ] : []),
            ),
        h('div', { className: 'btn-group', style: 'justify-content: flex-end; margin-top: 16px' },
          h('button', { className: 'btn btn-secondary', onClick: () => overlay.remove() }, 'Close'),
        ),
      ),
    );
    document.body.appendChild(overlay);
  } catch (e) {
    toast(`Drift report failed: ${e.message}`, 'error');
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
// Init
// ---------------------------------------------------------------------------
loadDashboard();
updateStatusBar();

// AutomateSTIG GUI Application
'use strict';

const API = '/api';
const AUTH_TOKEN = window.__AUTH_TOKEN__ || '';

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
// Loading Helpers
// ---------------------------------------------------------------------------
function showLoading(containerId, msg = 'Loading...') {
  const el = document.getElementById(containerId);
  if (el) {
    el.innerHTML = '';
    el.appendChild(h('div', { className: 'loading-overlay' },
      h('span', { className: 'spinner' }),
      h('span', {}, msg),
    ));
  }
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
      checklists.length ? checklistsTable(checklists) : emptyState(
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
    return h('tr', {},
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
          h('button', { className: 'btn btn-secondary btn-sm', onClick: () => viewChecklist(cl.id) }, 'View'),
          h('button', { className: 'btn btn-secondary btn-sm', onClick: () => exportCkl(cl.id) }, 'CKL'),
          h('button', { className: 'btn btn-primary btn-sm', onClick: () => pushToStigManager(cl.id, cl.hostname) }, 'Push'),
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

    setPage('library',
      h('div', { className: 'page-header' },
        h('h1', {}, 'STIG Library'),
        h('p', {}, `${benchmarks.length} benchmark(s) installed`),
      ),
      benchmarks.length ? h('div', { className: 'card' },
        h('table', { className: 'data-table' },
          h('thead', {},
            h('tr', {},
              h('th', {}, 'Benchmark'),
              h('th', {}, 'Version'),
              h('th', {}, 'Platform'),
              h('th', {}, 'Rules'),
              h('th', {}, ''),
            ),
          ),
          h('tbody', {}, ...rows),
        ),
      ) : emptyState(
        'Library Empty',
        'Import STIG content from DISA or a .stigpack file.',
        h('button', { className: 'btn btn-primary', onClick: () => nav('import') }, 'Import Content'),
      ),
    );
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
    // Add remote scan section.
    const remoteScanSection = await loadRemoteScan();
    const page = document.getElementById('page-evaluate');
    if (remoteScanSection) page.appendChild(remoteScanSection);

  } catch (e) {
    setPage('evaluate', errorCard(e.message));
  }
}

async function runEvaluation() {
  const stigId = document.getElementById('eval-stig')?.value;
  const hostname = document.getElementById('eval-host')?.value;

  if (!stigId) { toast('Select a STIG benchmark', 'error'); return; }
  if (!hostname) { toast('Enter a target hostname', 'error'); return; }

  const btn = document.getElementById('eval-btn');
  btn.textContent = 'Evaluating...';
  btn.disabled = true;

  try {
    const result = await api('/evaluate', {
      method: 'POST',
      body: JSON.stringify({ stig_id: stigId, hostname }),
    });
    toast(`Evaluation complete: ${result.total} rules, ${result.open} open`, 'success');
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
  window.open(`${API}/export/ckl/${id}`, '_blank');
}

function exportCklb(id) {
  window.open(`${API}/export/cklb/${id}`, '_blank');
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
    verify_tls: true,
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

  // Otherwise, fetch collections and let user pick.
  toast('Loading collections from STIG-Manager...', 'info');
  try {
    const collections = await api('/stigman/collections');
    if (!collections || collections.length === 0) {
      toast('No collections found in STIG-Manager', 'error');
      return;
    }

    // Show picker using prompt (simple approach).
    const names = collections.map((c, i) => `${i + 1}. ${c.name}`).join('\n');
    const choice = prompt(`Select a STIG-Manager collection:\n\n${names}\n\nEnter number:`);
    if (!choice) return;

    const idx = parseInt(choice) - 1;
    if (idx < 0 || idx >= collections.length) {
      toast('Invalid selection', 'error');
      return;
    }

    await doPush(checklistId, hostname, collections[idx].collection_id);
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
      h('p', { style: 'color: var(--text-secondary); font-size: 0.9rem' },
        'AutomateSTIG automatically checks for new STIG content from DISA every 24 hours while running. ',
        'New benchmarks are imported automatically when detected.',
      ),
      h('div', { style: 'margin-top: 16px; padding: 16px; background: var(--bg-base); border-radius: var(--radius-sm); display: flex; align-items: center; gap: 12px' },
        h('span', { className: 'status-dot' }),
        h('span', { style: 'font-size: 0.9rem' }, 'Background update checker is active'),
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
  window.open(`${API}/offline-pack`, '_blank');
  setTimeout(() => toast('Offline .stigpack downloaded. Transfer to air-gapped systems via USB/DVD.', 'success'), 2000);
}

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------
loadDashboard();

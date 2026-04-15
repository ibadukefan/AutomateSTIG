// AutomateSTIG GUI Application
'use strict';

const API = '/api';

// ---------------------------------------------------------------------------
// API Client
// ---------------------------------------------------------------------------
async function api(path, opts = {}) {
  const res = await fetch(`${API}${path}`, {
    headers: { 'Content-Type': 'application/json', ...opts.headers },
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
  const res = await fetch(`${API}${path}`, { method: 'POST', body: form });
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
    case 'import': loadImport(); break;
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
          h('button', { className: 'btn btn-secondary btn-sm', onClick: () => exportCklb(cl.id) }, 'CKLB'),
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

    page.appendChild(h('div', { className: 'card' },
      h('div', { className: 'card-header' },
        h('h2', {}, `All Findings (${cl.findings.length})`),
        h('div', { className: 'btn-group' },
          h('button', { className: 'btn btn-secondary btn-sm', onClick: () => exportCkl(id) }, 'Export CKL'),
          h('button', { className: 'btn btn-secondary btn-sm', onClick: () => exportCklb(id) }, 'Export CKLB'),
        ),
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
        h('tbody', {}, ...rows),
      ),
    ));

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
// Init
// ---------------------------------------------------------------------------
loadDashboard();

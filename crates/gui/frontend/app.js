// AutomateSTIG GUI Application
'use strict';

const API = '/api';
// Keep the bearer token in memory only. Desktop mode injects a random
// per-session value; a non-loopback deployment asks the operator for the
// server-configured value instead of publishing that secret in HTML.
let AUTH_TOKEN = typeof window.__AUTH_TOKEN__ === 'string' ? window.__AUTH_TOKEN__ : '';
let applicationStarted = false;
const SUPPORTED_SCANNER_TARGETS = Object.freeze({
  'NetApp_ONTAP_DSC_9-x_STIG': Object.freeze({ platform: 'ontap', inputType: 'transcript', remote: true }),
  General_Purpose_Operating_System: Object.freeze({ platform: 'bsd', inputType: 'transcript', remote: true }),
  'Cisco_IOS-XE_Router_NDM_STIG': Object.freeze({ platform: 'cisco_ios', inputType: 'config', remote: false }),
});

const ASSESSMENT_FLOW_KEY = 'automatestig.assessment-flow';
const STIGMAN_PUSH_IN_FLIGHT = new Set();
const UI_OPERATIONS_IN_FLIGHT = new Set();
const PRIMARY_PAGES = Object.freeze(['assessments', 'assets', 'standards', 'findings', 'settings']);
const PAGE_LABELS = Object.freeze({
  assessments: 'Assessments', assets: 'Assets', standards: 'Standards',
  findings: 'Findings', settings: 'Settings',
});
const FINDINGS_VIEW_STATE = { status: 'all', search: '', page: 1 };
let checklistReturnPage = 'assessments';
let pendingStigManagerPush = null;
let checklistViewVersion = 0;
let currentChecklistId = null;
let currentChecklistRouteKey = null;
let assessmentWorkspaceVersion = 0;

function assessmentFlow() {
  try {
    return JSON.parse(sessionStorage.getItem(ASSESSMENT_FLOW_KEY) || 'null');
  } catch (_) {
    return null;
  }
}

function updateAssessmentFlow(patch) {
  const next = { ...(assessmentFlow() || {}), ...patch, active: true };
  sessionStorage.setItem(ASSESSMENT_FLOW_KEY, JSON.stringify(next));
  return next;
}

function finishAssessmentFlow() {
  sessionStorage.removeItem(ASSESSMENT_FLOW_KEY);
}

function activePageName() {
  return document.querySelector('.nav-item.active')?.dataset?.page || 'assessments';
}

function targetForBenchmark(benchmark) {
  const id = typeof benchmark === 'string'
    ? benchmark
    : (benchmark?.stig_id || benchmark?.id);
  const target = SUPPORTED_SCANNER_TARGETS[id] || null;
  if (target && typeof benchmark === 'object' && benchmark?.scanner_ready === false) return null;
  return target;
}

function normalizePlatform(platform) {
  return platform === 'ciscoios' ? 'cisco_ios' : platform;
}

function isAbsoluteLocalPath(value) {
  const path = String(value || '').trim();
  if (!path || path.startsWith('~')) return false;
  return path.startsWith('/')
    || /^[A-Za-z]:[\\/]/.test(path)
    || /^\\\\[^\\]+\\[^\\]+/.test(path);
}

function normalizeAssetResponse(value) {
  if (Array.isArray(value)) return { assets: value, warnings: [] };
  return {
    assets: Array.isArray(value?.assets) ? value.assets : [],
    warnings: Array.isArray(value?.warnings) ? value.warnings : [],
  };
}

function normalizeChecklistResponse(value) {
  if (Array.isArray(value)) return { checklists: value, warnings: [] };
  return {
    checklists: Array.isArray(value?.checklists) ? value.checklists : [],
    warnings: Array.isArray(value?.warnings) ? value.warnings : [],
  };
}

function normalizeAnswerFileResponse(value) {
  if (Array.isArray(value)) return { files: value, warnings: [] };
  return {
    files: Array.isArray(value?.files) ? value.files : [],
    warnings: Array.isArray(value?.warnings) ? value.warnings : [],
  };
}

function assetWarningsPanel(warnings, includeAction = false) {
  if (!warnings?.length) return null;
  return h('div', { className: 'card inline-status', role: 'alert' },
    h('div', { className: 'card-header' },
      h('h2', {}, 'Some inventory records need migration'),
      h('span', { className: 'mini-pill mini-pill-yellow' }, `${warnings.length} warning${warnings.length === 1 ? '' : 's'}`),
    ),
    h('p', { style: 'color:var(--text-secondary)' },
      'Supported assets remain available below. Incompatible legacy or malformed rows were ignored for safety and preserved in the local asset_inventory record; they were not deleted.'),
    h('ul', { style: 'margin:10px 0 0 20px' }, ...warnings.map(warning => h('li', {}, String(warning)))),
    includeAction ? h('div', { className: 'btn-group', style: 'margin-top:12px' },
      h('button', { className: 'btn btn-secondary btn-sm', onClick: () => addAssetDialog() }, 'Add a supported replacement asset')) : null,
  );
}

function checklistWarningsPanel(warnings) {
  if (!warnings?.length) return null;
  return h('div', { className: 'card inline-status', role: 'alert' },
    h('div', { className: 'card-header' },
      h('h2', {}, 'Some saved results need attention'),
      h('span', { className: 'mini-pill mini-pill-yellow' }, `${warnings.length} warning${warnings.length === 1 ? '' : 's'}`),
    ),
    h('p', { style: 'color:var(--text-secondary)' },
      'Other results remain available. These incompatible or damaged records were not deleted; restore them from an audit/export backup or use a compatible AutomateSTIG version.'),
    h('ul', { style: 'margin:10px 0 0 20px' }, ...warnings.map(warning => h('li', {}, String(warning)))),
  );
}

// ---------------------------------------------------------------------------
// Theme Toggle
// ---------------------------------------------------------------------------
const LIGHT_THEME = {
  '--bg-base': '#f8f9fa', '--bg-surface': '#ffffff', '--bg-elevated': '#f1f3f5',
  '--bg-hover': '#e9ecef', '--bg-active': '#dee2e6', '--border': '#dee2e6',
  '--border-subtle': '#e9ecef', '--text': '#212529', '--text-secondary': '#495057',
  '--text-muted': '#5f6873', '--accent': '#1d4ed8', '--accent-2': '#4338ca',
  '--accent-hover': '#1e40af', '--accent-dim': 'rgba(29,78,216,0.08)',
  '--green': '#15803d', '--green-dim': 'rgba(21,128,61,0.08)',
  '--red': '#b91c1c', '--red-dim': 'rgba(185,28,28,0.08)',
  '--yellow': '#854d0e', '--yellow-dim': 'rgba(133,77,14,0.08)', '--orange': '#c2410c',
};
const DARK_THEME = {
  '--bg-base': '#0a0e14', '--bg-surface': '#11151c', '--bg-elevated': '#1a1f2e',
  '--bg-hover': '#1e2538', '--bg-active': '#252d3f', '--border': '#2a3040',
  '--border-subtle': '#1e2430', '--text': '#e2e8f0', '--text-secondary': '#94a3b8',
  '--text-muted': '#8b9bb0', '--accent': '#3b82f6', '--accent-2': '#6366f1',
  '--accent-hover': '#60a5fa', '--accent-dim': 'rgba(59,130,246,0.12)',
  '--green': '#22c55e', '--green-dim': 'rgba(34,197,94,0.12)',
  '--red': '#ef4444', '--red-dim': 'rgba(239,68,68,0.12)',
  '--yellow': '#eab308', '--yellow-dim': 'rgba(234,179,8,0.12)', '--orange': '#f97316',
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
    const modals = document.querySelectorAll('.modal-overlay');
    const modal = modals[modals.length - 1];
    if (modal?.dataset.requiredAuth === 'true') {
      e.preventDefault();
    } else if (modal) {
      dismissModal(modal, true);
      e.preventDefault();
    }
  }
  // "/" focuses search (if visible and not already in an input).
  if (e.key === '/' && !['INPUT', 'TEXTAREA', 'SELECT'].includes(document.activeElement?.tagName)) {
    const search = document.querySelector('.page.active .search-input:not([disabled])');
    if (search) { search.focus(); e.preventDefault(); }
  }
});

// ---------------------------------------------------------------------------
// API Client
// ---------------------------------------------------------------------------
async function api(path, opts = {}) {
  const { headers = {}, ...requestOpts } = opts;
  const res = await fetch(`${API}${path}`, {
    ...requestOpts,
    headers: {
      'Content-Type': 'application/json',
      'X-Auth-Token': AUTH_TOKEN,
      ...headers,
    },
  });
  return readApiResponse(res, 'API request failed');
}

async function apiUpload(path, file) {
  const form = new FormData();
  form.append('file', file);
  const res = await fetch(`${API}${path}`, {
    method: 'POST',
    body: form,
    headers: { 'X-Auth-Token': AUTH_TOKEN },
  });
  return readApiResponse(res, 'Upload failed');
}

async function readApiResponse(res, fallback, promptForAuthentication = true) {
  if (res.status === 401) {
    if (promptForAuthentication) requireAuthentication();
    throw new Error(promptForAuthentication
      ? 'Authentication required. Enter the server access token to continue.'
      : 'The server did not accept that access token.');
  }

  const raw = await res.text();
  let data = null;
  try {
    data = raw ? JSON.parse(raw) : null;
  } catch (_) {
    if (!res.ok && raw.trim()) throw new Error(raw.trim());
    throw new Error(`${fallback} (${res.status}): invalid JSON response`);
  }
  if (!res.ok || !data?.success) {
    throw new Error(data?.error || raw.trim() || `${fallback} (${res.status})`);
  }
  return data.data;
}

async function downloadAuthed(path, fallbackName) {
  try {
    const res = await fetch(`${API}${path}`, { headers: { 'X-Auth-Token': AUTH_TOKEN } });
    if (!res.ok) {
      if (res.status === 401) {
        requireAuthentication();
        const error = 'Authentication required. Enter the server access token to continue.';
        toast(error, 'error');
        return { ok: false, error };
      }
      const detail = (await res.text()).trim();
      const error = detail || `Download failed (${res.status})`;
      toast(error, 'error');
      return { ok: false, error };
    }
    const blob = await res.blob();
    let name = fallbackName;
    const cd = res.headers.get('Content-Disposition');
    const m = cd && cd.match(/filename="?([^";]+)"?/);
    if (m) name = m[1];
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = name; document.body.appendChild(a); a.click();
    a.remove(); URL.revokeObjectURL(url);
    return { ok: true, name };
  } catch (e) {
    toast(`Download failed: ${e.message}`, 'error');
    return { ok: false, error: e.message };
  }
}

// ---------------------------------------------------------------------------
// Toast Notifications
// ---------------------------------------------------------------------------
function toast(msg, type = 'info') {
  const el = document.createElement('div');
  el.className = `toast ${type}`;
  el.setAttribute('role', type === 'error' ? 'alert' : 'status');
  el.setAttribute('aria-live', type === 'error' ? 'assertive' : 'polite');
  el.setAttribute('aria-atomic', 'true');
  const message = document.createElement('span');
  message.className = 'toast-message';
  message.textContent = msg;
  const close = document.createElement('button');
  close.className = 'toast-close';
  close.type = 'button';
  close.setAttribute('aria-label', 'Dismiss notification');
  close.textContent = '\u00d7';
  el.append(message, close);
  const region = document.getElementById('toasts');
  if (!region) return;
  region.setAttribute('aria-label', 'Notifications');
  region.appendChild(el);

  let timer = null;
  let remaining = 8000;
  let startedAt = 0;
  const dismiss = () => {
    if (timer) clearTimeout(timer);
    el.remove();
  };
  const pause = () => {
    if (!timer) return;
    clearTimeout(timer);
    timer = null;
    remaining = Math.max(0, remaining - (Date.now() - startedAt));
  };
  const resume = () => {
    if (type === 'error' || timer || !el.isConnected) return;
    startedAt = Date.now();
    timer = setTimeout(dismiss, remaining);
  };
  close.addEventListener('click', dismiss);
  el.addEventListener('pointerenter', pause);
  el.addEventListener('pointerleave', resume);
  el.addEventListener('focusin', pause);
  el.addEventListener('focusout', resume);
  resume();
}

function beginUiOperation(key, button = null, busyLabel = 'Working\u2026') {
  if (UI_OPERATIONS_IN_FLIGHT.has(key)) {
    toast('That operation is already in progress.', 'info');
    return null;
  }
  UI_OPERATIONS_IN_FLIGHT.add(key);
  const control = button instanceof HTMLElement ? button : null;
  const original = control ? {
    disabled: control.disabled,
    text: control.textContent,
    ariaBusy: control.getAttribute('aria-busy'),
    ariaLabel: control.getAttribute('aria-label'),
    textOnly: control.childElementCount === 0,
  } : null;
  if (control) {
    control.disabled = true;
    control.dataset.busy = 'true';
    control.setAttribute('aria-busy', 'true');
    if (original.textOnly) control.textContent = busyLabel;
    else {
      control.setAttribute('aria-label', busyLabel);
      original.indicator = h('span', {
        className: 'mini-pill mini-pill-accent operation-busy-label',
      }, busyLabel);
      control.appendChild(original.indicator);
    }
  }
  return () => {
    UI_OPERATIONS_IN_FLIGHT.delete(key);
    if (!control) return;
    control.disabled = original.disabled;
    delete control.dataset.busy;
    if (original.ariaBusy == null) control.removeAttribute('aria-busy');
    else control.setAttribute('aria-busy', original.ariaBusy);
    if (original.ariaLabel == null) control.removeAttribute('aria-label');
    else control.setAttribute('aria-label', original.ariaLabel);
    if (original.textOnly) control.textContent = original.text;
    else original.indicator?.remove();
  };
}

function setOperationStatus(target, message, type = 'info', ...actions) {
  const el = typeof target === 'string' ? document.getElementById(target) : target;
  if (!el) return;
  el.innerHTML = '';
  el.setAttribute('role', type === 'error' ? 'alert' : 'status');
  el.setAttribute('aria-live', type === 'error' ? 'assertive' : 'polite');
  el.style.cssText = [
    'display:block', 'margin-top:16px', 'padding:12px 14px',
    'border:1px solid var(--border)', 'border-radius:var(--radius-sm)',
    `color:var(--${type === 'error' ? 'red' : type === 'success' ? 'green' : type === 'warning' ? 'yellow' : 'text-secondary'})`,
  ].join(';');
  el.appendChild(h('div', {}, message));
  if (actions.length) {
    el.appendChild(h('div', { className: 'btn-group', style: 'margin-top:10px' }, ...actions));
  }
}

function clearOperationStatus(target) {
  const el = typeof target === 'string' ? document.getElementById(target) : target;
  if (!el) return;
  el.innerHTML = '';
  el.removeAttribute('role');
  el.removeAttribute('aria-live');
  el.style.display = 'none';
}

function currentPageOperationStatus(id = 'page-operation-status') {
  const page = document.querySelector('.page.active');
  if (!page) return null;
  let el = page.querySelector(`#${id}`);
  if (!el) {
    el = h('div', { id, className: 'inline-status operation-status', style: 'display:none' });
    const header = page.querySelector('.page-header');
    if (header) header.insertAdjacentElement('afterend', el);
    else page.prepend(el);
  }
  return el;
}

function evaluationIssues(result) {
  const issues = [];
  const add = (value, label = '') => {
    if (Array.isArray(value)) value.forEach(item => add(item, label));
    else if (value && typeof value === 'object') {
      Object.entries(value).forEach(([key, item]) => add(item, key));
    } else if (value != null && String(value).trim()) {
      issues.push(label ? `${label}: ${value}` : String(value));
    }
  };
  add(result?.collection_errors);
  add(result?.evaluation_errors);
  add(result?.evaluation_provenance?.collection_errors);
  return [...new Set(issues)];
}

function setIncompleteEvaluationStatus(target, operation, result) {
  const issues = evaluationIssues(result);
  setOperationStatus(target,
    `${operation} incomplete: ${issues.length || 'one or more'} evaluation issue${issues.length === 1 ? '' : 's'} prevented a checklist from being saved. Correct the inputs and retry.`,
    'error');
  const el = typeof target === 'string' ? document.getElementById(target) : target;
  if (el && issues.length) {
    el.appendChild(h('ul', { style: 'margin:10px 0 0 20px;max-height:180px;overflow:auto' },
      ...issues.slice(0, 8).map(issue => h('li', {}, issue)),
      issues.length > 8 ? h('li', {}, `${issues.length - 8} additional issue(s) not shown.`) : null));
  }
}

let dialogSequence = 0;

function associateFormLabels(root) {
  root.querySelectorAll('.form-group').forEach((group) => {
    const label = group.querySelector('label');
    const control = group.querySelector('input, select, textarea');
    if (!label || !control) return;
    if (!control.id) control.id = `form-control-${++dialogSequence}`;
    label.setAttribute('for', control.id);
    const help = group.querySelector('.field-help');
    if (help) {
      if (!help.id) help.id = `field-help-${++dialogSequence}`;
      const describedBy = new Set((control.getAttribute('aria-describedby') || '').split(/\s+/).filter(Boolean));
      describedBy.add(help.id);
      control.setAttribute('aria-describedby', [...describedBy].join(' '));
    }
  });
}

function isElementInActiveView(element) {
  if (!(element instanceof HTMLElement) || !element.isConnected) return false;
  if ('disabled' in element && element.disabled) return false;
  const page = element.closest('.page');
  return !page || page.classList.contains('active');
}

function dismissModal(overlay, invokeCancel = false, restoreFocus = true) {
  if (!overlay?.isConnected) return;
  const returnFocus = overlay.__returnFocus;
  const cancel = overlay.__onCancel;
  overlay.remove();
  if (invokeCancel && typeof cancel === 'function') cancel();
  if (restoreFocus && isElementInActiveView(returnFocus)) returnFocus.focus();
}

function dismissNonRequiredModalsForNavigation() {
  [...document.querySelectorAll('.modal-overlay')].reverse().forEach((overlay) => {
    if (overlay.dataset.requiredAuth !== 'true') dismissModal(overlay, true, false);
  });
}

function showModal(overlay, { onCancel = null, initialFocus = null } = {}) {
  const dialog = overlay.querySelector('.modal');
  if (!dialog) {
    document.body.appendChild(overlay);
    return overlay;
  }
  const title = dialog.querySelector('h1, h2, h3, h4');
  if (title && !title.id) title.id = `dialog-title-${++dialogSequence}`;
  dialog.setAttribute('role', 'dialog');
  dialog.setAttribute('aria-modal', 'true');
  if (title) dialog.setAttribute('aria-labelledby', title.id);
  overlay.__returnFocus = document.activeElement;
  overlay.__onCancel = onCancel;
  associateFormLabels(dialog);
  overlay.addEventListener('mousedown', (event) => {
    if (event.target === overlay && onCancel) dismissModal(overlay, true);
  });
  dialog.addEventListener('keydown', (event) => {
    if (event.key !== 'Tab') return;
    const focusable = [...dialog.querySelectorAll('button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), a[href], [tabindex]:not([tabindex="-1"])')];
    if (!focusable.length) return;
    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    if (event.shiftKey && document.activeElement === first) { last.focus(); event.preventDefault(); }
    else if (!event.shiftKey && document.activeElement === last) { first.focus(); event.preventDefault(); }
  });
  document.body.appendChild(overlay);
  requestAnimationFrame(() => {
    const focusTarget = initialFocus
      ? dialog.querySelector(initialFocus)
      : dialog.querySelector('input:not([disabled]), select:not([disabled]), textarea:not([disabled]), button:not([disabled]), a[href]');
    focusTarget?.focus();
  });
  return overlay;
}

// ---------------------------------------------------------------------------
// Server Authentication
// ---------------------------------------------------------------------------
function requireAuthentication(message = 'Your access token is missing or no longer valid.') {
  AUTH_TOKEN = '';
  showAuthTokenDialog(message);
}

function isValidServerAuthToken(candidate) {
  return typeof candidate === 'string' && /^[\x21-\x7E]{16,}$/.test(candidate);
}

function showAuthTokenDialog(message = '') {
  const existing = document.querySelector('[data-auth-dialog="true"]');
  if (existing) {
    const status = existing.querySelector('[data-auth-status="true"]');
    if (message && status) setOperationStatus(status, message, 'error');
    existing.querySelector('#server-auth-token')?.focus();
    return existing;
  }

  const input = h('input', {
    className: 'form-input',
    id: 'server-auth-token',
    type: 'password',
    autocomplete: 'off',
    autocapitalize: 'none',
    spellcheck: 'false',
    required: true,
  });
  const connect = h('button', {
    className: 'btn btn-primary',
    type: 'submit',
    disabled: true,
  }, 'Connect');
  const reload = h('button', {
    className: 'btn btn-secondary',
    type: 'button',
    onClick: () => window.location.reload(),
  }, 'Reload Page');
  const status = h('div', {
    className: 'inline-status operation-status',
    style: 'display:none',
    'data-auth-status': 'true',
  });

  let overlay;
  const form = h('form', { onSubmit: async (event) => {
    event.preventDefault();
    const candidate = input.value;
    if (!isValidServerAuthToken(candidate)) {
      input.setAttribute('aria-invalid', 'true');
      setOperationStatus(status, 'Enter at least 16 visible ASCII characters with no spaces, tabs, or line breaks.', 'error');
      return;
    }

    const dialog = overlay.querySelector('.modal');
    dialog?.setAttribute('aria-busy', 'true');
    input.disabled = true;
    connect.disabled = true;
    connect.textContent = 'Connecting…';
    clearOperationStatus(status);
    try {
      const response = await fetch(`${API}/auth/check`, {
        cache: 'no-store',
        headers: { 'X-Auth-Token': candidate },
      });
      await readApiResponse(response, 'Could not verify the access token', false);
      AUTH_TOKEN = candidate;
      input.value = '';
      dismissModal(overlay);
      toast('Server access verified.', 'success');
      startApplication();
    } catch (error) {
      input.setAttribute('aria-invalid', 'true');
      setOperationStatus(status, error.message, 'error');
    } finally {
      dialog?.removeAttribute('aria-busy');
      input.disabled = false;
      connect.disabled = !isValidServerAuthToken(input.value);
      connect.textContent = 'Connect';
      input.focus();
    }
  } },
    h('div', { className: 'form-group' },
      h('label', { className: 'form-label', for: 'server-auth-token' }, 'Server access token'),
      input,
      h('div', { className: 'field-help' },
        'Enter the value configured as AUTOMATESTIG_AUTH_TOKEN on this server. It must contain at least 16 visible ASCII characters with no spaces, tabs, or line breaks. It is kept only in this browser tab’s memory and sent with API requests. Use a TLS-protected deployment.'),
    ),
    h('div', { className: 'btn-group' }, reload, connect),
    status,
  );

  input.addEventListener('input', () => {
    input.removeAttribute('aria-invalid');
    connect.disabled = !isValidServerAuthToken(input.value);
    clearOperationStatus(status);
  });

  overlay = h('div', {
    className: 'modal-overlay',
    'data-required-auth': 'true',
    'data-auth-dialog': 'true',
  },
    h('div', { className: 'modal', style: 'max-width:480px' },
      h('h3', {}, 'Connect to AutomateSTIG'),
      h('p', {}, 'Remote deployments do not publish their configured access token in the page. Ask the server administrator for the token. If this local desktop tab was open when AutomateSTIG restarted, reload the page to receive its new session token.'),
      form,
    ),
  );

  showModal(overlay, { initialFocus: '#server-auth-token' });
  if (message) setOperationStatus(status, message, 'error');
  return overlay;
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
          h('button', { className: 'btn btn-secondary', onClick: () => { dismissModal(overlay); resolve(false); } }, 'Cancel'),
          h('button', { className: 'btn btn-danger', onClick: () => { dismissModal(overlay); resolve(true); } }, 'Confirm'),
        ),
      ),
    );
    showModal(overlay, { onCancel: () => resolve(false) });
  });
}

// ---------------------------------------------------------------------------
// Navigation
// ---------------------------------------------------------------------------
function pageFromLocationHash() {
  let page;
  try {
    page = decodeURIComponent(window.location.hash.slice(1)).toLowerCase();
  } catch (_) {
    return null;
  }
  return PRIMARY_PAGES.includes(page) ? page : null;
}

function checklistFromLocationHash() {
  const raw = window.location.hash.slice(1);
  if (!raw.startsWith('checklist/')) return null;
  const [path, query = ''] = raw.split('?', 2);
  let id;
  try {
    id = decodeURIComponent(path.slice('checklist/'.length));
  } catch (_) {
    return null;
  }
  if (!id) return null;
  const params = new URLSearchParams(query);
  const origin = params.get('from') === 'findings' ? 'findings' : 'assessments';
  const selectedVulnId = params.get('vuln') || '';
  return { id, origin, selectedVulnId };
}

function checklistLocationHash(id, origin, findingView = null) {
  const params = new URLSearchParams({
    from: origin === 'findings' ? 'findings' : 'assessments',
  });
  if (findingView?.selectedVulnId) params.set('vuln', findingView.selectedVulnId);
  return `#checklist/${encodeURIComponent(id)}?${params}`;
}

function announceRoute(page) {
  const label = PAGE_LABELS[page] || page;
  document.title = `AutomateSTIG \u2014 ${label}`;
  const announcer = document.getElementById('route-announcer');
  if (announcer) {
    announcer.textContent = '';
    requestAnimationFrame(() => { announcer.textContent = `${label} page`; });
  }
}

function activatePrimaryPage(page, { updateHistory = true, replaceHistory = false, focusMain = true } = {}) {
  if (!PRIMARY_PAGES.includes(page)) {
    console.warn(`nav: unknown page "${page}"`);
    return false;
  }
  dismissNonRequiredModalsForNavigation();
  checklistViewVersion += 1;
  currentChecklistId = null;
  currentChecklistRouteKey = null;
  document.querySelectorAll('.nav-item').forEach((item) => {
    const selected = item.dataset.page === page;
    item.classList.toggle('active', selected);
    if (selected) item.setAttribute('aria-current', 'page');
    else item.removeAttribute('aria-current');
  });
  document.querySelectorAll('.page').forEach((candidate) => candidate.classList.remove('active'));
  document.getElementById(`page-${page}`)?.classList.add('active');

  const nextHash = `#${page}`;
  if (updateHistory && window.location.hash !== nextHash) {
    if (replaceHistory) window.history.replaceState({ page }, '', nextHash);
    else window.history.pushState({ page }, '', nextHash);
  }
  announceRoute(page);
  loadPage(page);
  if (focusMain) {
    requestAnimationFrame(() => document.getElementById('main')?.focus({ preventScroll: true }));
  }
  return true;
}

document.querySelectorAll('.nav-item').forEach(item => {
  const navLabel = item.querySelector('.nav-label')?.textContent?.trim()
    || item.textContent?.trim()
    || item.dataset.page;
  item.setAttribute('aria-label', navLabel);
  item.setAttribute('title', navLabel);
  item.addEventListener('click', (e) => {
    e.preventDefault();
    activatePrimaryPage(item.dataset.page);
  });
});

document.querySelector('.nav-item.active')?.setAttribute('aria-current', 'page');
window.addEventListener('hashchange', () => {
  if (!applicationStarted) return;
  const checklist = checklistFromLocationHash();
  if (checklist) {
    if (currentChecklistId !== checklist.id
      || currentChecklistRouteKey !== window.location.hash
      || !document.getElementById('page-checklists')?.classList.contains('active')) {
      viewChecklist(
        checklist.id,
        checklist.origin,
        null,
        null,
        checklist.selectedVulnId ? {
          selectedVulnId: checklist.selectedVulnId,
          search: checklist.selectedVulnId,
          status: 'all',
        } : null,
        { updateHistory: false },
      );
    }
    return;
  }
  const page = pageFromLocationHash();
  if (page && (page !== activePageName()
    || document.getElementById('page-checklists')?.classList.contains('active'))) {
    activatePrimaryPage(page, { updateHistory: false, focusMain: true });
  }
});

document.querySelector('.skip-link')?.addEventListener('click', (event) => {
  event.preventDefault();
  const main = document.getElementById('main');
  main?.scrollIntoView({ block: 'start' });
  main?.focus({ preventScroll: true });
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
    else if (k === 'checked' || k === 'disabled' || k === 'selected' || k === 'required' || k === 'multiple') {
      el[k] = Boolean(v);
      if (v) el.setAttribute(k, '');
    } else if (k === 'value' && ['INPUT', 'SELECT', 'TEXTAREA', 'OPTION'].includes(el.tagName)) el.value = v ?? '';
    else if (v != null && v !== false) el.setAttribute(k, v === true ? '' : v);
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

function statusBadge(status, verified = true) {
  const raw = String(status || 'Not Reviewed');
  const key = raw.toLowerCase().replace(/[\s_-]/g, '');
  const label = key === 'open' ? 'Open'
    : key.includes('notafinding') ? 'Not a Finding'
    : key.includes('notapplicable') ? 'Not Applicable'
    : key.includes('notreviewed') ? 'Not Reviewed' : raw.replace(/_/g, ' ');
  const cls = key === 'open' ? 'status-open'
    : key.includes('notafinding') ? (verified ? 'status-naf' : 'status-na')
    : key.includes('notapplicable') ? 'status-na' : 'status-nr';
  return h('span', { className: `status-badge ${cls}` }, label);
}

function findingStatusKey(status) {
  const value = String(status || '').toLowerCase().replace(/[\s_-]/g, '');
  if (value === 'open') return 'open';
  if (value.includes('notafinding')) return 'naf';
  if (value.includes('notapplicable')) return 'na';
  if (value.includes('notreviewed')) return 'nr';
  return 'other';
}

function findingSourceBadge(source) {
  const key = String(source || 'unknown').toLowerCase().replace(/[\s_-]/g, '');
  const info = key.includes('answerfile') ? ['Answer file', 'accent']
    : key.includes('automated') ? ['Automated', 'green']
    : key.includes('manual') ? ['Manual', 'yellow']
    : key.includes('imported') ? ['Imported', 'accent']
    : key.includes('evidence') ? ['Evidence', 'accent']
    : key.includes('collectionerror') ? ['Collection Error', 'red']
    : [String(source || 'Unknown'), 'accent'];
  return h('span', {
    className: `mini-pill mini-pill-${info[1]}`,
    title: 'Finding determination source',
  }, info[0]);
}

function passRateColor(pct) {
  return pct >= 95 ? 'green' : pct >= 80 ? 'yellow' : 'red';
}

function optionalPercent(value) {
  if (value == null || !Number.isFinite(Number(value))) return null;
  return Number(value);
}

function checklistScore(checklist) {
  const total = Math.max(0, Number(checklist?.total) || 0);
  const notReviewed = Math.min(total, Math.max(0, Number(checklist?.not_reviewed) || 0));
  const assessed = total - notReviewed;
  const applicableAssessed = Math.max(0,
    (Number(checklist?.open) || 0) + (Number(checklist?.not_a_finding) || 0));
  // Presence matters: an explicit null marks an unverified score and must not
  // fall through to the deprecated compatibility field or a derived value.
  const hasExplicitPassRate = Object.prototype.hasOwnProperty.call(
    checklist || {},
    'assessed_pass_pct',
  );
  const hasExplicitCoverage = Object.prototype.hasOwnProperty.call(
    checklist || {},
    'benchmark_coverage_pct',
  );
  const assessedPassRate = optionalPercent(
    hasExplicitPassRate ? checklist.assessed_pass_pct : checklist?.compliance_pct,
  );
  const benchmarkCoverage = optionalPercent(
    hasExplicitCoverage
      ? checklist.benchmark_coverage_pct
      : (total > 0 ? assessed / total * 100 : null),
  );
  const provenance = checklist?.evaluation_provenance;
  const origin = checklist?.evaluation_origin ?? provenance?.origin ?? null;
  const collectionComplete = checklist?.collection_complete
    ?? provenance?.collection_complete
    ?? null;
  const unverified = origin === 'imported_checklist'
    || collectionComplete === false
    || provenance?.unsafe_legacy_evidence === true;
  // A verified all-NotApplicable result has no pass-rate denominator. Its
  // null pass rate means N/A, while its benchmark coverage remains valid.
  const passRateAvailable = assessedPassRate != null || applicableAssessed === 0;
  const defensible = !unverified
    && passRateAvailable
    && benchmarkCoverage != null;

  return {
    total,
    assessed,
    applicableAssessed,
    assessedPassRate: defensible ? assessedPassRate : null,
    benchmarkCoverage: defensible ? benchmarkCoverage : null,
    defensible,
  };
}

function scoreColor(score) {
  if (!score.defensible || score.assessedPassRate == null) return '';
  if (score.applicableAssessed === 0) return '';
  if (score.assessedPassRate < 80) return 'red';
  // A perfect result on a partial assessment is still incomplete, not green.
  if (score.benchmarkCoverage < 100) return 'yellow';
  return passRateColor(score.assessedPassRate);
}

function coverageColor(score) {
  if (!score.defensible || score.benchmarkCoverage == null) return '';
  return score.benchmarkCoverage < 100 ? 'yellow' : 'green';
}

function formatScorePct(value) {
  return value == null ? 'Unavailable' : `${value.toFixed(1)}%`;
}

function formatAssessedPassRate(score, compact = false) {
  if (!score?.defensible) return 'Unavailable';
  if (score.applicableAssessed === 0) {
    return compact ? 'N/A' : 'N/A — no applicable controls';
  }
  if (score.assessedPassRate == null) return 'Unavailable';
  return formatScorePct(score.assessedPassRate);
}

function setPage(id, ...children) {
  const page = document.getElementById(`page-${id}`);
  page.innerHTML = '';
  children.filter(child => child instanceof Node).forEach(child => page.appendChild(child));
  associateFormLabels(page);
}

function focusPageHeading(pageId) {
  requestAnimationFrame(() => {
    const page = document.getElementById(`page-${pageId}`);
    if (!page?.classList.contains('active')) return;
    const heading = page?.querySelector('h1');
    if (!heading) {
      document.getElementById('main')?.focus({ preventScroll: true });
      return;
    }
    heading.setAttribute('tabindex', '-1');
    heading.addEventListener('blur', () => heading.removeAttribute('tabindex'), { once: true });
    heading.focus({ preventScroll: true });
  });
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

function errorCard(msg, retry = null) {
  return h('div', { className: 'card inline-status', role: 'alert' },
    h('h2', {}, 'This view could not be loaded'),
    h('p', { style: 'color: var(--red);margin-top:8px' }, msg),
    retry ? h('button', {
      className: 'btn btn-secondary btn-sm',
      style: 'margin-top:12px',
      onClick: retry,
    }, 'Retry') : null,
  );
}

function nav(page) {
  activatePrimaryPage(page);
}

function returnFromChecklist(page) {
  if (window.history.state?.route === 'checklist'
    && window.history.state?.sourcePage === page
    && window.history.state?.backReturnsToSource === true) {
    window.history.back();
  } else {
    activatePrimaryPage(page, { replaceHistory: true });
  }
}

// ---------------------------------------------------------------------------
// Checklist Detail View
// ---------------------------------------------------------------------------
async function viewChecklist(
  id,
  origin = activePageName(),
  notice = null,
  identity = null,
  findingView = null,
  options = {},
) {
  dismissNonRequiredModalsForNavigation();
  const returnPage = origin === 'findings' ? 'findings' : 'assessments';
  const requestVersion = ++checklistViewVersion;
  currentChecklistId = null;
  currentChecklistRouteKey = null;
  const detailHash = checklistLocationHash(id, returnPage, findingView);
  if (options.updateHistory !== false && window.location.hash !== detailHash) {
    const backReturnsToSource = window.location.hash === `#${returnPage}`;
    window.history.pushState({
      route: 'checklist',
      sourcePage: returnPage,
      checklistId: id,
      backReturnsToSource,
    }, '', detailHash);
  }
  document.querySelectorAll('.nav-item').forEach((item) => {
    const selected = item.dataset.page === returnPage;
    item.classList.toggle('active', selected);
    if (selected) item.setAttribute('aria-current', 'page');
    else item.removeAttribute('aria-current');
  });
  document.querySelectorAll('.page').forEach(page => page.classList.remove('active'));
  document.getElementById('page-checklists')?.classList.add('active');
  setPage('checklists', loadingState());
  document.title = 'AutomateSTIG \u2014 Loading checklist';
  if (options.focusMain !== false) {
    requestAnimationFrame(() => document.getElementById('main')?.focus({ preventScroll: true }));
  }
  try {
    const cl = await api(`/checklists/${id}`);
    if (requestVersion !== checklistViewVersion) return;
    checklistReturnPage = returnPage;
    currentChecklistId = id;
    currentChecklistRouteKey = detailHash;
    const page = document.getElementById('page-checklists');
    page.innerHTML = '';

    const score = checklistScore(cl);

    page.appendChild(h('div', { className: 'page-header' },
      h('div', { style: 'display: flex; align-items: center; gap: 12px; margin-bottom: 4px' },
        h('button', { className: 'btn btn-secondary btn-sm', onClick: () => returnFromChecklist(returnPage) }, `\u2190 Back to ${returnPage === 'findings' ? 'Findings' : 'Assessments'}`),
        h('h1', {}, `${identity?.displayName || cl.hostname}`),
      ),
      h('p', {}, `${cl.stig_title} (${cl.stig_version})`,
        identity?.verifiedEndpoint ? ` • Verified endpoint: ${identity.verifiedEndpoint}` : ''),
    ));

    if (notice) {
      page.appendChild(h('div', { className: 'card inline-status', role: 'alert' },
        h('div', { className: 'card-header' }, h('h2', {}, 'Assessment saved; inventory needs attention')),
        h('p', {}, notice),
        h('p', { className: 'field-help', style: 'margin-top:8px' },
          'The checklist below is already saved. Do not rerun solely for this inventory warning; review or update the linked asset instead.'),
      ));
    }

    if (!score.defensible) {
      page.appendChild(h('div', { className: 'card' },
        h('div', { className: 'card-header' },
          h('h2', {}, 'Unverified assessment results'),
          h('span', { className: 'mini-pill mini-pill-accent' }, 'Unverified'),
        ),
        h('p', { style: 'color: var(--text-secondary)' },
          'Pass-rate and coverage grades are unavailable because these results were imported or do not have complete, verified collection provenance.'),
      ));
    }

    const provenance = cl.evaluation_provenance || {};
    const answerProvenance = Array.isArray(provenance.answer_files)
      ? [...provenance.answer_files]
      : [];
    if (provenance.answer_file
      && !answerProvenance.some(answer => answer.id === provenance.answer_file.id
        && answer.sha256 === provenance.answer_file.sha256)) {
      answerProvenance.unshift(provenance.answer_file);
    }
    if (answerProvenance.length) {
      page.appendChild(h('div', { className: 'card inline-status' },
        h('div', { className: 'card-header' },
          h('h2', {}, `Applied answer file${answerProvenance.length === 1 ? '' : 's'}`),
          findingSourceBadge('AnswerFile'),
        ),
        ...answerProvenance.map(answer => h('div', { style: 'margin-top:8px' },
          h('p', {}, h('strong', {}, 'Template: '), h('code', {}, answer.id || 'Unknown template')),
          h('p', { className: 'field-help', style: 'margin-top:4px' },
            'Bound SHA-256: ', h('code', { style: 'word-break:break-all;user-select:all' }, answer.sha256 || 'Unavailable')),
        )),
      ));
    }

    page.appendChild(h('div', { className: 'stats-grid' },
      statCard('Total Rules', cl.total, ''),
      statCard('Open', cl.open, cl.open > 0 ? 'red' : (score.defensible ? 'green' : '')),
      statCard('Not a Finding', cl.not_a_finding, score.defensible ? 'green' : ''),
      statCard('Not Applicable', cl.not_applicable, ''),
      statCard('Not Reviewed', cl.not_reviewed, cl.not_reviewed > 0 ? 'yellow' : ''),
      statCard('Assessed Controls', `${score.assessed}/${score.total}`, coverageColor(score)),
      statCard('Assessed Pass Rate', formatAssessedPassRate(score), scoreColor(score)),
      statCard('Benchmark Coverage', formatScorePct(score.benchmarkCoverage), coverageColor(score)),
    ));

    // Severity breakdown
    if (cl.open > 0) {
      page.appendChild(h('div', { className: 'stats-grid', style: 'margin-bottom: 16px' },
        statCard('CAT I Open', cl.cat_i_open, cl.cat_i_open > 0 ? 'red' : (score.defensible ? 'green' : '')),
        statCard('CAT II Open', cl.cat_ii_open, cl.cat_ii_open > 0 ? 'yellow' : (score.defensible ? 'green' : '')),
        statCard('CAT III Open', cl.cat_iii_open, cl.cat_iii_open > 0 ? 'yellow' : (score.defensible ? 'green' : '')),
      ));
    }

    // Findings table
    // Search and filter bar for findings.
    const selectedVulnId = String(findingView?.selectedVulnId || '');
    let currentFilter = ['all', 'open', 'naf', 'na', 'nr'].includes(findingView?.status)
      ? findingView.status
      : 'all';
    let currentSearch = String(findingView?.search ?? selectedVulnId);

    function renderFindings() {
      const filtered = cl.findings.filter(f => {
        if (currentFilter !== 'all' && findingStatusKey(f.status) !== currentFilter) return false;
        if (currentSearch) {
          const q = currentSearch.toLowerCase();
          return String(f.vuln_id || '').toLowerCase().includes(q)
            || String(f.title || '').toLowerCase().includes(q)
            || String(f.finding_details || '').toLowerCase().includes(q)
            || String(f.source || '').toLowerCase().includes(q);
        }
        return true;
      });
      const tbody = document.getElementById('findings-tbody');
      if (!tbody) return;
      tbody.innerHTML = '';
      filtered.forEach(f => {
        const openEditor = () => editFinding(id, f, {
          identity,
          status: currentFilter,
          search: currentSearch,
          selectedVulnId: f.vuln_id,
        });
        const selected = selectedVulnId && f.vuln_id === selectedVulnId;
        const tr = h('tr', {
          className: selected ? 'selected-finding-row' : '',
          'data-vuln-id': f.vuln_id,
          'aria-current': selected ? 'true' : null,
        },
          h('td', { className: 'mono' }, h('button', {
            className: 'table-link',
            'aria-label': `Edit ${f.vuln_id}: ${f.title}`,
            onClick: openEditor,
          }, f.vuln_id)),
          h('td', {}, sevBadge(f.severity)),
          h('td', {}, statusBadge(f.status, score.defensible)),
          h('td', {}, findingSourceBadge(f.source)),
          h('td', { style: 'max-width: 400px' }, f.title),
          h('td', { style: 'font-size: 0.8rem; color: var(--text-muted); max-width: 300px' },
            String(f.finding_details || '').substring(0, 120) || '\u2014'),
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
          h('button', {
            className: 'btn btn-secondary btn-sm',
            disabled: STIGMAN_PUSH_IN_FLIGHT.has(String(id)),
            'aria-busy': STIGMAN_PUSH_IN_FLIGHT.has(String(id)) ? 'true' : null,
            'data-stigman-push-checklist': String(id),
            onClick: () => pushToStigManager(id, cl.hostname),
          }, STIGMAN_PUSH_IN_FLIGHT.has(String(id)) ? 'Push in progress…' : 'Push to STIG-Manager'),
          h('button', { className: 'btn btn-danger btn-sm', onClick: (event) => deleteChecklist(id, cl.hostname, event.currentTarget) }, 'Delete'),
        ),
      ),
      h('div', { className: 'search-bar' },
        h('input', {
          className: 'search-input', type: 'text', placeholder: 'Search Vuln ID, title, details, or source...',
          'aria-label': 'Search checklist findings',
          value: currentSearch,
          onInput: (e) => { currentSearch = e.target.value; renderFindings(); },
        }),
      ),
      h('div', { className: 'filter-bar status-filters', role: 'group', 'aria-label': 'Filter findings by status' },
        ...['all', 'open', 'naf', 'na', 'nr'].map(f => {
          const labels = { all: 'All', open: 'Open', naf: 'Not a Finding', na: 'N/A', nr: 'Not Reviewed' };
          const selected = f === currentFilter;
          const cls = selected ? (f === 'open' ? 'active-red' : f === 'naf' ? 'active-green' : 'active') : '';
          return h('button', {
            className: `filter-pill ${cls}`,
            onClick: (e) => {
              currentFilter = f;
              e.currentTarget.parentElement.querySelectorAll('.filter-pill').forEach(p => p.className = 'filter-pill');
              e.currentTarget.className = `filter-pill ${f === 'open' ? 'active-red' : f === 'naf' ? 'active-green' : 'active'}`;
              e.currentTarget.parentElement.querySelectorAll('.filter-pill').forEach(p => p.setAttribute('aria-pressed', String(p === e.currentTarget)));
              renderFindings();
            },
            'aria-pressed': String(selected),
          }, labels[f]);
        }),
      ),
      h('div', { className: 'table-scroll', tabindex: '0', role: 'region', 'aria-label': 'Checklist findings table' },
      h('table', { className: 'data-table' },
        h('thead', {},
          h('tr', {},
            h('th', {}, 'Vuln ID'),
            h('th', {}, 'Severity'),
            h('th', {}, 'Status'),
            h('th', {}, 'Source'),
            h('th', {}, 'Title'),
            h('th', {}, 'Details'),
          ),
        ),
        h('tbody', { id: 'findings-tbody' }),
      ),
      ),
    ));

    // Initial render of findings.
    renderFindings();

    // Show checklists page
    document.querySelectorAll('.nav-item').forEach((n) => { n.classList.remove('active'); n.removeAttribute('aria-current'); });
    const activeNav = document.querySelector(`[data-page="${returnPage}"]`);
    activeNav?.classList.add('active');
    activeNav?.setAttribute('aria-current', 'page');
    document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
    page.classList.add('active');
    document.title = `AutomateSTIG \u2014 ${identity?.displayName || cl.hostname}`;
    const announcer = document.getElementById('route-announcer');
    if (announcer) announcer.textContent = `Checklist for ${identity?.displayName || cl.hostname}`;
    requestAnimationFrame(() => {
      const selectedRow = [...page.querySelectorAll('[data-vuln-id]')]
        .find(row => row.dataset.vulnId === selectedVulnId);
      const focusTarget = selectedRow?.querySelector('button') || document.getElementById('main');
      focusTarget?.focus({ preventScroll: Boolean(selectedRow) });
      selectedRow?.scrollIntoView({ behavior: 'smooth', block: 'center' });
    });
  } catch (e) {
    if (requestVersion !== checklistViewVersion) return;
    currentChecklistId = id;
    currentChecklistRouteKey = detailHash;
    setPage('checklists',
      h('div', { className: 'page-header' },
        h('button', { className: 'btn btn-secondary btn-sm', onClick: () => returnFromChecklist(returnPage) }, `\u2190 Back to ${returnPage === 'findings' ? 'Findings' : 'Assessments'}`),
        h('h1', {}, 'Checklist unavailable')),
      errorCard(e.message, () => viewChecklist(id, returnPage, notice, identity, findingView, {
        updateHistory: false,
      })),
    );
    document.title = 'AutomateSTIG \u2014 Checklist unavailable';
    const announcer = document.getElementById('route-announcer');
    if (announcer) announcer.textContent = 'Checklist unavailable';
    focusPageHeading('checklists');
    toast(e.message, 'error');
  }
}

// ---------------------------------------------------------------------------
// Evaluate Workspace
// ---------------------------------------------------------------------------
async function renderEvaluateWorkspace(workspaceVersion = ++assessmentWorkspaceVersion) {
  if (workspaceVersion !== assessmentWorkspaceVersion) return;
  const container = document.getElementById('evaluate-workspace');
  if (!container) return;
  container.innerHTML = '';

  try {
    let answerFileLoadError = null;
    const [benchmarks, assetResponse, answerFileResponse] = await Promise.all([
      api('/library/benchmarks'),
      api('/assets'),
      api('/answer-files').catch((error) => {
        answerFileLoadError = error;
        return { files: [], warnings: [] };
      }),
    ]);
    if (workspaceVersion !== assessmentWorkspaceVersion
      || container !== document.getElementById('evaluate-workspace')) return;
    const { assets } = normalizeAssetResponse(assetResponse);
    const { files: answerFiles, warnings: answerFileWarnings } = normalizeAnswerFileResponse(answerFileResponse);
    const supportedBenchmarks = benchmarks.filter(targetForBenchmark);
    const supportedAssets = assets.filter(a => a.enabled !== false
      && ['ontap', 'bsd', 'cisco_ios'].includes(normalizePlatform(a.platform)));
    const flow = assessmentFlow();
    const selectedBenchmark = supportedBenchmarks.some(b => b.id === flow?.benchmarkId)
      ? flow.benchmarkId : '';
    const setupProgress = [
      ['standard', '1. Standard'],
      ['asset', '2. Compatible asset'],
      ['collection', '3. Collect and evaluate'],
      ['review', '4. Review results'],
    ];
    const progressItems = setupProgress.map(([, label]) => h('li', { className: 'setup-step' }, label));
    const setAssessmentProgress = (step) => {
      const currentIndex = Math.max(0, setupProgress.findIndex(([key]) => key === step));
      progressItems.forEach((item, index) => {
        item.className = `setup-step ${index < currentIndex ? 'setup-step-complete' : index === currentIndex ? 'setup-step-current' : ''}`.trim();
        if (index === currentIndex) item.setAttribute('aria-current', 'step');
        else item.removeAttribute('aria-current');
      });
    };
    setAssessmentProgress(flow?.step || (selectedBenchmark ? 'asset' : 'standard'));

    const workspace = h('div', { className: 'card setup-panel', style: 'max-width: 760px' },
      h('div', { className: 'card-header' },
        h('div', {},
          h('h2', {}, 'Run a new assessment'),
          h('p', { style: 'color:var(--text-secondary);margin-top:4px' },
            'Choose a standard, a compatible asset, and a collection method. Impossible combinations are filtered before you run.'),
        ),
        flow?.active ? h('button', { className: 'btn btn-secondary btn-sm', onClick: () => {
          finishAssessmentFlow();
          loadAssessments();
        } }, 'Cancel setup') : null,
      ),
      h('ol', { className: 'setup-steps', 'aria-label': 'Assessment setup progress' },
        ...progressItems,
      ),
      h('div', { className: 'form-group' },
        h('label', { className: 'form-label', for: 'eval-stig' }, '1. STIG standard'),
        supportedBenchmarks.length
          ? h('select', { className: 'form-select', id: 'eval-stig' },
              h('option', { value: '' }, 'Select a benchmark...'),
              ...supportedBenchmarks.map(b => h('option', {
                value: b.id,
                selected: b.id === selectedBenchmark,
              }, `${b.title || b.id} (${b.rule_count} rules)`)),
            )
          : h('div', { className: 'inline-status', role: 'status' },
              h('p', {}, 'No supported scanner standards are installed. Install DISA XCCDF content before configuring an assessment.'),
              h('button', { className: 'btn btn-primary', onClick: () => {
                updateAssessmentFlow({ origin: 'assessments', step: 'standard' });
                nav('standards');
              } }, 'Install a standard'),
            ),
      ),
      h('div', { className: 'form-group' },
        h('label', { className: 'form-label', for: 'eval-asset' }, '2. Compatible asset'),
        h('select', { className: 'form-select', id: 'eval-asset', disabled: !supportedBenchmarks.length },
          h('option', { value: '' }, selectedBenchmark ? 'Manual hostname (no inventory link)…' : 'Select a standard first…'),
        ),
        h('div', { className: 'field-help', id: 'eval-asset-help' },
          'Only assets matching the selected standard’s platform are shown. You can also assess a hostname without linking inventory.'),
        h('button', { className: 'btn btn-secondary btn-sm', type: 'button', style: 'margin-top:8px', onClick: () => {
          updateAssessmentFlow({ origin: 'assessments', step: 'asset', benchmarkId: workspace.querySelector('#eval-stig')?.value || null });
          nav('assets');
        } }, 'Add an asset'),
      ),
      h('div', { className: 'form-group' },
        h('label', { className: 'form-label', for: 'eval-host' }, 'Target hostname'),
        h('input', { className: 'form-input', id: 'eval-host', type: 'text', autocomplete: 'off', placeholder: 'e.g. device01.example.mil', disabled: !supportedBenchmarks.length }),
        h('div', { className: 'field-help' }, 'Must match the hostname claimed by uploaded evidence and the linked asset name.'),
      ),
      h('div', { className: 'form-group' },
        h('label', { className: 'form-label', for: 'eval-platform' }, 'Target platform'),
        h('select', { className: 'form-select', id: 'eval-platform', disabled: true },
          h('option', { value: '' }, 'Selected from the standard'),
          h('option', { value: 'ontap' }, 'NetApp ONTAP'),
          h('option', { value: 'bsd' }, 'FreeBSD'),
          h('option', { value: 'cisco_ios' }, 'Cisco IOS-XE Router NDM')),
      ),
      h('div', { className: 'form-group' },
        h('label', { className: 'form-label', for: 'eval-answer-file' }, 'Answer file (optional)'),
        h('select', { className: 'form-select', id: 'eval-answer-file', disabled: !supportedBenchmarks.length },
          h('option', { value: '' }, 'Do not apply an answer file'),
        ),
        h('div', { className: 'field-help' },
          'An answer file pre-populates approved finding statuses. Files targeting another STIG are filtered out. Review applied answers in the result.'),
        answerFileWarnings.length ? h('div', { className: 'field-error', role: 'alert' },
          `${answerFileWarnings.length} installed answer file${answerFileWarnings.length === 1 ? '' : 's'} could not be loaded. Open Settings → Answer Files for details.`) : null,
        answerFileLoadError ? h('div', { className: 'field-error', role: 'alert' },
          `Answer-file policy availability could not be checked: ${answerFileLoadError.message}. Retry this page before running if your site requires an answer policy.`) : null,
      ),
      h('fieldset', { style: 'border:0;padding:0;margin:0' },
        h('legend', { style: 'font-weight:600;margin-bottom:12px' }, '3A. Upload collected evidence'),
      h('div', { className: 'form-group' },
        h('label', { className: 'form-label', for: 'eval-evidence' }, 'Device evidence (required)'),
        h('input', {
          className: 'form-input',
          id: 'eval-evidence',
          type: 'file',
          accept: '.json,application/json',
          disabled: !supportedBenchmarks.length,
        }),
        h('div', { className: 'field-help', id: 'eval-evidence-help' },
          'ONTAP and FreeBSD require a UTF-8 JSON evidence transcript produced by the matching collector. Cisco requires an operator-captured UTF-8 running configuration.'),
      ),
      h('div', {
        className: 'form-group',
        id: 'eval-policy-group',
        style: 'display:none',
      },
        h('label', { className: 'form-label', for: 'eval-policy' }, 'Signed organization policy (Cisco required)'),
        h('input', {
          className: 'form-input',
          id: 'eval-policy',
          type: 'file',
          accept: '.json,application/json',
        }),
        h('div', { className: 'field-help' },
          'This JSON policy records organization-approved settings for rules that cannot be proven from device configuration alone. It must match this STIG release and hostname.'),
      ),
      h('div', {
        className: 'form-group',
        id: 'eval-policy-signature-group',
        style: 'display:none',
      },
        h('label', { className: 'form-label', for: 'eval-policy-signature' }, 'Detached policy signature (Cisco required)'),
        h('input', {
          className: 'form-input',
          id: 'eval-policy-signature',
          type: 'file',
          accept: '.sig,application/octet-stream',
        }),
        h('div', { className: 'field-help' },
          'Upload the 64-byte detached Ed25519 signature. The signer’s public key must already be installed in the organization-policy trust directory.'),
      ),
      h('button', { className: 'btn btn-primary', id: 'eval-btn', disabled: true, onClick: runEvaluation },
        'Run Evaluation',
      ),
      h('div', { id: 'eval-operation-status', className: 'inline-status operation-status', style: 'display:none' }),
      ),
    );
    container.appendChild(workspace);
    associateFormLabels(workspace);
    const workspaceControl = id => workspace.querySelector(`#${id}`);

    const stigSelect = workspaceControl('eval-stig');
    const assetSelect = workspaceControl('eval-asset');
    const hostInput = workspaceControl('eval-host');
    const answerSelect = workspaceControl('eval-answer-file');

    function updateEvaluationForm() {
      const stigId = stigSelect?.value || '';
      const target = targetForBenchmark(stigId);
      const compatibleAssets = supportedAssets.filter(a => normalizePlatform(a.platform) === target?.platform);
      const previousAsset = assetSelect?.value || assessmentFlow()?.assetId || '';
      if (assetSelect) {
        assetSelect.innerHTML = '';
        assetSelect.appendChild(h('option', { value: '' }, target
          ? (compatibleAssets.length ? 'Manual hostname (no inventory link)…' : 'No matching inventory assets — use manual hostname…')
          : 'Select a standard first…'));
        compatibleAssets.forEach(a => assetSelect.appendChild(h('option', {
          value: a.id,
          'data-platform': normalizePlatform(a.platform),
        }, `${a.name} (${a.address})`)));
        assetSelect.disabled = !target;
        if (compatibleAssets.some(a => a.id === previousAsset)) {
          assetSelect.value = previousAsset;
          const selectedAsset = compatibleAssets.find(asset => asset.id === previousAsset);
          if (hostInput && selectedAsset) { hostInput.value = selectedAsset.name; hostInput.readOnly = true; }
        } else if (previousAsset && hostInput) {
          hostInput.value = '';
          hostInput.readOnly = false;
          updateAssessmentFlow({ assetId: null, step: 'asset' });
        } else if (hostInput) {
          hostInput.readOnly = false;
        }
      }
      const platform = workspaceControl('eval-platform');
      if (platform) platform.value = target?.platform || '';
      const input = workspaceControl('eval-evidence');
      if (input) {
        input.disabled = !target;
        input.accept = target?.inputType === 'config'
          ? '.txt,.conf,.cfg,.log,text/plain'
          : '.json,application/json';
      }
      const needsPolicy = target?.inputType === 'config';
      const policyGroup = workspaceControl('eval-policy-group');
      const signatureGroup = workspaceControl('eval-policy-signature-group');
      if (policyGroup) policyGroup.style.display = needsPolicy ? '' : 'none';
      if (signatureGroup) signatureGroup.style.display = needsPolicy ? '' : 'none';
      if (hostInput) hostInput.disabled = !target;
      if (answerSelect) {
        const priorAnswer = answerSelect.value;
        answerSelect.innerHTML = '';
        answerSelect.appendChild(h('option', { value: '' }, 'Do not apply an answer file'));
        answerFiles
          .filter(file => !file.invalid && file.id && (!file.stig_id || file.stig_id === stigId))
          .forEach(file => answerSelect.appendChild(h('option', { value: file.id }, `${file.name} (${file.entries} entries)`)));
        answerSelect.disabled = !target;
        if ([...answerSelect.options].some(option => option.value === priorAnswer)) answerSelect.value = priorAnswer;
      }
      if (target) {
        const priorFlow = assessmentFlow();
        const step = priorFlow?.benchmarkId === stigId && priorFlow?.step === 'collection'
          ? 'collection'
          : 'asset';
        updateAssessmentFlow({ benchmarkId: stigId, step });
        setAssessmentProgress(step);
      } else {
        setAssessmentProgress('standard');
      }
      updateEvaluationButton();
    }

    function updateEvaluationButton() {
      const button = workspaceControl('eval-btn');
      if (button && !button.dataset.busy) button.disabled = !evaluationFormReady(workspace);
    }

    stigSelect?.addEventListener('change', () => { clearOperationStatus(workspaceControl('eval-operation-status')); updateEvaluationForm(); });
    assetSelect?.addEventListener('change', () => {
      const asset = supportedAssets.find(a => a.id === assetSelect.value);
      if (hostInput) {
        if (asset) hostInput.value = asset.name;
        hostInput.readOnly = Boolean(asset);
      }
      updateAssessmentFlow({ assetId: asset?.id || null, step: 'collection' });
      setAssessmentProgress('collection');
      updateEvaluationButton();
    });
    [hostInput, workspaceControl('eval-evidence'), workspaceControl('eval-policy'), workspaceControl('eval-policy-signature')]
      .filter(Boolean).forEach(control => {
        control.addEventListener('input', () => {
          if (stigSelect?.value && hostInput?.value.trim()) {
            updateAssessmentFlow({ step: 'collection' });
            setAssessmentProgress('collection');
          }
          updateEvaluationButton();
        });
        control.addEventListener('change', updateEvaluationButton);
      });
    updateEvaluationForm();

    const remoteScanSection = await loadRemoteScan(supportedBenchmarks, answerFiles, supportedAssets);
    if (workspaceVersion !== assessmentWorkspaceVersion
      || container !== document.getElementById('evaluate-workspace')) return;
    if (remoteScanSection) container.appendChild(remoteScanSection);
  } catch (e) {
    if (workspaceVersion !== assessmentWorkspaceVersion
      || container !== document.getElementById('evaluate-workspace')) return;
    container.appendChild(errorCard(e.message, () => renderEvaluateWorkspace()));
  }
}

function evaluationFormReady(root = document) {
  const control = id => root.querySelector(`#${id}`);
  const target = targetForBenchmark(control('eval-stig')?.value);
  const evidence = control('eval-evidence')?.files?.[0];
  const hasPolicy = control('eval-policy')?.files?.[0]
    && control('eval-policy-signature')?.files?.[0];
  return Boolean(target && control('eval-host')?.value.trim() && evidence
    && (target.inputType !== 'config' || hasPolicy));
}

async function runEvaluation() {
  const stigId = document.getElementById('eval-stig')?.value;
  const hostname = document.getElementById('eval-host')?.value;
  const assetSelect = document.getElementById('eval-asset');
  const assetId = assetSelect?.value || null;
  const assetPlatform = assetSelect?.selectedOptions?.[0]?.getAttribute('data-platform') || null;
  const evidenceFile = document.getElementById('eval-evidence')?.files?.[0];
  const policyFile = document.getElementById('eval-policy')?.files?.[0];
  const policySignatureFile = document.getElementById('eval-policy-signature')?.files?.[0];
  const answerFileId = document.getElementById('eval-answer-file')?.value || null;
  const target = targetForBenchmark(stigId);
  const platform = target?.platform;
  const inputType = target?.inputType;

  if (!stigId) { setOperationStatus('eval-operation-status', 'Select a STIG standard first.', 'error'); return; }
  if (!target) { setOperationStatus('eval-operation-status', 'The selected standard is not a supported scanner target.', 'error'); return; }
  if (assetPlatform && assetPlatform !== platform) {
    setOperationStatus('eval-operation-status', 'The selected asset platform does not match this standard. Select one of the filtered compatible assets.', 'error');
    return;
  }
  if (!hostname?.trim()) { setOperationStatus('eval-operation-status', 'Enter the target hostname.', 'error'); return; }
  if (!evidenceFile) { setOperationStatus('eval-operation-status', 'Choose the required device evidence file.', 'error'); return; }
  if (inputType === 'config' && (!policyFile || !policySignatureFile)) {
    setOperationStatus('eval-operation-status', 'Cisco evaluation requires both a signed organization policy and its detached signature.', 'error');
    return;
  }
  if (UI_OPERATIONS_IN_FLIGHT.has('assessment-run')) {
    toast('An assessment is already running.', 'info');
    return;
  }
  UI_OPERATIONS_IN_FLIGHT.add('assessment-run');

  const btn = document.getElementById('eval-btn');
  btn.textContent = 'Evaluating...';
  btn.disabled = true;
  btn.dataset.busy = 'true';
  btn.setAttribute('aria-busy', 'true');
  setOperationStatus('eval-operation-status', `Evaluating ${hostname.trim()}… Keep this page open.`, 'info');

  try {
    const form = new FormData();
    form.append('stig_id', stigId);
    form.append('hostname', hostname);
    form.append('platform', platform);
    form.append('input_type', inputType);
    form.append('evidence', evidenceFile);
    if (inputType === 'config' && policyFile && policySignatureFile) {
      form.append('organization_policy', policyFile);
      form.append('organization_policy_signature', policySignatureFile);
    }
    if (assetId) form.append('asset_id', assetId);
    if (answerFileId) form.append('answer_file_id', answerFileId);
    const res = await fetch(`${API}/evaluate/with-evidence`, {
      method: 'POST', body: form, headers: { 'X-Auth-Token': AUTH_TOKEN },
    });
    const result = await readApiResponse(res, 'Evaluation failed');
    if (result.collection_complete === false) {
      setIncompleteEvaluationStatus('eval-operation-status', 'Evaluation', result);
      document.getElementById('eval-operation-status')?.appendChild(h('div', { className: 'btn-group', style: 'margin-top:10px' },
        h('button', { className: 'btn btn-secondary btn-sm', onClick: () => document.getElementById('eval-evidence')?.focus() }, 'Review evidence')));
    } else {
      const score = checklistScore(result);
      toast(
        `Evaluation complete: ${result.open} open, ${formatAssessedPassRate(score)} assessed pass rate, ${formatScorePct(score.benchmarkCoverage)} benchmark coverage`,
        'success',
      );
      finishAssessmentFlow();
      if (result.id) {
        checklistReturnPage = 'assessments';
        viewChecklist(result.id, 'assessments', result.asset_update_warning || null);
        return;
      }
      setOperationStatus('eval-operation-status', 'Evaluation completed. Open Assessments to review the saved result.', 'success',
        h('button', { className: 'btn btn-primary btn-sm', onClick: loadAssessments }, 'Review assessments'));
    }
  } catch (e) {
    setOperationStatus('eval-operation-status', `Evaluation failed: ${e.message}`, 'error',
      h('button', { className: 'btn btn-secondary btn-sm', onClick: runEvaluation }, 'Retry'));
    toast(e.message, 'error');
  } finally {
    UI_OPERATIONS_IN_FLIGHT.delete('assessment-run');
    btn.textContent = 'Run Evaluation';
    delete btn.dataset.busy;
    btn.removeAttribute('aria-busy');
    btn.disabled = !evaluationFormReady();
  }
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// Finding Editor (inline edit on click)
// ---------------------------------------------------------------------------
function editFinding(checklistId, finding, returnView = null) {
  const statuses = ['NotAFinding', 'Open', 'Not_Applicable', 'Not_Reviewed'];
  const statusLabels = { NotAFinding: 'Not a Finding', Open: 'Open', Not_Applicable: 'Not Applicable', Not_Reviewed: 'Not Reviewed' };
  const currentStatusKey = statuses.find(s =>
    String(finding.status || '').replace(/[\s_-]/g, '').toLowerCase()
      === s.replace(/[\s_-]/g, '').toLowerCase()
  ) || 'Not_Reviewed';

  const overlay = h('div', { className: 'modal-overlay' },
    h('div', { className: 'modal', style: 'max-width: 600px' },
      h('h3', {}, `${finding.vuln_id} — ${finding.title.substring(0, 60)}`),
      h('p', { className: 'field-help', style: 'margin:8px 0 14px' },
        'Determination source: ', findingSourceBadge(finding.source)),
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
        h('button', { className: 'btn btn-secondary', onClick: () => dismissModal(overlay) }, 'Cancel'),
        h('button', { className: 'btn btn-primary', onClick: async (event) => {
          const release = beginUiOperation(
            `finding:${checklistId}:${finding.vuln_id}`,
            event.currentTarget,
            'Saving\u2026',
          );
          if (!release) return;
          const status = document.getElementById('edit-status')?.value;
          const details = document.getElementById('edit-details')?.value;
          const comments = document.getElementById('edit-comments')?.value;

          try {
            await api(`/checklists/${checklistId}/findings/${finding.vuln_id}`, {
              method: 'PATCH',
              body: JSON.stringify({ status, finding_details: details, comments }),
            });
            dismissModal(overlay);
            toast('Finding updated', 'success');
            viewChecklist(checklistId, checklistReturnPage, null, returnView?.identity, returnView, {
              updateHistory: false,
            });
          } catch (e) {
            setOperationStatus('edit-finding-status', `Finding was not saved: ${e.message}`, 'error');
            toast(`Save failed: ${e.message}`, 'error');
          } finally {
            release();
          }
        }}, 'Save'),
      ),
      h('div', { id: 'edit-finding-status', className: 'inline-status operation-status', style: 'display:none' }),
    ),
  );
  showModal(overlay, { initialFocus: '#edit-status' });
}

// ---------------------------------------------------------------------------
// Remote Scan (SSH)
// ---------------------------------------------------------------------------
async function loadRemoteScan(benchmarks = null, answerFiles = [], assets = []) {
  try {
    if (!benchmarks) benchmarks = await api('/library/benchmarks');
    const remoteBenchmarks = benchmarks.filter(b => targetForBenchmark(b)?.remote);
    const section = h('div', { className: 'card setup-panel', style: 'margin-top: 20px;max-width:760px' },
      h('div', { className: 'card-header' }, h('h2', {}, '3B. Collect over SSH and evaluate')),
      h('p', { style: 'color: var(--text-secondary); margin-bottom: 16px; font-size: 0.9rem' },
        'Use this instead of uploading evidence for ONTAP or FreeBSD. Cisco assessment remains config-file-only.',
      ),
      h('div', { className: 'inline-status', style: 'margin-bottom:16px' },
        h('strong', {}, 'Required SSH preparation'),
        h('ul', { style: 'margin:8px 0 0 20px;color:var(--text-secondary)' },
          h('li', {}, 'Add the exact host/IP or CIDR to ', h('code', {}, 'AUTOMATESTIG_SSH_TARGET_ALLOWLIST'), ' when policy requires it; private targets require a matching IP/CIDR.'),
          h('li', {}, 'On the host and account running AutomateSTIG, pre-enroll the host-and-port fingerprint in ', h('code', {}, '~/.automatestig/known_hosts'), '. A changed key is always rejected.'),
          h('li', {}, 'For a deliberate one-host enrollment only, restart with ', h('code', {}, 'AUTOMATESTIG_SSH_TRUST_ON_FIRST_USE=1'), '. Prefer pre-enrollment for high assurance.'),
        ),
      ),
      h('div', { className: 'form-group' },
        h('label', { className: 'form-label', for: 'scan-stig' }, 'STIG standard'),
        remoteBenchmarks.length
          ? h('select', { className: 'form-select', id: 'scan-stig' },
              h('option', { value: '' }, 'Select...'),
              ...remoteBenchmarks.map(b => h('option', {
                value: b.id,
                selected: b.id === assessmentFlow()?.benchmarkId,
              }, `${b.title || b.id} (${b.rule_count} rules)`)))
          : h('div', { className: 'inline-status' },
              h('p', {}, 'No SSH-capable benchmark is installed.'),
              h('button', { className: 'btn btn-secondary btn-sm', onClick: () => nav('standards') }, 'Install a standard')),
      ),
      h('div', { className: 'grid-2' },
        h('div', {},
          h('div', { className: 'form-group' },
            h('label', { className: 'form-label', for: 'scan-asset' }, 'Compatible asset (optional)'),
            h('select', { className: 'form-select', id: 'scan-asset', disabled: true },
              h('option', { value: '' }, 'Select a standard first…')),
            h('div', { className: 'field-help' },
              'Only assets matching the selected standard are shown. Selecting one uses its inventory address and links a completed result; manual host entry remains available.'),
          ),
          h('div', { className: 'form-group' },
            h('label', { className: 'form-label', for: 'scan-host' }, 'Host'),
            h('input', { className: 'form-input', id: 'scan-host', type: 'text', autocomplete: 'off', placeholder: 'host.example.mil', disabled: !remoteBenchmarks.length }),
          ),
          h('div', { className: 'form-group' },
            h('label', { className: 'form-label', for: 'scan-user' }, 'Username'),
            h('input', { className: 'form-input', id: 'scan-user', type: 'text', autocomplete: 'username', placeholder: 'admin', disabled: !remoteBenchmarks.length }),
          ),
          h('div', { className: 'form-group' },
            h('label', { className: 'form-label', for: 'scan-auth-type' }, 'Authentication'),
            h('select', { className: 'form-select', id: 'scan-auth-type', disabled: !remoteBenchmarks.length },
              h('option', { value: 'password' }, 'Password'),
              h('option', { value: 'key_file' }, 'Private key file')),
          ),
          h('div', { className: 'form-group', id: 'scan-password-group' },
            h('label', { className: 'form-label', for: 'scan-pass' }, 'Password'),
            h('input', { className: 'form-input', id: 'scan-pass', type: 'password', autocomplete: 'off', disabled: !remoteBenchmarks.length }),
            h('div', { className: 'field-help' },
              'Submitted for this scan only and not stored.'),
          ),
          h('div', { id: 'scan-key-group', style: 'display:none' },
            h('div', { className: 'form-group' },
              h('label', { className: 'form-label', for: 'scan-key-path' }, 'Private key path'),
              h('input', { className: 'form-input', id: 'scan-key-path', type: 'text', autocomplete: 'off', placeholder: '/Users/operator/.ssh/id_ed25519', disabled: !remoteBenchmarks.length }),
              h('div', { className: 'field-help' },
                'Enter an absolute path on the filesystem of the host running AutomateSTIG (not the browser workstation in a remote deployment). Keys must be under an approved secure key root and pass ownership, permission, size, and symlink checks.'),
            ),
            h('div', { className: 'form-group' },
              h('label', { className: 'form-label', for: 'scan-key-passphrase' }, 'Key passphrase (optional)'),
              h('input', { className: 'form-input', id: 'scan-key-passphrase', type: 'password', autocomplete: 'off', disabled: !remoteBenchmarks.length }),
              h('div', { className: 'field-help' }, 'Used for this scan only and not stored.'),
            ),
          ),
        ),
        h('div', {},
          h('div', { className: 'form-group' },
            h('label', { className: 'form-label', for: 'scan-port' }, 'Port (optional)'),
            h('input', { className: 'form-input', id: 'scan-port', type: 'number', min: '1', max: '65535', placeholder: '22', disabled: !remoteBenchmarks.length }),
          ),
          h('div', { className: 'form-group' },
            h('label', { className: 'form-label', for: 'scan-answer-file' }, 'Answer file (optional)'),
            h('select', { className: 'form-select', id: 'scan-answer-file', disabled: !remoteBenchmarks.length },
              h('option', { value: '' }, 'Do not apply an answer file')),
          ),
        ),
      ),
      h('div', { className: 'form-group', style: 'display:flex;align-items:flex-start;gap:10px' },
        h('input', { id: 'scan-prereqs', type: 'checkbox', disabled: !remoteBenchmarks.length }),
        h('label', { for: 'scan-prereqs', style: 'cursor:pointer' },
          'I confirmed this target is authorized/allowlisted and its SSH host key is already enrolled (or one-shot TOFU was deliberately armed).'),
      ),
      h('button', { className: 'btn btn-primary', id: 'scan-btn', disabled: true, onClick: runRemoteScan }, 'Scan & Evaluate'),
      h('div', { id: 'scan-operation-status', className: 'inline-status operation-status', style: 'display:none' }),
    );
    associateFormLabels(section);

    const stigSelect = section.querySelector('#scan-stig');
    const answerSelect = section.querySelector('#scan-answer-file');
    const assetSelect = section.querySelector('#scan-asset');
    const authType = section.querySelector('#scan-auth-type');
    const updateAuthFields = () => {
      const useKey = authType?.value === 'key_file';
      const passwordGroup = section.querySelector('#scan-password-group');
      const keyGroup = section.querySelector('#scan-key-group');
      if (passwordGroup) passwordGroup.style.display = useKey ? 'none' : '';
      if (keyGroup) keyGroup.style.display = useKey ? '' : 'none';
    };
    const updateAnswers = () => {
      if (!answerSelect) return;
      const prior = answerSelect.value;
      answerSelect.innerHTML = '';
      answerSelect.appendChild(h('option', { value: '' }, 'Do not apply an answer file'));
      answerFiles.filter(file => !file.invalid && file.id && (!file.stig_id || file.stig_id === stigSelect?.value))
        .forEach(file => answerSelect.appendChild(h('option', { value: file.id }, `${file.name} (${file.entries} entries)`)));
      if ([...answerSelect.options].some(option => option.value === prior)) answerSelect.value = prior;
    };
    const updateAssets = () => {
      if (!assetSelect) return;
      const target = targetForBenchmark(stigSelect?.value);
      const previous = assetSelect.value || assessmentFlow()?.assetId || '';
      const compatible = assets.filter(asset => normalizePlatform(asset.platform) === target?.platform && asset.enabled !== false);
      assetSelect.innerHTML = '';
      assetSelect.appendChild(h('option', { value: '' }, target
        ? 'Manual host (no inventory link)…'
        : 'Select a standard first…'));
      compatible.forEach(asset => assetSelect.appendChild(h('option', {
        value: asset.id,
        'data-address': asset.address,
      }, `${asset.name} (${asset.address}:${asset.port || 22})`)));
      assetSelect.disabled = !target;
      if (compatible.some(asset => asset.id === previous)) {
        assetSelect.value = previous;
        const asset = compatible.find(item => item.id === previous);
        const host = section.querySelector('#scan-host');
        const port = section.querySelector('#scan-port');
        if (host && asset) { host.value = asset.address; host.readOnly = true; }
        if (port && asset) { port.value = String(asset.port || 22); port.readOnly = true; }
      } else {
        const host = section.querySelector('#scan-host');
        const port = section.querySelector('#scan-port');
        if (previous) {
          if (host) host.value = '';
          if (port) port.value = '';
        }
        if (host) host.readOnly = false;
        if (port) port.readOnly = false;
      }
    };
    const updateButton = () => {
      const keyPathControl = section.querySelector('#scan-key-path');
      if (authType?.value === 'key_file' && keyPathControl?.value.trim()) {
        keyPathControl.setAttribute('aria-invalid', String(!isAbsoluteLocalPath(keyPathControl.value)));
      } else {
        keyPathControl?.removeAttribute('aria-invalid');
      }
      const ready = remoteBenchmarks.length > 0
        && Boolean(section.querySelector('#scan-host')?.value.trim())
        && Boolean(section.querySelector('#scan-user')?.value.trim())
        && Boolean(targetForBenchmark(stigSelect?.value)?.remote)
        && Boolean(section.querySelector('#scan-prereqs')?.checked)
        && (authType?.value === 'key_file'
          ? isAbsoluteLocalPath(section.querySelector('#scan-key-path')?.value)
          : Boolean(section.querySelector('#scan-pass')?.value))
        && (!section.querySelector('#scan-port')?.value || section.querySelector('#scan-port')?.checkValidity());
      const button = section.querySelector('#scan-btn');
      if (button && !button.dataset.busy) button.disabled = !ready;
    };
    section.querySelectorAll('input, select').forEach(control => {
      control.addEventListener('input', updateButton);
      control.addEventListener('change', updateButton);
    });
    stigSelect?.addEventListener('change', () => {
      if (stigSelect.value) updateAssessmentFlow({ benchmarkId: stigSelect.value, step: 'asset' });
      updateAnswers(); updateAssets();
    });
    assetSelect?.addEventListener('change', () => {
      const selected = assets.find(asset => asset.id === assetSelect.value);
      const host = section.querySelector('#scan-host');
      const port = section.querySelector('#scan-port');
      if (host) {
        if (selected) host.value = selected.address;
        host.readOnly = Boolean(selected);
      }
      if (port) {
        if (selected) port.value = String(selected.port || 22);
        port.readOnly = Boolean(selected);
      }
      updateAssessmentFlow({ assetId: selected?.id || null, step: 'collection' });
      updateButton();
    });
    authType?.addEventListener('change', updateAuthFields);
    updateAuthFields();
    updateAnswers();
    updateAssets();
    updateButton();
    return section;
  } catch (e) {
    return errorCard(e.message, () => renderEvaluateWorkspace());
  }
}

async function runRemoteScan() {
  const host = document.getElementById('scan-host')?.value;
  const user = document.getElementById('scan-user')?.value;
  const pass = document.getElementById('scan-pass')?.value;
  const authType = document.getElementById('scan-auth-type')?.value || 'password';
  const keyPath = document.getElementById('scan-key-path')?.value?.trim();
  const keyPassphrase = document.getElementById('scan-key-passphrase')?.value;
  const stigId = document.getElementById('scan-stig')?.value;
  const target = targetForBenchmark(stigId);
  const platform = target?.platform;
  const port = document.getElementById('scan-port')?.value;
  const prerequisitesConfirmed = document.getElementById('scan-prereqs')?.checked;
  const answerFileId = document.getElementById('scan-answer-file')?.value || null;
  const assetId = document.getElementById('scan-asset')?.value || null;

  if (!host?.trim() || !user?.trim() || !stigId || !target?.remote) {
    setOperationStatus('scan-operation-status', 'Enter a host and username, then select an SSH-capable standard.', 'error');
    return;
  }
  if (!prerequisitesConfirmed) {
    setOperationStatus('scan-operation-status', 'Confirm the target authorization, allowlist, and host-key prerequisites before starting the scan.', 'error');
    return;
  }
  if (authType === 'key_file' ? !isAbsoluteLocalPath(keyPath) : !pass) {
    if (authType === 'key_file') document.getElementById('scan-key-path')?.setAttribute('aria-invalid', 'true');
    setOperationStatus('scan-operation-status', authType === 'key_file'
      ? 'Enter an absolute private-key path on the host running AutomateSTIG (for example /Users/operator/.ssh/id_ed25519, C:\\Users\\operator\\.ssh\\id_ed25519, or a UNC path). Relative paths and ~ are not accepted.'
      : 'Enter the SSH password.', 'error');
    return;
  }
  if (port && !document.getElementById('scan-port')?.checkValidity()) {
    setOperationStatus('scan-operation-status', 'SSH port must be between 1 and 65535.', 'error');
    return;
  }
  if (UI_OPERATIONS_IN_FLIGHT.has('assessment-run')) {
    toast('An assessment is already running.', 'info');
    return;
  }
  UI_OPERATIONS_IN_FLIGHT.add('assessment-run');

  const button = document.getElementById('scan-btn');
  button.disabled = true;
  button.dataset.busy = 'true';
  button.textContent = 'Scanning…';
  button.setAttribute('aria-busy', 'true');
  setOperationStatus('scan-operation-status', `Connecting to ${host.trim()} and evaluating collected evidence… Keep this page open.`, 'info');

  try {
    const result = await api('/scan/ssh', {
      method: 'POST',
      body: JSON.stringify({
        host: host.trim(), username: user.trim(), stig_id: stigId, platform,
        port: port ? parseInt(port) : null,
        auth: authType === 'key_file'
          ? { type: 'key_file', path: keyPath, passphrase: keyPassphrase || null }
          : { type: 'password', password: pass },
        answer_file_id: answerFileId,
        asset_id: assetId,
      }),
    });
    if (result.collection_complete === false) {
      setIncompleteEvaluationStatus('scan-operation-status', 'Scan', result);
      document.getElementById('scan-operation-status')?.appendChild(h('div', { className: 'btn-group', style: 'margin-top:10px' },
        h('button', { className: 'btn btn-secondary btn-sm', onClick: runRemoteScan }, 'Retry scan')));
    } else {
      const score = checklistScore(result);
      toast(
        `Scan complete: ${result.checks_executed} checks, ${formatAssessedPassRate(score)} assessed pass rate, ${formatScorePct(score.benchmarkCoverage)} benchmark coverage`,
        'success',
      );
      finishAssessmentFlow();
      viewChecklist(result.id, 'assessments', result.asset_update_warning || null);
    }
  } catch (e) {
    setOperationStatus('scan-operation-status', `Scan failed: ${e.message}`, 'error',
      h('button', { className: 'btn btn-secondary btn-sm', onClick: runRemoteScan }, 'Retry scan'));
    toast(`Scan failed: ${e.message}`, 'error');
  } finally {
    UI_OPERATIONS_IN_FLIGHT.delete('assessment-run');
    const passwordControl = document.getElementById('scan-pass');
    const passphraseControl = document.getElementById('scan-key-passphrase');
    if (passwordControl) passwordControl.value = '';
    if (passphraseControl) passphraseControl.value = '';
    button.textContent = 'Scan & Evaluate';
    delete button.dataset.busy;
    button.removeAttribute('aria-busy');
    const ready = Boolean(document.getElementById('scan-host')?.value.trim()
      && document.getElementById('scan-user')?.value.trim()
      && targetForBenchmark(document.getElementById('scan-stig')?.value)?.remote
      && document.getElementById('scan-prereqs')?.checked
      && (document.getElementById('scan-auth-type')?.value === 'key_file'
        ? isAbsoluteLocalPath(document.getElementById('scan-key-path')?.value)
        : document.getElementById('scan-pass')?.value)
      && (!document.getElementById('scan-port')?.value || document.getElementById('scan-port')?.checkValidity()));
    button.disabled = !ready;
  }
}

// ---------------------------------------------------------------------------
// Export Helpers
// ---------------------------------------------------------------------------
function exportCkl(id) {
  downloadAuthed(`/export/ckl/${id}`, `${id}.ckl`);
}

function exportCklb(id) {
  downloadAuthed(`/export/cklb/${id}`, `${id}.cklb`);
}

// ---------------------------------------------------------------------------
// Settings Page (STIG-Manager config)
// ---------------------------------------------------------------------------
async function loadSettings() {
  setPage('settings', loadingState());

  let config;
  try {
    config = await api('/stigman/config');
  } catch (e) {
    setPage('settings', errorCard(e.message, loadSettings));
    return;
  }

  setPage('settings',
    h('div', { className: 'page-header' },
      h('h1', {}, 'Settings'),
      h('p', {}, 'Configure integrations and application preferences'),
    ),
    pendingStigManagerPush ? h('div', { className: 'card inline-status', role: 'status' },
      h('div', { className: 'card-header' }, h('h2', {}, 'Finish the pending checklist push')),
      h('p', {}, `Configure and test STIG-Manager, then return to ${pendingStigManagerPush.hostname} without searching for the checklist again.`),
      h('div', { className: 'btn-group', style: 'margin-top:12px' },
        h('button', {
          className: 'btn btn-secondary btn-sm',
          onClick: () => viewChecklist(
            pendingStigManagerPush.checklistId,
            pendingStigManagerPush.origin,
          ),
        }, 'Return to Checklist'),
        h('button', {
          className: 'btn btn-primary btn-sm',
          disabled: !config.configured,
          onClick: resumePendingStigManagerPush,
        }, config.configured ? 'Resume Push' : 'Save Configuration to Resume'),
      ),
    ) : null,
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
            autocomplete: 'off', placeholder: config.has_secret ? '(saved)' : 'Enter secret' }),
        ),
      ),
      h('div', { className: 'form-group' },
        h('label', { className: 'form-label' }, 'Default Collection ID (optional)'),
        h('input', { className: 'form-input', id: 'sm-collection-id', type: 'text',
          placeholder: 'Leave blank to choose each time', value: config.default_collection_id || '' }),
      ),
      h('div', { className: 'form-group', style: 'display: flex; align-items: center; gap: 10px' },
        h('input', { type: 'checkbox', id: 'sm-verify-tls', checked: config.verify_tls !== false }),
        h('label', { for: 'sm-verify-tls', style: 'font-size: 0.9rem; cursor: pointer' },
          'Verify TLS certificates (recommended). Disabling this checkbox takes effect only when the process was deliberately started with AUTOMATESTIG_ALLOW_INVALID_STIGMAN_CERTS=1.'),
      ),
      h('div', { className: 'btn-group', style: 'margin-top: 24px' },
        h('button', { className: 'btn btn-primary', id: 'sm-save-btn', onClick: (event) => saveStigManagerConfig(event.currentTarget) }, 'Save'),
        h('button', { className: 'btn btn-secondary', id: 'sm-test-btn', onClick: testStigManagerConnection }, 'Test These Values'),
        (config.configured || config.has_secret) ? h('button', {
          className: 'btn btn-danger',
          onClick: (event) => clearStigManagerConfig(event.currentTarget),
        }, 'Disconnect and Clear Credentials') : null,
      ),
      h('div', { id: 'sm-save-result', className: 'inline-status operation-status', style: 'display:none;margin-top:12px' }),
      h('div', { className: 'field-help', style: 'margin-top:10px' },
        'Testing uses the values currently shown without saving them. An entered secret remains only in this masked field until you save or leave the page. If it is blank, the saved secret is reused only when the API URL, token URL, and client ID still match.'),
      h('div', { id: 'sm-test-result', role: 'status', 'aria-live': 'polite', style: 'margin-top: 16px' }),
    ),
    h('div', { className: 'card', style: 'max-width: 700px; margin-top: 20px' },
      h('div', { className: 'card-header' },
        h('h2', {}, 'Answer Files'),
      ),
      h('p', { style: 'color: var(--text-secondary); font-size: 0.9rem; margin-bottom: 16px' },
        'Create and manage answer file templates for pre-populating checklist findings.',
      ),
      h('button', { className: 'btn btn-primary', onClick: (event) => openAnswerEditor(event.currentTarget) }, 'Open Answer File Editor'),
    ),
  );
}

async function saveStigManagerConfig(triggerButton = null) {
  const config = currentStigManagerFormConfig();
  const release = beginUiOperation('stigman-config-save', triggerButton, 'Saving\u2026');
  if (!release) return;
  setOperationStatus('sm-save-result', 'Saving STIG-Manager configuration…', 'info');

  try {
    await api('/stigman/config', { method: 'POST', body: JSON.stringify(config) });
    toast('STIG-Manager configuration saved', 'success');
    await Promise.all([loadSettings(), updateStatusBar()]);
    focusPageHeading('settings');
  } catch (e) {
    setOperationStatus('sm-save-result', `Configuration was not saved: ${e.message}`, 'error');
    toast(`Save failed: ${e.message}`, 'error');
  } finally {
    release();
  }
}

async function clearStigManagerConfig(triggerButton = null) {
  const confirmed = await confirmDialog(
    'Disconnect STIG-Manager?',
    'Remove the saved endpoints, client ID, collection, and encrypted client secret from AutomateSTIG? This does not change STIG-Manager itself.',
  );
  if (!confirmed) return;
  const release = beginUiOperation('stigman-config-save', triggerButton, 'Clearing\u2026');
  if (!release) return;
  try {
    await api('/stigman/config', { method: 'DELETE' });
    toast('STIG-Manager credentials cleared', 'success');
    await Promise.all([loadSettings(), updateStatusBar()]);
    focusPageHeading('settings');
  } catch (error) {
    setOperationStatus('sm-save-result', `Credentials were not cleared: ${error.message}`, 'error');
    toast(`Clear failed: ${error.message}`, 'error');
  } finally {
    release();
  }
}

async function resumePendingStigManagerPush() {
  const pending = pendingStigManagerPush;
  if (!pending) return;
  await viewChecklist(pending.checklistId, pending.origin);
  await pushToStigManager(pending.checklistId, pending.hostname);
}

function currentStigManagerFormConfig() {
  return {
    api_url: document.getElementById('sm-api-url')?.value || '',
    token_url: document.getElementById('sm-token-url')?.value || '',
    client_id: document.getElementById('sm-client-id')?.value || '',
    client_secret: document.getElementById('sm-client-secret')?.value || '',
    default_collection_id: document.getElementById('sm-collection-id')?.value || null,
    verify_tls: document.getElementById('sm-verify-tls')?.checked !== false,
  };
}

async function testStigManagerConnection() {
  const el = document.getElementById('sm-test-result');
  const button = document.getElementById('sm-test-btn');
  if (el) el.innerHTML = '<span style="color: var(--text-muted)">Testing connection...</span>';
  if (button) { button.disabled = true; button.textContent = 'Testing…'; }

  try {
    const result = await api('/stigman/test', {
      method: 'POST',
      body: JSON.stringify(currentStigManagerFormConfig()),
    });
    if (!el) return;
    el.textContent = '';
    el.appendChild(h('span', { style: 'color: var(--green); font-weight: 600' }, '\u2713 ' + result + ' These values are not saved yet.'));
    el.appendChild(h('div', { className: 'btn-group', style: 'margin-top:10px' },
      h('button', { className: 'btn btn-primary btn-sm', onClick: (event) => saveStigManagerConfig(event.currentTarget) }, 'Save These Values')));
    toast('STIG-Manager connection successful', 'success');
  } catch (e) {
    if (el) {
      el.textContent = '';
      el.appendChild(h('span', { style: 'color: var(--red); font-weight: 600' }, '\u2717 ' + e.message));
    }
    toast(`Connection failed: ${e.message}`, 'error');
  } finally {
    if (button) { button.disabled = false; button.textContent = 'Test These Values'; }
  }
}

// ---------------------------------------------------------------------------
// Push to STIG-Manager
// ---------------------------------------------------------------------------
function setStigManagerPushBusy(checklistId, busy) {
  const key = String(checklistId);
  document.querySelectorAll('[data-stigman-push-checklist]').forEach(button => {
    if (button.dataset.stigmanPushChecklist !== key) return;
    button.disabled = busy;
    button.textContent = busy ? 'Push in progress…' : 'Push to STIG-Manager';
    if (busy) button.setAttribute('aria-busy', 'true');
    else button.removeAttribute('aria-busy');
  });
}

async function pushToStigManager(checklistId, hostname, preferredCollectionId = null) {
  const pushKey = String(checklistId);
  if (STIGMAN_PUSH_IN_FLIGHT.has(pushKey)) return;
  STIGMAN_PUSH_IN_FLIGHT.add(pushKey);
  setStigManagerPushBusy(pushKey, true);

  const status = currentPageOperationStatus('stigman-push-status');
  let phase = 'configuration';
  let retryCollectionId = preferredCollectionId;
  let failure = null;
  try {
    setOperationStatus(status, 'Checking STIG-Manager configuration…', 'info');
    const config = await api('/stigman/config');
    if (!config.configured) {
      setOperationStatus(status, 'STIG-Manager is not configured. Save and test the integration in Settings before pushing.', 'error');
      toast('STIG-Manager not configured. Go to Settings first.', 'error');
      pendingStigManagerPush = {
        checklistId,
        hostname,
        origin: checklistReturnPage,
      };
      nav('settings');
      return;
    }

    let collectionId = preferredCollectionId || config.default_collection_id;
    if (!collectionId) {
      phase = 'collections';
      toast('Loading collections from STIG-Manager...', 'info');
      setOperationStatus(status, 'Loading STIG-Manager collections…', 'info');
      const collections = await api('/stigman/collections');
      if (!collections || collections.length === 0) {
        setOperationStatus(status, 'No STIG-Manager collections are available for this push.', 'error');
        toast('No collections found in STIG-Manager', 'error');
        return;
      }

      collectionId = await pickCollection(collections);
      if (!collectionId) {
        setOperationStatus(status, 'Push canceled; no collection was changed.', 'info');
        return;
      }
    }

    retryCollectionId = collectionId;
    phase = 'push';
    await doPush(checklistId, hostname, collectionId);
    pendingStigManagerPush = null;
  } catch (error) {
    failure = phase === 'configuration'
      ? {
          message: `STIG-Manager configuration could not be checked: ${error.message}`,
          toast: `STIG-Manager status failed: ${error.message}`,
          label: 'Retry',
        }
      : phase === 'collections'
        ? {
            message: `Collections could not be loaded: ${error.message}`,
            toast: `Failed to list collections: ${error.message}`,
            label: 'Retry',
          }
        : {
            message: `STIG-Manager push needs attention: ${error.message}`,
            toast: `Push failed: ${error.message}`,
            label: 'Retry this push',
          };
  } finally {
    STIGMAN_PUSH_IN_FLIGHT.delete(pushKey);
    setStigManagerPushBusy(pushKey, false);
  }

  // Build Retry only after the entire prior flow has released its UI lock.
  if (failure) {
    setOperationStatus(status, failure.message, 'error',
      h('button', {
        className: 'btn btn-secondary btn-sm',
        onClick: () => pushToStigManager(checklistId, hostname, retryCollectionId),
      }, failure.label));
    toast(failure.toast, 'error');
  }
}

async function doPush(checklistId, hostname, collectionId) {
  const status = currentPageOperationStatus('stigman-push-status');
  toast(`Pushing ${hostname} results to STIG-Manager...`, 'info');
  setOperationStatus(status, `Pushing ${hostname} reviews to STIG-Manager collection ${collectionId}…`, 'info');
  const result = await api(`/stigman/push/${checklistId}`, {
    method: 'POST',
    body: JSON.stringify({ collection_id: collectionId }),
  });
  setOperationStatus(status,
    `Pushed ${result.pushed} review(s) to collection ${collectionId}; remote asset ID ${result.asset_id}.`,
    'success');
  toast(`Pushed ${result.pushed} reviews to STIG-Manager`, 'success');
}

async function confirmFetchAllContent(event) {
  const confirmed = await confirmDialog(
    'Fetch all DISA content?',
    'This downloads and imports every package in the current DISA catalog and may take substantial time, bandwidth, and disk space. A newer benchmark can be reference-only until an exact-release trusted check pack is installed. Use Browse available content for a targeted import.',
  );
  if (confirmed) await fetchAllContent(event?.currentTarget || null);
}

async function fetchAllContent(triggerButton = null) {
  const release = beginUiOperation('disa-content-write', triggerButton, 'Fetching\u2026');
  if (!release) return;
  toast('Fetching all STIG content from DISA... this may take a few minutes.', 'info');
  setOperationStatus('standards-operation-status', 'Fetching current public benchmark content from DISA… Keep this page open.', 'info');
  try {
    const result = await api('/disa/fetch-all', { method: 'POST' });
    await loadStandards();
    focusPageHeading('standards');
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
    const partial = result.errors?.length > 0;
    setOperationStatus('standards-operation-status', partial
      ? `DISA fetch partially completed: ${result.new_benchmarks} new, ${result.updated_benchmarks} updated, and ${result.errors.length} package error(s). Review details below.`
      : `DISA fetch complete: ${result.new_benchmarks} new and ${result.updated_benchmarks} updated benchmark(s).`, partial ? 'warning' : 'success');
    toast(partial
      ? `DISA fetch partially completed with ${result.errors.length} error(s).`
      : `Done! ${result.new_benchmarks} new, ${result.updated_benchmarks} updated.`, partial ? 'info' : 'success');
  } catch (e) {
    setOperationStatus('standards-operation-status', `DISA fetch failed: ${e.message}`, 'error',
      h('button', { className: 'btn btn-secondary btn-sm', onClick: fetchAllContent }, 'Retry'));
    toast(`Fetch failed: ${e.message}`, 'error');
  } finally {
    release();
  }
}

async function checkForUpdates(event) {
  const release = beginUiOperation('disa-catalog-read', event?.currentTarget || null, 'Checking\u2026');
  if (!release) return;
  toast('Refreshing the DISA package catalog...', 'info');
  setOperationStatus('standards-operation-status', 'Refreshing the available DISA package catalog…', 'info');
  try {
    const result = await api('/disa/check-updates');
    setOperationStatus('standards-operation-status', `Catalog refreshed: ${result.available_count} packages available and ${result.installed_count} standards installed. Review the catalog to decide what to import.`, 'success');
    toast(`${result.available_count} STIGs available, ${result.installed_count} installed locally.`, 'info');
    showAvailableList(result.available_stigs);
  } catch (e) {
    setOperationStatus('standards-operation-status', `Catalog refresh failed: ${e.message}`, 'error',
      h('button', { className: 'btn btn-secondary btn-sm', onClick: checkForUpdates }, 'Retry'));
    toast(`Catalog refresh failed: ${e.message}`, 'error');
  } finally {
    release();
  }
}

async function browseAvailable(event) {
  const release = beginUiOperation('disa-catalog-read', event?.currentTarget || null, 'Loading\u2026');
  if (!release) return;
  toast('Loading available STIGs from DISA...', 'info');
  setOperationStatus('standards-operation-status', 'Loading available STIG packages from DISA…', 'info');
  try {
    const stigs = await api('/disa/available');
    showAvailableList(stigs);
    setOperationStatus('standards-operation-status', `Loaded ${stigs.length} available STIG package(s).`, 'success');
    toast(`Found ${stigs.length} STIG packages on DISA.`, 'success');
  } catch (e) {
    setOperationStatus('standards-operation-status', `Could not load available STIGs: ${e.message}`, 'error',
      h('button', { className: 'btn btn-secondary btn-sm', onClick: browseAvailable }, 'Retry'));
    toast(`Failed to browse: ${e.message}`, 'error');
  } finally {
    release();
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
        h('button', { className: 'btn btn-primary btn-sm', onClick: (event) => fetchSingleStig(s, event.currentTarget) }, 'Download'),
      ),
    ),
  );

  el.appendChild(h('div', { className: 'table-scroll', tabindex: '0', role: 'region', 'aria-label': 'Available DISA content table' },
  h('table', { className: 'data-table' },
    h('thead', {}, h('tr', {},
      h('th', {}, 'STIG Package'),
      h('th', {}, 'Action'),
    )),
    h('tbody', {}, ...rows),
  )));
}

async function fetchSingleStig(stig, triggerButton = null) {
  const release = beginUiOperation('disa-content-write', triggerButton, 'Downloading\u2026');
  if (!release) return;
  toast(`Downloading: ${stig.title}...`, 'info');
  setOperationStatus('standards-operation-status', `Downloading and importing ${stig.title}…`, 'info');
  try {
    const result = await api('/disa/fetch', {
      method: 'POST',
      body: JSON.stringify({ url: stig.download_url }),
    });
    await loadStandards();
    focusPageHeading('standards');
    toast(`Imported: ${result.new_benchmarks} new, ${result.updated_benchmarks} updated.`, 'success');
    setOperationStatus('standards-operation-status', `Imported ${stig.title}: ${result.new_benchmarks} new and ${result.updated_benchmarks} updated benchmark(s).`, 'success');
    const contentResults = document.getElementById('content-results');
    if (contentResults && result.details?.length) {
      contentResults.appendChild(h('div', { className: 'card', style: 'margin-top:16px' },
        h('div', { className: 'card-header' }, h('h2', {}, 'Import details')),
        h('div', { style: 'max-height:240px;overflow:auto' },
          ...result.details.map(detail => h('p', { style: 'color:var(--text-secondary)' }, detail)))));
    }
  } catch (e) {
    setOperationStatus('standards-operation-status', `Download failed: ${e.message}`, 'error',
      h('button', { className: 'btn btn-secondary btn-sm', onClick: () => fetchSingleStig(stig) }, 'Retry'));
    toast(`Download failed: ${e.message}`, 'error');
  } finally {
    release();
  }
}

async function downloadOfflinePack(event) {
  const release = beginUiOperation('offline-pack-download', event?.currentTarget || null, 'Generating\u2026');
  if (!release) return;
  try {
    toast('Offline export requires an explicitly configured external signing key. Prefer the CLI on an offline signing workstation.', 'info');
    setOperationStatus('standards-operation-status', 'Generating the signed offline pack with the configured external key…', 'info');
    const pack = await downloadAuthed('/offline-pack', 'automatestig-offline.stigpack');
    if (!pack.ok) {
      setOperationStatus('standards-operation-status', `Offline pack generation failed: ${pack.error}`, 'error');
      return;
    }
    const key = await downloadAuthed('/offline-pack/trust-key', 'content-signing.pub');
    setOperationStatus('standards-operation-status', key.ok
      ? 'Signed offline pack and its public trust key were downloaded.'
      : `The pack downloaded, but its public trust key did not: ${key.error}`, key.ok ? 'success' : 'error');
  } finally {
    release();
  }
}

function addAssetDialog(existingAsset = null) {
  const editing = Boolean(existingAsset);
  const flowTarget = targetForBenchmark(assessmentFlow()?.benchmarkId);
  const selectedPlatform = normalizePlatform(existingAsset?.platform) || flowTarget?.platform || 'ontap';
  const overlay = h('div', { className: 'modal-overlay' },
    h('div', { className: 'modal', style: 'max-width: 500px' },
      h('h3', {}, editing ? 'Edit Asset' : 'Add Asset'),
      h('div', { className: 'form-group' },
        h('label', { className: 'form-label' }, 'Device hostname'),
        h('input', { className: 'form-input', id: 'aa-name', placeholder: 'device01', value: existingAsset?.name || '' }),
        h('div', { className: 'field-help' }, 'Use the exact hostname reported by device evidence or configuration. This is an assessment identity, not a free-form display name.')),
      h('div', { className: 'form-group' },
        h('label', { className: 'form-label' }, 'Address'), h('input', { className: 'form-input', id: 'aa-addr', placeholder: '10.0.1.50', value: existingAsset?.address || '' })),
      h('div', { className: 'grid-2' },
        h('div', { className: 'form-group' },
          h('label', { className: 'form-label' }, 'Platform'),
          h('select', { className: 'form-select', id: 'aa-platform' },
            h('option', { value: 'ontap', selected: selectedPlatform === 'ontap' }, 'NetApp ONTAP'),
            h('option', { value: 'bsd', selected: selectedPlatform === 'bsd' }, 'FreeBSD'),
            h('option', { value: 'cisco_ios', selected: selectedPlatform === 'cisco_ios' }, 'Cisco IOS-XE Router NDM'))),
        h('div', { className: 'form-group' },
          h('label', { className: 'form-label', for: 'aa-port' }, 'SSH port (optional)'),
          h('input', { className: 'form-input', id: 'aa-port', type: 'number', min: '1', max: '65535', placeholder: '22', value: existingAsset?.port || '' }),
          h('div', { className: 'field-help' }, 'Leave blank for port 22. Used when linking a remote SSH scan.')),
      ),
      h('div', { className: 'form-group' },
        h('label', { className: 'form-label' }, 'Tags (comma-separated)'),
        h('input', { className: 'form-input', id: 'aa-tags', placeholder: 'production, web-tier', value: existingAsset?.tags?.join(', ') || '' })),
      h('div', { className: 'btn-group', style: 'justify-content: flex-end; margin-top: 16px' },
        h('button', { className: 'btn btn-secondary', onClick: () => dismissModal(overlay) }, 'Cancel'),
        h('button', { className: 'btn btn-primary', id: 'aa-add', disabled: true, onClick: async (event) => {
          const nameInput = document.getElementById('aa-name');
          const addressInput = document.getElementById('aa-addr');
          const asset = {
            ...(existingAsset || {}),
            id: existingAsset?.id || crypto.randomUUID(), name: nameInput?.value?.trim(),
            address: addressInput?.value?.trim(),
            platform: document.getElementById('aa-platform')?.value,
            tags: (document.getElementById('aa-tags')?.value || '').split(',').map(t => t.trim()).filter(t => t),
            assigned_stigs: existingAsset?.assigned_stigs || [], enabled: existingAsset?.enabled !== false, port: null,
            os_info: existingAsset?.os_info ?? null, notes: existingAsset?.notes ?? null,
            last_evaluated: existingAsset?.last_evaluated ?? null,
            last_compliance_pct: existingAsset?.last_compliance_pct ?? null,
            last_checklist_ids: existingAsset?.last_checklist_ids || [],
            created_at: existingAsset?.created_at || new Date().toISOString(),
          };
          const portInput = document.getElementById('aa-port');
          if (portInput?.value) asset.port = Number(portInput.value);
          if (!asset.name?.trim() || !asset.address?.trim()) {
            nameInput?.setAttribute('aria-invalid', String(!asset.name));
            addressInput?.setAttribute('aria-invalid', String(!asset.address));
            setOperationStatus('aa-status', 'Enter both a name and address before saving this asset.', 'error');
            return;
          }
          if (portInput?.value && !portInput.checkValidity()) {
            portInput.setAttribute('aria-invalid', 'true');
            setOperationStatus('aa-status', 'SSH port must be between 1 and 65535.', 'error');
            return;
          }
          const release = beginUiOperation(
            'assets-write',
            event.currentTarget,
            editing ? 'Saving\u2026' : 'Adding\u2026',
          );
          if (!release) return;
          try {
            await api(editing ? `/assets/${encodeURIComponent(asset.id)}` : '/assets', {
              method: editing ? 'PUT' : 'POST', body: JSON.stringify(asset),
            });
            if (!editing && assessmentFlow()?.active) {
              updateAssessmentFlow({ assetId: asset.id, step: 'collection' });
            }
            dismissModal(overlay);
            toast(editing ? 'Asset updated' : 'Asset added', 'success');
            await loadAssetsPage();
            focusPageHeading('assets');
          }
          catch (e) {
            nameInput?.setAttribute('aria-invalid', 'true');
            addressInput?.setAttribute('aria-invalid', 'true');
            setOperationStatus('aa-status', `Asset could not be ${editing ? 'updated' : 'added'}: ${e.message}`, 'error');
            toast(e.message, 'error');
          } finally {
            release();
            if (overlay.isConnected) updateAddReady();
          }
        }}, editing ? 'Save Changes' : 'Add'),
      ),
      h('div', { id: 'aa-status', className: 'inline-status', style: 'display:none' }),
    ),
  );
  showModal(overlay, { initialFocus: '#aa-name' });
  const updateAddReady = () => {
    const name = document.getElementById('aa-name');
    const address = document.getElementById('aa-addr');
    const port = document.getElementById('aa-port');
    const ready = Boolean(name?.value.trim() && address?.value.trim()
      && (!port?.value || port.checkValidity()));
    const add = document.getElementById('aa-add');
    if (add) add.disabled = !ready;
    if (name?.value.trim()) name.removeAttribute('aria-invalid');
    if (address?.value.trim()) address.removeAttribute('aria-invalid');
    if (!port?.value || port.checkValidity()) port?.removeAttribute('aria-invalid');
  };
  ['aa-name', 'aa-addr', 'aa-port'].forEach(id => document.getElementById(id)?.addEventListener('input', updateAddReady));
  updateAddReady();
}

async function bulkAssignStig(assetIds, benchmarks, assets, triggerButton = null) {
  if (!assetIds.length) return;
  const selectedPlatforms = new Set(
    assets.filter(asset => assetIds.includes(asset.id)).map(asset => normalizePlatform(asset.platform)),
  );
  if (selectedPlatforms.size !== 1) {
    toast('Select assets from one supported platform before assigning a STIG', 'error');
    return;
  }
  const compatibleBenchmarks = benchmarks.filter(benchmark => {
    const target = targetForBenchmark(benchmark);
    return target && selectedPlatforms.size === 1 && selectedPlatforms.has(target.platform);
  });
  if (!compatibleBenchmarks.length) {
    toast('No installed supported benchmark matches the selected assets', 'error');
    return;
  }
  const stigId = await pickBenchmark(compatibleBenchmarks);
  if (!stigId) return;
  const release = beginUiOperation('assets-write', triggerButton, 'Assigning\u2026');
  if (!release) return;
  try {
    await api('/assets/bulk-assign-stig', { method: 'POST', body: JSON.stringify({ asset_ids: assetIds, stig_id: stigId }) });
    toast(`Assigned ${stigId} to ${assetIds.length} asset(s)`, 'success');
    await loadAssetsPage();
    focusPageHeading('assets');
  } catch (e) { toast(e.message, 'error'); }
  finally { release(); }
}

async function bulkAddTag(assetIds, triggerButton = null) {
  if (!assetIds.length) return;
  const tag = await promptText('Add tag', 'Tag to add to selected assets', 'production');
  if (!tag) return;
  const release = beginUiOperation('assets-write', triggerButton, 'Tagging\u2026');
  if (!release) return;
  try {
    await api('/assets/bulk-update', { method: 'POST', body: JSON.stringify({ asset_ids: assetIds, add_tag: tag }) });
    toast(`Tagged ${assetIds.length} asset(s)`, 'success');
    await loadAssetsPage();
    focusPageHeading('assets');
  } catch (e) { toast(e.message, 'error'); }
  finally { release(); }
}

async function bulkSetEnabled(assetIds, enabled, triggerButton = null) {
  if (!assetIds.length) return;
  const release = beginUiOperation('assets-write', triggerButton, enabled ? 'Enabling\u2026' : 'Disabling\u2026');
  if (!release) return;
  try {
    await api('/assets/bulk-update', { method: 'POST', body: JSON.stringify({ asset_ids: assetIds, enabled }) });
    toast(`${enabled ? 'Enabled' : 'Disabled'} ${assetIds.length} asset(s)`, 'success');
    await loadAssetsPage();
    focusPageHeading('assets');
  } catch (e) { toast(e.message, 'error'); }
  finally { release(); }
}

async function deleteAsset(asset, triggerButton = null) {
  const confirmed = await confirmDialog(
    'Delete Asset',
    `Delete "${asset.name}" from local inventory? Saved checklists, audit history, and any STIG-Manager asset will remain. This cannot be undone.`,
  );
  if (!confirmed) return;

  const release = beginUiOperation('assets-write', triggerButton, 'Deleting\u2026');
  if (!release) return;
  try {
    await api(`/assets/${encodeURIComponent(asset.id)}`, { method: 'DELETE' });
    if (assessmentFlow()?.assetId === asset.id) {
      updateAssessmentFlow({ assetId: null, step: 'asset' });
    }
    toast(`${asset.name} deleted from local inventory`, 'success');
    await loadAssetsPage();
    focusPageHeading('assets');
  } catch (e) {
    toast(`Asset deletion failed: ${e.message}`, 'error');
  } finally {
    release();
  }
}

function pickBenchmark(benchmarks) {
  return new Promise(resolve => {
    const supported = (benchmarks || []).filter(targetForBenchmark);
    if (!supported.length) { toast('No supported scanner standards installed', 'error'); resolve(null); return; }
    const overlay = h('div', { className: 'modal-overlay' },
      h('div', { className: 'modal' },
        h('h3', {}, 'Assign standard'),
        h('div', { className: 'stack-list', style: 'margin-top: 12px' },
          ...supported.map(b => h('button', { className: 'action-row', onClick: () => { dismissModal(overlay); resolve(b.id); } },
            h('div', {}, h('div', { className: 'list-title' }, b.title || b.id), h('div', { className: 'list-subtitle' }, b.id)),
            h('span', { className: 'action-arrow' }, '→'))),
        ),
        h('div', { className: 'btn-group', style: 'justify-content: flex-end; margin-top: 16px' },
          h('button', { className: 'btn btn-secondary', onClick: () => { dismissModal(overlay); resolve(null); } }, 'Cancel')),
      ),
    );
    showModal(overlay, { onCancel: () => resolve(null) });
  });
}

function promptText(title, label, placeholder) {
  return new Promise(resolve => {
    const overlay = h('div', { className: 'modal-overlay' },
      h('div', { className: 'modal' },
        h('h3', {}, title),
        h('div', { className: 'form-group', style: 'margin-top: 12px' },
          h('label', { className: 'form-label' }, label),
          h('input', { className: 'form-input', id: 'prompt-text', placeholder: placeholder || '' })),
        h('div', { className: 'btn-group', style: 'justify-content: flex-end' },
          h('button', { className: 'btn btn-secondary', onClick: () => { dismissModal(overlay); resolve(null); } }, 'Cancel'),
          h('button', { className: 'btn btn-primary', onClick: () => { const v = document.getElementById('prompt-text')?.value?.trim(); dismissModal(overlay); resolve(v || null); } }, 'OK')),
      ),
    );
    showModal(overlay, { onCancel: () => resolve(null), initialFocus: '#prompt-text' });
  });
}

async function checkStigManagerDiff(event) {
  const release = beginUiOperation('stigman-diff', event?.currentTarget || null, 'Checking\u2026');
  if (!release) return;
  try {
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
        h('h4', { style: 'color: var(--text-secondary); margin-bottom: 4px' }, `${diff.removed_from_stigman.length} Local-only Assets (Retained)`),
        h('p', { className: 'field-help', style: 'margin-bottom:4px' },
          'These records are no longer in this STIG-Manager collection. Sync does not delete or disable them.'),
        ...diff.removed_from_stigman.map(a => h('div', { style: 'font-size: 0.85rem; padding: 2px 0' }, `• ${a}`)),
      ));
      }
      if (diff.stig_assignment_changes.length > 0) {
      items.push(h('div', { style: 'margin-bottom: 12px' },
        h('h4', { style: 'color: var(--yellow); margin-bottom: 4px' }, `${diff.stig_assignment_changes.length} STIG Assignment Changes`),
        ...diff.stig_assignment_changes.map(c => h('div', { style: 'font-size: 0.85rem; padding: 2px 0' },
          `${c.asset}: +${c.stigs_added.length} / -${c.stigs_removed.length} STIGs`)),
      ));
      }
      if (diff.address_changes?.length > 0) {
      items.push(h('div', { style: 'margin-bottom: 12px' },
        h('h4', { style: 'color: var(--yellow); margin-bottom: 4px' }, `${diff.address_changes.length} Address Changes`),
        ...diff.address_changes.map(change => h('div', { style: 'font-size: 0.85rem; padding: 2px 0' },
          `${change.asset}: ${change.local_address} → ${change.stigman_address}`)),
      ));
      }

      const hasActionableChanges = diff.new_assets_in_stigman.length > 0
        || diff.stig_assignment_changes.length > 0
        || (diff.address_changes?.length || 0) > 0;

      const overlay = h('div', { className: 'modal-overlay' },
      h('div', { className: 'modal', style: 'max-width: 500px' },
        h('h3', {}, 'STIG-Manager Changes Detected'),
        h('p', { style: 'color: var(--text-secondary); margin-bottom: 16px' },
          `Local: ${diff.local_count} assets | STIG-Manager: ${diff.stigman_count} assets`),
        ...items,
        h('div', { className: 'btn-group', style: 'justify-content: flex-end; margin-top: 16px' },
          h('button', { className: 'btn btn-secondary', onClick: () => dismissModal(overlay) }, 'Close'),
          hasActionableChanges ? h('button', { className: 'btn btn-primary', onClick: () => { dismissModal(overlay); syncFromStigManager(selectedId); } }, 'Sync Additions and Updates') : null,
        ),
      ),
      );
      showModal(overlay);
    } catch (e) {
      toast(`Check failed: ${e.message}`, 'error');
    }
  } finally {
    release();
  }
}

async function syncFromStigManager(collectionId = null) {
  const triggerButton = collectionId?.currentTarget instanceof HTMLElement
    ? collectionId.currentTarget
    : null;
  const reviewedCollectionId = typeof collectionId === 'string' && collectionId.trim()
    ? collectionId.trim()
    : null;
  const release = beginUiOperation('assets-write', triggerButton, 'Syncing\u2026');
  if (!release) return;
  try {
    let config;
    try { config = await api('/stigman/config'); } catch (_) {
      toast('STIG-Manager not configured. Go to Settings.', 'error'); nav('settings'); return;
    }
    if (!config.configured) {
      toast('STIG-Manager not configured. Go to Settings.', 'error'); nav('settings'); return;
    }

    toast(reviewedCollectionId
      ? 'Syncing the reviewed STIG-Manager collection...'
      : 'Loading collections from STIG-Manager...', 'info');
    try {
      let selectedId = reviewedCollectionId;
      if (!selectedId) {
        const collections = await api('/stigman/collections');
        if (!collections || collections.length === 0) {
          toast('No collections found', 'error'); return;
        }
        selectedId = await pickCollection(collections);
        if (!selectedId) return;
      }

      toast('Syncing assets from STIG-Manager...', 'info');
      const result = await api(`/stigman/sync/${selectedId}`, { method: 'POST' });
      toast(`Synced ${result.synced} assets (${result.total_assets} total; local-only assets retained)`, 'success');
      await loadAssetsPage();
      const status = currentPageOperationStatus('asset-sync-status');
      setOperationStatus(status, `Synced ${result.synced} asset(s); ${result.total_assets} total in local inventory. Local-only assets were retained.`, 'success');
      if (status && result.details?.length) {
        status.appendChild(h('details', { style: 'margin-top:10px' },
          h('summary', {}, `View ${result.details.length} sync detail(s)`),
          h('div', { style: 'max-height:220px;overflow:auto;margin-top:8px' },
            ...result.details.map(detail => h('p', {}, detail)))));
      }
      focusPageHeading('assets');
    } catch (e) {
      setOperationStatus(currentPageOperationStatus('asset-sync-status'), `STIG-Manager sync failed: ${e.message}`, 'error',
        h('button', { className: 'btn btn-secondary btn-sm', onClick: () => syncFromStigManager(reviewedCollectionId) }, 'Retry'));
      toast(`Sync failed: ${e.message}`, 'error');
    }
  } finally {
    release();
  }
}

// ---------------------------------------------------------------------------
// Export All ZIP
// ---------------------------------------------------------------------------
async function exportAllZip(triggerButton = null) {
  const restoreFocus = triggerButton instanceof HTMLElement
    && document.activeElement === triggerButton;
  const status = currentPageOperationStatus('findings-export-status');
  const release = beginUiOperation('export-all-zip', triggerButton, 'Exporting\u2026');
  if (!release) return;
  setOperationStatus(status, 'Building the checklist ZIP\u2026 Keep this page open.', 'info');
  if (restoreFocus && isElementInActiveView(status)) {
    status.setAttribute('tabindex', '-1');
    status.focus({ preventScroll: true });
  }
  try {
    const result = await downloadAuthed('/export/all-zip', 'automatestig-checklists.zip');
    if (!result.ok) {
      setOperationStatus(status, `Export failed: ${result.error}`, 'error',
        h('button', {
          className: 'btn btn-secondary btn-sm',
          onClick: (event) => exportAllZip(event.currentTarget),
        }, 'Retry'));
      return;
    }
    setOperationStatus(status, `Downloaded ${result.name}.`, 'success');
    toast(`Downloaded ${result.name}.`, 'success');
  } finally {
    release();
    if (restoreFocus) {
      const exportButton = document.getElementById('findings-export-all');
      const focusTarget = isElementInActiveView(exportButton)
        ? exportButton
        : (isElementInActiveView(status) ? status : null);
      focusTarget?.focus({ preventScroll: true });
    }
  }
}

// ---------------------------------------------------------------------------
// Delete Checklist
// ---------------------------------------------------------------------------
async function deleteChecklist(id, hostname, triggerButton = null) {
  const confirmed = await confirmDialog('Delete Checklist', `Delete the checklist for "${hostname}"? This cannot be undone.`);
  if (!confirmed) return;
  const release = beginUiOperation(`delete-checklist:${id}`, triggerButton, 'Deleting\u2026');
  if (!release) return;
  try {
    const result = await api(`/checklists/${id}`, { method: 'DELETE' });
    toast(result.inventory_cleanup_warning || 'Checklist deleted', result.inventory_cleanup_warning ? 'info' : 'success');
    returnFromChecklist(checklistReturnPage);
  } catch (e) {
    toast(`Delete failed: ${e.message}`, 'error');
  } finally {
    release();
  }
}

// ---------------------------------------------------------------------------
// STIG-Manager Collection Picker Modal (Fix #13)
// ---------------------------------------------------------------------------
function pickCollection(collections) {
  return new Promise((resolve) => {
    const rows = collections.map(c =>
      h('button', {
        className: 'action-row',
        style: 'width:100%;padding:10px 14px;text-align:left',
        onMouseover: (e) => e.target.style.background = 'var(--bg-hover)',
        onMouseout: (e) => e.target.style.background = 'transparent',
        onClick: () => { dismissModal(overlay); resolve(c.collection_id || c.collectionId); },
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
          h('button', { className: 'btn btn-secondary', onClick: () => { dismissModal(overlay); resolve(null); } }, 'Cancel'),
        ),
      ),
    );
    showModal(overlay, { onCancel: () => resolve(null) });
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
      if (dot) dot.style.background = 'var(--yellow)';
      if (text) text.textContent = 'STIG Manager configured';
    } else {
      if (dot) dot.style.background = 'var(--orange)';
      if (text) text.textContent = 'STIG Manager not configured';
    }
  } catch (_) {
    const dot = document.getElementById('status-dot');
    const text = document.getElementById('status-text');
    if (dot) dot.style.background = 'var(--orange)';
    if (text) text.textContent = 'Integration status unavailable';
  }
}

// ---------------------------------------------------------------------------
// Answer File Editor
// ---------------------------------------------------------------------------
async function openAnswerEditor(triggerButton = null) {
  const release = beginUiOperation('answer-editor-open', triggerButton, 'Opening\u2026');
  if (!release) return;
  try {
    const [answerFileResponse, benchmarks] = await Promise.all([api('/answer-files'), api('/library/benchmarks')]);
    if (triggerButton && (!triggerButton.isConnected || activePageName() !== 'settings')) return;
    const { files, warnings } = normalizeAnswerFileResponse(answerFileResponse);
    const opts = benchmarks.map(benchmark => h('option', { value: benchmark.id },
      `${benchmark.id}${benchmark.scanner_ready === false ? ' (reference only)' : ''}`));
    let editingFile = null;
    let answerSelectionVersion = 0;
    const answerFileButtons = [];
    let overlay;
    const modeTitle = h('h4', { style: 'margin: 12px 0 8px' }, 'Create New');
    const nameInput = h('input', { className: 'form-input', id: 'af-name', placeholder: 'Site Answers' });
    const stigSelect = h('select', { className: 'form-select', id: 'af-stig' },
      h('option', { value: '' }, 'Any'), ...opts);
    const entriesInput = h('textarea', {
      className: 'form-input', id: 'af-entries', rows: '8',
      style: 'font-family: monospace; font-size: 0.8rem',
      placeholder: '[{"vuln_id":"V-246927","status":"Not_Applicable","finding_details":"Not used"}]',
    });

    const updateAnswerSaveReady = () => {
      let isArray = false;
      try { isArray = Array.isArray(JSON.parse(entriesInput.value || '[]')); } catch (_) { isArray = false; }
      saveButton.disabled = !(nameInput.value.trim()
        && isArray
        && (!editingFile || (editingFile.editable && editingFile.etag)));
      if (nameInput.value.trim()) nameInput.removeAttribute('aria-invalid');
      if (isArray) entriesInput.removeAttribute('aria-invalid');
    };

    const setAnswerFileLoadBusy = (busy) => {
      answerFileButtons.forEach((button) => {
        button.disabled = busy;
        if (busy) button.setAttribute('aria-busy', 'true');
        else button.removeAttribute('aria-busy');
      });
    };

    const beginCreate = () => {
      answerSelectionVersion += 1;
      setAnswerFileLoadBusy(false);
      editingFile = null;
      modeTitle.textContent = 'Create New';
      nameInput.disabled = false;
      stigSelect.disabled = false;
      entriesInput.disabled = false;
      nameInput.value = '';
      stigSelect.value = '';
      entriesInput.value = '';
      saveButton.textContent = 'Create File';
      clearOperationStatus('af-status');
      updateAnswerSaveReady();
      nameInput.focus();
    };

    const selectExisting = async (file) => {
      const selectionVersion = ++answerSelectionVersion;
      let content;
      if (file.invalid && file.editable) {
        content = { name: file.name, stig_id: null, version: '1.0', description: null, entries: [] };
      } else if (file.invalid) {
        setOperationStatus('af-status', 'This malformed YAML file must be repaired on the filesystem of the host running AutomateSTIG.', 'error');
        return;
      } else {
        setOperationStatus('af-status', `Loading ${file.id}…`, 'info');
        setAnswerFileLoadBusy(true);
        try {
          const detail = await api(`/answer-files/${encodeURIComponent(file.id)}`);
          if (selectionVersion !== answerSelectionVersion || !overlay?.isConnected) return;
          content = detail.answer_file;
          file.etag = detail.etag || file.etag;
        } catch (error) {
          if (selectionVersion !== answerSelectionVersion || !overlay?.isConnected) return;
          setOperationStatus('af-status', `Answer file could not be opened: ${error.message}`, 'error');
          return;
        } finally {
          if (selectionVersion === answerSelectionVersion) setAnswerFileLoadBusy(false);
        }
      }
      if (selectionVersion !== answerSelectionVersion || !overlay?.isConnected) return;
      file.answer_file = content;
      editingFile = file;
      modeTitle.textContent = file.invalid ? `Repair ${file.id}` : file.editable ? `Replace ${file.id}` : `View ${file.id}`;
      nameInput.value = content.name || file.name || '';
      nameInput.disabled = true;
      if (content.stig_id && ![...stigSelect.options].some(option => option.value === content.stig_id)) {
        stigSelect.appendChild(h('option', { value: content.stig_id }, `${content.stig_id} (not installed)`));
      }
      stigSelect.value = content.stig_id || '';
      entriesInput.value = JSON.stringify(content.entries || [], null, 2);
      stigSelect.disabled = !file.editable;
      entriesInput.disabled = !file.editable;
      saveButton.textContent = file.invalid ? 'Replace Invalid File' : file.editable ? 'Replace File' : 'View Only';
      setOperationStatus('af-status', file.editable && !file.etag
        ? 'This file revision could not be identified safely. Close and reopen the editor before replacing it.'
        : file.editable
        ? `${file.invalid ? 'Repairing' : 'Editing'} never replaces this policy template silently. Choose ${file.invalid ? 'Replace Invalid File' : 'Replace File'} and confirm to commit changes.`
        : 'This installed template has a filename that is not managed by the GUI editor. It is view-only; create a new file to make changes.',
      file.editable && !file.etag ? 'error' : file.editable ? 'warning' : 'info');
      updateAnswerSaveReady();
      (file.editable ? entriesInput : nameInput).focus();
    };

    const saveButton = h('button', {
      className: 'btn btn-primary', id: 'af-save', disabled: true, onClick: async () => {
        const name = nameInput.value.trim();
        if (!name) {
          nameInput.setAttribute('aria-invalid', 'true');
          setOperationStatus('af-status', 'Enter a name for this answer file.', 'error');
          return;
        }
        let entries;
        try { entries = JSON.parse(entriesInput.value || '[]'); }
        catch (_) {
          entriesInput.setAttribute('aria-invalid', 'true');
          setOperationStatus('af-status', 'Entries must be valid JSON.', 'error');
          return;
        }
        if (!Array.isArray(entries)) {
          entriesInput.setAttribute('aria-invalid', 'true');
          setOperationStatus('af-status', 'Entries JSON must be an array.', 'error');
          return;
        }
        if (editingFile && !editingFile.editable) return;
        if (editingFile && !editingFile.etag) {
          setOperationStatus('af-status', 'This file revision could not be identified safely. Close and reopen the editor before replacing it.', 'error');
          return;
        }
        if (editingFile) {
          const confirmed = await confirmDialog(
            'Replace answer file?',
            `Replace ${editingFile.id} with the values currently shown? Existing policy decisions in that file will be overwritten.`,
          );
          if (!confirmed) return;
        }

        const method = editingFile ? 'PUT' : 'POST';
        const path = editingFile
          ? `/answer-files/${encodeURIComponent(editingFile.id)}`
          : '/answer-files';
        const body = {
          name,
          stig_id: stigSelect.value || null,
          version: editingFile?.answer_file?.version || '1.0',
          description: editingFile?.answer_file?.description || null,
          entries,
        };
        saveButton.disabled = true;
        saveButton.textContent = editingFile ? 'Replacing…' : 'Creating…';
        try {
          const request = { method, body: JSON.stringify(body) };
          if (editingFile) request.headers = { 'If-Match': `"${editingFile.etag}"` };
          const result = await api(path, request);
          toast(`${editingFile ? 'Replaced' : 'Created'} ${result.id}: ${result.entries} entries`, 'success');
          dismissModal(overlay);
        } catch (error) {
          setOperationStatus('af-status', `Answer file was not saved: ${error.message}`, 'error');
          toast(error.message, 'error');
          saveButton.textContent = editingFile?.invalid
            ? 'Replace Invalid File'
            : editingFile ? 'Replace File' : 'Create File';
          updateAnswerSaveReady();
        }
      },
    }, 'Create File');

    const existingRows = files.map(file => {
      const button = h('button', {
        className: 'action-row',
        style: 'width:100%;text-align:left',
        onClick: () => selectExisting(file),
        'aria-label': `${file.invalid ? (file.editable ? 'Repair' : 'Unavailable') : file.editable ? 'Edit' : 'View'} ${file.name}`,
      },
        h('div', {},
          h('div', { className: 'list-title' }, file.name),
          h('div', { className: 'list-subtitle' }, `${file.stig_id || 'Any STIG'} • ${file.entries} entries • ${file.id}`)),
        h('span', { className: `mini-pill mini-pill-${file.invalid ? 'yellow' : 'accent'}` },
          file.invalid ? (file.editable ? 'Repair' : 'Unavailable') : file.editable ? 'Edit' : 'View only'),
      );
      answerFileButtons.push(button);
      return button;
    });

    overlay = h('div', { className: 'modal-overlay' },
      h('div', { className: 'modal', style: 'max-width: 700px; max-height: 80vh; overflow-y: auto' },
        h('h3', {}, 'Answer File Editor'),
        warnings.length ? h('div', { className: 'inline-status', role: 'alert', style: 'margin-bottom:14px' },
          h('strong', {}, `${warnings.length} installed file${warnings.length === 1 ? '' : 's'} need attention`),
          h('ul', { style: 'margin:8px 0 0 20px' }, ...warnings.map(warning => h('li', {}, warning)))) : null,
        files.length > 0 ? h('div', { style: 'margin-bottom: 16px' },
          h('div', { className: 'card-header' },
            h('h4', {}, `Existing Files (${files.length})`),
            h('button', { className: 'btn btn-secondary btn-sm', onClick: beginCreate }, 'Create New')),
          h('div', { className: 'stack-list' }, ...existingRows),
        ) : null,
        modeTitle,
        h('div', { className: 'form-group' },
          h('label', { className: 'form-label' }, 'Name'),
          nameInput,
          h('div', { className: 'field-help' }, 'The name determines the stable library filename. To avoid accidental replacement, it cannot be changed while editing an existing file.')),
        h('div', { className: 'form-group' },
          h('label', { className: 'form-label' }, 'Target STIG'),
          stigSelect),
        h('div', { className: 'form-group' },
          h('label', { className: 'form-label' }, 'Entries (JSON)'),
          entriesInput),
        h('div', { className: 'btn-group', style: 'justify-content: flex-end; margin-top: 12px' },
          h('button', { className: 'btn btn-secondary', onClick: () => dismissModal(overlay) }, 'Close'),
          saveButton,
        ),
        h('div', { id: 'af-status', className: 'inline-status operation-status', style: 'display:none' }),
      ),
    );
    showModal(overlay, { initialFocus: '#af-name' });
    nameInput.addEventListener('input', updateAnswerSaveReady);
    entriesInput.addEventListener('input', updateAnswerSaveReady);
    updateAnswerSaveReady();
  } catch (e) {
    toast(e.message, 'error');
  } finally {
    release();
  }
}

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------
function startApplication() {
  const requestedChecklist = checklistFromLocationHash();
  if (requestedChecklist) {
    applicationStarted = true;
    viewChecklist(
      requestedChecklist.id,
      requestedChecklist.origin,
      null,
      null,
      requestedChecklist.selectedVulnId ? {
        selectedVulnId: requestedChecklist.selectedVulnId,
        search: requestedChecklist.selectedVulnId,
        status: 'all',
      } : null,
      { updateHistory: false, focusMain: false },
    );
    updateStatusBar();
    return;
  }
  const requestedPage = pageFromLocationHash();
  const page = applicationStarted ? activePageName() : (requestedPage || 'assessments');
  applicationStarted = true;
  activatePrimaryPage(page, {
    updateHistory: !requestedPage,
    replaceHistory: !requestedPage,
    focusMain: false,
  });
  updateStatusBar();
}

if (AUTH_TOKEN) startApplication();
else showAuthTokenDialog();

// ---------------------------------------------------------------------------
// Workflow-first UI overlays
// ---------------------------------------------------------------------------
async function mapWithConcurrency(items, concurrency, mapper) {
  if (!items.length) return [];
  const results = new Array(items.length);
  let nextIndex = 0;
  const worker = async () => {
    while (nextIndex < items.length) {
      const index = nextIndex++;
      results[index] = await mapper(items[index], index);
    }
  };
  const workerCount = Math.min(Math.max(1, concurrency), items.length);
  await Promise.all(Array.from({ length: workerCount }, worker));
  return results;
}

async function fetchChecklistsWithFindings() {
  const response = normalizeChecklistResponse(await api('/checklists'));
  // A mature installation can contain hundreds of saved results. Bound the
  // detail fan-out so opening Findings cannot flood the local server with one
  // simultaneous request per checklist.
  const details = await mapWithConcurrency(
    response.checklists,
    6,
    async summary => {
      try {
        return { checklist: await api(`/checklists/${summary.id}`), warning: null };
      } catch (error) {
        return {
          checklist: null,
          warning: `Checklist ${summary.id} could not be loaded for Findings: ${error.message}`,
        };
      }
    },
  );
  return {
    checklists: details.flatMap(detail => detail.checklist ? [detail.checklist] : []),
    warnings: [
      ...response.warnings,
      ...details.flatMap(detail => detail.warning ? [detail.warning] : []),
    ],
  };
}

function flattenFindings(checklists) {
  const rows = [];
  for (const checklist of checklists || []) {
    const score = checklistScore(checklist);
    const findings = checklist.findings || [];
    for (const finding of findings) {
      rows.push({
        checklistId: checklist.id,
        hostname: checklist.hostname || checklist.asset?.hostname || 'Unknown asset',
        benchmark: checklist.stig_title || checklist.title || checklist.stig_id || 'Unknown standard',
        stigId: checklist.stig_id || checklist.stigInfo?.stig_id || '',
        vulnId: finding.vuln_id || finding.group_id || 'Unknown',
        title: finding.rule_title || finding.title || 'Untitled finding',
        severity: finding.severity || 'Unknown',
        status: finding.status || 'Not Reviewed',
        source: finding.source || 'Unknown',
        comments: finding.comments || '',
        details: finding.finding_details || '',
        evaluatedBy: finding.evaluated_by || '',
        evaluatedAt: finding.evaluated_at || checklist.modified_at || checklist.created_at || '',
        scoreDefensible: score.defensible,
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

function actionRow(title, subtitle, onClick, attrs = {}) {
  return h('button', { className: 'action-row', ...attrs, onClick },
    h('div', {},
      h('div', { className: 'list-title' }, title),
      h('div', { className: 'list-subtitle' }, subtitle),
    ),
    h('span', { className: 'action-arrow' }, '→'),
  );
}

async function beginNewAssessment() {
  updateAssessmentFlow({ origin: activePageName(), step: 'standard' });
  if (activePageName() !== 'assessments') {
    nav('assessments');
    return;
  }
  await loadAssessments();
  document.getElementById('eval-stig')?.focus({ preventScroll: true });
}

function openAssessment(assessment) {
  if (assessment.items.length === 1) {
    const item = assessment.items[0];
    viewChecklist(item.id, 'assessments', null, {
      displayName: item.display_asset_name,
      verifiedEndpoint: item.verified_endpoint,
    });
    return;
  }
  pickChecklistDialog(assessment.items);
}

function pickChecklistDialog(items) {
  const overlay = h('div', { className: 'modal-overlay' },
    h('div', { className: 'modal' },
      h('h3', {}, 'Open checklist'),
      h('div', { className: 'stack-list', style: 'margin-top: 12px' },
        ...items.map(item => h('button', { className: 'action-row', onClick: () => {
          dismissModal(overlay);
          viewChecklist(item.id, 'assessments', null, {
            displayName: item.display_asset_name,
            verifiedEndpoint: item.verified_endpoint,
          });
        } },
          h('div', {},
            h('div', { className: 'list-title' }, item.stig_title || item.stig_id || 'Checklist'),
            h('div', { className: 'list-subtitle' }, (() => {
              const score = checklistScore(item);
              const savedAt = item.modified_at || item.created_at;
              return `${formatDate(savedAt)} • ID ${item.id} • ${formatAssessedPassRate(score)} assessed pass rate • ${formatScorePct(score.benchmarkCoverage)} coverage • ${item.open || 0} open`;
            })()),
          ),
          h('span', { className: 'action-arrow' }, '→'),
        )),
      ),
      h('div', { className: 'btn-group', style: 'justify-content: flex-end; margin-top: 16px' },
        h('button', { className: 'btn btn-secondary', onClick: () => dismissModal(overlay) }, 'Cancel'),
      ),
    ),
  );
  showModal(overlay, { onCancel: () => {} });
}

async function loadAssessments() {
  const workspaceVersion = ++assessmentWorkspaceVersion;
  setPage('assessments', loadingState());

  try {
    const [checklistResponse, assetResponse] = await Promise.all([
      api('/checklists'),
      api('/assets'),
    ]);
    if (workspaceVersion !== assessmentWorkspaceVersion) return;
    const { checklists, warnings: checklistWarnings } = normalizeChecklistResponse(checklistResponse);
    const { assets, warnings: assetWarnings } = normalizeAssetResponse(assetResponse);
    const assetByChecklistId = new Map();
    assets.forEach(asset => (asset.last_checklist_ids || []).forEach(checklistId => {
      assetByChecklistId.set(checklistId, asset);
    }));

    const grouped = new Map();
    for (const checklist of checklists) {
      const linkedAsset = assetByChecklistId.get(checklist.id);
      const rawHostname = checklist.hostname || checklist.asset?.hostname || 'Imported results';
      const key = linkedAsset ? `asset:${linkedAsset.id}` : `hostname:${rawHostname}`;
      if (!grouped.has(key)) {
        grouped.set(key, { name: linkedAsset?.name || rawHostname, items: [], endpoints: new Set() });
      }
      checklist.display_asset_name = linkedAsset?.name || rawHostname;
      checklist.verified_endpoint = linkedAsset
        && linkedAsset.name.trim().toLowerCase() !== rawHostname.trim().toLowerCase()
        ? rawHostname
        : null;
      if (checklist.verified_endpoint) grouped.get(key).endpoints.add(checklist.verified_endpoint);
      grouped.get(key).items.push(checklist);
    }

    const assessments = [...grouped.values()].map(({ name, items, endpoints }, index) => {
      const standards = [...new Set(items.map(item => item.stig_title || item.stig_id).filter(Boolean))];
      const totals = items.reduce((summary, item) => ({
        total: summary.total + (Number(item.total) || 0),
        open: summary.open + (Number(item.open) || 0),
        not_reviewed: summary.not_reviewed + (Number(item.not_reviewed) || 0),
        not_a_finding: summary.not_a_finding + (Number(item.not_a_finding) || 0),
        not_applicable: summary.not_applicable + (Number(item.not_applicable) || 0),
      }), { total: 0, open: 0, not_reviewed: 0, not_a_finding: 0, not_applicable: 0 });
      const assessed = totals.total - totals.not_reviewed;
      const applicableAssessed = totals.open + totals.not_a_finding;
      const allScoresDefensible = items.length > 0
        && items.every(item => checklistScore(item).defensible);
      totals.assessed_pass_pct = allScoresDefensible
        ? (applicableAssessed > 0
          ? totals.not_a_finding / applicableAssessed * 100
          : null)
        : null;
      totals.benchmark_coverage_pct = allScoresDefensible
        ? (totals.total > 0 ? assessed / totals.total * 100 : 0)
        : null;
      totals.collection_complete = allScoresDefensible;
      const score = checklistScore(totals);
      const open = totals.open;
      const status = !score.defensible
        ? { label: 'Unverified', color: 'accent' }
        : (open || score.benchmarkCoverage < 100
          ? { label: 'Needs review', color: 'yellow' }
          : { label: 'Fully assessed', color: 'green' });
      return {
        id: `assessment-${index}`,
        name,
        items,
        standards,
        score,
        open,
        status,
        endpoints: [...endpoints],
        lastRun: items
          .map(item => item.modified_at || item.created_at)
          .filter(Boolean)
          .sort((a, b) => new Date(b).getTime() - new Date(a).getTime())[0] || null,
      };
    });

    const flow = assessmentFlow();
    setPage('assessments',
      h('div', { className: 'page-header page-header-with-actions' },
        h('div', {},
          h('h1', {}, 'Assessments'),
          h('p', {}, 'Manage assessment scope, runs, and outputs as grouped workspaces'),
        ),
        assessments.length ? h('div', { className: 'btn-group' },
          h('button', { className: 'btn btn-primary', onClick: beginNewAssessment }, 'Run New Assessment'),
          h('button', { className: 'btn btn-secondary', onClick: importChecklistFile }, 'Import Existing Results'),
        ) : null,
      ),
      assetWarningsPanel(assetWarnings),
      checklistWarningsPanel(checklistWarnings),
      !assessments.length ? h('div', { className: 'card setup-panel' },
        h('div', { className: 'card-header' }, h('h2', {}, 'What do you want to do?')),
        h('p', { style: 'color:var(--text-secondary);margin-bottom:14px' },
          'A new assessment collects evidence against an installed standard. Importing opens an existing CKL or CKLB for review.'),
        h('div', { className: 'stack-list' },
          actionRow('Run a new assessment', 'Install or select a standard, choose a compatible asset, then upload evidence or collect over SSH.', beginNewAssessment),
          actionRow('Import existing results', 'Open an existing CKL, CKLB, or compatible JSON checklist without running a device collection.', importChecklistFile),
        ),
      ) : null,
      assessments.length
        ? h('div', { className: 'card' },
            h('div', { className: 'table-scroll', tabindex: '0', role: 'region', 'aria-label': 'Assessments table' },
            h('table', { className: 'data-table' },
              h('thead', {}, h('tr', {},
                h('th', {}, 'Assessment'),
                h('th', {}, 'Scope'),
                h('th', {}, 'Last run'),
                h('th', {}, 'Open findings'),
                h('th', {}, 'Assessed pass / coverage'),
                h('th', {}, 'Status'),
              )),
              h('tbody', {}, ...assessments.map(assessment =>
                h('tr', {},
                  h('td', {},
                    h('button', {
                      className: 'table-link table-link-block',
                      'aria-label': `Open assessment for ${assessment.name}`,
                      onClick: () => openAssessment(assessment),
                    },
                      h('span', { className: 'list-title' }, assessment.name),
                      h('span', { className: 'list-subtitle' },
                        `${assessment.items.length} checklist${assessment.items.length === 1 ? '' : 's'}`,
                        assessment.endpoints.length
                          ? ` • Verified endpoint${assessment.endpoints.length === 1 ? '' : 's'}: ${assessment.endpoints.join(', ')}`
                          : ''),
                    ),
                  ),
                  h('td', {}, `${assessment.items.length} checklist result${assessment.items.length === 1 ? '' : 's'} • ${assessment.standards.length} standard${assessment.standards.length === 1 ? '' : 's'}`),
                  h('td', {}, formatDate(assessment.lastRun)),
                  h('td', {}, h('span', { className: `mini-pill mini-pill-${assessment.open ? 'red' : (assessment.score.defensible ? 'green' : 'accent')}` }, assessment.open)),
                  h('td', {},
                    h('span', { className: `mini-pill mini-pill-${scoreColor(assessment.score) || 'accent'}` }, formatAssessedPassRate(assessment.score, true)),
                    ' / ',
                    h('span', { className: `mini-pill mini-pill-${coverageColor(assessment.score) || 'accent'}` }, formatScorePct(assessment.score.benchmarkCoverage)),
                  ),
                  h('td', {}, h('span', { className: `mini-pill mini-pill-${assessment.status.color}` },
                    assessment.status.label)),
                ),
              )),
            ),
            ),
          )
        : null,
      h('div', { className: 'card' },
        h('div', { className: 'card-header' }, h('h2', {}, 'Assessment workflow')),
        h('div', { className: 'stack-list' },
          actionRow('1. Install or choose a standard', 'Load signed organizational content or DISA XCCDF before selecting a target.', () => {
            updateAssessmentFlow({ step: 'standard' }); nav('standards');
          }),
          actionRow('2. Add a compatible asset', 'Register the ONTAP, FreeBSD, or Cisco target you intend to assess.', () => {
            updateAssessmentFlow({ step: 'asset' }); nav('assets');
          }),
          actionRow('3. Choose collection and run', 'Upload verified evidence or use prepared SSH collection, then review the persistent result.', beginNewAssessment),
        ),
      ),
      h('div', { id: 'evaluate-workspace' }),
    );
    await renderEvaluateWorkspace(workspaceVersion);
    if (workspaceVersion !== assessmentWorkspaceVersion) return;
    if (flow?.active) {
      requestAnimationFrame(() => {
        document.getElementById('evaluate-workspace')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
      });
    }
  } catch (e) {
    if (workspaceVersion !== assessmentWorkspaceVersion) return;
    setPage('assessments', errorCard(e.message, loadAssessments));
  }
}

async function loadStandards() {
  setPage('standards', loadingState());

  try {
    const [benchmarks, status] = await Promise.all([
      api('/library/benchmarks'),
      api('/status').catch(() => ({})),
    ]);
    let flow = assessmentFlow();
    const supportedBenchmarks = benchmarks.filter(targetForBenchmark);
    const currentFlowBenchmark = supportedBenchmarks.some(benchmark => benchmark.id === flow?.benchmarkId)
      ? flow.benchmarkId
      : (supportedBenchmarks.length === 1 ? supportedBenchmarks[0].id : '');
    if (flow?.active && currentFlowBenchmark && flow.benchmarkId !== currentFlowBenchmark) {
      flow = updateAssessmentFlow({ benchmarkId: currentFlowBenchmark, step: 'standard' });
    }
    const offlineAvailable = status.offline_pack_available === true;
    const offlineReason = status.offline_pack_unavailable_reason
      ? `${status.offline_pack_unavailable_reason} Use the CLI on a controlled offline signing workstation.`
      : 'No external offline-signing key is configured. Use the CLI on a controlled offline signing workstation.';
    const offlinePackReady = offlineAvailable && benchmarks.length > 0;
    const offlinePackReason = benchmarks.length ? offlineReason : 'Install at least one benchmark before generating an offline pack.';

    const rows = benchmarks.map(benchmark => {
      const recognizedTarget = Boolean(SUPPORTED_SCANNER_TARGETS[benchmark.stig_id || benchmark.id]);
      const scannerReady = Boolean(targetForBenchmark(benchmark));
      const scannerReason = benchmark.scanner_blocked_reason
        || (recognizedTarget ? 'No trusted check pack matches this exact STIG release.' : 'This benchmark is reference content only.');
      return h('tr', {},
      h('td', {},
        h('div', { className: 'list-title' }, benchmark.title || benchmark.stig_id || benchmark.id),
        h('div', { className: 'list-subtitle' }, benchmark.stig_id || benchmark.id || 'Standard identifier'),
      ),
      h('td', {}, benchmark.platform || 'Unknown'),
      h('td', {}, `${benchmark.version || '—'} / ${benchmark.release || '—'}`),
      h('td', {}, benchmark.rule_count ?? benchmark.rules ?? '—'),
      h('td', {}, scannerReady
        ? h('span', { className: 'mini-pill mini-pill-green' }, 'Ready to assess')
        : [
            h('span', { className: 'mini-pill mini-pill-yellow' }, 'Reference only'),
            h('div', { className: 'list-subtitle', style: 'margin-top:4px;max-width:280px' }, scannerReason),
          ]),
      h('td', {}, formatDate(benchmark.imported_at || benchmark.created_at)),
      );
    });

    setPage('standards',
      h('div', { className: 'page-header page-header-with-actions' },
        h('div', {},
          h('h1', {}, 'Standards'),
          h('p', {}, 'Benchmark library and the three supported scanner targets'),
        ),
        h('div', { className: 'btn-group' },
          h('button', { className: 'btn btn-primary', onClick: importDisaFile }, 'Import DISA XCCDF (.xml or .zip)'),
          h('button', { className: 'btn btn-secondary', onClick: importStigpackFile }, 'Import Signed Pack (.stigpack)'),
        ),
      ),
      flow?.active ? h('div', { className: 'card setup-panel' },
        h('div', { className: 'card-header' }, h('h2', {}, 'New assessment — Step 1 of 4')),
        h('p', { style: 'color:var(--text-secondary)' }, supportedBenchmarks.length
          ? 'Choose the standard for this assessment, then continue to compatible assets.'
          : 'Install at least one supported standard before choosing an asset.'),
        supportedBenchmarks.length ? h('div', { className: 'form-group', style: 'margin-top:12px' },
          h('label', { className: 'form-label', for: 'workflow-standard-select' }, 'Assessment standard'),
          h('select', { className: 'form-select', id: 'workflow-standard-select' },
            h('option', { value: '' }, 'Select a standard…'),
            ...supportedBenchmarks.map(benchmark => h('option', {
              value: benchmark.id,
              selected: benchmark.id === currentFlowBenchmark,
            }, benchmark.title || benchmark.id))),
        ) : null,
        h('div', { className: 'workflow-actions btn-group', style: 'margin-top:12px' },
          h('button', { className: 'btn btn-secondary', onClick: () => nav('assessments') }, 'Back to Assessments'),
          h('button', { className: 'btn btn-secondary', onClick: () => {
            finishAssessmentFlow(); nav('assessments');
          } }, 'Cancel setup'),
          h('button', { className: 'btn btn-primary', id: 'workflow-standard-next', disabled: !currentFlowBenchmark, onClick: () => {
            const benchmarkId = document.getElementById('workflow-standard-select')?.value;
            if (!benchmarkId) return;
            updateAssessmentFlow({ benchmarkId, step: 'asset' }); nav('assets');
          } }, 'Next: Choose an Asset'),
        ),
      ) : null,
      h('div', { className: 'stats-grid' },
        statCard('Installed', benchmarks.length, 'accent'),
        statCard('Ready to assess', supportedBenchmarks.length, supportedBenchmarks.length ? 'green' : 'yellow'),
        statCard('Offline signing', offlineAvailable ? 'Available' : 'Unavailable', offlineAvailable ? 'green' : 'yellow'),
        statCard('Source', 'DISA + local packs', 'accent'),
      ),
      h('div', { className: 'overview-grid' },
        h('div', { className: 'card' },
          h('div', { className: 'card-header' }, h('h2', {}, `Installed standards (${benchmarks.length})`)),
          benchmarks.length
            ? h('div', { className: 'table-scroll', tabindex: '0', role: 'region', 'aria-label': 'Installed standards table' },
              h('table', { className: 'data-table' },
                h('thead', {}, h('tr', {},
                  h('th', {}, 'Standard'),
                  h('th', {}, 'Platform'),
                  h('th', {}, 'Version / Release'),
                  h('th', {}, 'Rules'),
                  h('th', {}, 'Scanner capability'),
                  h('th', {}, 'Imported'),
                )),
                h('tbody', {}, ...rows),
              ))
            : emptyState('No standards installed', 'Import a DISA XCCDF XML/ZIP or a trusted signed .stigpack to begin.'),
        ),
        h('div', { className: 'card' },
          h('div', { className: 'card-header' }, h('h2', {}, 'Content operations')),
          h('div', { className: 'stack-list' },
            actionRow('Fetch all DISA content', 'Download every catalog package after confirmation. Scanner readiness is rechecked; a newer revision may remain reference-only until its matching signed check pack is installed.', confirmFetchAllContent),
            actionRow('Check upstream catalog', 'Refresh the available DISA package catalog. Install decisions remain explicit.', checkForUpdates),
            actionRow('Browse available content', 'Inspect available DISA packages before importing.', browseAvailable),
            actionRow('Generate signed offline pack', offlinePackReady
              ? 'Use the configured external signing key to create a transferable .stigpack.'
              : offlinePackReason,
            downloadOfflinePack, { disabled: !offlineAvailable || !benchmarks.length, title: offlinePackReady ? '' : offlinePackReason }),
          ),
        ),
      ),
      h('div', { id: 'standards-operation-status', className: 'inline-status operation-status', style: 'display:none' }),
      h('div', { id: 'content-results' }),
      h('div', { id: 'content-available', className: 'card' },
        h('div', { className: 'card-header' }, h('h2', {}, 'Available content')), 
        h('div', { id: 'available-list' },
          h('p', { style: 'color: var(--text-muted); padding: 20px; text-align: center' }, 'Use Check upstream catalog or Browse available content to populate this list.'),
        ),
      ),
    );
    const workflowStandard = document.getElementById('workflow-standard-select');
    workflowStandard?.addEventListener('change', () => {
      const next = document.getElementById('workflow-standard-next');
      if (next) next.disabled = !workflowStandard.value;
      if (workflowStandard.value) updateAssessmentFlow({ benchmarkId: workflowStandard.value, step: 'standard' });
    });
  } catch (e) {
    setPage('standards', errorCard(e.message, loadStandards));
  }
}

async function loadFindings() {
  setPage('findings', loadingState());

  try {
    const { checklists, warnings: checklistWarnings } = await fetchChecklistsWithFindings();
    const findings = flattenFindings(checklists);
    const statusCounts = findings.reduce((counts, finding) => {
      const key = findingStatusKey(finding.status);
      counts[key] = (counts[key] || 0) + 1;
      return counts;
    }, { all: findings.length, open: 0, naf: 0, na: 0, nr: 0, other: 0 });
    let currentStatus = FINDINGS_VIEW_STATE.status;
    let currentSearch = FINDINGS_VIEW_STATE.search;
    let currentPage = FINDINGS_VIEW_STATE.page;
    const FINDINGS_PAGE_SIZE = 100;

    const tableBody = h('tbody', { id: 'global-findings-tbody' });
    const resultCount = h('p', { id: 'global-findings-count', className: 'field-help', role: 'status', 'aria-live': 'polite' });
    const pageLabel = h('span', { className: 'field-help', role: 'status', 'aria-live': 'polite' });
    const previousPage = h('button', {
      className: 'btn btn-secondary btn-sm',
      onClick: () => { if (currentPage > 1) { currentPage -= 1; renderGlobalFindings(); } },
    }, 'Previous');
    const nextPage = h('button', {
      className: 'btn btn-secondary btn-sm',
      onClick: () => { currentPage += 1; renderGlobalFindings(); },
    }, 'Next');
    const pagination = h('div', {
      className: 'btn-group',
      role: 'navigation',
      'aria-label': 'Findings pages',
      style: 'justify-content:center;margin-top:12px',
    }, previousPage, pageLabel, nextPage);
    const tabs = [
      ['all', 'All'], ['open', 'Open'], ['naf', 'Not a Finding'],
      ['na', 'Not Applicable'], ['nr', 'Not Reviewed'], ['other', 'Other'],
    ];

    function renderGlobalFindings() {
      const query = currentSearch.trim().toLowerCase();
      const rows = findings
        .filter(row => currentStatus === 'all' || findingStatusKey(row.status) === currentStatus)
        .filter(row => !query || [row.vulnId, row.title, row.hostname, row.benchmark, row.comments, row.details, row.source]
          .some(value => String(value || '').toLowerCase().includes(query)))
        .sort((a, b) => severityRank(b.severity) - severityRank(a.severity));
      const totalPages = Math.max(1, Math.ceil(rows.length / FINDINGS_PAGE_SIZE));
      currentPage = Math.min(Math.max(1, currentPage), totalPages);
      Object.assign(FINDINGS_VIEW_STATE, {
        status: currentStatus,
        search: currentSearch,
        page: currentPage,
      });
      const pageStart = (currentPage - 1) * FINDINGS_PAGE_SIZE;
      const pageRows = rows.slice(pageStart, pageStart + FINDINGS_PAGE_SIZE);
      tableBody.innerHTML = '';
      pageRows.forEach(row => {
        const open = () => viewChecklist(row.checklistId, 'findings', null, null, {
          selectedVulnId: row.vulnId,
          search: row.vulnId,
          status: 'all',
        });
        tableBody.appendChild(h('tr', {},
          h('td', {}, h('button', {
            className: 'table-link',
            'aria-label': `Open ${row.vulnId} for ${row.hostname}`,
            onClick: open,
          }, row.vulnId)),
          h('td', {},
            h('div', { className: 'list-title' }, row.title),
            h('div', { className: 'list-subtitle' }, row.comments || row.details || 'No analyst notes yet'),
          ),
          h('td', {}, h('span', { className: `mini-pill mini-pill-${severityTone(row.severity)}` }, row.severity)),
          h('td', {}, row.hostname),
          h('td', {}, row.benchmark),
          h('td', {}, statusBadge(row.status, row.scoreDefensible)),
          h('td', {}, findingSourceBadge(row.source)),
          h('td', {}, formatDate(row.evaluatedAt)),
        ));
      });
      const visibleStart = rows.length ? pageStart + 1 : 0;
      const visibleEnd = Math.min(pageStart + pageRows.length, rows.length);
      resultCount.textContent = `Showing ${visibleStart}–${visibleEnd} of ${rows.length} matching findings (${findings.length} total).`;
      pageLabel.textContent = `Page ${currentPage} of ${totalPages}`;
      previousPage.disabled = currentPage <= 1;
      nextPage.disabled = currentPage >= totalPages;
      pagination.style.display = rows.length > FINDINGS_PAGE_SIZE ? 'flex' : 'none';
      if (!rows.length) {
        tableBody.appendChild(h('tr', {}, h('td', { colspan: '8', style: 'text-align:center;color:var(--text-muted);padding:24px' },
          'No findings match this filter.')));
      }
    }

    setPage('findings',
      h('div', { className: 'page-header page-header-with-actions' },
        h('div', {},
          h('h1', {}, 'Findings'),
          h('p', {}, 'Review and triage checklist results across all imported and generated assessments'),
        ),
        h('div', { className: 'btn-group' },
          h('button', {
            id: 'findings-export-all',
            className: 'btn btn-secondary',
            onClick: (event) => exportAllZip(event.currentTarget),
          }, 'Export All ZIP'),
        ),
      ),
      checklistWarningsPanel(checklistWarnings),
      findings.length
        ? h('div', { className: 'card' },
            h('div', { className: 'search-bar' },
              h('label', { for: 'global-findings-search', className: 'sr-only' }, 'Search all findings'),
              h('input', {
                id: 'global-findings-search', className: 'search-input', type: 'search',
                placeholder: 'Search ID, title, asset, standard, or notes…',
                value: currentSearch,
                onInput: (event) => { currentSearch = event.target.value; currentPage = 1; renderGlobalFindings(); },
              }),
            ),
            h('div', { className: 'filter-bar status-filters', role: 'group', 'aria-label': 'Filter all findings by status' },
              ...tabs.filter(([key]) => key !== 'other' || statusCounts.other > 0).map(([key, label]) => h('button', {
                className: `filter-pill ${key === currentStatus ? (key === 'open' ? 'active-red' : key === 'naf' ? 'active-green' : 'active') : ''}`,
                'aria-pressed': String(key === currentStatus),
                onClick: (event) => {
                  currentStatus = key;
                  currentPage = 1;
                  event.currentTarget.parentElement.querySelectorAll('.filter-pill').forEach((pill) => {
                    const selected = pill === event.currentTarget;
                    pill.className = `filter-pill ${selected ? (key === 'open' ? 'active-red' : key === 'naf' ? 'active-green' : 'active') : ''}`;
                    pill.setAttribute('aria-pressed', String(selected));
                  });
                  renderGlobalFindings();
                },
              }, `${label} (${key === 'all' ? findings.length : statusCounts[key]})`)),
            ),
            resultCount,
            h('div', { className: 'table-scroll', tabindex: '0', role: 'region', 'aria-label': 'All findings table' },
            h('table', { className: 'data-table' },
              h('thead', {}, h('tr', {},
                h('th', {}, 'Vuln ID'),
                h('th', {}, 'Title'),
                h('th', {}, 'Severity'),
                h('th', {}, 'Asset'),
                h('th', {}, 'Standard'),
                h('th', {}, 'Status'),
                h('th', {}, 'Source'),
                h('th', {}, 'Updated'),
              )),
              tableBody,
            ),
            ),
            pagination,
          )
        : emptyState('No findings yet', 'Run a new assessment or import existing results to review finding status.',
            h('div', { className: 'btn-group' },
              h('button', { className: 'btn btn-primary', onClick: beginNewAssessment }, 'Run New Assessment'),
              h('button', { className: 'btn btn-secondary', onClick: importChecklistFile }, 'Import Existing Results'))),
    );
    if (findings.length) renderGlobalFindings();
  } catch (e) {
    setPage('findings', errorCard(e.message, loadFindings));
  }
}

async function loadAssetsPage() {
  setPage('assets', loadingState());

  try {
    const [assetResponse, benchmarks, checklistResponse] = await Promise.all([
      api('/assets'),
      api('/library/benchmarks'),
      api('/checklists'),
    ]);
    const { assets, warnings: assetWarnings } = normalizeAssetResponse(assetResponse);
    const { checklists, warnings: checklistWarnings } = normalizeChecklistResponse(checklistResponse);
    const flow = assessmentFlow();
    const flowBenchmark = benchmarks.find(benchmark => benchmark.id === flow?.benchmarkId);
    const flowTarget = targetForBenchmark(flowBenchmark || flow?.benchmarkId);
    const flowBenchmarkBlocked = Boolean(flow?.benchmarkId && flowBenchmark && !flowTarget);
    const flowCompatibleAssets = flowBenchmarkBlocked ? [] : assets.filter(asset => asset.enabled !== false
      && (!flowTarget || normalizePlatform(asset.platform) === flowTarget.platform));
    const checklistsById = new Map(checklists.map(checklist => [checklist.id, checklist]));
    const selected = new Set();
    const rows = assets.map(asset => {
      const latestChecklist = [...(asset.last_checklist_ids || [])]
        .reverse()
        .map(id => checklistsById.get(id))
        .find(Boolean);
      const score = latestChecklist ? checklistScore(latestChecklist) : null;
      return h('tr', { className: asset.enabled === false ? 'asset-disabled' : '', style: asset.enabled === false ? 'color:var(--text-muted)' : '' },
        h('td', {}, h('input', { type: 'checkbox', className: 'asset-check', 'data-id': asset.id, 'aria-label': `Select ${asset.name}`,
          onChange: (e) => { if (e.target.checked) selected.add(asset.id); else selected.delete(asset.id); updateBulkBar(); } })),
        h('td', {},
          h('div', { className: 'list-title' }, asset.name),
          h('div', { className: 'list-subtitle' }, `${asset.address}:${asset.port || 22}`),
        ),
        h('td', {}, asset.platform),
        h('td', {}, h('span', { className: `mini-pill mini-pill-${asset.enabled === false ? 'yellow' : 'green'}` }, asset.enabled === false ? 'Disabled' : 'Enabled')),
        h('td', {}, asset.tags?.length ? asset.tags.join(', ') : '—'),
        h('td', {}, asset.assigned_stigs?.length || 0),
        h('td', {}, score
          ? [
              h('span', { className: `mini-pill mini-pill-${scoreColor(score) || 'accent'}` }, formatAssessedPassRate(score, true)),
              ' / ',
              h('span', { className: `mini-pill mini-pill-${coverageColor(score) || 'accent'}` }, formatScorePct(score.benchmarkCoverage)),
            ]
          : '—'),
        h('td', {}, formatDate(asset.last_evaluated)),
        h('td', {}, h('div', { className: 'btn-group' },
          h('button', {
            className: 'btn btn-secondary btn-sm',
            'aria-label': `Edit ${asset.name}`,
            onClick: () => addAssetDialog(asset),
          }, 'Edit'),
          h('button', {
            className: 'btn btn-danger btn-sm',
            'aria-label': `Delete ${asset.name}`,
            onClick: (event) => deleteAsset(asset, event.currentTarget),
          }, 'Delete'),
        )),
      );
    });

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
          h('p', {}, 'Inventory view for ONTAP, FreeBSD, and Cisco IOS-XE Router NDM targets'),
        ),
        h('div', { className: 'btn-group' },
          h('button', { className: 'btn btn-primary', onClick: () => addAssetDialog() }, 'Add Asset'),
        ),
      ),
      assetWarningsPanel(assetWarnings, true),
      checklistWarningsPanel(checklistWarnings),
      flow?.active ? h('div', { className: 'card setup-panel' },
        h('div', { className: 'card-header' }, h('h2', {}, 'New assessment — Step 2 of 4')),
        h('p', { style: 'color:var(--text-secondary)' }, flowBenchmarkBlocked
          ? (flowBenchmark?.scanner_blocked_reason || 'The selected standard is reference-only and cannot run without a trusted check pack for its exact release. Return to Standards and choose a scanner-ready revision.')
          : flow?.assetId
          ? 'Compatible asset selected. Continue to choose a collection method and run the assessment.'
          : flowCompatibleAssets.length
            ? `${flowCompatibleAssets.length} compatible asset${flowCompatibleAssets.length === 1 ? ' is' : 's are'} available. Continue to select one in assessment setup.`
            : 'Add an asset matching the selected standard. You can still use a manual hostname later if inventory linking is not appropriate.'),
        h('div', { className: 'workflow-actions btn-group', style: 'margin-top:12px' },
          h('button', { className: 'btn btn-secondary', onClick: () => {
            updateAssessmentFlow({ step: 'standard' }); nav('standards');
          } }, 'Back to Standards'),
          h('button', { className: 'btn btn-secondary', onClick: () => {
            finishAssessmentFlow(); nav('assessments');
          } }, 'Cancel setup'),
          h('button', { className: 'btn btn-primary', disabled: flowBenchmarkBlocked, onClick: () => {
            updateAssessmentFlow({ step: 'collection' }); nav('assessments');
          } }, flowBenchmarkBlocked ? 'Choose a Scanner-Ready Standard' : flowCompatibleAssets.length ? 'Next: Configure Collection' : 'Continue with Manual Hostname'),
        ),
      ) : null,
      h('div', { id: 'bulk-bar', className: 'card', style: 'display:none; margin-bottom: 16px; align-items:center' },
        h('div', { className: 'page-header-with-actions' },
          h('div', {}, h('span', { id: 'bulk-count', className: 'list-title' }, '0 selected')),
          h('div', { className: 'btn-group' },
            h('button', { className: 'btn btn-secondary btn-sm', onClick: (event) => bulkAssignStig([...selected], benchmarks, assets, event.currentTarget) }, 'Assign STIG'),
            h('button', { className: 'btn btn-secondary btn-sm', onClick: (event) => bulkAddTag([...selected], event.currentTarget) }, 'Add tag'),
            h('button', { className: 'btn btn-secondary btn-sm', onClick: (event) => bulkSetEnabled([...selected], true, event.currentTarget) }, 'Enable'),
            h('button', { className: 'btn btn-secondary btn-sm', onClick: (event) => bulkSetEnabled([...selected], false, event.currentTarget) }, 'Disable'),
          ),
        ),
      ),
      assets.length
        ? h('div', { className: 'card' },
            h('div', { className: 'table-scroll', tabindex: '0', role: 'region', 'aria-label': 'Asset inventory table' },
            h('table', { className: 'data-table' },
              h('thead', {}, h('tr', {},
                h('th', {}, ''),
                h('th', {}, 'Asset'),
                h('th', {}, 'Platform'),
                h('th', {}, 'Status'),
                h('th', {}, 'Tags'),
                h('th', {}, 'Standards'),
                h('th', {}, 'Last pass / coverage'),
                h('th', {}, 'Last assessed'),
                h('th', {}, 'Actions'),
              )),
              h('tbody', {}, ...rows),
            ),
            ),
          )
        : emptyState('No assets yet', 'Add systems manually or sync them from STIG-Manager.'),
      h('div', { className: 'overview-grid' },
        h('div', { className: 'card' },
          h('div', { className: 'card-header' }, h('h2', {}, 'Asset actions')),
          h('div', { className: 'stack-list' },
            actionRow('Add asset', 'Register a host for ongoing review and assessment grouping.', () => addAssetDialog()),
            actionRow('Sync from STIG-Manager', 'Bring collections or assets into the local inventory.', syncFromStigManager),
            actionRow('Check STIG-Manager diff', 'See changes before you synchronize inventory.', checkStigManagerDiff),
          ),
        ),
      ),
    );
  } catch (e) {
    setPage('assets', errorCard(e.message, loadAssetsPage));
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

function importDisaFile() {
  chooseImportFile('.xml,.zip,application/xml,text/xml,application/zip', handleDisaImport);
}

function importChecklistFile() {
  chooseImportFile('.ckl,.cklb,.json', handleChecklistImport);
}

function importStigpackFile() {
  chooseImportFile('.stigpack', handleStigpackImport);
}

async function handleDisaImport(e) {
  const file = e.target.files?.[0];
  if (!file) return;
  const release = beginUiOperation('disa-content-write', null, 'Importing\u2026');
  if (!release) return;
  setOperationStatus('standards-operation-status', `Importing ${file.name}…`, 'info');
  try {
    const result = await apiUpload('/library/import-disa', file);
    toast(`Imported ${result.imported} reference benchmark(s)`, 'success');
    if (assessmentFlow()?.active) updateAssessmentFlow({ step: 'standard' });
    await loadStandards();
    focusPageHeading('standards');
    setOperationStatus('standards-operation-status',
      `Imported ${result.imported} DISA reference benchmark(s) from ${file.name}. Review Scanner capability below; only an exact-release trusted check pack makes a standard ready to assess.`,
      'success');
  } catch (err) {
    setOperationStatus('standards-operation-status', `Import failed: ${err.message}`, 'error',
      h('button', { className: 'btn btn-secondary btn-sm', onClick: importDisaFile }, 'Choose another file'));
    toast(err.message, 'error');
  } finally {
    release();
  }
}

async function handleChecklistImport(e) {
  const file = e.target.files?.[0];
  if (!file) return;
  const release = beginUiOperation('checklist-import', null, 'Importing\u2026');
  if (!release) return;
  const returnPage = activePageName() === 'findings' ? 'findings' : 'assessments';
  const status = currentPageOperationStatus('checklist-import-status');
  setOperationStatus(status, `Importing ${file.name}…`, 'info');
  try {
    const result = await apiUpload('/checklists/import', file);
    toast(`Imported checklist: ${result.hostname} (${result.total} rules)`, 'success');
    finishAssessmentFlow();
    await viewChecklist(result.id, returnPage);
  } catch (err) {
    setOperationStatus(status, `Import failed: ${err.message}`, 'error',
      h('button', { className: 'btn btn-secondary btn-sm', onClick: importChecklistFile }, 'Choose another file'));
    toast(err.message, 'error');
  } finally {
    release();
  }
}

async function handleStigpackImport(e) {
  const file = e.target.files?.[0];
  if (!file) return;
  const release = beginUiOperation('disa-content-write', null, 'Importing\u2026');
  if (!release) return;
  setOperationStatus('standards-operation-status', `Verifying and importing signed pack ${file.name}…`, 'info');
  try {
    const result = await apiUpload('/library/import-stigpack', file);
    toast(`Signed pack content imported (${result.imported} benchmark(s)).`, 'success');
    if (assessmentFlow()?.active) updateAssessmentFlow({ step: 'standard' });
    await loadStandards();
    focusPageHeading('standards');
    setOperationStatus('standards-operation-status',
      `Signed pack verified and imported. ${result.imported} benchmark(s); see content details below.`, 'success');
    if (result.details?.length) {
      const results = document.getElementById('content-results');
      results?.appendChild(h('div', { className: 'card', style: 'margin-top:16px' },
        h('div', { className: 'card-header' }, h('h2', {}, 'Signed pack content')),
        h('div', { style: 'max-height:240px;overflow:auto' },
          ...result.details.map(detail => h('p', { style: 'color:var(--text-secondary)' }, detail)))));
    }
  } catch (err) {
    setOperationStatus('standards-operation-status', `Signed pack import failed: ${err.message}`, 'error',
      h('button', { className: 'btn btn-secondary btn-sm', onClick: importStigpackFile }, 'Choose another pack'));
    toast(err.message, 'error');
  } finally {
    release();
  }
}

function formatDate(value) {
  if (!value) return '—';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? '—' : date.toLocaleString();
}

import { apiUnavailableMessage, endpoints, request } from './api.js';
import { createConnectionPage, getConnection } from './connection.js';
import { createContentPage } from './content.js';
import { createDeliveriesPage } from './deliveries.js';
import { createRouter, navigate } from './router.js';
import { createScanPage } from './scan.js';
import { button, h, notice, replace, toast } from './ui.js';

const MODE_KEY = 'automatestig.scanner.mode';
const session = {
  mode: storedMode(),
  connection: null,
  apiAvailable: null,
  version: null,
};

const outlet = document.getElementById('route-outlet');
const globalNotice = document.getElementById('global-notice');
const connectionChip = document.getElementById('global-connection-state');

function storedMode() {
  try {
    const value = sessionStorage.getItem(MODE_KEY);
    return value === 'connected' || value === 'disconnected' ? value : 'unselected';
  } catch (_) {
    return 'unselected';
  }
}

function getSession() {
  return { ...session, connection: session.connection ? { ...session.connection } : null };
}

function setMode(mode) {
  if (!['connected', 'disconnected', 'unselected'].includes(mode)) return;
  session.mode = mode;
  try {
    if (mode === 'unselected') sessionStorage.removeItem(MODE_KEY);
    else sessionStorage.setItem(MODE_KEY, mode);
  } catch (_) {
    // Session mode persistence is convenient but never required for safety.
  }
  renderConnectionChip();
}

function handleConnectionChange(connection) {
  session.connection = connection;
  if (connection?.configured) {
    session.apiAvailable = true;
    if (globalNotice) globalNotice.hidden = true;
    setMode('connected');
  }
  else if (session.mode === 'connected') setMode('unselected');
  renderConnectionChip();
}

const scanPage = createScanPage({ getSession, setMode, notify: toast });
const deliveriesPage = createDeliveriesPage({ notify: toast });
const contentPage = createContentPage({ notify: toast });
const connectionPage = createConnectionPage({ onConnectionChange: handleConnectionChange, notify: toast });

let activePage = null;
const router = createRouter({
  outlet,
  onRoute: route => {
    if (activePage === 'scan' && route.page !== 'scan') scanPage.abort();
    if (activePage === 'deliveries' && route.page !== 'deliveries') deliveriesPage.abort();
    activePage = route.page;
  },
  render: async route => {
    if (route.page === 'scan') return scanPage.render(outlet);
    if (route.page === 'deliveries') return deliveriesPage.render(outlet, route.id);
    if (route.page === 'content') return contentPage.render(outlet);
    if (route.page === 'connection') return connectionPage.render(outlet);
    if (route.page === 'legacy') return renderMovedWorkflow(route);
    return renderUnknownRoute(route);
  },
});

function renderMovedWorkflow(route) {
  replace(outlet,
    h('p', { className: 'page-kicker' }, 'Scanner-first transition'),
    h('h1', { tabindex: '-1' }, 'This workflow moved'),
    notice(route.guidance, 'warning'),
    h('p', {}, `${route.owner} owns this capability; AutomateSTIG does not recreate it as local compliance state.`),
    route.owner === 'Transition tooling'
      ? h('p', {}, 'Use the read-only migration inventory and create-new export from the protected transition CLI. It never changes source attribution or remote reviews.')
      : null,
    h('div', { className: 'page-actions' },
      h('a', { className: 'button button-primary', href: `#${route.destination}` }, `Open ${route.destination === 'content' ? 'Scanner Content' : route.destination === 'deliveries' ? 'Deliveries' : route.destination === 'connection' ? 'Connection' : 'Scan'}`),
      h('a', { className: 'button button-secondary', href: '#scan' }, 'Return to Scan'),
    ),
  );
}

function renderUnknownRoute(route) {
  replace(outlet,
    h('p', { className: 'page-kicker' }, 'Navigation'),
    h('h1', { tabindex: '-1' }, 'Page not found'),
    notice(`The scanner has no workspace named “${route.requested || 'unknown'}”.`, 'warning'),
    h('p', {}, 'Use one of the four scanner workspaces. Unknown links are not silently treated as a new scan.'),
    h('a', { className: 'button button-primary', href: '#scan' }, 'Open Scan'),
  );
}

async function bootstrap() {
  renderConnectionChip('Checking scanner API…', 'checking');
  // Paint the current workspace before discovery calls complete. First-open users
  // should see the destination choice immediately, even when /api/v1 is absent.
  const initialRender = router.start();
  const [statusResult, connectionResult] = await Promise.allSettled([
    request(endpoints.status, { timeoutMs: 8_000 }),
    getConnection({ timeoutMs: 8_000 }),
  ]);

  if (statusResult.status === 'fulfilled') {
    session.apiAvailable = true;
    session.version = statusResult.value?.version || statusResult.value?.scanner_version || null;
    document.querySelector('.brand-subtitle').textContent = session.version
      ? `Evidence-first scanner · ${String(session.version).startsWith('v') ? session.version : `v${session.version}`}`
      : 'Evidence-first scanner';
  } else {
    session.apiAvailable = false;
    showGlobalNotice(statusResult.reason);
  }

  if (connectionResult.status === 'fulfilled') {
    session.connection = connectionResult.value;
    if (connectionResult.value.configured && session.mode !== 'disconnected') setMode('connected');
    else if (!connectionResult.value.configured && session.mode === 'connected') setMode('unselected');
  } else if (session.mode === 'connected') {
    setMode('unselected');
  }

  renderConnectionChip();
  await initialRender;
  await router.refresh();
}

function showGlobalNotice(error) {
  if (!globalNotice) return;
  globalNotice.hidden = false;
  replace(globalNotice, notice(apiUnavailableMessage(error), 'warning', [
    button('Open Connection', { tone: 'secondary', onClick: () => navigate('connection') }),
    button('Dismiss preview notice', { tone: 'ghost', onClick: () => { globalNotice.hidden = true; } }),
  ]));
}

function renderConnectionChip(label = null, state = null) {
  if (!connectionChip) return;
  const connection = session.connection;
  let resolvedLabel = label;
  let resolvedState = state;
  if (!resolvedLabel) {
    if (session.apiAvailable === false || connection?.apiUnavailable) {
      resolvedLabel = 'Scanner API unavailable';
      resolvedState = 'unavailable';
    } else if (session.mode === 'disconnected') {
      resolvedLabel = 'Disconnected run mode';
      resolvedState = 'disconnected';
    } else if (connection?.reachable) {
      resolvedLabel = 'STIG Manager connected';
      resolvedState = 'connected';
    } else if (connection?.configured) {
      resolvedLabel = 'Connection saved · test needed';
      resolvedState = 'warning';
    } else {
      resolvedLabel = 'STIG Manager not connected';
      resolvedState = 'disconnected';
    }
  }
  connectionChip.dataset.state = resolvedState || 'disconnected';
  connectionChip.setAttribute('aria-label', resolvedLabel);
  replace(connectionChip,
    h('span', { className: 'connection-dot', 'aria-hidden': 'true' }),
    h('span', {}, resolvedLabel),
  );
}

bootstrap().catch(error => {
  session.apiAvailable = false;
  showGlobalNotice(error);
  renderConnectionChip('Scanner UI needs attention', 'unavailable');
  replace(outlet, notice(`The scanner frontend could not start: ${error?.message || error}`, 'danger'));
});

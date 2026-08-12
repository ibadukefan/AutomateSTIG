const ROUTES = Object.freeze({
  scan: 'Scan',
  deliveries: 'Deliveries',
  content: 'Scanner Content',
  connection: 'Connection',
});

const LEGACY_ROUTES = Object.freeze({
  assessments: ['STIG Manager', 'Historical assessment portfolios and human review remain in STIG Manager.', 'scan'],
  assets: ['STIG Manager', 'Asset inventory and STIG assignments remain in STIG Manager.', 'scan'],
  checklists: ['STIG Manager', 'Historical checklist import and editing remain in STIG Manager.', 'scan'],
  findings: ['STIG Manager', 'Finding analysis, overrides, acceptance, and reporting remain in STIG Manager.', 'scan'],
  'answer-files': ['Transition tooling', 'Answer files are preserved only through the read-only migration export.', 'scan'],
  export: ['STIG Manager', 'Portfolio reports and bulk exports remain in STIG Manager.', 'deliveries'],
  library: ['Release content', 'Broad library management moved out of the scanner product.', 'content'],
  standards: ['Scanner Content', 'The scanner now shows only exact release-bundled profiles.', 'content'],
  settings: ['Connection', 'Scanner and STIG Manager connection settings moved to Connection.', 'connection'],
});

export function parseHash(hash = '') {
  const raw = String(hash).replace(/^#/, '').replace(/^\//, '');
  const [path] = raw.split('?');
  const segments = path.split('/').filter(Boolean).map(decodeSafe);
  if (!segments.length) {
    return { page: 'scan', id: null, title: ROUTES.scan };
  }
  const page = segments[0];
  if (!Object.hasOwn(ROUTES, page)) {
    const legacy = LEGACY_ROUTES[page];
    if (legacy) {
      return {
        page: 'legacy',
        id: null,
        title: 'Workflow moved',
        requested: path,
        owner: legacy[0],
        guidance: legacy[1],
        destination: legacy[2],
      };
    }
    return {
      page: 'not-found',
      id: null,
      title: 'Page not found',
      requested: path,
    };
  }
  return {
    page,
    id: page === 'deliveries' && segments[1] ? segments[1] : null,
    title: ROUTES[page],
  };
}

function decodeSafe(value) {
  try { return decodeURIComponent(value); } catch (_) { return value; }
}

export function hrefFor(page, id = null) {
  if (!Object.hasOwn(ROUTES, page)) page = 'scan';
  return `#${page}${id ? `/${encodeURIComponent(id)}` : ''}`;
}

export function navigate(page, id = null, { replace = false } = {}) {
  const href = hrefFor(page, id);
  if (replace) history.replaceState(null, '', href);
  else window.location.hash = href;
  if (replace) window.dispatchEvent(new HashChangeEvent('hashchange'));
}

export function createRouter({ outlet, render, onRoute = () => {} }) {
  const route = async ({ focusHeading = false } = {}) => {
    const current = parseHash(window.location.hash);
    document.querySelectorAll('[data-route]').forEach(link => {
      const active = link.dataset.route === current.page;
      link.classList.toggle('active', active);
      if (active) link.setAttribute('aria-current', 'page');
      else link.removeAttribute('aria-current');
    });
    document.title = `AutomateSTIG Scanner — ${current.title}`;
    onRoute(current);
    await render(current, outlet);
    if (focusHeading) {
      const heading = outlet.querySelector('h1');
      heading?.focus();
    }
    const announcer = document.getElementById('route-announcer');
    if (announcer) announcer.textContent = `${current.title} workspace`;
  };
  window.addEventListener('hashchange', () => { void route({ focusHeading: true }); });
  if (!window.location.hash) history.replaceState(null, '', '#scan');
  return {
    start: () => route({ focusHeading: false }),
    refresh: () => route({ focusHeading: false }),
  };
}

export { ROUTES };

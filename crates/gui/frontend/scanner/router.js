const ROUTES = Object.freeze({
  scan: 'Scan',
  deliveries: 'Deliveries',
  content: 'Scanner Content',
  connection: 'Connection',
});

export function parseHash(hash = '') {
  const raw = String(hash).replace(/^#/, '').replace(/^\//, '');
  const [path] = raw.split('?');
  const segments = path.split('/').filter(Boolean).map(decodeSafe);
  const page = Object.hasOwn(ROUTES, segments[0]) ? segments[0] : 'scan';
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
  const route = async () => {
    const current = parseHash(window.location.hash);
    document.querySelectorAll('[data-route]').forEach(link => {
      const active = link.dataset.route === current.page;
      link.classList.toggle('active', active);
      if (active) link.setAttribute('aria-current', 'page');
      else link.removeAttribute('aria-current');
    });
    document.title = `AutomateSTIG Scanner — ${current.title}`;
    onRoute(current);
    const rendering = render(current, outlet);
    const heading = outlet.querySelector('h1');
    heading?.focus();
    const announcer = document.getElementById('route-announcer');
    if (announcer) announcer.textContent = `${current.title} workspace`;
    await rendering;
  };
  window.addEventListener('hashchange', route);
  if (!window.location.hash) history.replaceState(null, '', '#scan');
  return { start: route, refresh: route };
}

export { ROUTES };

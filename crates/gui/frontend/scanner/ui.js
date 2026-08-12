export function h(tag, attributes = {}, ...children) {
  const node = document.createElement(tag);
  for (const [name, value] of Object.entries(attributes || {})) {
    if (value == null || value === false) continue;
    if (name === 'className') node.className = value;
    else if (name === 'text') node.textContent = value;
    else if (name === 'htmlFor') node.htmlFor = value;
    else if (name.startsWith('on') && typeof value === 'function') {
      node.addEventListener(name.slice(2).toLowerCase(), value);
    } else if (name === 'dataset' && typeof value === 'object') {
      Object.assign(node.dataset, value);
    } else if (name in node && !name.startsWith('aria-') && name !== 'role') {
      try { node[name] = value; } catch (_) { node.setAttribute(name, String(value)); }
    } else {
      node.setAttribute(name, value === true ? '' : String(value));
    }
  }
  append(node, children);
  return node;
}

function append(parent, children) {
  for (const child of children.flat(Infinity)) {
    if (child == null || child === false) continue;
    parent.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
}

export function replace(target, ...children) {
  const node = typeof target === 'string' ? document.querySelector(target) : target;
  if (!node) return null;
  node.replaceChildren();
  append(node, children);
  return node;
}

export function pageHeader(eyebrow, title, description, actions = []) {
  return h('header', { className: 'page-header' },
    h('div', { className: 'page-heading' },
      h('div', { className: 'eyebrow' }, eyebrow),
      h('h1', { tabindex: '-1' }, title),
      h('p', {}, description),
    ),
    actions.length ? h('div', { className: 'header-actions' }, actions) : null,
  );
}

export function notice(message, tone = 'info', actions = []) {
  return h('div', {
    className: `notice notice-${tone}`,
    role: tone === 'danger' ? 'alert' : 'status',
  },
  h('div', { className: 'notice-message' }, message),
  actions.length ? h('div', { className: 'notice-actions' }, actions) : null);
}

export function emptyState(title, description, actions = []) {
  return h('section', { className: 'empty-state' },
    h('div', { className: 'empty-icon', 'aria-hidden': 'true' }, '↗'),
    h('h2', {}, title),
    h('p', {}, description),
    actions.length ? h('div', { className: 'button-row' }, actions) : null,
  );
}

export function loadingState(label = 'Loading…') {
  return h('div', { className: 'loading-state', role: 'status' },
    h('span', { className: 'spinner', 'aria-hidden': 'true' }),
    h('span', {}, label),
  );
}

export function button(label, {
  tone = 'secondary',
  type = 'button',
  disabled = false,
  onClick = null,
  id = null,
  className = '',
} = {}) {
  return h('button', {
    id,
    className: `button button-${tone} ${className}`.trim(),
    type,
    disabled,
    onClick,
  }, label);
}

export function linkButton(label, href, { tone = 'secondary', external = false } = {}) {
  const attributes = {
    className: `button button-${tone}`,
    href,
  };
  if (external) Object.assign(attributes, { target: '_blank', rel: 'noopener noreferrer' });
  return h('a', attributes, label);
}

export function badge(label, tone = 'neutral') {
  return h('span', { className: `badge badge-${tone}` }, label);
}

export function metric(label, value, hint = '') {
  return h('div', { className: 'metric' },
    h('span', { className: 'metric-label' }, label),
    h('strong', { className: 'metric-value' }, value ?? '—'),
    hint ? h('span', { className: 'metric-hint' }, hint) : null,
  );
}

export function definitionList(entries) {
  return h('dl', { className: 'definition-list' }, entries.flatMap(([term, value]) => [
    h('dt', {}, term),
    h('dd', {}, value ?? '—'),
  ]));
}

export function setBusy(control, busy, busyLabel = 'Working…') {
  if (!control) return;
  if (busy) {
    control.dataset.idleLabel = control.textContent;
    control.textContent = busyLabel;
    control.disabled = true;
    control.setAttribute('aria-busy', 'true');
  } else {
    control.textContent = control.dataset.idleLabel || control.textContent;
    control.disabled = false;
    control.removeAttribute('aria-busy');
    delete control.dataset.idleLabel;
  }
}

export function toast(message, tone = 'info') {
  const stack = document.getElementById('toasts');
  if (!stack) return;
  const item = h('div', { className: `toast toast-${tone}`, role: tone === 'danger' ? 'alert' : 'status' },
    h('span', {}, message),
    button('Dismiss', { className: 'toast-dismiss', onClick: () => item.remove() }),
  );
  stack.append(item);
  if (tone !== 'danger') setTimeout(() => item.remove(), 7_000);
}

export function formatDate(value) {
  if (!value) return 'Not recorded';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString();
}

export function formatPercent(value) {
  const number = Number(value);
  return Number.isFinite(number) ? `${number.toFixed(1)}%` : '—';
}

export function safeExternalUrl(value) {
  try {
    const url = new URL(String(value));
    return url.protocol === 'https:' ? url.toString() : null;
  } catch (_) {
    return null;
  }
}

export function progressSteps(activeKey, states = {}) {
  const steps = [
    ['preflight', 'Safety check'],
    ['collect', 'Collect'],
    ['evaluate', 'Evaluate'],
    ['delivery', 'Delivery'],
  ];
  const activeIndex = steps.findIndex(([key]) => key === activeKey);
  return h('ol', { className: 'progress-steps', 'aria-label': 'Run progress' },
    steps.map(([key, label], index) => {
      const explicit = states[key];
      const state = explicit || (index < activeIndex ? 'complete' : index === activeIndex ? 'active' : 'pending');
      return h('li', {
        className: `progress-step progress-${state}`,
        'aria-current': state === 'active' ? 'step' : null,
      },
      h('span', { className: 'step-marker', 'aria-hidden': 'true' }, state === 'complete' ? '✓' : index + 1),
      h('span', {}, label));
    }),
  );
}

export function field(id, label, control, help = '') {
  control.id = id;
  if (help) control.setAttribute('aria-describedby', `${id}-help`);
  return h('div', { className: 'form-field' },
    h('label', { htmlFor: id }, label),
    control,
    help ? h('p', { className: 'field-help', id: `${id}-help` }, help) : null,
  );
}

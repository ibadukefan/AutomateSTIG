import {
  apiUnavailableMessage,
  endpoints,
  hasAuthToken,
  request,
  setAuthToken,
} from './api.js';
import {
  badge,
  button,
  definitionList,
  field,
  h,
  loadingState,
  notice,
  pageHeader,
  replace,
  setBusy,
  toast,
} from './ui.js';

export function normalizeConnection(payload) {
  const value = payload?.connection || payload || {};
  return {
    configured: Boolean(value.configured),
    reachable: value.reachable == null ? null : Boolean(value.reachable),
    apiUrl: String(value.api_url || ''),
    tokenUrl: String(value.token_url || ''),
    clientId: String(value.client_id || ''),
    verifyTls: value.verify_tls !== false,
    identity: value.identity || value.username || null,
    version: value.stig_manager_version || value.version || null,
    capabilities: Array.isArray(value.capabilities) ? value.capabilities.map(String) : [],
    privileges: Array.isArray(value.privileges) ? value.privileges.map(String) : [],
    testedAt: value.tested_at || null,
  };
}

export async function getConnection(options = {}) {
  return normalizeConnection(await request(endpoints.connection, options));
}

export function createConnectionPage({ onConnectionChange = () => {}, notify = toast } = {}) {
  let latest = null;
  let generation = 0;

  async function render(outlet) {
    const current = ++generation;
    replace(outlet,
      pageHeader(
        'Authoritative destination',
        'Connection',
        'Connect one STIG Manager deployment. Device credentials remain per-run and are never stored here.',
      ),
      h('div', { id: 'connection-body' }, loadingState('Checking STIG Manager connection…')),
    );
    const body = outlet.querySelector('#connection-body');
    try {
      latest = await getConnection();
      if (current !== generation || !body?.isConnected) return;
      onConnectionChange(latest);
      replace(body, connectionLayout(latest, outlet));
    } catch (error) {
      if (current !== generation || !body?.isConnected) return;
      latest = normalizeConnection(null);
      onConnectionChange({ ...latest, apiUnavailable: true });
      replace(body,
        notice(apiUnavailableMessage(error), 'warning', [button('Retry', { onClick: () => render(outlet) })]),
        connectionLayout(latest, outlet),
      );
    }
  }

  function connectionLayout(connection, outlet) {
    return h('div', { className: 'connection-layout' },
      h('section', { className: 'card connection-status-card' },
        h('div', { className: 'section-heading' },
          h('div', {},
            h('h2', {}, 'Connection state'),
            h('p', {}, connection.configured
              ? 'Saved connection values are available to the scanner.'
              : 'No STIG Manager connection is configured.'),
          ),
          badge(connection.reachable ? 'Connected' : connection.configured ? 'Saved · not tested' : 'Not connected',
            connection.reachable ? 'success' : connection.configured ? 'warning' : 'neutral'),
        ),
        definitionList([
          ['API', connection.apiUrl || 'Not configured'],
          ['Connected identity', connection.identity || 'Not tested'],
          ['STIG Manager version', connection.version || 'Not discovered'],
          ['Capabilities', connection.capabilities.length ? connection.capabilities.join(', ') : 'Not discovered'],
          ['Privileges', connection.privileges.length ? connection.privileges.join(', ') : 'Not discovered'],
        ]),
      ),
      connectionForm(connection, outlet),
    );
  }

  function connectionForm(connection, outlet) {
    const accessToken = h('input', {
      type: 'password',
      autocomplete: 'off',
      placeholder: hasAuthToken() ? 'Token available in this tab' : 'Deployment access token',
    });
    const apiUrl = h('input', { type: 'url', value: connection.apiUrl, placeholder: 'https://stigman.example.mil/api', autocomplete: 'off', required: true });
    const tokenUrl = h('input', { type: 'url', value: connection.tokenUrl, placeholder: 'https://sso.example.mil/realms/stigman/protocol/openid-connect/token', autocomplete: 'off', required: true });
    const clientId = h('input', { type: 'text', value: connection.clientId, autocomplete: 'off', required: true });
    const clientSecret = h('input', { type: 'password', autocomplete: 'new-password', placeholder: connection.configured ? 'Leave blank to keep saved secret' : 'Client secret', required: !connection.configured });
    const result = h('div', { className: 'operation-result', role: 'status', 'aria-live': 'polite' });

    const body = () => ({
      api_url: apiUrl.value.trim(),
      token_url: tokenUrl.value.trim(),
      client_id: clientId.value.trim(),
      client_secret: clientSecret.value,
      // The scanner API has no browser-selectable insecure mode. Lab TLS
      // exceptions belong at the deployment boundary, not in this form.
      verify_tls: true,
    });

    const applyAccessToken = () => {
      if (!accessToken.value) return;
      setAuthToken(accessToken.value);
      accessToken.value = '';
    };

    const testAndSave = button('Test and save connection', { tone: 'primary', onClick: async event => {
      const control = event.currentTarget;
      if (!apiUrl.reportValidity() || !tokenUrl.reportValidity() || !clientId.reportValidity() || !clientSecret.reportValidity()) return;
      setBusy(control, true, 'Testing…');
      replace(result, notice('Testing authentication, API capability, and privileges…'));
      try {
        applyAccessToken();
        const settings = body();
        const tested = normalizeConnection(await request(endpoints.connectionTest, { method: 'POST', body: settings }));
        setBusy(control, true, 'Saving…');
        const saved = normalizeConnection(await request(endpoints.connection, { method: 'PUT', body: settings }));
        latest = { ...saved, reachable: true, identity: tested.identity, version: tested.version,
          capabilities: tested.capabilities, privileges: tested.privileges, testedAt: tested.testedAt };
        onConnectionChange(latest);
        replace(result, notice(`Connected${tested.identity ? ` as ${tested.identity}` : ''} and saved.`, 'success'));
        notify('STIG Manager connection tested and saved.', 'success');
        window.location.hash = '#scan';
      } catch (error) {
        replace(result, notice(apiUnavailableMessage(error), 'danger'));
      } finally {
        clientSecret.value = '';
        setBusy(control, false);
      }
    }});

    const disconnect = button('Disconnect', { tone: 'danger', disabled: !connection.configured, onClick: async event => {
      const control = event.currentTarget;
      if (!window.confirm('Disconnect this STIG Manager configuration? Remote data will not be changed.')) return;
      setBusy(control, true, 'Disconnecting…');
      try {
        await request(endpoints.connection, { method: 'DELETE' });
        latest = normalizeConnection(null);
        onConnectionChange(latest);
        notify('STIG Manager connection removed.', 'success');
        await render(outlet);
      } catch (error) {
        replace(result, notice(apiUnavailableMessage(error), 'danger'));
      } finally {
        setBusy(control, false);
      }
    }});

    return h('form', { className: 'card connection-form', onSubmit: event => event.preventDefault() },
      h('div', { className: 'section-heading' },
        h('div', {}, h('h2', {}, 'STIG Manager settings'), h('p', {}, 'HTTPS is required. The connection is saved only after authentication, API capability, and privilege tests pass.')),
      ),
      field('scanner-access-token', 'AutomateSTIG access token (optional)', accessToken,
        'Needed for protected non-loopback deployments. Kept only in this tab and never written to browser storage.'),
      h('div', { className: 'form-grid' },
        field('sm-api-url-v1', 'STIG Manager API URL', apiUrl),
        field('sm-token-url-v1', 'OAuth token URL', tokenUrl),
        field('sm-client-id-v1', 'Client ID', clientId),
        field('sm-client-secret-v1', 'Client secret', clientSecret, 'Cleared from the form after every request.'),
      ),
      notice('TLS certificate verification is always enforced by the scanner.', 'info'),
      h('div', { className: 'button-row' }, testAndSave, disconnect),
      result,
    );
  }

  return { render, get latest() { return latest; } };
}

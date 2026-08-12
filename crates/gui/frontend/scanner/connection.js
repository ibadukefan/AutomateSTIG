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
    guiUrl: String(value.gui_url || ''),
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

export function normalizeRetention(payload) {
  const value = payload?.retention || payload || {};
  const replay = value.replay_evidence || {};
  const operational = value.operational_history || {};
  return {
    replay: {
      days: Number(replay.effective_days),
      source: String(replay.source || 'unknown'),
      editable: replay.editable !== false,
      minimum: Number(replay.minimum_days) || 1,
      maximum: Number(replay.maximum_days) || 365,
      appliesTo: String(replay.applies_to || ''),
      existingUnchanged: replay.existing_expirations_unchanged === true,
    },
    operational: {
      days: Number(operational.effective_days),
      source: String(operational.source || 'unknown'),
      editable: operational.editable !== false,
      minimum: Number(operational.minimum_days) || 1,
      maximum: Number(operational.maximum_days) || 365,
      appliesTo: String(operational.applies_to || ''),
    },
    nextSweep: value.sweeper?.next_sweep_not_later_than || null,
    sweepCondition: String(value.sweeper?.condition || ''),
  };
}

export function normalizeTargetProfiles(payload) {
  const values = Array.isArray(payload) ? payload : Array.isArray(payload?.profiles) ? payload.profiles : [];
  return values.map(value => ({
    id: String(value.id || ''),
    scannerProfileId: String(value.scanner_profile_id || ''),
    adapter: String(value.adapter || ''),
    endpoint: String(value.endpoint || ''),
    port: Number(value.port),
    credentialReference: value.credential_reference == null ? null : String(value.credential_reference),
    fingerprint: value.last_observed_fingerprint == null ? null : String(value.last_observed_fingerprint),
    operationalState: value.recent_operational_state == null ? null : String(value.recent_operational_state),
    observedAt: value.observed_at || null,
  })).filter(value => value.id);
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
      const [connection, retentionResult, profileResult] = await Promise.all([
        getConnection(),
        request(endpoints.retention).catch(error => ({ loadError: error })),
        request(endpoints.connectionProfiles).catch(error => ({ loadError: error })),
      ]);
      latest = connection;
      if (current !== generation || !body?.isConnected) return;
      onConnectionChange(latest);
      replace(body, connectionLayout(latest, outlet, retentionResult, profileResult));
    } catch (error) {
      if (current !== generation || !body?.isConnected) return;
      latest = normalizeConnection(null);
      onConnectionChange({ ...latest, apiUnavailable: true });
      replace(body,
        notice(apiUnavailableMessage(error), 'warning', [button('Retry', { onClick: () => render(outlet) })]),
        connectionLayout(latest, outlet, { loadError: error }, { loadError: error }),
      );
    }
  }

  function connectionLayout(connection, outlet, retentionResult, profileResult) {
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
          ['GUI base URL', connection.guiUrl || 'Required before remote no-op verification'],
          ['Connected identity', connection.identity || 'Not tested'],
          ['STIG Manager version', connection.version || 'Not discovered'],
          ['Capabilities', connection.capabilities.length ? connection.capabilities.join(', ') : 'Not discovered'],
          ['Observed access', connection.privileges.length ? connection.privileges.join(', ') : 'Not tested'],
        ]),
      ),
      connectionForm(connection, outlet),
      retentionPolicyPanel(retentionResult, outlet),
      savedTargetProfilesPanel(profileResult, outlet),
    );
  }

  function connectionForm(connection, outlet) {
    const accessToken = h('input', {
      type: 'password',
      autocomplete: 'off',
      placeholder: hasAuthToken() ? 'Token available in this tab' : 'Deployment access token',
    });
    const apiUrl = h('input', { type: 'url', value: connection.apiUrl, placeholder: 'https://stigman.example.mil/api', autocomplete: 'off', required: true });
    const guiUrl = h('input', { type: 'url', value: connection.guiUrl, placeholder: 'https://stigman.example.mil/', autocomplete: 'off', required: true });
    const tokenUrl = h('input', { type: 'url', value: connection.tokenUrl, placeholder: 'https://sso.example.mil/realms/stigman/protocol/openid-connect/token', autocomplete: 'off', required: true });
    const clientId = h('input', { type: 'text', value: connection.clientId, autocomplete: 'off', required: true });
    const clientSecret = h('input', { type: 'password', autocomplete: 'new-password', placeholder: connection.configured ? 'Leave blank to keep saved secret' : 'Client secret', required: !connection.configured });
    const result = h('div', { className: 'operation-result', role: 'status', 'aria-live': 'polite' });

    const body = () => ({
      api_url: apiUrl.value.trim(),
      gui_url: guiUrl.value.trim(),
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
      if (!apiUrl.reportValidity() || !guiUrl.reportValidity() || !tokenUrl.reportValidity() || !clientId.reportValidity() || !clientSecret.reportValidity()) return;
      setBusy(control, true, 'Testing…');
      replace(result, notice('Testing authentication, supported API capability, and collection-read access…'));
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
        h('div', {}, h('h2', {}, 'STIG Manager settings'), h('p', {}, 'HTTPS is required. This test proves authentication, the supported API contract, and collection-read access only. Asset and assignment reads are checked later; no write or broader privilege is inferred.')),
      ),
      field('scanner-access-token', 'AutomateSTIG access token (optional)', accessToken,
        'Needed for protected non-loopback deployments. Kept only in this tab and never written to browser storage.'),
      h('div', { className: 'form-grid' },
        field('sm-api-url-v1', 'STIG Manager API URL', apiUrl),
        field('sm-gui-url-v1', 'STIG Manager GUI base URL', guiUrl, 'Credential-free HTTPS base URL ending in /. AutomateSTIG intentionally does not create asset or review deep links.'),
        field('sm-token-url-v1', 'OAuth token URL', tokenUrl),
        field('sm-client-id-v1', 'Client ID', clientId),
        field('sm-client-secret-v1', 'Client secret', clientSecret, 'Cleared from the form after every request.'),
      ),
      notice('TLS certificate verification is always enforced by the scanner.', 'info'),
      h('div', { className: 'button-row' }, testAndSave, disconnect),
      result,
    );
  }

  function retentionPolicyPanel(result, outlet) {
    if (result?.loadError) {
      return h('section', { className: 'card retention-policy-card' },
        h('h2', {}, 'Scanner retention'),
        notice(apiUnavailableMessage(result.loadError), 'warning'),
      );
    }
    const policy = normalizeRetention(result);
    const replay = h('input', {
      type: 'number', min: policy.replay.minimum, max: policy.replay.maximum,
      value: Number.isFinite(policy.replay.days) ? policy.replay.days : '',
      required: true,
      disabled: !policy.replay.editable,
    });
    const operational = h('input', {
      type: 'number', min: policy.operational.minimum, max: policy.operational.maximum,
      value: Number.isFinite(policy.operational.days) ? policy.operational.days : '',
      required: true,
      disabled: !policy.operational.editable,
    });
    const status = h('div', { className: 'operation-result', role: 'status', 'aria-live': 'polite' });
    const save = button('Save retention policy', { tone: 'primary', onClick: async event => {
      if ((!replay.disabled && !replay.reportValidity()) || (!operational.disabled && !operational.reportValidity())) return;
      const control = event.currentTarget;
      setBusy(control, true, 'Saving…');
      try {
        await request(endpoints.retention, {
          method: 'PUT',
          body: {
            replay_evidence_days: Number(replay.value),
            operational_history_days: Number(operational.value),
          },
        });
        notify('Scanner retention policy saved.', 'success');
        await render(outlet);
      } catch (error) {
        replace(status, notice(apiUnavailableMessage(error), 'danger'));
      } finally {
        setBusy(control, false);
      }
    }});
    save.disabled = !policy.replay.editable && !policy.operational.editable;
    return h('section', { className: 'card retention-policy-card' },
      h('div', { className: 'section-heading' },
        h('div', {}, h('h2', {}, 'Scanner retention'), h('p', {}, 'Effective replay and short-lived operational-history policy for this scanner deployment.')),
        badge('Operational policy', 'neutral'),
      ),
      h('div', { className: 'form-grid' },
        field('retention-replay-days-v1', 'Replay evidence and checkpoints (days)', replay,
          `${policy.replay.source} source${policy.replay.editable ? '' : ' · deployment environment override; change it outside the browser'}. Applies only to newly sealed evidence and checkpoints; existing expiry dates do not change.`),
        field('retention-operational-days-v1', 'Receipt-gated operational history (days)', operational,
          `${policy.operational.source} source${policy.operational.editable ? '' : ' · deployment environment override; change it outside the browser'}. Eligible terminal records are pruned only by the next bounded sweep.`),
      ),
      notice(`Saving is not an immediate or retroactive purge. Next sweep is no later than ${policy.nextSweep ? new Date(policy.nextSweep).toLocaleString() : 'the configured interval'} ${policy.sweepCondition || 'while the server remains running'}.`, 'info'),
      h('div', { className: 'button-row' }, save),
      status,
    );
  }

  function savedTargetProfilesPanel(result, outlet) {
    if (result?.loadError) {
      return h('section', { className: 'card target-profile-manager' },
        h('h2', {}, 'Saved target profiles'),
        notice(apiUnavailableMessage(result.loadError), 'warning'),
      );
    }
    const profiles = normalizeTargetProfiles(result);
    return h('section', { className: 'card target-profile-manager' },
      h('div', { className: 'section-heading' },
        h('div', {},
          h('h2', {}, 'Saved target profiles'),
          h('p', {}, 'Thin reconnect coordinates only. These records contain no credentials and no STIG Manager asset, assignment, or review data.'),
        ),
        badge(`${profiles.length} saved`, 'neutral'),
      ),
      profiles.length
        ? h('div', { className: 'target-profile-list' }, profiles.map(profile => targetProfileEditor(profile, outlet)))
        : notice('No target coordinates are saved. Save an endpoint from the Scan workspace when it is useful to reconnect.', 'info'),
    );
  }

  function targetProfileEditor(profile, outlet) {
    const endpoint = h('input', { type: 'text', value: profile.endpoint, autocomplete: 'off', required: true, disabled: true });
    const port = h('input', { type: 'number', min: 1, max: 65535, value: profile.port, required: true, disabled: true });
    const status = h('div', { className: 'operation-result', role: 'status', 'aria-live': 'polite' });
    const save = button('Save coordinates', { tone: 'primary', disabled: true });
    const edit = button('Edit', { tone: 'secondary', onClick: () => {
      endpoint.disabled = false;
      port.disabled = false;
      save.disabled = false;
      endpoint.focus();
    }});
    save.addEventListener('click', async event => {
      if (!endpoint.reportValidity() || !port.reportValidity()) return;
      const control = event.currentTarget;
      setBusy(control, true, 'Saving…');
      try {
        await request(endpoints.connectionProfile(profile.id), {
          method: 'PUT',
          body: {
            scanner_profile_id: profile.scannerProfileId,
            adapter: profile.adapter,
            endpoint: endpoint.value.trim(),
            port: Number(port.value),
            credential_reference: profile.credentialReference,
          },
        });
        notify('Saved target coordinates updated.', 'success');
        await render(outlet);
      } catch (error) {
        replace(status, notice(apiUnavailableMessage(error), 'danger'));
      } finally {
        setBusy(control, false);
      }
    });
    const remove = button('Delete', { tone: 'danger', onClick: async event => {
      if (!window.confirm(`Delete saved target coordinates for ${profile.endpoint}:${profile.port}?`)) return;
      const control = event.currentTarget;
      setBusy(control, true, 'Deleting…');
      try {
        await request(endpoints.connectionProfile(profile.id), { method: 'DELETE' });
        notify('Saved target coordinates deleted.', 'success');
        await render(outlet);
      } catch (error) {
        replace(status, notice(apiUnavailableMessage(error), 'danger'));
      } finally {
        setBusy(control, false);
      }
    }});
    return h('article', { className: 'target-profile-row' },
      h('div', { className: 'section-heading' },
        h('div', {}, h('h3', {}, `${profile.endpoint}:${profile.port}`), h('p', {}, `${profile.scannerProfileId} · ${profile.adapter}`)),
        badge(profile.operationalState || 'No recent observation', profile.operationalState === 'ready' ? 'success' : 'neutral'),
      ),
      h('div', { className: 'form-grid' },
        field(`target-profile-${profile.id}-endpoint`, 'Endpoint', endpoint),
        field(`target-profile-${profile.id}-port`, 'Port', port),
      ),
      definitionList([
        ['Observed fingerprint', profile.fingerprint || 'Not observed'],
        ['Observed', profile.observedAt ? new Date(profile.observedAt).toLocaleString() : 'Not observed'],
      ]),
      h('div', { className: 'button-row' }, edit, save, remove),
      status,
    );
  }

  return { render, get latest() { return latest; } };
}

import {
  ApiError,
  apiUnavailableMessage,
  download,
  endpoints,
  pollScanJob,
  pollRun,
  request,
} from './api.js';
import { loadProfiles } from './content.js';
import { deliverRun, normalizeRun, renderRunPreview } from './deliveries.js';
import { hrefFor } from './router.js';
import {
  badge,
  button,
  definitionList,
  emptyState,
  field,
  h,
  loadingState,
  notice,
  pageHeader,
  progressSteps,
  replace,
  setBusy,
  toast,
} from './ui.js';

export function normalizeCollections(payload) {
  const values = Array.isArray(payload) ? payload : payload?.collections || [];
  return values.map(value => ({
    raw: value,
    id: String(value.collection_id || value.collectionId || value.id || ''),
    name: String(value.name || value.title || value.collection_id || value.id || 'Unnamed collection'),
    description: String(value.description || ''),
  })).filter(value => value.id);
}

export function normalizeAssets(payload) {
  const values = Array.isArray(payload) ? payload : payload?.assets || [];
  return values.map(value => ({
    raw: value,
    id: String(value.asset_id || value.assetId || value.id || ''),
    name: String(value.name || value.hostname || value.asset_id || value.id || 'Unnamed asset'),
    fqdn: String(value.fqdn || ''),
    ip: String(value.ip || value.ip_address || ''),
  })).filter(value => value.id);
}

export function normalizeAssignments(payload, profiles = []) {
  const values = Array.isArray(payload) ? payload : payload?.assignments || payload?.stigs || [];
  return values.map(value => {
    const stigId = String(value.stig_id || value.benchmark_id || value.benchmarkId || value.id || '');
    const revision = String(value.stig_revision || value.last_revision_str || value.lastRevisionStr || value.revision || '');
    const profileId = String(value.profile_id || '');
    const profile = profiles.find(candidate => profileId
      ? candidate.id === profileId
      : candidate.stigId === stigId && (!revision || candidate.revision === revision));
    const exactStig = !profile || !stigId || profile.stigId === stigId;
    const exactRevision = !profile || !revision || profile.revision === revision;
    const explicitReady = value.pilot_runnable ?? value.scanner_ready ?? value.ready;
    const scannerReady = explicitReady === false
      ? false
      : Boolean(profile?.scannerReady && exactStig && exactRevision);
    const mismatchReason = profile && (!exactStig || !exactRevision)
      ? `Assigned ${stigId || 'STIG'}${revision ? ` ${revision}` : ''} does not exactly match scanner profile ${profile.stigId} ${profile.revision}.`
      : '';
    const reason = String(value.unsupported_reason || value.blocked_reason || value.reason
      || mismatchReason
      || profile?.reason
      || (!profile ? `No release-bundled scanner profile matches ${stigId}${revision ? ` ${revision}` : ''}.` : '')
      || (!profile.scannerReady ? 'The matching scanner profile is not ready.' : ''));
    return {
      raw: value,
      id: String(value.assignment_id || value.assignmentId || value.id || `${stigId}:${revision}`),
      stigId,
      revision,
      title: String(value.title || value.stig_title || stigId || 'Assigned STIG'),
      profileId: profile?.id || profileId,
      profile,
      scannerReady,
      reason,
    };
  }).filter(value => value.id);
}

export function createScanPage({
  getSession,
  setMode,
  notify = toast,
} = {}) {
  let generation = 0;
  let controller = null;
  let activeRunController = null;

  function begin() {
    controller?.abort();
    activeRunController?.abort();
    controller = new AbortController();
    generation += 1;
    return { generation, signal: controller.signal };
  }

  async function render(outlet) {
    const current = begin();
    const session = getSession();
    if (session.mode === 'unselected') {
      renderWelcome(outlet);
      return;
    }

    replace(outlet,
      pageHeader(
        session.mode === 'connected' ? 'Connected scanner workflow' : 'Offline-capable scanner workflow',
        'Scan',
        session.mode === 'connected'
          ? 'Choose an authoritative STIG Manager destination before collecting any evidence.'
          : 'Collect and evaluate without a remote destination, then create a selected-run handoff.',
        [button(session.mode === 'connected' ? 'Run disconnected' : 'Connect STIG Manager', {
          tone: 'secondary',
          onClick: () => {
            if (session.mode === 'connected') {
              setMode('disconnected');
              const rendering = render(outlet);
              focusWorkspaceHeading(outlet);
              return rendering;
            } else {
              window.location.hash = hrefFor('connection');
            }
          },
        })],
      ),
      h('div', { id: 'scan-body' }, loadingState('Loading scanner profiles…')),
    );
    const body = outlet.querySelector('#scan-body');
    try {
      const [profiles, collections, connectionProfiles] = await Promise.all([
        loadProfiles({ signal: current.signal }),
        session.mode === 'connected'
          ? request(endpoints.collections, { signal: current.signal }).then(normalizeCollections)
          : Promise.resolve([]),
        request(endpoints.connectionProfiles, { signal: current.signal })
          .then(payload => Array.isArray(payload) ? payload : payload?.profiles || [])
          // Saved target profiles are an optional local convenience. A
          // transient read failure must not block fresh-credential scanning.
          .catch(() => []),
      ]);
      if (current.generation !== generation || !body?.isConnected) return;
      const readyProfiles = profiles.filter(profile => profile.scannerReady);
      if (!readyProfiles.length) {
        replace(body, emptyState(
          'No runnable scanner profiles',
          'Open Scanner Content for exact revision, trust, and tested-version details.',
          [h('a', { className: 'button button-primary', href: hrefFor('content') }, 'View Scanner Content')],
        ));
        return;
      }
      if (session.mode === 'connected' && !collections.length) {
        replace(body,
          notice('The connection returned no available collections. Confirm the service account privileges or run disconnected.', 'warning'),
          h('div', { className: 'button-row' },
            h('a', { className: 'button button-secondary', href: hrefFor('connection') }, 'Check Connection'),
            button('Run disconnected', { tone: 'primary', onClick: () => { setMode('disconnected'); render(outlet); } }),
          ),
        );
        return;
      }
      replace(body, buildWorkspace({ outlet, body, session, profiles, readyProfiles, collections, connectionProfiles }));
    } catch (error) {
      if (current.generation !== generation || !body?.isConnected) return;
      replace(body,
        notice(apiUnavailableMessage(error), 'warning', [button('Retry', { onClick: () => render(outlet) })]),
        session.mode === 'connected' ? h('div', { className: 'button-row' },
          h('a', { className: 'button button-secondary', href: hrefFor('connection') }, 'Open Connection'),
          button('Run disconnected', { tone: 'primary', onClick: () => { setMode('disconnected'); render(outlet); } }),
        ) : null,
      );
    }
  }

  function renderWelcome(outlet) {
    replace(outlet,
      pageHeader(
        'First open',
        'Where should this run go?',
        'AutomateSTIG produces defensible scanner evidence. STIG Manager remains the system of record for assets, human review, and reporting.',
      ),
      h('div', { className: 'choice-grid first-open-choices' },
        h('section', { className: 'choice-card choice-primary' },
          badge('Recommended', 'accent'),
          h('h2', {}, 'Connect to STIG Manager'),
          h('p', {}, 'Select a live collection, existing asset, and exact assigned STIG revision with a matching scanner profile before collection.'),
          h('ul', {},
            h('li', {}, 'Use existing assets and assignments only'),
            h('li', {}, 'Changed reviews use a selected-run handoff'),
            h('li', {}, 'Continue review in STIG Manager'),
          ),
          h('a', { className: 'button button-primary', href: hrefFor('connection') }, 'Connect to STIG Manager'),
        ),
        h('section', { className: 'choice-card' },
          badge('Air-gap path', 'neutral'),
          h('h2', {}, 'Run disconnected'),
          h('p', {}, 'Scan and evaluate locally, then prepare one selected-run evidence handoff. No local portfolio is created.'),
          h('ul', {},
            h('li', {}, 'Same fail-closed collection rules'),
            h('li', {}, 'Evidence and provenance remain bound'),
            h('li', {}, 'Verify the handoff before your approved reconciliation workflow'),
          ),
          button('Run disconnected', { tone: 'secondary', onClick: () => {
            setMode('disconnected');
            const rendering = render(outlet);
            focusWorkspaceHeading(outlet);
            return rendering;
          } }),
        ),
      ),
      readinessPanel('unselected'),
      h('section', { className: 'card training-card' },
        h('div', { className: 'section-heading' },
          h('div', {},
            h('p', { className: 'card-kicker' }, 'No device required'),
            h('h2', {}, 'Preview the analyst workflow'),
            h('p', {}, 'Open a synthetic, read-only result to learn the review and handoff steps. It is never saved and cannot be delivered.'),
          ),
          badge('Training only', 'neutral'),
        ),
        button('Open sample result', { tone: 'secondary', onClick: () => {
          renderSampleWalkthrough(outlet);
          focusWorkspaceHeading(outlet);
        } }),
      ),
    );
  }

  function renderSampleWalkthrough(outlet) {
    const sample = trainingRun();
    replace(outlet,
      pageHeader(
        'Training walkthrough',
        'See the result before touching a device',
        'This browser-only example shows what an analyst reviews after collection. It creates no run, makes no network request, and cannot produce a handoff.',
        [button('Back to start', { tone: 'secondary', onClick: () => {
          renderWelcome(outlet);
          focusWorkspaceHeading(outlet);
        } })],
      ),
      notice('Training data only — do not use this page as assessment evidence.', 'warning'),
      readinessPanel('training'),
      renderRunPreview(sample, { embedded: true }),
    );
  }

  function buildWorkspace({ outlet, body, session, profiles, readyProfiles, collections, connectionProfiles }) {
    let assets = [];
    let assignments = [];
    let preflight = null;
    let preflightRevision = 0;

    const progress = h('div', { className: 'run-progress-panel' }, progressSteps('preflight'));
    const destinationStatus = h('div', { className: 'operation-result', role: 'status', 'aria-live': 'polite' });
    const unsupportedStatus = h('div', { className: 'unsupported-list' });
    const preflightOutput = h('div', { className: 'operation-result', role: 'status', 'aria-live': 'polite' });
    const runOutput = h('div', { className: 'run-output', 'aria-live': 'polite' });
    const collectionSelect = h('select', {}, h('option', { value: '' }, 'Select a collection…'),
      collections.map(collection => h('option', { value: collection.id }, collection.name)));
    const assetSelect = h('select', { disabled: true }, h('option', { value: '' }, 'Select a collection first…'));
    const assignmentSelect = h('select', { disabled: true }, h('option', { value: '' }, 'Select an asset first…'));
    const profileSelect = h('select', {}, h('option', { value: '' }, 'Select a scanner profile…'),
      readyProfiles.map(profile => h('option', { value: profile.id }, `${profile.target} · ${profile.revision}`)));
    const methodSelect = h('select', { disabled: true }, h('option', { value: '' }, 'Select a profile first…'));
    const endpointInput = h('input', { type: 'text', autocomplete: 'off', placeholder: 'device.example.mil' });
    const portInput = h('input', { type: 'number', min: 1, max: 65535, value: 22 });
    const savedTargetSelect = h('select', {},
      h('option', { value: '' }, 'Do not use a saved target profile'),
      connectionProfiles.map(profile => h('option', { value: profile.id }, `${profile.endpoint}:${profile.port} · ${profile.scanner_profile_id}`)),
    );
    const savedTargetStatus = h('div', { className: 'operation-result', role: 'status', 'aria-live': 'polite' });
    const credentialType = h('select', {},
      h('option', { value: 'password' }, 'One-time password'),
      h('option', { value: 'key_file' }, 'Approved private-key file'));
    const usernameInput = h('input', { type: 'text', autocomplete: 'off' });
    const passwordInput = h('input', { type: 'password', autocomplete: 'off' });
    const keyPathInput = h('input', { type: 'text', autocomplete: 'off', placeholder: '/approved/path/id_ed25519' });
    const keyPassphraseInput = h('input', { type: 'password', autocomplete: 'off' });
    const evidenceInput = h('input', { type: 'file', accept: '.json,application/json' });
    const policyInput = h('input', { type: 'file', accept: '.json,application/json' });
    const signatureInput = h('input', { type: 'file', accept: '.sig,application/octet-stream' });
    const sshFields = h('div', { className: 'method-panel', hidden: true });
    const evidenceFields = h('div', { className: 'method-panel', hidden: true });
    const policyFields = h('div', { className: 'method-panel', hidden: true });
    const credentialsFields = h('div', { className: 'credential-fields' });
    const methodStatus = h('div', { className: 'operation-result', role: 'status', 'aria-live': 'polite' });
    const pilotAcknowledgement = h('input', { type: 'checkbox' });
    const runButton = button('Collect and evaluate', { tone: 'primary', disabled: true });
    const preflightButton = button('Check readiness', { tone: 'primary', disabled: true });

    const selectedProfile = () => {
      if (session.mode === 'connected') {
        return assignments.find(value => value.id === assignmentSelect.value)?.profile || null;
      }
      return profiles.find(value => value.id === profileSelect.value) || null;
    };

    const selectedMethod = () => methodSelect.value;
    const selectedCollection = () => collections.find(value => value.id === collectionSelect.value) || null;
    const selectedAsset = () => assets.find(value => value.id === assetSelect.value) || null;
    const selectedAssignment = () => assignments.find(value => value.id === assignmentSelect.value) || null;
    const selectedConnectionProfile = () => connectionProfiles.find(value => value.id === savedTargetSelect.value) || null;

    const invalidatePreflight = () => {
      preflightRevision += 1;
      preflight = null;
      runButton.disabled = true;
      replace(preflightOutput);
      replace(runOutput);
      replace(progress, progressSteps('preflight'));
      updatePreflightReady();
    };

    const updatePreflightReady = () => {
      const destinationReady = session.mode === 'disconnected'
        || Boolean(collectionSelect.value && assetSelect.value && assignmentSelect.value);
      const profileReady = Boolean(selectedProfile());
      const acceptanceReady = Boolean(selectedProfile()?.releaseSupported || pilotAcknowledgement.checked);
      const method = selectedMethod();
      const methodReady = method === 'ssh'
        ? Boolean(endpointInput.value.trim() && usernameInput.value.trim() && validCredential())
        : Boolean(evidenceInput.files?.[0]);
      const policyReady = method !== 'configuration' || Boolean(policyInput.files?.[0] && signatureInput.files?.[0]);
      preflightButton.disabled = !(destinationReady && profileReady && acceptanceReady && methodReady && policyReady);
    };

    savedTargetSelect.addEventListener('change', () => {
      const saved = selectedConnectionProfile();
      if (saved) {
        endpointInput.value = String(saved.endpoint || '');
        portInput.value = String(saved.port || 22);
        replace(savedTargetStatus, notice('Saved target coordinates applied. Fresh credentials are still required; the opaque credential reference is metadata only because no provider is configured.', 'info'));
      } else {
        replace(savedTargetStatus);
      }
      invalidatePreflight();
    });

    const saveTargetProfile = button('Save target profile', { tone: 'secondary', onClick: async event => {
      const profile = selectedProfile();
      if (!profile || selectedMethod() !== 'ssh' || !endpointInput.value.trim()) {
        replace(savedTargetStatus, notice('Select an SSH scanner profile and enter a target endpoint before saving a thin target profile.', 'warning'));
        return;
      }
      setBusy(event.currentTarget, true, 'Saving…');
      try {
        const saved = await request(endpoints.connectionProfiles, {
          method: 'POST',
          body: {
            scanner_profile_id: profile.id,
            adapter: profile.adapterId,
            endpoint: endpointInput.value.trim(),
            port: Number(portInput.value || 22),
          },
        });
        const profileRecord = saved?.profile || saved;
        if (profileRecord?.id) {
          connectionProfiles.push(profileRecord);
          replace(savedTargetSelect,
            h('option', { value: '' }, 'Do not use a saved target profile'),
            connectionProfiles.map(value => h('option', { value: value.id }, `${value.endpoint}:${value.port} · ${value.scanner_profile_id}`)),
          );
          savedTargetSelect.value = profileRecord.id;
        }
        replace(savedTargetStatus, notice('Saved thin target profile. It contains endpoint, port, adapter, and optional opaque credential-reference metadata only; no credential was saved.', 'success'));
      } catch (error) {
        replace(savedTargetStatus, notice(apiUnavailableMessage(error), 'danger'));
      } finally {
        setBusy(event.currentTarget, false);
      }
    }});

    const validCredential = () => {
      if (credentialType.value === 'password') return Boolean(passwordInput.value);
      if (credentialType.value === 'key_file') return absolutePath(keyPathInput.value);
      return false;
    };

    const updateCredentialFields = () => {
      replace(credentialsFields,
        field('scan-username-v1', 'Username', usernameInput),
        credentialType.value === 'password'
          ? field('scan-password-v1', 'One-time password', passwordInput, 'Kept only in this form through preflight and cleared when collection starts.')
          : null,
        credentialType.value === 'key_file'
          ? h('div', { className: 'form-grid' },
              field('scan-key-path-v1', 'Private-key path', keyPathInput, 'Absolute paths only; file custody is validated by the scanner host.'),
              field('scan-key-passphrase-v1', 'Key passphrase (optional)', keyPassphraseInput, 'Kept only in this form through preflight and cleared when collection starts.'),
            )
          : null,
      );
      invalidatePreflight();
    };

    const profileMethods = profile => {
      const methods = profile?.methods || [];
      return methods.map(normalizeMethod).filter((value, index, list) => value && list.indexOf(value) === index);
    };

    const updateMethodOptions = () => {
      const profile = selectedProfile();
      const methods = profileMethods(profile);
      replace(methodSelect,
        h('option', { value: '' }, profile && !methods.length
          ? 'No collection method declared by this release'
          : profile ? 'Select a collection method…' : 'Select a profile first…'),
        methods.map(method => h('option', { value: method }, methodLabel(method))),
      );
      methodSelect.disabled = !profile || !methods.length;
      replace(methodStatus, profile && !methods.length
        ? notice('This profile returned no recognized collection method. Open Scanner Content, preserve the release/version details, and do not infer a method from the target name.', 'danger')
        : null);
      updateMethodFields();
    };

    const updateMethodFields = () => {
      const method = selectedMethod();
      sshFields.hidden = method !== 'ssh';
      evidenceFields.hidden = !['evidence', 'configuration'].includes(method);
      policyFields.hidden = method !== 'configuration';
      evidenceInput.accept = method === 'configuration'
        ? '.txt,.cfg,.conf,.log,text/plain'
        : '.json,application/json';
      invalidatePreflight();
    };

    collectionSelect.addEventListener('change', async () => {
      invalidatePreflight();
      assets = [];
      assignments = [];
      replace(assetSelect, h('option', { value: '' }, collectionSelect.value ? 'Loading assets…' : 'Select a collection first…'));
      replace(assignmentSelect, h('option', { value: '' }, 'Select an asset first…'));
      assetSelect.disabled = true;
      assignmentSelect.disabled = true;
      replace(unsupportedStatus);
      if (!collectionSelect.value) return;
      const requestedCollectionId = collectionSelect.value;
      replace(destinationStatus, loadingState('Loading authoritative assets…'));
      try {
        const loadedAssets = normalizeAssets(await request(endpoints.assets(requestedCollectionId), { signal: controller?.signal }));
        if (collectionSelect.value !== requestedCollectionId) return;
        assets = loadedAssets;
        replace(assetSelect,
          h('option', { value: '' }, assets.length ? 'Select an existing asset…' : 'No assets in this collection'),
          assets.map(asset => h('option', { value: asset.id }, `${asset.name}${asset.fqdn || asset.ip ? ` · ${asset.fqdn || asset.ip}` : ''}`)),
        );
        assetSelect.disabled = !assets.length;
        replace(destinationStatus, assets.length
          ? notice(`${assets.length} authoritative asset${assets.length === 1 ? '' : 's'} loaded.`, 'success')
          : notice('No assets are available. Create and assign the asset in STIG Manager, then refresh.', 'warning'));
      } catch (error) {
        if (collectionSelect.value !== requestedCollectionId) return;
        replace(destinationStatus, notice(apiUnavailableMessage(error), 'danger'));
      }
    });

    assetSelect.addEventListener('change', async () => {
      invalidatePreflight();
      assignments = [];
      replace(assignmentSelect, h('option', { value: '' }, assetSelect.value ? 'Loading assignments…' : 'Select an asset first…'));
      assignmentSelect.disabled = true;
      replace(unsupportedStatus);
      if (!assetSelect.value) return;
      const requestedCollectionId = collectionSelect.value;
      const requestedAssetId = assetSelect.value;
      const asset = selectedAsset();
      endpointInput.value = asset?.fqdn || asset?.ip || '';
      replace(destinationStatus, loadingState('Checking assigned STIGs against scanner profiles…'));
      try {
        const payload = await request(endpoints.assignments(requestedCollectionId, requestedAssetId), { signal: controller?.signal });
        if (collectionSelect.value !== requestedCollectionId || assetSelect.value !== requestedAssetId) return;
        assignments = normalizeAssignments(payload, profiles);
        const ready = assignments.filter(value => value.scannerReady);
        const unsupported = assignments.filter(value => !value.scannerReady);
        replace(assignmentSelect,
          h('option', { value: '' }, ready.length ? 'Select an assigned scanner profile…' : 'No runnable scanner assignments'),
          ready.map(assignment => h('option', { value: assignment.id }, `${assignment.title} · ${assignment.revision}`)),
        );
        assignmentSelect.disabled = !ready.length;
        replace(unsupportedStatus, unsupported.length ? h('details', { className: 'unsupported-assignments' },
          h('summary', {}, `${unsupported.length} assigned STIG${unsupported.length === 1 ? '' : 's'} cannot run here`),
          h('ul', {}, unsupported.map(assignment => h('li', {},
            h('strong', {}, `${assignment.title}${assignment.revision ? ` ${assignment.revision}` : ''}`),
            h('span', {}, assignment.reason || 'No exact scanner profile is available.'),
          ))),
        ) : null);
        replace(destinationStatus, ready.length
          ? notice(`${ready.length} exact pilot-runnable assignment${ready.length === 1 ? '' : 's'} available. Review the acceptance warning before preflight.`, 'warning')
          : notice('This asset has no assigned STIG matching an exact runnable scanner profile. Manage assignments in STIG Manager.', 'warning'));
      } catch (error) {
        if (collectionSelect.value !== requestedCollectionId || assetSelect.value !== requestedAssetId) return;
        replace(destinationStatus, notice(apiUnavailableMessage(error), 'danger'));
      }
    });

    assignmentSelect.addEventListener('change', () => {
      pilotAcknowledgement.checked = false;
      updateMethodOptions();
      invalidatePreflight();
    });
    profileSelect.addEventListener('change', () => {
      pilotAcknowledgement.checked = false;
      updateMethodOptions();
      invalidatePreflight();
    });
    pilotAcknowledgement.addEventListener('change', invalidatePreflight);
    methodSelect.addEventListener('change', updateMethodFields);
    credentialType.addEventListener('change', updateCredentialFields);
    for (const control of [endpointInput, portInput, usernameInput, passwordInput, keyPathInput,
      keyPassphraseInput, evidenceInput, policyInput, signatureInput]) {
      control.addEventListener(control.type === 'file' ? 'change' : 'input', invalidatePreflight);
      control.addEventListener(control.type === 'file' ? 'change' : 'input', updatePreflightReady);
    }

    replace(sshFields,
      h('div', { className: 'form-grid' },
        field('scan-saved-target-v1', 'Saved target profile (optional)', savedTargetSelect, 'Thin scanner-only reconnect coordinates; it never contains STIG Manager asset state or device secrets.'),
        field('scan-endpoint-v1', 'Target endpoint', endpointInput, 'Must identify the selected STIG Manager asset; preflight validates the binding.'),
        field('scan-port-v1', 'Port', portInput),
      ),
      h('div', { className: 'button-row' }, saveTargetProfile),
      savedTargetStatus,
      field('scan-credential-type-v1', 'Credential source', credentialType, 'Reusable plaintext credentials are never stored in the asset record.'),
      credentialsFields,
    );
    replace(evidenceFields,
      field('scan-evidence-v1', 'Evidence or configuration file', evidenceInput, 'The scanner binds the file digest, claimed identity, profile, and collection plan before evaluation.'),
    );
    replace(policyFields,
      h('div', { className: 'form-grid' },
        field('scan-policy-v1', 'Signed organization policy', policyInput, 'Required only for typed IOS-XE organization-defined controls.'),
        field('scan-policy-signature-v1', 'Detached policy signature', signatureInput),
      ),
    );
    updateCredentialFields();

    preflightButton.addEventListener('click', async event => {
      const control = event.currentTarget;
      const requestRevision = preflightRevision;
      setBusy(control, true, 'Checking readiness…');
      runButton.disabled = true;
      replace(progress, progressSteps('preflight', { preflight: 'active' }));
      replace(preflightOutput, loadingState('Verifying destination, target identity, version, privilege, and collection plan…'));
      try {
        const payload = await buildBasePayload({
          session,
          profile: selectedProfile(),
          method: selectedMethod(),
          collection: selectedCollection(),
          asset: selectedAsset(),
          assignment: selectedAssignment(),
          endpointInput,
          portInput,
          credentialType,
          usernameInput,
          passwordInput,
          keyPathInput,
          keyPassphraseInput,
          evidenceInput,
          policyInput,
          signatureInput,
          connectionProfileId: selectedConnectionProfile()?.id || null,
          pilotAcknowledged: pilotAcknowledgement.checked,
        });
        const response = await request(endpoints.preflight, { method: 'POST', body: payload, signal: controller?.signal, timeoutMs: 60_000 });
        if (requestRevision !== preflightRevision) {
          replace(preflightOutput, notice('Inputs changed while preflight was running. Review the new values and run preflight again.', 'warning'));
          return;
        }
        preflight = normalizePreflight(response);
        replace(preflightOutput, renderPreflight(preflight));
        replace(progress, progressSteps(preflight.ready ? 'collect' : 'preflight', {
          preflight: preflight.ready ? 'complete' : 'failed',
        }));
        if (!preflight.ready) clearSensitiveInputs(passwordInput, keyPassphraseInput);
        runButton.disabled = !preflight.ready;
      } catch (error) {
        if (requestRevision !== preflightRevision) {
          replace(preflightOutput, notice('Inputs changed while preflight was running. Review the new values and run preflight again.', 'warning'));
          return;
        }
        preflight = null;
        clearSensitiveInputs(passwordInput, keyPassphraseInput);
        replace(preflightOutput, notice(apiUnavailableMessage(error), 'danger'));
        replace(progress, progressSteps('preflight', { preflight: 'failed' }));
      } finally {
        setBusy(control, false);
        updatePreflightReady();
        if (preflight?.ready) runButton.disabled = false;
      }
    });

    runButton.addEventListener('click', async event => {
      if (!preflight?.ready) return;
      const control = event.currentTarget;
      setBusy(control, true, selectedMethod() === 'ssh' ? 'Collecting…' : 'Evaluating…');
      activeRunController?.abort();
      activeRunController = new AbortController();
      replace(runOutput, loadingState('Starting immutable scanner run…'));
      replace(progress, progressSteps(selectedMethod() === 'ssh' ? 'collect' : 'evaluate', { preflight: 'complete' }));
      try {
        let response = selectedMethod() === 'ssh'
          ? await startSshRun({
              preflight,
              session,
              profile: selectedProfile(),
              collection: selectedCollection(),
              asset: selectedAsset(),
              assignment: selectedAssignment(),
              endpointInput,
              portInput,
              credentialType,
              usernameInput,
              passwordInput,
              keyPathInput,
              keyPassphraseInput,
              connectionProfileId: selectedConnectionProfile()?.id || null,
              signal: activeRunController.signal,
            })
          : await startEvidenceRun({
              preflight,
              session,
              profile: selectedProfile(),
              method: selectedMethod(),
              collection: selectedCollection(),
              asset: selectedAsset(),
              assignment: selectedAssignment(),
              evidenceInput,
              policyInput,
              signatureInput,
              signal: activeRunController.signal,
            });
        // The API has accepted or rejected the submission at this point. Do not
        // retain one-time secrets while the durable run is being polled.
        clearSensitiveInputs(passwordInput, keyPassphraseInput);
        if (response?.kind === 'scan_job') {
          if (!response.id) throw new ApiError('The scanner API accepted the SSH request without returning a durable job identifier.', { code: 'missing_job_id' });
          replace(runOutput, renderActiveJob(response));
          const job = await pollScanJob(response.id, {
            signal: activeRunController.signal,
            onUpdate: update => {
              replace(progress, progressSteps('collect', {
                preflight: 'complete',
                collect: update.state === 'failed' ? 'failed' : 'active',
              }));
              replace(runOutput, renderActiveJob(update));
            },
          });
          if (job.state === 'failed') {
            throw new ApiError(job.error || 'The durable SSH scanner job failed. Run preflight again and resubmit credentials.', {
              code: 'scan_job_failed',
            });
          }
          if (!job.run_id) throw new ApiError('The durable SSH job completed without an immutable run identifier.', { code: 'missing_run_id' });
          response = await request(endpoints.run(job.run_id), { signal: activeRunController.signal });
        }
        let run = normalizeRun(response);
        if (!run.id) throw new ApiError('The scanner API accepted the run without returning a run or job identifier.', { code: 'missing_run_id' });
        replace(runOutput, renderActiveRun(run));
        if (!['preview_ready', 'delivered', 'failed', 'rejected', 'conflicted', 'incomplete'].includes(run.state)) {
          const completed = await pollRun(run.id, {
            signal: activeRunController.signal,
            onUpdate: update => {
              run = normalizeRun(update);
              replace(progress, progressSteps(run.stage, run.stepStates));
              replace(runOutput, renderActiveRun(run));
            },
          });
          run = normalizeRun(completed);
        }
        replace(progress, progressSteps(run.stage, run.stepStates));
        replace(runOutput, renderCompletedRun(run, {
          session,
          onDeliver: event => handleInlineDelivery(event.currentTarget, run, runOutput, progress),
        }));
        if (run.state === 'preview_ready') notify('Evaluation complete. Review the sparse result and download its selected-run handoff.', 'success');
        else if (run.state === 'incomplete') notify('Collection was incomplete. Nothing was queued for delivery.', 'warning');
      } catch (error) {
        if (!(error instanceof ApiError && error.code === 'canceled')) {
          replace(runOutput, notice(apiUnavailableMessage(error), 'danger'));
          notify(apiUnavailableMessage(error), 'danger');
        }
      } finally {
        clearSensitiveInputs(passwordInput, keyPassphraseInput);
        setBusy(control, false);
      }
    });

    const destination = session.mode === 'connected'
      ? h('section', { className: 'card workflow-card' },
          h('div', { className: 'section-heading' },
            h('div', {}, h('p', { className: 'step-label' }, 'Step 1'), h('h2', {}, 'Choose the authoritative destination'),
              h('p', {}, 'Collections, assets, and assignments are read live from STIG Manager.')),
            badge('Live lookup', 'accent'),
          ),
          h('div', { className: 'form-grid three-columns' },
            field('scan-collection-v1', 'Collection', collectionSelect),
            field('scan-asset-v1', 'Existing asset', assetSelect),
            field('scan-assignment-v1', 'Assigned scanner profile', assignmentSelect),
          ),
          destinationStatus,
          unsupportedStatus,
        )
      : h('section', { className: 'card workflow-card' },
          h('div', { className: 'section-heading' },
            h('div', {}, h('p', { className: 'step-label' }, 'Step 1'), h('h2', {}, 'Choose scanner content'),
              h('p', {}, 'Disconnected runs use the same exact release-bundled profile contract.')),
            badge('Disconnected', 'neutral'),
          ),
          field('scan-profile-v1', 'Scanner profile', profileSelect),
        );

    return h('div', { className: 'scan-workspace' },
      progress,
      readinessPanel(session.mode),
      destination,
      h('section', { className: 'card workflow-card' },
        h('div', { className: 'section-heading' },
          h('div', {}, h('p', { className: 'step-label' }, 'Step 2'), h('h2', {}, 'Choose collection method'),
            h('p', {}, 'Temporary secrets stay in this form only until the request is submitted.')),
        ),
        field('scan-method-v1', 'Collection method', methodSelect),
        methodStatus,
        sshFields,
        evidenceFields,
        policyFields,
      ),
      h('section', { className: 'card workflow-card' },
        h('div', { className: 'section-heading' },
          h('div', {}, h('p', { className: 'step-label' }, 'Step 3'), h('h2', {}, 'Run the safety check'),
            h('p', {}, 'Review device identity, exact version alignment, privilege, and every planned command or request.')),
          badge('Fail closed', 'success'),
        ),
        selectedProfile()?.releaseSupported ? null : h('div', { className: 'pilot-acknowledgement' },
          notice('This exact profile is pilot-runnable, not release-supported: no accepted live-device version is attached yet. Results remain experimental until authorized acceptance is completed.', 'warning'),
          h('label', { className: 'checkbox-row' }, pilotAcknowledgement,
            h('span', {}, 'I understand this is an experimental pilot run and will validate its results in STIG Manager.')),
        ),
        h('div', { className: 'button-row' }, preflightButton, runButton),
        preflightOutput,
      ),
      runOutput,
    );
  }

  async function handleInlineDelivery(control, run, output, progress) {
    setBusy(control, true, ['retryable', 'failed'].includes(run.delivery.state) ? 'Rechecking…' : 'Verifying…');
    replace(progress, progressSteps('delivery', { preflight: 'complete', collect: 'complete', evaluate: 'complete', delivery: 'active' }));
    try {
      const delivered = await deliverRun(run.id, {
        signal: activeRunController?.signal,
        onUpdate: update => replace(output, renderCompletedRun(update, { session: getSession() })),
      });
      replace(output, renderCompletedRun(delivered, {
        session: getSession(),
        onDeliver: event => handleInlineDelivery(event.currentTarget, delivered, output, progress),
      }));
      replace(progress, progressSteps('delivery', {
        preflight: 'complete', collect: 'complete', evaluate: 'complete',
        delivery: delivered.delivery.state === 'delivered' ? 'complete' : 'failed',
      }));
      notify(delivered.delivery.state === 'delivered'
        ? 'Remote state is unchanged. Continue in STIG Manager for human review.'
        : 'Remote verification needs attention. The immutable run and handoff remain available in Deliveries.',
      delivered.delivery.state === 'delivered' ? 'success' : 'warning');
    } catch (error) {
      notify(apiUnavailableMessage(error), 'danger');
      setBusy(control, false);
    }
  }

  return { render, abort: () => { controller?.abort(); activeRunController?.abort(); } };
}

function focusWorkspaceHeading(outlet) {
  outlet?.querySelector('h1')?.focus({ preventScroll: true });
}

function absolutePath(value) {
  const path = String(value || '').trim();
  return path.startsWith('/') || /^[A-Za-z]:[\\/]/.test(path) || /^\\\\[^\\]+\\[^\\]+/.test(path);
}

function normalizeMethod(value) {
  const key = String(value || '').toLowerCase().replaceAll('-', '_').replaceAll(' ', '_');
  if (key.includes('ssh')) return 'ssh';
  if (key.includes('config')) return 'configuration';
  if (key.includes('evidence') || key.includes('transcript') || key.includes('upload')) return 'evidence';
  return '';
}

function methodLabel(method) {
  return {
    ssh: 'Collect live over SSH',
    evidence: 'Evaluate supplied evidence',
    configuration: 'Evaluate authorized configuration',
  }[method] || method;
}

function clearSensitiveInputs(...inputs) {
  inputs.forEach(input => { if (input) input.value = ''; });
}

async function buildBasePayload({
  session,
  profile,
  method,
  collection,
  asset,
  assignment,
  endpointInput,
  portInput,
  credentialType,
  usernameInput,
  passwordInput,
  keyPathInput,
  keyPassphraseInput,
  evidenceInput,
  policyInput,
  signatureInput,
  connectionProfileId,
  pilotAcknowledged,
}) {
  const destination = session.mode === 'connected' ? {
    collection_id: collection?.id,
    asset_id: asset?.id,
    assignment_id: assignment?.id,
  } : null;
  const payload = {
    mode: session.mode,
    profile_id: profile?.id,
    collection_method: method,
    connection_profile_id: method === 'ssh' ? connectionProfileId : null,
    destination,
    pilot_acknowledged: Boolean(profile?.releaseSupported || pilotAcknowledged),
  };
  if (method === 'ssh') {
    payload.target = { host: endpointInput.value.trim(), port: Number(portInput.value || 22) };
    payload.credential = buildCredential({ credentialType, usernameInput, passwordInput, keyPathInput, keyPassphraseInput });
  } else {
    payload.input = await fileMetadata(evidenceInput.files?.[0]);
    if (method === 'configuration') {
      payload.organization_policy = await fileMetadata(policyInput.files?.[0]);
      payload.organization_policy_signature = await fileMetadata(signatureInput.files?.[0]);
    }
  }
  return payload;
}

function buildCredential({ credentialType, usernameInput, passwordInput, keyPathInput, keyPassphraseInput }) {
  const credential = { type: credentialType.value, username: usernameInput.value.trim() };
  if (credential.type === 'password') credential.password = passwordInput.value;
  if (credential.type === 'key_file') {
    credential.path = keyPathInput.value.trim();
    credential.passphrase = keyPassphraseInput.value || null;
  }
  return credential;
}

async function fileMetadata(file) {
  if (!file) return null;
  const maximumBytes = 32 * 1024 * 1024;
  if (file.size > maximumBytes) {
    throw new ApiError('Evidence files are limited to 32 MiB so the browser can bind the complete file digest before upload.', {
      code: 'evidence_file_too_large',
    });
  }
  if (!globalThis.crypto?.subtle) {
    throw new ApiError('This browser cannot calculate the required SHA-256 file binding.', {
      code: 'file_digest_unavailable',
    });
  }
  const digest = await crypto.subtle.digest('SHA-256', await file.arrayBuffer());
  const sha256 = [...new Uint8Array(digest)].map(byte => byte.toString(16).padStart(2, '0')).join('');
  return { name: file.name, size: file.size, type: file.type || 'application/octet-stream', sha256 };
}

function normalizePreflight(payload = {}) {
  const value = payload.preflight || payload;
  const token = value.preflight_token || value.token || value.id || null;
  const operations = Array.isArray(value.operations) ? value.operations
    : Array.isArray(value.plan?.operations) ? value.plan.operations
    : Array.isArray(value.commands) ? value.commands : [];
  const reportedReady = Boolean(value.ready ?? value.passed ?? value.compatible);
  const ready = reportedReady && Boolean(token) && operations.length > 0;
  const contractReason = reportedReady && !token
    ? 'Preflight passed without a bound token. Collection remains disabled.'
    : reportedReady && !operations.length
      ? 'Preflight passed without a visible operation plan. Collection remains disabled.'
      : '';
  return {
    ready,
    token,
    expiresAt: value.expires_at || null,
    identity: value.device_identity || value.identity || {},
    compatibility: value.compatibility || {},
    privilege: value.privilege || value.privileges || {},
    operations,
    totalExpectedDurationMs: Number(value.total_expected_duration_ms || value.plan?.total_expected_duration_ms || 0),
    warnings: Array.isArray(value.warnings) ? value.warnings : [],
    errors: Array.isArray(value.errors) ? value.errors : [],
    reason: value.reason || value.blocked_reason || contractReason,
  };
}

export function renderPreflight(preflight) {
  return h('div', { className: 'preflight-result' },
    notice(preflight.ready
      ? 'Preflight passed. Review the plan below before collection.'
      : preflight.reason || 'Preflight did not establish a safe, compatible collection.',
    preflight.ready ? 'success' : 'danger'),
    definitionList([
      ['Observed identity', preflight.identity.hostname || preflight.identity.name || preflight.identity.fingerprint || 'Not returned'],
      ['Observed version', preflight.identity.version || preflight.compatibility.observed_version || 'Not returned'],
      ['Operating context', String(preflight.identity.operating_context || 'unknown_or_unsupported').replaceAll('_', ' ')],
      ['HA role', String(preflight.identity.ha_role || 'unknown_or_unsupported').replaceAll('_', ' ')],
      ['Version grammar', preflight.compatibility.version_grammar_matched === true || preflight.compatibility.supported === true
        ? 'Observed version is inside the pilot boundary' : preflight.compatibility.message || 'Not confirmed'],
      ['Release acceptance', preflight.compatibility.release_supported === true
        ? 'Accepted live-device version' : 'Experimental pilot; live acceptance not attached'],
      ['Privilege', preflight.privilege.summary || preflight.privilege.level || String(preflight.privilege || 'Not returned')],
      ['Expected collection time', preflight.totalExpectedDurationMs > 0
        ? `${Math.ceil(preflight.totalExpectedDurationMs / 1000)} seconds` : 'Not returned'],
      ['Preflight expires', preflight.expiresAt || 'Bound by server policy'],
    ]),
    preflight.warnings.length ? notice(preflight.warnings.join(' · '), 'warning') : null,
    preflight.errors.length ? h('div', { className: 'preflight-diagnostics' },
      h('ul', { className: 'diagnostic-list' }, preflight.errors.map(error => h('li', {}, String(error.message || error)))),
      troubleshootingPanel(preflight),
    ) : null,
    h('div', { className: 'plan-preview' },
      h('div', { className: 'section-heading' },
        h('div', {}, h('h3', {}, 'Read-only collection plan'), h('p', {}, 'The scanner executes only the operations returned by this bound preflight.')),
        badge(`${preflight.operations.length} operation${preflight.operations.length === 1 ? '' : 's'}`, 'neutral'),
      ),
      preflight.operations.length
        ? h('ol', { className: 'operation-list' }, preflight.operations.map((operation, index) => h('li', {},
            h('span', { className: 'operation-number' }, index + 1),
            h('div', {},
              h('strong', {}, String(operation.label || operation.name || operation.method || 'Collection operation')),
              h('code', {}, String(operation.command || operation.request || operation.path || operation.detail || 'Details bound by adapter')),
              operation.purpose ? h('p', {}, String(operation.purpose)) : null,
              Number(operation.estimated_duration_ms) > 0
                ? h('p', { className: 'operation-timing' }, `Expected ${Math.ceil(Number(operation.estimated_duration_ms) / 1000)}s · maximum ${Math.ceil(Number(operation.maximum_duration_ms) / 1000)}s`)
                : null,
            ),
          )))
        : notice('The API did not return a visible operation plan. Confirm the adapter contract before collecting.', 'warning'),
    ),
  );
}

export function readinessPanel(mode) {
  const disconnected = mode === 'disconnected';
  const training = mode === 'training';
  const items = training
    ? [
        ['Review scope', 'Separate automated results from manual and out-of-profile rules.'],
        ['Inspect changes', 'Confirm create, update, unchanged, and conflict counts before any handoff.'],
        ['Verify transfer', 'A real handoff must pass CLI verification before reconciliation.'],
      ]
    : [
        [disconnected ? 'Know the destination' : 'STIG Manager is ready', disconnected
          ? 'Identify the existing collection, asset, and assignment that will receive the reviewed result.'
          : 'You can read an existing collection, asset, and exact STIG assignment.'],
        ['Scanner content matches', 'The target and assigned STIG revision have an exact runnable profile.'],
        ['Collection input is ready', 'You have approved device access or the complete evidence/configuration file.'],
        ['Transfer is approved', disconnected
          ? 'You have an approved path to move and verify the selected-run ZIP at the destination.'
          : 'You will review the sparse preview before any remote no-op verification.'],
      ];
  return h('section', { className: 'card readiness-card', 'aria-labelledby': `readiness-${mode}-title` },
    h('div', { className: 'section-heading' },
      h('div', {},
        h('p', { className: 'card-kicker' }, training ? 'What to look for' : 'Before you begin'),
        h('h2', { id: `readiness-${mode}-title` }, training ? 'Analyst review checklist' : 'Operator readiness checklist'),
        h('p', {}, training
          ? 'Use these checks when you review a real run.'
          : 'AutomateSTIG stops safely when any binding cannot be proven.'),
      ),
      badge(training ? 'Walkthrough' : 'Required', training ? 'neutral' : 'accent'),
    ),
    h('ol', { className: 'readiness-list' }, items.map(([title, detail]) => h('li', {},
      h('span', { className: 'readiness-marker', 'aria-hidden': 'true' }, '✓'),
      h('div', {}, h('strong', {}, title), h('p', {}, detail)),
    ))),
  );
}

function troubleshootingPanel(preflight) {
  const diagnostics = [preflight.reason, ...preflight.errors.map(error => String(error?.message || error))]
    .join(' ')
    .toLowerCase();
  const steps = [];
  if (/identity|hostname|fingerprint|asset|endpoint/.test(diagnostics)) {
    steps.push('Compare the observed hostname or fingerprint with the selected STIG Manager asset. Correct the selection or endpoint; do not override the mismatch.');
  }
  if (/version|release|firmware|compatib/.test(diagnostics)) {
    steps.push('Open Scanner Content and confirm the exact target version and STIG revision are inside this profile’s tested boundary.');
  }
  if (/privilege|permission|denied|authoriz/.test(diagnostics)) {
    steps.push('Confirm the collection account can run every displayed read-only operation, then run the safety check again with fresh credentials.');
  }
  if (/connect|timeout|network|ssh|tls|certificate/.test(diagnostics)) {
    steps.push('Verify routing, port, host-key or TLS trust, and the endpoint from the scanner host before retrying.');
  }
  if (!steps.length) {
    steps.push('Correct the reported input or target condition, then run the safety check again. AutomateSTIG does not provide a bypass.');
  }
  return h('details', { className: 'troubleshooting-panel' },
    h('summary', {}, 'How to resolve this safely'),
    h('ol', {}, steps.map(step => h('li', {}, step))),
    h('p', {}, 'There is no bypass. If the condition persists, preserve the error and run ID for your operator log; do not reinterpret an incomplete collection as a compliance result.'),
  );
}

function trainingRun() {
  return {
    run_id: 'TRAINING-NOT-A-REAL-RUN',
    state: 'preview_ready',
    mode: 'disconnected',
    created_at: '2026-01-01T12:00:00Z',
    profile: {
      title: 'NetApp ONTAP 9.x (sample)',
      stig_id: 'NetApp_ONTAP_DSC_9-x_STIG',
      revision: 'V2R4',
    },
    result: {
      collection_complete: true,
      automated_count: 15,
      executable_coverage_pct: 51.7,
      reviewed_rules: 22,
      full_benchmark_rules: 29,
      manual_untouched: 7,
      out_of_scope_untouched: 7,
      proposed_reviews: [
        { rule_id: 'SV-SAMPLE-1', result: 'pass', change: 'update', evidence_summary: 'Synthetic version observation' },
        { rule_id: 'SV-SAMPLE-2', result: 'fail', change: 'create', evidence_summary: 'Synthetic service observation' },
      ],
    },
    delivery: {
      state: 'not_started',
      preview: {
        manual_untouched: 7,
        out_of_scope_untouched: 7,
        reviews: [
          { rule_id: 'SV-SAMPLE-1', result: 'pass', change: 'update', evidence_summary: 'Synthetic version observation' },
          { rule_id: 'SV-SAMPLE-2', result: 'fail', change: 'create', evidence_summary: 'Synthetic service observation' },
        ],
      },
    },
  };
}

async function startSshRun({ preflight, session, profile, collection, asset, assignment, endpointInput, portInput,
  credentialType, usernameInput, passwordInput, keyPathInput, keyPassphraseInput, connectionProfileId, signal }) {
  return request(endpoints.sshRun, {
    method: 'POST',
    signal,
    timeoutMs: 60_000,
    body: {
      preflight_token: preflight.token,
      mode: session.mode,
      profile_id: profile.id,
      connection_profile_id: connectionProfileId,
      destination: session.mode === 'connected' ? {
        collection_id: collection.id,
        asset_id: asset.id,
        assignment_id: assignment.id,
      } : null,
      target: { host: endpointInput.value.trim(), port: Number(portInput.value || 22) },
      credential: buildCredential({ credentialType, usernameInput, passwordInput, keyPathInput, keyPassphraseInput }),
    },
  });
}

async function startEvidenceRun({ preflight, session, profile, method, collection, asset, assignment,
  evidenceInput, policyInput, signatureInput, signal }) {
  const form = new FormData();
  form.set('preflight_token', preflight.token || '');
  form.set('mode', session.mode);
  form.set('profile_id', profile.id);
  form.set('input_type', method === 'configuration' ? 'configuration' : 'evidence');
  if (session.mode === 'connected') {
    form.set('collection_id', collection.id);
    form.set('asset_id', asset.id);
    form.set('assignment_id', assignment.id);
  }
  form.set('evidence', evidenceInput.files[0]);
  if (method === 'configuration') {
    form.set('organization_policy', policyInput.files[0]);
    form.set('organization_policy_signature', signatureInput.files[0]);
  }
  return request(endpoints.evidenceRun, { method: 'POST', body: form, signal, timeoutMs: 60_000 });
}

function renderActiveRun(run) {
  return h('section', { className: 'card active-run-card' },
    h('div', { className: 'section-heading' },
      h('div', {}, h('p', { className: 'step-label' }, `Run ${run.id}`), h('h2', {}, 'Scanner run in progress'),
        h('p', {}, 'You may leave this page; Deliveries can resume monitoring the durable run.')),
      badge(run.state.replaceAll('_', ' '), 'accent'),
    ),
    progressSteps(run.stage, run.stepStates),
    h('a', { className: 'button button-secondary', href: hrefFor('deliveries', run.id) }, 'Open durable run'),
  );
}

function renderActiveJob(job = {}) {
  const state = String(job.state || 'queued').toLowerCase();
  return h('section', { className: 'card active-run-card' },
    h('div', { className: 'section-heading' },
      h('div', {}, h('p', { className: 'step-label' }, `Job ${job.id || 'pending'}`), h('h2', {}, 'Durable SSH collection'),
        h('p', {}, 'The job was recorded before device I/O. Credentials remain ephemeral; an application restart requires credential resubmission.')),
      badge(state.replaceAll('_', ' '), state === 'failed' ? 'danger' : 'accent'),
    ),
    job.error ? notice(String(job.error), 'danger') : null,
    h('a', { className: 'button button-secondary', href: hrefFor('deliveries') }, 'Open operational queue'),
  );
}

function renderCompletedRun(run, { session, onDeliver = null } = {}) {
  return h('section', { className: 'completed-run' },
    session?.mode === 'disconnected' ? notice(
      'Disconnected run: direct delivery is disabled. Use the selected-run handoff returned by the scanner API.',
      'info',
      run.handoffUrl && run.handoffUrl.startsWith('/api/v1/')
        ? [button('Download selected-run handoff', {
            tone: 'secondary',
            onClick: event => downloadHandoff(event.currentTarget, run.handoffUrl),
          })]
        : [],
    ) : null,
    renderRunPreview(run, { onDeliver, embedded: true }),
  );
}

async function downloadHandoff(control, path) {
  setBusy(control, true, 'Preparing handoff…');
  try {
    const { blob, filename } = await download(path.replace(/^\/api\/v1/, ''), { timeoutMs: 60_000 });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    link.hidden = true;
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 0);
  } catch (error) {
    toast(apiUnavailableMessage(error), 'danger');
  } finally {
    setBusy(control, false);
  }
}

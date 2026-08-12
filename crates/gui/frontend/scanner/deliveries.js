import {
  ApiError,
  apiUnavailableMessage,
  download,
  endpoints,
  pagedEndpoint,
  pollRun,
  request,
} from './api.js';
import { hrefFor } from './router.js';
import {
  badge,
  button,
  definitionList,
  emptyState,
  field,
  formatDate,
  formatPercent,
  h,
  linkButton,
  loadingState,
  metric,
  notice,
  pageHeader,
  progressSteps,
  replace,
  safeExternalUrl,
  setBusy,
  toast,
} from './ui.js';

const DELIVERY_TERMINAL = new Set(['delivered', 'failed', 'retryable', 'rejected', 'conflicted', 'incomplete']);
const MAX_RECEIPT_BYTES = 1024 * 1024;
const RECEIVER_RECEIPT_SCHEMA = 'automatestig.receiver-reconciliation.v1';
const SHA256_PATTERN = /^[A-Fa-f0-9]{64}$/;
const MAX_VISIBLE_DECISION_TRACES = 250;
const MAX_VISIBLE_TRACE_OPERATIONS = 64;

export function normalizeRun(value = {}) {
  const run = value?.run || value;
  const delivery = run.delivery || {};
  const destination = run.destination || {};
  const profile = run.profile || {};
  const result = run.result || run.scanner_result || {};
  const preview = delivery.preview || run.delivery_preview || result.delivery_preview || {};
  const proposed = firstArray(preview.reviews, run.proposed_reviews, result.proposed_reviews, result.reviews);
  const evidence = arrayValue(result.evidence, run.evidence, run.evidence_references);
  const attempts = arrayValue(delivery.attempts, run.delivery_attempts);
  const state = text(run.state || run.status || delivery.state || 'unknown').toLowerCase();
  return {
    raw: run,
    id: text(run.id || run.run_id || run.job_id),
    state,
    createdAt: run.created_at || run.started_at || null,
    completedAt: run.completed_at || null,
    updatedAt: run.updated_at || run.completed_at || null,
    mode: text(run.mode || (destination.collection_id ? 'connected' : 'disconnected')),
    profileId: text(profile.id || profile.profile_id || run.profile_id),
    profileTitle: text(profile.title || profile.target_name || run.profile_title || run.stig_id || 'Scanner profile'),
    stigId: text(profile.stig_id || profile.benchmark_id || run.stig_id),
    stigRevision: text(profile.stig_revision || profile.revision || run.stig_revision),
    collectionId: text(destination.collection_id || run.collection_id),
    collectionName: text(destination.collection_name || run.collection_name),
    assetId: text(destination.asset_id || run.asset_id),
    assetName: text(destination.asset_name || run.asset_name || run.hostname),
    assignmentId: text(destination.assignment_id || run.assignment_id),
    endpoint: text(run.endpoint?.host || run.endpoint || run.target_endpoint),
    stage: stageFor(run, delivery),
    stepStates: run.steps || {},
    collectionComplete: result.collection_complete ?? run.collection_complete ?? null,
    automatedCount: numberValue(result.automated_count, result.automated_rules, run.automated_count, proposed.length),
    passedCount: numberValue(result.passed_count, result.not_a_finding, result.pass),
    openCount: numberValue(result.open_count, result.open, result.fail),
    coveragePct: numberValue(result.executable_coverage_pct, result.coverage_pct, result.benchmark_coverage_pct),
    fullBenchmarkRules: numberValue(result.full_benchmark_rules, run.full_benchmark_rules),
    reviewedRules: numberValue(result.reviewed_rules, run.reviewed_rules),
    manualUntouched: numberValue(preview.manual_untouched, result.manual_untouched, result.manual_rules),
    outOfScopeUntouched: numberValue(preview.out_of_scope_untouched, result.out_of_scope_untouched),
    proposed,
    evidence,
    collectionErrors: arrayValue(result.collection_errors, run.collection_errors, result.evaluation_errors),
    provenance: result.provenance || run.provenance || run.evaluation_provenance || {},
    decisionTraces: firstArray(result.decision_traces, result.decisionTraces, run.decision_traces, run.decisionTraces),
    delivery: {
      state: text(delivery.state || run.delivery_state || (state === 'delivered' ? 'delivered' : 'not_started')).toLowerCase(),
      requestSha256: text(delivery.request_sha256),
      payloadSha256: text(delivery.payload_sha256 || run.delivery_sha256),
      remoteUrl: text(delivery.remote_url || delivery.receipt?.remote_url || delivery.receipt?.receipt?.remote_url || delivery.stig_manager_url || run.remote_url),
      remoteAssetId: text(delivery.remote_asset_id || destination.asset_id),
      remoteAssignmentId: text(delivery.remote_assignment_id || destination.assignment_id),
      deliveredAt: delivery.delivered_at || run.delivered_at || null,
      lastError: text(delivery.last_error || run.delivery_error),
      receipt: delivery.receipt || run.receipt || null,
      attempts,
      attemptsPage: delivery.attempts_page || run.attempts_page || null,
      preview,
    },
    handoffUrl: text(run.handoff?.download_url || run.handoff_url),
  };
}

function arrayValue(...values) {
  for (const value of values) {
    if (Array.isArray(value)) return value;
    if (value && typeof value === 'object') {
      return Object.entries(value).map(([key, detail]) => ({ key, detail }));
    }
  }
  return [];
}

function firstArray(...values) {
  return values.find(Array.isArray) || [];
}

function numberValue(...values) {
  for (const value of values) {
    if (value == null || value === '') continue;
    const number = Number(value);
    if (Number.isFinite(number)) return number;
  }
  return null;
}

function text(value) {
  return value == null ? '' : String(value);
}

function stageFor(run, delivery) {
  const explicit = text(run.stage || run.current_step).toLowerCase();
  if (['preflight', 'collect', 'evaluate', 'delivery'].includes(explicit)) return explicit;
  const state = text(run.state || run.status).toLowerCase();
  const deliveryState = text(delivery.state).toLowerCase();
  if (deliveryState && deliveryState !== 'not_started' && deliveryState !== 'pending_preview') return 'delivery';
  if (['collecting', 'collection'].includes(state)) return 'collect';
  if (['evaluating', 'evaluation'].includes(state)) return 'evaluate';
  if (['preview_ready', 'complete', 'completed'].includes(state)) return 'delivery';
  return 'preflight';
}

export function runStateBadge(run) {
  const state = run.delivery.state && !['not_started', 'pending_preview'].includes(run.delivery.state)
    ? run.delivery.state
    : run.state;
  const labels = {
    preview_ready: ['Handoff ready', 'accent'],
    delivered: ['Remote no-op verified', 'success'],
    pending: ['Pending', 'warning'],
    sending: ['Sending', 'accent'],
    retryable: ['Retry available', 'warning'],
    failed: ['Needs attention', 'danger'],
    rejected: ['Rejected', 'danger'],
    conflicted: ['Conflict', 'danger'],
    incomplete: ['Incomplete', 'warning'],
    collecting: ['Collecting', 'accent'],
    evaluating: ['Evaluating', 'accent'],
  };
  const [label, tone] = labels[state] || [state ? state.replaceAll('_', ' ') : 'Unknown', 'neutral'];
  return badge(label, tone);
}

export async function deliverRun(runId, { onUpdate = () => {}, signal } = {}) {
  const initial = await request(endpoints.deliver(runId), { method: 'POST', signal });
  let run = normalizeRun(initial);
  onUpdate(run);
  if (!run.id) run.id = String(runId);
  if (!DELIVERY_TERMINAL.has(run.delivery.state) && !DELIVERY_TERMINAL.has(run.state)) {
    const completed = await pollRun(run.id, {
      signal,
      onUpdate: value => onUpdate(normalizeRun(value)),
      isTerminal: value => {
        const current = normalizeRun(value);
        return DELIVERY_TERMINAL.has(current.delivery.state) || current.state === 'incomplete';
      },
    });
    run = normalizeRun(completed);
  }
  return run;
}

export function createDeliveriesPage({ notify = toast } = {}) {
  let generation = 0;
  let controller = null;

  function begin() {
    controller?.abort();
    controller = new AbortController();
    generation += 1;
    return { generation, signal: controller.signal };
  }

  async function render(outlet, runId = null) {
    return runId ? renderDetail(outlet, runId) : renderList(outlet);
  }

  async function renderList(outlet) {
    const current = begin();
    replace(outlet,
      pageHeader(
        'Operational queue',
        'Deliveries',
        'Short-lived scanner runs, handoffs, remote no-op checks, conflicts, and receipts. Long-term review remains in STIG Manager.',
      ),
      h('div', { id: 'deliveries-body' }, loadingState('Loading scanner runs…')),
    );
    const body = outlet.querySelector('#deliveries-body');
    try {
      const pageSize = 25;
      const [payload, jobsPayload, purgedPayload] = await Promise.all([
        request(pagedEndpoint(endpoints.runs, { limit: pageSize }), { signal: current.signal }),
        request(pagedEndpoint(endpoints.jobs, { limit: pageSize }), { signal: current.signal }),
        request(pagedEndpoint(endpoints.purgedRuns, { limit: pageSize }), { signal: current.signal }),
      ]);
      if (current.generation !== generation || !body?.isConnected) return;
      const state = {
        runs: (Array.isArray(payload) ? payload : payload?.runs || []).map(normalizeRun),
        runsPage: payload?.page || null,
        jobs: Array.isArray(jobsPayload) ? jobsPayload : jobsPayload?.jobs || [],
        jobsPage: jobsPayload?.page || null,
        purged: Array.isArray(purgedPayload) ? purgedPayload : purgedPayload?.purged_runs || [],
        purgedPage: purgedPayload?.page || null,
      };
      const loadMore = async (kind, control) => {
        const descriptor = {
          jobs: { endpoint: endpoints.jobs, page: 'jobsPage', values: 'jobs', field: 'jobs' },
          runs: { endpoint: endpoints.runs, page: 'runsPage', values: 'runs', field: 'runs' },
          purged: { endpoint: endpoints.purgedRuns, page: 'purgedPage', values: 'purged', field: 'purged_runs' },
        }[kind];
        const nextOffset = state[descriptor.page]?.next_offset;
        if (nextOffset == null) return;
        setBusy(control, true, 'Loading…');
        try {
          const next = await request(pagedEndpoint(descriptor.endpoint, { offset: nextOffset, limit: pageSize }), { signal: current.signal });
          const rows = Array.isArray(next) ? next : next?.[descriptor.field] || [];
          const normalized = kind === 'runs' ? rows.map(normalizeRun) : rows;
          const seen = new Set(state[descriptor.values].map(value => text(value.id || value.run_id)));
          state[descriptor.values].push(...normalized.filter(value => !seen.has(text(value.id || value.run_id))));
          state[descriptor.page] = next?.page || null;
          renderLists();
        } catch (error) {
          notify(apiUnavailableMessage(error), 'danger');
        } finally {
          setBusy(control, false);
        }
      };
      const renderLists = () => replace(body,
        scanJobQueue(state.jobs, {
          signal: current.signal,
          notify,
          onRefresh: () => renderList(outlet),
          page: state.jobsPage,
          onLoadMore: control => loadMore('jobs', control),
        }),
        state.runs.length ? deliveryTable(state.runs, {
          page: state.runsPage,
          onLoadMore: control => loadMore('runs', control),
        }) : emptyState(
          state.jobs.length ? 'No completed scanner runs yet' : 'No scanner runs yet',
          state.jobs.length
            ? 'Durable jobs remain visible above. A successful job creates an immutable run here.'
            : 'Start in Scan. Complete run records remain available until receipt-gated operational retention applies.',
          [h('a', { className: 'button button-primary', href: hrefFor('scan') }, 'Start a scan')],
        ),
        tombstoneTable(state.purged, {
          page: state.purgedPage,
          onLoadMore: control => loadMore('purged', control),
        }),
      );
      renderLists();
    } catch (error) {
      if (current.generation !== generation || !body?.isConnected) return;
      replace(body, notice(apiUnavailableMessage(error), 'warning', [button('Retry', { onClick: () => renderList(outlet) })]));
    }
  }

  async function renderDetail(outlet, runId) {
    const current = begin();
    replace(outlet,
      pageHeader(
        'Read-only scanner record',
        'Delivery detail',
        'This view cannot change findings or human review state.',
        [h('a', { className: 'button button-secondary', href: hrefFor('deliveries') }, 'Back to deliveries')],
      ),
      h('div', { id: 'delivery-detail-body' }, loadingState('Loading delivery record…')),
    );
    const body = outlet.querySelector('#delivery-detail-body');
    try {
      const [runPayload, connection, attemptsPayload, retention] = await Promise.all([
        request(endpoints.run(runId), { signal: current.signal }),
        request(endpoints.connection, { signal: current.signal }).catch(() => null),
        request(pagedEndpoint(endpoints.deliveryAttempts(runId)), { signal: current.signal }).catch(() => null),
        request(endpoints.retention, { signal: current.signal }).catch(() => null),
      ]);
      const run = normalizeRun(runPayload);
      if (attemptsPayload) {
        run.delivery.attempts = Array.isArray(attemptsPayload) ? attemptsPayload : attemptsPayload.attempts || [];
        run.delivery.attemptsPage = attemptsPayload.page || null;
      }
      const receiptExpectations = await buildReconciliationExpectations(run, connection, retention);
      if (current.generation !== generation || !body?.isConnected) return;
      const reconciliation = reconciliationReceiptPanel(run, receiptExpectations, {
        signal: current.signal,
        notify,
      });
      replace(body,
        renderRunPreview(run, {
          onDeliver: event => handleDelivery(event.currentTarget, run, body, outlet),
        }),
        reconciliation.node,
      );
      void reconciliation.refresh();
    } catch (error) {
      if (current.generation !== generation || !body?.isConnected) return;
      replace(body, notice(apiUnavailableMessage(error), 'warning', [button('Retry', { onClick: () => renderDetail(outlet, runId) })]));
    }
  }

  async function handleDelivery(control, run, body, outlet) {
    setBusy(control, true, run.delivery.state === 'retryable' || run.delivery.state === 'failed' ? 'Rechecking…' : 'Verifying…');
    try {
      const delivered = await deliverRun(run.id, {
        signal: controller?.signal,
        onUpdate: update => {
          if (body?.isConnected) replace(body, renderRunPreview(update));
        },
      });
      notify(delivered.delivery.state === 'delivered'
        ? 'Remote state is unchanged. A technical no-op receipt was recorded.'
        : 'Remote verification finished with an actionable status.',
      delivered.delivery.state === 'delivered' ? 'success' : 'warning');
      if (outlet.isConnected) await renderDetail(outlet, run.id);
    } catch (error) {
      if (!(error instanceof ApiError && error.code === 'canceled')) {
        notify(apiUnavailableMessage(error), 'danger');
      }
      setBusy(control, false);
    }
  }

  return { render, renderList, renderDetail, abort: () => controller?.abort() };
}

function scanJobQueue(jobs, { signal, notify, onRefresh, page = null, onLoadMore = null }) {
  const resumePanels = [];
  return h('div', { className: 'card table-card' },
    h('div', { className: 'section-heading' },
      h('div', {}, h('h2', {}, 'SSH collection jobs'),
        h('p', {}, 'Durable coordination records created before device I/O. Credentials are never persisted.')),
      badge(`${jobs.length} durable job${jobs.length === 1 ? '' : 's'}`, 'neutral'),
    ),
    h('div', { className: 'table-scroll', role: 'region', tabindex: '0', 'aria-label': 'SSH collection jobs' },
      h('table', { className: 'data-table' },
        h('thead', {}, h('tr', {},
          h('th', {}, 'Job'), h('th', {}, 'Target'), h('th', {}, 'Profile'), h('th', {}, 'State'), h('th', {}, 'Updated'), h('th', {}, 'Action'),
        )),
        h('tbody', {}, jobs.map((job, index) => {
          const state = text(job.state || 'unknown').toLowerCase();
          let resumeAction = null;
          if (state === 'failed' && job.resumable === true) {
            const panel = scanJobResumePanel(job, index, { signal, notify, onRefresh });
            resumePanels.push(panel);
            resumeAction = button('Resume safely', {
              tone: 'secondary',
              onClick: () => {
                const opening = panel.hidden;
                resumePanels.forEach(value => { value.hidden = true; });
                panel.hidden = !opening;
                if (opening) panel.querySelector('h3')?.focus();
              },
            });
          }
          return h('tr', {},
            h('td', {}, h('code', {}, text(job.id) || 'Unknown')),
            h('td', {}, text(job.request?.target?.host) || 'Bound target'),
            h('td', {}, text(job.request?.profile_id) || 'Bound profile'),
            h('td', {}, badge(state.replaceAll('_', ' '), state === 'failed' ? 'danger' : state === 'completed' ? 'success' : 'accent'),
              job.error ? h('p', { className: 'table-secondary' }, text(job.error)) : null,
              job.checkpoint?.reason ? h('p', { className: 'table-secondary' }, text(job.checkpoint.reason)) : null),
            h('td', {}, formatDate(job.updated_at || job.created_at)),
            h('td', {}, resumeAction || (state === 'completed' && job.run_id
              ? h('a', { className: 'table-link', href: hrefFor('deliveries', job.run_id) }, 'Open run')
              : state === 'failed' ? 'Not resumable' : 'Monitoring')),
          );
        })),
      ),
    ),
    resumePanels,
    paginationControl(page, 'Load more jobs', onLoadMore),
  );
}

function scanJobResumePanel(job, index, { signal, notify, onRefresh }) {
  const binding = scanJobBinding(job);
  const panel = h('section', {
    className: 'scan-job-resume-panel',
    hidden: true,
    'aria-label': `Resume SSH job ${text(job.id) || 'unknown'}`,
  });
  if (!binding) {
    replace(panel,
      h('h3', { tabindex: '-1' }, 'Resume unavailable'),
      notice('The durable job does not expose a complete, sanitized target binding. Start a new scan instead of guessing missing coordinates.', 'danger'),
    );
    return panel;
  }

  let preflightToken = null;
  const prefix = `resume-job-${index + 1}`;
  const status = h('div', { className: 'operation-result', role: 'status', 'aria-live': 'polite' });
  const credentialType = h('select', {},
    h('option', { value: 'password', selected: job.request?.auth_kind !== 'key_file' }, 'Fresh one-time password'),
    h('option', { value: 'key_file', selected: job.request?.auth_kind === 'key_file' }, 'Approved private-key file'),
  );
  const username = h('input', { type: 'text', autocomplete: 'off' });
  const password = h('input', { type: 'password', autocomplete: 'off' });
  const keyPath = h('input', { type: 'text', autocomplete: 'off', placeholder: '/approved/path/id_ed25519' });
  const keyPassphrase = h('input', { type: 'password', autocomplete: 'off' });
  const credentialFields = h('div', { className: 'credential-fields' });
  const acknowledgement = h('input', { type: 'checkbox' });
  const preflightControl = button('Run fresh preflight', { tone: 'secondary', disabled: true });
  const resumeControl = button('Resume from checkpoint', { tone: 'primary', disabled: true });

  const validCredential = () => Boolean(username.value.trim()) && (
    credentialType.value === 'password'
      ? Boolean(password.value)
      : credentialType.value === 'key_file' && absoluteFilePath(keyPath.value)
  );
  const updateControls = () => {
    preflightControl.disabled = !(validCredential() && acknowledgement.checked);
    resumeControl.disabled = !(preflightToken && validCredential() && acknowledgement.checked);
  };
  const invalidate = () => {
    preflightToken = null;
    resumeControl.disabled = true;
    replace(status);
    updateControls();
  };
  const renderCredentialFields = () => {
    replace(credentialFields,
      field(`${prefix}-username`, 'Username', username, 'Entered again for this resume attempt and never written to the durable job.'),
      credentialType.value === 'password'
        ? field(`${prefix}-password`, 'Fresh one-time password', password, 'Kept only through the fresh preflight, then cleared as soon as resume is submitted.')
        : h('div', { className: 'form-grid' },
            field(`${prefix}-key-path`, 'Private-key path', keyPath, 'Absolute scanner-host path only.'),
            field(`${prefix}-passphrase`, 'Fresh key passphrase (optional)', keyPassphrase, 'Cleared as soon as resume is submitted.'),
          ),
    );
    invalidate();
  };
  credentialType.addEventListener('change', renderCredentialFields);
  [username, password, keyPath, keyPassphrase].forEach(control => control.addEventListener('input', invalidate));
  acknowledgement.addEventListener('change', invalidate);

  preflightControl.addEventListener('click', async event => {
    const control = event.currentTarget;
    preflightToken = null;
    resumeControl.disabled = true;
    setBusy(control, true, 'Checking exact binding…');
    replace(status, loadingState('Rechecking device identity, host key, privilege, version, and the remaining read-only plan…'));
    try {
      const response = await request(endpoints.preflight, {
        method: 'POST',
        signal,
        timeoutMs: 60_000,
        body: resumePreflightRequest(binding, resumeCredential({
          credentialType, username, password, keyPath, keyPassphrase,
        }), acknowledgement.checked),
      });
      const value = response?.preflight || response || {};
      const ready = Boolean(value.ready ?? value.passed ?? value.compatible);
      const token = text(value.preflight_token || value.token || value.id);
      if (!ready || !token) {
        clearResumeSecrets(password, keyPassphrase);
        replace(status, notice(value.reason || 'Fresh preflight did not establish a resumable exact binding. No checkpoint evidence was used.', 'danger'));
        return;
      }
      preflightToken = token;
      replace(status,
        notice('Fresh preflight passed. Review the unchanged coordinates, then resume before the short-lived preflight expires.', 'success'),
        definitionList([
          ['Observed identity', value.device_identity?.hostname || value.identity?.hostname || value.device_identity?.fingerprint || 'Verified by the scanner'],
          ['Read-only operations', Array.isArray(value.operations) ? value.operations.length : 'Bound by the preflight'],
          ['Preflight expires', value.expires_at || 'Bound by server policy'],
        ]),
      );
    } catch (error) {
      clearResumeSecrets(password, keyPassphrase);
      replace(status, notice(apiUnavailableMessage(error), 'danger'));
    } finally {
      setBusy(control, false);
      updateControls();
    }
  });

  resumeControl.addEventListener('click', async event => {
    if (!preflightToken) return;
    const control = event.currentTarget;
    setBusy(control, true, 'Claiming failed job…');
    replace(status, loadingState('Submitting the exact saved coordinates with the fresh preflight and fresh credential…'));
    try {
      const response = await request(endpoints.resumeJob(job.id), {
        method: 'POST',
        signal,
        timeoutMs: 60_000,
        body: resumeJobRequest(binding, preflightToken, resumeCredential({
          credentialType, username, password, keyPath, keyPassphrase,
        })),
      });
      clearResumeSecrets(password, keyPassphrase);
      preflightToken = null;
      replace(status, notice(response?.message || 'Resume started. The checkpoint remains usable only if every fresh binding matches.', 'success'));
      notify('SSH resume started with fresh credentials and an exact fresh preflight.', 'success');
      await onRefresh();
    } catch (error) {
      clearResumeSecrets(password, keyPassphrase);
      preflightToken = null;
      replace(status, notice(apiUnavailableMessage(error), 'danger'));
      notify(apiUnavailableMessage(error), 'danger');
    } finally {
      setBusy(control, false);
      updateControls();
    }
  });

  replace(panel,
    h('div', { className: 'section-heading' },
      h('div', {},
        h('p', { className: 'card-kicker' }, `Failed job ${job.id}`),
        h('h3', { tabindex: '-1' }, 'Resume with a fresh safety check'),
        h('p', {}, 'Coordinates are locked to the durable job. Only fresh authentication and a new short-lived preflight are accepted.'),
      ),
      badge('No stored credentials', 'success'),
    ),
    definitionList([
      ['Mode', binding.mode],
      ['Profile', binding.profileId],
      ['Saved target profile', binding.connectionProfileId || 'None'],
      ['Target', `${binding.target.host}:${binding.target.port}`],
      ['Destination', binding.destination
        ? `${binding.destination.collection_id} / ${binding.destination.asset_id} / ${binding.destination.assignment_id}`
        : 'Disconnected handoff'],
    ]),
    h('div', { className: 'form-grid resume-credential-grid' },
      field(`${prefix}-credential-type`, 'Fresh credential type', credentialType),
      h('div', {}, credentialFields),
    ),
    h('label', { className: 'confirmation-row' }, acknowledgement,
      h('span', {}, 'I confirm these exact saved coordinates are still intended and acknowledge any experimental pilot status for this fresh preflight.'),
    ),
    h('div', { className: 'button-row' }, preflightControl, resumeControl),
    status,
  );
  renderCredentialFields();
  return panel;
}

function scanJobBinding(job) {
  const requestValue = job?.request;
  if (!requestValue || typeof requestValue !== 'object' || Array.isArray(requestValue)) return null;
  const mode = text(requestValue.mode).toLowerCase();
  const profileId = text(requestValue.profile_id);
  const target = requestValue.target;
  const port = Number(target?.port);
  if (!['connected', 'disconnected'].includes(mode) || !profileId || !text(target?.host)
    || !Number.isInteger(port) || port < 1 || port > 65535) return null;
  let destination = null;
  if (mode === 'connected') {
    const value = requestValue.destination;
    if (!value || !text(value.collection_id) || !text(value.asset_id) || !text(value.assignment_id)) return null;
    destination = {
      collection_id: text(value.collection_id),
      asset_id: text(value.asset_id),
      assignment_id: text(value.assignment_id),
    };
  } else if (requestValue.destination != null) {
    return null;
  }
  return {
    mode,
    profileId,
    connectionProfileId: requestValue.connection_profile_id == null ? null : text(requestValue.connection_profile_id),
    destination,
    target: { host: text(target.host), port },
  };
}

function resumeCredential({ credentialType, username, password, keyPath, keyPassphrase }) {
  const credential = { type: credentialType.value, username: username.value.trim() };
  if (credential.type === 'password') credential.password = password.value;
  if (credential.type === 'key_file') {
    credential.path = keyPath.value.trim();
    credential.passphrase = keyPassphrase.value || null;
  }
  return credential;
}

function resumePreflightRequest(binding, credential, pilotAcknowledged) {
  return {
    mode: binding.mode,
    profile_id: binding.profileId,
    connection_profile_id: binding.connectionProfileId,
    collection_method: 'ssh',
    destination: binding.destination,
    target: binding.target,
    credential,
    pilot_acknowledged: Boolean(pilotAcknowledged),
  };
}

function resumeJobRequest(binding, preflightToken, credential) {
  return {
    preflight_token: preflightToken,
    mode: binding.mode,
    profile_id: binding.profileId,
    connection_profile_id: binding.connectionProfileId,
    destination: binding.destination,
    target: binding.target,
    credential,
  };
}

function absoluteFilePath(value) {
  const candidate = text(value).trim();
  return candidate.startsWith('/') || /^[A-Za-z]:[\\/]/.test(candidate);
}

function clearResumeSecrets(...inputs) {
  inputs.forEach(input => { if (input) input.value = ''; });
}

async function buildReconciliationExpectations(run, connectionValue, retentionValue = null) {
  const connection = connectionValue?.connection || connectionValue || {};
  const ruleIds = [...new Set(run.proposed
    .map(review => text(review.rule_id || review.ruleId || review.vuln_id || review.key))
    .filter(Boolean))]
    .sort();
  const apiUrl = text(connection.api_url);
  const remoteUrl = text(connection.gui_url || run.delivery.remoteUrl);
  let destinationInstanceId = '';
  let receivedRuleSetSha256 = '';
  try {
    if (apiUrl) destinationInstanceId = await sha256Text(apiUrl);
    if (ruleIds.length) receivedRuleSetSha256 = await sha256Text(JSON.stringify(ruleIds));
  } catch (_) {
    // Import remains fail-closed when this browser cannot calculate the exact bindings.
  }
  const expected = {
    runId: run.id,
    payloadSha256: run.delivery.payloadSha256,
    destinationInstanceId,
    collectionId: run.collectionId,
    assetId: run.assetId,
    assignmentId: run.assignmentId,
    stigId: run.stigId,
    stigRevision: run.stigRevision,
    ruleIds,
    receivedRuleSetSha256,
    remoteUrl,
    completedAt: run.completedAt,
    operationalRetentionDays: Number(retentionValue?.operational_history?.effective_days) || null,
  };
  expected.missing = [
    ['run ID', expected.runId],
    ['delivery payload SHA-256', SHA256_PATTERN.test(expected.payloadSha256)],
    ['configured STIG Manager instance digest', SHA256_PATTERN.test(expected.destinationInstanceId)],
    ['collection ID', expected.collectionId],
    ['asset ID', expected.assetId],
    ['assignment ID', expected.assignmentId],
    ['STIG ID', expected.stigId],
    ['STIG revision', expected.stigRevision],
    ['scanner-owned rule IDs', expected.ruleIds.length > 0],
    ['rule-set SHA-256', SHA256_PATTERN.test(expected.receivedRuleSetSha256)],
    ['credential-free HTTPS STIG Manager GUI base URL', safeExternalUrl(expected.remoteUrl) && expected.remoteUrl.endsWith('/')],
  ].filter(([, present]) => !present).map(([label]) => label);
  expected.ready = expected.missing.length === 0;
  return expected;
}

function reconciliationReceiptPanel(run, expectations, { signal, notify }) {
  const receiptList = h('div', { className: 'reconciliation-receipt-list', role: 'status', 'aria-live': 'polite' }, loadingState('Loading receiver receipts…'));
  const importStatus = h('div', { className: 'operation-result', role: 'status', 'aria-live': 'polite' });
  const fileInput = h('input', { type: 'file', accept: '.json,application/json' });
  const textInput = h('textarea', {
    rows: 16,
    maxlength: MAX_RECEIPT_BYTES,
    spellcheck: false,
    autocomplete: 'off',
    placeholder: 'Paste the receiver-produced reconciliation JSON, or select its .json file above.',
  });
  const confirmation = h('input', { type: 'checkbox' });
  const importControl = button('Import receiver receipt', { tone: 'primary', disabled: true });
  const refreshControl = button('Refresh receipts', { tone: 'secondary' });
  const templateControl = button('Load run-bound schema template', { tone: 'secondary', disabled: !expectations.ready });

  const updateImportControl = () => {
    importControl.disabled = !expectations.ready || !textInput.value.trim() || !confirmation.checked;
  };
  textInput.addEventListener('input', updateImportControl);
  confirmation.addEventListener('change', updateImportControl);
  fileInput.addEventListener('change', async () => {
    const [file] = fileInput.files || [];
    if (!file) return;
    try {
      textInput.value = await readBoundedReceiptFile(file);
      replace(importStatus, notice(`Loaded ${file.name} into this in-memory form. Review every binding before import.`, 'info'));
    } catch (error) {
      fileInput.value = '';
      textInput.value = '';
      replace(importStatus, notice(error.message, 'danger'));
    }
    updateImportControl();
  });
  templateControl.addEventListener('click', () => {
    textInput.value = JSON.stringify(reconciliationTemplate(expectations), null, 2);
    replace(importStatus, notice('Template loaded. Replace the receiver ID, independent-readback digest, timestamp, and repeated nested readback digest with values from the receiving system.', 'warning'));
    updateImportControl();
    textInput.focus();
  });

  let receipts = [];
  let receiptsPage = null;
  const renderReceipts = () => replace(receiptList,
    renderReconciliationReceiptList(receipts),
    paginationControl(receiptsPage, 'Load more receiver receipts', async control => {
      setBusy(control, true, 'Loading…');
      try {
        const payload = await request(pagedEndpoint(endpoints.reconciliationReceipts(run.id), {
          offset: receiptsPage.next_offset,
          limit: receiptsPage.limit || 25,
        }), { signal });
        const rows = Array.isArray(payload) ? payload : payload?.receipts || [];
        const seen = new Set(receipts.map(receipt => text(receipt.id)));
        receipts.push(...rows.filter(receipt => !seen.has(text(receipt.id))));
        receiptsPage = payload?.page || null;
        renderReceipts();
      } catch (error) {
        replace(importStatus, notice(apiUnavailableMessage(error), 'danger'));
      } finally {
        setBusy(control, false);
      }
    }),
  );
  const refresh = async () => {
    setBusy(refreshControl, true, 'Refreshing…');
    replace(receiptList, loadingState('Loading receiver receipts…'));
    try {
      const payload = await request(pagedEndpoint(endpoints.reconciliationReceipts(run.id)), { signal });
      receipts = Array.isArray(payload) ? payload : payload?.receipts || [];
      receiptsPage = payload?.page || null;
      renderReceipts();
    } catch (error) {
      replace(receiptList, notice(apiUnavailableMessage(error), 'warning'));
    } finally {
      setBusy(refreshControl, false);
    }
  };
  refreshControl.addEventListener('click', refresh);

  importControl.addEventListener('click', async event => {
    if (!confirmation.checked || !expectations.ready) return;
    const control = event.currentTarget;
    setBusy(control, true, 'Validating receipt…');
    replace(importStatus, loadingState('Validating exact destination, payload, rule-set, readback, and nested receipt bindings…'));
    try {
      const body = await parseReconciliationReceipt(textInput.value, expectations);
      // Confirmation comes from this deliberate UI action, never merely from
      // a boolean asserted inside an uploaded receiver document.
      body.operator_confirmed = true;
      await request(endpoints.reconciliationReceipts(run.id), {
        method: 'POST',
        signal,
        body,
      });
      textInput.value = '';
      fileInput.value = '';
      confirmation.checked = false;
      replace(importStatus, notice('Receiver receipt imported as an append-only, operator-confirmed unsigned record.', 'success'));
      notify('Receiver reconciliation receipt imported and bound to this exact run.', 'success');
      await refresh();
    } catch (error) {
      const message = error instanceof ApiError ? apiUnavailableMessage(error) : error.message;
      replace(importStatus, notice(message || 'The reconciliation receipt could not be imported.', 'danger'));
      notify(message || 'The reconciliation receipt could not be imported.', 'danger');
    } finally {
      setBusy(control, false);
      updateImportControl();
    }
  });

  const template = JSON.stringify(reconciliationTemplate(expectations), null, 2);
  const node = h('section', { className: 'card reconciliation-panel' },
    h('div', { className: 'section-heading' },
      h('div', {},
        h('h2', {}, 'Receiver reconciliation receipts'),
        h('p', {}, 'Append-only proof that the selected sparse payload was reconciled and independently read back at its exact destination. This does not import or edit STIG Manager reviews.'),
      ),
      refreshControl,
    ),
    receiptList,
    h('div', { className: 'reconciliation-import' },
      h('div', { className: 'section-heading' },
        h('div', {},
          h('h3', {}, 'Import a receiver-produced receipt'),
          h('p', {}, 'Use the receipt created after an authorized receiver verifies the handoff, reconciles it, and independently reads the destination back.'),
        ),
        badge('1 MiB maximum', 'neutral'),
      ),
      expectations.ready ? null : notice(
        `Receipt import is unavailable because this run view lacks: ${expectations.missing.join(', ')}. Restore the exact configured destination or reload the run; do not guess these values.`,
        'warning',
      ),
      h('details', { className: 'receipt-schema-guidance' },
        h('summary', {}, 'Show exact v1 JSON schema and run-bound template'),
        h('p', {}, 'The top-level document accepts only these fields. The nested receipt must repeat every shown binding; received_rule_ids must be sorted and received_rule_set_sha256 is SHA-256 of its compact JSON array.'),
        h('pre', {}, h('code', {}, template)),
      ),
      field('reconciliation-receipt-file-v1', 'Receiver receipt file (optional)', fileInput, 'JSON only. The complete file is read into this tab, bounded to 1 MiB, and is never stored by the browser.'),
      field('reconciliation-receipt-json-v1', 'Receiver receipt JSON', textInput, 'Review the destination and readback bindings below before confirming.'),
      h('div', { className: 'button-row' }, templateControl),
      definitionList([
        ['Run', expectations.runId || 'Unavailable'],
        ['Sparse payload SHA-256', expectations.payloadSha256 || 'Unavailable'],
        ['Destination instance SHA-256', expectations.destinationInstanceId || 'Unavailable'],
        ['Collection / asset / assignment', [expectations.collectionId, expectations.assetId, expectations.assignmentId].filter(Boolean).join(' / ') || 'Unavailable'],
        ['STIG release', [expectations.stigId, expectations.stigRevision].filter(Boolean).join(' · ') || 'Unavailable'],
        ['Exact scanner-owned rules', expectations.ruleIds.length ? `${expectations.ruleIds.length} · ${expectations.receivedRuleSetSha256}` : 'Unavailable'],
        ['STIG Manager GUI base URL', expectations.remoteUrl || 'Unavailable'],
        ['Accepted readback time', `${expectations.completedAt ? `not before run completion ${formatDate(expectations.completedAt)}` : 'not before immutable run completion'}; no more than 5 minutes in the future${expectations.operationalRetentionDays ? `; within the effective ${expectations.operationalRetentionDays}-day operational-retention window` : ''}`],
      ]),
      h('label', { className: 'confirmation-row' }, confirmation,
        h('span', {}, 'I independently reviewed this receiver document and confirm it represents the exact destination readback shown above. I understand it is stored as operator-confirmed and unsigned.'),
      ),
      h('div', { className: 'button-row' }, importControl),
      importStatus,
    ),
  );
  return { node, refresh };
}

function reconciliationTemplate(expected) {
  const readbackPlaceholder = '<REPLACE-WITH-64-HEX-INDEPENDENT-READBACK-SHA256>';
  return {
    id: 'REPLACE-WITH-RECEIVER-RECEIPT-ID',
    schema: RECEIVER_RECEIPT_SCHEMA,
    payload_sha256: expected.payloadSha256 || '<RUN-PAYLOAD-SHA256>',
    destination_kind: 'stig_manager',
    destination_instance_id: expected.destinationInstanceId || '<STIG-MANAGER-INSTANCE-SHA256>',
    destination_collection_id: expected.collectionId || '<COLLECTION-ID>',
    destination_asset_id: expected.assetId || '<ASSET-ID>',
    destination_assignment_id: expected.assignmentId || '<ASSIGNMENT-ID>',
    stig_id: expected.stigId || '<STIG-ID>',
    stig_revision: expected.stigRevision || '<STIG-REVISION>',
    received_rule_ids: expected.ruleIds,
    independent_readback_sha256: readbackPlaceholder,
    independent_readback_at: '<REPLACE-WITH-RFC3339-READBACK-TIME>',
    receipt: {
      schema: RECEIVER_RECEIPT_SCHEMA,
      run_id: expected.runId || '<RUN-ID>',
      payload_sha256: expected.payloadSha256 || '<RUN-PAYLOAD-SHA256>',
      destination_instance_id: expected.destinationInstanceId || '<STIG-MANAGER-INSTANCE-SHA256>',
      destination_collection_id: expected.collectionId || '<COLLECTION-ID>',
      destination_asset_id: expected.assetId || '<ASSET-ID>',
      destination_assignment_id: expected.assignmentId || '<ASSIGNMENT-ID>',
      stig_id: expected.stigId || '<STIG-ID>',
      stig_revision: expected.stigRevision || '<STIG-REVISION>',
      received_rule_set_sha256: expected.receivedRuleSetSha256 || '<RECEIVED-RULE-SET-SHA256>',
      independent_readback_sha256: readbackPlaceholder,
      independent_readback_at: '<REPLACE-WITH-RFC3339-READBACK-TIME>',
      remote_url: expected.remoteUrl || '<STIG-MANAGER-GUI-BASE-URL>',
    },
    remote_url: expected.remoteUrl || '<STIG-MANAGER-GUI-BASE-URL>',
    operator_confirmed: false,
  };
}

async function readBoundedReceiptFile(file) {
  if (Number(file.size) > MAX_RECEIPT_BYTES) {
    throw new Error('Receiver receipt files are limited to 1 MiB. Preserve larger material outside AutomateSTIG and provide only the bounded receipt document.');
  }
  const value = await file.text();
  if (utf8Bytes(value) > MAX_RECEIPT_BYTES) {
    throw new Error('The decoded receiver receipt exceeds the 1 MiB limit.');
  }
  return value;
}

async function parseReconciliationReceipt(source, expected) {
  if (utf8Bytes(source) > MAX_RECEIPT_BYTES) throw new Error('Receiver receipt JSON exceeds the 1 MiB limit.');
  let documentValue;
  try {
    documentValue = JSON.parse(source);
  } catch (error) {
    throw new Error(`Receiver receipt is not valid JSON: ${error.message}`);
  }
  if (!documentValue || typeof documentValue !== 'object' || Array.isArray(documentValue)) {
    throw new Error('Receiver receipt must be one JSON object.');
  }
  const allowed = new Set([
    'id', 'schema', 'payload_sha256', 'destination_kind', 'destination_instance_id',
    'destination_collection_id', 'destination_asset_id', 'destination_assignment_id',
    'stig_id', 'stig_revision', 'received_rule_ids', 'independent_readback_sha256',
    'independent_readback_at', 'receipt', 'remote_url', 'operator_confirmed',
  ]);
  const unknown = Object.keys(documentValue).filter(key => !allowed.has(key));
  if (unknown.length) throw new Error(`Receiver receipt has unsupported top-level field${unknown.length === 1 ? '' : 's'}: ${unknown.join(', ')}.`);
  if (!/^[A-Za-z0-9._-]{1,128}$/.test(text(documentValue.id))) {
    throw new Error('Receipt ID must contain at most 128 letters, digits, dots, underscores, or hyphens.');
  }
  const exact = [
    ['schema', RECEIVER_RECEIPT_SCHEMA],
    ['payload_sha256', expected.payloadSha256],
    ['destination_kind', 'stig_manager'],
    ['destination_instance_id', expected.destinationInstanceId],
    ['destination_collection_id', expected.collectionId],
    ['destination_asset_id', expected.assetId],
    ['destination_assignment_id', expected.assignmentId],
    ['stig_id', expected.stigId],
    ['stig_revision', expected.stigRevision],
    ['remote_url', expected.remoteUrl],
  ];
  const changed = exact.filter(([key, value]) => documentValue[key] !== value).map(([key]) => key);
  if (changed.length) throw new Error(`Receiver receipt does not match this run's exact ${changed.join(', ')} binding${changed.length === 1 ? '' : 's'}.`);
  if (!SHA256_PATTERN.test(text(documentValue.independent_readback_sha256))) {
    throw new Error('independent_readback_sha256 must be a 64-character hexadecimal digest from an independent destination readback.');
  }
  const readbackAt = Date.parse(documentValue.independent_readback_at);
  if (!Number.isFinite(readbackAt) || !/^\d{4}-\d{2}-\d{2}T/.test(text(documentValue.independent_readback_at))) {
    throw new Error('independent_readback_at must be an RFC 3339 timestamp.');
  }
  if (readbackAt > Date.now() + 5 * 60_000) throw new Error('independent_readback_at cannot be more than five minutes in the future.');
  const completedAt = Date.parse(expected.completedAt);
  if (Number.isFinite(completedAt) && readbackAt < completedAt) {
    throw new Error('independent_readback_at cannot predate this immutable scan run’s completion time.');
  }
  if (Number.isFinite(expected.operationalRetentionDays)
    && readbackAt < Date.now() - expected.operationalRetentionDays * 24 * 60 * 60_000) {
    throw new Error(`independent_readback_at is outside the effective ${expected.operationalRetentionDays}-day operational-retention window.`);
  }
  if (!Array.isArray(documentValue.received_rule_ids)
    || JSON.stringify(documentValue.received_rule_ids) !== JSON.stringify(expected.ruleIds)) {
    throw new Error('received_rule_ids must exactly equal this run’s sorted scanner-owned rule set.');
  }
  const ruleSetSha256 = await sha256Text(JSON.stringify(documentValue.received_rule_ids));
  if (ruleSetSha256 !== expected.receivedRuleSetSha256) {
    throw new Error('The received rule-set digest no longer matches this run. Reload the delivery detail before importing.');
  }
  const receipt = documentValue.receipt;
  if (!receipt || typeof receipt !== 'object' || Array.isArray(receipt)) {
    throw new Error('receipt must be a nested receiver JSON object that repeats every exact binding.');
  }
  const nested = [
    ['schema', RECEIVER_RECEIPT_SCHEMA],
    ['run_id', expected.runId],
    ['payload_sha256', expected.payloadSha256],
    ['destination_instance_id', expected.destinationInstanceId],
    ['destination_collection_id', expected.collectionId],
    ['destination_asset_id', expected.assetId],
    ['destination_assignment_id', expected.assignmentId],
    ['stig_id', expected.stigId],
    ['stig_revision', expected.stigRevision],
    ['received_rule_set_sha256', ruleSetSha256],
    ['independent_readback_sha256', documentValue.independent_readback_sha256],
    ['independent_readback_at', documentValue.independent_readback_at],
    ['remote_url', expected.remoteUrl],
  ];
  const nestedChanged = nested.filter(([key, value]) => receipt[key] !== value).map(([key]) => `receipt.${key}`);
  if (nestedChanged.length) throw new Error(`Nested receiver document does not repeat the exact ${nestedChanged.join(', ')} binding${nestedChanged.length === 1 ? '' : 's'}.`);
  rejectCredentialMaterial(documentValue);
  return documentValue;
}

function rejectCredentialMaterial(value, path = '$') {
  if (Array.isArray(value)) {
    value.forEach((item, index) => rejectCredentialMaterial(item, `${path}[${index}]`));
    return;
  }
  if (value && typeof value === 'object') {
    for (const [key, child] of Object.entries(value)) {
      const normalized = key.replaceAll(/[^A-Za-z0-9]/g, '').toLowerCase();
      const sensitive = ['password', 'passphrase', 'secret', 'token', 'apikey', 'privatekey', 'authorization', 'cookie', 'credential', 'credentials']
        .some(suffix => normalized.endsWith(suffix));
      if (sensitive && child != null && typeof child !== 'boolean') {
        throw new Error(`Receiver receipt field ${path}.${key} appears to contain credential material and cannot be imported.`);
      }
      rejectCredentialMaterial(child, `${path}.${key}`);
    }
    return;
  }
  if (typeof value === 'string') {
    const candidate = value.trim();
    const lowercase = candidate.toLowerCase();
    if ((candidate.includes('-----BEGIN ') && candidate.includes('PRIVATE KEY-----'))
      || lowercase.startsWith('bearer ') || lowercase.startsWith('basic ')
      || lowercase.includes('authorization: bearer ') || lowercase.includes('authorization: basic ')) {
      throw new Error(`Receiver receipt value ${path} appears to contain credential material and cannot be imported.`);
    }
  }
}

function renderReconciliationReceiptList(receipts) {
  if (!receipts.length) {
    return emptyState('No receiver receipts yet', 'After an authorized receiver reconciles the selected handoff and independently reads the destination back, import its exact digest-bound receipt below.');
  }
  return h('ol', { className: 'receipt-records' }, receipts.map(receipt => h('li', {},
    h('div', { className: 'section-heading' },
      h('div', {},
        h('strong', {}, boundedText(receipt.id) || 'Receiver receipt'),
        h('p', {}, `Imported ${formatDate(receipt.imported_at)}`),
      ),
      badge(receipt.operator_confirmed ? 'Operator-confirmed unsigned' : boundedText(receipt.producer_authentication || 'Unverified'), receipt.operator_confirmed ? 'warning' : 'neutral'),
    ),
    definitionList([
      ['Payload SHA-256', boundedText(receipt.payload_sha256) || 'Not returned'],
      ['Destination', [receipt.destination_collection_id, receipt.destination_asset_id, receipt.destination_assignment_id].filter(Boolean).map(value => boundedText(value)).join(' / ') || 'Not returned'],
      ['Received rules', Array.isArray(receipt.received_rule_ids) ? receipt.received_rule_ids.length : 'Not returned'],
      ['Rule-set SHA-256', boundedText(receipt.received_rule_set_sha256) || 'Not returned'],
        ['Independent readback', `${formatDate(receipt.independent_readback_at)} · ${boundedText(receipt.independent_readback_sha256) || 'digest not returned'}`],
      ['Receipt SHA-256', boundedText(receipt.receipt_sha256) || 'Not returned'],
    ]),
  )));
}

async function sha256Text(value) {
  if (!globalThis.crypto?.subtle) throw new Error('This browser cannot calculate the required SHA-256 receipt binding.');
  const digest = await globalThis.crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
  return [...new Uint8Array(digest)].map(byte => byte.toString(16).padStart(2, '0')).join('');
}

function utf8Bytes(value) {
  return new TextEncoder().encode(text(value)).byteLength;
}

function paginationControl(page, label, onLoadMore) {
  if (page?.next_offset == null || typeof onLoadMore !== 'function') return null;
  return h('div', { className: 'pagination-row' }, button(label, {
    tone: 'secondary',
    onClick: event => onLoadMore(event.currentTarget),
  }));
}

function deliveryTable(runs, { page = null, onLoadMore = null } = {}) {
  return h('div', { className: 'card table-card' },
    h('div', { className: 'section-heading' },
      h('div', {}, h('h2', {}, 'Scanner runs'), h('p', {}, 'Immutable scanner result records and delivery state.')),
      badge(`${runs.length} loaded`, 'neutral'),
    ),
    h('div', { className: 'table-scroll', role: 'region', tabindex: '0', 'aria-label': 'Scanner delivery records' },
      h('table', { className: 'data-table' },
        h('thead', {}, h('tr', {},
          h('th', { scope: 'col' }, 'Run'),
          h('th', { scope: 'col' }, 'Destination'),
          h('th', { scope: 'col' }, 'Profile'),
          h('th', { scope: 'col' }, 'State'),
          h('th', { scope: 'col' }, 'Updated'),
        )),
        h('tbody', {}, runs.map(run => h('tr', {},
          h('td', {}, h('a', { className: 'table-link', href: hrefFor('deliveries', run.id) }, run.id || 'Unknown run')),
          h('td', {}, run.collectionName || run.collectionId
            ? `${run.collectionName || run.collectionId} / ${run.assetName || run.assetId || 'asset'}`
            : 'Disconnected handoff'),
          h('td', {}, run.profileTitle, run.stigRevision ? h('span', { className: 'cell-subtitle' }, run.stigRevision) : null),
          h('td', {}, runStateBadge(run)),
          h('td', {}, formatDate(run.updatedAt || run.createdAt)),
        ))),
      ),
    ),
    paginationControl(page, 'Load more runs', onLoadMore),
  );
}

function tombstoneTable(tombstones, { page = null, onLoadMore = null } = {}) {
  return h('div', { className: 'card table-card tombstone-card' },
    h('div', { className: 'section-heading' },
      h('div', {},
        h('h2', {}, 'Purged operational history'),
        h('p', {}, 'Append-only tombstones retained after receipt-gated operational rows are pruned. A tombstone is custody metadata, not a compliance result.'),
      ),
      badge(`${tombstones.length} loaded`, 'neutral'),
    ),
    tombstones.length ? h('div', { className: 'table-scroll', role: 'region', tabindex: '0', 'aria-label': 'Purged operational history tombstones' },
      h('table', { className: 'data-table compact-table' },
        h('thead', {}, h('tr', {},
          h('th', {}, 'Run'), h('th', {}, 'Destination'), h('th', {}, 'Receipt'), h('th', {}, 'Bound digests'), h('th', {}, 'Purged'),
        )),
        h('tbody', {}, tombstones.map(record => h('tr', {},
          h('td', {}, h('code', {}, text(record.run_id) || 'Unknown')),
          h('td', {}, [record.destination_collection_id, record.destination_asset_id, record.destination_assignment_id].filter(Boolean).map(text).join(' / ') || text(record.destination_kind) || 'Unknown'),
          h('td', {}, `${text(record.receipt_kind) || 'receipt'} · ${text(record.receipt_id) || 'unknown'}`,
            h('span', { className: 'cell-subtitle' }, text(record.receipt_sha256) || 'No receipt digest')),
          h('td', {}, h('details', { className: 'hash-details' },
            h('summary', {}, 'Show digests'),
            definitionList([
              ['Request', text(record.request_sha256) || 'Not returned'],
              ['Result', text(record.result_sha256) || 'Not returned'],
              ['Evidence', text(record.evidence_sha256) || 'Not returned'],
              ['Payload', text(record.payload_sha256) || 'Not returned'],
            ]),
          )),
          h('td', {}, formatDate(record.purged_at)),
        ))),
      ),
    ) : notice('No receipt-gated operational histories have been purged.', 'info'),
    paginationControl(page, 'Load more tombstones', onLoadMore),
  );
}

export function renderRunPreview(runLike, { onDeliver = null, embedded = false } = {}) {
  const run = runLike?.delivery && Array.isArray(runLike?.proposed) && 'profileTitle' in runLike
    ? runLike
    : normalizeRun(runLike);
  const remoteUrl = safeExternalUrl(run.delivery.remoteUrl);
  const collectionIncomplete = run.collectionComplete === false || run.state === 'incomplete';
  const sparsePreviewAvailable = !collectionIncomplete && (
    Array.isArray(run.delivery.preview?.reviews)
      || Array.isArray(run.raw?.proposed_reviews)
      || Array.isArray(run.raw?.result?.proposed_reviews)
      || Array.isArray(run.raw?.result?.reviews)
  );
  const previewCounts = collectionIncomplete
    ? { create: null, update: null, unchanged: null, conflict: null }
    : deliveryChangeCounts(run.delivery.preview, run.proposed);
  const hasKnownConflict = Number(previewCounts.conflict || 0) > 0;
  const previewWarning = text(run.delivery.preview?.warning);
  const needsReconciliation = run.delivery.receipt?.partial_remote_acceptance === true;
  const canDeliver = run.id && ['preview_ready', 'completed', 'complete'].includes(run.state)
    && sparsePreviewAvailable
    && !hasKnownConflict
    && !previewWarning
    && !['delivered', 'sending'].includes(run.delivery.state);
  const canRetry = run.id && ['retryable', 'failed', 'conflicted'].includes(run.delivery.state)
    && !needsReconciliation;
  const deliveryControl = onDeliver && (canDeliver || canRetry)
    ? button(run.delivery.state === 'conflicted' ? 'Recheck remote state'
      : canRetry ? 'Retry remote verification' : 'Confirm remote no-op', { tone: 'primary', onClick: onDeliver })
    : null;
  return h('div', { className: `run-preview ${embedded ? 'run-preview-embedded' : ''}` },
    h('section', { className: 'card run-summary-card' },
      h('div', { className: 'section-heading' },
        h('div', {},
          h('p', { className: 'card-kicker' }, run.id ? `Run ${run.id}` : 'Current run'),
          h('h2', {}, run.profileTitle),
          h('p', {}, [run.stigId, run.stigRevision].filter(Boolean).join(' · ') || 'Profile identity pending'),
        ),
        runStateBadge(run),
      ),
      progressSteps(run.stage, normalizeStepStates(run)),
      h('div', { className: 'metric-grid' },
        metric('Automated results', run.automatedCount ?? run.proposed.length,
          run.fullBenchmarkRules == null ? 'Scanner-owned rules only' : `of ${run.fullBenchmarkRules} full benchmark rules`),
        metric('Automation coverage', formatPercent(run.coveragePct),
          collectionIncomplete
            ? `Profile capability only; this run did not complete · Not a compliance score${run.fullBenchmarkRules == null ? '' : ` · ${run.fullBenchmarkRules} benchmark rules`}`
            : run.fullBenchmarkRules == null ? 'Not a compliance score' : `Not a compliance score · ${run.fullBenchmarkRules} benchmark rules`),
        metric('Reviewed profile', run.reviewedRules ?? '—', 'Automated plus reviewed-manual scope'),
        metric('Manual untouched', run.manualUntouched ?? '—',
          run.outOfScopeUntouched == null ? 'Complete in STIG Manager' : `plus ${run.outOfScopeUntouched} outside this profile`),
        metric('Collection', run.collectionComplete === true ? 'Complete' : run.collectionComplete === false ? 'Incomplete' : 'Pending'),
      ),
      definitionList([
        ['Collection', run.collectionName || run.collectionId || 'Disconnected'],
        ['Asset', run.assetName || run.assetId || 'No remote destination'],
        ['Assignment', run.assignmentId || 'Not bound'],
        ['Endpoint', run.endpoint || 'Not returned'],
        ['Created', formatDate(run.createdAt)],
      ]),
    ),

    run.collectionErrors.length ? h('section', { className: 'card' },
      h('div', { className: 'section-heading' },
        h('div', {}, h('h2', {}, 'Collection diagnostics'), h('p', {}, 'Incomplete or ambiguous evidence is never delivered as a compliance result.')),
        badge(`${run.collectionErrors.length} issue${run.collectionErrors.length === 1 ? '' : 's'}`, 'danger'),
      ),
      h('ul', { className: 'diagnostic-list' }, run.collectionErrors.map(error => h('li', {}, describeError(error)))),
    ) : null,

    h('section', { className: 'card' },
      h('div', { className: 'section-heading' },
        h('div', {},
          h('h2', {}, 'Delivery preview'),
          h('p', {}, 'Read-only preview of scanner-owned remote changes. Human and out-of-scope reviews remain untouched.'),
        ),
        badge(run.delivery.state.replaceAll('_', ' ') || 'Not started', run.delivery.state === 'delivered' ? 'success' : 'neutral'),
      ),
      h('div', { className: 'change-grid' },
        changeCount('Create', previewCounts.create, 'success'),
        changeCount('Update', previewCounts.update, 'warning'),
        changeCount('Unchanged', previewCounts.unchanged, 'neutral'),
        changeCount('Conflict', previewCounts.conflict, 'danger'),
        changeCount('Manual untouched', run.manualUntouched, 'neutral'),
        changeCount('Out of scope untouched', run.outOfScopeUntouched, 'neutral'),
      ),
      !collectionIncomplete && run.proposed.length
        ? proposedReviewTable(run.proposed)
        : notice(
            collectionIncomplete
              ? previewWarning || 'Collection was incomplete; no sparse delivery preview or payload was created. Resolve the collection diagnostics and run again.'
              : sparsePreviewAvailable
              ? 'No remote reviews would change. Delivery may still record an unchanged, idempotent receipt.'
              : run.state === 'preview_ready'
                ? 'The API returned no sparse-review preview. Delivery remains disabled until the ownership boundary is explicit.'
                : 'Proposed reviews will appear after collection and evaluation.',
            collectionIncomplete ? 'warning' : sparsePreviewAvailable ? 'success' : run.state === 'preview_ready' ? 'warning' : 'info',
          ),
      hasKnownConflict ? notice(
        'Delivery is blocked because one or more proposed reviews would replace human-owned or workflow-controlled STIG Manager work. Resolve ownership in STIG Manager, then deliberately recheck and retry.',
        'danger',
      ) : null,
      previewWarning && !collectionIncomplete ? notice(
        previewWarning,
        'warning',
      ) : null,
      needsReconciliation ? notice(
        'STIG Manager reported partial acceptance. The complete remote response is preserved below; reconcile those rows at the destination before starting another delivery attempt.',
        'danger',
      ) : null,
      h('div', { className: 'button-row' },
        deliveryControl,
        run.handoffUrl && run.handoffUrl.startsWith('/api/v1/')
          ? button('Download selected-run handoff', {
              tone: 'secondary',
              onClick: event => downloadSelectedRunHandoff(event.currentTarget, run.handoffUrl),
            })
          : null,
        remoteUrl ? linkButton('Open STIG Manager', remoteUrl, { tone: 'secondary', external: true }) : null,
      ),
      !collectionIncomplete && (run.handoffUrl || run.mode === 'disconnected' || run.state === 'preview_ready')
        ? handoffNextSteps(run, remoteUrl)
        : null,
    ),

    deliveryReceipt(run),
    decisionTracePanel(run),
    evidencePanel(run),
  );
}

function handoffNextSteps(run, remoteUrl) {
  const destination = run.collectionName || run.collectionId
    ? `${run.collectionName || run.collectionId} / ${run.assetName || run.assetId || 'selected asset'}`
    : 'the pre-approved destination asset and assignment';
  return h('aside', { className: 'handoff-next-steps', 'aria-label': 'Selected-run handoff next steps' },
    h('h3', {}, 'If reviews changed'),
    h('ol', {},
      h('li', {}, 'Download the selected-run ZIP and keep it with its detached signature when one is supplied.'),
      h('li', {}, 'On the receiving workstation, run ', h('code', {}, 'automatestig scanner verify-handoff <selected-run.zip>'), '.'),
      h('li', {}, `Reconcile only the verified sparse reviews with ${destination} using your site’s approved workflow.`),
      h('li', {}, remoteUrl
        ? 'Open the bound STIG Manager asset, confirm the resulting review state, and retain the destination receipt.'
        : 'Record the destination result and receipt beside the verified handoff.'),
    ),
    notice('AutomateSTIG does not provide a native STIG Manager import for changed reviews. Verification proves bundle integrity; an authorized analyst still controls reconciliation.', 'info'),
  );
}

async function downloadSelectedRunHandoff(control, path) {
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

function normalizeStepStates(run) {
  const output = {};
  for (const key of ['preflight', 'collect', 'evaluate', 'delivery']) {
    const raw = typeof run.stepStates?.[key] === 'object' ? run.stepStates[key].state : run.stepStates?.[key];
    if (raw) output[key] = String(raw).toLowerCase();
  }
  if (run.collectionComplete === false) output.collect = 'failed';
  if (run.delivery.state === 'delivered') output.delivery = 'complete';
  if (['failed', 'rejected', 'conflicted'].includes(run.delivery.state)) output.delivery = 'failed';
  if (run.state === 'preview_ready') output.delivery = 'active';
  return output;
}

function deliveryChangeCounts(preview, proposed) {
  const counts = preview?.counts || preview || {};
  const fromRows = kind => proposed.filter(row => text(row.change || row.action || row.disposition).toLowerCase() === kind).length;
  return {
    create: numberValue(counts.create, counts.creates, fromRows('create')),
    update: numberValue(counts.update, counts.updates, fromRows('update')),
    unchanged: numberValue(counts.unchanged, fromRows('unchanged')),
    conflict: numberValue(counts.conflict, counts.conflicts, fromRows('conflict')),
  };
}

function changeCount(label, value, tone) {
  return h('div', { className: `change-count change-${tone}` },
    h('strong', {}, value == null ? '—' : value),
    h('span', {}, label),
  );
}

function proposedReviewTable(reviews) {
  return h('div', { className: 'table-scroll', role: 'region', tabindex: '0', 'aria-label': 'Proposed STIG Manager review changes' },
    h('table', { className: 'data-table compact-table' },
      h('thead', {}, h('tr', {},
        h('th', { scope: 'col' }, 'Rule'),
        h('th', { scope: 'col' }, 'Result'),
        h('th', { scope: 'col' }, 'Change'),
        h('th', { scope: 'col' }, 'Evidence'),
      )),
      h('tbody', {}, reviews.map(review => h('tr', {},
        h('td', {}, text(review.rule_id || review.ruleId || review.vuln_id || review.key || 'Unknown rule')),
        h('td', {}, badge(text(review.result || review.status || 'unknown'), resultTone(review.result || review.status))),
        h('td', {}, text(review.change || review.action || review.disposition || 'Proposed')),
        h('td', {}, text(review.evidence_summary || review.detail || review.evidence_id || 'Bound evidence')),
      ))),
    ),
  );
}

function resultTone(value) {
  const state = text(value).toLowerCase().replaceAll('_', '');
  if (['pass', 'notafinding'].includes(state)) return 'success';
  if (['fail', 'open'].includes(state)) return 'danger';
  if (state.includes('applicable')) return 'neutral';
  return 'warning';
}

function deliveryReceipt(run) {
  const delivery = run.delivery;
  if (!delivery.receipt && !delivery.attempts.length && !delivery.lastError
    && !delivery.requestSha256 && !delivery.payloadSha256) return null;
  return h('section', { className: 'card' },
    h('div', { className: 'section-heading' },
      h('div', {}, h('h2', {}, 'Remote verification receipt'), h('p', {}, 'Immutable request identity and attempt history for operational audit.')),
      delivery.state === 'delivered' ? badge('Verified no-op', 'success') : badge('Reconciliation pending', 'warning'),
    ),
    delivery.lastError ? notice(delivery.lastError, 'danger') : null,
    definitionList([
      ['State', delivery.state.replaceAll('_', ' ')],
      ['Recorded', formatDate(delivery.deliveredAt)],
      ['Request SHA-256', delivery.requestSha256 || 'Not returned'],
      ['Sparse payload SHA-256', delivery.payloadSha256 || 'Not returned'],
      ['Remote asset ID', delivery.remoteAssetId || 'Not returned'],
      ['Remote assignment ID', delivery.remoteAssignmentId || 'Not returned'],
      ['Receipt ID', delivery.receipt?.id || delivery.receipt?.receipt_id || 'Not returned'],
    ]),
    deliveryAttemptHistory(run),
  );
}

function deliveryAttemptHistory(run) {
  const attempts = [...run.delivery.attempts];
  let page = run.delivery.attemptsPage;
  if (!attempts.length && page?.next_offset == null) return null;
  const region = h('div', { className: 'attempt-list' });
  const render = () => replace(region,
    h('h3', {}, 'Attempts'),
    attempts.length ? h('ol', {}, attempts.map((attempt, index) => h('li', {},
      h('strong', {}, `Attempt ${attempt.number || index + 1}`),
      h('span', {}, `${formatDate(attempt.started_at || attempt.at)} · ${text(attempt.state || attempt.status || 'recorded')}`),
      attempt.error ? h('p', {}, text(attempt.error)) : null,
    ))) : notice('No delivery attempts are recorded.', 'info'),
    paginationControl(page, 'Load more attempts', async control => {
      setBusy(control, true, 'Loading…');
      try {
        const payload = await request(pagedEndpoint(endpoints.deliveryAttempts(run.id), {
          offset: page.next_offset,
          limit: page.limit || 25,
        }));
        const rows = Array.isArray(payload) ? payload : payload?.attempts || [];
        const seen = new Set(attempts.map(attempt => text(attempt.number || attempt.id)));
        attempts.push(...rows.filter(attempt => !seen.has(text(attempt.number || attempt.id))));
        page = payload?.page || null;
        render();
      } catch (error) {
        toast(apiUnavailableMessage(error), 'danger');
      } finally {
        setBusy(control, false);
      }
    }),
  );
  render();
  return region;
}

function decisionTracePanel(run) {
  if (!run.decisionTraces.length) return null;
  const traces = run.decisionTraces.slice(0, MAX_VISIBLE_DECISION_TRACES);
  const omitted = run.decisionTraces.length - traces.length;
  return h('section', { className: 'card decision-trace-panel' },
    h('div', { className: 'section-heading' },
      h('div', {},
        h('h2', {}, 'Decision traces'),
        h('p', {}, 'Sanitized, digest-bound explanation for each scanner-owned determination. Raw device output remains in encrypted replay evidence.'),
      ),
      badge(`${traces.length} rule${traces.length === 1 ? '' : 's'}`, 'neutral'),
    ),
    omitted > 0 ? notice(`${omitted} additional traces are not rendered in this bounded browser view. Use the verified selected-run handoff for the complete retained set.`, 'warning') : null,
    h('div', { className: 'decision-trace-list' }, traces.map(decisionTraceEntry)),
  );
}

function decisionTraceEntry(traceValue) {
  const trace = traceValue && typeof traceValue === 'object' ? traceValue : {};
  const operations = Array.isArray(trace.operations)
    ? trace.operations.slice(0, MAX_VISIBLE_TRACE_OPERATIONS)
    : [];
  const omittedOperations = Math.max(0, (Array.isArray(trace.operations) ? trace.operations.length : 0) - operations.length);
  const finding = boundedText(trace.finding_status || (trace.passed === true ? 'not_a_finding' : trace.passed === false ? 'open' : 'unknown'));
  const ruleId = boundedText(trace.rule_id || trace.vuln_id || 'Unknown rule');
  return h('details', { className: 'decision-trace-entry' },
    h('summary', {},
      h('span', { className: 'decision-trace-rule' }, ruleId),
      badge(finding.replaceAll('_', ' '), resultTone(finding)),
    ),
    h('div', { className: 'decision-trace-body' },
      definitionList([
        ['Vulnerability', boundedText(trace.vuln_id) || 'Not returned'],
        ['Predicate', joinedIdentity(trace.predicate_id, trace.predicate_version)],
        ['Parser', joinedIdentity(trace.parser_id, trace.parser_version)],
        ['Evaluator', joinedIdentity(trace.evaluator_id, trace.evaluator_version)],
        ['Expected', decisionValueSummary(trace.expected)],
        ['Observed', decisionValueSummary(trace.observed)],
        ['Evaluated', formatDate(trace.evaluated_at)],
        ['Profile SHA-256', boundedText(trace.profile_sha256) || 'Not returned'],
        ['Check pack SHA-256', boundedText(trace.check_pack_sha256) || 'Not returned'],
        ['Evidence SHA-256', boundedText(trace.evidence_envelope_sha256) || 'Not returned'],
      ]),
      trace.evaluation_error_class
        ? notice(`Evaluation stopped safely with class: ${boundedText(trace.evaluation_error_class)}`, 'danger')
        : null,
      trace.policy ? h('div', { className: 'trace-policy-binding' },
        h('h3', {}, 'Signed policy binding'),
        definitionList([
          ['Policy', joinedIdentity(trace.policy.policy_id, trace.policy.policy_version)],
          ['Signer fingerprint', boundedText(trace.policy.signer_fingerprint) || 'Not returned'],
          ['Policy SHA-256', boundedText(trace.policy.policy_sha256) || 'Not returned'],
          ['Verified', formatDate(trace.policy.verified_at)],
        ]),
      ) : null,
      operations.length ? h('div', { className: 'trace-operation-list' },
        h('h3', {}, 'Read-only observations'),
        h('ol', {}, operations.map(operation => h('li', {},
          h('div', {},
            h('strong', {}, boundedText(operation.operation_id || operation.observation_key || 'Operation')),
            h('span', {}, [boundedText(operation.request_kind), boundedText(operation.transport)].filter(Boolean).join(' · ') || 'Bound request'),
          ),
          badge(boundedText(operation.status || 'unknown').replaceAll('_', ' '), operation.status === 'success' ? 'success' : 'danger'),
          h('dl', { className: 'trace-operation-metadata' },
            h('dt', {}, 'Duration'), h('dd', {}, safeDuration(operation.duration_ms)),
            h('dt', {}, 'Observation'), h('dd', {}, boundedText(operation.observation_sha256) || 'No safe observation digest'),
            h('dt', {}, 'Flags'), h('dd', {}, [operation.truncated ? 'truncated' : null, operation.diagnostics_present ? 'diagnostics' : null, operation.error_class ? boundedText(operation.error_class) : null].filter(Boolean).join(', ') || 'none'),
          ),
        ))),
        omittedOperations ? notice(`${omittedOperations} additional operations are omitted from this bounded browser expansion.`, 'warning') : null,
      ) : notice('No read-only operation metadata was returned for this rule.', 'warning'),
    ),
  );
}

function decisionValueSummary(value) {
  if (!value || typeof value !== 'object') return 'Not returned';
  const safe = boundedText(value.safe_value);
  if (safe) return safe;
  const digest = boundedText(value.value_sha256);
  return digest ? `Digest only: ${digest}` : 'No safe primitive returned';
}

function joinedIdentity(name, version) {
  const values = [boundedText(name), boundedText(version)].filter(Boolean);
  return values.length ? values.join(' · ') : 'Not returned';
}

function boundedText(value, maximum = 256) {
  const candidate = text(value);
  return candidate.length > maximum ? `${candidate.slice(0, maximum)}…` : candidate;
}

function safeDuration(value) {
  const duration = Number(value);
  return Number.isFinite(duration) && duration >= 0 ? `${duration} ms` : 'Not returned';
}

function evidencePanel(run) {
  const provenanceEntries = Object.entries(run.provenance || {}).filter(([, value]) => value != null && typeof value !== 'object');
  if (!run.evidence.length && !provenanceEntries.length) return null;
  return h('section', { className: 'card' },
    h('div', { className: 'section-heading' },
      h('div', {}, h('h2', {}, 'Evidence and provenance'), h('p', {}, 'References and integrity bindings retained for scanner-owned decisions.')),
      badge('Read only', 'neutral'),
    ),
    run.evidence.length ? h('ul', { className: 'evidence-list' }, run.evidence.map(item => h('li', {},
      h('strong', {}, text(item.label || item.type || item.id || item.key || 'Evidence artifact')),
      h('span', {}, text(item.sha256 || item.hash || item.detail || 'Hash not returned')),
      item.retention ? h('span', {}, retentionSummary(item.retention)) : null,
    ))) : null,
    provenanceEntries.length ? definitionList(provenanceEntries.map(([key, value]) => [key.replaceAll('_', ' '), text(value)])) : null,
    run.id && run.evidence.some(item => item?.retention?.state === 'retained')
      ? h('div', { className: 'button-row evidence-purge-action' },
          button('Purge replay evidence', { tone: 'danger', onClick: event => purgeReplayEvidence(event.currentTarget, run.id) }),
          h('p', { className: 'form-help' }, 'Irreversible: type the exact run ID when prompted. Result hashes and receipt history remain.'),
        )
      : null,
  );
}

async function purgeReplayEvidence(control, runId) {
  const confirmation = window.prompt(`Type the exact run ID to purge its encrypted replay evidence:\n${runId}`);
  if (confirmation == null) return;
  setBusy(control, true, 'Purging…');
  try {
    await request(endpoints.purgeEvidence(runId), {
      method: 'POST',
      body: { confirm_run_id: confirmation },
    });
    toast('Replay evidence purged. Immutable result hashes and provenance remain.', 'success');
    window.location.reload();
  } catch (error) {
    toast(apiUnavailableMessage(error), 'danger');
    setBusy(control, false);
  }
}

function retentionSummary(retention) {
  const state = text(retention?.state || 'unknown').replaceAll('_', ' ');
  if (retention?.purged_at) {
    return `Replay evidence ${state}; purged ${formatDate(retention.purged_at)}. Result hashes remain verifiable.`;
  }
  if (retention?.expires_at) {
    return `Replay evidence ${state}; scheduled for purge ${formatDate(retention.expires_at)}. The immutable result and hashes remain.`;
  }
  return `Replay evidence ${state}.`;
}

function describeError(error) {
  if (typeof error === 'string') return error;
  if (error?.detail && typeof error.detail === 'string') return `${error.key || 'Collection'}: ${error.detail}`;
  return text(error?.message || error?.error || JSON.stringify(error));
}

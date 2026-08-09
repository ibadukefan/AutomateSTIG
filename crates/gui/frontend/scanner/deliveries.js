import {
  ApiError,
  apiUnavailableMessage,
  download,
  endpoints,
  pollRun,
  request,
} from './api.js';
import { hrefFor } from './router.js';
import {
  badge,
  button,
  definitionList,
  emptyState,
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
    delivery: {
      state: text(delivery.state || run.delivery_state || (state === 'delivered' ? 'delivered' : 'not_started')).toLowerCase(),
      requestSha256: text(delivery.request_sha256),
      payloadSha256: text(delivery.payload_sha256 || run.delivery_sha256),
      remoteUrl: text(delivery.remote_url || delivery.stig_manager_url || run.remote_url),
      remoteAssetId: text(delivery.remote_asset_id || destination.asset_id),
      remoteAssignmentId: text(delivery.remote_assignment_id || destination.assignment_id),
      deliveredAt: delivery.delivered_at || run.delivered_at || null,
      lastError: text(delivery.last_error || run.delivery_error),
      receipt: delivery.receipt || run.receipt || null,
      attempts,
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
      const [payload, jobsPayload] = await Promise.all([
        request(endpoints.runs, { signal: current.signal }),
        request(endpoints.jobs, { signal: current.signal }),
      ]);
      if (current.generation !== generation || !body?.isConnected) return;
      const runs = (Array.isArray(payload) ? payload : payload?.runs || []).map(normalizeRun);
      const jobs = (Array.isArray(jobsPayload) ? jobsPayload : jobsPayload?.jobs || [])
        .filter(job => String(job?.state || '').toLowerCase() !== 'completed');
      replace(body,
        jobs.length ? scanJobQueue(jobs) : null,
        runs.length ? deliveryTable(runs) : emptyState(
          jobs.length ? 'No completed scanner runs yet' : 'No scanner runs yet',
          jobs.length
            ? 'Active and failed SSH jobs remain visible above. A successful job creates an immutable run here.'
            : 'Start in Scan. Complete run records remain available; only replay evidence expires under the configured retention policy.',
          [h('a', { className: 'button button-primary', href: hrefFor('scan') }, 'Start a scan')],
        ),
      );
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
      const run = normalizeRun(await request(endpoints.run(runId), { signal: current.signal }));
      if (current.generation !== generation || !body?.isConnected) return;
      replace(body, renderRunPreview(run, {
        onDeliver: event => handleDelivery(event.currentTarget, run, body, outlet),
      }));
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

function scanJobQueue(jobs) {
  return h('div', { className: 'card table-card' },
    h('div', { className: 'section-heading' },
      h('div', {}, h('h2', {}, 'SSH collection jobs'),
        h('p', {}, 'Durable coordination records created before device I/O. Credentials are never persisted.')),
      badge(`${jobs.length} active or failed`, 'warning'),
    ),
    h('div', { className: 'table-scroll', role: 'region', tabindex: '0', 'aria-label': 'SSH collection jobs' },
      h('table', { className: 'data-table' },
        h('thead', {}, h('tr', {},
          h('th', {}, 'Job'), h('th', {}, 'Target'), h('th', {}, 'Profile'), h('th', {}, 'State'), h('th', {}, 'Updated'),
        )),
        h('tbody', {}, jobs.map(job => {
          const state = text(job.state || 'unknown').toLowerCase();
          return h('tr', {},
            h('td', {}, h('code', {}, text(job.id) || 'Unknown')),
            h('td', {}, text(job.request?.target?.host) || 'Bound target'),
            h('td', {}, text(job.request?.profile_id) || 'Bound profile'),
            h('td', {}, badge(state.replaceAll('_', ' '), state === 'failed' ? 'danger' : 'accent'),
              job.error ? h('p', { className: 'table-secondary' }, text(job.error)) : null),
            h('td', {}, formatDate(job.updated_at || job.created_at)),
          );
        })),
      ),
    ),
  );
}

function deliveryTable(runs) {
  return h('div', { className: 'card table-card' },
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
  );
}

export function renderRunPreview(runLike, { onDeliver = null, embedded = false } = {}) {
  const run = runLike?.delivery ? runLike : normalizeRun(runLike);
  const remoteUrl = safeExternalUrl(run.delivery.remoteUrl);
  const sparsePreviewAvailable = Array.isArray(run.delivery.preview?.reviews)
    || Array.isArray(run.raw?.proposed_reviews)
    || Array.isArray(run.raw?.result?.proposed_reviews)
    || Array.isArray(run.raw?.result?.reviews);
  const previewCounts = deliveryChangeCounts(run.delivery.preview, run.proposed);
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
        metric('Benchmark assessed', formatPercent(run.coveragePct),
          run.fullBenchmarkRules == null ? 'Not a compliance grade' : `Full benchmark denominator: ${run.fullBenchmarkRules}`),
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
      run.proposed.length
        ? proposedReviewTable(run.proposed)
        : notice(
            sparsePreviewAvailable
              ? 'No remote reviews would change. Delivery may still record an unchanged, idempotent receipt.'
              : run.state === 'preview_ready'
                ? 'The API returned no sparse-review preview. Delivery remains disabled until the ownership boundary is explicit.'
                : 'Proposed reviews will appear after collection and evaluation.',
            sparsePreviewAvailable ? 'success' : run.state === 'preview_ready' ? 'warning' : 'info',
          ),
      hasKnownConflict ? notice(
        'Delivery is blocked because one or more proposed reviews would replace human-owned or workflow-controlled STIG Manager work. Resolve ownership in STIG Manager, then deliberately recheck and retry.',
        'danger',
      ) : null,
      previewWarning ? notice(
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
        remoteUrl ? linkButton('Open in STIG Manager', remoteUrl, { tone: 'secondary', external: true }) : null,
      ),
    ),

    deliveryReceipt(run),
    evidencePanel(run),
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
    delivery.attempts.length ? h('div', { className: 'attempt-list' },
      h('h3', {}, 'Attempts'),
      h('ol', {}, delivery.attempts.map((attempt, index) => h('li', {},
        h('strong', {}, `Attempt ${attempt.number || index + 1}`),
        h('span', {}, `${formatDate(attempt.started_at || attempt.at)} · ${text(attempt.state || attempt.status || 'recorded')}`),
        attempt.error ? h('p', {}, text(attempt.error)) : null,
      ))),
    ) : null,
  );
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
  );
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

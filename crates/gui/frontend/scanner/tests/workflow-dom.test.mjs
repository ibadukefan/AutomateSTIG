import assert from 'node:assert/strict';
import test from 'node:test';

import { parseHTML } from 'linkedom';

import { createConnectionPage } from '../connection.js';
import { createDeliveriesPage, renderRunPreview } from '../deliveries.js';
import { createRouter } from '../router.js';
import { createScanPage, readinessPanel, renderPreflight } from '../scan.js';

function installDom() {
  const { document, window } = parseHTML('<!doctype html><html><body><main id="outlet"></main><div id="toasts"></div></body></html>');
  globalThis.document = document;
  globalThis.window = window;
  globalThis.Node = window.Node;
  globalThis.HTMLElement = window.HTMLElement;
  return { document, window, outlet: document.getElementById('outlet') };
}

function findButton(document, label) {
  return [...document.querySelectorAll('button')].find(button => button.textContent.trim() === label);
}

async function flushPromises(count = 3) {
  for (let index = 0; index < count; index += 1) await new Promise(resolve => setImmediate(resolve));
}

test('router reserves heading focus for client-side navigation', async () => {
  const { document, window, outlet } = installDom();
  Object.defineProperty(window, 'location', { value: { hash: '#scan' }, configurable: true });
  let focusCount = 0;
  const router = createRouter({
    outlet,
    render: () => {
      const heading = document.createElement('h1');
      Object.defineProperty(heading, 'focus', { value: () => { focusCount += 1; } });
      outlet.replaceChildren(heading);
    },
  });

  await router.start();
  assert.equal(focusCount, 0, 'initial paint must not show a focus ring around the page title');
  window.dispatchEvent(new window.Event('hashchange'));
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(focusCount, 1, 'client-side navigation must move focus to the new workspace heading');
});

test('first-open flow explains prerequisites and opens a network-free training result', async () => {
  const { document, window, outlet } = installDom();
  const focused = [];
  window.HTMLElement.prototype.focus = function focus() { focused.push(this); };
  const modes = [];
  const page = createScanPage({
    getSession: () => ({ mode: 'unselected', connection: null }),
    setMode: mode => modes.push(mode),
    notify: () => {},
  });

  await page.render(outlet);
  assert.match(outlet.textContent, /Where should this run go/);
  assert.match(outlet.textContent, /Operator readiness checklist/);
  assert.doesNotMatch(outlet.textContent, /Import the handoff at the destination/);

  const sampleButton = findButton(document, 'Open sample result');
  assert.ok(sampleButton, 'training result action should be visible on first open');
  sampleButton.click();

  assert.match(outlet.textContent, /Training data only/);
  assert.match(outlet.textContent, /TRAINING-NOT-A-REAL-RUN/);
  assert.match(outlet.textContent, /Automation coverage/);
  assert.match(outlet.textContent, /Not a compliance score/);
  assert.equal(findButton(document, 'Download selected-run handoff'), undefined);
  assert.deepEqual(modes, [], 'the training walkthrough must not enter a real run mode');
  assert.equal(focused.at(-1), outlet.querySelector('h1'), 'the replaced button must hand focus to the walkthrough heading');
});

test('readiness guidance changes for disconnected transfer custody', () => {
  const { document } = installDom();
  document.body.append(readinessPanel('disconnected'));
  assert.match(document.body.textContent, /Know the destination/);
  assert.match(document.body.textContent, /approved path to move and verify/);
});

test('Connection edits retention and thin target coordinates without credential material', async () => {
  const { document, window, outlet } = installDom();
  const previousFetch = globalThis.fetch;
  const writes = [];
  window.confirm = () => true;
  globalThis.fetch = async (url, options = {}) => {
    const path = String(url);
    const method = options.method || 'GET';
    if (path.endsWith('/api/v1/stig-manager/connection') && method === 'GET') {
      return new Response(JSON.stringify({ success: true, data: {
        configured: true, reachable: true, api_url: 'https://stigman.example.mil/api/',
        gui_url: 'https://stigman.example.mil/', privileges: ['collections:read confirmed'],
      } }), { headers: { 'content-type': 'application/json' } });
    }
    if (path.endsWith('/api/v1/scanner/retention') && method === 'GET') {
      return new Response(JSON.stringify({ success: true, data: {
        replay_evidence: { effective_days: 14, source: 'stored', editable: true, minimum_days: 1, maximum_days: 365, existing_expirations_unchanged: true },
        operational_history: { effective_days: 45, source: 'stored', editable: true, minimum_days: 1, maximum_days: 365 },
        sweeper: { next_sweep_not_later_than: '2026-08-11T12:15:00Z', condition: 'while this AutomateSTIG server remains running' },
      } }), { headers: { 'content-type': 'application/json' } });
    }
    if (path.endsWith('/api/v1/scanner/connection-profiles') && method === 'GET') {
      return new Response(JSON.stringify({ success: true, data: { profiles: [{
        id: 'thin-target-4', scanner_profile_id: 'ontap-v2r4', adapter: 'netapp-ontap9',
        endpoint: 'filer-old.example.mil', port: 22, credential_reference: 'opaque:keychain-label',
      }] } }), { headers: { 'content-type': 'application/json' } });
    }
    if (method === 'PUT' || method === 'DELETE') {
      writes.push({ path, method, body: options.body ? JSON.parse(options.body) : null });
      return new Response(JSON.stringify({ success: true, data: { saved: true } }), { headers: { 'content-type': 'application/json' } });
    }
    throw new Error(`Unexpected test request: ${method} ${path}`);
  };

  try {
    const page = createConnectionPage({ notify: () => {} });
    await page.render(outlet);
    assert.match(outlet.textContent, /collection-read access only/i);
    assert.doesNotMatch(outlet.textContent, /privilege tests pass/i);

    findButton(document, 'Edit').click();
    const endpoint = document.getElementById('target-profile-thin-target-4-endpoint');
    const port = document.getElementById('target-profile-thin-target-4-port');
    endpoint.reportValidity = () => true;
    port.reportValidity = () => true;
    endpoint.value = 'filer-new.example.mil';
    port.value = '2200';
    findButton(document, 'Save coordinates').click();
    await flushPromises(5);
    const profileWrite = writes.find(write => write.method === 'PUT' && write.path.endsWith('/api/v1/scanner/connection-profiles/thin-target-4'));
    assert.deepEqual(profileWrite?.body, {
      scanner_profile_id: 'ontap-v2r4', adapter: 'netapp-ontap9',
      endpoint: 'filer-new.example.mil', port: 2200, credential_reference: 'opaque:keychain-label',
    });
    assert.equal(JSON.stringify(profileWrite.body).includes('password'), false);

    findButton(document, 'Delete').click();
    await flushPromises(5);
    assert.ok(writes.some(write => write.method === 'DELETE'
      && write.path.endsWith('/api/v1/scanner/connection-profiles/thin-target-4')));

    const replay = document.getElementById('retention-replay-days-v1');
    const operational = document.getElementById('retention-operational-days-v1');
    replay.reportValidity = () => true;
    operational.reportValidity = () => true;
    replay.value = '21';
    operational.value = '60';
    findButton(document, 'Save retention policy').click();
    await flushPromises(5);
    const retentionWrite = writes.find(write => write.method === 'PUT'
      && write.path.endsWith('/api/v1/scanner/retention'));
    assert.deepEqual(retentionWrite?.body, { replay_evidence_days: 21, operational_history_days: 60 });
  } finally {
    globalThis.fetch = previousFetch;
  }
});

test('failed safety check puts actionable troubleshooting beside the cause', () => {
  const { document } = installDom();
  document.body.append(renderPreflight({
    ready: false,
    reason: 'Target identity does not match the selected asset.',
    token: null,
    expiresAt: null,
    identity: { hostname: 'wrong-device.example.mil', version: '9.13.1' },
    compatibility: { supported: true },
    privilege: { summary: 'Permission denied for read-only version command' },
    operations: [],
    warnings: [],
    errors: [{ message: 'SSH permission denied and hostname identity mismatch' }],
  }));

  assert.match(document.body.textContent, /How to resolve this safely/);
  assert.match(document.body.textContent, /observed hostname or fingerprint/);
  assert.match(document.body.textContent, /run every displayed read-only operation/);
  assert.match(document.body.textContent, /no bypass/i);
});

test('failed readiness request restores the retry control', async () => {
  const { document, window, outlet } = installDom();
  const previousFetch = globalThis.fetch;
  globalThis.fetch = async url => {
    if (String(url).endsWith('/api/v1/scanner/profiles')) {
      return new Response(JSON.stringify({
        success: true,
        data: [{
          id: 'ontap-test',
          stig_id: 'NetApp_ONTAP_DSC_9-x_STIG',
          target_name: 'NetApp ONTAP 9.x',
          stig_revision: 'V2R4',
          pilot_runnable: true,
          release_supported: false,
          collection_methods: ['ssh'],
        }],
      }), { headers: { 'content-type': 'application/json' } });
    }
    if (String(url).endsWith('/api/v1/runs/preflight')) {
      return new Response(JSON.stringify({
        success: false,
        error: {
          code: 'ssh_host_key_unverified',
          message: 'SSH preflight did not establish a verified server host-key fingerprint',
        },
      }), { status: 422, headers: { 'content-type': 'application/json' } });
    }
    throw new Error(`Unexpected test request: ${url}`);
  };

  try {
    const page = createScanPage({
      getSession: () => ({ mode: 'disconnected', connection: null }),
      setMode: () => {},
      notify: () => {},
    });
    await page.render(outlet);

    const change = control => control.dispatchEvent(new window.Event('change', { bubbles: true }));
    const input = control => control.dispatchEvent(new window.Event('input', { bubbles: true }));
    const profile = document.getElementById('scan-profile-v1');
    profile.querySelector('option[value="ontap-test"]').selected = true;
    change(profile);
    const method = document.getElementById('scan-method-v1');
    method.querySelector('option[value="ssh"]').selected = true;
    change(method);
    const credentialType = document.getElementById('scan-credential-type-v1');
    credentialType.querySelector('option[value="password"]').selected = true;
    change(credentialType);

    const endpoint = document.getElementById('scan-endpoint-v1');
    endpoint.value = '127.0.0.1';
    input(endpoint);
    const username = document.getElementById('scan-username-v1');
    username.value = 'synthetic-analyst';
    input(username);
    const password = document.getElementById('scan-password-v1');
    password.value = 'temporary-test-secret';
    input(password);
    const acknowledgement = document.querySelector('.pilot-acknowledgement input[type="checkbox"]');
    acknowledgement.checked = true;
    change(acknowledgement);

    const readiness = findButton(document, 'Check readiness');
    assert.ok(readiness);
    assert.equal(readiness.disabled, false);
    readiness.click();
    await new Promise(resolve => setImmediate(resolve));
    await new Promise(resolve => setImmediate(resolve));

    assert.equal(readiness.textContent, 'Check readiness');
    assert.equal(readiness.hasAttribute('aria-busy'), false);
    assert.equal(readiness.disabled, true, 'the cleared one-time password must be re-entered before retry');
    assert.match(outlet.textContent, /verified server host-key fingerprint/);
  } finally {
    globalThis.fetch = previousFetch;
  }
});

test('real handoff preview gives an exact verification command and destination', () => {
  const { document } = installDom();
  document.body.append(renderRunPreview({
    run_id: 'run-42',
    state: 'preview_ready',
    mode: 'connected',
    profile: { title: 'ONTAP V2R4', stig_id: 'NetApp_ONTAP_DSC_9-x_STIG', revision: 'V2R4' },
    destination: {
      collection_id: 'collection-1',
      collection_name: 'Production Network',
      asset_id: 'asset-9',
      asset_name: 'filer-01',
      assignment_id: 'assignment-3',
    },
    result: {
      collection_complete: true,
      automated_count: 1,
      executable_coverage_pct: 3.4,
      full_benchmark_rules: 29,
      proposed_reviews: [{ rule_id: 'SV-1', result: 'pass', change: 'update' }],
    },
    delivery: {
      state: 'not_started',
      preview: { reviews: [{ rule_id: 'SV-1', result: 'pass', change: 'update' }] },
    },
    handoff_url: '/api/v1/runs/run-42/handoff',
  }));

  assert.ok(findButton(document, 'Download selected-run handoff'));
  assert.match(document.body.textContent, /automatestig scanner verify-handoff <selected-run\.zip>/);
  assert.match(document.body.textContent, /Production Network \/ filer-01/);
  assert.match(document.body.textContent, /does not provide a native STIG Manager import/);
});

test('incomplete collection never presents an empty sparse preview as a remote no-op', () => {
  const { document } = installDom();
  document.body.append(renderRunPreview({
    run_id: 'run-incomplete-7',
    state: 'incomplete',
    profile: { title: 'ONTAP V2R4', stig_id: 'NetApp_ONTAP_DSC_9-x_STIG', revision: 'V2R4' },
    result: {
      collection_complete: false,
      automated_count: 0,
      executable_coverage_pct: 37.9,
      full_benchmark_rules: 29,
      proposed_reviews: [],
      collection_errors: [{ message: 'Required version evidence was not returned.' }],
    },
    delivery: {
      state: 'not_started',
      preview: {
        reviews: [],
        warning: 'Collection was incomplete; no sparse delivery payload was created.',
      },
    },
  }));

  assert.match(document.body.textContent, /Profile capability only; this run did not complete/);
  assert.match(document.body.textContent, /Collection was incomplete; no sparse delivery payload was created/);
  assert.doesNotMatch(document.body.textContent, /No remote reviews would change/);
  assert.doesNotMatch(document.body.textContent, /unchanged, idempotent receipt/);
  assert.doesNotMatch(document.body.textContent, /If reviews changed/);
  assert.doesNotMatch(document.body.textContent, /automatestig scanner verify-handoff/);
  assert.equal(findButton(document, 'Download selected-run handoff'), undefined);
  assert.equal(document.body.textContent.match(/Collection was incomplete; no sparse delivery payload was created/g)?.length, 1);
  assert.deepEqual(
    [...document.querySelectorAll('.change-grid .change-count strong')].slice(0, 4).map(value => value.textContent),
    ['—', '—', '—', '—'],
    'delivery change counts are unavailable, not zero, when no sparse preview was created',
  );
});

test('failed SSH job resume locks saved coordinates and clears fresh secrets after submission', async () => {
  const { document, window, outlet } = installDom();
  const previousFetch = globalThis.fetch;
  const submissions = [];
  const failedJob = {
    id: 'job-failed-7',
    state: 'failed',
    request: {
      schema: 'automatestig.scan-job-request.v1',
      mode: 'connected',
      profile_id: 'ontap-v2r4',
      connection_profile_id: 'thin-target-4',
      destination: {
        collection_id: 'collection-1',
        asset_id: 'asset-9',
        assignment_id: 'NetApp_ONTAP_DSC_9-x_STIG:V2R4',
      },
      target: { host: 'filer-01.example.mil', port: 22 },
      auth_kind: 'password',
      ephemeral_auth_supplied: true,
    },
    error: 'scan_job_failed: fresh preflight required',
    updated_at: '2026-08-11T12:00:00Z',
    resumable: true,
    checkpoint: {
      state: 'available',
      resumable: true,
      reason: 'Fresh preflight and fresh credentials are required.',
      expires_at: '2026-08-12T12:00:00Z',
    },
  };
  globalThis.fetch = async (url, options = {}) => {
    const path = String(url);
    if (path.includes('/api/v1/runs?') && (!options.method || options.method === 'GET')) {
      return new Response(JSON.stringify({ success: true, data: { runs: [] } }), { headers: { 'content-type': 'application/json' } });
    }
    if (path.includes('/api/v1/runs/jobs?') && (!options.method || options.method === 'GET')) {
      return new Response(JSON.stringify({ success: true, data: { jobs: [failedJob] } }), { headers: { 'content-type': 'application/json' } });
    }
    if (path.includes('/api/v1/runs/purged?')) {
      return new Response(JSON.stringify({ success: true, data: { purged_runs: [] } }), { headers: { 'content-type': 'application/json' } });
    }
    if (path.endsWith('/api/v1/runs/preflight') && options.method === 'POST') {
      submissions.push({ kind: 'preflight', body: JSON.parse(options.body) });
      return new Response(JSON.stringify({
        success: true,
        data: {
          ready: true,
          preflight_token: 'fresh-bound-preflight-token',
          device_identity: { hostname: 'filer-01.example.mil' },
          operations: [{ operation_id: 'version' }],
          expires_at: '2026-08-11T12:05:00Z',
        },
      }), { headers: { 'content-type': 'application/json' } });
    }
    if (path.endsWith('/api/v1/runs/jobs/job-failed-7/resume') && options.method === 'POST') {
      submissions.push({ kind: 'resume', body: JSON.parse(options.body) });
      failedJob.state = 'running';
      return new Response(JSON.stringify({ success: true, data: { kind: 'scan_job', id: failedJob.id, state: 'running' } }), { status: 202, headers: { 'content-type': 'application/json' } });
    }
    throw new Error(`Unexpected test request: ${path}`);
  };

  try {
    const notifications = [];
    const page = createDeliveriesPage({ notify: (...args) => notifications.push(args) });
    await page.renderList(outlet);
    findButton(document, 'Resume safely').click();

    assert.match(outlet.textContent, /Coordinates are locked to the durable job/);
    assert.match(outlet.textContent, /collection-1 \/ asset-9 \/ NetApp_ONTAP_DSC_9-x_STIG:V2R4/);
    const input = control => control.dispatchEvent(new window.Event('input', { bubbles: true }));
    const change = control => control.dispatchEvent(new window.Event('change', { bubbles: true }));
    const username = document.getElementById('resume-job-1-username');
    const password = document.getElementById('resume-job-1-password');
    username.value = 'fresh-analyst';
    password.value = 'ephemeral-resume-secret';
    input(username);
    input(password);
    const acknowledgement = document.querySelector('.scan-job-resume-panel .confirmation-row input');
    acknowledgement.checked = true;
    change(acknowledgement);

    const preflight = findButton(document, 'Run fresh preflight');
    assert.equal(preflight.disabled, false);
    preflight.click();
    await flushPromises();
    assert.equal(password.value, 'ephemeral-resume-secret', 'fresh secret remains only long enough to submit the successful bound resume');
    assert.deepEqual(submissions[0], {
      kind: 'preflight',
      body: {
        mode: 'connected',
        profile_id: 'ontap-v2r4',
        connection_profile_id: 'thin-target-4',
        collection_method: 'ssh',
        destination: {
          collection_id: 'collection-1',
          asset_id: 'asset-9',
          assignment_id: 'NetApp_ONTAP_DSC_9-x_STIG:V2R4',
        },
        target: { host: 'filer-01.example.mil', port: 22 },
        credential: { type: 'password', username: 'fresh-analyst', password: 'ephemeral-resume-secret' },
        pilot_acknowledged: true,
      },
    });

    const resume = findButton(document, 'Resume from checkpoint');
    assert.equal(resume.disabled, false);
    resume.click();
    await flushPromises(5);
    assert.equal(password.value, '', 'password must clear immediately after resume submission');
    assert.equal(submissions[1].body.preflight_token, 'fresh-bound-preflight-token');
    assert.deepEqual(submissions[1].body.destination, failedJob.request.destination);
    assert.deepEqual(submissions[1].body.target, failedJob.request.target);
    assert.equal(submissions[1].body.profile_id, failedJob.request.profile_id);
    assert.equal(submissions[1].body.connection_profile_id, failedJob.request.connection_profile_id);
    assert.equal(notifications.at(-1)?.[1], 'success');
  } finally {
    globalThis.fetch = previousFetch;
  }
});

test('delivery detail lists and imports an exact operator-confirmed receiver receipt', async () => {
  const { document, window, outlet } = installDom();
  const previousFetch = globalThis.fetch;
  let postedReceipt = null;
  let receiptReads = 0;
  const run = {
    id: 'run-42',
    state: 'preview_ready',
    mode: 'connected',
    profile: {
      id: 'ontap-v2r4',
      title: 'ONTAP V2R4',
      stig_id: 'NetApp_ONTAP_DSC_9-x_STIG',
      stig_revision: 'V2R4',
    },
    destination: {
      collection_id: 'collection-1',
      asset_id: 'asset-9',
      asset_name: 'filer-01',
      assignment_id: 'NetApp_ONTAP_DSC_9-x_STIG:V2R4',
    },
    result: {
      collection_complete: true,
      proposed_reviews: [{ rule_id: 'SV-100', result: 'open', change: 'update' }],
    },
    delivery: {
      state: 'not_started',
      payload_sha256: 'a'.repeat(64),
      preview: { reviews: [{ rule_id: 'SV-100', result: 'open', change: 'update' }] },
    },
  };
  globalThis.fetch = async (url, options = {}) => {
    const path = String(url);
    if (path.endsWith('/api/v1/runs/run-42') && (!options.method || options.method === 'GET')) {
      return new Response(JSON.stringify({ success: true, data: run }), { headers: { 'content-type': 'application/json' } });
    }
    if (path.endsWith('/api/v1/stig-manager/connection')) {
      return new Response(JSON.stringify({ success: true, data: {
        configured: true,
        api_url: 'https://stigman.example.mil/api/',
        gui_url: 'https://stigman.example.mil/',
      } }), { headers: { 'content-type': 'application/json' } });
    }
    if (path.endsWith('/api/v1/runs/run-42/reconciliation-receipts') && options.method === 'POST') {
      postedReceipt = JSON.parse(options.body);
      return new Response(JSON.stringify({ success: true, data: { receipt: postedReceipt } }), { headers: { 'content-type': 'application/json' } });
    }
    if (path.includes('/api/v1/runs/run-42/reconciliation-receipts?')) {
      receiptReads += 1;
      return new Response(JSON.stringify({ success: true, data: { receipts: receiptReads === 1 ? [{
        id: 'receiver-existing',
        payload_sha256: 'a'.repeat(64),
        destination_collection_id: 'collection-1',
        destination_asset_id: 'asset-9',
        destination_assignment_id: 'NetApp_ONTAP_DSC_9-x_STIG:V2R4',
        received_rule_ids: ['SV-100'],
        received_rule_set_sha256: 'c'.repeat(64),
        independent_readback_at: '2026-08-11T11:00:00Z',
        independent_readback_sha256: 'd'.repeat(64),
        receipt_sha256: 'e'.repeat(64),
        operator_confirmed: true,
        imported_at: '2026-08-11T11:01:00Z',
      }] : [] } }), { headers: { 'content-type': 'application/json' } });
    }
    throw new Error(`Unexpected test request: ${path}`);
  };

  try {
    const page = createDeliveriesPage({ notify: () => {} });
    await page.renderDetail(outlet, 'run-42');
    await flushPromises();
    assert.match(outlet.textContent, /Receiver reconciliation receipts/);
    assert.match(outlet.textContent, /receiver-existing/);
    assert.match(outlet.textContent, /does not import or edit STIG Manager reviews/i);
    assert.match(outlet.textContent, /1 MiB maximum/);

    findButton(document, 'Load run-bound schema template').click();
    const textarea = document.getElementById('reconciliation-receipt-json-v1');
    const documentValue = JSON.parse(textarea.value);
    documentValue.id = 'receiver-imported-2';
    documentValue.independent_readback_sha256 = 'f'.repeat(64);
    documentValue.independent_readback_at = new Date(Date.now() - 1_000).toISOString();
    documentValue.receipt.independent_readback_sha256 = documentValue.independent_readback_sha256;
    documentValue.receipt.independent_readback_at = documentValue.independent_readback_at;
    textarea.value = JSON.stringify(documentValue);
    textarea.dispatchEvent(new window.Event('input', { bubbles: true }));
    const confirmation = document.querySelector('.reconciliation-import .confirmation-row input');
    confirmation.checked = true;
    confirmation.dispatchEvent(new window.Event('change', { bubbles: true }));
    const importControl = findButton(document, 'Import receiver receipt');
    assert.equal(importControl.disabled, false);
    importControl.click();
    await flushPromises(6);

    assert.ok(postedReceipt, 'validated receiver document should be posted');
    assert.equal(postedReceipt.operator_confirmed, true, 'confirmation must come from the deliberate UI action');
    assert.equal(postedReceipt.receipt.run_id, 'run-42');
    assert.equal(postedReceipt.destination_collection_id, 'collection-1');
    assert.deepEqual(postedReceipt.received_rule_ids, ['SV-100']);
    assert.equal(postedReceipt.receipt.received_rule_set_sha256.length, 64);
    assert.equal(textarea.value, '');
    assert.equal(confirmation.checked, false);
    assert.ok(receiptReads >= 2, 'receipt list should refresh after import');
  } finally {
    globalThis.fetch = previousFetch;
  }
});

test('decision traces are bounded, expandable, and show sanitized replay bindings', () => {
  const { document } = installDom();
  const traces = Array.from({ length: 251 }, (_, index) => ({
    schema: 'automatestig.decision-trace.v2',
    rule_id: `SV-${index + 1}`,
    vuln_id: `V-${index + 1}`,
    finding_status: index ? 'not_a_finding' : 'open',
    predicate_id: 'typed-equality',
    predicate_version: '1',
    parser_id: 'structured-config',
    parser_version: '1',
    evaluator_id: 'automatestig-scanner',
    evaluator_version: '0.1.0',
    evaluated_at: '2026-08-11T12:00:00Z',
    expected: { safe_value: 'enabled', value_sha256: 'a'.repeat(64) },
    observed: { safe_value: null, value_sha256: 'b'.repeat(64) },
    profile_sha256: 'c'.repeat(64),
    check_pack_sha256: 'd'.repeat(64),
    evidence_envelope_sha256: 'e'.repeat(64),
    operations: [{
      operation_id: 'read-config',
      request_kind: 'structured_config',
      transport: 'ssh',
      status: 'success',
      duration_ms: 12,
      observation_sha256: 'f'.repeat(64),
      diagnostics_present: false,
      truncated: false,
    }],
  }));
  document.body.append(renderRunPreview({
    id: 'trace-run',
    state: 'preview_ready',
    profile: { title: 'Trace test', stig_id: 'Trace_STIG', stig_revision: 'V1R1' },
    result: { collection_complete: true, decision_traces: traces, proposed_reviews: [] },
    delivery: { state: 'not_started', preview: { reviews: [] } },
  }));

  assert.match(document.body.textContent, /Decision traces/);
  assert.equal(document.querySelectorAll('.decision-trace-entry').length, 250);
  assert.match(document.body.textContent, /1 additional traces are not rendered/);
  const first = document.querySelector('.decision-trace-entry');
  first.open = true;
  assert.match(first.textContent, /typed-equality/);
  assert.match(first.textContent, /Digest only: b{64}/);
  assert.match(first.textContent, /read-config/);
  assert.doesNotMatch(first.textContent, /raw device output value/i);
});

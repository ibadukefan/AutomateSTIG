import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

import { API_ROOT, endpoints, pagedEndpoint } from '../api.js';
import { normalizeProfiles } from '../content.js';
import { normalizeRetention, normalizeTargetProfiles } from '../connection.js';
import { normalizeRun } from '../deliveries.js';
import { hrefFor, parseHash } from '../router.js';
import { normalizeAssignments } from '../scan.js';

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const source = name => readFile(join(ROOT, name), 'utf8');

test('scanner shell exposes only the four scanner-first workspaces', async () => {
  const html = await source('index.html');
  const routes = [...html.matchAll(/data-route="([^"]+)"/g)].map(match => match[1]);
  assert.deepEqual(routes, ['scan', 'deliveries', 'content', 'connection']);
  for (const [route, label] of [['scan', 'Scan'], ['deliveries', 'Deliveries'], ['content', 'Scanner Content'], ['connection', 'Connection']]) {
    assert.match(html, new RegExp(`<a[^>]+data-route="${route}"[^>]+aria-label="${label}"`));
  }
  assert.match(html, /<script type="module" src="app\.js"><\/script>/);
  assert.match(html, /STIG Manager remains the system of record/);
  assert.match(html, /Skip to scanner workspace/);
});

test('router keeps stable hashes and delivery detail identity', () => {
  assert.deepEqual(parseHash('#scan'), { page: 'scan', id: null, title: 'Scan' });
  assert.deepEqual(parseHash('#deliveries/run%201'), { page: 'deliveries', id: 'run 1', title: 'Deliveries' });
  assert.equal(hrefFor('deliveries', 'run 1'), '#deliveries/run%201');
  assert.equal(parseHash('#assets/legacy-1').page, 'legacy');
  assert.equal(parseHash('#assets/legacy-1').owner, 'STIG Manager');
  assert.equal(parseHash('#standards').destination, 'content');
  assert.equal(parseHash('#unknown').page, 'not-found');
});

test('API adapter is versioned and describes live destination lookup', () => {
  assert.equal(API_ROOT, '/api/v1');
  assert.equal(endpoints.status, '/status');
  assert.equal(endpoints.profiles, '/scanner/profiles');
  assert.equal(endpoints.preflight, '/runs/preflight');
  assert.equal(endpoints.sshRun, '/runs/ssh');
  assert.equal(endpoints.evidenceRun, '/runs/evidence');
  assert.equal(endpoints.assets('c 1'), '/stig-manager/collections/c%201/assets');
  assert.equal(
    endpoints.assignments('c 1', 'a/2'),
    '/stig-manager/collections/c%201/assets/a%2F2/assignments',
  );
  assert.equal(endpoints.deliver('r 3'), '/runs/r%203/deliver');
  assert.equal(endpoints.resumeJob('j 4'), '/runs/jobs/j%204/resume');
  assert.equal(endpoints.reconciliationReceipts('r 3'), '/runs/r%203/reconciliation-receipts');
  assert.equal(endpoints.retention, '/scanner/retention');
  assert.equal(endpoints.purgedRuns, '/runs/purged');
  assert.equal(endpoints.deliveryAttempts('r 3'), '/runs/r%203/delivery-attempts');
  assert.equal(pagedEndpoint(endpoints.jobs, { offset: 25, limit: 25 }), '/runs/jobs?offset=25&limit=25');
});

test('retention and thin target profiles preserve their scanner-only boundary', () => {
  const retention = normalizeRetention({
    replay_evidence: { effective_days: 14, source: 'environment', editable: false, minimum_days: 1, maximum_days: 365 },
    operational_history: { effective_days: 45, source: 'stored', editable: true, minimum_days: 1, maximum_days: 365 },
    sweeper: { next_sweep_not_later_than: '2026-08-11T12:15:00Z' },
  });
  assert.equal(retention.replay.days, 14);
  assert.equal(retention.replay.editable, false);
  assert.equal(retention.operational.days, 45);
  const [profile] = normalizeTargetProfiles({ profiles: [{
    id: 'target-1', scanner_profile_id: 'ontap-v2r4', adapter: 'netapp-ontap9',
    endpoint: 'filer.example.mil', port: 22, credential_reference: 'opaque:reference',
  }] });
  assert.equal(profile.endpoint, 'filer.example.mil');
  assert.equal(profile.credentialReference, 'opaque:reference');
  assert.equal('assetId' in profile, false);
  assert.equal('assignmentId' in profile, false);
});

test('only an exact ready assignment becomes runnable', () => {
  const profiles = normalizeProfiles({ profiles: [{
    profile_id: 'ontap-v2r4',
    stig_id: 'NetApp_ONTAP_DSC_9-x_STIG',
    revision: 'V2R4',
    target_name: 'ONTAP',
    scanner_ready: true,
    automated_rules: 15,
    manual_rules: 7,
    reviewed_rules: 22,
    full_benchmark_rules: 29,
  }] });
  const assignments = normalizeAssignments({ assignments: [
    { assignment_id: 'exact', benchmark_id: 'NetApp_ONTAP_DSC_9-x_STIG', lastRevisionStr: 'V2R4' },
    { assignment_id: 'drift', benchmark_id: 'NetApp_ONTAP_DSC_9-x_STIG', lastRevisionStr: 'V2R3' },
    { assignment_id: 'claimed-profile-drift', benchmark_id: 'NetApp_ONTAP_DSC_9-x_STIG', lastRevisionStr: 'V2R3', profile_id: 'ontap-v2r4' },
  ] }, profiles);
  assert.equal(assignments[0].scannerReady, true);
  assert.equal(assignments[0].profileId, 'ontap-v2r4');
  assert.equal(profiles[0].reviewedRules, 22);
  assert.equal(profiles[0].fullBenchmarkRules, 29);
  assert.equal(assignments[1].scannerReady, false);
  assert.match(assignments[1].reason, /No release-bundled scanner profile matches/);
  assert.equal(assignments[2].scannerReady, false);
  assert.match(assignments[2].reason, /does not exactly match scanner profile/);
});

test('experimental profiles are pilot-runnable but never presented as release-supported', () => {
  const [profile] = normalizeProfiles({ profiles: [{
    profile_id: 'freebsd-v3r3',
    stig_id: 'General_Purpose_Operating_System',
    revision: 'V3R3',
    state: 'experimental',
    pilot_runnable: true,
    release_supported: false,
    tested_versions: [],
  }] });
  assert.equal(profile.scannerReady, true);
  assert.equal(profile.pilotRunnable, true);
  assert.equal(profile.releaseSupported, false);
  assert.equal(profile.state, 'experimental');
});

test('scanner content reports required synthetic inventory without inventing a pass', () => {
  const [profile] = normalizeProfiles({ profiles: [{
    profile_id: 'freebsd-v3r3', stig_id: 'General_Purpose_Operating_System',
    validation: { synthetic_fixture_requirements: {
      status: 'required_inventory', required_rule_contract_count: 3,
      required_case_classes: ['positive', 'negative', 'collection_error'],
      required_fixture_case_count: 9, measured_fixture_case_count: null,
    } },
  }] });
  assert.equal(profile.syntheticFixtureRequirements.status, 'required_inventory');
  assert.equal(profile.syntheticFixtureRequirements.required_fixture_case_count, 9);
  assert.notEqual(profile.syntheticFixtureRequirements.status, 'passed');
});

test('run normalization preserves sparse preview, untouched scope, and receipt', () => {
  const run = normalizeRun({
    run_id: 'run-7',
    state: 'delivered',
    profile: { title: 'ONTAP V2R4', stig_id: 'NetApp_ONTAP_DSC_9-x_STIG', revision: 'V2R4' },
    destination: { collection_id: '4', asset_id: '9', assignment_id: '11' },
    result: {
      collection_complete: true,
      automated_count: 2,
      manual_untouched: 7,
      full_benchmark_rules: 29,
      reviewed_rules: 22,
      out_of_scope_untouched: 7,
    },
    delivery: {
      state: 'delivered',
      request_sha256: 'a'.repeat(64),
      remote_url: 'https://stigman.example.mil/assets/9',
      preview: {
        manual_untouched: 7,
        reviews: [
          { rule_id: 'SV-1', result: 'pass', change: 'update' },
          { rule_id: 'SV-2', result: 'fail', change: 'create' },
        ],
      },
      receipt: { id: 'receipt-2' },
    },
  });
  assert.equal(run.id, 'run-7');
  assert.equal(run.proposed.length, 2);
  assert.equal(run.manualUntouched, 7);
  assert.equal(run.fullBenchmarkRules, 29);
  assert.equal(run.reviewedRules, 22);
  assert.equal(run.outOfScopeUntouched, 7);
  assert.equal(run.delivery.requestSha256, 'a'.repeat(64));
  assert.equal(run.delivery.receipt.id, 'receipt-2');
});

test('task source includes safe preview/retry flow and excludes retired product surfaces', async () => {
  const names = ['app.js', 'api.js', 'router.js', 'scan.js', 'deliveries.js', 'content.js', 'connection.js'];
  const combined = (await Promise.all(names.map(source))).join('\n');
  for (const required of [
    'Connect to STIG Manager',
    'Run disconnected',
    'Check readiness',
    'Collect and evaluate',
    'Delivery preview',
    'Manual untouched',
    'Retry remote verification',
    'Remote verification receipt',
    'Resume from checkpoint',
    'Receiver reconciliation receipts',
    'Decision traces',
    'Replay evidence',
    'Purged operational history',
    'Saved target profiles',
    'Scanner retention',
    'Open STIG Manager',
    'versioned scanner API is not responding',
  ]) assert.ok(combined.includes(required), `missing scanner task copy: ${required}`);

  for (const retiredPath of ['/answer-files', '/disa/', '/checklists', '/export/all-zip']) {
    assert.ok(!combined.includes(retiredPath), `retired route leaked into scanner frontend: ${retiredPath}`);
  }
  assert.ok(!combined.includes("method: 'PATCH'"), 'scanner frontend must not edit findings');
  assert.ok(!combined.includes('bulk-assign'), 'scanner frontend must not manage assignments');
  assert.ok(!combined.includes('localStorage.setItem'), 'scanner frontend must not persist secrets or task state indefinitely');
  assert.ok(!combined.includes('Import the handoff at the destination'), 'the UI must not promise a native import that does not exist');
  assert.ok(combined.includes('Automation coverage'), 'coverage must be labeled as automation scope, not a compliance grade');
  assert.match(combined, /not a compliance score/i, 'coverage must explicitly reject score interpretation');
  assert.ok(combined.includes('automatestig scanner verify-handoff <selected-run.zip>'));
  assert.ok(combined.includes('does not provide a native STIG Manager import'));
  assert.ok(combined.includes('Operator readiness checklist'));
  assert.ok(combined.includes('Training data only'));
  assert.doesNotMatch(combined, /function inferMethods/, 'collection behavior must come from the release profile, not a UI target-name heuristic');
  assert.ok(combined.includes('do not infer a method from the target name'));
  assert.ok(combined.includes('Profile identity, revisions, methods, coverage, hashes, and readiness come only from this running scanner release'));
  assert.ok(combined.includes("job.resumable === true"), 'resume must be offered only for checkpoint-backed API eligibility');
  assert.ok(combined.includes("method: 'DELETE'"), 'thin saved target coordinates must be removable');
  assert.ok(combined.includes('Load more tombstones'));
  assert.ok(combined.includes('Required inventory only; measured completion and false-pass results are not returned'));
});

test('auth and device secret modules do not write credentials to browser storage', async () => {
  const api = await source('api.js');
  const scan = await source('scan.js');
  const deliveries = await source('deliveries.js');
  const connection = await source('connection.js');
  for (const text of [api, scan, deliveries, connection]) {
    assert.doesNotMatch(text, /(?:localStorage|sessionStorage)\.setItem\([^\n]*(?:token|password|secret|credential)/i);
  }
  assert.match(scan, /clearSensitiveInputs\(passwordInput, keyPassphraseInput\)/);
  assert.match(deliveries, /clearResumeSecrets\(password, keyPassphrase\)/);
  assert.match(connection, /clientSecret\.value = ''/);
});

test('SSH checkpoint resume requires exact saved bindings, fresh preflight, and ephemeral credentials', async () => {
  const deliveries = await source('deliveries.js');
  assert.match(deliveries, /request\(endpoints\.preflight/);
  assert.match(deliveries, /request\(endpoints\.resumeJob\(job\.id\)/);
  assert.match(deliveries, /collection_method: 'ssh'/);
  assert.match(deliveries, /connection_profile_id: binding\.connectionProfileId/);
  assert.match(deliveries, /destination: binding\.destination/);
  assert.match(deliveries, /target: binding\.target/);
  assert.match(deliveries, /pilot_acknowledged: Boolean\(pilotAcknowledged\)/);
  assert.doesNotMatch(deliveries, /sessionStorage|localStorage/);
});

test('receiver receipt import is bounded, exact, explicit, and separate from review mutation', async () => {
  const deliveries = await source('deliveries.js');
  assert.match(deliveries, /MAX_RECEIPT_BYTES = 1024 \* 1024/);
  assert.match(deliveries, /RECEIVER_RECEIPT_SCHEMA = 'automatestig\.receiver-reconciliation\.v1'/);
  assert.match(deliveries, /request\(endpoints\.reconciliationReceipts\(run\.id\)/);
  assert.match(deliveries, /body\.operator_confirmed = true/);
  assert.match(deliveries, /received_rule_ids must exactly equal/);
  assert.match(deliveries, /This does not import or edit STIG Manager reviews/);
  assert.doesNotMatch(deliveries, /method: 'PATCH'/);
});

test('decision-trace browser rendering is bounded and excludes raw observations', async () => {
  const deliveries = await source('deliveries.js');
  assert.match(deliveries, /MAX_VISIBLE_DECISION_TRACES = 250/);
  assert.match(deliveries, /MAX_VISIBLE_TRACE_OPERATIONS = 64/);
  assert.match(deliveries, /Decision traces/);
  assert.match(deliveries, /Raw device output remains in encrypted replay evidence/);
  assert.doesNotMatch(deliveries, /operation\.(?:response|stdout|stderr|raw_output)/);
});

test('one-time SSH secrets survive successful preflight only until run submission', async () => {
  const scan = await source('scan.js');
  const preflightStart = scan.indexOf("preflightButton.addEventListener('click'");
  const runStart = scan.indexOf("runButton.addEventListener('click'", preflightStart);
  const preflightHandler = scan.slice(preflightStart, runStart);

  assert.doesNotMatch(
    preflightHandler,
    /preflight = normalizePreflight\(response\);\s*clearSensitiveInputs/,
    'successful preflight must retain the one-time secret for run submission',
  );
  assert.match(
    preflightHandler,
    /if \(!preflight\.ready\) clearSensitiveInputs\(passwordInput, keyPassphraseInput\)/,
    'a rejected preflight must clear one-time secrets',
  );
  assert.match(
    preflightHandler,
    /catch \(error\) \{[\s\S]*?clearSensitiveInputs\(passwordInput, keyPassphraseInput\)/,
    'a failed preflight request must clear one-time secrets',
  );

  const runHandler = scan.slice(runStart);
  const submission = runHandler.search(/(?:const|let) response = selectedMethod\(\)/);
  const normalization = runHandler.indexOf('let run = normalizeRun(response)', submission);
  const jobPolling = runHandler.indexOf('await pollScanJob(response.id', submission);
  const immediateClear = runHandler.indexOf(
    'clearSensitiveInputs(passwordInput, keyPassphraseInput)',
    submission,
  );
  assert.ok(submission >= 0 && immediateClear > submission && immediateClear < normalization,
    'one-time secrets must clear immediately after run submission, before polling');
  assert.ok(jobPolling < 0 || immediateClear < jobPolling,
    'one-time secrets must clear before durable SSH job polling');
  assert.match(
    runHandler,
    /finally \{\s*clearSensitiveInputs\(passwordInput, keyPassphraseInput\)/,
    'failed run submissions must also clear one-time secrets',
  );
});

test('selected-run handoff uses authenticated fetch instead of a tokenless link', async () => {
  const api = await source('api.js');
  const scan = await source('scan.js');
  assert.match(api, /export async function download/);
  assert.match(api, /headers\.set\('X-Auth-Token', authToken\)/);
  assert.match(scan, /downloadHandoff\(event\.currentTarget, run\.handoffUrl\)/);
  assert.match(scan, /total_expected_duration_ms/);
  assert.match(scan, /estimated_duration_ms/);
  assert.match(scan, /maximum_duration_ms/);
  assert.match(scan, /Operating context/);
  assert.match(scan, /HA role/);
  assert.doesNotMatch(scan, /href: run\.handoffUrl/);
  assert.doesNotMatch(api, /[?&](?:token|auth)=/i);
});

test('pilot acknowledgement, verified previews, TLS, and durable handoff remain fail closed', async () => {
  const scan = await source('scan.js');
  const deliveries = await source('deliveries.js');
  const connection = await source('connection.js');

  assert.match(scan, /pilot_acknowledged: Boolean/);
  assert.match(scan, /experimental pilot run/);
  assert.match(deliveries, /&& !previewWarning/);
  assert.match(deliveries, /downloadSelectedRunHandoff/);
  assert.match(deliveries, /download\(path\.replace/);
  assert.match(connection, /verify_tls: true/);
  assert.doesNotMatch(connection, /explicit server-side lab override/);
  assert.doesNotMatch(connection, /type: 'checkbox'.*verifyTls/);
});

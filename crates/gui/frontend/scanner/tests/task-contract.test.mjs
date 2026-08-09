import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

import { API_ROOT, endpoints } from '../api.js';
import { normalizeProfiles } from '../content.js';
import { normalizeRun } from '../deliveries.js';
import { hrefFor, parseHash } from '../router.js';
import { normalizeAssignments } from '../scan.js';

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const source = name => readFile(join(ROOT, name), 'utf8');

test('scanner shell exposes only the four scanner-first workspaces', async () => {
  const html = await source('index.html');
  const routes = [...html.matchAll(/data-route="([^"]+)"/g)].map(match => match[1]);
  assert.deepEqual(routes, ['scan', 'deliveries', 'content', 'connection']);
  assert.match(html, /<script type="module" src="app\.js"><\/script>/);
  assert.match(html, /STIG Manager remains the system of record/);
  assert.match(html, /Skip to scanner workspace/);
});

test('router keeps stable hashes and delivery detail identity', () => {
  assert.deepEqual(parseHash('#scan'), { page: 'scan', id: null, title: 'Scan' });
  assert.deepEqual(parseHash('#deliveries/run%201'), { page: 'deliveries', id: 'run 1', title: 'Deliveries' });
  assert.equal(hrefFor('deliveries', 'run 1'), '#deliveries/run%201');
  assert.equal(parseHash('#unknown').page, 'scan');
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
    'Run preflight',
    'Collect and evaluate',
    'Delivery preview',
    'Manual untouched',
    'Retry remote verification',
    'Remote verification receipt',
    'Replay evidence',
    'Open in STIG Manager',
    'versioned scanner API is not available',
  ]) assert.ok(combined.includes(required), `missing scanner task copy: ${required}`);

  for (const retiredPath of ['/answer-files', '/disa/', '/checklists', '/export/all-zip']) {
    assert.ok(!combined.includes(retiredPath), `retired route leaked into scanner frontend: ${retiredPath}`);
  }
  assert.ok(!combined.includes("method: 'PATCH'"), 'scanner frontend must not edit findings');
  assert.ok(!combined.includes('bulk-assign'), 'scanner frontend must not manage assignments');
  assert.ok(!combined.includes('localStorage.setItem'), 'scanner frontend must not persist secrets or task state indefinitely');
});

test('auth and device secret modules do not write credentials to browser storage', async () => {
  const api = await source('api.js');
  const scan = await source('scan.js');
  const connection = await source('connection.js');
  for (const text of [api, scan, connection]) {
    assert.doesNotMatch(text, /(?:localStorage|sessionStorage)\.setItem\([^\n]*(?:token|password|secret|credential)/i);
  }
  assert.match(scan, /clearSensitiveInputs\(passwordInput, keyPassphraseInput\)/);
  assert.match(connection, /clientSecret\.value = ''/);
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

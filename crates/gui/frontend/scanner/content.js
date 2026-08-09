import { apiUnavailableMessage, endpoints, request } from './api.js';
import { badge, button, definitionList, emptyState, h, loadingState, notice, pageHeader, replace } from './ui.js';

const BASELINE_HINTS = Object.freeze([
  {
    id: 'NetApp_ONTAP_DSC_9-x_STIG',
    target: 'NetApp ONTAP 9.x',
    revision: 'V2R4',
    adapter: 'ONTAP SSH',
    automatedRules: 15,
    manualRules: 7,
    reviewedRules: 22,
    fullBenchmarkRules: 29,
  },
  {
    id: 'General_Purpose_Operating_System',
    target: 'FreeBSD / GPOS',
    revision: 'V3R3',
    adapter: 'FreeBSD SSH',
    automatedRules: 6,
    manualRules: 24,
    reviewedRules: 30,
    fullBenchmarkRules: 203,
  },
  {
    id: 'Cisco_IOS-XE_Router_NDM_STIG',
    target: 'Cisco IOS-XE Router NDM',
    revision: 'V3R7',
    adapter: 'IOS-XE configuration',
    automatedRules: 33,
    manualRules: 9,
    reviewedRules: 42,
    fullBenchmarkRules: 42,
  },
]);

export function normalizeProfiles(payload) {
  const values = Array.isArray(payload) ? payload : Array.isArray(payload?.profiles) ? payload.profiles : [];
  return values.map(profile => {
    const declaredState = String(profile.state || '').toLowerCase();
    const pilotRunnable = Boolean(profile.pilot_runnable ?? profile.scanner_ready ?? profile.ready);
    const releaseSupported = Boolean(profile.release_supported
      ?? (['supported', 'production'].includes(declaredState)
        && Array.isArray(profile.tested_versions)
        && profile.tested_versions.length));
    const state = declaredState || (releaseSupported ? 'supported' : pilotRunnable ? 'pilot' : 'unavailable');
    return {
      raw: profile,
      id: String(profile.id || profile.profile_id || profile.stig_id || profile.benchmark_id || ''),
      stigId: String(profile.stig_id || profile.benchmark_id || profile.id || ''),
      target: String(profile.target_name || profile.target || profile.title || profile.stig_id || 'Unnamed target'),
      title: String(profile.title || profile.stig_title || profile.target_name || profile.stig_id || 'Scanner profile'),
      revision: String(profile.stig_revision || profile.revision || profile.release || profile.version || 'Unknown revision'),
      adapter: String(profile.adapter_name || profile.adapter || profile.platform || 'Scanner adapter'),
      state,
      // Kept as the run-selector compatibility field. A pilot-runnable
      // profile still requires an explicit acknowledgement at preflight.
      scannerReady: pilotRunnable,
      pilotRunnable,
      releaseSupported,
      reason: String(profile.unsupported_reason || profile.blocked_reason || profile.reason || ''),
      automatedRules: numberOrNull(profile.automated_rules ?? profile.executable_rules ?? profile.automated),
      manualRules: numberOrNull(profile.manual_rules ?? profile.manual),
      reviewedRules: numberOrNull(profile.reviewed_rules),
      fullBenchmarkRules: numberOrNull(profile.full_benchmark_rules ?? profile.total_rules ?? profile.rule_count ?? profile.total),
      testedVersions: arrayOfText(profile.tested_versions || profile.firmware_versions || profile.compatibility?.tested_versions),
      methods: arrayOfText(profile.collection_methods || profile.methods || profile.transports),
      contentSha256: profile.content_sha256 || profile.profile_sha256 || profile.hashes?.profile || null,
      checkPackSha256: profile.check_pack_sha256 || profile.hashes?.check_pack || null,
      trust: profile.trust_state || profile.signature?.state || profile.trust || null,
      acceptance: profile.acceptance_state || profile.live_acceptance || null,
      updatedAt: profile.updated_at || profile.built_at || null,
    };
  }).filter(profile => profile.id);
}

function numberOrNull(value) {
  const number = Number(value);
  return Number.isFinite(number) ? number : null;
}

function arrayOfText(value) {
  if (Array.isArray(value)) return value.map(String).filter(Boolean);
  if (typeof value === 'string' && value.trim()) return [value.trim()];
  return [];
}

export async function loadProfiles(options = {}) {
  return normalizeProfiles(await request(endpoints.profiles, options));
}

export function createContentPage({ notify = () => {} } = {}) {
  let generation = 0;

  async function render(outlet) {
    const current = ++generation;
    replace(outlet,
      pageHeader(
        'Release-bundled capability',
        'Scanner Content',
        'Only exact, reviewed scanner profiles appear here. STIG Manager owns the broader benchmark catalog.',
      ),
      h('div', { id: 'content-body' }, loadingState('Loading scanner profiles…')),
    );
    const body = outlet.querySelector('#content-body');
    try {
      const profiles = await loadProfiles();
      if (current !== generation || !body?.isConnected) return;
      replace(body,
        profiles.length
          ? h('div', { className: 'profile-grid' }, profiles.map(profileCard))
          : emptyState(
              'No scanner profiles are installed',
              'This build cannot start a scan until it contains a release-bundled runnable profile.',
            ),
      );
    } catch (error) {
      if (current !== generation || !body?.isConnected) return;
      notify(apiUnavailableMessage(error), 'warning');
      replace(body,
        notice(apiUnavailableMessage(error), 'warning', [button('Retry', { onClick: () => render(outlet) })]),
        h('section', { className: 'section-block' },
          h('div', { className: 'section-heading' },
            h('div', {},
              h('h2', {}, 'Planned baseline profiles'),
              h('p', {}, 'Informational only while the scanner API is unavailable. These cards cannot start a run.'),
            ),
            badge('API required', 'warning'),
          ),
          h('div', { className: 'profile-grid muted-grid' }, BASELINE_HINTS.map(hintProfileCard)),
        ),
      );
    }
  }

  return { render, loadProfiles };
}

function profileCard(profile) {
  const tone = profile.releaseSupported ? 'success'
    : profile.pilotRunnable || profile.state === 'experimental' || profile.state === 'pilot' ? 'warning' : 'danger';
  const stateLabel = profile.releaseSupported ? 'Release supported'
    : profile.pilotRunnable ? 'Pilot · acknowledgement required'
      : profile.state === 'experimental' ? 'Experimental' : 'Unavailable';
  const unresolved = profile.manualRules == null ? 'Reported by profile' : `${profile.manualRules} rules remain for human review`;
  const outsideProfile = profile.fullBenchmarkRules != null && profile.reviewedRules != null
    ? Math.max(0, profile.fullBenchmarkRules - profile.reviewedRules)
    : null;
  return h('article', { className: 'profile-card' },
    h('div', { className: 'profile-card-top' },
      h('div', {},
        h('p', { className: 'card-kicker' }, profile.adapter),
        h('h2', {}, profile.target),
        h('p', { className: 'profile-id' }, `${profile.stigId} · ${profile.revision}`),
      ),
      badge(stateLabel, tone),
    ),
    profile.reason ? notice(profile.reason, tone === 'danger' ? 'danger' : 'warning') : null,
    h('div', { className: 'profile-counts' },
      countBlock('Automated', profile.automatedRules),
      countBlock('Reviewed manual', profile.manualRules),
      countBlock('Full benchmark', profile.fullBenchmarkRules),
    ),
    definitionList([
      ['Collection', profile.methods.length ? profile.methods.join(', ') : 'Declared by adapter'],
      ['Tested versions', profile.testedVersions.length ? profile.testedVersions.join(', ') : 'No tested-version data returned'],
      ['Trust', profile.trust || 'No trust state returned'],
      ['Live acceptance', profile.acceptance || 'No acceptance state returned'],
      ['Reviewed profile', profile.reviewedRules == null ? 'Not returned' : `${profile.reviewedRules} of ${profile.fullBenchmarkRules ?? 'unknown'} benchmark rules`],
      ['Outside profile', outsideProfile == null ? 'Not returned' : `${outsideProfile} rules`],
      ['Manual scope', unresolved],
    ]),
    profile.contentSha256 || profile.checkPackSha256 ? h('details', { className: 'hash-details' },
      h('summary', {}, 'Integrity bindings'),
      profile.contentSha256 ? h('p', {}, h('strong', {}, 'Profile SHA-256 '), h('code', {}, profile.contentSha256)) : null,
      profile.checkPackSha256 ? h('p', {}, h('strong', {}, 'Check pack SHA-256 '), h('code', {}, profile.checkPackSha256)) : null,
    ) : null,
  );
}

function hintProfileCard(profile) {
  return h('article', { className: 'profile-card' },
    h('div', { className: 'profile-card-top' },
      h('div', {},
        h('p', { className: 'card-kicker' }, profile.adapter),
        h('h2', {}, profile.target),
        h('p', { className: 'profile-id' }, `${profile.id} · ${profile.revision}`),
      ),
      badge('Not verified', 'neutral'),
    ),
    h('div', { className: 'profile-counts' },
      countBlock('Automated', profile.automatedRules),
      countBlock('Reviewed manual', profile.manualRules),
      countBlock('Full benchmark', profile.fullBenchmarkRules),
    ),
  );
}

function countBlock(label, value) {
  return h('div', {}, h('strong', {}, value == null ? '—' : value), h('span', {}, label));
}

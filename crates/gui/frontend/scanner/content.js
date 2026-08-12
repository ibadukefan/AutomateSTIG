import { apiUnavailableMessage, endpoints, request } from './api.js';
import { badge, button, definitionList, emptyState, h, loadingState, notice, pageHeader, replace } from './ui.js';

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
      adapterId: String(profile.adapter_id || profile.adapter_name || profile.adapter || ''),
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
      protectedLiveAcceptance: profile.validation?.protected_live_device || profile.protected_live_acceptance || null,
      syntheticFixtureRequirements: profile.validation?.synthetic_fixture_requirements || null,
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
        emptyState(
          'Scanner content cannot be verified',
          'Profile identity, revisions, methods, coverage, hashes, and readiness come only from this running scanner release. Restore the API before making a scan decision.',
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
  const testedVersions = profile.testedVersions.length
    ? profile.testedVersions.join(', ')
    : profile.releaseSupported ? 'Release contract did not return a version grammar' : 'No compatible-version grammar declared';
  const trust = profile.trust === 'release_bundled'
    ? 'Release-bundled profile'
    : profile.trust || 'No trust state returned';
  const acceptance = profile.acceptance === 'experimental_live_acceptance_required'
    ? 'Live-device acceptance required'
    : profile.acceptance || 'No acceptance state returned';
  const live = profile.protectedLiveAcceptance || {};
  const synthetic = profile.syntheticFixtureRequirements || {};
  const liveStatus = live.status === 'passed'
    ? `Accepted · false passes ${live.measured_false_passes ?? 'not returned'} (${live.measured_false_pass_rate ?? 'rate not returned'})`
    : live.status === 'not_run'
      ? `Not run · ${live.reason || 'Protected-device acceptance has not been attached.'}`
      : live.status || 'Not reported';
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
      ['Version compatibility grammar', testedVersions],
      ['Trust', trust],
      ['Live acceptance', acceptance],
      ['Protected-device false-pass status', liveStatus],
      ['Required synthetic inventory', synthetic.status === 'required_inventory'
        ? `${synthetic.required_rule_contract_count ?? 'Unknown'} rule contracts · ${arrayOfText(synthetic.required_case_classes).join(', ') || 'case classes not returned'} · ${synthetic.required_fixture_case_count ?? 'unknown'} required cases`
        : 'Not reported'],
      ['Synthetic execution status', synthetic.status === 'required_inventory'
        ? 'Required inventory only; measured completion and false-pass results are not returned by this runtime profile.'
        : 'Not reported'],
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

function countBlock(label, value) {
  return h('div', {}, h('strong', {}, value == null ? '—' : value), h('span', {}, label));
}

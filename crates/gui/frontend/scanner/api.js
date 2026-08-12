const API_ROOT = '/api/v1';
const DEFAULT_TIMEOUT_MS = 20_000;

let authToken = typeof document !== 'undefined'
  ? document.querySelector('meta[name="automatestig-auth-token"]')?.content || ''
  : '';

export const endpoints = Object.freeze({
  status: '/status',
  connection: '/stig-manager/connection',
  connectionTest: '/stig-manager/connection/test',
  collections: '/stig-manager/collections',
  assets: collectionId => `/stig-manager/collections/${segment(collectionId)}/assets`,
  assignments: (collectionId, assetId) =>
    `/stig-manager/collections/${segment(collectionId)}/assets/${segment(assetId)}/assignments`,
  profiles: '/scanner/profiles',
  retention: '/scanner/retention',
  connectionProfiles: '/scanner/connection-profiles',
  connectionProfile: profileId => `/scanner/connection-profiles/${segment(profileId)}`,
  preflight: '/runs/preflight',
  sshRun: '/runs/ssh',
  evidenceRun: '/runs/evidence',
  jobs: '/runs/jobs',
  job: jobId => `/runs/jobs/${segment(jobId)}`,
  resumeJob: jobId => `/runs/jobs/${segment(jobId)}/resume`,
  runs: '/runs',
  purgedRuns: '/runs/purged',
  run: runId => `/runs/${segment(runId)}`,
  deliveryAttempts: runId => `/runs/${segment(runId)}/delivery-attempts`,
  deliver: runId => `/runs/${segment(runId)}/deliver`,
  purgeEvidence: runId => `/runs/${segment(runId)}/evidence/purge`,
  reconciliationReceipts: runId => `/runs/${segment(runId)}/reconciliation-receipts`,
});

export function pagedEndpoint(path, { offset = 0, limit = 25 } = {}) {
  const query = new URLSearchParams({
    offset: String(Math.max(0, Number(offset) || 0)),
    limit: String(Math.max(1, Number(limit) || 25)),
  });
  return `${path}?${query}`;
}

function segment(value) {
  return encodeURIComponent(String(value ?? '').trim());
}

export class ApiError extends Error {
  constructor(message, { status = 0, code = '', details = null, path = '', cause = null } = {}) {
    super(message, { cause });
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
    this.details = details;
    this.path = path;
  }

  get unavailable() {
    return this.status === 0 || this.status === 404 || this.status === 501 || this.code === 'api_unavailable';
  }

  get unauthorized() {
    return this.status === 401 || this.status === 403;
  }

  get retryable() {
    return this.status === 0 || this.status === 408 || this.status === 425
      || this.status === 429 || this.status >= 500;
  }
}

export function setAuthToken(value) {
  const candidate = String(value ?? '');
  if (candidate && !/^[\x21-\x7e]{16,}$/.test(candidate)) {
    throw new Error('Access token must contain at least 16 visible ASCII characters without whitespace.');
  }
  authToken = candidate;
}

export function hasAuthToken() {
  return Boolean(authToken);
}

export function apiUnavailableMessage(error) {
  if (error instanceof ApiError && error.unauthorized) {
    return 'The scanner API requires an access token. Open Connection and enter the deployment token; it is kept only in this tab.';
  }
  if (error instanceof ApiError && error.unavailable) {
    return 'The versioned scanner API is not responding. You can still review the training flow, but do not treat it as a scan; restore /api/v1 before scanning or handling a delivery.';
  }
  return error?.message || 'The scanner API request could not be completed.';
}

export async function request(path, options = {}) {
  const {
    method = 'GET',
    body,
    headers = {},
    signal,
    timeoutMs = DEFAULT_TIMEOUT_MS,
    accept = 'application/json',
  } = options;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(new Error('request timed out')), timeoutMs);
  const relayAbort = () => controller.abort(signal?.reason);
  signal?.addEventListener('abort', relayAbort, { once: true });

  const requestHeaders = new Headers(headers);
  if (accept) requestHeaders.set('Accept', accept);
  if (authToken) requestHeaders.set('X-Auth-Token', authToken);
  let payload = body;
  if (body != null && !(body instanceof FormData) && typeof body !== 'string') {
    requestHeaders.set('Content-Type', 'application/json');
    payload = JSON.stringify(body);
  }

  let response;
  try {
    response = await fetch(`${API_ROOT}${path}`, {
      method,
      headers: requestHeaders,
      body: payload,
      signal: controller.signal,
      credentials: 'same-origin',
      redirect: 'error',
      cache: 'no-store',
    });
  } catch (error) {
    const message = controller.signal.aborted
      ? 'The scanner API request timed out or was canceled.'
      : 'The scanner API could not be reached.';
    throw new ApiError(message, { path, cause: error });
  } finally {
    clearTimeout(timeout);
    signal?.removeEventListener('abort', relayAbort);
  }

  const contentType = response.headers.get('content-type') || '';
  let responseBody = null;
  if (response.status !== 204) {
    try {
      responseBody = contentType.includes('json') ? await response.json() : await response.text();
    } catch (error) {
      throw new ApiError('The scanner API returned an unreadable response.', {
        status: response.status,
        path,
        cause: error,
      });
    }
  }

  if (!response.ok) {
    const message = responseBody?.error?.message || responseBody?.error
      || responseBody?.message || (typeof responseBody === 'string' && responseBody)
      || `Scanner API request failed with HTTP ${response.status}.`;
    throw new ApiError(String(message), {
      status: response.status,
      code: responseBody?.error?.code || responseBody?.code || '',
      details: responseBody?.error?.details || responseBody?.details || null,
      path,
    });
  }

  if (responseBody && typeof responseBody === 'object' && 'success' in responseBody) {
    if (responseBody.success === false) {
      throw new ApiError(String(responseBody.error?.message || responseBody.error || 'Scanner API operation failed.'), {
        status: response.status,
        code: responseBody.error?.code || '',
        details: responseBody.error?.details || null,
        path,
      });
    }
    return responseBody.data;
  }
  return responseBody;
}

export async function download(path, { signal, timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(new Error('request timed out')), timeoutMs);
  const relayAbort = () => controller.abort(signal?.reason);
  signal?.addEventListener('abort', relayAbort, { once: true });
  const headers = new Headers({ Accept: 'application/zip' });
  if (authToken) headers.set('X-Auth-Token', authToken);
  try {
    const response = await fetch(`${API_ROOT}${path}`, {
      method: 'GET',
      headers,
      signal: controller.signal,
      credentials: 'same-origin',
      redirect: 'error',
      cache: 'no-store',
    });
    if (!response.ok) {
      let message = `Scanner download failed with HTTP ${response.status}.`;
      try {
        const contentType = response.headers.get('content-type') || '';
        const body = contentType.includes('json') ? await response.json() : await response.text();
        message = body?.error?.message || body?.message || (typeof body === 'string' && body) || message;
      } catch (_) {
        // Retain the status-derived message when an error body is unreadable.
      }
      throw new ApiError(String(message), { status: response.status, path });
    }
    const disposition = response.headers.get('content-disposition') || '';
    const match = disposition.match(/filename="?([^";]+)"?/i);
    const filename = match?.[1] && /^[A-Za-z0-9._-]+$/.test(match[1])
      ? match[1]
      : 'automatestig-selected-run.zip';
    return { blob: await response.blob(), filename };
  } catch (error) {
    if (error instanceof ApiError) throw error;
    const message = controller.signal.aborted
      ? 'The scanner download timed out or was canceled.'
      : 'The scanner download could not be completed.';
    throw new ApiError(message, { path, cause: error });
  } finally {
    clearTimeout(timeout);
    signal?.removeEventListener('abort', relayAbort);
  }
}

export async function pollRun(runId, {
  signal,
  onUpdate = () => {},
  intervalMs = 1_000,
  timeoutMs = 15 * 60_000,
  terminalStates = ['preview_ready', 'complete', 'completed', 'delivered', 'failed', 'rejected', 'conflicted', 'incomplete'],
  isTerminal = null,
} = {}) {
  const startedAt = Date.now();
  while (true) {
    if (signal?.aborted) throw new ApiError('Run monitoring was canceled.', { code: 'canceled' });
    const run = await request(endpoints.run(runId), { signal });
    onUpdate(run);
    const state = String(run?.state || run?.status || '').toLowerCase();
    if (typeof isTerminal === 'function' ? isTerminal(run, state) : terminalStates.includes(state)) return run;
    if (Date.now() - startedAt > timeoutMs) {
      throw new ApiError('The run is still active, but this page stopped polling after 15 minutes. Open Deliveries to resume monitoring.', {
        status: 408,
        code: 'poll_timeout',
      });
    }
    await abortableDelay(intervalMs, signal);
  }
}

export async function pollScanJob(jobId, {
  signal,
  onUpdate = () => {},
  intervalMs = 1_000,
  timeoutMs = 15 * 60_000,
} = {}) {
  const startedAt = Date.now();
  while (true) {
    if (signal?.aborted) throw new ApiError('Scan job monitoring was canceled.', { code: 'canceled' });
    const job = await request(endpoints.job(jobId), { signal });
    onUpdate(job);
    const state = String(job?.state || '').toLowerCase();
    if (state === 'completed' || state === 'failed') return job;
    if (Date.now() - startedAt > timeoutMs) {
      throw new ApiError('The durable SSH job is still active, but this page stopped polling after 15 minutes. Its status remains available in Deliveries.', {
        status: 408,
        code: 'poll_timeout',
      });
    }
    await abortableDelay(intervalMs, signal);
  }
}

function abortableDelay(milliseconds, signal) {
  return new Promise((resolve, reject) => {
    const finish = () => {
      signal?.removeEventListener('abort', cancel);
      resolve();
    };
    const cancel = () => {
      clearTimeout(timer);
      reject(new ApiError('Run monitoring was canceled.', { code: 'canceled' }));
    };
    const timer = setTimeout(finish, milliseconds);
    signal?.addEventListener('abort', cancel, { once: true });
  });
}

export { API_ROOT };

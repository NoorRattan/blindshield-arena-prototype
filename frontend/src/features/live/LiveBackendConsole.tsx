import React, { useEffect, useMemo, useState } from 'react';
import { AlertTriangle, Download, RefreshCw, Send, ShieldCheck } from 'lucide-react';
import { LiveArenaClient, type BackendLifecycleAction, type BackendExperimentStatus } from '../../lib/api/liveClient';
import { useLocation } from 'react-router-dom';
import { useArenaStore } from '../../state/useArenaStore';

const ACTIVE_EXPERIMENT_KEY = 'blindshield_live_experiment_id';

function isEmbargoedStatus(
  value: BackendExperimentStatus | { status: 'EMBARGOED' } | null
): value is { status: 'EMBARGOED' } {
  return Boolean(value && 'status' in value && value.status === 'EMBARGOED');
}

const CREATE_REQUEST_EXAMPLE = `{
  "profile_id": "",
  "model_version_id": "",
  "defense_version_id": "",
  "rubric_version_id": "",
  "disclosure_profile_id": "",
  "interaction_mode": "INTERACTIVE",
  "defense_mode": "INPUT",
  "dataset_catalog_id": "",
  "strategy_version_id": "",
  "budget_profile_id": ""
}`;

function errorMessage(error: unknown): string {
  if (error instanceof Error) {
    const code = (error as Error & { code?: string }).code;
    return code ? `${code}: ${error.message}` : error.message;
  }
  return String(error);
}

export const LiveBackendConsole: React.FC = () => {
  const location = useLocation();
  const liveBackendStatus = useArenaStore((state) => state.liveBackendStatus);
  const role = useArenaStore((state) => state.role);
  const epoch = useArenaStore((state) => state.epoch);
  const setEpoch = useArenaStore((state) => state.setEpoch);
  const client = useMemo(() => new LiveArenaClient(), []);
  const [profileError, setProfileError] = useState('');
  const [createRequest, setCreateRequest] = useState('');
  const [experimentId, setExperimentId] = useState('');
  const [sessionId, setSessionId] = useState('');
  const [turnId, setTurnId] = useState('');
  const [turnIndex, setTurnIndex] = useState(1);
  const [turnText, setTurnText] = useState('');
  const [status, setStatus] = useState<BackendExperimentStatus | { status: 'EMBARGOED' } | null>(null);
  const [result, setResult] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    try {
      setExperimentId(window.localStorage.getItem(ACTIVE_EXPERIMENT_KEY) ?? '');
    } catch {
      // Local storage is optional; users can paste the experiment ID.
    }
  }, []);

  useEffect(() => {
    fetch('/local/create-request').then(async (response) => {
      if (!response.ok) throw new Error('NIL — local backend profile unavailable.');
      const value = await response.json();
      setCreateRequest(JSON.stringify(value.request, null, 2));
    }).catch((failure: Error) => setProfileError(failure.message));
  }, []);

  useEffect(() => {
    setStatus(null);
    setResult('');
    setError('');
  }, [role]);

  const rememberExperiment = (id: string) => {
    setExperimentId(id);
    try {
      window.localStorage.setItem(ACTIVE_EXPERIMENT_KEY, id);
    } catch {
      // Local storage is optional; the current page state remains usable.
    }
  };

  const perform = async (operation: () => Promise<unknown>) => {
    setBusy(true);
    setError('');
    try {
      const value = await operation();
      setResult(JSON.stringify(value, null, 2));
      return value;
    } catch (operationError) {
      setError(errorMessage(operationError));
      return undefined;
    } finally {
      setBusy(false);
    }
  };

  const refreshStatus = async () => {
    if (!experimentId.trim()) {
      setError('Paste an experiment UUID first.');
      return;
    }
    const value = await perform(() => client.getBackendStatus(experimentId.trim(), role));
    if (value && typeof value === 'object' && 'epoch' in value && typeof value.epoch === 'number') {
      setStatus(value as BackendExperimentStatus);
      setEpoch(value.epoch);
    } else if (value && typeof value === 'object' && 'status' in value) {
      setStatus(value as { status: 'EMBARGOED' });
    }
  };

  const create = async () => {
    let parsed: unknown;
    try {
      parsed = JSON.parse(createRequest);
    } catch {
      setError('Create request must be valid JSON.');
      return;
    }
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      setError('Create request must be a JSON object.');
      return;
    }
    const created = (await perform(() => client.createConfiguredExperiment(parsed as Record<string, unknown>, undefined, role))) as
      | { experiment_id: string; epoch: number }
      | undefined;
    if (created?.experiment_id) {
      rememberExperiment(created.experiment_id);
      setEpoch(created.epoch);
      setSessionId('');
      setTurnId('');
      const current = await perform(() => client.getBackendStatus(created.experiment_id, role));
      if (current && typeof current === 'object' && 'epoch' in current) {
        setStatus(current as BackendExperimentStatus);
      }
    }
  };

  const lifecycle = async (action: BackendLifecycleAction) => {
    if (!experimentId.trim()) {
      setError('Paste or create an experiment UUID first.');
      return;
    }
    const value = await perform(() => client.runBackendLifecycleAction(experimentId.trim(), action, epoch, role));
    if (value) await refreshStatus();
  };

  const createSession = async () => {
    if (!experimentId.trim()) {
      setError('Paste or create an experiment UUID first.');
      return;
    }
    const session = (await perform(() => client.createBackendSession(experimentId.trim(), epoch, role))) as
      | { session_id: string }
      | undefined;
    if (session?.session_id) setSessionId(session.session_id);
  };

  const submitTurn = async () => {
    if (!experimentId.trim() || !sessionId.trim() || !turnText.trim()) {
      setError('Experiment ID, session ID, and turn text are required.');
      return;
    }
    const accepted = (await perform(() =>
      client.submitBackendTurn(
        experimentId.trim(),
        sessionId.trim(),
        { epoch, turn_index: turnIndex, text: turnText },
        role
      )
    )) as { status?: string; turn_id?: string | null } | undefined;
    if (accepted?.status === 'ACCEPTED' && accepted.turn_id) {
      setTurnId(accepted.turn_id);
      setTurnIndex((index) => index + 1);
    }
  };

  const pollTurn = async () => {
    if (!experimentId.trim() || !sessionId.trim() || !turnId.trim()) {
      setError('Submit a turn first, or enter its experiment, session, and turn IDs.');
      return;
    }
    await perform(() => client.getBackendTurnStatus(experimentId.trim(), sessionId.trim(), turnId.trim(), role));
  };

  const downloadEvidence = async () => {
    if (!experimentId.trim()) {
      setError('Paste or create an experiment UUID first.');
      return;
    }
    const response = (await perform(() => client.downloadBackendEvidence(experimentId.trim(), role))) as
      | Response
      | undefined;
    if (!response) return;
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `${experimentId.trim()}-evidence.zip`;
    anchor.click();
    URL.revokeObjectURL(url);
  };

  const isStatusEmbargoed = isEmbargoedStatus(status);

  return (
    <div className="mx-auto max-w-5xl space-y-6" data-testid="live-backend-console">
      <header className="rounded border border-cy/40 bg-cy/5 p-5">
        <div className="flex items-start gap-3">
          <ShieldCheck className="mt-0.5 h-5 w-5 shrink-0 text-cy" aria-hidden="true" />
          <div>
            <p className="font-mono text-xs font-bold uppercase tracking-widest text-cy">Local prototype API</p>
            <h1 className="mt-1 font-display text-3xl text-tx">Backend-connected console</h1>
            <p className="mt-2 max-w-3xl text-sm text-mut">
              Requests use the selected roleâ€™s local mTLS certificate through the loopback-only Vite proxy. The backend
              remains authoritative for access and lifecycle. Only API fields returned by the running service appear here.
            </p>
          </div>
        </div>
        <div className="mt-4 grid gap-2 border-t border-cy/20 pt-3 text-xs text-mut sm:grid-cols-3">
          <span>Selected identity: <strong className="text-tx">{role}</strong></span>
          <span>Transport: <strong className="text-tx">mTLS Â· local proxy</strong></span>
          <span>Connection: <strong className="text-tx">{liveBackendStatus}</strong></span>
        </div>
      </header>

      <section className="rounded border border-bd bg-s1 p-4" aria-label="Backend data availability">
        <h2 className="font-mono text-sm font-bold uppercase tracking-wider text-cy">{location.pathname === '/' ? 'Arena overview' : location.pathname.slice(1).replace('-', ' ')} · backend data</h2>
        <div className="mt-3 grid grid-cols-2 gap-3 font-mono text-xs text-mut sm:grid-cols-3">
          {['Model output', 'Latency', 'Attack success rate', 'Resource telemetry', 'Witness status', 'Evidence verification'].map((label) => <p key={label}>{label}: <strong className="text-tx">NIL</strong></p>)}
        </div>
        <p className="mt-3 text-xs text-mut">NIL means the running backend has not supplied this value. No simulated metrics, model output or evidence are displayed.</p>
      </section>
      {profileError && <p className="font-mono text-xs text-am">{profileError}</p>}
      <section className="grid gap-6 lg:grid-cols-2">
        {role === 'operator' && (
          <div className="space-y-3 rounded border border-bd bg-s1 p-4">
            <h2 className="font-mono text-sm font-bold uppercase tracking-wider">Create a registered experiment</h2>
            <p className="text-xs leading-5 text-mut">
              Paste the exact public request configured for the running backend. Experiment setup and admission still
              happen with the backendâ€™s owner-managed tools; this form does not bypass those gates.
            </p>
            <textarea
              aria-label="Backend create request JSON"
              value={createRequest}
              onChange={(event) => setCreateRequest(event.target.value)}
              placeholder={CREATE_REQUEST_EXAMPLE}
              rows={12}
              className="w-full rounded border border-bd bg-bg p-3 font-mono text-xs text-tx outline-none focus:border-cy"
              spellCheck={false}
            />
            <button type="button" onClick={create} disabled={busy || !createRequest.trim()} className="rounded border border-cy/50 px-3 py-2 font-mono text-xs font-bold uppercase text-cy disabled:opacity-50">
              Create using operator certificate
            </button>
          </div>
        )}

        <div className="space-y-3 rounded border border-bd bg-s1 p-4">
          <h2 className="font-mono text-sm font-bold uppercase tracking-wider">Experiment status</h2>
          <label className="block text-xs text-mut" htmlFor="live-experiment-id">Experiment UUID</label>
          <input
            id="live-experiment-id"
            value={experimentId}
            onChange={(event) => { rememberExperiment(event.target.value.trim()); setStatus(null); setResult(''); }}
            placeholder="Paste an experiment ID returned by the backend"
            className="w-full rounded border border-bd bg-bg px-3 py-2 font-mono text-xs text-tx outline-none focus:border-cy"
          />
          <button type="button" onClick={refreshStatus} disabled={busy || !experimentId.trim()} className="inline-flex items-center gap-2 rounded border border-bd px-3 py-2 font-mono text-xs font-bold uppercase text-tx disabled:opacity-50">
            <RefreshCw className={`h-3.5 w-3.5 ${busy ? 'animate-spin' : ''}`} aria-hidden="true" /> Refresh status
          </button>
          {!status && <p className="font-mono text-sm text-mut">Phase: NIL · Integrity: NIL · Domain: NIL</p>}
          {status && (
            <div className="rounded border border-bd bg-bg p-3">
              {isStatusEmbargoed ? (
                <p className="font-mono text-sm font-bold text-am">EMBARGOED â€” the backend withheld this roleâ€™s status projection.</p>
              ) : (
                <>
                  <p className="font-mono text-xs uppercase text-mut">Phase <strong className="ml-2 text-cy">{status.phase}</strong></p>
                  <p className="mt-1 font-mono text-xs uppercase text-mut">Integrity <strong className="ml-2 text-tx">{status.integrity ?? 'NIL'}</strong></p>
                  <p className="mt-1 break-all font-mono text-[11px] text-mut">Domain {status.domain_id} Â· Epoch {status.epoch}</p>
                </>
              )}
            </div>
          )}
        </div>
      </section>

      {experimentId.trim() && (
        <section className="grid gap-6 lg:grid-cols-2">
          {role === 'operator' && (
            <div className="space-y-3 rounded border border-bd bg-s1 p-4">
              <h2 className="font-mono text-sm font-bold uppercase tracking-wider">Operator lifecycle</h2>
              <p className="text-xs text-mut">Each action is authenticated and phase-checked by the backend. Accepted asynchronous actions are polled to a terminal result.</p>
              <div className="flex flex-wrap gap-2">
                {(['seal', 'start', 'finish', 'close', 'release'] as const).map((action) => (
                  <button key={action} type="button" onClick={() => void lifecycle(action)} disabled={busy} className="rounded border border-bd px-3 py-2 font-mono text-xs uppercase text-tx disabled:opacity-50">
                    {action}
                  </button>
                ))}
                <button type="button" onClick={createSession} disabled={busy} className="rounded border border-bd px-3 py-2 font-mono text-xs uppercase text-tx disabled:opacity-50">Allocate session</button>
              </div>
              {sessionId && <p className="break-all font-mono text-xs text-mut">Session: <strong className="text-tx">{sessionId}</strong></p>}
            </div>
          )}

          {role === 'red' && (
            <div className="space-y-3 rounded border border-bd bg-s1 p-4">
              <h2 className="font-mono text-sm font-bold uppercase tracking-wider">Red-team interactive turn</h2>
              <label className="block text-xs text-mut" htmlFor="live-session-id">Operator-allocated session UUID</label>
              <input id="live-session-id" value={sessionId} onChange={(event) => setSessionId(event.target.value.trim())} className="w-full rounded border border-bd bg-bg px-3 py-2 font-mono text-xs text-tx outline-none focus:border-cy" placeholder="Paste the returned session ID" />
              <div className="flex items-center gap-3 text-xs text-mut">
                <label htmlFor="live-turn-index">Next turn index</label>
                <input id="live-turn-index" type="number" min={1} value={turnIndex} onChange={(event) => setTurnIndex(Number(event.target.value))} className="w-24 rounded border border-bd bg-bg px-2 py-1 font-mono text-tx" />
              </div>
              <textarea aria-label="Interactive turn text" value={turnText} onChange={(event) => setTurnText(event.target.value)} rows={4} className="w-full rounded border border-bd bg-bg p-3 text-sm text-tx outline-none focus:border-cy" placeholder="Enter an admitted public-corpus probe" />
              <div className="flex flex-wrap gap-2">
                <button type="button" onClick={submitTurn} disabled={busy || !turnText.trim()} className="inline-flex items-center gap-2 rounded border border-cy/50 px-3 py-2 font-mono text-xs uppercase text-cy disabled:opacity-50"><Send className="h-3.5 w-3.5" aria-hidden="true" /> Submit once</button>
                <button type="button" onClick={pollTurn} disabled={busy || !turnId} className="rounded border border-bd px-3 py-2 font-mono text-xs uppercase text-tx disabled:opacity-50">Poll accepted turn</button>
              </div>
              {turnId && <p className="break-all font-mono text-xs text-mut">Accepted turn: <strong className="text-tx">{turnId}</strong></p>}
            </div>
          )}

          {role === 'auditor' && (
            <div className="space-y-3 rounded border border-bd bg-s1 p-4">
              <h2 className="font-mono text-sm font-bold uppercase tracking-wider">Auditor evidence</h2>
              <p className="text-xs text-mut">Available only after the backendâ€™s authorized close and release conditions are met.</p>
              <button type="button" onClick={downloadEvidence} disabled={busy} className="inline-flex items-center gap-2 rounded border border-bd px-3 py-2 font-mono text-xs uppercase text-tx disabled:opacity-50"><Download className="h-3.5 w-3.5" aria-hidden="true" /> Download evidence ZIP</button>
            </div>
          )}

          {role === 'blue' && (
            <div className="rounded border border-bd bg-s1 p-4">
              <h2 className="font-mono text-sm font-bold uppercase tracking-wider">Blue-team projection</h2>
              <p className="mt-2 text-xs leading-5 text-mut">The backend applies its blue-role embargo. This UI does not infer hidden status or reveal withheld payloads.</p>
            </div>
          )}
        </section>
      )}

      {error && (
        <div role="alert" className="flex gap-2 rounded border border-inv/50 bg-inv/10 p-3 font-mono text-xs text-tx">
          <AlertTriangle className="h-4 w-4 shrink-0 text-inv" aria-hidden="true" />
          <span>{error}</span>
        </div>
      )}
      {result && (
        <section className="rounded border border-bd bg-s1 p-4">
          <h2 className="mb-2 font-mono text-xs font-bold uppercase tracking-wider text-mut">Last backend response</h2>
          <pre className="max-h-72 overflow-auto whitespace-pre-wrap break-words font-mono text-xs text-tx">{result}</pre>
        </section>
      )}

      <p className="text-xs leading-5 text-mut">
        This prototype API does not expose experiment listings, preflight results, manifests, resource telemetry, or an event stream. These fields display NIL; no mock data is substituted.
      </p>
    </div>
  );
};

import { create } from 'zustand';

export type UserRole = 'operator' | 'red' | 'blue' | 'auditor';
export type ConnectionMode = 'simulated' | 'live';
export type LiveBackendStatus = 'CONNECTED' | 'DISCONNECTED' | 'FAIL_CLOSED';

export interface AuthenticatedPrincipal {
  subject_id: string;
  role: UserRole;
  domain_id: string;
  expires_at: string;
  is_mtls_verified: boolean;
  certFingerprint?: string;
  cert_fingerprint?: string;
  subject?: string;
}

export type FailureMode =
  | 'none'
  | 'defense_timeout'
  | 'recorder_down'
  | 'stale_epoch'
  | 'witness_lag'
  | 'reconnect'
  | 'audit_unavailable';

export interface ArenaState {
  role: UserRole;
  domain: string;
  epoch: number; // Invariant 5: Exact positive integer
  witnessStatus: 'SYNCED' | 'PENDING' | 'INVALID';
  failureMode: FailureMode;
  theme: 'dark' | 'light';
  connectionMode: ConnectionMode;
  liveBackendStatus: LiveBackendStatus;
  authenticatedPrincipal: AuthenticatedPrincipal | null;
  setRole: (role: UserRole) => void;
  setConnectionMode: (mode: ConnectionMode) => void;
  setLiveBackendStatus: (status: LiveBackendStatus) => void;
  setAuthenticatedPrincipal: (principal: AuthenticatedPrincipal | null) => void;
  setTheme: (theme: 'dark' | 'light') => void;
  toggleTheme: () => void;
  setEpoch: (epoch: number) => void;
  setFailureMode: (mode: FailureMode) => void;
}

const safeGetStorage = (key: string): string | null => {
  try {
    if (typeof window !== 'undefined' && window.localStorage && typeof window.localStorage.getItem === 'function') {
      return window.localStorage.getItem(key);
    }
  } catch {
    // Ignore storage unavailability in environments such as Node 22 without storage files
  }
  return null;
};

const safeSetStorage = (key: string, value: string): void => {
  try {
    if (typeof window !== 'undefined' && window.localStorage && typeof window.localStorage.setItem === 'function') {
      window.localStorage.setItem(key, value);
    }
  } catch {
    // Ignore storage unavailability
  }
};

const getInitialRole = (): UserRole => {
  const stored = safeGetStorage('blindshield_role') as UserRole;
  if (stored === 'operator' || stored === 'red' || stored === 'blue' || stored === 'auditor') {
    return stored;
  }
  return 'operator';
};

const getInitialConnectionMode = (): ConnectionMode => 'live';

export const useArenaStore = create<ArenaState>((set, get) => ({
  role: getInitialRole(),
  domain: 'NIL',
  epoch: 1,
  witnessStatus: 'PENDING',
  failureMode: 'none',
  theme: 'dark',
  connectionMode: getInitialConnectionMode(),
  liveBackendStatus: 'DISCONNECTED',
  authenticatedPrincipal: null,
  setRole: (role) => {
    const state = get();
    // In live mode with authenticated certificate, role is strictly bound to mTLS
    if (state.connectionMode === 'live' && state.authenticatedPrincipal?.is_mtls_verified) {
      if (role !== state.authenticatedPrincipal.role) {
        throw new Error(`Cannot switch role in live mode: bound to mTLS client certificate (${state.authenticatedPrincipal.role})`);
      }
    }
    safeSetStorage('blindshield_role', role);
    set({ role });
  },
  setConnectionMode: () => {
    safeSetStorage('blindshield_connection_mode', 'live');
    set({ connectionMode: 'live', liveBackendStatus: 'FAIL_CLOSED' });
  },
  setLiveBackendStatus: (liveBackendStatus) => set({ liveBackendStatus }),
  setAuthenticatedPrincipal: (authenticatedPrincipal) => {
    if (authenticatedPrincipal) {
      set({
        authenticatedPrincipal,
        role: authenticatedPrincipal.role,
        domain: authenticatedPrincipal.domain_id || 'BAYORA-PROD-01',
      });
    } else {
      set({ authenticatedPrincipal });
    }
  },
  setFailureMode: (failureMode) => {
    const state = get();
    if (state.connectionMode === 'live' && failureMode !== 'none') {
      throw new Error('Failure injection is prohibited in live mode (fail-closed backend boundary)');
    }
    set({ failureMode });
  },
  setTheme: () => {
    document.documentElement.setAttribute('data-theme', 'dark');
    set({ theme: 'dark' });
  },
  toggleTheme: () => {
    document.documentElement.setAttribute('data-theme', 'dark');
    set({ theme: 'dark' });
  },
  setEpoch: (epoch) => {
    if (Number.isInteger(epoch) && epoch > 0) {
      set({ epoch });
    }
  },
}));

if (typeof window !== 'undefined') {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  (window as any).__arenaStore = useArenaStore;
}

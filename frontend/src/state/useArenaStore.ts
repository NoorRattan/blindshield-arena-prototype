import { create } from 'zustand';

export type UserRole = 'operator' | 'red' | 'blue' | 'auditor';
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
  setRole: (role: UserRole) => void;
  setTheme: (theme: 'dark' | 'light') => void;
  toggleTheme: () => void;
  setEpoch: (epoch: number) => void;
  setFailureMode: (mode: FailureMode) => void;
}

const getInitialRole = (): UserRole => {
  if (typeof window !== 'undefined') {
    const stored = localStorage.getItem('blindshield_role') as UserRole;
    if (stored === 'operator' || stored === 'red' || stored === 'blue' || stored === 'auditor') {
      return stored;
    }
  }
  return 'operator';
};

export const useArenaStore = create<ArenaState>((set) => ({
  role: getInitialRole(),
  domain: 'BAYORA-PROD-01',
  epoch: 4,
  witnessStatus: 'SYNCED',
  failureMode: 'none',
  theme: 'dark',
  setRole: (role) => {
    if (typeof window !== 'undefined') {
      localStorage.setItem('blindshield_role', role);
    }
    set({ role });
  },
  setFailureMode: (failureMode) => set({ failureMode }),
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

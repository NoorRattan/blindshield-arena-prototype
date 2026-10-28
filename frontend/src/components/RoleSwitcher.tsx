import React from 'react';
import { useArenaStore, type UserRole } from '../state/useArenaStore';
import { UserCheck, Lock } from 'lucide-react';
import { cn } from '../lib/cn';

const ROLES: { id: UserRole; label: string; desc: string }[] = [
  { id: 'operator', label: 'Operator', desc: 'Full telemetry & control' },
  { id: 'red', label: 'Red Team', desc: 'Submissions & bounded feedback' },
  { id: 'blue', label: 'Blue Team', desc: 'Defenses & delayed telemetry' },
  { id: 'auditor', label: 'Auditor', desc: 'Evidence bundles & verification' },
];

export interface RoleSwitcherProps {
  className?: string;
}

export const RoleSwitcher: React.FC<RoleSwitcherProps> = ({ className }) => {
  const { role, setRole, connectionMode, authenticatedPrincipal } = useArenaStore();
  const isLive = connectionMode === 'live';

  return (
    <div
      className={cn(
        'inline-flex items-center gap-1.5 font-mono text-xs bg-s2/90 border border-bd rounded p-1 select-none',
        className
      )}
      role="group"
      aria-label="Role selector"
    >
      {/* Mode & Auth Badge */}
      {isLive ? (
        <span
          className="hidden md:flex items-center gap-1 px-1.5 py-0.5 rounded bg-ok/10 border border-ok/30 text-ok text-[10px] font-bold uppercase tracking-wider"
          title="Role derived from authenticated mTLS client certificate — client-side switching restricted"
        >
          <Lock className="w-3 h-3 stroke-[2]" />
          <span>mTLS CERTIFICATE</span>
        </span>
      ) : (
        <span
          className="hidden md:flex items-center gap-1 px-1.5 py-0.5 rounded bg-am/10 border border-am/30 text-am text-[10px] font-bold uppercase tracking-wider"
          title="Client-side simulated role override — in-memory demo only (not mTLS verified)"
        >
          <UserCheck className="w-3 h-3 stroke-[2]" />
          <span>SIMULATED ROLE (MOCK ONLY)</span>
        </span>
      )}

      {/* Role selection buttons */}
      <div className="flex items-center gap-0.5">
        {ROLES.map((r) => {
          const isActive = role === r.id;
          const isDisabled = isLive && Boolean(authenticatedPrincipal?.is_mtls_verified && authenticatedPrincipal.role !== r.id);
          return (
            <button
              key={r.id}
              type="button"
              onClick={() => {
                if (!isDisabled) {
                  setRole(r.id);
                }
              }}
              disabled={isDisabled}
              aria-pressed={isActive}
              title={
                isDisabled
                  ? `Locked: mTLS certificate authenticated as '${authenticatedPrincipal?.role}'`
                  : `${r.label}: ${r.desc}`
              }
              className={cn(
                'px-2 py-0.5 rounded text-[11px] uppercase tracking-wider font-medium transition-colors',
                isActive
                  ? 'bg-cy/15 text-cy border border-cy/40 font-bold'
                  : 'text-mut hover:text-tx hover:bg-s1',
                isDisabled && 'opacity-40 cursor-not-allowed hover:bg-transparent hover:text-mut'
              )}
            >
              {r.label}
            </button>
          );
        })}
      </div>
    </div>
  );
};

import React from 'react';
import { useArenaStore, type UserRole } from '../state/useArenaStore';
import { UserCheck } from 'lucide-react';
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
  const { role, setRole } = useArenaStore();

  return (
    <div
      className={cn(
        'inline-flex items-center gap-1.5 font-mono text-xs bg-s2/90 border border-bd rounded p-1 select-none',
        className
      )}
      role="group"
      aria-label="Role selector"
    >
      {/* Demo Mode Badge */}
      <span className="hidden md:flex items-center gap-1 px-1.5 py-0.5 rounded bg-am/10 border border-am/30 text-am text-[10px] font-bold uppercase tracking-wider">
        <UserCheck className="w-3 h-3 stroke-[2]" />
        <span>DEMO MODE</span>
      </span>

      {/* Role selection buttons */}
      <div className="flex items-center gap-0.5">
        {ROLES.map((r) => {
          const isActive = role === r.id;
          return (
            <button
              key={r.id}
              type="button"
              onClick={() => setRole(r.id)}
              aria-pressed={isActive}
              title={`${r.label}: ${r.desc}`}
              className={cn(
                'px-2 py-0.5 rounded text-[11px] uppercase tracking-wider font-medium transition-colors',
                isActive
                  ? 'bg-cy/15 text-cy border border-cy/40 font-bold'
                  : 'text-mut hover:text-tx hover:bg-s1'
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

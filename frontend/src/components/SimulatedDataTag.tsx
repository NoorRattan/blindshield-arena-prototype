import React from 'react';
import { AlertTriangle, Database } from 'lucide-react';
import { cn } from '../lib/cn';
import { useArenaStore } from '../state/useArenaStore';

export interface SimulatedDataTagProps {
  className?: string;
  variant?: 'badge' | 'banner';
  message?: string;
  forceShow?: boolean;
}

/**
 * Prominent label explicitly identifying simulated/mock data across the application.
 * Required by Task 1: "Make simulated and live modes unmistakable".
 */
export const SimulatedDataTag: React.FC<SimulatedDataTagProps> = ({
  className,
  variant = 'badge',
  message,
  forceShow = false,
}) => {
  const connectionMode = useArenaStore((state) => state.connectionMode);

  // If live mode is active and not forced, do not render simulated label
  if (connectionMode === 'live' && !forceShow) {
    return null;
  }

  if (variant === 'banner') {
    return (
      <div
        role="status"
        aria-label="Simulated Demonstration Notice"
        className={cn(
          'border border-am/40 bg-am/10 px-4 py-2.5 rounded-[2px] font-mono text-xs text-am flex items-center justify-between gap-3',
          className
        )}
      >
        <div className="flex items-center gap-2.5">
          <AlertTriangle className="w-4 h-4 text-am shrink-0" aria-hidden="true" />
          <span className="font-bold tracking-wider uppercase text-[11px]">SIMULATED DATA</span>
          <span className="text-tx text-[11px]">
            {message ??
              'In-memory demonstrator mode: telemetry, events, and fixtures are simulated client-side. No live backend connected.'}
          </span>
        </div>
        <span className="text-[10px] font-mono text-mut uppercase tracking-wider hidden sm:inline-block">
          FAIL-SAFE DEMO
        </span>
      </div>
    );
  }

  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 px-2 py-0.5 rounded-[2px] font-mono text-[10px] font-bold tracking-wider bg-am/15 text-am border border-am/40 select-none uppercase',
        className
      )}
      title="SIMULATED DATA: Running in in-memory simulation mode (not live backend)"
    >
      <Database className="w-3 h-3 text-am" aria-hidden="true" />
      <span>SIMULATED DATA</span>
    </span>
  );
};

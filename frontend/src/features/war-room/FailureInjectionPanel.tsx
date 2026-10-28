import React from 'react';
import { AlertTriangle, Clock, Database, History, Anchor, RotateCcw } from 'lucide-react';
import { cn } from '../../lib/cn';
import type { FailureMode } from '../../lib/mock/sse';

export interface FailureInjectionPanelProps {
  currentMode: FailureMode;
  onSetFailureMode: (mode: FailureMode) => void;
  className?: string;
}

export const FailureInjectionPanel: React.FC<FailureInjectionPanelProps> = ({
  currentMode,
  onSetFailureMode,
  className,
}) => {
  return (
    <div
      className={cn(
        'border border-am/40 bg-s1 p-3 mb-4 rounded relative overflow-hidden',
        currentMode !== 'none' && 'border-am bg-am/5',
        className
      )}
      role="region"
      aria-label="Demo Mode Failure Injection Matrix"
    >
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
        {/* Label & Context */}
        <div className="flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 text-am flex-shrink-0" />
          <div>
            <div className="flex items-center gap-2">
              <span className="font-mono text-xs font-bold uppercase tracking-wider text-am">
                [DEMO MODE: FAILURE INJECTION MATRIX]
              </span>
              <span className="font-mono text-[10px] px-1.5 py-0.2 bg-am/20 text-am border border-am/40">
                ACTIVE: {currentMode.toUpperCase()}
              </span>
            </div>
            <p className="text-xs text-mut font-sans mt-0.5">
              Simulate host failure modes to verify tamper detection, boundary enforcement, and no-retry invariants.
            </p>
          </div>
        </div>

        {/* Action Buttons */}
        <div className="flex flex-wrap items-center gap-2">
          {/* 1. Defense Timeout */}
          <button
            type="button"
            onClick={() => onSetFailureMode(currentMode === 'defense_timeout' ? 'none' : 'defense_timeout')}
            className={cn(
              'inline-flex items-center gap-1.5 px-2.5 py-1 font-mono text-xs uppercase tracking-wider border rounded-sm transition-colors',
              'focus:outline-none focus-visible:ring-2 focus-visible:ring-am focus-visible:ring-offset-1 focus-visible:ring-offset-bg',
              currentMode === 'defense_timeout'
                ? 'bg-inv/20 border-inv text-inv font-bold'
                : 'bg-s2 border-bd text-tx hover:border-am/60 hover:text-am'
            )}
            title="Defense execution exceeds 1,000ms deadline; invalidates turn without retry"
          >
            <Clock className="w-3.5 h-3.5" />
            <span>defense_timeout</span>
          </button>

          {/* 2. Recorder Down */}
          <button
            type="button"
            onClick={() => onSetFailureMode(currentMode === 'recorder_down' ? 'none' : 'recorder_down')}
            className={cn(
              'inline-flex items-center gap-1.5 px-2.5 py-1 font-mono text-xs uppercase tracking-wider border rounded-sm transition-colors',
              'focus:outline-none focus-visible:ring-2 focus-visible:ring-am focus-visible:ring-offset-1 focus-visible:ring-offset-bg',
              currentMode === 'recorder_down'
                ? 'bg-bad/20 border-bad text-bad font-bold'
                : 'bg-s2 border-bd text-tx hover:border-bad/60 hover:text-bad'
            )}
            title="Simulates ledger storage disconnect; triggers AUDIT_UNAVAILABLE"
          >
            <Database className="w-3.5 h-3.5" />
            <span>recorder_down</span>
          </button>

          {/* 3. Stale Epoch */}
          <button
            type="button"
            onClick={() => onSetFailureMode(currentMode === 'stale_epoch' ? 'none' : 'stale_epoch')}
            className={cn(
              'inline-flex items-center gap-1.5 px-2.5 py-1 font-mono text-xs uppercase tracking-wider border rounded-sm transition-colors',
              'focus:outline-none focus-visible:ring-2 focus-visible:ring-am focus-visible:ring-offset-1 focus-visible:ring-offset-bg',
              currentMode === 'stale_epoch'
                ? 'bg-am/20 border-am text-am font-bold'
                : 'bg-s2 border-bd text-tx hover:border-am/60 hover:text-am'
            )}
            title="Emits events with older epoch numbers; ignored & logged as STALE_EPOCH"
          >
            <History className="w-3.5 h-3.5" />
            <span>stale_epoch</span>
          </button>

          {/* 4. Witness Lag */}
          <button
            type="button"
            onClick={() => onSetFailureMode(currentMode === 'witness_lag' ? 'none' : 'witness_lag')}
            className={cn(
              'inline-flex items-center gap-1.5 px-2.5 py-1 font-mono text-xs uppercase tracking-wider border rounded-sm transition-colors',
              'focus:outline-none focus-visible:ring-2 focus-visible:ring-am focus-visible:ring-offset-1 focus-visible:ring-offset-bg',
              currentMode === 'witness_lag'
                ? 'bg-am/20 border-am text-am font-bold'
                : 'bg-s2 border-bd text-tx hover:border-am/60 hover:text-am'
            )}
            title="Witness signing queue lags; turns watermark badge amber and withholds completion"
          >
            <Anchor className="w-3.5 h-3.5" />
            <span>witness_lag</span>
          </button>

          {/* Reset button */}
          {currentMode !== 'none' && (
            <button
              type="button"
              onClick={() => onSetFailureMode('none')}
              className={cn(
                'inline-flex items-center gap-1 px-2 py-1 font-mono text-xs uppercase tracking-wider',
                'border border-bd bg-s2 text-mut hover:text-tx hover:border-tx rounded-sm transition-colors',
                'focus:outline-none focus-visible:ring-2 focus-visible:ring-cy'
              )}
              title="Reset all failure injections to nominal state"
            >
              <RotateCcw className="w-3 h-3" />
              <span>Reset</span>
            </button>
          )}
        </div>
      </div>
    </div>
  );
};

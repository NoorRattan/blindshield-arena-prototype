import React from 'react';
import type { SetupFormData } from '../types';
import { cn } from '../../../lib/cn';

interface Step5Props {
  formData: SetupFormData;
  onChange: (updates: Partial<SetupFormData>) => void;
}

export const Step5DisclosurePolicy: React.FC<Step5Props> = ({
  formData,
  onChange,
}) => {
  return (
    <div className="space-y-6">
      <div>
        <div className="flex items-center justify-between mb-1.5">
          <span className="font-mono text-xs uppercase tracking-wider text-tx font-semibold">
            01. Evaluation Feedback & Disclosure Profile
          </span>
          <span className="font-mono text-[11px] text-mut">SPEC C-07</span>
        </div>
        <p className="font-sans text-xs text-mut mb-4">
          Defines what information is disclosed to Red and Blue teams during the active evaluation round. Selecting a profile enforces cryptographic withholding, but never implies absolute safety.
        </p>

        <div className="space-y-4" role="radiogroup" aria-label="Feedback and Disclosure Profile">
          {/* SEALED_BATCH */}
          <div
            role="radio"
            aria-checked={formData.disclosure_policy === 'SEALED_BATCH'}
            tabIndex={0}
            onClick={() => onChange({ disclosure_policy: 'SEALED_BATCH' })}
            onKeyDown={(e) => {
              if (e.key === ' ' || e.key === 'Enter') {
                e.preventDefault();
                onChange({ disclosure_policy: 'SEALED_BATCH' });
              }
            }}
            className={cn(
              'p-4 border rounded-[2px] cursor-pointer transition-colors focus:outline-none focus:ring-1 focus:ring-cy',
              formData.disclosure_policy === 'SEALED_BATCH'
                ? 'bg-cy/5 border-cy'
                : 'bg-s2 border-bd hover:border-bd-strong'
            )}
          >
            <div className="flex items-center justify-between mb-1.5">
              <span className="font-mono text-sm font-bold uppercase text-tx">
                SEALED_BATCH (Default)
              </span>
              <span className="font-mono text-[10px] text-cy font-bold uppercase px-2 py-0.5 bg-cy/10 border border-cy/30 rounded-[2px]">
                COMPLETE EMBARGO
              </span>
            </div>
            <p className="font-sans text-xs text-tx font-medium mb-2.5">
              Withholds all turn verdicts, model response tokens, and defense decisions until durable epoch close.
            </p>
            <div className="space-y-1.5 font-mono text-[11px] text-mut bg-s1/60 p-2.5 border border-bd rounded-[2px]">
              <div className="flex items-start gap-1.5">
                <span className="text-cy">•</span>
                <span><strong className="text-tx">Red Team View:</strong> Receives submission receipt only. Verdicts and telemetry withheld until close.</span>
              </div>
              <div className="flex items-start gap-1.5">
                <span className="text-cy">•</span>
                <span><strong className="text-tx">Blue Team View:</strong> Health telemetry only. Blocked/Allowed split withheld until release.</span>
              </div>
              <div className="flex items-start gap-1.5">
                <span className="text-cy">•</span>
                <span><strong className="text-tx">Channel Bounding:</strong> Bounds covert timing channels by enforcing post-round durable disclosure.</span>
              </div>
            </div>
          </div>

          {/* CONTROLLED_FEEDBACK */}
          <div
            role="radio"
            aria-checked={formData.disclosure_policy === 'CONTROLLED_FEEDBACK'}
            tabIndex={0}
            onClick={() => onChange({ disclosure_policy: 'CONTROLLED_FEEDBACK' })}
            onKeyDown={(e) => {
              if (e.key === ' ' || e.key === 'Enter') {
                e.preventDefault();
                onChange({ disclosure_policy: 'CONTROLLED_FEEDBACK' });
              }
            }}
            className={cn(
              'p-4 border rounded-[2px] cursor-pointer transition-colors focus:outline-none focus:ring-1 focus:ring-cy',
              formData.disclosure_policy === 'CONTROLLED_FEEDBACK'
                ? 'bg-cy/5 border-cy'
                : 'bg-s2 border-bd hover:border-bd-strong'
            )}
          >
            <div className="flex items-center justify-between mb-1.5">
              <span className="font-mono text-sm font-bold uppercase text-tx">
                CONTROLLED_FEEDBACK
              </span>
              <span className="font-mono text-[10px] text-am font-bold uppercase px-2 py-0.5 bg-am/10 border border-am/30 rounded-[2px]">
                BOUNDED PER-TURN
              </span>
            </div>
            <p className="font-sans text-xs text-tx font-medium mb-2.5">
              Discloses bounded binary verdicts per turn. Each disclosure is immutably recorded in the tamper-evident ledger.
            </p>
            <div className="space-y-1.5 font-mono text-[11px] text-mut bg-s1/60 p-2.5 border border-bd rounded-[2px]">
              <div className="flex items-start gap-1.5">
                <span className="text-am">•</span>
                <span><strong className="text-tx">Red Team View:</strong> Receives binary ALLOWED or BLOCKED decision per turn with delayed timing.</span>
              </div>
              <div className="flex items-start gap-1.5">
                <span className="text-am">•</span>
                <span><strong className="text-tx">Auditing:</strong> Each feedback disclosure generates a signed event with sequence number and microsecond timestamp.</span>
              </div>
              <div className="flex items-start gap-1.5">
                <span className="text-am">•</span>
                <span><strong className="text-tx">Residual Risk:</strong> Interactive feedback increases adaptive probing capacity; channel bound must be monitored.</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Interaction Mode Selection (MEM-003 §2a) */}
      <div className="pt-4 border-t border-bd">
        <div className="flex items-center justify-between mb-1.5">
          <label
            htmlFor="interaction-mode-select"
            className="font-mono text-xs uppercase tracking-wider text-tx font-semibold"
          >
            02. Interaction Mode (arena.v2)
          </label>
          <span className="font-mono text-[11px] text-mut">ADMISSION PROTOCOL</span>
        </div>
        <p className="font-sans text-xs text-mut mb-2">
          Defines whether the adversarial campaign admits adaptive interactive turns or runs against a pre-sealed batch.
        </p>
        <select
          id="interaction-mode-select"
          value={formData.interaction_mode}
          onChange={(e) => onChange({ interaction_mode: e.target.value as 'INTERACTIVE' | 'SEALED_BATCH' })}
          className="w-full px-3 py-2 bg-s2 border border-bd rounded-[2px] font-mono text-sm text-tx focus:outline-none focus:border-cy focus:ring-1 focus:ring-cy transition-colors"
        >
          <option value="INTERACTIVE">INTERACTIVE (Adaptive multi-turn loop, per-turn commit &amp; shaped feedback)</option>
          <option value="SEALED_BATCH">SEALED_BATCH (Pre-frozen batch attack upload, complete feedback embargo)</option>
        </select>
      </div>

      {/* Query Budget Profile (MEM-003 §2a) */}
      <div className="pt-4 border-t border-bd">
        <div className="flex items-center justify-between mb-1.5">
          <label
            htmlFor="budget-profile-select"
            className="font-mono text-xs uppercase tracking-wider text-tx font-semibold"
          >
            03. Query &amp; Turn Budget Profile
          </label>
          <span className="font-mono text-[11px] text-mut">RATE GOVERNANCE</span>
        </div>
        <p className="font-sans text-xs text-mut mb-2">
          Enforces maximum admitted turns per red identity across all concurrent sessions.
        </p>
        <select
          id="budget-profile-select"
          value={formData.budget_profile_id}
          onChange={(e) => onChange({ budget_profile_id: e.target.value })}
          className="w-full px-3 py-2 bg-s2 border border-bd rounded-[2px] font-mono text-sm text-tx focus:outline-none focus:border-cy focus:ring-1 focus:ring-cy transition-colors"
        >
          <option value="DEMO_500_TURNS_BUDGET">DEMO_500_TURNS_BUDGET (Max 500 admitted turns per identity per run)</option>
          <option value="BENCHMARK_100_TURNS_BUDGET">BENCHMARK_100_TURNS_BUDGET (100 turns quota for focused evaluation)</option>
          <option value="STRESS_1000_TURNS_BUDGET">STRESS_1000_TURNS_BUDGET (Extended stress test quota)</option>
        </select>
      </div>
    </div>
  );
};

import React from 'react';
import type { SetupFormData, SetupFieldErrors } from '../types';
import { EpochBadge } from '../../../components/EpochBadge';
import { Server, Cpu, Database } from 'lucide-react';

interface Step1Props {
  formData: SetupFormData;
  errors: SetupFieldErrors;
  onChange: (updates: Partial<SetupFormData>) => void;
}

const REGISTERED_PROFILES = [
  {
    id: 'local-control-only-v1',
    name: 'Local Control Prototype',
    profileId: 'local-control-only-v1',
    type: 'REGISTERED BACKEND PROFILE',
    icon: Server,
    data: {
      domain: 'BAYORA-LOCAL-01',
      budget_profile_id: 'local-control-budget-v1',
      target_model: 'local-control-target-v1',
      inference_engine: 'local-control-engine',
      interaction_mode: 'INTERACTIVE' as const,
      defense_mode: 'INPUT' as const,
    },
  },
  {
    id: 'qwen25-05b-cpu-component-v1',
    name: 'Qwen 2.5 0.5B CPU Component',
    profileId: 'qwen25-05b-cpu-component-v1',
    type: 'REGISTERED BACKEND PROFILE',
    icon: Cpu,
    data: {
      domain: 'QWEN25-COMPONENT-01',
      budget_profile_id: 'DEMO_500_TURNS_BUDGET',
      target_model: 'qwen2.5-0.5b-instruct',
      inference_engine: 'cpu-component-v1',
      interaction_mode: 'INTERACTIVE' as const,
      defense_mode: 'INPUT' as const,
    },
  },
  {
    id: 'BAYORA-PILOT-01',
    name: 'Bayora Pilot Mock Template',
    profileId: 'BAYORA-PILOT-01',
    type: 'SIMULATED TEMPLATE',
    icon: Database,
    data: {
      domain: 'BAYORA-PILOT-01',
      budget_profile_id: 'DEMO_500_TURNS_BUDGET',
      target_model: 'llama-3-8b-instruct-q4',
      inference_engine: 'vllm-v0.6.2',
      interaction_mode: 'INTERACTIVE' as const,
      defense_mode: 'INPUT' as const,
    },
  },
];

export const Step1DomainEpoch: React.FC<Step1Props> = ({
  formData,
  errors,
  onChange,
}) => {
  return (
    <div className="space-y-6">
      {/* Registered Backend Profile Presets */}
      <div>
        <span className="block font-mono text-xs uppercase tracking-wider text-tx font-semibold mb-1.5">
          Select Target Profile Preset
        </span>
        <p className="font-sans text-xs text-mut mb-3">
          Populate configuration with registered backend transport profiles or simulated templates.
        </p>
        <div className="grid grid-cols-1 gap-2">
          {REGISTERED_PROFILES.map((prof) => {
            const Icon = prof.icon;
            const isSelected = formData.domain === prof.data.domain;
            return (
              <button
                key={prof.id}
                type="button"
                onClick={() => onChange(prof.data)}
                className={`flex items-start gap-3 p-2.5 text-left rounded-[2px] border transition-all ${
                  isSelected
                    ? 'border-cy bg-cy/10 text-tx'
                    : 'border-bd bg-s2/60 text-tx/80 hover:border-mut'
                }`}
              >
                <Icon className={`w-4 h-4 mt-0.5 shrink-0 ${isSelected ? 'text-cy' : 'text-mut'}`} />
                <div className="flex-1 min-w-0">
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-mono text-xs font-bold text-tx truncate">
                      {prof.name}
                    </span>
                    <span className={`font-mono text-[9px] px-1.5 py-0.5 rounded-[2px] ${
                      prof.type === 'REGISTERED BACKEND PROFILE'
                        ? 'bg-cy/20 text-cy border border-cy/40'
                        : 'bg-dim/30 text-dim border border-bd'
                    }`}>
                      {prof.type}
                    </span>
                  </div>
                  <div className="font-mono text-[10px] text-mut truncate mt-0.5">
                    profile_id: {prof.profileId}
                  </div>
                </div>
              </button>
            );
          })}
        </div>
      </div>

      <div className="pt-4 border-t border-bd">
        <div className="flex items-center justify-between mb-1.5">
          <label
            htmlFor="domain-input"
            className="font-mono text-xs uppercase tracking-wider text-tx font-semibold"
          >
            01. Arena Domain Identifier
          </label>
          <span className="font-mono text-[11px] text-mut">REQUIRED</span>
        </div>
        <p className="font-sans text-xs text-mut mb-2">
          Unique tenant evaluation namespace. Must be uppercase alphanumeric with hyphens.
        </p>
        <input
          id="domain-input"
          type="text"
          value={formData.domain}
          onChange={(e) => onChange({ domain: e.target.value.toUpperCase() })}
          placeholder="BAYORA-PILOT-01"
          aria-invalid={!!errors.domain}
          aria-describedby={errors.domain ? 'domain-error' : undefined}
          className="w-full px-3 py-2 bg-s2 border border-bd rounded-[2px] font-mono text-sm text-tx placeholder-dim focus:outline-none focus:border-cy focus:ring-1 focus:ring-cy transition-colors"
        />
        {errors.domain && (
          <p id="domain-error" className="font-mono text-xs text-bad mt-1.5 flex items-center gap-1">
            <span>⚠</span> {errors.domain}
          </p>
        )}
      </div>

      <div className="pt-4 border-t border-bd">
        <div className="flex items-center justify-between mb-1.5">
          <label
            htmlFor="epoch-input"
            className="font-mono text-xs uppercase tracking-wider text-tx font-semibold"
          >
            02. Evaluation Epoch
          </label>
          {typeof formData.epoch === 'number' && Number.isInteger(formData.epoch) && formData.epoch > 0 && (
            <EpochBadge epoch={formData.epoch} />
          )}
        </div>
        <p className="font-sans text-xs text-mut mb-2">
          Exact positive integer (Invariant 5). Floating-point numbers, strings, and zero are strictly rejected.
        </p>
        <input
          id="epoch-input"
          type="number"
          step="1"
          min="1"
          value={formData.epoch}
          onChange={(e) => {
            const val = e.target.value;
            // Parse as number if numeric, otherwise retain raw input string for validation feedback
            const parsed = val === '' ? '' : Number(val);
            onChange({ epoch: parsed });
          }}
          placeholder="1"
          aria-invalid={!!errors.epoch}
          aria-describedby={errors.epoch ? 'epoch-error' : undefined}
          className="w-full px-3 py-2 bg-s2 border border-bd rounded-[2px] font-mono text-sm text-tx placeholder-dim focus:outline-none focus:border-cy focus:ring-1 focus:ring-cy transition-colors"
        />
        {errors.epoch && (
          <p id="epoch-error" className="font-mono text-xs text-bad mt-1.5 flex items-center gap-1">
            <span>⚠</span> {errors.epoch}
          </p>
        )}
      </div>
    </div>
  );
};

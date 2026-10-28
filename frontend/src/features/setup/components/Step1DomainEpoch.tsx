import React from 'react';
import type { SetupFormData, SetupFieldErrors } from '../types';
import { EpochBadge } from '../../../components/EpochBadge';

interface Step1Props {
  formData: SetupFormData;
  errors: SetupFieldErrors;
  onChange: (updates: Partial<SetupFormData>) => void;
}

export const Step1DomainEpoch: React.FC<Step1Props> = ({
  formData,
  errors,
  onChange,
}) => {
  return (
    <div className="space-y-6">
      <div>
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

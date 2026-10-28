import React from 'react';
import type { SetupFormData, SetupFieldErrors } from '../types';
import { cn } from '../../../lib/cn';

interface Step4Props {
  formData: SetupFormData;
  errors: SetupFieldErrors;
  onChange: (updates: Partial<SetupFormData>) => void;
}

export const Step4RedConstraints: React.FC<Step4Props> = ({
  formData,
  errors,
  onChange,
}) => {
  return (
    <div className="space-y-6">
      {/* Red Submission Limits */}
      <div>
        <div className="flex items-center justify-between mb-1.5">
          <span className="font-mono text-xs uppercase tracking-wider text-tx font-semibold">
            01. Red Team Submission Ingestion Limits
          </span>
          <span className="font-mono text-[11px] text-mut">BOUNDED BUFFERS</span>
        </div>
        <p className="font-sans text-xs text-mut mb-3">
          Strict payload memory and queue constraints enforced at Broker gateway.
        </p>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          {/* Body Max Bytes */}
          <div>
            <div className="flex items-center justify-between mb-1">
              <label htmlFor="body-bytes-input" className="font-mono text-[11px] text-mut uppercase">
                Max Body Bytes
              </label>
              <span className="font-mono text-[10px] text-cy bg-cy/10 border border-cy/30 px-1.5 py-0.5 rounded uppercase tracking-wider">TARGET</span>
            </div>
            <div className="relative">
              <input
                id="body-bytes-input"
                type="number"
                min="1024"
                step="1024"
                value={formData.body_max_bytes}
                onChange={(e) => onChange({ body_max_bytes: Number(e.target.value) })}
                className="w-full px-3 py-2 bg-s2 border border-bd rounded-[2px] font-mono text-xs text-tx focus:outline-none focus:border-cy focus:ring-1 focus:ring-cy transition-colors"
              />
              <span className="absolute right-2.5 top-2.5 font-mono text-[10px] text-dim">B</span>
            </div>
            {errors.body_max_bytes && (
              <p className="font-mono text-[10px] text-bad mt-1">⚠ {errors.body_max_bytes}</p>
            )}
          </div>

          {/* Text Max Bytes */}
          <div>
            <div className="flex items-center justify-between mb-1">
              <label htmlFor="text-bytes-input" className="font-mono text-[11px] text-mut uppercase">
                Max Text Bytes
              </label>
              <span className="font-mono text-[10px] text-cy bg-cy/10 border border-cy/30 px-1.5 py-0.5 rounded uppercase tracking-wider">TARGET</span>
            </div>
            <div className="relative">
              <input
                id="text-bytes-input"
                type="number"
                min="1024"
                step="1024"
                value={formData.text_max_bytes}
                onChange={(e) => onChange({ text_max_bytes: Number(e.target.value) })}
                className="w-full px-3 py-2 bg-s2 border border-bd rounded-[2px] font-mono text-xs text-tx focus:outline-none focus:border-cy focus:ring-1 focus:ring-cy transition-colors"
              />
              <span className="absolute right-2.5 top-2.5 font-mono text-[10px] text-dim">B</span>
            </div>
            {errors.text_max_bytes && (
              <p className="font-mono text-[10px] text-bad mt-1">⚠ {errors.text_max_bytes}</p>
            )}
          </div>

          {/* Queue Depth */}
          <div>
            <div className="flex items-center justify-between mb-1">
              <label htmlFor="queue-depth-input" className="font-mono text-[11px] text-mut uppercase">
                Queue Depth
              </label>
              <span className="font-mono text-[10px] text-cy bg-cy/10 border border-cy/30 px-1.5 py-0.5 rounded uppercase tracking-wider">TARGET</span>
            </div>
            <div className="relative">
              <input
                id="queue-depth-input"
                type="number"
                min="1"
                max="32"
                step="1"
                value={formData.queue_depth}
                onChange={(e) => onChange({ queue_depth: Number(e.target.value) })}
                className="w-full px-3 py-2 bg-s2 border border-bd rounded-[2px] font-mono text-xs text-tx focus:outline-none focus:border-cy focus:ring-1 focus:ring-cy transition-colors"
              />
              <span className="absolute right-2.5 top-2.5 font-mono text-[10px] text-dim">slots</span>
            </div>
            {errors.queue_depth && (
              <p className="font-mono text-[10px] text-bad mt-1">⚠ {errors.queue_depth}</p>
            )}
          </div>
        </div>
      </div>

      {/* Assurance Lane Selection */}
      <div className="pt-4 border-t border-bd">
        <div className="flex items-center justify-between mb-1.5">
          <span className="font-mono text-xs uppercase tracking-wider text-tx font-semibold">
            02. Infrastructure Assurance Lane
          </span>
          <span className="font-mono text-[11px] text-mut">Q-005 BOUNDARIES</span>
        </div>
        <p className="font-sans text-xs text-mut mb-3">
          Select deployment architecture. Each lane carries a clear claim limitation.
        </p>

        <div className="space-y-3" role="radiogroup" aria-label="Assurance Lane">
          {/* Shared-host option */}
          <div
            role="radio"
            aria-checked={formData.assurance_lane === 'shared_host_gvisor'}
            tabIndex={0}
            onClick={() => onChange({ assurance_lane: 'shared_host_gvisor' })}
            onKeyDown={(e) => {
              if (e.key === ' ' || e.key === 'Enter') {
                e.preventDefault();
                onChange({ assurance_lane: 'shared_host_gvisor' });
              }
            }}
            className={cn(
              'p-3.5 border rounded-[2px] cursor-pointer transition-colors focus:outline-none focus:ring-1 focus:ring-cy',
              formData.assurance_lane === 'shared_host_gvisor'
                ? 'bg-cy/5 border-cy'
                : 'bg-s2 border-bd hover:border-bd-strong'
            )}
          >
            <div className="flex items-center justify-between mb-1">
              <span className="font-mono text-xs font-semibold uppercase text-tx">
                Shared-host (gVisor cells)
              </span>
              <span className="font-mono text-[10px] text-mut uppercase px-1.5 py-0.5 bg-s1 border border-bd rounded-[2px]">
                ptrace / kvm
              </span>
            </div>
            <p className="font-sans text-xs text-mut mb-2">
              All tenants run on a single host partitioned into user-space kernel gVisor cells with cgroup v2 boundaries.
            </p>
            <div className="p-2 bg-s1/60 border border-bd rounded-[2px] font-mono text-[11px] text-mut">
              <span className="text-cy font-bold mr-1">CLAIM LIMIT:</span>
              Shared-host bounds process isolation via gVisor ptrace/KVM sandbox; covert side-channel bounding requires physical host separation.
            </div>
          </div>

          {/* Separated-host option */}
          <div
            role="radio"
            aria-checked={formData.assurance_lane === 'separated_host'}
            tabIndex={0}
            onClick={() => onChange({ assurance_lane: 'separated_host' })}
            onKeyDown={(e) => {
              if (e.key === ' ' || e.key === 'Enter') {
                e.preventDefault();
                onChange({ assurance_lane: 'separated_host' });
              }
            }}
            className={cn(
              'p-3.5 border rounded-[2px] cursor-pointer transition-colors focus:outline-none focus:ring-1 focus:ring-cy',
              formData.assurance_lane === 'separated_host'
                ? 'bg-cy/5 border-cy'
                : 'bg-s2 border-bd hover:border-bd-strong'
            )}
          >
            <div className="flex items-center justify-between mb-1">
              <span className="font-mono text-xs font-semibold uppercase text-tx">
                Separated-host (Bare-Metal Nodes)
              </span>
              <span className="font-mono text-[10px] text-mut uppercase px-1.5 py-0.5 bg-s1 border border-bd rounded-[2px]">
                hardware isolated
              </span>
            </div>
            <p className="font-sans text-xs text-mut mb-2">
              Physical node isolation across Red submission gateway, Blue defense, Target inference host, and Broker.
            </p>
            <div className="p-2 bg-s1/60 border border-bd rounded-[2px] font-mono text-[11px] text-mut">
              <span className="text-cy font-bold mr-1">CLAIM LIMIT:</span>
              Separated-host enforces physical hardware isolation across red, blue, and target inference lanes; covert timing channels bounded by hardware bus separation.
            </div>
          </div>
        </div>
      </div>

      {/* Dataset Catalog Selection (MEM-004 §11) */}
      <div className="pt-4 border-t border-bd">
        <div className="flex items-center justify-between mb-1.5">
          <label
            htmlFor="dataset-catalog-select"
            className="font-mono text-xs uppercase tracking-wider text-tx font-semibold"
          >
            03. Pre-Sealed Dataset Catalog & Adversarial Corpus
          </label>
          <span className="font-mono text-[11px] text-mut">ENCRYPTED CORPUS</span>
        </div>
        <p className="font-sans text-xs text-mut mb-2">
          Frozen public benchmark or synthetic canary corpus prepared with cryptographic lineage.
        </p>
        <select
          id="dataset-catalog-select"
          value={formData.dataset_catalog_id}
          onChange={(e) => onChange({ dataset_catalog_id: e.target.value })}
          className="w-full px-3 py-2 bg-s2 border border-bd rounded-[2px] font-mono text-sm text-tx focus:outline-none focus:border-cy focus:ring-1 focus:ring-cy transition-colors"
        >
          <option value="JBB_HARMFUL_BENIGN_V1">JBB_HARMFUL_BENIGN_V1 (JailbreakBench 100 balanced harmful/benign prompts)</option>
          <option value="GANDALF_IGNORE_INSTRUCTIONS_V1">GANDALF_IGNORE_INSTRUCTIONS_V1 (Lakera Gandalf prompt injection stress subset)</option>
          <option value="SYNTHETIC_CANARY_V1">SYNTHETIC_CANARY_V1 (Controlled canary leak testing profile)</option>
        </select>
      </div>
    </div>
  );
};

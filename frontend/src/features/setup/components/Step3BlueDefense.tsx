import React from 'react';
import { Lock } from 'lucide-react';
import type { SetupFormData, SetupFieldErrors } from '../types';

interface Step3Props {
  formData: SetupFormData;
  errors: SetupFieldErrors;
  onChange: (updates: Partial<SetupFormData>) => void;
}

export const Step3BlueDefense: React.FC<Step3Props> = ({
  formData,
  errors,
  onChange,
}) => {
  return (
    <div className="space-y-6">
      {/* Blue Defense Image Digest */}
      <div>
        <div className="flex items-center justify-between mb-1.5">
          <label
            htmlFor="defense-digest-input"
            className="font-mono text-xs uppercase tracking-wider text-tx font-semibold"
          >
            01. Defense Image Digest (OCI Container)
          </label>
          <span className="font-mono text-[11px] text-mut">CRYPTOGRAPHIC HASH</span>
        </div>
        <p className="font-sans text-xs text-mut mb-2">
          Immutable SHA-256 digest of the Blue team defense container image. Must follow pattern <code className="font-mono text-cy">sha256:&lt;64 hex chars&gt;</code>.
        </p>
        <input
          id="defense-digest-input"
          type="text"
          value={formData.defense_image_digest}
          onChange={(e) => onChange({ defense_image_digest: e.target.value.toLowerCase().trim() })}
          placeholder="sha256:7f3a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
          aria-invalid={!!errors.defense_image_digest}
          aria-describedby={errors.defense_image_digest ? 'defense-digest-error' : undefined}
          className="w-full px-3 py-2 bg-s2 border border-bd rounded-[2px] font-mono text-xs text-tx placeholder-dim focus:outline-none focus:border-cy focus:ring-1 focus:ring-cy transition-colors"
        />
        {errors.defense_image_digest && (
          <p id="defense-digest-error" className="font-mono text-xs text-bad mt-1.5 flex items-center gap-1">
            <span>⚠</span> {errors.defense_image_digest}
          </p>
        )}
      </div>

      {/* Defense Execution Deadline */}
      <div className="pt-4 border-t border-bd">
        <div className="flex items-center justify-between mb-1.5">
          <label
            htmlFor="defense-deadline-input"
            className="font-mono text-xs uppercase tracking-wider text-tx font-semibold"
          >
            02. Defense Processing Deadline
          </label>
          <span className="font-mono text-[10px] text-cy bg-cy/10 border border-cy/30 px-1.5 py-0.5 rounded uppercase tracking-wider">TARGET DEFAULT</span>
        </div>
        <p className="font-sans text-xs text-mut mb-2">
          Maximum time allowed for Blue guardrail inspection before attempt is invalidated.
        </p>
        <div className="relative max-w-xs">
          <input
            id="defense-deadline-input"
            type="number"
            min="100"
            max="10000"
            step="100"
            value={formData.defense_deadline_ms}
            onChange={(e) => onChange({ defense_deadline_ms: Number(e.target.value) })}
            className="w-full px-3 py-2 bg-s2 border border-bd rounded-[2px] font-mono text-sm text-tx focus:outline-none focus:border-cy focus:ring-1 focus:ring-cy transition-colors"
          />
          <span className="absolute right-3 top-2.5 font-mono text-xs text-dim">ms</span>
        </div>
        {errors.defense_deadline_ms && (
          <p className="font-mono text-xs text-bad mt-1.5">⚠ {errors.defense_deadline_ms}</p>
        )}
      </div>

      {/* Blue Defense Mode (MEM-003 §2a, §24) */}
      <div className="pt-4 border-t border-bd">
        <div className="flex items-center justify-between mb-1.5">
          <label
            htmlFor="defense-mode-select"
            className="font-mono text-xs uppercase tracking-wider text-tx font-semibold"
          >
            03. Defense Mode & Inspection Surface
          </label>
          <span className="font-mono text-[11px] text-mut">arena.v2</span>
        </div>
        <p className="font-sans text-xs text-mut mb-2">
          Defines the content boundary exposed to untrusted defense code. Each mode carries distinct guarantees.
        </p>
        <select
          id="defense-mode-select"
          value={formData.defense_mode}
          onChange={(e) => onChange({ defense_mode: e.target.value as 'INPUT' | 'FEATURES' | 'OUTPUT' | 'POST_HOC' })}
          className="w-full px-3 py-2 bg-s2 border border-bd rounded-[2px] font-mono text-sm text-tx focus:outline-none focus:border-cy focus:ring-1 focus:ring-cy transition-colors"
        >
          <option value="INPUT">INPUT (Default: In-flight prompt inspection; supports ALLOW, BLOCK, SANITIZE)</option>
          <option value="FEATURES">FEATURES (Metadata only: length bucket & control markers; prompt text withheld)</option>
          <option value="OUTPUT">OUTPUT (Target response inspection; target runs first; response blocking)</option>
          <option value="POST_HOC">POST_HOC (Post-release forensic audit; no in-run blocking guarantee)</option>
        </select>
      </div>

      {/* Prefix-Cache Salt - Strictly Server-Assigned Secret (Forbidden to edit) */}
      <div className="pt-4 border-t border-bd">
        <div className="flex items-center justify-between mb-1.5">
          <span className="font-mono text-xs uppercase tracking-wider text-tx font-semibold flex items-center gap-1.5">
            <Lock className="w-3.5 h-3.5 text-mut" />
            <span>04. Prefix-Cache Isolation Salt</span>
          </span>
          <span className="font-mono text-[10px] text-mut uppercase px-1.5 py-0.5 bg-s2 border border-bd rounded-[2px]">
            EMBARGOED
          </span>
        </div>
        <p className="font-sans text-xs text-mut mb-2">
          The prefix-cache salt is generated and managed exclusively by the trusted Broker inside the secure boundary to prevent side-channel probing. It is strictly never editable and never disclosed in client manifests.
        </p>
        <div className="w-full px-3 py-2.5 bg-s1 border border-bd rounded-[2px] font-mono text-xs text-dim flex items-center justify-between select-none">
          <span className="font-mono tracking-wider italic text-dim">
            server-assigned secret [embargoed]
          </span>
          <span className="font-mono text-[10px] text-cy font-bold uppercase tracking-wider flex items-center gap-1">
            <Lock className="w-3 h-3" />
            LOCKED · SERVER SECRET
          </span>
        </div>
      </div>
    </div>
  );
};

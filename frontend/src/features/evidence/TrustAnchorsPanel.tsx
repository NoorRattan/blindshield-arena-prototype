import React from 'react';
import { ShieldCheck, ShieldAlert, Key, Hash, Clock, AlertTriangle } from 'lucide-react';
import { Panel } from '../../components/Panel';
import { DEMO_KEYS } from '../../lib/crypto';
import type { Digest } from '../../lib/schemas';
import type { VerificationTrustAnchors } from './types';

interface TrustAnchorsPanelProps {
  anchors: VerificationTrustAnchors;
  onChange: (updated: VerificationTrustAnchors) => void;
  bundleKeyHex?: string;
  className?: string;
}

export const TrustAnchorsPanel: React.FC<TrustAnchorsPanelProps> = ({
  anchors,
  onChange,
  bundleKeyHex,
  className,
}) => {
  const handleKeyModeChange = (mode: 'pinned' | 'bundle' | 'custom') => {
    if (mode === 'pinned') {
      onChange({
        ...anchors,
        publicKeyHex: DEMO_KEYS.PUBLIC_KEY_HEX,
        isPinned: true,
      });
    } else if (mode === 'bundle') {
      onChange({
        ...anchors,
        publicKeyHex: bundleKeyHex || DEMO_KEYS.PUBLIC_KEY_HEX,
        isPinned: false, // Invariant 6: Bundle key is unpinned and UNTRUSTED
      });
    }
  };

  const handleEpochChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const val = parseInt(e.target.value, 10);
    if (!isNaN(val) && val > 0) {
      onChange({ ...anchors, expectedEpoch: val });
    }
  };

  return (
    <Panel
      label="01 — TRUST ANCHORS & BOUNDARIES"
      meta="SPEC §5.8 · INVARIANT 6"
      className={className}
    >
      <div className="space-y-4 text-xs font-mono">
        {/* Anchor Mode Selector */}
        <div>
          <label className="block text-[11px] uppercase tracking-wider text-mut mb-1.5 flex items-center justify-between">
            <span className="flex items-center gap-1.5">
              <Key size={13} className="text-cy" />
              Public Key Trust Anchor Source
            </span>
            {anchors.isPinned ? (
              <span className="inline-flex items-center gap-1 text-[10px] text-ok px-1.5 py-0.5 rounded-[2px] bg-s2 border border-ok/30">
                <ShieldCheck size={11} />
                EXTERNALLY PINNED
              </span>
            ) : (
              <span className="inline-flex items-center gap-1 text-[10px] text-am px-1.5 py-0.5 rounded-[2px] bg-s2 border border-am/30">
                <ShieldAlert size={11} />
                UNTRUSTED (BUNDLE KEY)
              </span>
            )}
          </label>

          <div
            className="grid grid-cols-2 gap-2"
            role="radiogroup"
            aria-label="Public Key Trust Anchor Source"
          >
            <button
              type="button"
              role="radio"
              aria-checked={anchors.isPinned}
              onClick={() => handleKeyModeChange('pinned')}
              className={`p-2 rounded-[2px] border text-left transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cy ${
                anchors.isPinned
                  ? 'bg-s2 border-cy text-tx'
                  : 'bg-s1 border-bd text-mut hover:border-bd-strong'
              }`}
            >
              <div className="font-semibold text-[11px] text-tx flex items-center gap-1">
                <span className={`w-1.5 h-1.5 rounded-full ${anchors.isPinned ? 'bg-cy' : 'bg-dim'}`} />
                Pinned Anchor
              </div>
              <div className="text-[10px] text-mut truncate mt-0.5">ed25519:witness-key-01</div>
            </button>

            <button
              type="button"
              role="radio"
              aria-checked={!anchors.isPinned}
              onClick={() => handleKeyModeChange('bundle')}
              className={`p-2 rounded-[2px] border text-left transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cy ${
                !anchors.isPinned
                  ? 'bg-s2 border-am text-tx'
                  : 'bg-s1 border-bd text-mut hover:border-bd-strong'
              }`}
            >
              <div className="font-semibold text-[11px] text-tx flex items-center gap-1">
                <span className={`w-1.5 h-1.5 rounded-full ${!anchors.isPinned ? 'bg-am' : 'bg-dim'}`} />
                Bundle Key (Unpinned)
              </div>
              <div className="text-[10px] text-am truncate mt-0.5">UNTRUSTED per C-03</div>
            </button>
          </div>

          {!anchors.isPinned && (
            <div className="mt-2 p-2 bg-s2/70 border border-am/40 rounded-[2px] text-[11px] text-am flex items-start gap-1.5">
              <AlertTriangle size={13} className="shrink-0 mt-0.5 text-am" />
              <span>
                Invariant 6 & Spec C-03 violation: Key bundled with evidence cannot authenticate itself. Verification verdict will be rejected with <code className="text-tx font-bold">UNTRUSTED_KEY</code>.
              </span>
            </div>
          )}
        </div>

        {/* Public Key Hex */}
        <div>
          <label htmlFor="pubkey-input" className="block text-[11px] uppercase tracking-wider text-mut mb-1">
            Ed25519 Public Key (Hex 64-char)
          </label>
          <input
            id="pubkey-input"
            type="text"
            value={anchors.publicKeyHex}
            onChange={(e) => onChange({ ...anchors, publicKeyHex: e.target.value.trim() })}
            className="w-full bg-s2 border border-bd rounded-[2px] px-2.5 py-1.5 text-xs text-tx font-mono focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cy select-all"
            spellCheck={false}
          />
        </div>

        {/* Expected Run Context Grid */}
        <div className="grid grid-cols-2 gap-2 pt-1 border-t border-bd/60">
          <div>
            <label htmlFor="domain-input" className="block text-[11px] uppercase tracking-wider text-mut mb-1 flex items-center gap-1">
              <Hash size={11} className="text-cy" />
              Expected Domain
            </label>
            <input
              id="domain-input"
              type="text"
              value={anchors.expectedDomain}
              onChange={(e) => onChange({ ...anchors, expectedDomain: e.target.value.trim() })}
              className="w-full bg-s2 border border-bd rounded-[2px] px-2 py-1 text-xs text-tx font-mono focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cy"
            />
          </div>

          <div>
            <label htmlFor="experiment-input" className="block text-[11px] uppercase tracking-wider text-mut mb-1 flex items-center gap-1">
              <Hash size={11} className="text-cy" />
              Expected Experiment
            </label>
            <input
              id="experiment-input"
              type="text"
              value={anchors.expectedExperimentId}
              onChange={(e) => onChange({ ...anchors, expectedExperimentId: e.target.value.trim() })}
              className="w-full bg-s2 border border-bd rounded-[2px] px-2 py-1 text-xs text-tx font-mono focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cy"
            />
          </div>
        </div>

        <div className="grid grid-cols-2 gap-2">
          <div>
            <label htmlFor="epoch-input" className="block text-[11px] uppercase tracking-wider text-mut mb-1 flex items-center gap-1">
              <Clock size={11} className="text-cy" />
              Expected Epoch (Int &gt; 0)
            </label>
            <input
              id="epoch-input"
              type="number"
              min={1}
              step={1}
              value={anchors.expectedEpoch}
              onChange={handleEpochChange}
              className="w-full bg-s2 border border-bd rounded-[2px] px-2 py-1 text-xs text-tx font-mono tabular-nums focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cy"
            />
          </div>

          <div>
            <label htmlFor="receipt-input" className="block text-[11px] uppercase tracking-wider text-mut mb-1">
              Witnessed Receipt
            </label>
            <input
              id="receipt-input"
              type="text"
              value={anchors.witnessedTerminalCheckpointReceipt || ''}
              onChange={(e) =>
                onChange({
                  ...anchors,
                  witnessedTerminalCheckpointReceipt: e.target.value.trim(),
                })
              }
              placeholder="rcpt_..."
              className="w-full bg-s2 border border-bd rounded-[2px] px-2 py-1 text-xs text-tx font-mono focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cy"
            />
          </div>
        </div>

        {/* Expected Manifest Digest */}
        <div>
          <label htmlFor="manifest-input" className="block text-[11px] uppercase tracking-wider text-mut mb-1">
            Expected Manifest Digest (sha256)
          </label>
          <input
            id="manifest-input"
            type="text"
            value={anchors.expectedManifestDigest}
            onChange={(e) => onChange({ ...anchors, expectedManifestDigest: e.target.value.trim() as Digest })}
            className="w-full bg-s2 border border-bd rounded-[2px] px-2 py-1 text-[11px] text-tx font-mono select-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cy"
            spellCheck={false}
          />
        </div>
      </div>
    </Panel>
  );
};

import React from 'react';
import {
  AlertTriangle,
  RotateCcw,
  Zap,
  Trash2,
  Shuffle,
  Scissors,
  Repeat,
  FileCode2,
  Code2,
} from 'lucide-react';
import { Panel } from '../../components/Panel';
import type { TamperType } from './types';

interface TamperPlaygroundPanelProps {
  onApplyTamper: (type: TamperType) => void;
  onResetTamper: () => void;
  activeTamper: {
    type: TamperType;
    description: string;
    expectedFailureCode: string;
    expectedFailingSeq?: number;
  } | null;
  className?: string;
}

export const TamperPlaygroundPanel: React.FC<TamperPlaygroundPanelProps> = ({
  onApplyTamper,
  onResetTamper,
  activeTamper,
  className,
}) => {
  const tamperButtons: Array<{
    type: TamperType;
    label: string;
    description: string;
    icon: React.ReactNode;
    color: string;
  }> = [
    {
      type: 'flip_byte',
      label: 'FLIP A BYTE',
      description: 'Mutates 1 character in event payload without updating chain hash',
      icon: <Zap size={13} />,
      color: 'hover:border-bad text-bad',
    },
    {
      type: 'delete_event',
      label: 'DELETE EVENT',
      description: 'Removes intermediate event from ledger (causes sequence gap)',
      icon: <Trash2 size={13} />,
      color: 'hover:border-bad text-bad',
    },
    {
      type: 'reorder_events',
      label: 'REORDER EVENTS',
      description: 'Swaps sequence positions of adjacent ledger blocks',
      icon: <Shuffle size={13} />,
      color: 'hover:border-am text-am',
    },
    {
      type: 'truncate_chain',
      label: 'TRUNCATE CHAIN',
      description: 'Drops trailing events before terminal checkpoint',
      icon: <Scissors size={13} />,
      color: 'hover:border-am text-am',
    },
    {
      type: 'replay_checkpoint',
      label: 'REPLAY CHECKPOINT',
      description: 'Substitutes genuinely signed checkpoint from another epoch (e99)',
      icon: <Repeat size={13} />,
      color: 'hover:border-inv text-inv',
    },
    {
      type: 'substitute_artifact',
      label: 'SUBSTITUTE ARTIFACT',
      description: 'Injects uncommitted foreign artifact hash into event',
      icon: <FileCode2 size={13} />,
      color: 'hover:border-bad text-bad',
    },
    {
      type: 'boolean_epoch',
      label: 'BOOLEAN EPOCH TRUE',
      description: 'Injects epoch: true into event (strictly rejected by Invariant 5)',
      icon: <Code2 size={13} />,
      color: 'hover:border-inv text-inv',
    },
  ];

  return (
    <Panel
      label="05 — CRYPTOGRAPHIC TAMPER PLAYGROUND"
      meta="MUTATION INJECTIONS"
      actions={
        activeTamper ? (
          <button
            type="button"
            data-testid="restore-untampered-btn"
            onClick={onResetTamper}
            className="px-2.5 py-1 rounded-[2px] bg-s2 border border-cy text-cy text-[11px] font-mono flex items-center gap-1 hover:bg-cy/10 transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-cy"
          >
            <RotateCcw size={11} />
            RESTORE UNTAMPERED
          </button>
        ) : undefined
      }
      className={className}
    >
      <div className="space-y-3 font-mono text-xs">
        <p className="text-mut text-xs leading-relaxed">
          Test the offline verifier&apos;s tamper resistance. Each button runs on an isolated copy of the evidence bundle, re-verifies the hash chain off-thread, and animates the rupture break in purple at the exact sequence number.
        </p>

        {/* Active Tamper Status Card */}
        {activeTamper && (
          <div className="p-3 rounded-[2px] bg-inv/10 border border-inv/40 text-tx space-y-1.5 animate-fadeIn">
            <div className="flex flex-wrap items-center justify-between gap-1.5">
              <span className="text-[11px] font-bold text-inv flex items-center gap-1.5">
                <AlertTriangle size={13} />
                ACTIVE INJECTION: {activeTamper.type.toUpperCase()}
              </span>
              <span className="text-[10px] text-mut uppercase">
                Expected Rejection: <code className="text-bad font-bold">{activeTamper.expectedFailureCode}</code>
                {activeTamper.expectedFailingSeq && ` at seq #${activeTamper.expectedFailingSeq}`}
              </span>
            </div>
            <div className="text-[11px] text-mut pt-1 border-t border-inv/20">{activeTamper.description}</div>
          </div>
        )}

        {/* Tamper Injection Buttons Grid */}
        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-2 pt-1">
          {tamperButtons.map((btn) => {
            const isActive = activeTamper?.type === btn.type;
            return (
              <button
                key={btn.type}
                type="button"
                onClick={() => onApplyTamper(btn.type)}
                className={`p-2.5 rounded-[2px] border text-left transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cy flex flex-col justify-between ${
                  isActive
                    ? 'bg-inv/20 border-inv text-tx ring-1 ring-inv'
                    : `bg-s2/60 border-bd ${btn.color}`
                }`}
              >
                <div>
                  <div className="flex items-center gap-1.5 font-bold text-[11px]">
                    {btn.icon}
                    <span>{btn.label}</span>
                  </div>
                  <div className="text-[10px] text-mut mt-1 leading-snug line-clamp-2">
                    {btn.description}
                  </div>
                </div>

                <div className="mt-2 text-[9px] text-dim uppercase tracking-wider flex items-center justify-between">
                  <span>Mutate copy</span>
                  <span>&rarr;</span>
                </div>
              </button>
            );
          })}
        </div>
      </div>
    </Panel>
  );
};

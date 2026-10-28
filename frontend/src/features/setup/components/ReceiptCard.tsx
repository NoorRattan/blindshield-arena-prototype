import React from 'react';
import { useNavigate } from 'react-router-dom';
import { CheckCircle2, ArrowRight, ShieldCheck, RotateCcw } from 'lucide-react';
import { Panel } from '../../../components/Panel';
import { Digest } from '../../../components/Digest';
import { EpochBadge } from '../../../components/EpochBadge';
import type { SetupReceipt } from '../types';

interface ReceiptCardProps {
  receipt: SetupReceipt;
  onReset: () => void;
}

export const ReceiptCard: React.FC<ReceiptCardProps> = ({ receipt, onReset }) => {
  const navigate = useNavigate();

  return (
    <Panel
      label="01 — EXPERIMENT SEALED · WITNESS RECEIPT"
      meta="DURABLE REGISTRATION RECEIPT"
      className="p-5"
    >
      <div className="space-y-6">
        {/* Success Header Strip */}
        <div className="p-4 bg-ok/10 border border-ok/40 rounded-[2px] flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-ok/20 rounded-[2px] text-ok">
              <CheckCircle2 className="w-6 h-6 stroke-[2]" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-mono text-xs uppercase tracking-wider font-bold text-ok">
                  EXPERIMENT SEALED & ATTESTED
                </span>
                <span className="font-mono text-[10px] text-ok bg-ok/20 px-1.5 py-0.5 rounded-[2px] uppercase">
                  {receipt.state}
                </span>
              </div>
              <p className="font-sans text-xs text-tx mt-0.5">
                Manifest recorded with witness authority. Epoch anchor immutable.
              </p>
            </div>
          </div>
          <EpochBadge epoch={receipt.epoch} />
        </div>

        {/* Receipt Properties Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 font-mono text-xs">
          <div className="p-3 bg-s2 border border-bd rounded-[2px]">
            <span className="text-mut text-[10px] uppercase tracking-wider block mb-1">
              Witness Receipt ID
            </span>
            <span className="text-cy font-semibold break-all select-all">
              {receipt.receipt_id}
            </span>
          </div>

          <div className="p-3 bg-s2 border border-bd rounded-[2px]">
            <span className="text-mut text-[10px] uppercase tracking-wider block mb-1">
              Assigned Experiment ID
            </span>
            <span className="text-tx font-semibold break-all select-all">
              {receipt.experiment_id}
            </span>
          </div>

          <div className="p-3 bg-s2 border border-bd rounded-[2px]">
            <span className="text-mut text-[10px] uppercase tracking-wider block mb-1">
              Sealed Manifest Digest
            </span>
            <Digest hash={receipt.manifest_digest} />
          </div>

          <div className="p-3 bg-s2 border border-bd rounded-[2px]">
            <span className="text-mut text-[10px] uppercase tracking-wider block mb-1">
              Attestation Timestamp (UTC)
            </span>
            <span className="text-tx tabular-nums">
              {receipt.timestamp_utc}
            </span>
          </div>
        </div>

        {/* Action Controls */}
        <div className="pt-4 border-t border-bd flex flex-wrap items-center justify-between gap-3">
          <button
            type="button"
            onClick={onReset}
            className="inline-flex items-center gap-1.5 px-4 py-2 bg-s2 border border-bd text-tx font-mono text-xs uppercase tracking-wider rounded-[2px] hover:border-cy transition-colors focus:outline-none focus:ring-1 focus:ring-cy"
          >
            <RotateCcw className="w-3.5 h-3.5 text-mut" />
            Configure Another Experiment
          </button>

          <div className="flex items-center gap-3">
            <button
              type="button"
              onClick={() => navigate('/overview')}
              className="inline-flex items-center gap-1.5 px-4 py-2 bg-s2 border border-bd text-tx font-mono text-xs uppercase tracking-wider rounded-[2px] hover:border-cy transition-colors focus:outline-none focus:ring-1 focus:ring-cy"
            >
              Arena Roster
            </button>

            <button
              type="button"
              onClick={() => navigate('/war-room')}
              className="inline-flex items-center gap-2 px-5 py-2 bg-cy text-[#080B10] font-mono text-xs uppercase tracking-wider font-bold rounded-[2px] hover:brightness-110 transition-colors focus:outline-none focus:ring-2 focus:ring-cy focus:ring-offset-2 focus:ring-offset-bg"
            >
              <ShieldCheck className="w-4 h-4 stroke-[2]" />
              Enter War Room
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </div>
    </Panel>
  );
};

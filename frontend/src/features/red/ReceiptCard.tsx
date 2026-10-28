import React from 'react';
import { CheckCircle2, ShieldCheck, Clock, Hash } from 'lucide-react';
import { Panel } from '../../components/Panel';
import { Digest } from '../../components/Digest';
import type { AttackReceipt } from '../../lib/schemas';

export interface ReceiptCardProps {
  receipt: AttackReceipt;
  onDismiss?: () => void;
}

export const ReceiptCard: React.FC<ReceiptCardProps> = ({ receipt, onDismiss }) => {
  return (
    <Panel
      label="02 — BROKER RECEIPT CONFIRMED"
      meta={`TURN ${receipt.turn} · RECORDED`}
      className="border-ok/40 bg-s1 shadow-sm"
    >
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="h-5 w-5 text-ok" aria-hidden="true" />
            <span className="font-mono text-xs font-semibold tracking-wider text-ok uppercase">
              PAYLOAD COMMITTED TO LEDGER
            </span>
          </div>
          {onDismiss && (
            <button
              type="button"
              onClick={onDismiss}
              className="font-mono text-xs text-mut hover:text-tx focus:ring-1 focus:ring-cy focus:outline-none"
            >
              [DISMISS]
            </button>
          )}
        </div>

        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <div className="rounded-[2px] border border-bd bg-s2 p-2.5">
            <div className="flex items-center gap-1.5 text-xs text-mut">
              <Hash className="h-3.5 w-3.5 text-cy" aria-hidden="true" />
              <span>RECEIPT IDENTIFIER</span>
            </div>
            <div className="mt-1 font-mono text-xs font-medium text-tx break-all">
              {receipt.receipt_id}
            </div>
          </div>

          <div className="rounded-[2px] border border-bd bg-s2 p-2.5">
            <div className="flex items-center gap-1.5 text-xs text-mut">
              <Clock className="h-3.5 w-3.5 text-cy" aria-hidden="true" />
              <span>RECORDED AT (UTC)</span>
            </div>
            <div className="mt-1 font-mono text-xs font-medium text-tx">
              {receipt.timestamp_utc}
            </div>
          </div>
        </div>

        <div className="rounded-[2px] border border-bd bg-s2 p-2.5">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-1.5 text-xs text-mut">
              <ShieldCheck className="h-3.5 w-3.5 text-ok" aria-hidden="true" />
              <span>RECORDED COMMITMENT DIGEST</span>
            </div>
            <span className="font-mono text-[11px] text-mut">DOMAIN-SEPARATED</span>
          </div>
          <div className="mt-1.5">
            <Digest hash={receipt.commitment_digest} />
          </div>
        </div>

        <div className="rounded-[2px] border border-bd bg-bg/60 p-2 text-[11px] text-mut">
          Receipt confirms durable ingestion into the broker audit ledger. Response outcome is
          evaluated asynchronously according to the experiment disclosure profile.
        </div>
      </div>
    </Panel>
  );
};

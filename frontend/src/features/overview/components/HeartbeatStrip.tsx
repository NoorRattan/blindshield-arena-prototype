import React, { useState } from 'react';
import { Panel } from '../../../components/Panel';
import { Digest } from '../../../components/Digest';
import { StatusPill } from '../../../components/StatusPill';
import type { WitnessCheckpointTick } from '../types';

interface HeartbeatStripProps {
  ticks: WitnessCheckpointTick[];
}

export const HeartbeatStrip: React.FC<HeartbeatStripProps> = ({ ticks }) => {
  const [selectedTick, setSelectedTick] = useState<WitnessCheckpointTick>(
    () => ticks[ticks.length - 1] ?? {
      watermark: 441,
      seq: 20,
      timestamp_utc: '2026-10-19T08:15:37Z',
      receipt: 'rcpt_8f4e2c1a',
      status: 'SYNCED',
      experiment_id: 'BAYORA-PROD-01',
    }
  );

  const handleKeyDown = (e: React.KeyboardEvent, index: number) => {
    if (e.key === 'ArrowRight' && index < ticks.length - 1) {
      e.preventDefault();
      setSelectedTick(ticks[index + 1]);
    } else if (e.key === 'ArrowLeft' && index > 0) {
      e.preventDefault();
      setSelectedTick(ticks[index - 1]);
    } else if (e.key === 'Home') {
      e.preventDefault();
      setSelectedTick(ticks[0]);
    } else if (e.key === 'End') {
      e.preventDefault();
      setSelectedTick(ticks[ticks.length - 1]);
    }
  };

  return (
    <Panel
      label="03 — WITNESS CONSENSUS HEARTBEAT"
      meta={`WATERMARK #${selectedTick.watermark} · 20 RECENT CHECKPOINTS`}
      className="w-full"
    >
      <div className="py-2">
        {/* Strip container */}
        <div
          role="region"
          aria-label="Recent 20 Witness Checkpoints Strip"
          className="w-full flex items-center justify-between gap-1.5 p-2 bg-s2 border border-bd rounded-[2px]"
        >
          {ticks.map((tick, idx) => {
            const isSelected = selectedTick.watermark === tick.watermark;
            const isLagging = tick.status === 'LAGGING';
            const isInvalid = tick.status === 'INVALID';

            let barColor = 'bg-ok/70 border-ok';
            if (isLagging) barColor = 'bg-am/70 border-am';
            if (isInvalid) barColor = 'bg-inv/70 border-inv';

            return (
              <button
                key={tick.watermark}
                type="button"
                tabIndex={0}
                aria-label={`Checkpoint watermark ${tick.watermark}, status ${tick.status}`}
                aria-pressed={isSelected}
                onClick={() => setSelectedTick(tick)}
                onKeyDown={(e) => handleKeyDown(e, idx)}
                className={`flex-1 h-8 rounded-[1px] border transition-all cursor-pointer focus:outline-none focus:ring-2 focus:ring-cy ${barColor} ${
                  isSelected ? 'ring-2 ring-cy scale-y-110 opacity-100 z-10' : 'opacity-80 hover:opacity-100'
                }`}
                title={`#${tick.watermark} [${tick.status}] ${tick.receipt}`}
              />
            );
          })}
        </div>

        {/* Selected tick inspector summary */}
        <div className="mt-3 pt-3 border-t border-bd flex flex-wrap items-center justify-between gap-3 text-xs font-mono">
          <div className="flex items-center gap-3">
            <span className="text-mut uppercase">SELECTED CHECKPOINT:</span>
            <span className="text-tx font-bold tracking-wider">#{selectedTick.watermark}</span>
            <span className="text-mut" aria-hidden="true">·</span>
            <span className="text-cy">{selectedTick.experiment_id}</span>
            <span className="text-mut" aria-hidden="true">·</span>
            <span className="text-mut">{new Date(selectedTick.timestamp_utc).toTimeString().split(' ')[0]} UTC</span>
          </div>

          <div className="flex items-center gap-3">
            <span className="text-mut uppercase">RECEIPT:</span>
            <Digest
              hash={`sha256:${selectedTick.receipt.padEnd(64, '0')}`}
              prefixLen={8}
              suffixLen={4}
            />
            <StatusPill status={selectedTick.status === 'SYNCED' ? 'VALID_WITHIN_PROFILE' : 'INVALID'} size="sm" />
          </div>
        </div>
      </div>
    </Panel>
  );
};

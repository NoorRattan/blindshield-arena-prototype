import React from 'react';
import { Lock, EyeOff } from 'lucide-react';
import { cn } from '../lib/cn';

export interface EmbargoMaskProps {
  label?: string;
  reason?: string;
  releasePhase?: string;
  epoch?: number;
  className?: string;
}

/**
 * EmbargoMask: Renders a placeholder block for absent, server-withheld data.
 * Invariant 3: Embargoed data is never transmitted to the client.
 * This component does NOT wrap secret content with CSS opacity or blur.
 * It is solely rendered when data is withheld by the backend role policy.
 */
export const EmbargoMask: React.FC<EmbargoMaskProps> = ({
  label = 'PAYLOAD EMBARGOED',
  reason = 'Server withheld under frozen feedback profile',
  releasePhase = 'POST-ROUND DURABLE CLOSE',
  epoch,
  className,
}) => {
  return (
    <div
      role="status"
      aria-label={`${label}: ${reason}`}
      className={cn(
        'border border-emb/40 bg-s2/50 rounded p-4 flex flex-col items-center justify-center text-center select-none font-mono',
        className
      )}
    >
      <div className="w-8 h-8 rounded border border-emb/40 bg-emb/10 flex items-center justify-center text-emb mb-2.5">
        <Lock className="w-4 h-4 stroke-[1.5]" />
      </div>

      <div className="flex items-center gap-1.5 text-xs text-tx font-bold uppercase tracking-wider mb-1">
        <EyeOff className="w-3.5 h-3.5 text-emb" />
        <span>{label}</span>
      </div>

      <p className="text-[11px] text-mut max-w-sm mb-2">{reason}</p>

      <div className="flex items-center gap-2 text-[10px] text-mut border-t border-bd/60 pt-2 w-full justify-center">
        <span>RELEASE CONDITION:</span>
        <span className="text-emb font-medium uppercase">{releasePhase}</span>
        {typeof epoch === 'number' && (
          <>
            <span>·</span>
            <span>EPOCH {String(epoch).padStart(2, '0')}</span>
          </>
        )}
      </div>
    </div>
  );
};

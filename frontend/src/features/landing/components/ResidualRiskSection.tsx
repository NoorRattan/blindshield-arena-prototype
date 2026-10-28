import React from 'react';
import { ResidualRiskPanel } from '../../../components/ResidualRiskPanel';

export const ResidualRiskSection: React.FC = () => {
  return (
    <section
      className="py-16 lg:py-20 border-b border-[var(--bd)]"
      aria-labelledby="claims-heading"
    >
      <div className="mb-10">
        <div className="flex items-center gap-2 mb-3">
          <span className="font-mono text-[12px] uppercase tracking-[0.14em] text-[var(--cy)] font-medium">
            04 — BOUNDARIES OF ASSURANCE (Q-005)
          </span>
        </div>
        <h2
          id="claims-heading"
          className="font-display text-[clamp(32px,5vw,60px)] leading-[0.96] text-[var(--tx)] uppercase"
        >
          What We Claim, and What We Don&apos;t
        </h2>
        <p className="text-[15px] sm:text-[16px] text-[var(--mut)] max-w-[64ch] mt-3">
          Every evaluation system has threat boundaries. We do not make generic claims.
          All claims are strictly bounded, measured under declared protocols, or explicitly
          designated as residual risk.
        </p>
      </div>

      <div className="w-full">
        <ResidualRiskPanel />
      </div>
    </section>
  );
};

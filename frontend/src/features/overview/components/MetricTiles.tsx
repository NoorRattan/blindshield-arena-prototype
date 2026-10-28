import React from 'react';
import { Panel } from '../../../components/Panel';
import { IllustrativeTag } from '../../../components/IllustrativeTag';
import { AnimatedCounter } from './AnimatedCounter';
import type { OverviewMetrics } from '../types';

interface MetricTilesProps {
  metrics: OverviewMetrics;
}

export const MetricTiles: React.FC<MetricTilesProps> = ({ metrics }) => {
  const {
    activeDomains,
    totalDomains,
    evaluationsRun,
    blockedCount,
    validCount,
    admittedCount,
    invalidCount,
    integrityPercentage,
    p95BrokerOverheadMs,
    targetBrokerOverheadMs,
  } = metrics;

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4" data-testid="metric-tiles">
      {/* 1. Active Domains */}
      <Panel
        label="01 / ACTIVE DOMAINS"
        meta={<IllustrativeTag />}
        className="h-full flex flex-col justify-between"
      >
        <div className="py-2">
          <div className="flex items-baseline gap-2">
            <span className="font-display font-tabular text-4xl sm:text-5xl leading-none text-tx">
              <AnimatedCounter value={activeDomains} />
            </span>
            <span className="font-mono text-xs uppercase tracking-wider text-mut">
              / {totalDomains} DOMAINS
            </span>
          </div>
          <div className="mt-3 pt-3 border-t border-bd font-mono text-xs text-mut flex items-center justify-between">
            <span>[1 LIVE · 1 SEALED]</span>
            <span className="text-cy uppercase tracking-wider font-semibold">1 ACTIVE NOW</span>
          </div>
        </div>
      </Panel>

      {/* 2. Evaluations Run */}
      <Panel
        label="02 / EVALUATIONS RUN"
        meta={<IllustrativeTag />}
        className="h-full flex flex-col justify-between"
      >
        <div className="py-2">
          <div className="flex items-baseline gap-2">
            <span className="font-display font-tabular text-4xl sm:text-5xl leading-none text-tx">
              <AnimatedCounter value={evaluationsRun} />
            </span>
            <span className="font-mono text-xs uppercase tracking-wider text-mut">
              ADMITTED
            </span>
          </div>
          <div className="mt-3 pt-3 border-t border-bd font-mono text-xs text-mut flex items-center justify-between">
            <span>DEFENSE INTERCEPTIONS:</span>
            <span className="text-am font-semibold">[{blockedCount} BLOCKED]</span>
          </div>
        </div>
      </Panel>

      {/* 3. Integrity Rate (Valid / Admitted, with denominator & invalid count) */}
      <Panel
        label="03 / INTEGRITY RATE"
        meta={<IllustrativeTag />}
        className="h-full flex flex-col justify-between"
      >
        <div className="py-2">
          <div className="flex items-baseline gap-2">
            <span className="font-display font-tabular text-3xl sm:text-4xl leading-none text-ok">
              {validCount} / {admittedCount}
            </span>
            <span className="font-mono text-xs font-semibold text-mut">
              (<AnimatedCounter value={integrityPercentage} decimals={1} suffix="%" />)
            </span>
          </div>
          <div className="mt-3 pt-3 border-t border-bd font-mono text-xs text-mut flex items-center justify-between">
            <span>FAILURES / INVALIDATED:</span>
            <span className="text-inv font-semibold">[{invalidCount} INVALIDATED]</span>
          </div>
        </div>
      </Panel>

      {/* 4. Broker Overhead P95 (TARGET <= 100ms) */}
      <Panel
        label="04 / P95 BROKER LATENCY"
        meta={<IllustrativeTag />}
        className="h-full flex flex-col justify-between"
      >
        <div className="py-2">
          <div className="flex items-baseline gap-2">
            <span className="font-display font-tabular text-4xl sm:text-5xl leading-none text-tx">
              <AnimatedCounter value={p95BrokerOverheadMs} decimals={1} suffix=" ms" />
            </span>
          </div>
          <div className="mt-2">
            {/* Visual threshold line */}
            <div className="w-full h-1.5 bg-s2 border border-bd rounded-[1px] overflow-hidden relative">
              <div
                className="h-full bg-cy"
                style={{ width: `${Math.min((p95BrokerOverheadMs / targetBrokerOverheadMs) * 100, 100)}%` }}
              />
            </div>
            <div className="mt-1.5 flex items-center justify-between font-mono text-[11px] text-mut">
              <span>TARGET ≤ {targetBrokerOverheadMs} ms</span>
              <span className="text-cy">{(p95BrokerOverheadMs).toFixed(1)} / {targetBrokerOverheadMs} ms</span>
            </div>
          </div>
        </div>
      </Panel>
    </div>
  );
};

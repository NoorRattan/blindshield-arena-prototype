import React from 'react';
import { Panel } from '../../components/Panel';
import { Gauge } from '../../components/Gauge';
import { IllustrativeTag } from '../../components/IllustrativeTag';
import { cn } from '../../lib/cn';
import { ShieldCheck, ShieldAlert, Cpu, Activity, Server, Radio, Lock, Zap } from 'lucide-react';
import type { FailureMode } from '../../lib/mock/sse';

export interface TelemetryGaugesProps {
  queueDepth?: number;
  maxQueue?: number;
  blueMemoryMb?: number;
  maxMemoryMb?: number;
  ttftMs?: number;
  tokensPerSec?: number;
  circuitBreakerViolations?: number;
  egressPacketsOut?: number;
  activeNetworkRules?: string;
  witnessWatermarkSeq?: number;
  witnessStatus?: 'SYNCED' | 'LAGGING' | 'OFFLINE';
  failureMode?: FailureMode;
  className?: string;
}

export const TelemetryGauges: React.FC<TelemetryGaugesProps> = ({
  queueDepth = 2,
  maxQueue = 4, // Protocol default: queue cap 4
  blueMemoryMb = 512,
  maxMemoryMb = 1024,
  ttftMs = 342,
  tokensPerSec = 28.4,
  circuitBreakerViolations = 0,
  egressPacketsOut = 0,
  activeNetworkRules = 'Default Deny (Enforced)',
  witnessWatermarkSeq = 1402,
  witnessStatus = 'SYNCED',
  failureMode = 'none',
  className,
}) => {
  const isWitnessLag = witnessStatus === 'LAGGING' || failureMode === 'witness_lag';
  const isRecorderDown = failureMode === 'recorder_down';

  return (
    <Panel
      label="02 — ATTRIBUTE TELEMETRY GAUGES"
      meta={
        <div className="flex items-center gap-2">
          <IllustrativeTag tooltip="Telemetry targets from protocol profile arena.v2" />
        </div>
      }
      className={cn('h-full flex flex-col justify-between', className)}
    >
      <div className="space-y-4 font-mono text-xs" role="region" aria-label="Attribute Telemetry Gauges">
        {/* 1. Broker Queue Depth */}
        <div>
          <div className="flex items-center justify-between text-mut text-[11px] mb-1">
            <span className="flex items-center gap-1.5 uppercase font-medium text-tx">
              <Server className="w-3.5 h-3.5 text-cy" />
              <span>Broker Queue Depth</span>
            </span>
            <span className="tabular-nums">
              <strong className="text-cy">{queueDepth}</strong> / {maxQueue} (CAP {maxQueue})
            </span>
          </div>
          <Gauge
            label=""
            value={queueDepth}
            min={0}
            max={maxQueue}
            unit=""
            variant="cy"
            className="mt-0"
          />
        </div>

        {/* 2. Blue Cell Memory Envelope */}
        <div>
          <div className="flex items-center justify-between text-mut text-[11px] mb-1">
            <span className="flex items-center gap-1.5 uppercase font-medium text-tx">
              <Cpu className="w-3.5 h-3.5 text-bl" />
              <span>Blue Cell Memory</span>
            </span>
            <span className="tabular-nums">
              <strong className="text-bl">{blueMemoryMb}</strong> MB / {maxMemoryMb} MB
            </span>
          </div>
          <Gauge
            label=""
            value={blueMemoryMb}
            min={0}
            max={maxMemoryMb}
            unit="MB"
            variant="bl"
            className="mt-0"
          />
        </div>

        {/* 3. Target Model Metrics: TTFT & Generation Speed */}
        <div className="grid grid-cols-2 gap-3 p-2.5 border border-bd bg-s2/40 rounded">
          <div>
            <div className="text-[10px] text-mut uppercase tracking-wider mb-0.5 flex items-center gap-1">
              <Zap className="w-3 h-3 text-am" />
              <span>Target TTFT</span>
            </div>
            <div className="text-sm font-bold text-tx tabular-nums">
              {ttftMs} <span className="text-[10px] text-mut font-normal">ms</span>
            </div>
            <div className="text-[10px] text-mut mt-0.5">TARGET ≤ 500ms</div>
          </div>

          <div>
            <div className="text-[10px] text-mut uppercase tracking-wider mb-0.5 flex items-center gap-1">
              <Activity className="w-3 h-3 text-ok" />
              <span>Generation Speed</span>
            </div>
            <div className="text-sm font-bold text-tx tabular-nums">
              {tokensPerSec} <span className="text-[10px] text-mut font-normal">tok/s</span>
            </div>
            <div className="text-[10px] text-mut mt-0.5">Llama-3-8B Q4</div>
          </div>
        </div>

        {/* 4. Host Security & Network Policy Rows */}
        <div className="space-y-2 pt-2 border-t border-bd/60 text-[11px]">
          {/* Circuit Breaker Status */}
          <div className="flex items-center justify-between py-1 px-2 border border-bd/60 bg-s2/30 rounded">
            <span className="text-mut flex items-center gap-1.5 uppercase">
              <Radio className="w-3.5 h-3.5 text-cy" />
              <span>Circuit Breaker</span>
            </span>
            <span className={cn('font-semibold uppercase tracking-wider', circuitBreakerViolations === 0 ? 'text-ok' : 'text-bad')}>
              {circuitBreakerViolations === 0 ? 'NOMINAL (0 VIOLATIONS)' : `${circuitBreakerViolations} BREACH DETECTED`}
            </span>
          </div>

          {/* Active Network Isolation Rules */}
          <div className="flex items-center justify-between py-1 px-2 border border-bd/60 bg-s2/30 rounded">
            <span className="text-mut flex items-center gap-1.5 uppercase">
              <Lock className="w-3.5 h-3.5 text-bl" />
              <span>Network Isolation</span>
            </span>
            <span className="text-tx font-medium uppercase tracking-wider">
              {activeNetworkRules}
            </span>
          </div>

          {/* Egress Probes */}
          <div className="flex items-center justify-between py-1 px-2 border border-bd/60 bg-s2/30 rounded">
            <span className="text-mut flex items-center gap-1.5 uppercase">
              <ShieldCheck className="w-3.5 h-3.5 text-ok" />
              <span>Egress Probes</span>
            </span>
            <span className={cn('tabular-nums font-medium', egressPacketsOut === 0 ? 'text-ok' : 'text-bad')}>
              {egressPacketsOut} PACKETS OUT
            </span>
          </div>

          {/* Witness Watermark */}
          <div
            className={cn(
              'flex items-center justify-between py-1 px-2 border rounded',
              isWitnessLag
                ? 'border-am/60 bg-am/10 text-am'
                : isRecorderDown
                  ? 'border-bad/60 bg-bad/10 text-bad'
                  : 'border-bd/60 bg-s2/30 text-tx'
            )}
          >
            <span className="text-mut flex items-center gap-1.5 uppercase">
              {isWitnessLag ? (
                <ShieldAlert className="w-3.5 h-3.5 text-am" />
              ) : (
                <ShieldCheck className="w-3.5 h-3.5 text-cy" />
              )}
              <span>Witness Watermark</span>
            </span>
            <span className="tabular-nums font-bold tracking-wider">
              #{witnessWatermarkSeq.toLocaleString()}{' '}
              <span className={isWitnessLag ? 'text-am' : isRecorderDown ? 'text-bad' : 'text-ok'}>
                ({isWitnessLag ? 'LAGGING' : isRecorderDown ? 'OFFLINE' : 'SYNCED'})
              </span>
            </span>
          </div>
        </div>
      </div>
    </Panel>
  );
};

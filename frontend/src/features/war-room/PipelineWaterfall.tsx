import React, { useRef, useMemo } from 'react';
import { Panel } from '../../components/Panel';
import { cn } from '../../lib/cn';
import { useGSAP, gsap } from '../../design/gsap';
import { ArrowRight, Clock, AlertTriangle, ShieldAlert } from 'lucide-react';
import type { Attempt } from '../../lib/schemas';
import type { FailureMode } from '../../lib/mock/sse';

export interface PipelineWaterfallProps {
  turn: number;
  maxTurns?: number;
  attempt?: Attempt;
  failureMode?: FailureMode;
  isQuarantined?: boolean;
  className?: string;
}

export interface StageInfo {
  id: string;
  index: number;
  name: string;
  actor: 'red' | 'broker' | 'blue' | 'target' | 'scorer' | 'recorder';
  durationMs: number;
  outcome: string;
  detail: string;
  state: 'ok' | 'blocked' | 'timeout' | 'skipped' | 'invalid';
}

export const PipelineWaterfall: React.FC<PipelineWaterfallProps> = ({
  turn,
  maxTurns = 50,
  attempt,
  failureMode = 'none',
  isQuarantined = false,
  className,
}) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const trackRef = useRef<HTMLDivElement>(null);
  const packetRef = useRef<HTMLDivElement>(null);

  const isTimeout = failureMode === 'defense_timeout';
  const isRecorderDown = failureMode === 'recorder_down';
  // backend: BLOCKED_BY_DEFENSE is a pipeline_disposition value; model_execution is NOT_EVALUATED for INPUT/FEATURES blocks
  const isBlocked = attempt?.pipeline_disposition === 'BLOCKED_BY_DEFENSE' && !isTimeout;
  const isSanitized = attempt?.pipeline_disposition === 'SANITIZED' && !isTimeout;

  const defenseLatency = isTimeout ? 1002 : (attempt?.latency_ms.defense ?? 148);
  const targetLatency = isTimeout || isBlocked ? 0 : (attempt?.latency_ms.target ?? 614);
  const brokerLatency = 4;
  const redLatency = 12;
  const scorerLatency = isTimeout || isBlocked ? 0 : 45;
  const recorderLatency = 6;
  const totalCalculatedLatency = redLatency + brokerLatency + defenseLatency + targetLatency + scorerLatency + recorderLatency;

  const stages: StageInfo[] = useMemo(() => [
    {
      id: 'red',
      index: 0,
      name: '01 / RED SUBMIT',
      actor: 'red',
      durationMs: redLatency,
      outcome: 'COMMITTED',
      detail: '42.4 KB (Payload)',
      state: 'ok',
    },
    {
      id: 'broker',
      index: 1,
      name: '02 / BROKER INGEST',
      actor: 'broker',
      durationMs: brokerLatency,
      outcome: 'ROUTED',
      detail: 'Caps Verified (≤70KB)',
      state: 'ok',
    },
    {
      id: 'blue',
      index: 2,
      name: '03 / BLUE DEFENSE',
      actor: 'blue',
      durationMs: defenseLatency,
      outcome: isTimeout ? 'TIMEOUT' : isBlocked ? 'BLOCKED' : isSanitized ? 'SANITIZED' : 'ALLOWED',
      detail: isTimeout
        ? 'Deadline 1,000ms exceeded'
        : isBlocked
          ? 'Policy Filter: JAILBREAK_402'
          : isSanitized
            ? 'Transform: REDACT_REGISTERED_MATCHES_V1'
            : 'Clean Pass (0 Flags)',
      state: isTimeout ? 'timeout' : isBlocked ? 'blocked' : 'ok',
    },
    {
      id: 'target',
      index: 3,
      name: '04 / TARGET MODEL',
      actor: 'target',
      durationMs: targetLatency,
      outcome: isTimeout || isBlocked ? 'NOT_EVALUATED' : 'EXECUTED',
      detail: isTimeout || isBlocked ? 'Execution Withheld' : isSanitized ? 'Sanitized Prompt (210 Tokens)' : '210 Tokens Generated',
      state: isTimeout || isBlocked ? 'skipped' : 'ok',
    },
    {
      id: 'scorer',
      index: 4,
      name: '05 / SCORER',
      actor: 'scorer',
      durationMs: scorerLatency,
      outcome: isTimeout || isBlocked ? 'NOT_EVALUATED' : 'SCORED',
      detail: isTimeout || isBlocked ? 'Evaluation Bypassed' : 'Rubric 0 (Safe)',
      state: isTimeout || isBlocked ? 'skipped' : 'ok',
    },
    {
      id: 'recorder',
      index: 5,
      name: '06 / RECORDER',
      actor: 'recorder',
      durationMs: recorderLatency,
      outcome: isRecorderDown ? 'AUDIT_UNAVAILABLE' : isTimeout ? 'INVALID_SEALED' : 'CHAINED',
      detail: isRecorderDown ? 'Storage Unreachable' : `Turn #${turn} Ledger Anchored`,
      state: isRecorderDown ? 'invalid' : isTimeout ? 'timeout' : 'ok',
    },
  ], [turn, isTimeout, isBlocked, isSanitized, isRecorderDown, defenseLatency, targetLatency, scorerLatency]);

  // GSAP animation for packet travel along the pipeline
  useGSAP(
    () => {
      if (!trackRef.current || !packetRef.current) return;

      const prefersReducedMotion =
        typeof window !== 'undefined' &&
        window.matchMedia('(prefers-reduced-motion: reduce)').matches;

      gsap.killTweensOf(packetRef.current);

      if (prefersReducedMotion) {
        // Reduced motion: hide traveling packet, maintain instant state updates
        gsap.set(packetRef.current, { opacity: 0 });
        return;
      }

      // Calculate travel limit: stops at Blue stage if blocked or timed out
      const maxStageIndex = isTimeout || isBlocked ? 2 : 5;
      const trackWidth = trackRef.current.clientWidth;
      const stageWidth = trackWidth / 6;
      const targetX = maxStageIndex * stageWidth + stageWidth * 0.5 - 6;

      // Animate packet along track
      gsap.set(packetRef.current, { opacity: 1, x: 0 });
      gsap.to(packetRef.current, {
        x: targetX,
        duration: isTimeout ? 1.4 : 1.8,
        ease: 'power2.inOut',
        onComplete: () => {
          if (packetRef.current) {
            gsap.to(packetRef.current, {
              opacity: 0.4,
              duration: 0.3,
            });
          }
        },
      });
    },
    { dependencies: [turn, isTimeout, isBlocked, isRecorderDown], scope: containerRef }
  );

  return (
    <Panel
      label={`01 — PIPELINE EXECUTION WATERFALL (TURN #${turn} / ${maxTurns})`}
      meta={`DURATION ${totalCalculatedLatency}ms · BROKER ${brokerLatency}ms · TARGET ${targetLatency}ms`}
      className={cn('mb-4', className)}
    >
      <div ref={containerRef} className="space-y-4">
        {/* Waterfall Track & Animated Packet */}
        <div className="relative pt-2 pb-1">
          {/* Background track line */}
          <div ref={trackRef} className="relative h-1 w-full bg-bd rounded-full overflow-visible">
            {/* Active packet marker */}
            <div
              ref={packetRef}
              data-testid="waterfall-packet"
              className={cn(
                'absolute -top-1.5 w-4 h-4 rounded-full border-2 border-bg shadow-sm transition-colors',
                isTimeout
                  ? 'bg-inv shadow-inv/50'
                  : isBlocked
                    ? 'bg-am shadow-am/50'
                    : 'bg-cy shadow-cy/50'
              )}
              style={{ left: 0 }}
            />
          </div>
        </div>

        {/* 6 Stage Cards Grid */}
        <div
          className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-6 gap-2.5"
          role="region"
          aria-label="Pipeline Stages"
        >
          {stages.map((stage) => {
            const isStageTimeout = stage.state === 'timeout';
            const isStageBlocked = stage.state === 'blocked';
            const isStageSkipped = stage.state === 'skipped';
            const isStageInvalid = stage.state === 'invalid';

            return (
              <div
                key={stage.id}
                data-testid={`waterfall-stage-${stage.id}`}
                className={cn(
                  'border p-3 rounded font-mono text-xs flex flex-col justify-between transition-colors relative',
                  isStageTimeout && 'border-inv bg-inv/10 text-tx',
                  isStageBlocked && 'border-am/80 bg-am/10 text-tx',
                  isStageInvalid && 'border-inv bg-inv/15 text-tx',
                  isStageSkipped && 'border-bd/60 bg-s2/40 text-dim',
                  stage.state === 'ok' && 'border-bd bg-s2 text-tx hover:border-cy/40'
                )}
              >
                {/* Stage Header */}
                <div>
                  <div className="flex items-center justify-between text-[11px] text-mut mb-1.5">
                    <span className="font-semibold tracking-wider uppercase">{stage.name}</span>
                    <span className="flex items-center gap-1 text-mut tabular-nums">
                      <Clock className="w-3 h-3" />
                      {stage.durationMs}ms
                    </span>
                  </div>

                  {/* Outcome Tag */}
                  <div className="my-1.5">
                    <span
                      className={cn(
                        'inline-block px-1.5 py-0.5 text-[11px] uppercase tracking-wider font-bold border rounded-sm',
                        isStageTimeout && 'border-inv bg-inv/20 text-inv',
                        isStageBlocked && 'border-am bg-am/20 text-am',
                        isStageInvalid && 'border-inv bg-inv/20 text-inv',
                        isStageSkipped && 'border-dim/40 bg-dim/10 text-mut',
                        stage.state === 'ok' && 'border-cy/40 bg-cy/10 text-cy'
                      )}
                    >
                      {stage.outcome}
                    </span>
                  </div>
                </div>

                {/* Stage Detail Microcopy */}
                <div className="mt-2 pt-2 border-t border-bd/40 text-[11px] text-mut truncate">
                  {stage.detail}
                </div>
              </div>
            );
          })}
        </div>

        {/* Informative Status Strip under Waterfall */}
        <div className="flex flex-wrap items-center justify-between gap-2 pt-2 border-t border-bd/60 text-xs font-mono text-mut">
          <div className="flex items-center gap-2">
            <span className="text-mut">STATUS:</span>
            {isQuarantined ? (
              <span className="text-inv font-bold flex items-center gap-1">
                <AlertTriangle className="w-3.5 h-3.5" /> DOMAIN QUARANTINED (EXECUTION HALTED)
              </span>
            ) : isTimeout ? (
              <span className="text-inv font-bold flex items-center gap-1">
                <ShieldAlert className="w-3.5 h-3.5" /> DEFENSE DEADLINE EXCEEDED (1,002ms) · ATTEMPT INVALIDATED
              </span>
            ) : isBlocked ? (
              <span className="text-am font-bold flex items-center gap-1">
                <AlertTriangle className="w-3.5 h-3.5" /> ADVERSARIAL ATTEMPT INTERCEPTED BY DEFENSE
              </span>
            ) : (
              <span className="text-ok font-medium flex items-center gap-1">
                <ArrowRight className="w-3.5 h-3.5 text-cy" /> PIPELINE TRANSIT NOMINAL (P95 &lt; 100ms)
              </span>
            )}
          </div>

          <div className="flex items-center gap-3 text-[11px]">
            <span>BLUE LATENCY: <strong className="text-tx">{defenseLatency}ms</strong></span>
            <span>TARGET LATENCY: <strong className="text-tx">{targetLatency}ms</strong></span>
            <span>TOTAL: <strong className="text-tx">{totalCalculatedLatency}ms</strong></span>
          </div>
        </div>
      </div>
    </Panel>
  );
};

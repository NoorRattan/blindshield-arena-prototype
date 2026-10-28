import React from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  Clock,
  Lock,
  Info,
  CheckCircle,
} from 'lucide-react';
import { Panel } from '../../components/Panel';
import { DualVerdict } from '../../components/DualVerdict';
import { EmbargoMask } from '../../components/EmbargoMask';
import { RadialMeter } from '../../components/RadialMeter';
import type { FeedbackItem, FeedbackProfile } from '../../lib/schemas';

export interface TurnFeedbackLogProps {
  feedback: FeedbackItem[];
  profile: FeedbackProfile;
  maxTurns?: number;
  isLoading?: boolean;
}

export const TurnFeedbackLog: React.FC<TurnFeedbackLogProps> = ({
  feedback,
  profile,
  maxTurns = 50,
  isLoading = false,
}) => {
  const turnsCount = feedback.length;
  const turnsPercentage = Math.min(100, Math.round((turnsCount / maxTurns) * 100));
  const isSealedBatch = profile === 'SEALED_BATCH';

  // Sort turns in descending order (latest turn first)
  const sortedFeedback = [...feedback].sort((a, b) => b.turn - a.turn);

  return (
    <div className="space-y-6">
      {/* SECTION 1: TURN BUDGET & PROFILE STATUS */}
      <Panel
        label="02 — TURN BUDGET & CAPACITY"
        meta={`PROFILE: ${profile}`}
        className="bg-s1"
      >
        <div className="flex flex-col sm:flex-row items-center gap-6 p-2">
          {/* Radial Meter with GSAP */}
          <div className="shrink-0 flex flex-col items-center">
            <RadialMeter
              value={turnsPercentage}
              label="BUDGET USED"
              size={110}
              variant={turnsPercentage > 85 ? 'am' : 'cy'}
            />
          </div>

          {/* Details & Disclosures */}
          <div className="flex-1 space-y-3 w-full">
            <div className="grid grid-cols-2 gap-2 text-xs">
              <div className="rounded-[2px] border border-bd bg-s2 p-2">
                <span className="font-mono text-mut block uppercase text-[10px]">TURNS SUBMITTED</span>
                <span className="font-mono font-semibold text-tx text-sm">
                  {turnsCount} <span className="text-mut font-normal">/ {maxTurns}</span>
                </span>
              </div>
              <div className="rounded-[2px] border border-bd bg-s2 p-2">
                <span className="font-mono text-mut block uppercase text-[10px]">REMAINING QUOTA</span>
                <span className="font-mono font-semibold text-tx text-sm">
                  {Math.max(0, maxTurns - turnsCount)} <span className="text-mut font-normal">turns</span>
                </span>
              </div>
            </div>

            <div className="rounded-[2px] border border-bd bg-bg/60 p-2.5 text-xs">
              <div className="flex items-center gap-1.5 font-mono text-[11px] font-medium text-tx">
                {isSealedBatch ? (
                  <Lock className="h-3.5 w-3.5 text-emb" aria-hidden="true" />
                ) : (
                  <CheckCircle className="h-3.5 w-3.5 text-ok" aria-hidden="true" />
                )}
                <span>{isSealedBatch ? 'SEALED BATCH DISCLOSURE POLICY' : 'CONTROLLED FEEDBACK POLICY'}</span>
              </div>
              <p className="mt-1 text-[11px] text-mut leading-relaxed">
                {isSealedBatch
                  ? 'Turns remain sealed in broker quarantine. Evaluation decisions and outcomes are withheld until round close.'
                  : 'Bounded model defense decisions and coarse 50ms latency buckets are disclosed per turn. Raw target output remains embargoed.'}
              </p>
            </div>
          </div>
        </div>
      </Panel>

      {/* SECTION 2: TURN HISTORY & FEEDBACK LOG */}
      <Panel
        label="03 — OUTCOME & FEEDBACK LOG"
        meta={`${turnsCount} TURNS RECORDED`}
        className="bg-s1"
      >
        <div className="space-y-4">
          {isLoading ? (
            <div className="py-8 text-center font-mono text-xs text-mut animate-pulse">
              SYNCING TURN FEEDBACK LOG...
            </div>
          ) : sortedFeedback.length === 0 ? (
            <div className="py-8 text-center rounded-[2px] border border-dashed border-bd bg-s2/30 p-6 font-mono text-xs text-mut">
              NO ATTACK ATTEMPTS RECORDED IN ACTIVE ROUND.
              <div className="mt-1 text-[11px] text-mut">
                Submit an adversarial payload via the workshop to observe broker feedback.
              </div>
            </div>
          ) : (
            <div className="space-y-3" role="feed" aria-label="Turn Feedback History">
              {sortedFeedback.map((item) => {
                const isEmbargoed =
                  !item.disclosure.visible || item.disclosure.reason === 'EMBARGOED';
                const isBlocked =
                  // backend: BLOCKED_BY_DEFENSE lives in pipeline_disposition, not model_execution
                  item.pipeline_disposition === 'BLOCKED_BY_DEFENSE' ||
                  item.defense_status === 'BLOCKED';

                return (
                  <article
                    key={`turn_${item.turn}_${item.request_id}`}
                    aria-label={`Turn ${item.turn} Feedback`}
                    className="rounded-[2px] border border-bd bg-s2/60 p-3.5 space-y-3 transition-colors hover:border-bd-strong"
                  >
                    {/* Header Row */}
                    <div className="flex flex-wrap items-center justify-between gap-2 border-b border-bd/60 pb-2.5">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-xs font-bold text-tx">
                          TURN {String(item.turn).padStart(2, '0')}
                        </span>
                        <span className="font-mono text-[11px] text-mut">
                          [{item.request_id}]
                        </span>
                      </div>

                      {/* State Pills */}
                      <div className="flex items-center gap-2">
                        {isEmbargoed ? (
                          <span className="inline-flex items-center gap-1 rounded-[2px] border border-emb/40 bg-emb/10 px-2 py-0.5 font-mono text-[11px] font-medium text-emb">
                            <Lock className="h-3 w-3" aria-hidden="true" />
                            <span>SUBMITTED · AWAITING CLOSE</span>
                          </span>
                        ) : (
                          <div className="flex items-center gap-1.5">
                            {isBlocked ? (
                              <span className="inline-flex items-center gap-1 rounded-[2px] border border-am/40 bg-am/10 px-2 py-0.5 font-mono text-[11px] font-medium text-am">
                                <ShieldAlert className="h-3 w-3" aria-hidden="true" />
                                <span>BLOCKED_BY_DEFENSE</span>
                              </span>
                            ) : (
                              <span className="inline-flex items-center gap-1 rounded-[2px] border border-ok/40 bg-ok/10 px-2 py-0.5 font-mono text-[11px] font-medium text-ok">
                                <ShieldCheck className="h-3 w-3" aria-hidden="true" />
                                <span>ALLOWED_BY_DEFENSE</span>
                              </span>
                            )}
                          </div>
                        )}
                      </div>
                    </div>

                    {/* Content / Verdicts */}
                    {isEmbargoed ? (
                      <div className="space-y-2">
                        <EmbargoMask
                          reason="Withheld until round close (C-07: Sealed Batch profile)"
                          className="py-3 text-xs"
                        />
                      </div>
                    ) : (
                      <div className="space-y-3">
                        {/* Dual Verdict (Invariant 1) */}
                        <div className="flex flex-wrap items-center justify-between gap-3 rounded-[2px] border border-bd bg-bg/50 p-2.5">
                          <div>
                            <span className="font-mono text-[10px] text-mut uppercase block">
                              EVALUATION VERDICTS (DUAL VERDICT)
                            </span>
                            <div className="mt-1">
                              <DualVerdict
                                modelOutcome={item.model_execution ?? 'NOT_EVALUATED'}
                                integrity={item.integrity ?? 'VALID_WITHIN_PROFILE'}
                                size="sm"
                              />
                            </div>
                          </div>

                          {/* Latency Bucket */}
                          {item.latency_bucket_ms !== undefined && (
                            <div className="flex items-center gap-1 font-mono text-xs text-mut">
                              <Clock className="h-3.5 w-3.5 text-cy" aria-hidden="true" />
                              <span>LATENCY:</span>
                              <span className="font-medium text-tx">{item.latency_bucket_ms} ms</span>
                              <span className="text-[10px] text-mut">(50ms bucket)</span>
                            </div>
                          )}
                        </div>

                        {/* Embargoed Target Model Output */}
                        <div>
                          <div className="flex items-center justify-between text-[11px] font-mono text-mut mb-1">
                            <span>TARGET MODEL OUTPUT</span>
                            <span className="text-emb">EMBARGOED</span>
                          </div>
                          <EmbargoMask
                            reason="Target response withheld until official round release"
                            className="py-2.5 text-[11px]"
                          />
                        </div>
                      </div>
                    )}
                  </article>
                );
              })}
            </div>
          )}
        </div>
      </Panel>

      {/* SECTION 3: PRIVACY NOTICE */}
      <Panel
        label="04 — OPERATIONAL PRIVACY NOTICE"
        meta="SPEC §5.6 & C-07"
        className="border-bd bg-s1/60"
      >
        <div className="flex items-start gap-2.5 text-xs text-mut leading-relaxed">
          <Info className="mt-0.5 h-4 w-4 shrink-0 text-cy" aria-hidden="true" />
          <div className="space-y-1.5">
            <p>
              In accordance with the BlindShield evaluation contract, raw target model responses,
              scoring ground truth, and defense classifier internals (regex patterns, confidence scores)
              remain <span className="text-emb font-mono font-medium">EMBARGOED</span> until official round close.
            </p>
            <p className="text-[11px]">
              Feedback disclosures are bounded and monitored: each query consumption is durable,
              cryptographically anchored, and deducted against active tenant quotas.
            </p>
          </div>
        </div>
      </Panel>
    </div>
  );
};

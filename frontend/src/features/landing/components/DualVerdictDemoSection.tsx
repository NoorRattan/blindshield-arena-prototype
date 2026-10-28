import React, { useState } from 'react';
import { AlertCircle, CheckCircle2, Play, Zap } from 'lucide-react';
import { DualVerdict } from '../../../components/DualVerdict';
import { Panel } from '../../../components/Panel';
import { arenaClient } from '../../../lib/api';
import type { StatusValue } from '../../../components/StatusPill';

export const DualVerdictDemoSection: React.FC = () => {
  const [injectTimeout, setInjectTimeout] = useState<boolean>(false);

  const handleToggleFailure = () => {
    const nextState = !injectTimeout;
    setInjectTimeout(nextState);

    // Synchronize with mock ArenaClient failure matrix
    arenaClient.setFailureMode(nextState ? 'defense_timeout' : 'none');
  };

  // Outcome computation:
  // When timeout injected: Integrity = INVALID, Model Outcome = NOT_EVALUATED
  // Normal state: Integrity = VALID_WITHIN_PROFILE, Model Outcome = BLOCKED_BY_DEFENSE
  const integrityStatus: StatusValue = injectTimeout ? 'INVALID' : 'VALID_WITHIN_PROFILE';
  const modelOutcomeStatus: StatusValue = injectTimeout ? 'NOT_EVALUATED' : 'BLOCKED_BY_DEFENSE';
  const scoringOutcomeStatus: StatusValue = injectTimeout ? 'NOT_EVALUATED' : 'SCORED';

  return (
    <section
      className="py-16 lg:py-20 border-b border-[var(--bd)]"
      aria-labelledby="dual-verdict-heading"
    >
      <div className="mb-10">
        <div className="flex items-center gap-2 mb-3">
          <span className="font-mono text-[12px] uppercase tracking-[0.14em] text-[var(--cy)] font-medium">
            02 — SEPARATION OF INTEGRITY AND OUTCOME
          </span>
        </div>
        <h2
          id="dual-verdict-heading"
          className="font-display text-[clamp(32px,5vw,60px)] leading-[0.96] text-[var(--tx)] uppercase"
        >
          Two Independent Outcomes, Always
        </h2>
        <p className="text-[15px] sm:text-[16px] text-[var(--mut)] max-w-[64ch] mt-3">
          Traditional benchmarks report a single pass/fail verdict. When an evaluation container
          crashes or drops a packet, it is often erroneously chalked up as a defensive block or safe
          refusal. BlindShield separates model safety findings from evaluation validity.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
        {/* Left Side (Cols 1-7): Interactive simulation panel */}
        <div className="lg:col-span-7">
          <Panel
            label="LIVE VERDICT SIMULATOR"
            meta={injectTimeout ? 'SIMULATING FAILURE' : 'NORMAL ENVELOPE'}
            className="w-full"
          >
            <div className="space-y-6">
              {/* Controls */}
              <div className="flex flex-wrap items-center justify-between gap-4 p-3.5 bg-[var(--s2)]/40 border border-[var(--bd)] rounded-[2px]">
                <div className="flex items-center gap-3">
                  <span className="font-mono text-[12px] uppercase text-[var(--tx)] font-medium tracking-[0.08em]">
                    FAILURE INJECTION:
                  </span>
                  <span
                    className={`font-mono text-[12px] uppercase px-2 py-0.5 rounded-[2px] font-semibold ${
                      injectTimeout
                        ? 'bg-[var(--inv)]/20 text-[var(--inv)] border border-[var(--inv)]/40'
                        : 'bg-[var(--ok)]/20 text-[var(--ok)] border border-[var(--ok)]/40'
                    }`}
                  >
                    {injectTimeout ? 'DEFENSE TIMEOUT (1,042ms)' : 'NORMAL EXECUTION (38ms)'}
                  </span>
                </div>

                <button
                  type="button"
                  onClick={handleToggleFailure}
                  className={`inline-flex items-center gap-2 px-4 py-2 font-mono text-[12px] uppercase tracking-[0.1em] font-semibold rounded-[2px] transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--cy)] ${
                    injectTimeout
                      ? 'bg-[var(--s1)] text-[var(--tx)] border border-[var(--bd-strong)] hover:border-[var(--cy)]'
                      : 'bg-[var(--s1)] text-[var(--bad)] border border-[var(--bad)] hover:bg-[var(--bad)]/10'
                  }`}
                  aria-pressed={injectTimeout}
                >
                  {injectTimeout ? (
                    <Play className="w-3.5 h-3.5" />
                  ) : (
                    <Zap className="w-3.5 h-3.5" />
                  )}
                  <span>{injectTimeout ? 'Restore Normal Flow' : 'Inject Defense Timeout'}</span>
                </button>
              </div>

              {/* Rendered Dual Verdict Component */}
              <div className="p-4 bg-[var(--bg)] border border-[var(--bd)] rounded-[2px] transition-all">
                <span className="block font-mono text-[11px] text-[var(--mut)] uppercase tracking-[0.1em] mb-3">
                  OUTPUT VERDICT CONTAINER (RENDERED COMPONENT)
                </span>
                <DualVerdict
                  modelOutcome={modelOutcomeStatus}
                  integrity={integrityStatus}
                  scoringOutcome={scoringOutcomeStatus}
                  layout="stack"
                  size="md"
                />
              </div>

              {/* Diagnostic Log */}
              <div
                className={`p-4 border font-mono text-[12px] space-y-1.5 transition-colors ${
                  injectTimeout
                    ? 'bg-[var(--inv)]/5 border-[var(--inv)]/40 text-[var(--tx)]'
                    : 'bg-[var(--ok)]/5 border-[var(--ok)]/30 text-[var(--tx)]'
                }`}
              >
                <div className="flex items-center justify-between text-[11px] text-[var(--mut)]">
                  <span>LOG SEQUENCE: #EV-00492</span>
                  <span>T+00:00:01.042</span>
                </div>
                {injectTimeout ? (
                  <p className="leading-relaxed">
                    <span className="text-[var(--inv)] font-semibold">DEADLINE_EXCEEDED: </span>
                    Defense deadline exceeded at 1,042 ms (budget: 1,000 ms). Attempt invalidated.
                    Model execution aborted to avoid timing side-channel leakage.
                  </p>
                ) : (
                  <p className="leading-relaxed">
                    <span className="text-[var(--ok)] font-semibold">EXECUTION_COMPLIANT: </span>
                    Defense executed in 38 ms. Scoped shaping applied. Output refusal verified and
                    witnessed into signed checkpoint.
                  </p>
                )}
              </div>
            </div>
          </Panel>
        </div>

        {/* Right Side (Cols 8-12): Explanation of Invariant 1 */}
        <div className="lg:col-span-5 space-y-6">
          <div className="p-6 bg-[var(--s1)] border border-[var(--bd)]">
            <h3 className="font-display text-[22px] leading-tight text-[var(--tx)] uppercase mb-3 flex items-center gap-2">
              <CheckCircle2 className="w-5 h-5 text-[var(--cy)]" />
              <span>THE FIRST INVARIANT</span>
            </h3>
            <p className="text-[14px] leading-[1.6] text-[var(--mut)] mb-4">
              A model outcome is only interpretable if the experiment itself remained uncompromised.
              If a defense crashes, hangs, or breaches memory boundaries, the verdict is{' '}
              <strong className="text-[var(--inv)] font-mono">INVALID</strong>, and the model row
              becomes{' '}
              <strong className="text-[var(--mut)] font-mono">NOT_EVALUATED</strong>.
            </p>
            <div className="border-t border-[var(--bd)] pt-4 space-y-3 font-mono text-[12px]">
              <div className="flex items-start gap-2">
                <span className="text-[var(--cy)]">01</span>
                <span className="text-[var(--tx)]">
                  Never a single green &ldquo;Safe&rdquo; badge.
                </span>
              </div>
              <div className="flex items-start gap-2">
                <span className="text-[var(--cy)]">02</span>
                <span className="text-[var(--tx)]">
                  Infrastructure faults never register as defensive blocks.
                </span>
              </div>
              <div className="flex items-start gap-2">
                <span className="text-[var(--cy)]">03</span>
                <span className="text-[var(--tx)]">
                  Auditors verify cryptographic witnesses before accepting model scores.
                </span>
              </div>
            </div>
          </div>

          <div className="p-4 bg-[var(--s2)]/40 border border-[var(--bd)] flex items-start gap-3">
            <AlertCircle className="w-4 h-4 text-[var(--am)] shrink-0 mt-0.5" />
            <p className="text-[12px] leading-relaxed text-[var(--mut)] font-mono">
              <strong className="text-[var(--tx)] font-semibold">SPEC CORRECTION C-04: </strong>
              VALID_WITHIN_PROFILE indicates that the declared isolation protocol completed without
              detected boundary violation. It is never a blanket claim of model safety.
            </p>
          </div>
        </div>
      </div>
    </section>
  );
};

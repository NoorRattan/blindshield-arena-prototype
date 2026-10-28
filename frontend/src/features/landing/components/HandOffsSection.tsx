import React, { useState, useRef } from 'react';
import { Eye, EyeOff, ShieldCheck, ArrowRight, Lock } from 'lucide-react';
import { Panel } from '../../../components/Panel';
import { ArenaHero2DFallback } from '../../../three/ArenaHero2DFallback';
import type { ActiveArenaNode } from '../../../three/ArenaHeroScene';
import { useGSAP, ScrollTrigger } from '../../../design/gsap';
import { useReducedMotion } from 'framer-motion';

const LazyScene = React.lazy(() => import('../../../three/ArenaHeroScene'));

interface HandOffStep {
  num: string;
  title: string;
  actor: string;
  node: ActiveArenaNode;
  summary: string;
  canSee: string[];
  cannotSee: string[];
  boundaryRule: string;
}

const HAND_OFF_STEPS: HandOffStep[] = [
  {
    num: '01',
    title: 'Adversarial Submission',
    actor: 'Red Team Tenant',
    node: 'red',
    summary:
      'The red attacker commits an adversarial probe with client timestamp and sha256 body hash.',
    canSee: ['Own attack prompt', 'Local client timestamp', 'Estimated token budget'],
    cannotSee: [
      'Defense pipeline internals',
      'Broker queue telemetry',
      'Target model hidden state',
      'Concurrent tenant queries',
    ],
    boundaryRule: 'Wire budget enforced: body ≤ 70,000 bytes, text ≤ 65,536 UTF-8 bytes.',
  },
  {
    num: '02',
    title: 'Default-Deny Ingestion',
    actor: 'Trusted Broker',
    node: 'broker',
    summary:
      'The trusted broker validates schemas, assigns a monotonic sequence, and initiates isolated lanes.',
    canSee: [
      'Raw incoming payload',
      'Client authenticated key',
      'Active epoch and domain',
      'Monotonic sequence number',
    ],
    cannotSee: [
      'Target model proprietary weights',
      'External network egress (disabled)',
      'Unauthenticated client state',
    ],
    boundaryRule: 'Default-deny routing. All inter-tenant communication mediated via broker.',
  },
  {
    num: '03',
    title: 'Frozen Defense Inspection',
    actor: 'Blue Defense Container',
    node: 'blue',
    summary:
      'The frozen defense evaluates the current candidate input without historical memory.',
    canSee: ['Current turn input candidate only', 'Configured token filter bounds'],
    cannotSee: [
      'Multi-turn attack history',
      'Red attacker identity or tenant ID',
      'Downstream model weights or responses',
    ],
    boundaryRule:
      'Stateless execution with 1,000 ms hard wall-clock deadline. Typed ALLOW/BLOCK/SANITIZE.',
  },
  {
    num: '04',
    title: 'Isolated Target Inference',
    actor: 'Target Model Lane',
    node: 'target',
    summary:
      'The target LLM performs token generation in a quarantined container with dedicated cpusets.',
    canSee: ['Allowed or sanitized prompt text', 'Max token generation limit (256 tokens)'],
    cannotSee: [
      'Red attacker identity',
      'Blue defense rule triggers',
      'Cross-lane memory or unseparated KV cache',
    ],
    boundaryRule: 'Dedicated cpusets and constant-time reply shaping bound covert channel leakage.',
  },
  {
    num: '05',
    title: 'Dual Scorer Evaluation',
    actor: 'Automated Evaluator',
    node: 'scorer',
    summary:
      'Evaluates whether the model complied with adversarial instructions and checks execution invariants.',
    canSee: [
      'Input candidate',
      'Defense action code',
      'Model completion text',
      'Telemetry timestamps',
    ],
    cannotSee: [
      'Unsanitized tenant private keys',
      'Host hypervisor credentials',
    ],
    boundaryRule:
      'Decoupled evaluation: scores model compliance and experimental integrity independently.',
  },
  {
    num: '06',
    title: 'Witnessed Cryptographic Receipt',
    actor: 'Recorder & External Witness',
    node: 'witness',
    summary:
      'Events are hashed into the Merkle chain (RFC 8785) and signed with an Ed25519 witnessed checkpoint.',
    canSee: [
      'Event digests and signatures',
      'Merkle root hash',
      'Witnessed epoch checkpoint',
    ],
    cannotSee: [
      'Raw embargoed payloads (withheld until durable round close)',
    ],
    boundaryRule:
      'Terminal checkpoint witnessed before round release. Tampering invalidates chain digest.',
  },
];

export const HandOffsSection: React.FC = () => {
  const [activeStepIndex, setActiveStepIndex] = useState<number>(0);
  const containerRef = useRef<HTMLDivElement>(null);
  const stepsContainerRef = useRef<HTMLDivElement>(null);
  const shouldReduceMotion = useReducedMotion();

  const activeStep = HAND_OFF_STEPS[activeStepIndex];

  useGSAP(
    () => {
      if (shouldReduceMotion) return;

      const container = containerRef.current;
      const stepItems = stepsContainerRef.current?.querySelectorAll('.handoff-step-item');
      if (!container || !stepItems || stepItems.length === 0) return;

      // ScrollTrigger scrub to update active step as user scrolls
      stepItems.forEach((item, index) => {
        ScrollTrigger.create({
          trigger: item,
          start: 'top center+=100',
          end: 'bottom center+=100',
          onEnter: () => setActiveStepIndex(index),
          onEnterBack: () => setActiveStepIndex(index),
        });
      });
    },
    { scope: containerRef, dependencies: [shouldReduceMotion] }
  );

  return (
    <section
      ref={containerRef}
      className="py-16 lg:py-20 border-b border-[var(--bd)]"
      aria-labelledby="handoffs-heading"
    >
      {/* Section Header */}
      <div className="mb-10">
        <div className="flex items-center gap-2 mb-3">
          <span className="font-mono text-[12px] uppercase tracking-[0.14em] text-[var(--cy)] font-medium">
            03 — EXECUTION ENVELOPE WATERFALL
          </span>
        </div>
        <h2
          id="handoffs-heading"
          className="font-display text-[clamp(32px,5vw,60px)] leading-[0.96] text-[var(--tx)] uppercase"
        >
          One Round, Six Hand-offs
        </h2>
        <p className="text-[15px] sm:text-[16px] text-[var(--mut)] max-w-[64ch] mt-3">
          Every evaluation turn traverses a strict sequence of six mediated boundaries. Each step
          enforces strict observer isolation, recording what that participant is permitted to observe
          and what is cryptographically withheld.
        </p>
      </div>

      {/* Step Navigation Pill Bar (for direct keyboard and touch stepping) */}
      <div
        className="flex items-center gap-1.5 overflow-x-auto pb-4 mb-8 border-b border-[var(--bd)] font-mono text-[12px]"
        role="tablist"
        aria-label="Six Hand-offs Sequence"
      >
        {HAND_OFF_STEPS.map((step, idx) => {
          const isActive = idx === activeStepIndex;
          return (
            <button
              key={step.num}
              type="button"
              role="tab"
              aria-selected={isActive}
              aria-controls={`step-content-${step.num}`}
              id={`step-tab-${step.num}`}
              onClick={() => setActiveStepIndex(idx)}
              className={`px-3 py-2 rounded-[2px] transition-all whitespace-nowrap uppercase tracking-[0.08em] flex items-center gap-2 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-[var(--cy)] ${
                isActive
                  ? 'bg-[var(--cy)]/15 text-[var(--cy)] border border-[var(--cy)] font-semibold'
                  : 'bg-[var(--s1)] text-[var(--tx)] hover:text-[var(--cy)] border border-[var(--bd)] font-medium'
              }`}
            >
              <span>{step.num}</span>
              <span className="hidden sm:inline">{step.title}</span>
            </button>
          );
        })}
      </div>

      {/* 2-Column Split: Interactive Narrative on Left, Sticky Scene on Right */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
        {/* Left Side (Cols 1-7): Detailed Step Information & Visibility Matrix */}
        <div ref={stepsContainerRef} className="lg:col-span-7 space-y-6">
          <Panel
            label={`HAND-OFF ${activeStep.num} OF 06 · ${activeStep.actor.toUpperCase()}`}
            meta={`NODE: ${activeStep.node?.toUpperCase()}`}
            className="w-full"
          >
            <div
              id={`step-content-${activeStep.num}`}
              role="tabpanel"
              aria-labelledby={`step-tab-${activeStep.num}`}
              className="space-y-6 handoff-step-item"
            >
              <div>
                <div className="flex items-baseline gap-3 mb-2">
                  <span className="font-display text-[32px] sm:text-[40px] leading-none text-[var(--cy)]">
                    {activeStep.num}
                  </span>
                  <h3 className="font-display text-[24px] sm:text-[28px] leading-tight text-[var(--tx)] uppercase">
                    {activeStep.title}
                  </h3>
                </div>
                <p className="text-[15px] leading-relaxed text-[var(--mut)]">
                  {activeStep.summary}
                </p>
              </div>

              {/* Observer Visibility Matrix */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                {/* Permitted to see */}
                <div className="p-4 bg-[var(--s2)]/40 border border-[var(--bd)] rounded-[2px]">
                  <div className="flex items-center gap-2 mb-3">
                    <Eye className="w-4 h-4 text-[var(--ok)]" />
                    <span className="font-mono text-[11px] uppercase tracking-[0.1em] text-[var(--tx)] font-semibold">
                      WHAT OBSERVER CAN SEE
                    </span>
                  </div>
                  <ul className="space-y-2 font-mono text-[12px] text-[var(--mut)]">
                    {activeStep.canSee.map((item, idx) => (
                      <li key={idx} className="flex items-start gap-2">
                        <span className="text-[var(--ok)] shrink-0">+</span>
                        <span className="text-[var(--tx)]">{item}</span>
                      </li>
                    ))}
                  </ul>
                </div>

                {/* Withheld / Embargoed */}
                <div className="p-4 bg-[var(--s2)]/40 border border-[var(--bd)] rounded-[2px]">
                  <div className="flex items-center gap-2 mb-3">
                    <EyeOff className="w-4 h-4 text-[var(--bad)]" />
                    <span className="font-mono text-[11px] uppercase tracking-[0.1em] text-[var(--tx)] font-semibold">
                      WHAT IS WITHHELD
                    </span>
                  </div>
                  <ul className="space-y-2 font-mono text-[12px] text-[var(--mut)]">
                    {activeStep.cannotSee.map((item, idx) => (
                      <li key={idx} className="flex items-start gap-2">
                        <span className="text-[var(--bad)] shrink-0">×</span>
                        <span>{item}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              </div>

              {/* Boundary Rule */}
              <div className="p-3.5 bg-[var(--s1)] border-l-2 border-[var(--cy)] border border-[var(--bd)] flex items-start gap-3">
                <Lock className="w-4 h-4 text-[var(--cy)] shrink-0 mt-0.5" />
                <div className="text-[13px] font-mono leading-relaxed">
                  <span className="text-[var(--cy)] font-semibold mr-1.5 uppercase tracking-wide">
                    INVARIANT ENFORCEMENT:
                  </span>
                  <span className="text-[var(--tx)]">{activeStep.boundaryRule}</span>
                </div>
              </div>

              {/* Step Navigation Controls */}
              <div className="flex items-center justify-between pt-4 border-t border-[var(--bd)] text-[12px] font-mono">
                <button
                  type="button"
                  disabled={activeStepIndex === 0}
                  onClick={() => setActiveStepIndex((prev) => Math.max(0, prev - 1))}
                  className="px-3 py-1.5 border border-[var(--bd)] text-[var(--mut)] disabled:opacity-30 disabled:pointer-events-none hover:text-[var(--tx)] hover:border-[var(--cy)] transition-colors"
                >
                  ← PREVIOUS STEP
                </button>
                <span className="text-[var(--mut)]">
                  STEP {activeStepIndex + 1} OF {HAND_OFF_STEPS.length}
                </span>
                <button
                  type="button"
                  disabled={activeStepIndex === HAND_OFF_STEPS.length - 1}
                  onClick={() =>
                    setActiveStepIndex((prev) => Math.min(HAND_OFF_STEPS.length - 1, prev + 1))
                  }
                  className="px-3 py-1.5 border border-[var(--bd)] text-[var(--mut)] disabled:opacity-30 disabled:pointer-events-none hover:text-[var(--tx)] hover:border-[var(--cy)] transition-colors"
                >
                  NEXT STEP →
                </button>
              </div>
            </div>
          </Panel>
        </div>

        {/* Right Side (Cols 8-12): Sticky 3D Node & Topology Highlight */}
        <div className="lg:col-span-5 sticky top-24">
          <Panel
            label="TOPOLOGY HIGHLIGHT"
            meta={`ACTIVE: ${activeStep.node?.toUpperCase()}`}
            className="w-full"
          >
            <div className="h-[340px] sm:h-[400px] w-full relative flex items-center justify-center bg-[var(--bg)]/50">
              {shouldReduceMotion ? (
                <ArenaHero2DFallback activeNode={activeStep.node} />
              ) : (
                <React.Suspense
                  fallback={<ArenaHero2DFallback activeNode={activeStep.node} />}
                >
                  <LazyScene activeNode={activeStep.node} />
                </React.Suspense>
              )}
            </div>

            <div className="p-3 bg-[var(--s2)]/30 border-t border-[var(--bd)] flex items-center justify-between text-[11px] font-mono text-[var(--mut)]">
              <span className="flex items-center gap-1.5">
                <ShieldCheck className="w-3.5 h-3.5 text-[var(--cy)]" />
                <span>ISOLATION ACTIVE</span>
              </span>
              <span className="text-[var(--tx)] uppercase font-medium flex items-center gap-1">
                <span>{activeStep.actor}</span>
                <ArrowRight className="w-3 h-3 text-[var(--cy)]" />
              </span>
            </div>
          </Panel>
        </div>
      </div>
    </section>
  );
};

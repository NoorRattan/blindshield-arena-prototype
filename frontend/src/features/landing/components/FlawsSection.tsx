import React from 'react';

interface EvaluationFlaw {
  num: string;
  code: string;
  title: string;
  problem: string;
  countermeasure: string;
}

const EVALUATION_FLAWS: EvaluationFlaw[] = [
  {
    num: '01',
    code: 'FLAW-ADAPTIVE-OVERFIT',
    title: 'Defender overfits to the attack stream',
    problem:
      'When defensive layers observe multi-turn attack iterations with persistent memory or live tuning, the pipeline memorizes the test distribution rather than establishing generalized robustness.',
    countermeasure:
      'BlindShield enforces frozen, stateless defenses with fixed execution bounds. Defenses evaluate strictly within the current turn envelope.',
  },
  {
    num: '02',
    code: 'FLAW-PROMPT-EXTRACTION',
    title: 'Attacker extracts defensive guardrails',
    problem:
      'Unbounded, granular feedback channels allow red teams to systematically probe token filtering boundaries and reverse-engineer defense rules in sub-quadratic query counts.',
    countermeasure:
      'Frozen disclosure profiles (Sealed Batch or Controlled Feedback) bound the information leaked per attempt. Every disclosure is recorded in the audit log.',
  },
  {
    num: '03',
    code: 'FLAW-STATE-CONTAMINATION',
    title: 'Shared inference serving contaminates lanes',
    problem:
      'Unseparated KV-caches, shared GPU memory, and microarchitectural side-channels leak prompts and outputs between red evaluation lanes and target model instances.',
    countermeasure:
      'Three overlapping but isolated model lanes with dedicated cpusets, non-shared memory namespaces, and constant-time reply shaping bound covert cross-lane leakage.',
  },
  {
    num: '04',
    code: 'FLAW-FAILURE-MASKING',
    title: 'Infrastructure failure masquerades as safety',
    problem:
      'Network partitions, broker queue timeouts, and container crashes are routinely recorded as defensive blocks or model refusals, falsifying robustness metrics.',
    countermeasure:
      'Two verdicts, always. BlindShield tracks Model Execution and Evaluation Integrity on completely independent axes. A dropped attempt is marked INVALID, never Safe.',
  },
];

export const FlawsSection: React.FC = () => {
  return (
    <section
      className="py-16 lg:py-20 border-b border-[var(--bd)]"
      aria-labelledby="flaws-heading"
    >
      {/* Section Header */}
      <div className="mb-12">
        <div className="flex items-center gap-2 mb-3">
          <span className="font-mono text-[12px] uppercase tracking-[0.14em] text-[var(--cy)] font-medium">
            01 — THE FAILURE MODES OF UNCHECKED TESTING
          </span>
        </div>
        <h2
          id="flaws-heading"
          className="font-display text-[clamp(32px,5vw,60px)] leading-[0.96] text-[var(--tx)] uppercase"
        >
          The Four Ways Evaluations Lie
        </h2>
        <p className="text-[15px] sm:text-[16px] text-[var(--mut)] max-w-[64ch] mt-3">
          Adversarial evaluations without verifiable isolation produce deceptive metrics. Real
          assurance requires separating model outcomes from execution validity.
        </p>
      </div>

      {/* Editorial Numbered Rows */}
      <div className="border-t border-[var(--bd)]" role="list">
        {EVALUATION_FLAWS.map((flaw) => (
          <div
            key={flaw.code}
            role="listitem"
            className="py-8 border-b border-[var(--bd)] grid grid-cols-1 md:grid-cols-12 gap-6 items-baseline transition-colors hover:bg-[var(--s1)]/30"
          >
            {/* Huge Numeral */}
            <div className="md:col-span-2 flex items-baseline gap-3">
              <span className="font-display text-[44px] sm:text-[54px] leading-none text-[var(--cy)] tracking-normal">
                {flaw.num}
              </span>
              <span className="font-mono text-[11px] text-[var(--mut)] tracking-[0.12em] uppercase">
                / 04
              </span>
            </div>

            {/* Title & Technical Code */}
            <div className="md:col-span-4">
              <span className="inline-block font-mono text-[11px] text-[var(--mut)] tracking-[0.1em] uppercase mb-1">
                {flaw.code}
              </span>
              <h3 className="font-display text-[22px] sm:text-[26px] leading-[1.05] text-[var(--tx)] uppercase">
                {flaw.title}
              </h3>
            </div>

            {/* Problem & BlindShield Countermeasure */}
            <div className="md:col-span-6 space-y-3">
              <p className="text-[14px] leading-[1.55] text-[var(--mut)]">
                <strong className="text-[var(--tx)] font-medium">The Flaw: </strong>
                {flaw.problem}
              </p>
              <div className="p-3 bg-[var(--s1)] border-l-2 border-[var(--cy)] border border-[var(--bd)]">
                <p className="text-[13px] leading-[1.5] text-[var(--tx)]">
                  <span className="font-mono text-[11px] text-[var(--cy)] tracking-[0.1em] uppercase mr-2 font-medium">
                    ASSURANCE FIX:
                  </span>
                  {flaw.countermeasure}
                </p>
              </div>
            </div>
          </div>
        ))}
      </div>
    </section>
  );
};

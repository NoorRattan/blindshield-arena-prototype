import React from 'react';
import { useNavigate } from 'react-router-dom';
import { motion, useReducedMotion } from 'framer-motion';
import { ArrowRight, ShieldCheck, BarChart3, Info } from 'lucide-react';
import { IllustrativeTag } from '../../../components/IllustrativeTag';

export const EnterSection: React.FC = () => {
  const navigate = useNavigate();
  const shouldReduceMotion = useReducedMotion();

  return (
    <section className="py-16 lg:py-24" aria-labelledby="enter-heading">
      <div className="p-8 sm:p-12 lg:p-16 bg-[var(--s1)] border border-[var(--bd)] relative overflow-hidden">
        {/* Subtle decorative grid corner marker */}
        <div
          className="absolute top-0 right-0 w-32 h-32 border-b border-l border-[var(--bd)] pointer-events-none opacity-40"
          aria-hidden="true"
        />

        <div className="max-w-[720px] mb-10">
          <div className="flex items-center gap-2 mb-3">
            <span className="font-mono text-[12px] uppercase tracking-[0.14em] text-[var(--cy)] font-medium">
              05 — ARENA ENTRY & AUDIT SINK
            </span>
          </div>

          <h2
            id="enter-heading"
            className="font-display text-[clamp(36px,6vw,72px)] leading-[0.92] text-[var(--tx)] uppercase mb-6"
          >
            Verifiable AI Safety Assurance
          </h2>

          <p className="text-[16px] sm:text-[18px] text-[var(--mut)] leading-[1.55] mb-8">
            Deploy defenses into frozen containers, submit adversarial attacks under strictly
            bounded feedback channels, and verify cryptographic receipts offline.
          </p>

          {/* Action CTAs */}
          <div className="flex flex-wrap items-center gap-4">
            <motion.button
              type="button"
              onClick={() => navigate('/overview')}
              className="inline-flex items-center gap-2.5 px-6 py-3.5 bg-[var(--cy)] text-[#080B10] font-mono text-[13px] uppercase tracking-[0.12em] font-semibold rounded-[2px] transition-colors hover:brightness-110 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--cy)]"
              whileHover={{ scale: shouldReduceMotion ? 1 : 1.02 }}
              whileTap={{ scale: shouldReduceMotion ? 1 : 0.98 }}
            >
              <span>Enter the Arena</span>
              <ArrowRight className="w-4 h-4" strokeWidth={2} />
            </motion.button>

            <motion.button
              type="button"
              onClick={() => navigate('/evidence')}
              className="inline-flex items-center gap-2 px-6 py-3.5 bg-[var(--s2)] text-[var(--tx)] border border-[var(--bd-strong)] font-mono text-[13px] uppercase tracking-[0.12em] font-medium rounded-[2px] transition-colors hover:border-[var(--cy)] hover:text-[var(--cy)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--cy)]"
              whileHover={{ scale: shouldReduceMotion ? 1 : 1.02 }}
              whileTap={{ scale: shouldReduceMotion ? 1 : 0.98 }}
            >
              <ShieldCheck className="w-4 h-4 text-[var(--ok)]" strokeWidth={1.8} />
              <span>Verify Evidence Bundle</span>
            </motion.button>

            <motion.button
              type="button"
              onClick={() => navigate('/benchmarks')}
              className="inline-flex items-center gap-2 px-5 py-3.5 bg-transparent text-[var(--mut)] border border-[var(--bd)] font-mono text-[13px] uppercase tracking-[0.12em] font-medium rounded-[2px] transition-colors hover:text-[var(--tx)] hover:border-[var(--bd-strong)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--cy)]"
              whileHover={{ scale: shouldReduceMotion ? 1 : 1.02 }}
              whileTap={{ scale: shouldReduceMotion ? 1 : 0.98 }}
            >
              <BarChart3 className="w-4 h-4 text-[var(--cy)]" strokeWidth={1.8} />
              <span>Benchmark Analytics</span>
            </motion.button>
          </div>
        </div>

        {/* Technical Specification Footer Strip */}
        <div className="pt-8 border-t border-[var(--bd)] grid grid-cols-1 md:grid-cols-12 gap-6 text-[12px] font-mono text-[var(--mut)]">
          <div className="md:col-span-6 space-y-1">
            <div className="flex items-center gap-2">
              <span className="text-[var(--tx)] font-semibold">TCB METADATA:</span>
              <span>v0.4.2-proto (AMD EPYC · Isolated Cpusets)</span>
            </div>
            <p className="truncate text-[11px]">
              GENESIS: 7f3a09b3c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852
            </p>
          </div>

          <div className="md:col-span-6 flex flex-col justify-between items-start md:items-end gap-2">
            <div className="flex items-center gap-2">
              <IllustrativeTag />
              <span className="text-[11px]">All live metrics represent demonstrator state.</span>
            </div>
            <div className="flex items-center gap-1.5 text-[11px] text-[var(--mut)]">
              <Info className="w-3.5 h-3.5 text-[var(--cy)]" />
              <span>Protocol: arena.v2 · Three isolated overlapping lanes</span>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
};

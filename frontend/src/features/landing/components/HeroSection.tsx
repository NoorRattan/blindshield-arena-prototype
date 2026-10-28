import React, { useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion, useReducedMotion } from 'framer-motion';
import { ArrowRight, ShieldCheck } from 'lucide-react';
import { gsap, useGSAP } from '../../../design/gsap';

interface HeroSectionProps {
  children?: React.ReactNode;
}

export const HeroSection: React.FC<HeroSectionProps> = ({ children }) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const navigate = useNavigate();
  const shouldReduceMotion = useReducedMotion();

  useGSAP(
    () => {
      if (shouldReduceMotion) return;

      const mm = gsap.matchMedia(containerRef);
      mm.add('(prefers-reduced-motion: no-preference)', () => {
        const tl = gsap.timeline({ defaults: { ease: 'power3.out' } });

        tl.from('.hero-eyebrow', {
          opacity: 0,
          y: -12,
          duration: 0.4,
        })
          .from(
            '.hero-headline-line',
            {
              opacity: 0,
              y: 28,
              stagger: 0.08,
              duration: 0.6,
            },
            '-=0.2'
          )
          .from(
            '.hero-lead',
            {
              opacity: 0,
              y: 16,
              duration: 0.45,
            },
            '-=0.25'
          )
          .from(
            '.hero-actions',
            {
              opacity: 0,
              y: 12,
              duration: 0.4,
            },
            '-=0.2'
          )
          .from(
            '.hero-facts',
            {
              opacity: 0,
              duration: 0.5,
            },
            '-=0.15'
          );
      });
    },
    { scope: containerRef, dependencies: [shouldReduceMotion] }
  );

  return (
    <section
      ref={containerRef}
      className="relative border-b border-[var(--bd)] pt-8 pb-16 lg:py-20"
      aria-label="Landing Hero"
    >
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 lg:gap-12 items-center">
        {/* Left column (Cols 1-7): Editorial copy & actions */}
        <div className="lg:col-span-7 flex flex-col justify-center">
          {/* Eyebrow */}
          <div className="hero-eyebrow flex items-center gap-2 mb-4">
            <span className="inline-block w-2 h-2 bg-[var(--cy)]" aria-hidden="true" />
            <span className="font-mono text-[12px] uppercase tracking-[0.14em] text-[var(--cy)] font-medium">
              BLINDSHIELD ARENA · EVALUATION INTEGRITY
            </span>
          </div>

          {/* Headline (Bebas Neue, huge scale, tight leading) */}
          <h1 className="font-display text-[clamp(44px,7.5vw,96px)] leading-[0.92] tracking-normal text-[var(--tx)] uppercase mb-6">
            <span className="hero-headline-line block">Every safety finding,</span>
            <span className="hero-headline-line block text-[var(--tx)]">accountable to its</span>
            <span className="hero-headline-line block text-[var(--cy)]">execution conditions.</span>
          </h1>

          {/* Lead sentence */}
          <p className="hero-lead text-[17px] sm:text-[18px] leading-[1.55] text-[var(--mut)] max-w-[60ch] mb-8">
            Infrastructure assurance around adversarial AI evaluation loops. Isolating tenant
            containers, freezing defensive pipelines, and generating tamper-evident cryptographic
            receipts for every prompt and response.
          </p>

          {/* Actions */}
          <div className="hero-actions flex flex-wrap items-center gap-4 mb-10">
            <motion.button
              type="button"
              onClick={() => navigate('/overview')}
              className="inline-flex items-center gap-2.5 px-6 py-3.5 bg-[var(--cy)] text-[#080B10] font-mono text-[13px] uppercase tracking-[0.12em] font-semibold rounded-[2px] transition-colors hover:brightness-110 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--cy)] focus-visible:ring-offset-2 focus-visible:ring-offset-[var(--bg)]"
              whileHover={{ scale: shouldReduceMotion ? 1 : 1.02 }}
              whileTap={{ scale: shouldReduceMotion ? 1 : 0.98 }}
            >
              <span>Enter the arena</span>
              <ArrowRight className="w-4 h-4" strokeWidth={2} />
            </motion.button>

            <motion.button
              type="button"
              onClick={() => navigate('/evidence')}
              className="inline-flex items-center gap-2 px-6 py-3.5 bg-[var(--s1)] text-[var(--tx)] border border-[var(--bd-strong)] font-mono text-[13px] uppercase tracking-[0.12em] font-medium rounded-[2px] transition-colors hover:border-[var(--cy)] hover:text-[var(--cy)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--cy)] focus-visible:ring-offset-2 focus-visible:ring-offset-[var(--bg)]"
              whileHover={{ scale: shouldReduceMotion ? 1 : 1.02 }}
              whileTap={{ scale: shouldReduceMotion ? 1 : 0.98 }}
            >
              <ShieldCheck className="w-4 h-4 text-[var(--ok)]" strokeWidth={1.8} />
              <span>Verify a bundle</span>
            </motion.button>
          </div>

          {/* Mono Fact Strip */}
          <div className="hero-facts pt-6 border-t border-[var(--bd)]">
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
              <div className="flex flex-col">
                <span className="font-mono text-[11px] text-[var(--mut)] tracking-[0.1em] uppercase">
                  TENANT CONTROL
                </span>
                <span className="font-mono text-[13px] text-[var(--tx)] font-medium mt-0.5">
                  FROZEN DEFENSE
                </span>
              </div>
              <div className="flex flex-col border-t sm:border-t-0 sm:border-l border-[var(--bd)] sm:pl-4 pt-3 sm:pt-0">
                <span className="font-mono text-[11px] text-[var(--mut)] tracking-[0.1em] uppercase">
                  DISCLOSURE POLICY
                </span>
                <span className="font-mono text-[13px] text-[var(--tx)] font-medium mt-0.5">
                  SEALED ATTACKS
                </span>
              </div>
              <div className="flex flex-col border-t sm:border-t-0 sm:border-l border-[var(--bd)] sm:pl-4 pt-3 sm:pt-0">
                <span className="font-mono text-[11px] text-[var(--mut)] tracking-[0.1em] uppercase">
                  RECORDING ANCHOR
                </span>
                <span className="font-mono text-[13px] text-[var(--tx)] font-medium mt-0.5">
                  SIGNED, WITNESSED
                </span>
              </div>
            </div>
          </div>
        </div>

        {/* Right column (Cols 6-12 / 8-12): 3D Scene / Visual Slot */}
        <div className="lg:col-span-5 h-[340px] sm:h-[400px] lg:h-[480px] w-full relative flex items-center justify-center">
          {children}
        </div>
      </div>
    </section>
  );
};

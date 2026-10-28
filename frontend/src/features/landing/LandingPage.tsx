import React from 'react';
import { useReducedMotion } from 'framer-motion';
import { HeroSection } from './components/HeroSection';
import { FlawsSection } from './components/FlawsSection';
import { DualVerdictDemoSection } from './components/DualVerdictDemoSection';
import { HandOffsSection } from './components/HandOffsSection';
import { ResidualRiskSection } from './components/ResidualRiskSection';
import { EnterSection } from './components/EnterSection';
import { ArenaHero2DFallback } from '../../three/ArenaHero2DFallback';

const LazyArenaHeroScene = React.lazy(() => import('../../three/ArenaHeroScene'));

export const LandingPage: React.FC = () => {
  const shouldReduceMotion = useReducedMotion();

  return (
    <div className="w-full max-w-[1440px] mx-auto px-4 sm:px-6 lg:px-8">
      {/* Hero Section with 3D Scene or 2D Architectural Fallback */}
      <HeroSection>
        {shouldReduceMotion ? (
          <ArenaHero2DFallback activeNode="broker" />
        ) : (
          <React.Suspense fallback={<ArenaHero2DFallback activeNode="broker" />}>
            <LazyArenaHeroScene activeNode="broker" />
          </React.Suspense>
        )}
      </HeroSection>

      {/* 01 — The Four Ways Evaluations Lie */}
      <FlawsSection />

      {/* 02 — Two Verdicts: Live DualVerdict Demo */}
      <DualVerdictDemoSection />

      {/* 03 — One Round, Six Hand-offs Waterfall */}
      <HandOffsSection />

      {/* 04 — What We Claim, and What We Don't (Residual Risk Panel Q-005) */}
      <ResidualRiskSection />

      {/* 05 — Enter: Closing CTA & Honest Notes */}
      <EnterSection />
    </div>
  );
};

export default LandingPage;

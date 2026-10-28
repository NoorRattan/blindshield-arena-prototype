import React from 'react';
import { NavLink, Outlet, useLocation } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { Shield, Command } from 'lucide-react';
import { Backdrop } from '../components/Backdrop';
import { RoleSwitcher } from '../components/RoleSwitcher';
import { CommandPalette } from '../components/CommandPalette';
import { EpochBadge } from '../components/EpochBadge';
import { useArenaStore } from '../state/useArenaStore';
import { FADE_VARIANTS } from '../design/motion';
import { cn } from '../lib/cn';
import { ErrorBoundary } from '../components/ErrorBoundary';
import { RouteLoadingFallback } from './RouteLoadingFallback';

interface NavItem {
  to: string;
  label: string;
  numeral: string;
}

const NAV_ITEMS: NavItem[] = [
  { to: '/', label: 'Landing', numeral: '00' },
  { to: '/overview', label: 'Overview', numeral: '01' },
  { to: '/setup', label: 'Setup', numeral: '02' },
  { to: '/war-room', label: 'War Room', numeral: '03' },
  { to: '/red', label: 'Red Portal', numeral: '04' },
  { to: '/blue', label: 'Blue Console', numeral: '05' },
  { to: '/evidence', label: 'Evidence', numeral: '06' },
  { to: '/benchmarks', label: 'Benchmarks', numeral: '07' },
  { to: '/__kit', label: 'Dev Kit', numeral: 'KIT' },
];

export const AppShell: React.FC = () => {
  const { domain, epoch, witnessStatus } = useArenaStore();
  const location = useLocation();

  return (
    <div className="min-h-screen bg-bg text-tx font-body flex flex-col relative selection:bg-cy selection:text-bg">
      {/* Background System */}
      <Backdrop />

      {/* Top Telemetry & Control Bar */}
      <header className="sticky top-0 z-40 bg-s1/90 backdrop-blur-md border-b border-bd select-none">
        <div className="max-w-[1440px] mx-auto px-4 sm:px-6 py-2.5 flex flex-wrap items-center justify-between gap-4">
          {/* Logo & Identity */}
          <div className="flex items-center gap-4">
            <NavLink
              to="/"
              className="flex items-center gap-2.5 group focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-cy rounded p-0.5"
            >
              <div className="w-7 h-7 rounded border border-cy/40 bg-cy/10 flex items-center justify-center text-cy group-hover:border-cy transition-colors">
                <Shield className="w-4 h-4 stroke-[1.75]" />
              </div>
              <div className="flex items-baseline gap-1 font-display tracking-wider text-xl">
                <span className="text-tx">BLINDSHIELD</span>
                <span className="text-cy">ARENA</span>
              </div>
            </NavLink>

            {/* Separator */}
            <div className="hidden md:block h-4 w-px bg-bd" />

            {/* Domain & Witness Status */}
            <div className="hidden lg:flex items-center gap-3 font-mono text-[11px] text-mut">
              <span>
                DOMAIN: <strong className="text-tx">{domain}</strong>
              </span>
              <span>·</span>
              <EpochBadge epoch={epoch} size="sm" />
              <span>·</span>
              <span className="flex items-center gap-1.5">
                <span className="text-mut">WITNESS:</span>
                <span className="w-1.5 h-1.5 rounded-full bg-ok animate-pulse" />
                <span className="text-ok font-bold">{witnessStatus}</span>
              </span>
            </div>
          </div>

          {/* Right Controls: Role Switcher, Command Palette Trigger */}
          <div className="flex items-center gap-2.5">
            <RoleSwitcher />

            {/* Command Palette Trigger */}
            <button
              type="button"
              onClick={() => {
                window.dispatchEvent(
                  new KeyboardEvent('keydown', { key: 'k', metaKey: true, bubbles: true })
                );
              }}
              className="hidden sm:flex items-center gap-1.5 px-2 py-1 rounded border border-bd bg-s2/70 text-mut hover:text-tx hover:border-cy text-[11px] font-mono transition-colors"
              title="Open Command Palette (Cmd+K)"
            >
              <Command className="w-3 h-3 text-cy" />
              <span className="tabular-nums">⌘K</span>
            </button>
          </div>
        </div>

        {/* Global Navigation Strip */}
        <nav
          aria-label="Arena subsystems"
          className="border-t border-bd/60 bg-s2/30 font-mono text-xs overflow-x-auto"
        >
          <div className="max-w-[1440px] mx-auto px-4 sm:px-6 flex items-center gap-1">
            {NAV_ITEMS.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.to === '/'}
                className={({ isActive }) =>
                  cn(
                    'relative py-2 px-3 flex items-center gap-1.5 uppercase tracking-wider text-[11px] transition-colors whitespace-nowrap',
                    isActive
                      ? 'text-cy font-bold border-b-2 border-cy bg-cy/5'
                      : 'text-mut hover:text-tx hover:bg-s2/40'
                  )
                }
              >
                <span className="text-[10px] text-mut tabular-nums">{item.numeral}</span>
                <span>{item.label}</span>
              </NavLink>
            ))}
          </div>
        </nav>
      </header>

      {/* Main Page Route Outlet with Framer Motion AnimatePresence and ErrorBoundary */}
      <main className="flex-1 max-w-[1440px] w-full mx-auto p-4 sm:p-6 lg:p-8">
        <ErrorBoundary>
          <AnimatePresence mode="wait">
            <motion.div
              key={location.pathname}
              variants={FADE_VARIANTS}
              initial="initial"
              animate="animate"
              exit="exit"
            >
              <React.Suspense fallback={<RouteLoadingFallback />}>
                <Outlet />
              </React.Suspense>
            </motion.div>
          </AnimatePresence>
        </ErrorBoundary>
      </main>

      {/* Operator & Auditor Assured Footer */}
      <footer className="border-t border-bd bg-s1/80 backdrop-blur-sm text-mut font-mono text-[11px] py-3 select-none">
        <div className="max-w-[1440px] mx-auto px-4 sm:px-6 flex flex-wrap items-center justify-between gap-3">
          <div className="flex flex-wrap items-center gap-3">
            <span>
              TCB <strong className="text-tx">v0.4.2</strong>
            </span>
            <span className="text-mut">·</span>
            <span>
              PINNED MODEL: <strong className="text-tx">llama-3.1-8b-instruct</strong>
            </span>
            <span className="text-mut">·</span>
            <span>
              BROKER OVERHEAD: <strong className="text-ok">38ms</strong> (p95 ≤ 100ms)
            </span>
          </div>

          <div className="flex items-center gap-3 text-mut text-[10px]">
            <span>TELEMETRY: DELAYED T-30s</span>
            <span>·</span>
            <span className="text-cy">ASSURANCE GRADE: TAMPER-EVIDENT</span>
          </div>
        </div>
      </footer>

      {/* Global Command Palette */}
      <CommandPalette />
    </div>
  );
};

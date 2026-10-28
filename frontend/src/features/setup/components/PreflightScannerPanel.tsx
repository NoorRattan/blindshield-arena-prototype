import React, { useRef } from 'react';
import { useReducedMotion } from 'framer-motion';
import {
  CheckCircle2,
  XCircle,
  HelpCircle,
  RefreshCw,
  Server,
  ExternalLink,
} from 'lucide-react';
import { Panel } from '../../../components/Panel';
import { gsap, useGSAP } from '../../../design/gsap';
import type { PreflightReport } from '../types';
import { cn } from '../../../lib/cn';

interface PreflightScannerPanelProps {
  report: PreflightReport | null;
  isScanning: boolean;
  onRunScan: () => void;
}

export const PreflightScannerPanel: React.FC<PreflightScannerPanelProps> = ({
  report,
  isScanning,
  onRunScan,
}) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const shouldReduceMotion = useReducedMotion();

  // GSAP-sequenced scan animation
  useGSAP(
    () => {
      if (shouldReduceMotion || !report || isScanning) return;

      const mm = gsap.matchMedia(containerRef);
      mm.add('(prefers-reduced-motion: no-preference)', () => {
        gsap.killTweensOf('.preflight-row');
        gsap.fromTo(
          '.preflight-row',
          { opacity: 0, x: -10 },
          {
            opacity: 1,
            x: 0,
            stagger: 0.03,
            duration: 0.2,
            ease: 'power2.out',
            clearProps: 'transform,opacity',
          }
        );
      });
    },
    { dependencies: [report, isScanning, shouldReduceMotion], scope: containerRef }
  );

  const checks = report?.checks ?? [];
  const requiredChecks = checks.filter((c) => c.isRequired);
  const passedRequired = requiredChecks.filter((c) => c.status === 'PASS').length;
  const isOverallPass = report?.overall_status === 'PASS';

  return (
    <div ref={containerRef}>
      <Panel
        label="03 — INFRASTRUCTURE PREFLIGHT SCANNER"
        meta={report ? `HOST: ${report.host_id}` : 'SCAN PENDING'}
        actions={
          <button
            type="button"
            onClick={onRunScan}
            disabled={isScanning}
            className="inline-flex items-center gap-1.5 px-3 py-1 bg-s2 border border-bd text-tx font-mono text-[11px] uppercase tracking-wider rounded-[2px] hover:border-cy disabled:opacity-40 transition-colors focus:outline-none focus:ring-1 focus:ring-cy"
          >
            <RefreshCw className={cn('w-3 h-3 text-cy', isScanning && 'animate-spin')} />
            <span>{isScanning ? 'SCANNING...' : 'RE-RUN SCAN'}</span>
          </button>
        }
        className="p-5"
      >
      {/* Overall Status Banner */}
      <div className="mb-5">
        {isScanning ? (
          <div className="p-3 bg-cy/5 border border-cy/30 rounded-[2px] flex items-center justify-between font-mono text-xs text-cy animate-pulse">
            <span className="flex items-center gap-2">
              <RefreshCw className="w-4 h-4 animate-spin text-cy" />
              RUNNING HOST PREFLIGHT VERIFICATION SCAN...
            </span>
            <span className="text-[10px] text-mut uppercase">WAITING FOR AUDIT RECEIPT</span>
          </div>
        ) : isOverallPass ? (
          <div className="p-3 bg-ok/10 border border-ok/40 rounded-[2px] flex items-center justify-between font-mono text-xs text-ok">
            <span className="flex items-center gap-2 font-semibold">
              <CheckCircle2 className="w-4 h-4 text-ok stroke-[2]" />
              PREFLIGHT CLEARED · {passedRequired} OF {requiredChecks.length} REQUIRED CHECKS PASSED
            </span>
            <span className="text-[10px] text-mut uppercase">READY FOR WITNESS REGISTRATION</span>
          </div>
        ) : (
          <div className="p-3 bg-bad/10 border border-bad/40 rounded-[2px] flex items-center justify-between font-mono text-xs text-bad">
            <span className="flex items-center gap-2 font-semibold">
              <XCircle className="w-4 h-4 text-bad stroke-[2]" />
              PREFLIGHT FAILED · REQUIRED INFRASTRUCTURE CHECKS FAILED
            </span>
            <span className="text-[10px] text-bad uppercase font-bold">REGISTRATION BLOCKED</span>
          </div>
        )}
      </div>

      {/* Preflight Checks List */}
      <div
        tabIndex={0}
        role="region"
        aria-label="Preflight checks table"
        className="space-y-2 focus:outline-none focus:ring-1 focus:ring-cy rounded-[2px]"
      >
        {checks.map((check) => {
          const isPass = check.status === 'PASS';
          const isFail = check.status === 'FAIL';
          const isNotEnabled = check.status === 'NOT_ENABLED';

          return (
            <div
              key={check.id}
              className={cn(
                'preflight-row p-3 rounded-[2px] border transition-colors flex flex-col sm:flex-row sm:items-center justify-between gap-3',
                isFail
                  ? 'bg-bad/5 border-bad/30'
                  : isPass
                    ? 'bg-s2/60 border-bd'
                    : 'bg-s1 border-bd'
              )}
            >
              {/* Check Header & Details */}
              <div className="flex items-start gap-3 min-w-0">
                <div className="mt-0.5 shrink-0">
                  {isPass && <CheckCircle2 className="w-4 h-4 text-ok stroke-[2]" />}
                  {isFail && <XCircle className="w-4 h-4 text-bad stroke-[2]" />}
                  {isNotEnabled && <HelpCircle className="w-4 h-4 text-mut stroke-[1.5]" />}
                </div>

                <div className="min-w-0">
                  <div className="flex items-center gap-2 flex-wrap mb-1">
                    <span className="font-mono text-xs font-semibold text-tx">
                      {check.name}
                    </span>
                    <span className="font-mono text-[9px] uppercase px-1.5 py-0.2 bg-s1 border border-bd text-mut rounded-[2px]">
                      {check.category}
                    </span>
                    {check.latency_ms !== undefined && check.latency_ms > 0 && (
                      <span className="font-mono text-[10px] text-mut tabular-nums">
                        {check.latency_ms}ms
                      </span>
                    )}
                  </div>
                  <p className="font-sans text-xs text-mut truncate mb-1">
                    {check.detail}
                  </p>
                  <div className="flex items-center gap-1 font-mono text-[10px] text-mut">
                    <Server className="w-3 h-3 text-mut shrink-0" />
                    <span className="truncate">evidence: {check.evidence_link}</span>
                    <ExternalLink className="w-2.5 h-2.5 text-mut ml-0.5 shrink-0" />
                  </div>
                </div>
              </div>

              {/* Status Pill */}
              <div className="shrink-0 self-start sm:self-center">
                {isPass && (
                  <span className="inline-flex items-center gap-1 px-2.5 py-0.5 font-mono text-[11px] font-bold text-ok bg-ok/10 border border-ok/30 rounded-[2px] tracking-wider uppercase">
                    PASS
                  </span>
                )}
                {isFail && (
                  <span className="inline-flex items-center gap-1 px-2.5 py-0.5 font-mono text-[11px] font-bold text-bad bg-bad/10 border border-bad/30 rounded-[2px] tracking-wider uppercase">
                    FAIL
                  </span>
                )}
                {isNotEnabled && (
                  <span className="inline-flex items-center gap-1 px-2 py-0.5 font-mono text-[10px] font-medium text-tx bg-s2 border border-bd rounded-[2px] tracking-wider uppercase">
                    NOT ENABLED (FUTURE WORK)
                  </span>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </Panel>
  </div>
);
};

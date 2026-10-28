import React from 'react';
import {
  CheckCircle2,
  XCircle,
  Clock,
  Download,
  Play,
  Loader2,
  ShieldAlert,
  ArrowRight,
} from 'lucide-react';
import { Panel } from '../../components/Panel';
import { exportVerificationReportJson } from './verifierCore';
import type { VerificationChecklistRow, VerificationReport } from './types';

interface VerificationChecklistPanelProps {
  report: VerificationReport | null;
  isVerifying: boolean;
  onRunVerify: () => void;
  onSelectBlock?: (seq: number) => void;
  className?: string;
}

export const VerificationChecklistPanel: React.FC<VerificationChecklistPanelProps> = ({
  report,
  isVerifying,
  onRunVerify,
  onSelectBlock,
  className,
}) => {
  const handleExport = () => {
    if (!report) return;
    const jsonStr = exportVerificationReportJson(report);
    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `verification-report-${report.bundle_summary.experiment_id}-e${report.bundle_summary.epoch}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const renderStatusBadge = (status: VerificationChecklistRow['status'], code: string) => {
    if (status === 'PASS') {
      return (
        <span className="inline-flex items-center gap-1 text-[11px] font-semibold text-ok bg-s2 border border-ok/30 px-2 py-0.5 rounded-[2px]">
          <CheckCircle2 size={12} />
          PASS
        </span>
      );
    }
    if (status === 'FAIL') {
      return (
        <span className="inline-flex items-center gap-1 text-[11px] font-semibold text-bad bg-s2 border border-bad/40 px-2 py-0.5 rounded-[2px]">
          <XCircle size={12} />
          FAIL ({code})
        </span>
      );
    }
    return (
      <span className="inline-flex items-center gap-1 text-[11px] font-semibold text-mut bg-s2 border border-bd px-2 py-0.5 rounded-[2px]">
        <Clock size={12} />
        SKIPPED
      </span>
    );
  };

  return (
    <Panel
      aria-label="9-Point Verification Checklist"
      label="03 — CRYPTOGRAPHIC VERIFICATION CHECKLIST"
      meta={report ? `COMPUTED IN ${report.duration_ms}ms · NOBLE WORKER` : 'OFFLINE ENGINE'}
      className={className}
    >
      <div className="space-y-4 font-mono">
        {/* Verification Trigger & Report Export Action Bar */}
        <div className="flex flex-wrap items-center justify-between gap-2 pb-3 border-b border-bd/60">
          <button
            type="button"
            onClick={onRunVerify}
            disabled={isVerifying}
            className="px-3 py-1.5 rounded-[2px] bg-cy text-bg font-semibold text-xs flex items-center gap-1.5 hover:bg-cy/90 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cy disabled:opacity-50"
          >
            {isVerifying ? (
              <>
                <Loader2 size={13} className="animate-spin" />
                VERIFYING OFFLINE...
              </>
            ) : (
              <>
                <Play size={13} />
                RUN VERIFICATION
              </>
            )}
          </button>

          <button
            type="button"
            onClick={handleExport}
            disabled={!report}
            className="px-3 py-1.5 rounded-[2px] bg-s2 border border-bd text-tx text-xs flex items-center gap-1.5 hover:border-cy transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cy disabled:opacity-40"
          >
            <Download size={13} className="text-cy" />
            EXPORT REPORT (.JSON)
          </button>
        </div>

        {/* Three Verdicts Header Strip (Spec C-04) */}
        {report && (
          <div className="p-3 bg-s2 border border-bd rounded-[2px] space-y-3">
            <div className="text-[11px] uppercase tracking-wider text-mut font-semibold flex items-center justify-between">
              <span>Three Independent Verdicts (Spec C-04)</span>
              <span className="text-[10px] text-mut">{report.timestamp_utc}</span>
            </div>

            <div className="grid grid-cols-3 gap-2 text-xs">
              <div data-testid="verdict-authenticity" className="p-2 rounded-[2px] bg-s1 border border-bd/60">
                <div className="text-[10px] text-mut uppercase">Authenticity</div>
                <div className="mt-1 flex items-center gap-1 font-semibold">
                  {report.verdicts.authenticity === 'PASS' ? (
                    <span className="text-ok flex items-center gap-1">
                      <CheckCircle2 size={12} /> PASS (Pinned)
                    </span>
                  ) : report.verdicts.authenticity === 'UNTRUSTED' ? (
                    <span className="text-am flex items-center gap-1">
                      <ShieldAlert size={12} /> UNTRUSTED
                    </span>
                  ) : (
                    <span className="text-bad flex items-center gap-1">
                      <XCircle size={12} /> REJECTED
                    </span>
                  )}
                </div>
              </div>

              <div data-testid="verdict-completeness" className="p-2 rounded-[2px] bg-s1 border border-bd/60">
                <div className="text-[10px] text-mut uppercase">Completeness</div>
                <div className="mt-1 flex items-center gap-1 font-semibold">
                  {report.verdicts.completeness === 'PASS' ? (
                    <span className="text-ok flex items-center gap-1">
                      <CheckCircle2 size={12} /> PASS (Complete)
                    </span>
                  ) : (
                    <span className="text-bad flex items-center gap-1">
                      <XCircle size={12} /> INCOMPLETE
                    </span>
                  )}
                </div>
              </div>

              <div data-testid="verdict-integrity" className="p-2 rounded-[2px] bg-s1 border border-bd/60">
                <div className="text-[10px] text-mut uppercase">Experimental Integrity</div>
                <div className="mt-1 flex items-center gap-1 font-semibold">
                  {report.verdicts.experimentalIntegrity === 'PASS' ? (
                    <span className="text-ok flex items-center gap-1">
                      <CheckCircle2 size={12} /> PASS (Unbroken)
                    </span>
                  ) : (
                    <span className="text-bad flex items-center gap-1">
                      <XCircle size={12} /> TAMPERED
                    </span>
                  )}
                </div>
              </div>
            </div>

            {/* Overall Verdict Banner */}
            <div
              data-testid="overall-verdict-chip"
              className={`p-2.5 rounded-[2px] border flex items-center justify-between ${
                report.overall_verdict === 'VALID_WITHIN_PROFILE'
                  ? 'bg-ok/10 border-ok/40 text-ok'
                  : 'bg-bad/10 border-bad/40 text-bad'
              }`}
            >
              <div>
                <div className="text-[10px] text-mut uppercase font-semibold">Overall Verification Verdict</div>
                <div className="text-sm font-bold tracking-wider mt-0.5">
                  {report.overall_verdict === 'VALID_WITHIN_PROFILE'
                    ? 'VALID_WITHIN_PROFILE'
                    : `REJECTED (${report.rejection_code})`}
                </div>
              </div>
              <div className="text-right text-[11px] text-mut">
                {report.overall_verdict === 'VALID_WITHIN_PROFILE'
                  ? 'Checks passed within declared assurance profile'
                  : 'Tampering or trust anchor mismatch detected'}
              </div>
            </div>
          </div>
        )}

        {/* 9-Point Checklist Table / Rows */}
        <div className="space-y-2">
          {report ? (
            report.checklist.map((row, idx) => (
              <div
                key={row.id}
                className={`p-2.5 rounded-[2px] border transition-colors ${
                  row.status === 'FAIL'
                    ? 'bg-bad/5 border-bad/40'
                    : 'bg-s2/60 border-bd/60 hover:border-bd'
                }`}
              >
                <div className="flex items-start justify-between gap-2">
                  <div className="space-y-0.5">
                    <div className="flex items-center gap-2">
                      <span className="text-[10px] text-mut">{String(idx + 1).padStart(2, '0')}.</span>
                      <span className="text-xs font-semibold text-tx">{row.name}</span>
                    </div>
                    <div className="text-[11px] text-mut pl-5 break-words">{row.detail}</div>
                  </div>

                  <div className="flex items-center gap-2 shrink-0">
                    {row.failingSeq !== undefined && onSelectBlock && (
                      <button
                        type="button"
                        onClick={() => onSelectBlock(row.failingSeq!)}
                        className="px-1.5 py-0.5 rounded-[2px] bg-s1 border border-bad/60 text-[10px] text-bad hover:bg-bad/10 flex items-center gap-0.5"
                        title={`Inspect failing block seq ${row.failingSeq}`}
                      >
                        Seq #{row.failingSeq}
                        <ArrowRight size={10} />
                      </button>
                    )}
                    {renderStatusBadge(row.status, row.code)}
                  </div>
                </div>
              </div>
            ))
          ) : (
            <div className="p-6 text-center text-mut text-xs border border-dashed border-bd rounded-[2px]">
              Ready to verify. Click &quot;Run Verification&quot; to execute all 9 cryptographic checks offline.
            </div>
          )}
        </div>
      </div>
    </Panel>
  );
};

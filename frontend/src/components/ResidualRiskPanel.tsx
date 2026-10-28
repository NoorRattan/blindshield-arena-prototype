import React from 'react';
import { Panel } from './Panel';
import { StatusPill, type StatusValue } from './StatusPill';
import { ShieldAlert, Info } from 'lucide-react';
import { cn } from '../lib/cn';

export interface ThreatScopeRow {
  threat: string;
  scope: StatusValue;
  evidence: StatusValue;
  consequence: string;
  whatRemains: string;
}

export const COMMITTED_THREAT_SCOPE: ThreatScopeRow[] = [
  {
    threat: 'Malicious tenant code (red, blue, model)',
    scope: 'IN SCOPE',
    evidence: 'TESTED (profile)',
    consequence: 'Isolation, default-deny, role-scoped views, frozen defense',
    whatRemains: 'Zero-day kernel escapes, hardware microcode errata',
  },
  {
    threat: 'Red–blue collusion',
    scope: 'BOUNDED',
    evidence: 'NOT MEASURED',
    consequence: 'Channel capacity bounded (bits/query); never claims "zero"',
    whatRemains: 'Covert timing modulation below statistical detection floor',
  },
  {
    threat: 'Curious non-root operators (logs/dashboards)',
    scope: 'IN SCOPE',
    evidence: 'TESTED (profile)',
    consequence: 'Role-scoped, delayed monitoring labeled DELAYED T-30s',
    whatRemains: 'Direct out-of-band host console inspection by root',
  },
  {
    threat: 'Host root, cloud provider, hypervisor',
    scope: 'OUT OF SCOPE',
    evidence: 'NOT ENABLED',
    consequence: 'Signed audit trail + external anchor; confidential computing NOT ENABLED',
    whatRemains: 'Direct host RAM inspection and hypervisor memory tampering',
  },
  {
    threat: 'Microarchitectural side channels',
    scope: 'PARTIAL',
    evidence: 'NOT VERIFIED',
    consequence: 'Dedicated cpusets, SMT sharing off, reply duration shaping',
    whatRemains: 'Cross-core L3 cache eviction and speculative branch execution leaks',
  },
];

export interface ResidualRiskPanelProps {
  className?: string;
  compact?: boolean;
  evidenceStatusOverride?: StatusValue;
}

export const ResidualRiskPanel: React.FC<ResidualRiskPanelProps> = ({
  className,
  compact = false,
  evidenceStatusOverride,
}) => {
  return (
    <Panel
      label="00 — THREAT SCOPE & RESIDUAL RISK (Q-005)"
      meta="ASSURANCE BOUNDARIES"
      className={cn('w-full', className)}
    >
      <div className="space-y-4">
        {/* Scope header disclaimer */}
        <div className="flex items-start gap-2.5 p-3 rounded bg-s2/40 border border-bd text-xs font-mono text-mut leading-relaxed">
          <Info className="w-4 h-4 text-cy shrink-0 mt-0.5" />
          <div>
            <p className="text-tx font-medium">HONEST ASSURANCE POLICY</p>
            <p className="mt-0.5">
              Consistent with a trusted recorded history. Does not prove the recorder was honest,
              every event was captured, or the model is safe. Bounded within declared evaluation profile.
            </p>
          </div>
        </div>

        {/* Tabular threat scope matrix */}
        <div
          tabIndex={0}
          role="region"
          aria-label="Committed Threat Scope and Residual Risk Matrix"
          className="overflow-x-auto border border-bd rounded focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-cy"
        >
          <table className="w-full text-left font-mono text-xs border-collapse">
            <thead>
              <tr className="border-b border-bd bg-s2/80 text-mut uppercase text-[11px] tracking-wider">
                <th scope="col" className="p-3 font-medium">Actor / Threat Vector</th>
                <th scope="col" className="p-3 font-medium">Scope</th>
                <th scope="col" className="p-3 font-medium">Evidence Status</th>
                {!compact && <th scope="col" className="p-3 font-medium">Mitigation Mechanism</th>}
                <th scope="col" className="p-3 font-medium">Residual Risk (What Remains)</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-bd">
              {COMMITTED_THREAT_SCOPE.map((row) => (
                <tr key={row.threat} className="hover:bg-s2/30 transition-colors">
                  <td className="p-3 text-tx font-medium">
                    {row.threat}
                  </td>
                  <td className="p-3 whitespace-nowrap">
                    <StatusPill status={row.scope} size="sm" />
                  </td>
                  <td className="p-3 whitespace-nowrap">
                    <StatusPill status={evidenceStatusOverride ?? row.evidence} size="sm" />
                  </td>
                  {!compact && (
                    <td className="p-3 text-mut text-[11px]">
                      {row.consequence}
                    </td>
                  )}
                  <td className="p-3 text-mut text-[11px] flex items-center gap-1.5">
                    <ShieldAlert className="w-3.5 h-3.5 text-mut shrink-0" />
                    <span className="text-mut">{row.whatRemains}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </Panel>
  );
};

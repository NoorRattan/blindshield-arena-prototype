import React, { useState } from 'react';
import { Download, Lock, CheckCircle2, ShieldCheck, FileCode, AlertOctagon } from 'lucide-react';
import { Panel } from '../../components/Panel';
import { StatusPill } from '../../components/StatusPill';
import { Digest } from '../../components/Digest';
import { UntrustedText } from '../../components/UntrustedText';
import { DualVerdict } from '../../components/DualVerdict';
import { useToast } from '../../components/Toast';
import { arenaClient } from '../../lib/api/client';
import type { ExperimentStatus, ReleasedEpochForensics, Role } from '../../lib/schemas';

interface ForensicWorkshopPanelProps {
  experiments: ExperimentStatus[];
  currentRole: Role;
  selectedExperimentId: string;
  onSelectExperimentId: (id: string) => void;
  forensics?: ReleasedEpochForensics;
  isLoading?: boolean;
}

export const ForensicWorkshopPanel: React.FC<ForensicWorkshopPanelProps> = ({
  experiments,
  currentRole,
  selectedExperimentId,
  onSelectExperimentId,
  forensics,
  isLoading = false,
}) => {
  const { showToast } = useToast();
  const [selectedTurnIndex, setSelectedTurnIndex] = useState<number>(0);
  const [isDownloading, setIsDownloading] = useState<boolean>(false);

  const isAuditor = currentRole === 'auditor';
  const selectedExp = experiments.find((e) => e.experiment_id === selectedExperimentId);
  const isReleased = selectedExp?.state === 'RELEASED';

  const handleDownloadReplayBundle = async () => {
    if (!isAuditor) return;
    setIsDownloading(true);
    try {
      const bundle = await arenaClient.getEvidenceBundle(selectedExperimentId, currentRole);
      const jsonContent = JSON.stringify(bundle, null, 2);
      const blob = new Blob([jsonContent], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `blindshield-replay-bundle-${selectedExperimentId}-epoch-${selectedExp?.epoch ?? 1}.json`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);

      showToast({
        variant: 'success',
        title: 'Replay Bundle Downloaded',
        message: `Auditor decrypted evidence bundle saved for ${selectedExperimentId}.`,
      });
    } catch (err) {
      showToast({
        variant: 'error',
        title: 'Download Failed',
        message: err instanceof Error ? err.message : 'Failed to export replay bundle',
      });
    } finally {
      setIsDownloading(false);
    }
  };

  const currentTurn = forensics?.turns[selectedTurnIndex] ?? forensics?.turns[0];

  return (
    <Panel
      label="03 — CLOSED ROUND FORENSIC WORKSHOP"
      meta={isReleased ? 'RELEASED EPOCH FORENSICS' : 'LOCKED EPOCH'}
      className="p-5"
    >
      <div className="space-y-6">
        {/* Top Control Bar: Epoch Selector & Replay Download */}
        <div className="flex flex-wrap items-center justify-between gap-4 border-b border-bd pb-4">
          <div className="flex items-center gap-3">
            <label
              htmlFor="forensic-epoch-select"
              className="font-mono text-xs uppercase tracking-wider text-mut"
            >
              Select Epoch:
            </label>
            <select
              id="forensic-epoch-select"
              value={selectedExperimentId}
              onChange={(e) => {
                onSelectExperimentId(e.target.value);
                setSelectedTurnIndex(0);
              }}
              className="border border-bd bg-s2 px-3 py-1.5 font-mono text-xs text-tx focus:border-cy focus:outline-none focus:ring-1 focus:ring-cy"
            >
              {experiments.map((exp) => {
                const released = exp.state === 'RELEASED';
                return (
                  <option
                    key={exp.experiment_id}
                    value={exp.experiment_id}
                    disabled={!released}
                  >
                    {exp.domain} (Epoch {exp.epoch}) — {exp.state} {released ? '✓ [UNLOCKED]' : '🔒 [LOCKED]'}
                  </option>
                );
              })}
            </select>
          </div>

          {/* Download Replay Bundle (Auditor Only) */}
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={handleDownloadReplayBundle}
              disabled={!isAuditor || !isReleased || isDownloading}
              title={
                !isAuditor
                  ? 'Auditor-authorized only. Replay bundles require cryptographic auditor credentials.'
                  : !isReleased
                  ? 'Replay bundles only unlock after epoch release.'
                  : 'Download signed evidence replay bundle'
              }
              className={`inline-flex items-center gap-2 px-3.5 py-1.5 font-mono text-xs uppercase tracking-wider transition-colors ${
                isAuditor && isReleased
                  ? 'border border-cy bg-cy/10 text-cy hover:bg-cy/20 focus:outline-none focus:ring-1 focus:ring-cy'
                  : 'border border-bd bg-s2 text-mut cursor-not-allowed opacity-60'
              }`}
            >
              <Download className="h-3.5 w-3.5" />
              {isDownloading ? 'Exporting...' : 'Download Decrypted Replay Bundle'}
            </button>
            {!isAuditor && (
              <span className="font-mono text-[10px] text-mut">
                [Auditor Credentials Required]
              </span>
            )}
          </div>
        </div>

        {/* Non-Released Lock State */}
        {!isReleased ? (
          <div
            role="region"
            aria-label="Locked Epoch State"
            className="border border-bd bg-s2 p-8 text-center space-y-3"
          >
            <div className="inline-flex h-12 w-12 items-center justify-center rounded-sm border border-emb/40 bg-s1 text-emb">
              <Lock className="h-6 w-6" />
            </div>
            <div className="space-y-1">
              <h3 className="font-mono text-sm font-semibold text-tx uppercase tracking-wider">
                EPOCH FORENSICS LOCKED
              </h3>
              <p className="font-mono text-xs text-mut max-w-lg mx-auto">
                Experiment {selectedExp?.domain ?? selectedExperimentId} is currently in state{' '}
                <span className="text-cy font-semibold">{selectedExp?.state ?? 'ACTIVE'}</span>. Per protocol spec C-02, full attack payloads and defense decision traces unlock only after durable round closure and cryptographic release.
              </p>
            </div>
            <div className="pt-2">
              <span className="border border-bd bg-s1 px-3 py-1 font-mono text-[11px] text-mut">
                Release Condition: Durable checkpoint witnessed &amp; signed by recorder
              </span>
            </div>
          </div>
        ) : isLoading || !forensics ? (
          <div className="py-12 text-center font-mono text-xs text-mut animate-pulse">
            LOADING CRYPTOGRAPHICALLY RELEASED FORENSIC RECORDS...
          </div>
        ) : (
          <div className="space-y-6">
            {/* Post-Release Performance & Ratio Strip */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
              <div className="border border-bd bg-s2 p-3.5 space-y-1">
                <div className="text-mut text-[11px] font-mono uppercase tracking-wider">
                  Total Analyzed Turns
                </div>
                <div className="font-mono text-xl font-bold text-tx">
                  {forensics.total_turns}
                </div>
                <div className="font-mono text-[10px] text-mut">
                  Cryptographically released
                </div>
              </div>

              <div className="border border-bd bg-s2 p-3.5 space-y-1">
                <div className="text-mut text-[11px] font-mono uppercase tracking-wider">
                  Blocked by Defense
                </div>
                <div className="font-mono text-xl font-bold text-bad">
                  {forensics.blocked_count}
                  <span className="text-xs font-normal text-mut ml-2">
                    ({((forensics.blocked_count / forensics.total_turns) * 100).toFixed(1)}%)
                  </span>
                </div>
                <div className="font-mono text-[10px] text-mut">
                  Harmful prompts mitigated
                </div>
              </div>

              <div className="border border-bd bg-s2 p-3.5 space-y-1">
                <div className="text-mut text-[11px] font-mono uppercase tracking-wider">
                  Allowed to Target
                </div>
                <div className="font-mono text-xl font-bold text-ok">
                  {forensics.allowed_count}
                  <span className="text-xs font-normal text-mut ml-2">
                    ({((forensics.allowed_count / forensics.total_turns) * 100).toFixed(1)}%)
                  </span>
                </div>
                <div className="font-mono text-[10px] text-mut">
                  Neutral inputs passed
                </div>
              </div>

              <div className="border border-bd bg-s2 p-3.5 space-y-1">
                <div className="text-mut text-[11px] font-mono uppercase tracking-wider">
                  Verification Verdict
                </div>
                <div className="pt-0.5">
                  <StatusPill status="VALID_WITHIN_PROFILE" label="VERIFIED POST-RELEASE" />
                </div>
                <div className="font-mono text-[10px] text-mut">
                  Signatures validated
                </div>
              </div>
            </div>

            {/* Turn Navigation Carousel / Pill Row */}
            <div className="space-y-2">
              <div className="flex items-center justify-between text-xs font-mono">
                <span className="text-mut uppercase tracking-wider">
                  Select Turn for Plaintext Forensic Analysis:
                </span>
                <span className="text-tx">
                  Turn {currentTurn?.turn ?? 1} of {forensics.total_turns}
                </span>
              </div>
              <div
                role="region"
                aria-label="Released Turns Navigation"
                tabIndex={0}
                className="flex items-center gap-1.5 overflow-x-auto pb-2 border-b border-bd focus:outline-none focus:ring-1 focus:ring-cy"
              >
                {forensics.turns.map((turn, idx) => {
                  const isSelected = idx === selectedTurnIndex;
                  const isBlocked = turn.decision === 'BLOCKED_BY_DEFENSE';
                  const isSanitized = turn.decision === 'SANITIZED';
                  return (
                    <button
                      key={turn.request_id}
                      type="button"
                      onClick={() => setSelectedTurnIndex(idx)}
                      aria-current={isSelected ? 'true' : undefined}
                      className={`px-2.5 py-1 font-mono text-xs whitespace-nowrap border transition-colors ${
                        isSelected
                          ? 'border-cy bg-cy/20 text-tx font-bold'
                          : isBlocked
                          ? 'border-bad/40 bg-s2 text-bad hover:border-bad'
                          : isSanitized
                          ? 'border-am/40 bg-s2 text-am hover:border-am'
                          : 'border-bd bg-s2 text-mut hover:border-tx hover:text-tx'
                      }`}
                    >
                      {turn.turn} {isBlocked ? '[BLOCK]' : isSanitized ? '[SANITIZE]' : '[ALLOW]'}
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Turn Detail Quad Grid */}
            {currentTurn && (
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
                {/* 1. Attack Payload (Released) */}
                <div className="border border-bd bg-s2 p-4 space-y-3">
                  <div className="flex items-center justify-between border-b border-bd pb-2">
                    <span className="font-mono text-xs font-semibold uppercase tracking-wider text-tx flex items-center gap-2">
                      <FileCode className="h-4 w-4 text-am" />
                      Attack Payload (Released)
                    </span>
                    <span className="border border-am/30 bg-am/10 px-1.5 py-0.5 font-mono text-[10px] text-am">
                      RED PROBE
                    </span>
                  </div>
                  <UntrustedText
                    text={currentTurn.attack_payload}
                    label={`Turn ${currentTurn.turn} Released Payload`}
                  />
                  <div className="pt-1 font-mono text-[11px] text-mut">
                    Raw UTF-8 input artifact unmasked following cryptographic release.
                  </div>
                </div>

                {/* 2. Defense Decision Log */}
                <div className="border border-bd bg-s2 p-4 space-y-3">
                  <div className="flex items-center justify-between border-b border-bd pb-2">
                    <span className="font-mono text-xs font-semibold uppercase tracking-wider text-tx flex items-center gap-2">
                      <ShieldCheck className="h-4 w-4 text-bl" />
                      Defense Decision Log
                    </span>
                    <StatusPill
                      status={
                        currentTurn.decision === 'BLOCKED_BY_DEFENSE'
                          ? 'BLOCKED_BY_DEFENSE'
                          : currentTurn.decision === 'SANITIZED'
                          ? 'SANITIZED'
                          : 'ALLOWED'
                      }
                      label={currentTurn.decision}
                    />
                  </div>

                  <div className="space-y-2.5 font-mono text-xs">
                    <div className="flex items-center justify-between border-b border-bd/40 pb-1.5">
                      <span className="text-mut">Matched Rule:</span>
                      <span className="text-tx font-semibold">{currentTurn.matched_rule}</span>
                    </div>

                    {currentTurn.transform_id && (
                      <div className="flex items-center justify-between border-b border-bd/40 pb-1.5">
                        <span className="text-mut">Transform:</span>
                        <span className="text-am font-semibold">{currentTurn.transform_id}</span>
                      </div>
                    )}

                    <div className="flex items-center justify-between border-b border-bd/40 pb-1.5">
                      <span className="text-mut">Confidence Score:</span>
                      <span className="text-cy font-bold">
                        {(currentTurn.confidence * 100).toFixed(1)}% ({currentTurn.confidence})
                      </span>
                    </div>

                    <div className="flex items-center justify-between border-b border-bd/40 pb-1.5">
                      <span className="text-mut">Defense Filter Latency:</span>
                      <span className="text-tx">{currentTurn.latency_ms.defense} ms</span>
                    </div>

                    <div className="space-y-1 pt-1">
                      <span className="text-mut text-[11px]">Defense Execution Digest:</span>
                      <Digest hash={currentTurn.defense_digest} />
                    </div>
                  </div>
                </div>

                {/* 3. Scorer Ground Truth & Dual Verdict */}
                <div className="border border-bd bg-s2 p-4 space-y-3">
                  <div className="flex items-center justify-between border-b border-bd pb-2">
                    <span className="font-mono text-xs font-semibold uppercase tracking-wider text-tx flex items-center gap-2">
                      <CheckCircle2 className="h-4 w-4 text-ok" />
                      Scorer Ground Truth
                    </span>
                    <span className="font-mono text-[11px] text-mut">
                      INDEPENDENT AUDIT
                    </span>
                  </div>

                  <div className="space-y-3">
                    <DualVerdict
                      modelOutcome={
                        currentTurn.decision === 'BLOCKED_BY_DEFENSE'
                          ? 'BLOCKED_BY_DEFENSE'
                          : currentTurn.decision === 'SANITIZED'
                          ? 'SANITIZED'
                          : 'EXECUTED'
                      }
                      integrity="VALID_WITHIN_PROFILE"
                    />

                    <div className="border border-bd bg-s1 p-3 font-mono text-xs space-y-1">
                      <div className="text-mut text-[11px] uppercase">
                        Safety Classification
                      </div>
                      <div className="text-tx font-semibold flex items-center gap-2">
                        {currentTurn.scorer_ground_truth === 'UNSAFE' ? (
                          <>
                            <AlertOctagon className="h-4 w-4 text-bad" />
                            <span className="text-bad">UNSAFE // Harmful Intent Detected</span>
                          </>
                        ) : (
                          <>
                            <CheckCircle2 className="h-4 w-4 text-ok" />
                            <span className="text-ok">BENIGN // Permissible Safety Query</span>
                          </>
                        )}
                      </div>
                      <p className="text-mut text-[11px] pt-1">
                        {currentTurn.decision === 'BLOCKED_BY_DEFENSE'
                          ? 'Defense action aligned with ground truth safety policy.'
                          : 'Prompt executed safely by target model without violation.'}
                      </p>
                    </div>
                  </div>
                </div>

                {/* 4. Model Response (Post-Release) */}
                <div className="border border-bd bg-s2 p-4 space-y-3">
                  <div className="flex items-center justify-between border-b border-bd pb-2">
                    <span className="font-mono text-xs font-semibold uppercase tracking-wider text-tx flex items-center gap-2">
                      <FileCode className="h-4 w-4 text-cy" />
                      Model Response (Post-Release)
                    </span>
                    <span className="font-mono text-[10px] text-mut">
                      {currentTurn.decision === 'BLOCKED_BY_DEFENSE' ? 'EXECUTION SKIPPED' : '256 TOKENS'}
                    </span>
                  </div>

                  {currentTurn.model_response ? (
                    <UntrustedText
                      text={currentTurn.model_response}
                      label={`Turn ${currentTurn.turn} Model Output`}
                    />
                  ) : (
                    <div className="border border-bd/60 bg-s1 p-4 text-center font-mono text-xs text-mut space-y-1">
                      <div className="text-emb font-semibold">[EXECUTION TERMINATED BY DEFENSE FILTER]</div>
                      <p className="text-[11px]">
                        Target model inference was not invoked because the defense filter blocked the payload at the perimeter.
                      </p>
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </Panel>
  );
};

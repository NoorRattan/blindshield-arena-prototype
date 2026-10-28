import type { ArenaEvent, Checkpoint, Digest, Epoch, EvidenceBundleMetadata } from '../../lib/schemas';

export type ChecklistRowId =
  | 'SIGNATURE'
  | 'CANONICAL_SCHEMA'
  | 'EPOCH_EXACT_TYPE'
  | 'SEQUENCE_CONTINUITY'
  | 'CHAIN_INTEGRITY'
  | 'TERMINAL_MARKER'
  | 'MANIFEST_DIGEST'
  | 'CIPHERTEXT_DIGESTS'
  | 'WITNESS_WATERMARK';

export type ChecklistStatus = 'PASS' | 'FAIL' | 'SKIPPED';

export interface VerificationChecklistRow {
  id: ChecklistRowId;
  name: string;
  status: ChecklistStatus;
  code: string;
  detail: string;
  failingSeq?: number;
}

export type VerdictStatus = 'PASS' | 'FAIL' | 'UNTRUSTED';

export interface VerdictBreakdown {
  authenticity: VerdictStatus;
  completeness: 'PASS' | 'FAIL';
  experimentalIntegrity: 'PASS' | 'FAIL';
  overallVerdict: 'VALID_WITHIN_PROFILE' | 'REJECTED';
  rejectionCode?: string;
}

export interface VerificationTrustAnchors {
  publicKeyHex: string;
  isPinned: boolean; // Invariant 6: if false, key is UNTRUSTED and cannot yield VALID
  expectedDomain: string;
  expectedExperimentId: string;
  expectedEpoch: Epoch;
  expectedManifestDigest: Digest;
  witnessedTerminalCheckpointReceipt?: string;
}

export interface EvidenceBundle {
  metadata: EvidenceBundleMetadata;
  ledger: ArenaEvent[];
  checkpoint: Checkpoint;
}

export interface VerificationReport {
  timestamp_utc: string;
  overall_verdict: 'VALID_WITHIN_PROFILE' | 'REJECTED';
  rejection_code?: string;
  verdicts: {
    authenticity: VerdictStatus;
    completeness: 'PASS' | 'FAIL';
    experimentalIntegrity: 'PASS' | 'FAIL';
  };
  checklist: VerificationChecklistRow[];
  trust_anchors: {
    public_key_hex: string;
    is_pinned: boolean;
    expected_domain: string;
    expected_experiment_id: string;
    expected_epoch: number;
    expected_manifest_digest: string;
    witnessed_receipt?: string;
  };
  bundle_summary: {
    experiment_id: string;
    domain: string;
    epoch: number;
    event_count: number;
    final_digest: string;
    manifest_digest: string;
    protocol: string;
    terminal_receipt: string;
  };
  broken_index?: number;
  duration_ms: number;
}

export type TamperType =
  | 'flip_byte'
  | 'delete_event'
  | 'reorder_events'
  | 'truncate_chain'
  | 'replay_checkpoint'
  | 'substitute_artifact'
  | 'boolean_epoch';

export interface TamperDefinition {
  type: TamperType;
  label: string;
  description: string;
  expectedFailingCheck: ChecklistRowId;
  expectedCode: string;
}

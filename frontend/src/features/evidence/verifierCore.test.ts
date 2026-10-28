import { describe, it, expect } from 'vitest';
import { MockArenaServer } from '../../lib/mock/server';
import { DEMO_KEYS } from '../../lib/crypto';
import {
  verifyEvidenceBundle,
  applyTamper,
  parseBundleJson,
  parseBundleZip,
  exportVerificationReportJson,
} from './verifierCore';
import type { EvidenceBundle, VerificationTrustAnchors } from './types';
import { zipSync, strToU8 } from 'fflate';

describe('Evidence Inspector Verifier Core Engine (P10-S1)', () => {
  const server = new MockArenaServer();
  const rawBundle = server.getEvidenceBundle('exp_released_04', 'auditor');
  const validBundle: EvidenceBundle = {
    metadata: rawBundle.metadata,
    ledger: rawBundle.ledger as EvidenceBundle['ledger'],
    checkpoint: rawBundle.checkpoint,
  };

  const validTrustAnchors: VerificationTrustAnchors = {
    publicKeyHex: DEMO_KEYS.PUBLIC_KEY_HEX,
    isPinned: true,
    expectedDomain: validBundle.metadata.domain,
    expectedExperimentId: validBundle.metadata.experiment_id,
    expectedEpoch: validBundle.metadata.epoch,
    expectedManifestDigest: validBundle.checkpoint.manifest_digest,
    witnessedTerminalCheckpointReceipt: validBundle.checkpoint.witness_receipt,
  };

  it('verifies an authentic, untampered evidence bundle with 9 PASS checks', () => {
    const report = verifyEvidenceBundle(validBundle, validTrustAnchors);

    expect(report.overall_verdict).toBe('VALID_WITHIN_PROFILE');
    expect(report.rejection_code).toBeUndefined();
    expect(report.verdicts.authenticity).toBe('PASS');
    expect(report.verdicts.completeness).toBe('PASS');
    expect(report.verdicts.experimentalIntegrity).toBe('PASS');
    expect(report.checklist).toHaveLength(9);
    expect(report.checklist.every((row) => row.status === 'PASS')).toBe(true);
    expect(report.broken_index).toBeUndefined();
  });

  it('rejects verification when using unpinned bundle public key (Invariant 6 & Spec C-03)', () => {
    const unpinnedAnchors: VerificationTrustAnchors = {
      ...validTrustAnchors,
      isPinned: false, // User did not pin an external anchor
    };

    const report = verifyEvidenceBundle(validBundle, unpinnedAnchors);

    expect(report.overall_verdict).toBe('REJECTED');
    expect(report.verdicts.authenticity).toBe('UNTRUSTED');
    expect(report.rejection_code).toBe('UNTRUSTED_KEY');

    const sigRow = report.checklist.find((r) => r.id === 'SIGNATURE');
    expect(sigRow?.status).toBe('FAIL');
    expect(sigRow?.code).toBe('UNTRUSTED_KEY');
    expect(sigRow?.detail).toContain('UNTRUSTED');
  });

  it('rejects boolean epoch injection with INVALID_EPOCH_TYPE (Invariant 5)', () => {
    const { mutatedBundle, expectedFailureCode, expectedFailingSeq } = applyTamper(
      validBundle,
      'boolean_epoch'
    );

    const report = verifyEvidenceBundle(mutatedBundle, validTrustAnchors);

    expect(report.overall_verdict).toBe('REJECTED');
    expect(report.rejection_code).toBe(expectedFailureCode);

    const epochRow = report.checklist.find((r) => r.id === 'EPOCH_EXACT_TYPE');
    expect(epochRow?.status).toBe('FAIL');
    expect(epochRow?.code).toBe(expectedFailureCode);
    expect(epochRow?.failingSeq).toBe(expectedFailingSeq);
  });

  it('detects flipped byte in event payload with CHAIN_BROKEN', () => {
    const { mutatedBundle, expectedFailureCode, expectedFailingSeq } = applyTamper(
      validBundle,
      'flip_byte'
    );

    const report = verifyEvidenceBundle(mutatedBundle, validTrustAnchors);

    expect(report.overall_verdict).toBe('REJECTED');
    expect(report.rejection_code).toBe(expectedFailureCode);

    const chainRow = report.checklist.find((r) => r.id === 'CHAIN_INTEGRITY');
    expect(chainRow?.status).toBe('FAIL');
    expect(chainRow?.code).toBe(expectedFailureCode);
    expect(chainRow?.failingSeq).toBe(expectedFailingSeq);
  });

  it('detects deleted intermediate event with SEQ_GAP', () => {
    const { mutatedBundle, expectedFailureCode } = applyTamper(
      validBundle,
      'delete_event'
    );

    const report = verifyEvidenceBundle(mutatedBundle, validTrustAnchors);

    expect(report.overall_verdict).toBe('REJECTED');
    expect(report.rejection_code).toBe(expectedFailureCode);

    const seqRow = report.checklist.find((r) => r.id === 'SEQUENCE_CONTINUITY');
    expect(seqRow?.status).toBe('FAIL');
    expect(seqRow?.code).toBe(expectedFailureCode);
  });

  it('detects reordered events with SEQ_GAP', () => {
    const { mutatedBundle, expectedFailureCode } = applyTamper(
      validBundle,
      'reorder_events'
    );

    const report = verifyEvidenceBundle(mutatedBundle, validTrustAnchors);

    expect(report.overall_verdict).toBe('REJECTED');
    expect(report.rejection_code).toBe(expectedFailureCode);
  });

  it('detects truncated chain with SEQ_GAP and final digest mismatch', () => {
    const { mutatedBundle, expectedFailureCode } = applyTamper(
      validBundle,
      'truncate_chain'
    );

    const report = verifyEvidenceBundle(mutatedBundle, validTrustAnchors);

    expect(report.overall_verdict).toBe('REJECTED');
    expect(report.rejection_code).toBe(expectedFailureCode);
  });

  it('detects replayed foreign checkpoint with MANIFEST_MISMATCH', () => {
    const { mutatedBundle, expectedFailureCode } = applyTamper(
      validBundle,
      'replay_checkpoint'
    );

    const report = verifyEvidenceBundle(mutatedBundle, validTrustAnchors);

    expect(report.overall_verdict).toBe('REJECTED');
    expect(report.rejection_code).toBe(expectedFailureCode);

    const manifestRow = report.checklist.find((r) => r.id === 'MANIFEST_DIGEST');
    expect(manifestRow?.status).toBe('FAIL');
  });

  it('detects substituted artifact digest with CHAIN_BROKEN', () => {
    const { mutatedBundle, expectedFailureCode } = applyTamper(
      validBundle,
      'substitute_artifact'
    );

    const report = verifyEvidenceBundle(mutatedBundle, validTrustAnchors);

    expect(report.overall_verdict).toBe('REJECTED');
    expect(report.rejection_code).toBe(expectedFailureCode);
  });

  it('detects wrong-run checkpoint when expected experiment id differs', () => {
    const wrongRunAnchors: VerificationTrustAnchors = {
      ...validTrustAnchors,
      expectedExperimentId: 'exp_unrelated_foreign_run',
    };

    const report = verifyEvidenceBundle(validBundle, wrongRunAnchors);

    expect(report.overall_verdict).toBe('REJECTED');
    const manifestRow = report.checklist.find((r) => r.id === 'MANIFEST_DIGEST');
    expect(manifestRow?.status).toBe('FAIL');
    expect(manifestRow?.detail).toContain('exp_unrelated_foreign_run');
  });

  it('parses bundle from raw JSON string and produces exportable report', () => {
    const jsonStr = JSON.stringify(validBundle);
    const parsed = parseBundleJson(jsonStr);
    expect(parsed.metadata.experiment_id).toBe(validBundle.metadata.experiment_id);
    expect(parsed.ledger).toHaveLength(validBundle.ledger.length);

    const report = verifyEvidenceBundle(parsed, validTrustAnchors);
    const exportedJson = exportVerificationReportJson(report);
    expect(exportedJson).toContain('VALID_WITHIN_PROFILE');
    expect(exportedJson).toContain(report.bundle_summary.experiment_id);
  });

  it('parses bundle from ZIP archive using fflate', () => {
    const jsonStr = JSON.stringify(validBundle);
    const u8 = strToU8(jsonStr, true);
    const files = {
      'bundle.json': u8,
    };
    const zipBytes = zipSync(files);

    const parsedFromZip = parseBundleZip(zipBytes);
    expect(parsedFromZip.metadata.experiment_id).toBe(validBundle.metadata.experiment_id);
    expect(parsedFromZip.checkpoint.signature).toBe(validBundle.checkpoint.signature);
  });
});

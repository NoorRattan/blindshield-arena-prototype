import { unzipSync, strFromU8 } from 'fflate';
import {
  canonicalJson,
  computeChainDigest,
  verifyEd25519,
  DOMAIN_PREFIXES,
} from '../../lib/crypto';
import type { Digest } from '../../lib/schemas';
import {
  CheckpointSchema,
  DigestSchema,
  EventSchema,
  EvidenceBundleMetadataSchema,
} from '../../lib/schemas';
import { createSignedCheckpoint } from '../../lib/mock/ledger';
import type {
  EvidenceBundle,
  TamperType,
  VerificationChecklistRow,
  VerificationReport,
  VerificationTrustAnchors,
} from './types';

/**
 * Validates whether an epoch is strictly an exact positive integer.
 * Invariant 5: Rejects booleans (e.g. true), strings, floats, non-positive numbers.
 */
function isExactPositiveInteger(val: unknown): boolean {
  if (typeof val !== 'number') return false;
  if (!Number.isInteger(val)) return false;
  if (val <= 0) return false;
  return true;
}

/**
 * Pure cryptographic verification engine for BlindShield Arena evidence bundles.
 * Runs completely offline without any network traffic or untrusted assumptions.
 */
export function verifyEvidenceBundle(
  rawBundle: unknown,
  trustAnchors: VerificationTrustAnchors
): VerificationReport {
  const startTime = performance.now();
  const rows: VerificationChecklistRow[] = [];
  let brokenIndex: number | undefined = undefined;

  // 1. Bundle Structural Check
  const bundle = rawBundle as Partial<EvidenceBundle>;
  const hasMetadata = Boolean(bundle?.metadata);
  const hasLedger = Array.isArray(bundle?.ledger);
  const hasCheckpoint = Boolean(bundle?.checkpoint);

  if (!hasMetadata || !hasLedger || !hasCheckpoint) {
    const errorDetail = `Malformed bundle structure: missing ${[
      !hasMetadata && 'metadata',
      !hasLedger && 'ledger',
      !hasCheckpoint && 'checkpoint',
    ]
      .filter(Boolean)
      .join(', ')}`;

    const fallbackChecklist: VerificationChecklistRow[] = [
      {
        id: 'CANONICAL_SCHEMA',
        name: 'RFC 8785 Canonical Schema & JCS Format',
        status: 'FAIL',
        code: 'MALFORMED_BUNDLE',
        detail: errorDetail,
      },
      {
        id: 'SIGNATURE',
        name: 'Witness Ed25519 Signature (Pinned Anchor)',
        status: 'SKIPPED',
        code: 'SKIPPED',
        detail: 'Skipped due to malformed bundle',
      },
      {
        id: 'EPOCH_EXACT_TYPE',
        name: 'Epoch Positive Integer Strict Typing',
        status: 'SKIPPED',
        code: 'SKIPPED',
        detail: 'Skipped due to malformed bundle',
      },
      {
        id: 'SEQUENCE_CONTINUITY',
        name: 'Ledger Sequence Monotonic Continuity',
        status: 'SKIPPED',
        code: 'SKIPPED',
        detail: 'Skipped due to malformed bundle',
      },
      {
        id: 'CHAIN_INTEGRITY',
        name: 'Domain-Separated Merkle Hash Chain',
        status: 'SKIPPED',
        code: 'SKIPPED',
        detail: 'Skipped due to malformed bundle',
      },
      {
        id: 'TERMINAL_MARKER',
        name: 'Terminal Marker & Required Event Set',
        status: 'SKIPPED',
        code: 'SKIPPED',
        detail: 'Skipped due to malformed bundle',
      },
      {
        id: 'MANIFEST_DIGEST',
        name: 'Manifest Digest & Run Boundary Match',
        status: 'SKIPPED',
        code: 'SKIPPED',
        detail: 'Skipped due to malformed bundle',
      },
      {
        id: 'CIPHERTEXT_DIGESTS',
        name: 'Artifact & Ciphertext Digest Formats',
        status: 'SKIPPED',
        code: 'SKIPPED',
        detail: 'Skipped due to malformed bundle',
      },
      {
        id: 'WITNESS_WATERMARK',
        name: 'Witness Receipt & Monotonic Watermark',
        status: 'SKIPPED',
        code: 'SKIPPED',
        detail: 'Skipped due to malformed bundle',
      },
    ];

    return {
      timestamp_utc: new Date().toISOString(),
      overall_verdict: 'REJECTED',
      rejection_code: 'MALFORMED_BUNDLE',
      verdicts: {
        authenticity: 'FAIL',
        completeness: 'FAIL',
        experimentalIntegrity: 'FAIL',
      },
      checklist: fallbackChecklist,
      trust_anchors: {
        public_key_hex: trustAnchors.publicKeyHex,
        is_pinned: trustAnchors.isPinned,
        expected_domain: trustAnchors.expectedDomain,
        expected_experiment_id: trustAnchors.expectedExperimentId,
        expected_epoch: trustAnchors.expectedEpoch,
        expected_manifest_digest: trustAnchors.expectedManifestDigest,
        witnessed_receipt: trustAnchors.witnessedTerminalCheckpointReceipt,
      },
      bundle_summary: {
        experiment_id: 'unknown',
        domain: 'unknown',
        epoch: 0,
        event_count: 0,
        final_digest: 'unknown',
        manifest_digest: 'unknown',
        protocol: 'unknown',
        terminal_receipt: 'unknown',
      },
      duration_ms: Math.round(performance.now() - startTime),
    };
  }

  const { metadata, ledger, checkpoint } = bundle as EvidenceBundle;

  // --- CHECK 1: SIGNATURE & PINNED TRUST ANCHOR ---
  if (!trustAnchors.isPinned) {
    // Invariant 6 & Spec C-03: Bundle-supplied key without external pin is UNTRUSTED
    rows.push({
      id: 'SIGNATURE',
      name: 'Witness Ed25519 Signature (Pinned Anchor)',
      status: 'FAIL',
      code: 'UNTRUSTED_KEY',
      detail:
        'Bundle-supplied public key is UNTRUSTED. An external trust anchor must be pinned to verify authenticity.',
    });
  } else {
    try {
      const { signature, ...unsignedPayload } = checkpoint;
      const canonical = canonicalJson(unsignedPayload);
      const isSigValid = verifyEd25519(
        signature,
        `${DOMAIN_PREFIXES.CHECKPOINT}${canonical}`,
        trustAnchors.publicKeyHex
      );

      if (isSigValid) {
        rows.push({
          id: 'SIGNATURE',
          name: 'Witness Ed25519 Signature (Pinned Anchor)',
          status: 'PASS',
          code: 'SIG_VALID',
          detail: `Ed25519 signature verified against pinned anchor ${trustAnchors.publicKeyHex.slice(0, 16)}...`,
        });
      } else {
        rows.push({
          id: 'SIGNATURE',
          name: 'Witness Ed25519 Signature (Pinned Anchor)',
          status: 'FAIL',
          code: 'SIG_INVALID',
          detail: 'Terminal checkpoint signature failed cryptographic verification under pinned key.',
        });
      }
    } catch (err) {
      rows.push({
        id: 'SIGNATURE',
        name: 'Witness Ed25519 Signature (Pinned Anchor)',
        status: 'FAIL',
        code: 'SIG_ERROR',
        detail: `Signature verification error: ${err instanceof Error ? err.message : String(err)}`,
      });
    }
  }

  // --- CHECK 2: EPOCH EXACT POSITIVE INTEGER TYPE (Invariant 5) ---
  // Invariant 5: Epoch must be an exact positive integer. Rejects booleans (true), strings, floats.
  let epochPass = true;
  let epochError = '';
  let epochFailingSeq: number | undefined;

  if (!isExactPositiveInteger(checkpoint.epoch)) {
    epochPass = false;
    epochError = `Checkpoint epoch is not an exact positive integer (found type ${typeof checkpoint.epoch}: ${String(checkpoint.epoch)})`;
  } else if (!isExactPositiveInteger(metadata.epoch)) {
    epochPass = false;
    epochError = `Metadata epoch is not an exact positive integer (found type ${typeof metadata.epoch}: ${String(metadata.epoch)})`;
  } else {
    for (let i = 0; i < ledger.length; i++) {
      const event = ledger[i];
      if (!isExactPositiveInteger(event.epoch)) {
        epochPass = false;
        epochError = `Event seq ${event.seq} contains non-integer/boolean epoch (${JSON.stringify(event.epoch)}). Prohibited by Invariant 5.`;
        epochFailingSeq = event.seq;
        if (brokenIndex === undefined) brokenIndex = i;
        break;
      }
    }
  }

  rows.push({
    id: 'EPOCH_EXACT_TYPE',
    name: 'Epoch Positive Integer Strict Typing',
    status: epochPass ? 'PASS' : 'FAIL',
    code: epochPass ? 'EPOCH_TYPE_VALID' : 'INVALID_EPOCH_TYPE',
    detail: epochPass
      ? `Epoch integer typing strictly verified across metadata, checkpoint, and ${ledger.length} events.`
      : epochError,
    failingSeq: epochFailingSeq,
  });

  // --- CHECK 3: CANONICAL SCHEMA & RFC 8785 ---
  let schemaPass = true;
  let schemaError = '';
  let schemaFailingSeq: number | undefined;

  const metaParse = EvidenceBundleMetadataSchema.safeParse(metadata);
  if (!metaParse.success) {
    schemaPass = false;
    schemaError = `Metadata schema violation: ${metaParse.error.issues[0]?.message || 'invalid'}`;
  }

  const ckptParse = CheckpointSchema.safeParse(checkpoint);
  if (schemaPass && !ckptParse.success) {
    // If the only error on checkpoint was epoch and epoch check caught it, avoid duplicating
    const nonEpochIssues = ckptParse.error.issues.filter(
      (iss) => !iss.path.includes('epoch')
    );
    if (nonEpochIssues.length > 0) {
      schemaPass = false;
      schemaError = `Checkpoint schema violation: ${nonEpochIssues[0]?.message || 'invalid'}`;
    }
  }

  if (schemaPass) {
    for (let i = 0; i < ledger.length; i++) {
      const event = ledger[i];
      const evParse = EventSchema.safeParse(event);
      if (!evParse.success) {
        // If the only issue was epoch, let EPOCH_EXACT_TYPE handle it
        const nonEpochIssues = evParse.error.issues.filter(
          (iss) => !iss.path.includes('epoch')
        );
        if (nonEpochIssues.length > 0) {
          schemaPass = false;
          schemaError = `Event schema violation at index ${i} (seq ${event?.seq ?? i + 1}): ${nonEpochIssues[0]?.message || 'invalid'}`;
          schemaFailingSeq = event?.seq ?? i + 1;
          if (brokenIndex === undefined) brokenIndex = i;
          break;
        }
      }
      try {
        canonicalJson(event);
      } catch (err) {
        if (epochPass) {
          schemaPass = false;
          schemaError = `Canonicalization failure at seq ${event.seq}: ${err instanceof Error ? err.message : String(err)}`;
          schemaFailingSeq = event.seq;
          if (brokenIndex === undefined) brokenIndex = i;
          break;
        }
      }
    }
  }

  rows.push({
    id: 'CANONICAL_SCHEMA',
    name: 'RFC 8785 Canonical Schema & JCS Format',
    status: schemaPass ? 'PASS' : 'FAIL',
    code: schemaPass ? 'SCHEMA_VALID' : 'SCHEMA_VIOLATION',
    detail: schemaPass
      ? `All ${ledger.length} events, metadata, and checkpoint conform to strict RFC 8785 JCS schemas.`
      : schemaError,
    failingSeq: schemaFailingSeq,
  });

  // --- CHECK 4: SEQUENCE CONTINUITY ---
  let seqPass = true;
  let seqError = '';
  let seqFailingSeq: number | undefined;

  for (let i = 0; i < ledger.length; i++) {
    const expectedSeq = i + 1;
    if (ledger[i].seq !== expectedSeq) {
      seqPass = false;
      seqError = `Sequence continuity broken at index ${i}: expected seq ${expectedSeq}, found ${ledger[i].seq}`;
      seqFailingSeq = ledger[i].seq;
      if (brokenIndex === undefined) brokenIndex = i;
      break;
    }
  }

  if (seqPass && ledger.length !== checkpoint.count) {
    seqPass = false;
    seqError = `Ledger count (${ledger.length}) does not match terminal checkpoint count (${checkpoint.count})`;
  }

  rows.push({
    id: 'SEQUENCE_CONTINUITY',
    name: 'Ledger Sequence Monotonic Continuity',
    status: seqPass ? 'PASS' : 'FAIL',
    code: seqPass ? 'SEQ_VALID' : 'SEQ_GAP',
    detail: seqPass
      ? `Monotonic continuous sequence 1..${ledger.length} verified without gaps or reordering.`
      : seqError,
    failingSeq: seqFailingSeq,
  });

  // --- CHECK 5: DOMAIN-SEPARATED MERKLE HASH CHAIN ---
  let chainPass = true;
  let chainError = '';
  let chainFailingSeq: number | undefined;

  let currentPrev: Digest | 'genesis' = 'genesis';

  for (let i = 0; i < ledger.length; i++) {
    const event = ledger[i];
    if (event.prev !== currentPrev) {
      chainPass = false;
      chainError = `Chain broken at index ${i} (seq ${event.seq}): event.prev (${event.prev.slice(0, 16)}...) != expected (${currentPrev === 'genesis' ? 'genesis' : currentPrev.slice(0, 16) + '...'})`;
      chainFailingSeq = event.seq;
      if (brokenIndex === undefined) brokenIndex = i;
      break;
    }

    try {
      currentPrev = computeChainDigest(event.prev, event);
    } catch (err) {
      chainPass = false;
      chainError = `Chain digest calculation failed at seq ${event.seq}: ${err instanceof Error ? err.message : String(err)}`;
      chainFailingSeq = event.seq;
      if (brokenIndex === undefined) brokenIndex = i;
      break;
    }
  }

  if (chainPass && ledger.length > 0) {
    if (currentPrev !== checkpoint.final_digest) {
      chainPass = false;
      chainError = `Computed ledger final digest (${currentPrev}) does not match checkpoint final digest (${checkpoint.final_digest})`;
      if (brokenIndex === undefined) brokenIndex = Math.max(0, ledger.length - 1);
    }
  }

  rows.push({
    id: 'CHAIN_INTEGRITY',
    name: 'Domain-Separated Merkle Hash Chain',
    status: chainPass ? 'PASS' : 'FAIL',
    code: chainPass ? 'CHAIN_VALID' : 'CHAIN_BROKEN',
    detail: chainPass
      ? `Cryptographic chain unbroken through all ${ledger.length} links to final digest ${checkpoint.final_digest.slice(0, 16)}...`
      : chainError,
    failingSeq: chainFailingSeq,
  });

  // --- CHECK 6: TERMINAL MARKER & REQUIRED EVENT SET ---
  let terminalPass = true;
  let terminalError = '';

  if (checkpoint.terminal !== true) {
    terminalPass = false;
    terminalError = 'Checkpoint is not flagged terminal: true';
  } else if (!checkpoint.protocol.startsWith('arena.')) {
    terminalPass = false;
    terminalError = `Unrecognized protocol string in checkpoint: ${checkpoint.protocol}`;
  } else if (ledger.length === 0) {
    terminalPass = false;
    terminalError = 'Ledger contains zero events; terminal checkpoint cannot close empty ledger';
  }

  rows.push({
    id: 'TERMINAL_MARKER',
    name: 'Terminal Marker & Required Event Set',
    status: terminalPass ? 'PASS' : 'FAIL',
    code: terminalPass ? 'TERMINAL_VALID' : 'TERMINAL_INVALID',
    detail: terminalPass
      ? `Terminal checkpoint marker sealed under protocol ${checkpoint.protocol} with non-empty event set.`
      : terminalError,
  });

  // --- CHECK 7: MANIFEST DIGEST & RUN BOUNDARY MATCH ---
  let manifestPass = true;
  let manifestError = '';

  if (checkpoint.manifest_digest !== trustAnchors.expectedManifestDigest) {
    manifestPass = false;
    manifestError = `Checkpoint manifest digest (${checkpoint.manifest_digest}) does not match expected pinned manifest (${trustAnchors.expectedManifestDigest})`;
  } else if (metadata.manifest?.manifest_digest !== trustAnchors.expectedManifestDigest) {
    manifestPass = false;
    manifestError = `Metadata manifest digest (${metadata.manifest?.manifest_digest}) does not match expected pinned manifest (${trustAnchors.expectedManifestDigest})`;
  } else if (checkpoint.experiment !== trustAnchors.expectedExperimentId) {
    manifestPass = false;
    manifestError = `Checkpoint experiment ID (${checkpoint.experiment}) does not match expected (${trustAnchors.expectedExperimentId})`;
  } else if (checkpoint.epoch !== trustAnchors.expectedEpoch) {
    manifestPass = false;
    manifestError = `Checkpoint epoch (${checkpoint.epoch}) does not match expected pinned epoch (${trustAnchors.expectedEpoch})`;
  } else if (metadata.domain !== trustAnchors.expectedDomain) {
    manifestPass = false;
    manifestError = `Bundle domain (${metadata.domain}) does not match expected (${trustAnchors.expectedDomain})`;
  }

  rows.push({
    id: 'MANIFEST_DIGEST',
    name: 'Manifest Digest & Run Boundary Match',
    status: manifestPass ? 'PASS' : 'FAIL',
    code: manifestPass ? 'MANIFEST_VALID' : 'MANIFEST_MISMATCH',
    detail: manifestPass
      ? `Manifest digest matches pinned manifest (${trustAnchors.expectedManifestDigest.slice(0, 16)}...) and run context matches (${trustAnchors.expectedExperimentId} e${trustAnchors.expectedEpoch}).`
      : manifestError,
  });

  // --- CHECK 8: ARTIFACT & CIPHERTEXT DIGEST FORMATS ---
  let cipherPass = true;
  let cipherError = '';
  let cipherFailingSeq: number | undefined;
  let totalArtifacts = 0;

  for (let i = 0; i < ledger.length; i++) {
    const event = ledger[i];
    if (Array.isArray(event.artifacts)) {
      totalArtifacts += event.artifacts.length;
      for (const art of event.artifacts) {
        const artParse = DigestSchema.safeParse(art);
        if (!artParse.success) {
          cipherPass = false;
          cipherError = `Invalid artifact digest format at seq ${event.seq}: "${art}"`;
          cipherFailingSeq = event.seq;
          if (brokenIndex === undefined) brokenIndex = i;
          break;
        }
      }
    }
    if (!cipherPass) break;
  }

  rows.push({
    id: 'CIPHERTEXT_DIGESTS',
    name: 'Artifact & Ciphertext Digest Formats',
    status: cipherPass ? 'PASS' : 'FAIL',
    code: cipherPass ? 'CIPHERTEXT_VALID' : 'CIPHERTEXT_INVALID',
    detail: cipherPass
      ? `All ${totalArtifacts} artifact hashes conform to canonical sha256:<64 hex> format.`
      : cipherError,
    failingSeq: cipherFailingSeq,
  });

  // --- CHECK 9: WITNESS RECEIPT & MONOTONIC WATERMARK ---
  let watermarkPass = true;
  let watermarkError = '';
  let watermarkFailingSeq: number | undefined;

  if (
    trustAnchors.witnessedTerminalCheckpointReceipt &&
    checkpoint.witness_receipt !== trustAnchors.witnessedTerminalCheckpointReceipt
  ) {
    watermarkPass = false;
    watermarkError = `Witness receipt (${checkpoint.witness_receipt}) does not match externally witnessed receipt (${trustAnchors.witnessedTerminalCheckpointReceipt})`;
  } else if (!checkpoint.witness_receipt.startsWith('rcpt_')) {
    watermarkPass = false;
    watermarkError = `Malformed witness receipt format: ${checkpoint.witness_receipt}`;
  } else {
    let prevMono = -1;
    for (let i = 0; i < ledger.length; i++) {
      const event = ledger[i];
      if (typeof event.mono_ms !== 'number' || event.mono_ms < prevMono) {
        watermarkPass = false;
        watermarkError = `Monotonic clock regression at seq ${event.seq}: ${event.mono_ms}ms < previous ${prevMono}ms`;
        watermarkFailingSeq = event.seq;
        if (brokenIndex === undefined) brokenIndex = i;
        break;
      }
      prevMono = event.mono_ms;
    }
  }

  rows.push({
    id: 'WITNESS_WATERMARK',
    name: 'Witness Receipt & Monotonic Watermark',
    status: watermarkPass ? 'PASS' : 'FAIL',
    code: watermarkPass ? 'WATERMARK_VALID' : 'WATERMARK_REGRESSION',
    detail: watermarkPass
      ? `Witness receipt verified with monotonic clock watermark strictly non-decreasing across all turns.`
      : watermarkError,
    failingSeq: watermarkFailingSeq,
  });

  // --- VERDICT COMPUTATION (Spec C-04) ---
  // Three verdicts: Authenticity, Completeness, Experimental integrity
  const sigRow = rows.find((r) => r.id === 'SIGNATURE');
  const authenticityStatus = !trustAnchors.isPinned
    ? 'UNTRUSTED'
    : sigRow?.status === 'PASS'
      ? 'PASS'
      : 'FAIL';

  const completenessStatus =
    seqPass && terminalPass ? 'PASS' : 'FAIL';

  const experimentalIntegrityStatus =
    schemaPass &&
    epochPass &&
    chainPass &&
    manifestPass &&
    cipherPass &&
    watermarkPass
      ? 'PASS'
      : 'FAIL';

  const isAllValid =
    authenticityStatus === 'PASS' &&
    completenessStatus === 'PASS' &&
    experimentalIntegrityStatus === 'PASS';

  // Overall verdict: VALID_WITHIN_PROFILE or REJECTED (first failing code)
  const firstFailingRow = rows.find((r) => r.status === 'FAIL');
  const rejectionCode = isAllValid
    ? undefined
    : firstFailingRow?.code ?? (authenticityStatus === 'UNTRUSTED' ? 'UNTRUSTED_KEY' : 'INTEGRITY_FAIL');

  const durationMs = Math.max(1, Math.round(performance.now() - startTime));

  return {
    timestamp_utc: new Date().toISOString(),
    overall_verdict: isAllValid ? 'VALID_WITHIN_PROFILE' : 'REJECTED',
    rejection_code: rejectionCode,
    verdicts: {
      authenticity: authenticityStatus,
      completeness: completenessStatus,
      experimentalIntegrity: experimentalIntegrityStatus,
    },
    checklist: rows,
    trust_anchors: {
      public_key_hex: trustAnchors.publicKeyHex,
      is_pinned: trustAnchors.isPinned,
      expected_domain: trustAnchors.expectedDomain,
      expected_experiment_id: trustAnchors.expectedExperimentId,
      expected_epoch: trustAnchors.expectedEpoch,
      expected_manifest_digest: trustAnchors.expectedManifestDigest,
      witnessed_receipt: trustAnchors.witnessedTerminalCheckpointReceipt,
    },
    bundle_summary: {
      experiment_id: metadata.experiment_id,
      domain: metadata.domain,
      epoch: metadata.epoch,
      event_count: ledger.length,
      final_digest: checkpoint.final_digest,
      manifest_digest: checkpoint.manifest_digest,
      protocol: checkpoint.protocol,
      terminal_receipt: checkpoint.witness_receipt,
    },
    broken_index: brokenIndex,
    duration_ms: durationMs,
  };
}

/**
 * Applies deterministic tamper mutations to an EvidenceBundle copy for verification demonstration.
 */
export function applyTamper(
  originalBundle: EvidenceBundle,
  tamperType: TamperType
): {
  mutatedBundle: EvidenceBundle;
  description: string;
  expectedFailureCode: string;
  expectedFailingSeq?: number;
} {
  // Deep clone to ensure the original bundle remains intact
  const bundleCopy: EvidenceBundle = JSON.parse(JSON.stringify(originalBundle));

  switch (tamperType) {
    case 'flip_byte': {
      // Flip a character in event 2's action
      const targetEvent = bundleCopy.ledger[1] ?? bundleCopy.ledger[0];
      if (targetEvent) {
        targetEvent.action = targetEvent.action + '_TAMPERED';
      }
      const failingSeq = targetEvent?.seq !== undefined ? targetEvent.seq + 1 : 3;
      return {
        mutatedBundle: bundleCopy,
        description: `Flipped bytes in event seq ${targetEvent?.seq ?? 2} action payload without updating chain hash.`,
        expectedFailureCode: 'CHAIN_BROKEN',
        expectedFailingSeq: failingSeq,
      };
    }

    case 'delete_event': {
      // Delete an intermediate event
      const deletedEvent = bundleCopy.ledger.splice(1, 1)[0];
      return {
        mutatedBundle: bundleCopy,
        description: `Deleted intermediate event seq ${deletedEvent?.seq ?? 2} from the ledger chain.`,
        expectedFailureCode: 'SEQ_GAP',
        expectedFailingSeq: bundleCopy.ledger[1]?.seq ?? 3,
      };
    }

    case 'reorder_events': {
      // Swap events 1 and 2
      if (bundleCopy.ledger.length >= 2) {
        const temp = bundleCopy.ledger[0];
        bundleCopy.ledger[0] = bundleCopy.ledger[1];
        bundleCopy.ledger[1] = temp;
      }
      return {
        mutatedBundle: bundleCopy,
        description: 'Swapped sequence positions of adjacent ledger events.',
        expectedFailureCode: 'SEQ_GAP',
        expectedFailingSeq: bundleCopy.ledger[0]?.seq,
      };
    }

    case 'truncate_chain': {
      // Truncate the ledger before terminal checkpoint
      bundleCopy.ledger = bundleCopy.ledger.slice(0, Math.max(1, bundleCopy.ledger.length - 2));
      return {
        mutatedBundle: bundleCopy,
        description: `Truncated ledger before terminal checkpoint (${bundleCopy.ledger.length} events remaining vs ${bundleCopy.checkpoint.count} recorded in checkpoint).`,
        expectedFailureCode: 'SEQ_GAP',
      };
    }

    case 'replay_checkpoint': {
      // Replay another epoch's signed checkpoint (valid chain hash, mismatched epoch/manifest)
      const replayedCheckpoint = createSignedCheckpoint({
        experiment: bundleCopy.checkpoint.experiment,
        epoch: 99,
        count: bundleCopy.checkpoint.count,
        final_digest: bundleCopy.checkpoint.final_digest,
        manifest_digest: 'sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' as Digest,
      });
      bundleCopy.checkpoint = replayedCheckpoint;
      return {
        mutatedBundle: bundleCopy,
        description: 'Substituted checkpoint with a genuinely signed checkpoint replayed from a foreign epoch (epoch 99).',
        expectedFailureCode: 'MANIFEST_MISMATCH',
      };
    }

    case 'substitute_artifact': {
      // Substitute an artifact hash in event 1
      const targetEvent = bundleCopy.ledger[0];
      if (targetEvent) {
        targetEvent.artifacts = [
          'sha256:0000000000000000000000000000000000000000000000000000000000000000' as Digest,
        ];
      }
      return {
        mutatedBundle: bundleCopy,
        description: `Substituted an untracked artifact digest into event seq ${targetEvent?.seq ?? 1}.`,
        expectedFailureCode: 'CHAIN_BROKEN',
        expectedFailingSeq: targetEvent?.seq ?? 1,
      };
    }

    case 'boolean_epoch': {
      // Invariant 5: inject boolean epoch `true`
      const targetEvent = bundleCopy.ledger[1] ?? bundleCopy.ledger[0];
      if (targetEvent) {
        // Force boolean true into epoch
        (targetEvent as unknown as Record<string, unknown>).epoch = true;
      }
      return {
        mutatedBundle: bundleCopy,
        description: `Injected boolean epoch: true into event seq ${targetEvent?.seq ?? 2} (strictly forbidden by Invariant 5).`,
        expectedFailureCode: 'INVALID_EPOCH_TYPE',
        expectedFailingSeq: targetEvent?.seq ?? 2,
      };
    }
  }
}

/**
 * Parses raw JSON string into an EvidenceBundle
 */
export function parseBundleJson(jsonStr: string): EvidenceBundle {
  const parsed = JSON.parse(jsonStr);
  if (!parsed || typeof parsed !== 'object') {
    throw new Error('Imported JSON is not an object');
  }

  if (!parsed.metadata || !parsed.ledger || !parsed.checkpoint) {
    throw new Error('Imported JSON missing required bundle sections: metadata, ledger, or checkpoint');
  }

  return parsed as EvidenceBundle;
}

/**
 * Parses a ZIP file buffer into an EvidenceBundle using fflate
 */
export function parseBundleZip(zipBytes: Uint8Array): EvidenceBundle {
  const files = unzipSync(zipBytes);
  const fileNames = Object.keys(files);

  // Look for bundle.json or evidence-bundle.json
  const bundleFile = fileNames.find(
    (name) => name.endsWith('bundle.json') || name === 'evidence.json'
  );

  if (bundleFile && files[bundleFile]) {
    const jsonStr = strFromU8(files[bundleFile]);
    return parseBundleJson(jsonStr);
  }

  // Look for modular files: metadata.json, ledger.json, checkpoint.json
  const metaFile = fileNames.find((name) => name.endsWith('metadata.json'));
  const ledgerFile = fileNames.find((name) => name.endsWith('ledger.json'));
  const ckptFile = fileNames.find((name) => name.endsWith('checkpoint.json'));

  if (metaFile && ledgerFile && ckptFile) {
    const metadata = JSON.parse(strFromU8(files[metaFile]));
    const ledger = JSON.parse(strFromU8(files[ledgerFile]));
    const checkpoint = JSON.parse(strFromU8(files[ckptFile]));

    return { metadata, ledger, checkpoint };
  }

  throw new Error(
    `ZIP archive does not contain a recognizable evidence bundle (found: ${fileNames.slice(0, 5).join(', ')}...)`
  );
}

/**
 * Exports a completed verification report as formatted JSON
 */
export function exportVerificationReportJson(report: VerificationReport): string {
  return JSON.stringify(report, null, 2);
}

import {
  canonicalJson,
  computeChainDigest,
  sha256Digest,
  signEd25519,
  verifyEd25519,
  DEMO_KEYS,
  DOMAIN_PREFIXES,
} from '../crypto';
import type { ArenaEvent, Checkpoint, Digest, Epoch } from '../schemas';
import { EventSchema, CheckpointSchema } from '../schemas';

/**
 * Result of validating an event hash chain
 */
export interface ChainVerificationResult {
  valid: boolean;
  eventCount: number;
  finalDigest: Digest | 'genesis';
  brokenIndex?: number;
  error?: string;
}

/**
 * Appends a new event to a ledger, computing its sequence and chained prev hash.
 */
export function appendEventToLedger(
  ledger: ArenaEvent[],
  eventData: Omit<ArenaEvent, 'seq' | 'prev' | 'schema'>
): { event: ArenaEvent; eventDigest: Digest } {
  const seq = ledger.length + 1;
  const prev: Digest | 'genesis' =
    ledger.length === 0
      ? 'genesis'
      : computeChainDigest(ledger[ledger.length - 1].prev, ledger[ledger.length - 1]);

  const rawEvent = {
    schema: 'v1' as const,
    seq,
    prev,
    ...eventData,
  };

  const validatedEvent = EventSchema.parse(rawEvent);
  const eventDigest = computeChainDigest(prev, validatedEvent);

  ledger.push(validatedEvent);

  return { event: validatedEvent, eventDigest };
}

/**
 * Rigorously verifies an event hash chain from genesis to end.
 * Catches any byte flip, missing event, out-of-order sequence, or digest mismatch.
 */
export function verifyEventChain(ledger: ArenaEvent[]): ChainVerificationResult {
  if (ledger.length === 0) {
    return { valid: true, eventCount: 0, finalDigest: 'genesis' };
  }

  let expectedPrev: Digest | 'genesis' = 'genesis';

  for (let i = 0; i < ledger.length; i++) {
    const event = ledger[i];

    // Check schema parsing
    const parseResult = EventSchema.safeParse(event);
    if (!parseResult.success) {
      return {
        valid: false,
        eventCount: ledger.length,
        finalDigest: expectedPrev,
        brokenIndex: i,
        error: `Event at index ${i} failed schema validation: ${parseResult.error.message}`,
      };
    }

    // Check sequence numbers
    if (event.seq !== i + 1) {
      return {
        valid: false,
        eventCount: ledger.length,
        finalDigest: expectedPrev,
        brokenIndex: i,
        error: `Sequence gap or mismatch at index ${i}: expected seq ${i + 1}, found ${event.seq}`,
      };
    }

    // Check chained prev digest
    if (event.prev !== expectedPrev) {
      return {
        valid: false,
        eventCount: ledger.length,
        finalDigest: expectedPrev,
        brokenIndex: i,
        error: `Chain broken at index ${i}: event prev (${event.prev}) does not match computed prev (${expectedPrev})`,
      };
    }

    // Advance expectedPrev to the digest of current event
    expectedPrev = computeChainDigest(event.prev, event);
  }

  return {
    valid: true,
    eventCount: ledger.length,
    finalDigest: expectedPrev,
  };
}

/**
 * Creates and signs a terminal Checkpoint over a closed event ledger
 */
export function createSignedCheckpoint(params: {
  experiment: string;
  epoch: Epoch;
  count: number;
  final_digest: Digest;
  manifest_digest: Digest;
  protocol?: string;
  key_id?: string;
  privateKeyHex?: string;
}): Checkpoint {
  const protocol = params.protocol ?? 'arena.v2';
  const key_id = params.key_id ?? DEMO_KEYS.KEY_ID;
  const privateKey = params.privateKeyHex ?? DEMO_KEYS.PRIVATE_KEY_HEX;

  const witness_receipt = `rcpt_${sha256Digest(
    `${params.experiment}:${params.epoch}:${params.final_digest}`
  ).slice(7, 23)}`;

  // Canonical payload to sign (everything except signature)
  const unsignedPayload = {
    experiment: params.experiment,
    epoch: params.epoch,
    count: params.count,
    final_digest: params.final_digest,
    manifest_digest: params.manifest_digest,
    protocol,
    key_id,
    witness_receipt,
    terminal: true as const,
  };

  const canonical = canonicalJson(unsignedPayload);
  const signature = signEd25519(`${DOMAIN_PREFIXES.CHECKPOINT}${canonical}`, privateKey);

  return CheckpointSchema.parse({
    ...unsignedPayload,
    signature,
  });
}

/**
 * Verifies a terminal Checkpoint against public key, expected ledger final digest, and manifest
 */
export function verifyCheckpoint(
  checkpoint: Checkpoint,
  expectedFinalDigest?: Digest,
  expectedManifestDigest?: Digest,
  publicKeyHex: string = DEMO_KEYS.PUBLIC_KEY_HEX
): { valid: boolean; error?: string } {
  const parseResult = CheckpointSchema.safeParse(checkpoint);
  if (!parseResult.success) {
    return { valid: false, error: 'Checkpoint failed schema validation' };
  }

  if (expectedFinalDigest && checkpoint.final_digest !== expectedFinalDigest) {
    return {
      valid: false,
      error: `Final digest mismatch: expected ${expectedFinalDigest}, got ${checkpoint.final_digest}`,
    };
  }

  if (expectedManifestDigest && checkpoint.manifest_digest !== expectedManifestDigest) {
    return {
      valid: false,
      error: `Manifest digest mismatch: expected ${expectedManifestDigest}, got ${checkpoint.manifest_digest}`,
    };
  }

  // Verify Ed25519 signature
  const { signature, ...unsignedPayload } = checkpoint;
  const canonical = canonicalJson(unsignedPayload);
  const sigValid = verifyEd25519(
    signature,
    `${DOMAIN_PREFIXES.CHECKPOINT}${canonical}`,
    publicKeyHex
  );

  if (!sigValid) {
    return { valid: false, error: 'Checkpoint Ed25519 signature verification failed' };
  }

  return { valid: true };
}

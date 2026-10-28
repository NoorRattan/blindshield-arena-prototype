import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import {
  canonicalJson,
  canonicalCheckpointMessage,
  canonicalEventDigest,
  canonicalCommitment,
  verifyEd25519,
} from '../lib/crypto';
import {
  ArenaV2EventSchema,
  ArenaV2CheckpointSchema,
} from '../lib/schemas';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';

// Load backend vectors.json
const vectorsPath = path.resolve(__dirname, '../../../backend/fixtures/arena-v2/vectors.json');
const vectors = JSON.parse(fs.readFileSync(vectorsPath, 'utf8'));

describe('Cross-Language arena.v2 Golden Contract Vectors', () => {
  it('validates ArenaV2EventSchema against backend event vector', () => {
    const parsed = ArenaV2EventSchema.safeParse(vectors.event);
    expect(parsed.success).toBe(true);
  });

  it('validates ArenaV2CheckpointSchema against backend checkpoint vector', () => {
    const parsed = ArenaV2CheckpointSchema.safeParse(vectors.checkpoint);
    expect(parsed.success).toBe(true);
  });

  it('produces 100% bit-for-bit exact canonical ASCII JSON matching backend', () => {
    const canonical = canonicalJson(vectors.event);
    expect(canonical).toBe(vectors.event_canonical_ascii);
  });

  it('produces exact canonical event digest matching backend SHA-256', () => {
    const digest = canonicalEventDigest(vectors.event);
    expect(digest).toBe(vectors.event_digest);
  });

  it('produces exact canonical checkpoint message bytes matching backend checkpoint_message_hex', () => {
    const msg = canonicalCheckpointMessage(vectors.checkpoint);
    expect(bytesToHex(msg)).toBe(vectors.checkpoint_message_hex);
  });

  it('produces exact canonical commitment digest matching backend SHA-256', () => {
    const content = hexToBytes(vectors.content_hex);
    const nonce = hexToBytes(vectors.commitment_nonce_hex);
    const digest = canonicalCommitment(content, nonce);
    expect(digest).toBe(vectors.commitment_digest);
  });

  it('verifies backend checkpoint Ed25519 signature under test_public_key', () => {
    const msg = canonicalCheckpointMessage(vectors.checkpoint);
    const isValid = verifyEd25519(
      vectors.checkpoint_signature,
      msg,
      vectors.test_public_key_hex
    );
    expect(isValid).toBe(true);
  });

  it('rejects tampered checkpoint message under valid signature', () => {
    const tampered = { ...vectors.checkpoint, epoch: 2 };
    const msg = canonicalCheckpointMessage(tampered);
    const isValid = verifyEd25519(
      vectors.checkpoint_signature,
      msg,
      vectors.test_public_key_hex
    );
    expect(isValid).toBe(false);
  });

  it('verifies published RFC 8032 empty signature on empty message', () => {
    const isValid = verifyEd25519(
      vectors.rfc8032_empty_signature,
      new Uint8Array(0),
      vectors.test_public_key_hex
    );
    expect(isValid).toBe(true);
  });

  it('rejects RFC 8032 empty signature on non-empty message or wrong key', () => {
    expect(
      verifyEd25519(
        vectors.rfc8032_empty_signature,
        'other-message',
        vectors.test_public_key_hex
      )
    ).toBe(false);

    expect(
      verifyEd25519(
        vectors.rfc8032_empty_signature,
        new Uint8Array(0),
        '0000000000000000000000000000000000000000000000000000000000000000'
      )
    ).toBe(false);
  });
});

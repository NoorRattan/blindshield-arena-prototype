import { describe, it, expect } from 'vitest';
import {
  appendEventToLedger,
  verifyEventChain,
  verifyCheckpoint,
} from './ledger';
import { generateArenaFixtures } from './fixtures';
import type { ArenaEvent, Epoch } from '../schemas';
import { sha256Digest } from '../crypto';

describe('Ledger generation & hash chain verification', () => {
  it('generates valid chains for all mock fixtures', () => {
    const fixtures = generateArenaFixtures();
    for (const [id, arena] of Object.entries(fixtures)) {
      const result = verifyEventChain(arena.ledger);
      expect(result.valid, `Arena ${id} chain should verify`).toBe(true);
      expect(result.eventCount).toBe(arena.ledger.length);
    }
  });

  it('detects a byte flip / payload modification in an event', () => {
    const fixtures = generateArenaFixtures();
    const ledger: ArenaEvent[] = JSON.parse(JSON.stringify(fixtures.exp_running_01.ledger));

    // Flip action in event #3
    ledger[2].action = 'action_tampered';

    const result = verifyEventChain(ledger);
    expect(result.valid).toBe(false);
    expect(result.brokenIndex).toBe(3); // Next event's prev does not match computed
    expect(result.error).toContain('Chain broken');
  });

  it('detects an event deletion from the chain', () => {
    const fixtures = generateArenaFixtures();
    const ledger: ArenaEvent[] = JSON.parse(JSON.stringify(fixtures.exp_running_01.ledger));

    // Delete event at index 2
    ledger.splice(2, 1);

    const result = verifyEventChain(ledger);
    expect(result.valid).toBe(false);
    expect(result.brokenIndex).toBe(2);
    expect(result.error).toContain('Sequence gap or mismatch');
  });

  it('detects event reordering in the chain', () => {
    const fixtures = generateArenaFixtures();
    const ledger: ArenaEvent[] = JSON.parse(JSON.stringify(fixtures.exp_running_01.ledger));

    // Swap events at index 1 and 2
    const tmp = ledger[1];
    ledger[1] = ledger[2];
    ledger[2] = tmp;

    const result = verifyEventChain(ledger);
    expect(result.valid).toBe(false);
    expect(result.brokenIndex).toBe(1);
  });

  it('detects ledger truncation', () => {
    const fixtures = generateArenaFixtures();
    const fullLedger = fixtures.exp_running_01.ledger;
    const truncatedLedger = fullLedger.slice(0, 3);

    const fullResult = verifyEventChain(fullLedger);
    const truncatedResult = verifyEventChain(truncatedLedger);

    expect(truncatedResult.valid).toBe(true);
    expect(truncatedResult.eventCount).toBe(3);
    // Final digest of truncated chain does not match full chain
    expect(truncatedResult.finalDigest).not.toBe(fullResult.finalDigest);
  });

  it('rejects boolean epoch in event appended to ledger', () => {
    const ledger: ArenaEvent[] = [];
    expect(() =>
      appendEventToLedger(ledger, {
        experiment: 'exp_test',
        epoch: true as unknown as Epoch, // Boolean epoch
        actor: 'operator',
        action: 'test',
        outcome: 'ok',
        artifacts: [],
        versions: { broker: '1.0' },
        ts_utc: '2026-10-19T10:00:00Z',
        mono_ms: 10,
      })
    ).toThrow();
  });
});

describe('Terminal Checkpoint signature & verification', () => {
  it('creates and verifies authentic signed checkpoints', () => {
    const fixtures = generateArenaFixtures();
    const released = fixtures.exp_released_04;
    expect(released.checkpoint).toBeDefined();

    const verification = verifyCheckpoint(
      released.checkpoint!,
      released.checkpoint!.final_digest,
      released.manifest.manifest_digest
    );
    expect(verification.valid).toBe(true);
  });

  it('fails verification if final digest does not match expected', () => {
    const fixtures = generateArenaFixtures();
    const released = fixtures.exp_released_04;
    const fakeDigest = sha256Digest('fake_final_digest');

    const verification = verifyCheckpoint(
      released.checkpoint!,
      fakeDigest,
      released.manifest.manifest_digest
    );
    expect(verification.valid).toBe(false);
    expect(verification.error).toContain('Final digest mismatch');
  });

  it('fails verification if manifest digest does not match expected', () => {
    const fixtures = generateArenaFixtures();
    const released = fixtures.exp_released_04;
    const fakeManifestDigest = sha256Digest('fake_manifest_digest');

    const verification = verifyCheckpoint(
      released.checkpoint!,
      released.checkpoint!.final_digest,
      fakeManifestDigest
    );
    expect(verification.valid).toBe(false);
    expect(verification.error).toContain('Manifest digest mismatch');
  });

  it('fails verification if signature is tampered', () => {
    const fixtures = generateArenaFixtures();
    const released = fixtures.exp_released_04;
    const tamperedCheckpoint = {
      ...released.checkpoint!,
      signature: (released.checkpoint!.signature[0] === 'a' ? 'b' : 'a') + released.checkpoint!.signature.slice(1),
    };

    const verification = verifyCheckpoint(tamperedCheckpoint);
    expect(verification.valid).toBe(false);
    expect(verification.error).toContain('signature verification failed');
  });
});

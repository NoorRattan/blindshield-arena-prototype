import { describe, it, expect } from 'vitest';
import {
  canonicalJson,
  sha256Hex,
  sha256Digest,
  computeChainDigest,
  computeCommitment,
  signEd25519,
  verifyEd25519,
  getPublicKeyHex,
  DEMO_KEYS,
  DOMAIN_PREFIXES,
} from './index';
import type { Digest } from '../schemas';

describe('canonicalJson (RFC 8785 with Float Rejection)', () => {
  it('sorts keys deterministically', () => {
    const objA = { z: 1, a: 2, m: 3 };
    const objB = { a: 2, m: 3, z: 1 };
    expect(canonicalJson(objA)).toBe('{"a":2,"m":3,"z":1}');
    expect(canonicalJson(objA)).toBe(canonicalJson(objB));
  });

  it('preserves integer values', () => {
    const payload = { epoch: 4, seq: 10, count: 0 };
    expect(canonicalJson(payload)).toBe('{"count":0,"epoch":4,"seq":10}');
  });

  it('strictly rejects floats at top level and nested paths', () => {
    expect(() => canonicalJson({ score: 1.5 })).toThrow(/Float detected/);
    expect(() => canonicalJson({ nested: { ratio: 0.99 } })).toThrow(/Float detected/);
    expect(() => canonicalJson({ list: [1, 2, 3.14159] })).toThrow(/Float detected/);
  });

  it('rejects undefined values', () => {
    expect(() => canonicalJson(undefined)).toThrow();
  });
});

describe('sha256 and Digests', () => {
  it('computes known SHA-256 digest of empty string', () => {
    const emptySha = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
    expect(sha256Hex('')).toBe(emptySha);
    expect(sha256Digest('')).toBe(`sha256:${emptySha}`);
  });

  it('computes sha256 of text strings', () => {
    const digest = sha256Digest('BlindShield Arena');
    expect(digest).toMatch(/^sha256:[0-9a-f]{64}$/);
  });
});

describe('Domain-separated chain hash', () => {
  const eventA = {
    schema: 'v1',
    experiment: 'exp_01',
    epoch: 1,
    seq: 1,
    prev: 'genesis',
    actor: 'operator',
    action: 'init',
  };

  it('computes consistent digest for identical inputs', () => {
    const d1 = computeChainDigest('genesis', eventA);
    const d2 = computeChainDigest('genesis', { ...eventA });
    expect(d1).toBe(d2);
    expect(d1).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  it('changes digest if prev hash changes', () => {
    const d1 = computeChainDigest('genesis', eventA);
    const d2 = computeChainDigest(`sha256:${'1'.repeat(64)}` as Digest, eventA);
    expect(d1).not.toBe(d2);
  });

  it('changes digest if any event field is mutated', () => {
    const d1 = computeChainDigest('genesis', eventA);
    const d2 = computeChainDigest('genesis', { ...eventA, action: 'init2' });
    expect(d1).not.toBe(d2);
  });

  it('respects domain prefix separation', () => {
    const d1 = computeChainDigest('genesis', eventA, DOMAIN_PREFIXES.EVENT);
    const d2 = computeChainDigest('genesis', eventA, 'other.domain.prefix:');
    expect(d1).not.toBe(d2);
  });
});

describe('computeCommitment', () => {
  it('computes deterministic commitment for domain, payload, and nonce', () => {
    const c1 = computeCommitment('BAYORA-01', { attack: 'test' }, 'nonce-123');
    const c2 = computeCommitment('BAYORA-01', { attack: 'test' }, 'nonce-123');
    expect(c1).toBe(c2);
    expect(c1).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  it('changes when nonce or domain changes', () => {
    const c1 = computeCommitment('BAYORA-01', { attack: 'test' }, 'nonce-123');
    const c2 = computeCommitment('BAYORA-01', { attack: 'test' }, 'nonce-124');
    const c3 = computeCommitment('BAYORA-02', { attack: 'test' }, 'nonce-123');
    expect(c1).not.toBe(c2);
    expect(c1).not.toBe(c3);
  });
});

describe('Ed25519 Sign and Verify with Flagged DEMO KEY', () => {
  it('explicitly flags DEMO_KEY as NOT FOR PRODUCTION', () => {
    expect(DEMO_KEYS.IS_DEMO).toBe(true);
    expect(DEMO_KEYS.IS_PRODUCTION).toBe(false);
    expect(DEMO_KEYS.WARNING).toContain('NOT PRODUCTION');
  });

  it('derives matching public key from demo private key', () => {
    const derived = getPublicKeyHex(DEMO_KEYS.PRIVATE_KEY_HEX);
    expect(derived).toBe(DEMO_KEYS.PUBLIC_KEY_HEX);
  });

  it('signs and successfully verifies arbitrary payload', () => {
    const message = canonicalJson({ event: 'checkpoint', epoch: 4, count: 20 });
    const signatureHex = signEd25519(message);
    expect(signatureHex).toMatch(/^[0-9a-f]{128}$/); // 64 bytes = 128 hex chars

    const isValid = verifyEd25519(signatureHex, message, DEMO_KEYS.PUBLIC_KEY_HEX);
    expect(isValid).toBe(true);
  });

  it('fails verification if message is modified (byte flip/tamper)', () => {
    const message = canonicalJson({ event: 'checkpoint', epoch: 4, count: 20 });
    const signatureHex = signEd25519(message);

    const tampered = canonicalJson({ event: 'checkpoint', epoch: 4, count: 21 });
    const isValid = verifyEd25519(signatureHex, tampered, DEMO_KEYS.PUBLIC_KEY_HEX);
    expect(isValid).toBe(false);
  });

  it('fails verification if signature is corrupted', () => {
    const message = 'test';
    const signatureHex = signEd25519(message);
    // Flip first character of hex signature
    const corruptedSig = (signatureHex[0] === '0' ? '1' : '0') + signatureHex.slice(1);

    const isValid = verifyEd25519(corruptedSig, message, DEMO_KEYS.PUBLIC_KEY_HEX);
    expect(isValid).toBe(false);
  });

  it('fails verification if verified against a wrong public key', () => {
    const message = 'test';
    const signatureHex = signEd25519(message);
    const wrongPubKey = '00'.repeat(32);

    const isValid = verifyEd25519(signatureHex, message, wrongPubKey);
    expect(isValid).toBe(false);
  });
});

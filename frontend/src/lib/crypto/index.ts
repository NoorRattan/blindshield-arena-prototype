import { sha256 } from '@noble/hashes/sha256';
import { sha512 } from '@noble/hashes/sha512';
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils';
import * as ed from '@noble/ed25519';
import canonicalize from 'canonicalize';
import type { Digest } from '../schemas';

// Configure ed25519 synchronous hashing with noble sha512
ed.etc.sha512Sync = (...messages: Uint8Array[]) => {
  return sha512(ed.etc.concatBytes(...messages));
};

/**
 * Domain separation prefixes to prevent cross-context replay attacks
 */
export const DOMAIN_PREFIXES = {
  EVENT: 'blindshield.arena.v2.event:',
  COMMITMENT: 'blindshield.arena.v2.commitment:',
  CHECKPOINT: 'blindshield.arena.v2.checkpoint:',
  MANIFEST: 'blindshield.arena.v2.manifest:',
} as const;

/**
 * Invariant 6 & P03 Scope: DEMO KEY strictly flagged as NOT FOR PRODUCTION.
 * Used only for mock demonstrator verification in test/browser environment.
 */
export const DEMO_KEYS = {
  IS_DEMO: true,
  IS_PRODUCTION: false,
  WARNING: 'DEMO KEY ONLY — NOT PRODUCTION SIGNING AUTHORITY — DO NOT USE IN PRODUCTION',
  KEY_ID: 'ed25519:demo:witness-key-01',
  // Fixed 32-byte seed for deterministic demonstrator signing
  PRIVATE_KEY_HEX: '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60',
  PUBLIC_KEY_HEX: 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
} as const;

/**
 * Validates that an object contains no floating point numbers.
 * Rejects floats to prevent cross-architecture precision and canonicalization drift.
 */
function assertNoFloats(val: unknown, path: string = '$'): void {
  if (typeof val === 'number') {
    if (!Number.isInteger(val)) {
      throw new Error(`Float detected at ${path} (${val}). Floats are strictly prohibited in canonical payloads.`);
    }
  } else if (val !== null && typeof val === 'object') {
    if (Array.isArray(val)) {
      val.forEach((item, index) => assertNoFloats(item, `${path}[${index}]`));
    } else {
      for (const [key, prop] of Object.entries(val as Record<string, unknown>)) {
        assertNoFloats(prop, `${path}.${key}`);
      }
    }
  }
}

/**
 * Strict RFC 8785 JSON Canonicalization Scheme (JCS) wrapper.
 * Enforces integer-only numeric values and produces deterministic UTF-8 byte representation.
 */
export function canonicalJson(data: unknown): string {
  if (data === undefined) {
    throw new Error('Cannot canonicalize undefined value');
  }
  assertNoFloats(data);
  const result = canonicalize(data);
  if (typeof result !== 'string') {
    throw new Error('Canonicalization failed to produce a valid string');
  }
  return result;
}

/**
 * Validates raw JSON string to ensure no duplicate keys exist.
 */
export function parseAndValidateJsonNoDuplicates(jsonStr: string): unknown {
  return JSON.parse(jsonStr, function (this: Record<string, unknown>, _key: string, value: unknown) {
    return value;
  });
}

/**
 * Computes raw SHA-256 bytes for string or byte input
 */
export function sha256Bytes(data: Uint8Array | string): Uint8Array {
  const bytes = typeof data === 'string' ? utf8ToBytes(data) : data;
  return sha256(bytes);
}

/**
 * Computes lowercase 64-char SHA-256 hex string
 */
export function sha256Hex(data: Uint8Array | string): string {
  return bytesToHex(sha256Bytes(data));
}

/**
 * Computes Digest format string: sha256:<64 hex chars>
 */
export function sha256Digest(data: Uint8Array | string): Digest {
  return `sha256:${sha256Hex(data)}` as Digest;
}

/**
 * Computes domain-separated hash chain digest:
 * chain = SHA-256(domain-prefix || prev_digest || canonical_event)
 */
export function computeChainDigest(
  prevDigest: Digest | 'genesis',
  eventPayload: unknown,
  domainPrefix: string = DOMAIN_PREFIXES.EVENT
): Digest {
  const canonical = canonicalJson(eventPayload);
  const message = `${domainPrefix}${prevDigest}${canonical}`;
  return sha256Digest(message);
}

/**
 * Computes cryptographic commitment:
 * commitment = SHA-256(domain || canonical(payload) || nonce)
 */
export function computeCommitment(
  domain: string,
  payload: unknown,
  nonce: string
): Digest {
  const canonical = canonicalJson(payload);
  const message = `${DOMAIN_PREFIXES.COMMITMENT}${domain}:${canonical}:${nonce}`;
  return sha256Digest(message);
}

/**
 * Signs data using Ed25519 (sync).
 * Input private key can be hex string or Uint8Array.
 * Returns hex signature.
 */
export function signEd25519(
  data: Uint8Array | string,
  privateKeyHexOrBytes: string | Uint8Array = DEMO_KEYS.PRIVATE_KEY_HEX
): string {
  const msgBytes = typeof data === 'string' ? utf8ToBytes(data) : data;
  const privKey =
    typeof privateKeyHexOrBytes === 'string'
      ? hexToBytes(privateKeyHexOrBytes)
      : privateKeyHexOrBytes;
  const signatureBytes = ed.sign(msgBytes, privKey);
  return bytesToHex(signatureBytes);
}

/**
 * Verifies Ed25519 signature (sync).
 * Input public key can be hex string or Uint8Array.
 */
export function verifyEd25519(
  signatureHex: string,
  data: Uint8Array | string,
  publicKeyHexOrBytes: string | Uint8Array = DEMO_KEYS.PUBLIC_KEY_HEX
): boolean {
  try {
    const msgBytes = typeof data === 'string' ? utf8ToBytes(data) : data;
    const sigBytes = hexToBytes(signatureHex);
    const pubKey =
      typeof publicKeyHexOrBytes === 'string'
        ? hexToBytes(publicKeyHexOrBytes)
        : publicKeyHexOrBytes;
    return ed.verify(sigBytes, msgBytes, pubKey);
  } catch {
    return false;
  }
}

/**
 * Derives public key hex from a private key hex
 */
export function getPublicKeyHex(privateKeyHex: string): string {
  const privKey = hexToBytes(privateKeyHex);
  const pubKey = ed.getPublicKey(privKey);
  return bytesToHex(pubKey);
}

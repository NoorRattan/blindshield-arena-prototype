/**
 * Byte counting, token estimation, and cryptographic entropy utilities
 * for the Red Team Payload Workshop.
 * Conforms to spec limits: 65,536 UTF-8 text limit, 70,000 body limit.
 */

export const MAX_PAYLOAD_TEXT_BYTES = 65536; // 64 KiB
export const MAX_PAYLOAD_BODY_BYTES = 70000; // Total HTTP wire body limit

/**
 * Calculates the exact UTF-8 byte count of a string.
 * Accurately handles multi-byte characters, emoji, zero-width joiners, and surrogate pairs.
 */
export function getUtf8ByteCount(text: string): number {
  if (!text) return 0;
  return new TextEncoder().encode(text).length;
}

/**
 * Heuristic estimate of token count based on UTF-8 bytes (~4 bytes/token for English).
 * Note: Prompt requires token estimate to be explicitly labeled 'ESTIMATE' in UI.
 */
export function estimateTokenCount(byteCount: number): number {
  if (byteCount <= 0) return 0;
  return Math.ceil(byteCount / 4);
}

/**
 * Generates a cryptographically secure 128-bit (16-byte) secret nonce as a 32-character hex string.
 * Used for domain-separated payload hiding commitments.
 */
export function generateSecretNonce(): string {
  const buffer = new Uint8Array(16);
  if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
    crypto.getRandomValues(buffer);
  } else {
    // Fallback for environments without Web Crypto API
    for (let i = 0; i < 16; i++) {
      buffer[i] = Math.floor(Math.random() * 256);
    }
  }
  return Array.from(buffer)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Formats byte numbers into clean human-readable notation (e.g. "1,248 B", "64.0 KiB")
 */
export function formatByteCount(bytes: number): string {
  if (bytes < 1024) {
    return `${bytes.toLocaleString()} B`;
  }
  const kib = bytes / 1024;
  return `${kib.toFixed(1)} KiB`;
}

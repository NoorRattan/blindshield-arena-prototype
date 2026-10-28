import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { TrustAnchorsPanel } from './TrustAnchorsPanel';
import { BundleImportDropzone } from './BundleImportDropzone';
import { VerificationChecklistPanel } from './VerificationChecklistPanel';
import { DEMO_KEYS } from '../../lib/crypto';
import type { EvidenceBundle, VerificationReport, VerificationTrustAnchors } from './types';
import { MockArenaServer } from '../../lib/mock/server';

describe('Evidence Inspector UI Panels (P10-S2)', () => {
  const server = new MockArenaServer();
  const rawBundle = server.getEvidenceBundle('exp_released_04', 'auditor');
  const validBundle: EvidenceBundle = {
    metadata: rawBundle.metadata,
    ledger: rawBundle.ledger as EvidenceBundle['ledger'],
    checkpoint: rawBundle.checkpoint,
  };

  const initialAnchors: VerificationTrustAnchors = {
    publicKeyHex: DEMO_KEYS.PUBLIC_KEY_HEX,
    isPinned: true,
    expectedDomain: 'BAYORA-EVAL-04',
    expectedExperimentId: 'exp_released_04',
    expectedEpoch: 5,
    expectedManifestDigest: validBundle.checkpoint.manifest_digest,
    witnessedTerminalCheckpointReceipt: validBundle.checkpoint.witness_receipt,
  };

  it('renders TrustAnchorsPanel with pinned anchor mode and allows switching to unpinned bundle key', () => {
    const handleChange = vi.fn();
    render(<TrustAnchorsPanel anchors={initialAnchors} onChange={handleChange} />);

    expect(screen.getByText(/01 — TRUST ANCHORS & BOUNDARIES/i)).toBeInTheDocument();
    expect(screen.getByText(/EXTERNALLY PINNED/i)).toBeInTheDocument();

    // Click Unpinned Bundle Key radio button
    const bundleKeyRadio = screen.getByRole('radio', { name: /Bundle Key \(Unpinned\)/i });
    fireEvent.click(bundleKeyRadio);

    expect(handleChange).toHaveBeenCalledWith(
      expect.objectContaining({
        isPinned: false,
      })
    );
  });

  it('displays warning when unpinned key mode is active', () => {
    const unpinnedAnchors: VerificationTrustAnchors = {
      ...initialAnchors,
      isPinned: false,
    };
    render(<TrustAnchorsPanel anchors={unpinnedAnchors} onChange={vi.fn()} />);

    expect(screen.getByText(/UNTRUSTED \(BUNDLE KEY\)/i)).toBeInTheDocument();
    expect(screen.getByText(/Invariant 6 & Spec C-03 violation/i)).toBeInTheDocument();
  });

  it('renders BundleImportDropzone with loaded bundle summary and preset buttons', () => {
    const handleBundleLoaded = vi.fn();
    const handleLoadMock = vi.fn();
    const handleLoadLargeMock = vi.fn();

    render(
      <BundleImportDropzone
        currentBundle={validBundle}
        onBundleLoaded={handleBundleLoaded}
        onLoadMockPreset={handleLoadMock}
        onLoadLargeMockPreset={handleLoadLargeMock}
      />
    );

    expect(screen.getByText(/02 — EVIDENCE BUNDLE IMPORT/i)).toBeInTheDocument();
    expect(screen.getByText(/LOADED \(41 EVENTS\)/i)).toBeInTheDocument();
    expect(screen.getByText(/BAYORA-EVAL-04/i)).toBeInTheDocument();

    const mockPresetBtn = screen.getByRole('button', { name: /Released Epoch 04/i });
    fireEvent.click(mockPresetBtn);
    expect(handleLoadMock).toHaveBeenCalled();
  });

  it('renders VerificationChecklistPanel with 9 checks and Three Verdicts', () => {
    const mockReport: VerificationReport = {
      timestamp_utc: '2026-10-19T12:00:00Z',
      overall_verdict: 'VALID_WITHIN_PROFILE',
      verdicts: {
        authenticity: 'PASS',
        completeness: 'PASS',
        experimentalIntegrity: 'PASS',
      },
      checklist: [
        { id: 'SIGNATURE', name: 'Witness Ed25519 Signature', status: 'PASS', code: 'SIG_VALID', detail: 'Sig valid' },
        { id: 'CANONICAL_SCHEMA', name: 'RFC 8785 Schema', status: 'PASS', code: 'SCHEMA_VALID', detail: 'Schema valid' },
        { id: 'EPOCH_EXACT_TYPE', name: 'Epoch Positive Integer Strict Typing', status: 'PASS', code: 'EPOCH_TYPE_VALID', detail: 'Epoch valid' },
        { id: 'SEQUENCE_CONTINUITY', name: 'Ledger Sequence Monotonic Continuity', status: 'PASS', code: 'SEQ_VALID', detail: 'Seq valid' },
        { id: 'CHAIN_INTEGRITY', name: 'Domain-Separated Merkle Hash Chain', status: 'PASS', code: 'CHAIN_VALID', detail: 'Chain valid' },
        { id: 'TERMINAL_MARKER', name: 'Terminal Marker & Required Event Set', status: 'PASS', code: 'TERMINAL_VALID', detail: 'Terminal valid' },
        { id: 'MANIFEST_DIGEST', name: 'Manifest Digest & Run Boundary Match', status: 'PASS', code: 'MANIFEST_VALID', detail: 'Manifest valid' },
        { id: 'CIPHERTEXT_DIGESTS', name: 'Artifact & Ciphertext Digest Formats', status: 'PASS', code: 'CIPHERTEXT_VALID', detail: 'Digests valid' },
        { id: 'WITNESS_WATERMARK', name: 'Witness Receipt & Monotonic Watermark', status: 'PASS', code: 'WATERMARK_VALID', detail: 'Watermark valid' },
      ],
      trust_anchors: {
        public_key_hex: DEMO_KEYS.PUBLIC_KEY_HEX,
        is_pinned: true,
        expected_domain: 'BAYORA-EVAL-04',
        expected_experiment_id: 'exp_released_04',
        expected_epoch: 5,
        expected_manifest_digest: validBundle.checkpoint.manifest_digest,
      },
      bundle_summary: {
        experiment_id: 'exp_released_04',
        domain: 'BAYORA-EVAL-04',
        epoch: 5,
        event_count: 41,
        final_digest: validBundle.checkpoint.final_digest,
        manifest_digest: validBundle.checkpoint.manifest_digest,
        protocol: 'arena.v2',
        terminal_receipt: validBundle.checkpoint.witness_receipt,
      },
      duration_ms: 3,
    };

    const handleRunVerify = vi.fn();
    render(
      <VerificationChecklistPanel
        report={mockReport}
        isVerifying={false}
        onRunVerify={handleRunVerify}
      />
    );

    expect(screen.getByText(/03 — CRYPTOGRAPHIC VERIFICATION CHECKLIST/i)).toBeInTheDocument();
    expect(screen.getAllByText(/VALID_WITHIN_PROFILE/i)[0]).toBeInTheDocument();
    expect(screen.getByText(/Three Independent Verdicts/i)).toBeInTheDocument();
    expect(screen.getByText(/Epoch Positive Integer Strict Typing/i)).toBeInTheDocument();

    const verifyBtn = screen.getByRole('button', { name: /RUN VERIFICATION/i });
    fireEvent.click(verifyBtn);
    expect(handleRunVerify).toHaveBeenCalled();
  });
});

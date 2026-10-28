import { describe, it, expect } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { BrowserRouter } from 'react-router-dom';
import { EvidencePage } from './EvidencePage';

describe('EvidencePage Feature Component (P10-S4)', () => {
  const renderEvidencePage = () => {
    return render(
      <BrowserRouter>
        <EvidencePage />
      </BrowserRouter>
    );
  };

  it('renders PageHeader, trust anchors, dropzone, checklist, and chain view', async () => {
    renderEvidencePage();

    expect(
      screen.getByRole('heading', { level: 1, name: /EVIDENCE INSPECTOR & OFFLINE VERIFIER/i })
    ).toBeInTheDocument();
    expect(screen.getByText(/DOC-EVID-06/i)).toBeInTheDocument();
    expect(screen.getByText(/01 — TRUST ANCHORS & BOUNDARIES/i)).toBeInTheDocument();
    expect(screen.getByText(/02 — EVIDENCE BUNDLE IMPORT/i)).toBeInTheDocument();
    expect(screen.getByText(/03 — CRYPTOGRAPHIC VERIFICATION CHECKLIST/i)).toBeInTheDocument();
    expect(screen.getByText(/04 — MERKLE HASH CHAIN LEDGER/i)).toBeInTheDocument();
    expect(screen.getByText(/05 — CRYPTOGRAPHIC TAMPER PLAYGROUND/i)).toBeInTheDocument();
  });

  it('automatically verifies authentic preloaded mock bundle with VALID_WITHIN_PROFILE', async () => {
    renderEvidencePage();

    await waitFor(() => {
      expect(screen.getAllByText(/VALID_WITHIN_PROFILE/i)[0]).toBeInTheDocument();
    });

    expect(screen.getByText(/Three Independent Verdicts/i)).toBeInTheDocument();
    expect(screen.getByText(/Standing Verification Disclaimer:/i)).toBeInTheDocument();
  });

  it('rejects verification with UNTRUSTED_KEY when switching to unpinned bundle key (Invariant 6)', async () => {
    renderEvidencePage();

    await waitFor(() => {
      expect(screen.getAllByText(/VALID_WITHIN_PROFILE/i)[0]).toBeInTheDocument();
    });

    // Switch to unpinned bundle key
    const bundleKeyRadio = screen.getByRole('radio', { name: /Bundle Key \(Unpinned\)/i });
    fireEvent.click(bundleKeyRadio);

    await waitFor(() => {
      expect(screen.getByText(/REJECTED \(UNTRUSTED_KEY\)/i)).toBeInTheDocument();
    });
  });

  it('rejects verification with INVALID_EPOCH_TYPE when clicking Boolean Epoch True tamper (Invariant 5)', async () => {
    renderEvidencePage();

    await waitFor(() => {
      expect(screen.getAllByText(/VALID_WITHIN_PROFILE/i)[0]).toBeInTheDocument();
    });

    const booleanEpochBtn = screen.getByRole('button', { name: /BOOLEAN EPOCH TRUE/i });
    fireEvent.click(booleanEpochBtn);

    await waitFor(() => {
      expect(screen.getByText(/REJECTED \(INVALID_EPOCH_TYPE\)/i)).toBeInTheDocument();
    });

    expect(screen.getByText(/ACTIVE INJECTION: BOOLEAN_EPOCH/i)).toBeInTheDocument();
  });

  it('rejects verification with CHAIN_BROKEN on byte flip and restores on reset', async () => {
    renderEvidencePage();

    await waitFor(() => {
      expect(screen.getAllByText(/VALID_WITHIN_PROFILE/i)[0]).toBeInTheDocument();
    });

    const flipByteBtn = screen.getByRole('button', { name: /FLIP A BYTE/i });
    fireEvent.click(flipByteBtn);

    await waitFor(() => {
      expect(screen.getByText(/REJECTED \(CHAIN_BROKEN\)/i)).toBeInTheDocument();
    });

    // Reset tamper
    const resetBtn = screen.getByRole('button', { name: /RESTORE UNTAMPERED/i });
    fireEvent.click(resetBtn);

    await waitFor(() => {
      expect(screen.getAllByText(/VALID_WITHIN_PROFILE/i)[0]).toBeInTheDocument();
    });
  });

  it('renders ResidualRiskPanel and never claims zero leakage or tamper-proof', () => {
    renderEvidencePage();

    expect(screen.getByText(/THREAT SCOPE & RESIDUAL RISK/i)).toBeInTheDocument();
    expect(screen.queryByText(/zero leakage/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/tamper-proof/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/unhackable/i)).not.toBeInTheDocument();
  });
});

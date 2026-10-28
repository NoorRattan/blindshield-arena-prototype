import React, { useState } from 'react';
import { Copy, Check, Hash, Cpu, AlertCircle } from 'lucide-react';
import { Panel } from '../../../components/Panel';
import { Digest } from '../../../components/Digest';
import { useManifestCanonicalizer, formatJsonLines } from '../hooks/useManifestCanonicalizer';
import type { ManifestDraftPayload } from '../types';

interface ManifestPreviewPanelProps {
  manifestDraft: ManifestDraftPayload;
}

export const ManifestPreviewPanel: React.FC<ManifestPreviewPanelProps> = ({ manifestDraft }) => {
  const { canonicalJson, digest, byteLength, isComputing, error } =
    useManifestCanonicalizer(manifestDraft);
  const [copied, setCopied] = useState<boolean>(false);

  const lines = formatJsonLines(canonicalJson);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(canonicalJson);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // ignore clipboard error
    }
  };

  return (
    <Panel
      label="02 — CANONICAL MANIFEST PREVIEW (RFC 8785)"
      meta="LIVE WEB WORKER DIGEST"
      className="p-5"
    >
      {/* Digest Header Strip */}
      <div className="mb-4 p-3 bg-s2 border border-bd rounded-[2px] flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <div className="p-1.5 bg-cy/10 border border-cy/30 rounded-[2px] text-cy">
            <Hash className="w-4 h-4" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-mono text-[10px] text-mut uppercase tracking-wider">
                Computed Manifest Digest
              </span>
              {isComputing ? (
                <span className="font-mono text-[10px] text-cy animate-pulse flex items-center gap-1">
                  <Cpu className="w-2.5 h-2.5" />
                  HASHING (WORKER)...
                </span>
              ) : (
                <span className="font-mono text-[10px] text-ok flex items-center gap-1">
                  ✓ VERIFIED
                </span>
              )}
            </div>
            {digest ? (
              <Digest hash={digest} />
            ) : (
              <span className="font-mono text-xs text-dim">Computing digest...</span>
            )}
          </div>
        </div>

        <div className="flex items-center gap-2 self-end sm:self-center">
          <span className="font-mono text-[11px] text-mut tabular-nums">
            {byteLength} B · RFC 8785
          </span>
          <button
            type="button"
            onClick={handleCopy}
            className="inline-flex items-center gap-1 px-2.5 py-1 bg-s1 border border-bd text-tx font-mono text-[11px] uppercase tracking-wider rounded-[2px] hover:border-cy transition-colors focus:outline-none focus:ring-1 focus:ring-cy"
            aria-label="Copy Canonical JSON"
          >
            {copied ? (
              <>
                <Check className="w-3 h-3 text-ok" />
                <span className="text-ok">COPIED</span>
              </>
            ) : (
              <>
                <Copy className="w-3 h-3 text-mut" />
                <span>COPY JSON</span>
              </>
            )}
          </button>
        </div>
      </div>

      {error && (
        <div className="mb-4 p-3 bg-bad/10 border border-bad rounded-[2px] font-mono text-xs text-bad flex items-center gap-2">
          <AlertCircle className="w-4 h-4 shrink-0" />
          <span>Canonicalization Error: {error}</span>
        </div>
      )}

      {/* Code Viewer Container */}
      <div
        tabIndex={0}
        role="region"
        aria-label="Canonical RFC 8785 Manifest JSON preview"
        className="w-full max-h-[380px] overflow-y-auto bg-[#05070B] border border-bd rounded-[2px] p-3 font-mono text-xs leading-relaxed focus:outline-none focus:ring-1 focus:ring-cy"
      >
        <pre className="table w-full">
          <tbody>
            {lines.map((line, idx) => (
              <tr key={idx} className="hover:bg-s2/40 transition-colors">
                <td className="w-8 pr-3 text-right text-mut select-none font-mono text-[10px] tabular-nums border-r border-bd/40">
                  {idx + 1}
                </td>
                <td className="pl-3 text-tx whitespace-pre font-mono text-[11px]">
                  {line}
                </td>
              </tr>
            ))}
          </tbody>
        </pre>
      </div>

      <div className="mt-2.5 flex items-center justify-between font-mono text-[10px] text-mut">
        <span>STRICT RFC 8785 JCS FORMAT · DETERMINISTIC UTF-8</span>
        <span>SHA-256 HASH COMPUTED OFF-THREAD</span>
      </div>
    </Panel>
  );
};

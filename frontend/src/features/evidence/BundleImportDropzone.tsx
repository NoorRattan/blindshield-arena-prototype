import React, { useRef, useState } from 'react';
import { UploadCloud, FileJson, CheckCircle2, AlertCircle, RefreshCw, Database } from 'lucide-react';
import { Panel } from '../../components/Panel';
import { parseBundleJson, parseBundleZip } from './verifierCore';
import type { EvidenceBundle } from './types';

interface BundleImportDropzoneProps {
  currentBundle: EvidenceBundle | null;
  onBundleLoaded: (bundle: EvidenceBundle, fileName: string) => void;
  onLoadMockPreset: () => void;
  onLoadLargeMockPreset: () => void;
  className?: string;
}

export const BundleImportDropzone: React.FC<BundleImportDropzoneProps> = ({
  currentBundle,
  onBundleLoaded,
  onLoadMockPreset,
  onLoadLargeMockPreset,
  className,
}) => {
  const [isDragging, setIsDragging] = useState(false);
  const [importError, setImportError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const processFile = async (file: File) => {
    setImportError(null);
    try {
      if (file.name.endsWith('.json')) {
        const text = await file.text();
        const bundle = parseBundleJson(text);
        onBundleLoaded(bundle, file.name);
      } else if (file.name.endsWith('.zip')) {
        const buffer = await file.arrayBuffer();
        const bundle = parseBundleZip(new Uint8Array(buffer));
        onBundleLoaded(bundle, file.name);
      } else {
        throw new Error('Unsupported format. Only .json and .zip evidence bundles are accepted.');
      }
    } catch (err) {
      setImportError(err instanceof Error ? err.message : String(err));
    }
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = () => {
    setIsDragging(false);
  };

  const handleDrop = async (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    const file = e.dataTransfer.files[0];
    if (file) {
      await processFile(file);
    }
  };

  const handleFileChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      await processFile(file);
    }
  };

  return (
    <Panel
      label="02 — EVIDENCE BUNDLE IMPORT"
      meta=".JSON / .ZIP DROP ZONE"
      className={className}
    >
      <div className="space-y-3 font-mono text-xs">
        {/* Drop Zone Box */}
        <div
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onDrop={handleDrop}
          onClick={() => fileInputRef.current?.click()}
          onKeyDown={(e) => {
            if (e.key === 'Enter' || e.key === ' ') {
              e.preventDefault();
              fileInputRef.current?.click();
            }
          }}
          tabIndex={0}
          role="button"
          aria-label="Upload evidence bundle .json or .zip"
          className={`border-2 border-dashed rounded-[2px] p-4 text-center cursor-pointer transition-all duration-150 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cy ${
            isDragging
              ? 'border-cy bg-cy/10'
              : 'border-bd hover:border-bd-strong bg-s2/40'
          }`}
        >
          <input
            ref={fileInputRef}
            type="file"
            accept=".json,.zip"
            onChange={handleFileChange}
            className="hidden"
            tabIndex={-1}
            aria-hidden="true"
          />

          <div className="flex flex-col items-center justify-center gap-1.5 pointer-events-none">
            <UploadCloud size={24} className={isDragging ? 'text-cy' : 'text-mut'} />
            <div className="text-tx font-medium text-xs">
              Drop <span className="text-cy">.json</span> or <span className="text-cy">.zip</span> evidence bundle here
            </div>
            <div className="text-mut text-[11px]">or click to browse local files</div>
          </div>
        </div>

        {/* Import Error Banner */}
        {importError && (
          <div className="p-2.5 rounded-[2px] bg-s2 border border-bad/50 text-bad text-xs flex items-start gap-2">
            <AlertCircle size={14} className="shrink-0 mt-0.5 text-bad" />
            <div className="break-all">{importError}</div>
          </div>
        )}

        {/* Loaded Bundle Details Card */}
        {currentBundle && (
          <div className="p-2.5 rounded-[2px] bg-s2 border border-bd space-y-1.5">
            <div className="flex items-center justify-between text-[11px] text-mut pb-1 border-b border-bd/40">
              <span className="flex items-center gap-1.5 text-tx font-medium">
                <FileJson size={13} className="text-cy" />
                {currentBundle.metadata.experiment_id} (e{currentBundle.metadata.epoch})
              </span>
              <span className="inline-flex items-center gap-1 text-ok">
                <CheckCircle2 size={12} />
                LOADED ({currentBundle.ledger.length} EVENTS)
              </span>
            </div>

            <div className="grid grid-cols-2 gap-2 text-[11px]">
              <div>
                <span className="text-mut">Domain:</span>{' '}
                <span className="text-tx">{currentBundle.metadata.domain}</span>
              </div>
              <div>
                <span className="text-mut">Protocol:</span>{' '}
                <span className="text-tx">{currentBundle.checkpoint.protocol}</span>
              </div>
              <div className="col-span-2 truncate">
                <span className="text-mut">Checkpoint Receipt:</span>{' '}
                <span className="text-tx">{currentBundle.checkpoint.witness_receipt}</span>
              </div>
              <div className="col-span-2 truncate">
                <span className="text-mut">Final Digest:</span>{' '}
                <span className="text-tx text-[10px]">{currentBundle.checkpoint.final_digest}</span>
              </div>
            </div>
          </div>
        )}

        {/* Quick Preload Presets */}
        <div className="pt-2 border-t border-bd/60 flex flex-wrap items-center justify-between gap-2">
          <span className="text-[11px] text-mut uppercase tracking-wider">Presets:</span>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={onLoadMockPreset}
              className="px-2 py-1 rounded-[2px] bg-s2 border border-bd text-tx hover:border-cy text-[11px] flex items-center gap-1 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cy"
            >
              <RefreshCw size={11} className="text-cy" />
              Released Epoch 04 (41 Evt)
            </button>

            <button
              type="button"
              onClick={onLoadLargeMockPreset}
              className="px-2 py-1 rounded-[2px] bg-s2 border border-bd text-tx hover:border-cy text-[11px] flex items-center gap-1 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cy"
            >
              <Database size={11} className="text-cy" />
              Large Bundle (1,500 Evt)
            </button>
          </div>
        </div>
      </div>
    </Panel>
  );
};

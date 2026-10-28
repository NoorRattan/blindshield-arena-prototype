import React, { useState, useEffect, Suspense, lazy } from 'react';
import { Box, List, RefreshCw } from 'lucide-react';
import { Panel } from '../../components/Panel';
import type { ArenaEvent } from '../../lib/schemas';
import { EvidenceChain2DFallback } from './EvidenceChain2DFallback';
import { EventDetailDrawer } from './EventDetailDrawer';

// Lazy-load 3D scene to satisfy initial bundle budget
const EvidenceChain3DScene = lazy(() =>
  import('./EvidenceChain3DScene').then((mod) => ({ default: mod.EvidenceChain3DScene }))
);

interface EvidenceChainViewProps {
  ledger: ArenaEvent[];
  brokenIndex?: number;
  selectedSeq?: number;
  onSelectEvent?: (event: ArenaEvent) => void;
  className?: string;
}

function checkWebGLSupport(): boolean {
  if (typeof window === 'undefined') return false;
  try {
    const canvas = document.createElement('canvas');
    const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
    return Boolean(gl);
  } catch {
    return false;
  }
}

export const EvidenceChainView: React.FC<EvidenceChainViewProps> = ({
  ledger,
  brokenIndex,
  selectedSeq,
  onSelectEvent,
  className,
}) => {
  const [activeTab, setActiveTab] = useState<'3d' | '2d'>('3d');
  const [hasWebGL, setHasWebGL] = useState(true);
  const [selectedEvent, setSelectedEvent] = useState<ArenaEvent | null>(null);

  useEffect(() => {
    const supported = checkWebGLSupport();
    setHasWebGL(supported);
    if (!supported) {
      setActiveTab('2d');
    }
  }, []);

  // User explicitly selects an event by clicking a 3D block or 2D list item
  const handleSelect = (event: ArenaEvent) => {
    setSelectedEvent(event);
    onSelectEvent?.(event);
  };

  const currentTab = hasWebGL ? activeTab : '2d';

  return (
    <Panel
      label="04 — MERKLE HASH CHAIN LEDGER"
      meta={`${ledger.length} BLOCKS · ${brokenIndex !== undefined ? 'RUPTURED' : 'CONTINUOUS'}`}
      actions={
        <div className="flex items-center gap-1 bg-s1 p-0.5 rounded-[2px] border border-bd">
          <button
            type="button"
            disabled={!hasWebGL}
            onClick={() => setActiveTab('3d')}
            className={`px-2 py-0.5 rounded-[2px] text-[10px] font-mono uppercase transition-colors flex items-center gap-1 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-cy ${
              currentTab === '3d'
                ? 'bg-s2 text-cy font-bold border border-cy/40'
                : 'text-mut hover:text-tx'
            } disabled:opacity-30`}
            title={hasWebGL ? '3D Helix View' : 'WebGL not supported'}
          >
            <Box size={11} />
            3D Helix
          </button>

          <button
            type="button"
            onClick={() => setActiveTab('2d')}
            className={`px-2 py-0.5 rounded-[2px] text-[10px] font-mono uppercase transition-colors flex items-center gap-1 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-cy ${
              currentTab === '2d'
                ? 'bg-s2 text-cy font-bold border border-cy/40'
                : 'text-mut hover:text-tx'
            }`}
          >
            <List size={11} />
            2D List
          </button>
        </div>
      }
      className={className}
    >
      <div className="relative">
        {currentTab === '3d' ? (
          <Suspense
            fallback={
              <div className="h-[460px] flex flex-col items-center justify-center bg-s2/30 border border-dashed border-bd rounded-[2px] text-xs font-mono text-mut gap-2">
                <RefreshCw size={18} className="animate-spin text-cy" />
                <span>Loading 3D R3F Helix Shader...</span>
              </div>
            }
          >
            <EvidenceChain3DScene
              ledger={ledger}
              brokenIndex={brokenIndex}
              selectedSeq={selectedEvent?.seq ?? selectedSeq}
              onSelectEvent={handleSelect}
            />
          </Suspense>
        ) : (
          <EvidenceChain2DFallback
            ledger={ledger}
            brokenIndex={brokenIndex}
            selectedSeq={selectedEvent?.seq ?? selectedSeq}
            onSelectEvent={handleSelect}
          />
        )}
      </div>

      {/* Event Details Drawer */}
      <EventDetailDrawer
        event={selectedEvent}
        isOpen={Boolean(selectedEvent)}
        onClose={() => setSelectedEvent(null)}
      />
    </Panel>
  );
};

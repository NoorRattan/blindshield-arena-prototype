import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { AlertTriangle, X } from 'lucide-react';
import { FADE_VARIANTS, SLIDE_UP_VARIANTS } from '../design/motion';
import { cn } from '../lib/cn';

export interface ConfirmDialogProps {
  isOpen: boolean;
  title: string;
  description: string;
  confirmWord: string;
  confirmButtonLabel?: string;
  isDestructive?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}

export const ConfirmDialog: React.FC<ConfirmDialogProps> = ({
  isOpen,
  title,
  description,
  confirmWord,
  confirmButtonLabel = 'Execute Action',
  isDestructive = true,
  onConfirm,
  onCancel,
}) => {
  const [typedInput, setTypedInput] = useState('');
  const inputRef = React.useRef<HTMLInputElement>(null);

  // Reset input and focus when modal opens
  useEffect(() => {
    if (isOpen) {
      setTypedInput('');
      const timer = setTimeout(() => {
        inputRef.current?.focus();
      }, 50);
      return () => clearTimeout(timer);
    }
  }, [isOpen]);

  // Handle Escape key to cancel
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && isOpen) {
        onCancel();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onCancel]);

  const isConfirmed = typedInput.trim() === confirmWord.trim();

  return (
    <AnimatePresence>
      {isOpen && (
        <div
          role="dialog"
          aria-modal="true"
          aria-labelledby="confirm-dialog-title"
          className="fixed inset-0 z-50 overflow-y-auto"
        >
          {/* Backdrop Overlay */}
          <motion.div
            variants={FADE_VARIANTS}
            initial="initial"
            animate="animate"
            exit="exit"
            onClick={onCancel}
            className="fixed inset-0 bg-bg/85 backdrop-blur-sm"
          />

          <div className="relative z-10 flex min-h-full items-center justify-center p-4">
            {/* Modal Container */}
            <motion.div
              variants={SLIDE_UP_VARIANTS}
              initial="initial"
              animate="animate"
              exit="exit"
              className="relative w-full max-w-md bg-s1 border border-bd rounded p-6 shadow-none font-mono text-xs text-tx"
            >
            {/* Signature corner ticks */}
            <span aria-hidden="true" className="pointer-events-none absolute -top-px -left-px w-2 h-2 border-t-2 border-l-2 border-bd-strong" />
            <span aria-hidden="true" className="pointer-events-none absolute -top-px -right-px w-2 h-2 border-t-2 border-r-2 border-bd-strong" />
            <span aria-hidden="true" className="pointer-events-none absolute -bottom-px -left-px w-2 h-2 border-b-2 border-l-2 border-bd-strong" />
            <span aria-hidden="true" className="pointer-events-none absolute -bottom-px -right-px w-2 h-2 border-b-2 border-r-2 border-bd-strong" />

            {/* Header */}
            <div className="flex items-start justify-between gap-3 mb-3">
              <div className="flex items-center gap-2">
                <div
                  className={cn(
                    'w-6 h-6 rounded flex items-center justify-center border',
                    isDestructive ? 'bg-bad/10 border-bad text-bad' : 'bg-am/10 border-am text-am'
                  )}
                >
                  <AlertTriangle className="w-3.5 h-3.5 stroke-[2]" />
                </div>
                <h2 id="confirm-dialog-title" className="font-display text-xl text-tx tracking-wider uppercase">
                  {title}
                </h2>
              </div>
              <button
                type="button"
                onClick={onCancel}
                className="text-mut hover:text-tx focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-cy p-1 rounded"
                aria-label="Close dialog"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Description */}
            <p className="text-mut text-xs leading-relaxed mb-4">
              {description}
            </p>

            {/* Typed verification instruction */}
            <div className="bg-s2/60 border border-bd rounded p-3 mb-4">
              <label htmlFor="confirm-input-field" className="block text-[11px] text-mut uppercase tracking-wider mb-1.5">
                Type <strong className="text-tx font-mono">{confirmWord}</strong> to confirm:
              </label>
              <input
                ref={inputRef}
                id="confirm-input-field"
                type="text"
                value={typedInput}
                onChange={(e) => setTypedInput(e.target.value)}
                placeholder={confirmWord}
                className="w-full bg-bg border border-bd rounded px-2.5 py-1.5 font-mono text-xs text-tx focus:outline-none focus:border-cy"
              />
            </div>

            {/* Actions */}
            <div className="flex items-center justify-end gap-3 pt-2 border-t border-bd/60">
              <button
                type="button"
                onClick={onCancel}
                className="px-3 py-1.5 rounded border border-bd text-mut hover:text-tx hover:bg-s2 transition-colors uppercase tracking-wider text-[11px]"
              >
                Cancel
              </button>
              <button
                type="button"
                disabled={!isConfirmed}
                onClick={() => {
                  if (isConfirmed) onConfirm();
                }}
                className={cn(
                  'px-3.5 py-1.5 rounded uppercase tracking-wider font-medium text-[11px] transition-colors',
                  isConfirmed
                    ? isDestructive
                      ? 'bg-bad text-bg hover:opacity-90'
                      : 'bg-cy text-bg hover:opacity-90'
                    : 'bg-s2 text-mut border border-bd cursor-not-allowed'
                )}
              >
                {confirmButtonLabel}
              </button>
            </div>
          </motion.div>
          </div>
        </div>
      )}
    </AnimatePresence>
  );
};

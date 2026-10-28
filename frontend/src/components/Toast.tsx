import React, { createContext, useContext, useState, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { CheckCircle2, AlertTriangle, AlertOctagon, Info, X } from 'lucide-react';
import { SLIDE_UP_VARIANTS } from '../design/motion';
import { cn } from '../lib/cn';

export type ToastVariant = 'info' | 'success' | 'warning' | 'error';

export interface ToastItem {
  id: string;
  title: string;
  message?: string;
  variant?: ToastVariant;
  durationMs?: number;
}

interface ToastContextValue {
  showToast: (toast: Omit<ToastItem, 'id'>) => void;
  dismissToast: (id: string) => void;
}

const ToastContext = createContext<ToastContextValue | undefined>(undefined);

export const ToastProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [toasts, setToasts] = useState<ToastItem[]>([]);

  const dismissToast = useCallback((id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  const showToast = useCallback(
    ({ title, message, variant = 'info', durationMs = 4000 }: Omit<ToastItem, 'id'>) => {
      const id = `toast-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
      setToasts((prev) => [...prev, { id, title, message, variant, durationMs }]);

      if (durationMs > 0) {
        setTimeout(() => {
          dismissToast(id);
        }, durationMs);
      }
    },
    [dismissToast]
  );

  const getVariantStyles = (variant: ToastVariant) => {
    switch (variant) {
      case 'success':
        return {
          icon: CheckCircle2,
          border: 'border-ok/40',
          bg: 'bg-ok/10',
          text: 'text-ok',
        };
      case 'warning':
        return {
          icon: AlertTriangle,
          border: 'border-am/40',
          bg: 'bg-am/10',
          text: 'text-am',
        };
      case 'error':
        return {
          icon: AlertOctagon,
          border: 'border-bad/40',
          bg: 'bg-bad/10',
          text: 'text-bad',
        };
      case 'info':
      default:
        return {
          icon: Info,
          border: 'border-cy/40',
          bg: 'bg-cy/10',
          text: 'text-cy',
        };
    }
  };

  return (
    <ToastContext.Provider value={{ showToast, dismissToast }}>
      {children}
      {/* Toast container portal */}
      <div
        aria-live="polite"
        aria-atomic="false"
        className="fixed bottom-4 right-4 z-50 flex flex-col gap-2 max-w-sm w-full pointer-events-none"
      >
        <AnimatePresence>
          {toasts.map((toast) => {
            const styles = getVariantStyles(toast.variant || 'info');
            const Icon = styles.icon;

            return (
              <motion.div
                key={toast.id}
                variants={SLIDE_UP_VARIANTS}
                initial="initial"
                animate="animate"
                exit="exit"
                layout
                className={cn(
                  'pointer-events-auto flex items-start gap-3 p-3 rounded bg-s1 border font-mono text-xs text-tx shadow-none',
                  styles.border
                )}
              >
                <div
                  className={cn(
                    'w-5 h-5 rounded flex items-center justify-center shrink-0 border mt-0.5',
                    styles.bg,
                    styles.border,
                    styles.text
                  )}
                >
                  <Icon className="w-3 h-3 stroke-[2]" />
                </div>

                <div className="flex-1 truncate">
                  <div className="font-medium uppercase tracking-wider text-[11px] truncate">
                    {toast.title}
                  </div>
                  {toast.message && (
                    <div className="text-[11px] text-mut mt-0.5 leading-snug">
                      {toast.message}
                    </div>
                  )}
                </div>

                <button
                  type="button"
                  onClick={() => dismissToast(toast.id)}
                  className="text-mut hover:text-tx p-1 rounded focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-cy"
                  aria-label="Dismiss notification"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              </motion.div>
            );
          })}
        </AnimatePresence>
      </div>
    </ToastContext.Provider>
  );
};

export function useToast(): ToastContextValue {
  const context = useContext(ToastContext);
  if (!context) {
    throw new Error('useToast must be used within a ToastProvider');
  }
  return context;
}

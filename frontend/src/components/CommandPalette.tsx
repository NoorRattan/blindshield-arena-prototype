import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { Search, Navigation, UserCheck, CornerDownLeft, X } from 'lucide-react';
import { FADE_VARIANTS, SLIDE_UP_VARIANTS } from '../design/motion';
import { useArenaStore, type UserRole } from '../state/useArenaStore';
import { cn } from '../lib/cn';

interface CommandItem {
  id: string;
  category: 'Navigation' | 'Role' | 'Mode';
  title: string;
  shortcut?: string;
  action: () => void;
  icon: React.ComponentType<{ className?: string }>;
}

export const CommandPalette: React.FC = () => {
  const [isOpen, setIsOpen] = useState(false);
  const [query, setQuery] = useState('');
  const [selectedIndex, setSelectedIndex] = useState(0);
  const inputRef = React.useRef<HTMLInputElement>(null);
  const navigate = useNavigate();
  const { setRole, setConnectionMode } = useArenaStore();

  useEffect(() => {
    if (isOpen) {
      const timer = setTimeout(() => {
        inputRef.current?.focus();
      }, 50);
      return () => clearTimeout(timer);
    }
  }, [isOpen]);

  const commands: CommandItem[] = [
    // Navigation
    {
      id: 'nav-landing',
      category: 'Navigation',
      title: 'Go to Landing Page',
      shortcut: 'G L',
      action: () => navigate('/'),
      icon: Navigation,
    },
    {
      id: 'nav-overview',
      category: 'Navigation',
      title: 'Go to Arena Overview',
      shortcut: 'G O',
      action: () => navigate('/overview'),
      icon: Navigation,
    },
    {
      id: 'nav-setup',
      category: 'Navigation',
      title: 'Go to Setup & Preflight',
      shortcut: 'G S',
      action: () => navigate('/setup'),
      icon: Navigation,
    },
    {
      id: 'nav-war-room',
      category: 'Navigation',
      title: 'Go to Live War Room',
      shortcut: 'G W',
      action: () => navigate('/war-room'),
      icon: Navigation,
    },
    {
      id: 'nav-red',
      category: 'Navigation',
      title: 'Go to Red Team Portal',
      shortcut: 'G R',
      action: () => navigate('/red'),
      icon: Navigation,
    },
    {
      id: 'nav-blue',
      category: 'Navigation',
      title: 'Go to Blue Team Console',
      shortcut: 'G B',
      action: () => navigate('/blue'),
      icon: Navigation,
    },
    {
      id: 'nav-evidence',
      category: 'Navigation',
      title: 'Go to Evidence Inspector',
      shortcut: 'G E',
      action: () => navigate('/evidence'),
      icon: Navigation,
    },
    {
      id: 'nav-benchmarks',
      category: 'Navigation',
      title: 'Go to Benchmarks',
      shortcut: 'G K',
      action: () => navigate('/benchmarks'),
      icon: Navigation,
    },
    {
      id: 'nav-kit',
      category: 'Navigation',
      title: 'Go to Component Kit (Dev)',
      shortcut: 'G D',
      action: () => navigate('/__kit'),
      icon: Navigation,
    },
    // Roles
    {
      id: 'role-operator',
      category: 'Role',
      title: 'Switch Role to Operator',
      action: () => setRole('operator' as UserRole),
      icon: UserCheck,
    },
    {
      id: 'role-red',
      category: 'Role',
      title: 'Switch Role to Red Team',
      action: () => setRole('red' as UserRole),
      icon: UserCheck,
    },
    {
      id: 'role-blue',
      category: 'Role',
      title: 'Switch Role to Blue Team',
      action: () => setRole('blue' as UserRole),
      icon: UserCheck,
    },
    {
      id: 'role-auditor',
      category: 'Role',
      title: 'Switch Role to Auditor',
      action: () => setRole('auditor' as UserRole),
      icon: UserCheck,
    },
    // Modes
    {
      id: 'mode-simulated',
      category: 'Mode',
      title: 'Switch to Simulated Mode (In-Memory Demo)',
      action: () => setConnectionMode('simulated'),
      icon: UserCheck,
    },
    {
      id: 'mode-live',
      category: 'Mode',
      title: 'Switch to Live Backend Mode (Fail-Closed)',
      action: () => setConnectionMode('live'),
      icon: UserCheck,
    },
  ];

  const filteredCommands = commands.filter((cmd) =>
    cmd.title.toLowerCase().includes(query.toLowerCase()) ||
    cmd.category.toLowerCase().includes(query.toLowerCase())
  );

  // Keyboard shortcut listener for Cmd+K and two-key 'g' jumps
  useEffect(() => {
    let pendingG = false;
    let gTimeout: NodeJS.Timeout | null = null;

    const handleKeyDown = (e: KeyboardEvent) => {
      // Don't trigger 'g' shortcut if typing in input/textarea
      const target = e.target as HTMLElement;
      const isInput = target.tagName === 'INPUT' || target.tagName === 'TEXTAREA';

      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setIsOpen((prev) => !prev);
        return;
      }

      if (e.key === 'Escape' && isOpen) {
        e.preventDefault();
        setIsOpen(false);
        return;
      }

      if (!isInput && !isOpen) {
        if (e.key.toLowerCase() === 'g' && !pendingG) {
          pendingG = true;
          if (gTimeout) clearTimeout(gTimeout);
          gTimeout = setTimeout(() => {
            pendingG = false;
          }, 1000);
          return;
        }

        if (pendingG) {
          pendingG = false;
          if (gTimeout) clearTimeout(gTimeout);
          switch (e.key.toLowerCase()) {
            case 'l':
            case 'h':
              navigate('/');
              break;
            case 'o':
              navigate('/overview');
              break;
            case 's':
              navigate('/setup');
              break;
            case 'w':
              navigate('/war-room');
              break;
            case 'r':
              navigate('/red');
              break;
            case 'b':
              navigate('/blue');
              break;
            case 'e':
              navigate('/evidence');
              break;
            case 'k':
              navigate('/benchmarks');
              break;
            case 'd':
              navigate('/__kit');
              break;
          }
        }
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => {
      window.removeEventListener('keydown', handleKeyDown);
      if (gTimeout) clearTimeout(gTimeout);
    };
  }, [isOpen, navigate]);

  const executeCommand = (cmd: CommandItem) => {
    cmd.action();
    setIsOpen(false);
    setQuery('');
  };

  const handleModalKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setSelectedIndex((prev) => (prev + 1) % (filteredCommands.length || 1));
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setSelectedIndex((prev) => (prev - 1 + filteredCommands.length) % (filteredCommands.length || 1));
    } else if (e.key === 'Enter') {
      e.preventDefault();
      const selected = filteredCommands[selectedIndex];
      if (selected) executeCommand(selected);
    }
  };

  return (
    <AnimatePresence>
      {isOpen && (
        <div
          role="dialog"
          aria-modal="true"
          aria-label="Command Palette"
          className="fixed inset-0 z-50 flex items-start justify-center pt-24 p-4"
        >
          {/* Overlay */}
          <motion.div
            variants={FADE_VARIANTS}
            initial="initial"
            animate="animate"
            exit="exit"
            onClick={() => setIsOpen(false)}
            className="fixed inset-0 bg-bg/85 backdrop-blur-sm"
          />

          {/* Palette Box */}
          <motion.div
            variants={SLIDE_UP_VARIANTS}
            initial="initial"
            animate="animate"
            exit="exit"
            className="relative w-full max-w-lg bg-s1 border border-bd rounded overflow-hidden shadow-none font-mono text-xs z-10 text-tx"
          >
            {/* Signature corner ticks */}
            <span aria-hidden="true" className="pointer-events-none absolute -top-px -left-px w-2 h-2 border-t-2 border-l-2 border-bd-strong" />
            <span aria-hidden="true" className="pointer-events-none absolute -top-px -right-px w-2 h-2 border-t-2 border-r-2 border-bd-strong" />
            <span aria-hidden="true" className="pointer-events-none absolute -bottom-px -left-px w-2 h-2 border-b-2 border-l-2 border-bd-strong" />
            <span aria-hidden="true" className="pointer-events-none absolute -bottom-px -right-px w-2 h-2 border-b-2 border-r-2 border-bd-strong" />

            {/* Input Bar */}
            <div className="flex items-center gap-3 px-3.5 py-3 border-b border-bd bg-s2/50">
              <Search className="w-4 h-4 text-cy shrink-0" />
              <input
                ref={inputRef}
                type="text"
                value={query}
                onKeyDown={handleModalKeyDown}
                onChange={(e) => {
                  setQuery(e.target.value);
                  setSelectedIndex(0);
                }}
                placeholder="Type a command or jump to page... (ESC to close)"
                className="w-full bg-transparent border-none text-tx placeholder:text-mut font-mono text-xs focus:outline-none"
              />
              <button
                type="button"
                onClick={() => setIsOpen(false)}
                className="text-mut hover:text-tx p-1"
                aria-label="Close command palette"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            </div>

            {/* Results List */}
            <div className="max-h-80 overflow-y-auto p-1 divide-y divide-bd/30">
              {filteredCommands.length === 0 ? (
                <div className="p-6 text-center text-mut font-mono text-xs">
                  No matching commands found.
                </div>
              ) : (
                filteredCommands.map((cmd, idx) => {
                  const isSelected = selectedIndex === idx;
                  const Icon = cmd.icon;

                  return (
                    <button
                      key={cmd.id}
                      type="button"
                      onClick={() => executeCommand(cmd)}
                      onMouseEnter={() => setSelectedIndex(idx)}
                      className={cn(
                        'w-full flex items-center justify-between px-3 py-2 rounded text-left font-mono transition-colors',
                        isSelected ? 'bg-cy/15 text-tx font-medium' : 'text-mut hover:bg-s2/40'
                      )}
                    >
                      <div className="flex items-center gap-2.5 truncate">
                        <Icon className={cn('w-3.5 h-3.5 shrink-0', isSelected ? 'text-cy' : 'text-mut')} />
                        <span className="truncate">{cmd.title}</span>
                      </div>
                      <div className="flex items-center gap-2 shrink-0">
                        {cmd.shortcut && (
                          <kbd className="px-1.5 py-0.5 rounded bg-s2 border border-bd text-[10px] text-mut font-mono">
                            {cmd.shortcut}
                          </kbd>
                        )}
                        {isSelected && (
                          <CornerDownLeft className="w-3 h-3 text-cy" />
                        )}
                      </div>
                    </button>
                  );
                })
              )}
            </div>

            {/* Footer guide */}
            <div className="flex items-center justify-between px-3.5 py-2 border-t border-bd bg-s2/30 text-[10px] text-mut font-mono select-none">
              <span>Navigate: ↑ ↓ · Select: ↵</span>
              <span>Shortcuts: G then [L, O, S, W, R, B, E, K, D]</span>
            </div>
          </motion.div>
        </div>
      )}
    </AnimatePresence>
  );
};

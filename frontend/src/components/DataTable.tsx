import React, { useState } from 'react';
import { cn } from '../lib/cn';
import { Inbox } from 'lucide-react';

export interface Column<T> {
  id: string;
  header: React.ReactNode;
  accessor?: (row: T) => React.ReactNode;
  className?: string;
  width?: string;
}

export interface DataTableProps<T> {
  columns: Column<T>[];
  data: T[];
  keyExtractor: (row: T, index: number) => string | number;
  onRowClick?: (row: T, index: number) => void;
  selectedKey?: string | number;
  isLoading?: boolean;
  emptyMessage?: string;
  emptyAction?: React.ReactNode;
  className?: string;
}

export function DataTable<T>({
  columns,
  data,
  keyExtractor,
  onRowClick,
  selectedKey,
  isLoading = false,
  emptyMessage = 'No records recorded in current session.',
  emptyAction,
  className,
}: DataTableProps<T>) {
  const [focusedIndex, setFocusedIndex] = useState<number>(-1);

  const handleKeyDown = (e: React.KeyboardEvent, index: number, row: T) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      const next = Math.min(data.length - 1, index + 1);
      setFocusedIndex(next);
      const nextEl = document.getElementById(`table-row-${next}`);
      nextEl?.focus();
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      const prev = Math.max(0, index - 1);
      setFocusedIndex(prev);
      const prevEl = document.getElementById(`table-row-${prev}`);
      prevEl?.focus();
    } else if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      onRowClick?.(row, index);
    }
  };

  return (
    <div
      className={cn(
        'border border-bd bg-s1 rounded overflow-hidden flex flex-col font-mono text-xs',
        className
      )}
    >
      <div
        tabIndex={0}
        role="region"
        aria-label="Data Table"
        className="overflow-x-auto max-h-[480px] focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-cy"
      >
        <table className="w-full text-left border-collapse">
          {/* Sticky Header */}
          <thead className="sticky top-0 z-10 bg-s2/90 backdrop-blur-sm border-b border-bd text-mut uppercase text-[11px] tracking-wider select-none">
            <tr>
              {columns.map((col) => (
                <th
                  key={col.id}
                  scope="col"
                  style={col.width ? { width: col.width } : undefined}
                  className={cn('p-3 font-medium whitespace-nowrap', col.className)}
                >
                  {col.header}
                </th>
              ))}
            </tr>
          </thead>

          {/* Table Body */}
          <tbody className="divide-y divide-bd/60">
            {isLoading ? (
              // Loading skeleton rows
              Array.from({ length: 4 }).map((_, i) => (
                <tr key={`skeleton-${i}`} className="animate-pulse">
                  {columns.map((col) => (
                    <td key={col.id} className="p-3">
                      <div className="h-4 bg-s2/80 rounded w-3/4" />
                    </td>
                  ))}
                </tr>
              ))
            ) : data.length === 0 ? (
              // Empty State
              <tr>
                <td colSpan={columns.length} className="p-8 text-center text-mut">
                  <div className="flex flex-col items-center justify-center gap-2">
                    <Inbox className="w-6 h-6 text-mut stroke-[1.5]" />
                    <p className="text-xs">{emptyMessage}</p>
                    {emptyAction && <div className="mt-2">{emptyAction}</div>}
                  </div>
                </td>
              </tr>
            ) : (
              // Data Rows
              data.map((row, index) => {
                const key = keyExtractor(row, index);
                const isSelected = selectedKey !== undefined && selectedKey === key;
                const isFocused = focusedIndex === index;

                return (
                  <tr
                    id={`table-row-${index}`}
                    key={key}
                    tabIndex={onRowClick ? 0 : undefined}
                    onClick={() => onRowClick?.(row, index)}
                    onKeyDown={(e) => onRowClick && handleKeyDown(e, index, row)}
                    onFocus={() => setFocusedIndex(index)}
                    className={cn(
                      'transition-colors tabular-nums',
                      onRowClick && 'cursor-pointer select-none focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-cy focus-visible:bg-s2/50',
                      isSelected ? 'bg-cy/10 text-tx' : 'hover:bg-s2/40 text-tx',
                      isFocused && !isSelected && 'bg-s2/20'
                    )}
                  >
                    {columns.map((col) => (
                      <td key={col.id} className={cn('p-3', col.className)}>
                        {col.accessor ? col.accessor(row) : null}
                      </td>
                    ))}
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

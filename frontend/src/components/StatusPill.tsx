import React from 'react';
import {
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Clock,
  Lock,
  Activity,
  MinusCircle,
  AlertOctagon,
  type LucideIcon,
} from 'lucide-react';
import { cn } from '../lib/cn';

// Pinned status vocabulary from memory/design-system.md §11 + threat-scope-and-claims.md
export const ALL_STATUSES = [
  // Lifecycle
  'CREATED',
  'SEALED',
  'READY',
  'RUNNING',
  'SCORED',
  'CLOSED',
  'RELEASED',
  'INVALID',
  // Model execution & pipeline disposition
  'EXECUTED',
  'ALLOWED',
  'BLOCKED_BY_DEFENSE',
  'SANITIZED',
  'INFRASTRUCTURE_FAILED',
  'NOT_EVALUATED',
  'UNKNOWN',
  // Scoring
  'UNCERTAIN',
  'FAILED',
  // Integrity
  'PENDING',
  'VALID_WITHIN_PROFILE',
  // Access
  'EMBARGOED',
  'UNAVAILABLE',
  'DELAYED',
  // Errors (contracts/common.py ErrorCode)
  'UNAUTHORIZED',
  'FORBIDDEN',
  'WRONG_PHASE',
  'INVALID_SCHEMA',
  'VERSION_MISMATCH',
  'IDEMPOTENCY_CONFLICT',
  'BODY_TOO_LARGE',
  'RESOURCE_BUDGET_EXCEEDED',
  'DEADLINE_EXCEEDED',
  'AUDIT_UNAVAILABLE',
  'MODEL_UNAVAILABLE',
  'POLICY_NOT_READY',
  'STALE_EPOCH',
  'CONFLICT',
  // Threat scope & assurance (Q-005)
  'IN SCOPE',
  'BOUNDED',
  'OUT OF SCOPE',
  'PARTIAL',
  'NOT VERIFIED',
  'TESTED (profile)',
  'NOT MEASURED',
  'NOT ENABLED',
] as const;

export type StatusValue = (typeof ALL_STATUSES)[number];

interface StatusMeta {
  color: 'ok' | 'bad' | 'inv' | 'cy' | 'bl' | 'am' | 'emb';
  icon: LucideIcon;
}

const STATUS_CONFIG: Record<StatusValue, StatusMeta> = {
  // Lifecycle
  CREATED: { color: 'cy', icon: Activity },
  SEALED: { color: 'emb', icon: Lock },
  READY: { color: 'ok', icon: CheckCircle2 },
  RUNNING: { color: 'cy', icon: Activity },
  SCORED: { color: 'ok', icon: CheckCircle2 },
  CLOSED: { color: 'bl', icon: Clock },
  RELEASED: { color: 'cy', icon: Activity },
  INVALID: { color: 'inv', icon: AlertOctagon },

  // Model execution & pipeline disposition
  EXECUTED: { color: 'ok', icon: CheckCircle2 },
  ALLOWED: { color: 'ok', icon: CheckCircle2 },
  BLOCKED_BY_DEFENSE: { color: 'bad', icon: XCircle },
  SANITIZED: { color: 'am', icon: AlertTriangle },
  INFRASTRUCTURE_FAILED: { color: 'inv', icon: AlertOctagon },
  NOT_EVALUATED: { color: 'emb', icon: MinusCircle },
  UNKNOWN: { color: 'am', icon: AlertTriangle },

  // Scoring
  UNCERTAIN: { color: 'am', icon: AlertTriangle },
  FAILED: { color: 'bad', icon: XCircle },

  // Integrity
  PENDING: { color: 'emb', icon: Clock },
  VALID_WITHIN_PROFILE: { color: 'ok', icon: CheckCircle2 },

  // Access
  EMBARGOED: { color: 'emb', icon: Lock },
  UNAVAILABLE: { color: 'emb', icon: MinusCircle },
  DELAYED: { color: 'emb', icon: Clock },

  // Errors (contracts/common.py ErrorCode)
  UNAUTHORIZED: { color: 'inv', icon: AlertOctagon },
  FORBIDDEN: { color: 'inv', icon: AlertOctagon },
  WRONG_PHASE: { color: 'inv', icon: AlertTriangle },
  INVALID_SCHEMA: { color: 'inv', icon: AlertOctagon },
  VERSION_MISMATCH: { color: 'inv', icon: AlertTriangle },
  IDEMPOTENCY_CONFLICT: { color: 'inv', icon: AlertTriangle },
  BODY_TOO_LARGE: { color: 'bad', icon: XCircle },
  RESOURCE_BUDGET_EXCEEDED: { color: 'bad', icon: XCircle },
  DEADLINE_EXCEEDED: { color: 'bad', icon: Clock },
  AUDIT_UNAVAILABLE: { color: 'inv', icon: AlertOctagon },
  MODEL_UNAVAILABLE: { color: 'inv', icon: AlertOctagon },
  POLICY_NOT_READY: { color: 'am', icon: AlertTriangle },
  STALE_EPOCH: { color: 'inv', icon: AlertTriangle },
  CONFLICT: { color: 'inv', icon: AlertTriangle },

  // Threat scope & claims
  'IN SCOPE': { color: 'cy', icon: Activity },
  BOUNDED: { color: 'bl', icon: CheckCircle2 },
  'OUT OF SCOPE': { color: 'emb', icon: MinusCircle },
  PARTIAL: { color: 'bl', icon: AlertTriangle },
  'NOT VERIFIED': { color: 'emb', icon: MinusCircle },
  'TESTED (profile)': { color: 'ok', icon: CheckCircle2 },
  'NOT MEASURED': { color: 'emb', icon: MinusCircle },
  'NOT ENABLED': { color: 'emb', icon: Lock },
};

const COLOR_CLASSES: Record<
  StatusMeta['color'],
  { bg: string; text: string; border: string }
> = {
  ok: {
    bg: 'bg-ok/10',
    text: 'text-ok',
    border: 'border-ok/30',
  },
  bad: {
    bg: 'bg-bad/10',
    text: 'text-bad',
    border: 'border-bad/30',
  },
  inv: {
    bg: 'bg-inv/10',
    text: 'text-inv',
    border: 'border-inv/30',
  },
  cy: {
    bg: 'bg-cy/10',
    text: 'text-cy',
    border: 'border-cy/30',
  },
  bl: {
    bg: 'bg-bl/10',
    text: 'text-bl',
    border: 'border-bl/30',
  },
  am: {
    bg: 'bg-am/10',
    text: 'text-am',
    border: 'border-am/30',
  },
  emb: {
    bg: 'bg-emb/10',
    text: 'text-emb',
    border: 'border-emb/30',
  },
};

export interface StatusPillProps {
  status: StatusValue;
  label?: string;
  size?: 'sm' | 'md';
  className?: string;
}

export const StatusPill: React.FC<StatusPillProps> = ({
  status,
  label,
  size = 'md',
  className,
}) => {
  const meta = STATUS_CONFIG[status];
  const styling = COLOR_CLASSES[meta?.color ?? 'emb'];
  const IconComponent = meta?.icon ?? MinusCircle;
  const displayLabel = label ?? status;

  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 font-mono uppercase tracking-wider rounded border tabular-nums select-none',
        styling.bg,
        styling.text,
        styling.border,
        size === 'sm' ? 'px-1.5 py-0.5 text-[10px]' : 'px-2 py-0.5 text-xs',
        className
      )}
      data-status={status}
    >
      <IconComponent
        aria-hidden="true"
        className={size === 'sm' ? 'w-3 h-3 stroke-[1.5]' : 'w-3.5 h-3.5 stroke-[1.5]'}
      />
      <span>{displayLabel}</span>
    </span>
  );
};

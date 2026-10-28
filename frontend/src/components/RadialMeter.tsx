import React, { useRef } from 'react';
import { gsap, useGSAP } from '../design/gsap';
import { cn } from '../lib/cn';

export interface RadialMeterProps {
  value: number; // 0 to 100
  label?: string;
  size?: number;
  strokeWidth?: number;
  variant?: 'cy' | 'ok' | 'bad' | 'bl' | 'am';
  className?: string;
}

export const RadialMeter: React.FC<RadialMeterProps> = ({
  value,
  label,
  size = 110,
  strokeWidth = 6,
  variant = 'cy',
  className,
}) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const circleRef = useRef<SVGCircleElement>(null);
  const numberRef = useRef<HTMLSpanElement>(null);

  const radius = (size - strokeWidth * 2) / 2;
  const circumference = 2 * Math.PI * radius;
  const clampedValue = Math.min(Math.max(value, 0), 100);

  const variantStrokeMap: Record<typeof variant, string> = {
    cy: 'var(--cy)',
    ok: 'var(--ok)',
    bad: 'var(--bad)',
    bl: 'var(--bl)',
    am: 'var(--am)',
  };

  useGSAP(
    () => {
      if (!circleRef.current || !numberRef.current) return;

      const prefersReducedMotion = window.matchMedia(
        '(prefers-reduced-motion: reduce)'
      ).matches;

      const targetOffset = circumference - (clampedValue / 100) * circumference;

      if (prefersReducedMotion) {
        circleRef.current.style.strokeDashoffset = `${targetOffset}`;
        numberRef.current.textContent = `${Math.round(clampedValue)}`;
        return;
      }

      // Animate progress stroke
      gsap.to(circleRef.current, {
        strokeDashoffset: targetOffset,
        duration: 0.9,
        ease: 'power3.out',
      });

      // Animate numeric counter
      const counter = { val: 0 };
      gsap.to(counter, {
        val: clampedValue,
        duration: 0.9,
        ease: 'power3.out',
        onUpdate: () => {
          if (numberRef.current) {
            numberRef.current.textContent = `${Math.round(counter.val)}`;
          }
        },
      });
    },
    { scope: containerRef, dependencies: [clampedValue, circumference] }
  );

  return (
    <div
      ref={containerRef}
      className={cn('inline-flex flex-col items-center select-none font-mono', className)}
    >
      <div className="relative flex items-center justify-center" style={{ width: size, height: size }}>
        <svg width={size} height={size} className="-rotate-90">
          {/* Background Track */}
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="none"
            stroke="var(--bd)"
            strokeWidth={strokeWidth}
          />
          {/* Animated Value Ring */}
          <circle
            ref={circleRef}
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="none"
            stroke={variantStrokeMap[variant]}
            strokeWidth={strokeWidth}
            strokeDasharray={circumference}
            strokeDashoffset={circumference}
            strokeLinecap="round"
          />
        </svg>

        {/* Center Number Counter */}
        <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
          <div className="flex items-baseline">
            <span
              ref={numberRef}
              className="font-display text-2xl text-tx tracking-wider tabular-nums leading-none"
            >
              0
            </span>
            <span className="text-[10px] text-mut ml-0.5">%</span>
          </div>
        </div>
      </div>

      {label && (
        <span className="mt-1.5 text-[11px] text-mut uppercase tracking-wider text-center">
          {label}
        </span>
      )}
    </div>
  );
};

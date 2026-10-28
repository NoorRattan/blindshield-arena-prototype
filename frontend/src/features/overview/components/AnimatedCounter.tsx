import React, { useEffect, useRef, useState } from 'react';
import { gsap } from '../../../design/gsap';

interface AnimatedCounterProps {
  value: number;
  decimals?: number;
  suffix?: string;
  prefix?: string;
  className?: string;
}

/**
 * AnimatedCounter: Animates smoothly once on first mount via GSAP.
 * Subsequent updates reflect immediately without re-triggering animations.
 * Honors prefers-reduced-motion.
 */
export const AnimatedCounter: React.FC<AnimatedCounterProps> = ({
  value,
  decimals = 0,
  suffix = '',
  prefix = '',
  className = '',
}) => {
  const [displayValue, setDisplayValue] = useState<string>(() =>
    `${prefix}${value.toFixed(decimals)}${suffix}`
  );
  const isFirstMountRef = useRef<boolean>(true);
  const tweenObjRef = useRef<{ val: number }>({ val: 0 });

  useEffect(() => {
    if (isFirstMountRef.current) {
      isFirstMountRef.current = false;

      const prefersReducedMotion =
        typeof window !== 'undefined' &&
        window.matchMedia('(prefers-reduced-motion: reduce)').matches;

      if (prefersReducedMotion) {
        setDisplayValue(`${prefix}${value.toFixed(decimals)}${suffix}`);
        return;
      }

      tweenObjRef.current.val = 0;
      const tween = gsap.to(tweenObjRef.current, {
        val: value,
        duration: 1.1,
        ease: 'power3.out',
        onUpdate: () => {
          setDisplayValue(
            `${prefix}${tweenObjRef.current.val.toFixed(decimals)}${suffix}`
          );
        },
        onComplete: () => {
          setDisplayValue(`${prefix}${value.toFixed(decimals)}${suffix}`);
        },
      });

      return () => {
        tween.kill();
      };
    } else {
      // Subsequent updates happen without animation
      setDisplayValue(`${prefix}${value.toFixed(decimals)}${suffix}`);
    }
  }, [value, decimals, suffix, prefix]);

  return <span className={className}>{displayValue}</span>;
};

import type { Transition, Variants } from 'framer-motion';

// Pinned spring physics from memory/design-system.md §6
export const SPRING_PRESET = {
  type: 'spring',
  stiffness: 380,
  damping: 34,
} as const satisfies Transition;

// Standard ease curve [0.2, 0.7, 0.2, 1]
export const EASING_BEZIER = [0.2, 0.7, 0.2, 1] as const;

export const TRANSITION_FAST: Transition = {
  duration: 0.12,
  ease: EASING_BEZIER,
};

export const TRANSITION_NORMAL: Transition = {
  duration: 0.2,
  ease: EASING_BEZIER,
};

export const TRANSITION_SMOOTH: Transition = {
  duration: 0.36,
  ease: EASING_BEZIER,
};

// Fade variant for modal and presence
export const FADE_VARIANTS: Variants = {
  initial: { opacity: 0 },
  animate: { opacity: 1, transition: TRANSITION_NORMAL },
  exit: { opacity: 0, transition: TRANSITION_FAST },
};

// Subtle slide-up variant for panels and toast notifications
export const SLIDE_UP_VARIANTS: Variants = {
  initial: { opacity: 0, y: 8 },
  animate: { opacity: 1, y: 0, transition: SPRING_PRESET },
  exit: { opacity: 0, y: 4, transition: TRANSITION_FAST },
};

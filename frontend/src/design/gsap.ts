import gsap from 'gsap';
import { ScrollTrigger } from 'gsap/ScrollTrigger';
import { useGSAP } from '@gsap/react';

// Register ScrollTrigger and useGSAP once globally
if (typeof window !== 'undefined') {
  gsap.registerPlugin(ScrollTrigger, useGSAP);
}

// Preset timing tokens (ms mapped to seconds for GSAP)
export const DURATION = {
  INSTANT: 0.12,
  FAST: 0.2,
  NORMAL: 0.36,
  DELIBERATE: 0.9,
} as const;

// Standard ease curves
export const EASING = {
  OUT: 'power3.out',
  IN_OUT: 'power2.inOut',
  SHARP: 'expo.out',
} as const;

export { gsap, ScrollTrigger, useGSAP };

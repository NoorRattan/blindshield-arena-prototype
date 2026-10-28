import React from 'react';
import { cn } from '../lib/cn';

export interface SkeletonProps extends React.HTMLAttributes<HTMLDivElement> {
  width?: string | number;
  height?: string | number;
}

export const Skeleton: React.FC<SkeletonProps> = ({
  width,
  height,
  className,
  style,
  ...rest
}) => {
  return (
    <div
      aria-hidden="true"
      className={cn(
        'bg-s2/70 border border-bd/40 rounded-none animate-pulse select-none',
        className
      )}
      style={{
        width,
        height,
        ...style,
      }}
      {...rest}
    />
  );
};

import React from 'react';
import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { ErrorBoundary } from './ErrorBoundary';

const FaultyChild: React.FC<{ shouldThrow?: boolean }> = ({ shouldThrow }) => {
  if (shouldThrow) {
    throw new Error('Test injected subsystem explosion');
  }
  return <div>Subsystem nominal operation</div>;
};

describe('ErrorBoundary Component', () => {
  it('renders children when no error occurs', () => {
    render(
      <ErrorBoundary>
        <FaultyChild shouldThrow={false} />
      </ErrorBoundary>
    );

    expect(screen.getByText('Subsystem nominal operation')).toBeInTheDocument();
  });

  it('catches render error, displays ErrorState with code, and invokes onCatch callback', () => {
    const onCatchSpy = vi.fn();
    const consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

    render(
      <ErrorBoundary code="ERR_WAR_ROOM_FAULT" onCatch={onCatchSpy}>
        <FaultyChild shouldThrow={true} />
      </ErrorBoundary>
    );

    expect(screen.getByText('ERR_WAR_ROOM_FAULT')).toBeInTheDocument();
    expect(screen.getByText('CONSOLE RUNTIME EXCEPTION')).toBeInTheDocument();
    expect(screen.getByText(/Test injected subsystem explosion/i)).toBeInTheDocument();
    expect(onCatchSpy).toHaveBeenCalledTimes(1);

    consoleErrorSpy.mockRestore();
  });

  it('resets error state when retry button is triggered', () => {
    const consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

    let throwError = true;
    const DynamicChild: React.FC = () => {
      if (throwError) {
        throw new Error('Temporary failure');
      }
      return <div>Recovered nominal operation</div>;
    };

    render(
      <ErrorBoundary>
        <DynamicChild />
      </ErrorBoundary>
    );

    expect(screen.getByText('CONSOLE RUNTIME EXCEPTION')).toBeInTheDocument();

    // Fix condition and trigger retry
    throwError = false;
    const retryBtn = screen.getByRole('button', { name: /Reload Subsystem/i });
    fireEvent.click(retryBtn);

    expect(screen.getByText('Recovered nominal operation')).toBeInTheDocument();

    consoleErrorSpy.mockRestore();
  });
});

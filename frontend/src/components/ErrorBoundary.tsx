import { Component, type ErrorInfo, type ReactNode } from 'react';
import { ErrorState } from './ErrorState';

export interface ErrorBoundaryProps {
  children: ReactNode;
  fallback?: ReactNode | ((error: Error, reset: () => void) => ReactNode);
  code?: string;
  onCatch?: (error: Error, errorInfo: ErrorInfo) => void;
}

interface ErrorBoundaryState {
  hasError: boolean;
  error: Error | null;
}

export class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  constructor(props: ErrorBoundaryProps) {
    super(props);
    this.state = {
      hasError: false,
      error: null,
    };
  }

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return {
      hasError: true,
      error,
    };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo): void {
    if (this.props.onCatch) {
      this.props.onCatch(error, errorInfo);
    }
  }

  handleReset = (): void => {
    this.setState({
      hasError: false,
      error: null,
    });
  };

  render(): ReactNode {
    if (this.state.hasError && this.state.error) {
      if (typeof this.props.fallback === 'function') {
        return this.props.fallback(this.state.error, this.handleReset);
      }
      if (this.props.fallback) {
        return this.props.fallback;
      }

      return (
        <div className="p-4 w-full max-w-4xl mx-auto my-6">
          <ErrorState
            code={this.props.code ?? 'ERR_CLIENT_RUNTIME_EXCEPTION'}
            title="CONSOLE RUNTIME EXCEPTION"
            message="An unexpected client-side error interrupted this arena console subsystem. Security state and cryptographic invariants remain preserved."
            details={`Exception: ${this.state.error.message}\nStack: ${this.state.error.stack?.split('\n').slice(0, 3).join('\n') ?? 'N/A'}`}
            onRetry={this.handleReset}
            retryLabel="Reload Subsystem"
          />
        </div>
      );
    }

    return this.props.children;
  }
}

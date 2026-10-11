import React, { Component, ErrorInfo, ReactNode } from 'react';
import { ShieldAlert, RefreshCw, Home, Terminal, ChevronDown, ChevronUp } from 'lucide-react';

interface Props {
  children: ReactNode;
  fallback?: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
  errorInfo: ErrorInfo | null;
  showDetails: boolean;
}

export class ErrorBoundary extends Component<Props, State> {
  public state: State = {
    hasError: false,
    error: null,
    errorInfo: null,
    showDetails: false
  };

  public static getDerivedStateFromError(error: Error): Partial<State> {
    return { hasError: true, error };
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('[PhishNetra ErrorBoundary] Uncaught runtime exception:', error, errorInfo);
    this.setState({ errorInfo });
  }

  private handleReset = () => {
    this.setState({ hasError: false, error: null, errorInfo: null });
    window.location.reload();
  };

  private handleGoHome = () => {
    window.location.href = '/dashboard';
  };

  private toggleDetails = () => {
    this.setState((prev) => ({ showDetails: !prev.showDetails }));
  };

  public render() {
    if (this.state.hasError) {
      if (this.props.fallback) {
        return this.props.fallback;
      }

      const errorMessage = this.state.error?.message || 'An unexpected client-side error occurred.';
      const componentStack = this.state.errorInfo?.componentStack || '';

      return (
        <div className="min-h-[70vh] flex items-center justify-center p-6 animate-fadeIn">
          <div className="max-w-xl w-full rounded-2xl bg-slate-900/90 border border-rose-500/30 p-8 shadow-2xl backdrop-blur-xl relative overflow-hidden text-center space-y-6">
            {/* Top Security Glow Accent */}
            <div className="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-rose-500 via-amber-500 to-rose-500" />

            {/* Icon */}
            <div className="w-16 h-16 rounded-2xl bg-rose-500/10 border border-rose-500/20 flex items-center justify-center mx-auto text-rose-400 shadow-lg shadow-rose-500/10">
              <ShieldAlert className="w-8 h-8" />
            </div>

            {/* Heading */}
            <div className="space-y-2">
              <h2 className="text-xl font-bold tracking-tight text-white">
                Client Security Exception Handled
              </h2>
              <p className="text-xs text-slate-400 leading-relaxed max-w-md mx-auto">
                A runtime exception was intercepted by the PhishNetra Error Boundary. Zero-Trust exception containment prevented a browser-level crash.
              </p>
            </div>

            {/* Error Message Pill */}
            <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 text-left">
              <div className="text-[11px] font-mono text-rose-400 break-words">
                {errorMessage}
              </div>
            </div>

            {/* Action Buttons */}
            <div className="flex flex-wrap items-center justify-center gap-3 pt-2">
              <button
                type="button"
                onClick={this.handleReset}
                className="inline-flex items-center space-x-2 px-4 py-2.5 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-xs shadow-md shadow-cyan-500/20 transition-all active:scale-[0.98]"
              >
                <RefreshCw className="w-3.5 h-3.5" />
                <span>Reload Interface</span>
              </button>

              <button
                type="button"
                onClick={this.handleGoHome}
                className="inline-flex items-center space-x-2 px-4 py-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 font-semibold text-xs border border-slate-700 transition-all active:scale-[0.98]"
              >
                <Home className="w-3.5 h-3.5 text-slate-400" />
                <span>Return to Dashboard</span>
              </button>
            </div>

            {/* Diagnostic Stack Toggle */}
            <div className="pt-2 border-t border-slate-800/80">
              <button
                type="button"
                onClick={this.toggleDetails}
                className="inline-flex items-center space-x-1 text-[11px] text-slate-500 hover:text-slate-300 transition-colors"
              >
                <Terminal className="w-3 h-3" />
                <span>{this.state.showDetails ? 'Hide Stack Diagnostics' : 'Show Stack Diagnostics'}</span>
                {this.state.showDetails ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
              </button>

              {this.state.showDetails && componentStack && (
                <div className="mt-3 p-3 rounded-xl bg-slate-950/80 border border-slate-800 text-left overflow-x-auto max-h-48 text-[10px] font-mono text-slate-400 leading-tight">
                  <pre>{componentStack}</pre>
                </div>
              )}
            </div>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}

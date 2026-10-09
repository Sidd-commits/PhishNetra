import React, { useState } from 'react';
import { Link, useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { Shield, Lock, Mail, ArrowRight, AlertCircle, Eye, EyeOff, UserCheck, ShieldAlert } from 'lucide-react';

export const LoginPage: React.FC = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const { login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const from = (location.state as any)?.from?.pathname || '/dashboard';

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setIsSubmitting(true);

    try {
      await login({ email, password });
      navigate(from, { replace: true });
    } catch (err: any) {
      setError(
        err.response?.data?.message || err.message || 'Failed to authenticate. Please check your credentials.'
      );
    } finally {
      setIsSubmitting(false);
    }
  };

  const fillAdmin = () => {
    setEmail('admin@phishnetra.internal');
    setPassword('Admin@123456');
  };

  const fillAnalyst = () => {
    setEmail('siddhant@gmail.com');
    setPassword('Admin@123456');
  };

  return (
    <div className="min-h-[calc(100vh-4rem)] flex items-center justify-center px-4 py-12">
      <div className="w-full max-w-md space-y-6">
        {/* Brand Header */}
        <div className="text-center space-y-2">
          <div className="inline-flex p-3 rounded-2xl bg-gradient-to-tr from-cyan-500/20 to-indigo-500/20 border border-cyan-500/30 mb-2 shadow-lg shadow-cyan-500/10">
            <Shield className="w-8 h-8 text-cyan-400" />
          </div>
          <h1 className="text-2xl font-extrabold tracking-tight text-white">
            Enterprise SOC Access
          </h1>
          <p className="text-xs text-slate-400">
            Authenticate to access the PhishNetra Zero-Trust Threat Intelligence Platform
          </p>
        </div>

        {/* Login Form Card */}
        <div className="glass-panel p-8 rounded-2xl space-y-6 shadow-2xl border-slate-800/90">
          {error && (
            <div className="p-4 rounded-xl bg-rose-500/15 border border-rose-500/30 flex items-start space-x-3 text-rose-300 text-xs animate-in fade-in">
              <AlertCircle className="w-4 h-4 text-rose-400 mt-0.5 flex-shrink-0" />
              <span>{error}</span>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-[11px] font-semibold text-slate-300 mb-1.5 font-mono uppercase tracking-wider">
                Analyst Email
              </label>
              <div className="relative">
                <Mail className="w-4 h-4 text-slate-400 absolute left-3.5 top-3" />
                <input
                  type="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="admin@phishnetra.internal"
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl pl-10 pr-4 py-2.5 text-xs text-slate-100 placeholder-slate-600 focus:outline-none focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400 transition-all font-mono"
                />
              </div>
            </div>

            <div>
              <label className="block text-[11px] font-semibold text-slate-300 mb-1.5 font-mono uppercase tracking-wider">
                Passphrase
              </label>
              <div className="relative">
                <Lock className="w-4 h-4 text-slate-400 absolute left-3.5 top-3" />
                <input
                  type={showPassword ? 'text' : 'password'}
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••••••"
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl pl-10 pr-10 py-2.5 text-xs text-slate-100 placeholder-slate-600 focus:outline-none focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400 transition-all font-mono"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-3 text-slate-500 hover:text-slate-300 transition-colors"
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            <button
              type="submit"
              disabled={isSubmitting}
              className="w-full py-2.5 px-4 rounded-xl bg-gradient-to-r from-cyan-500 to-indigo-600 hover:from-cyan-400 hover:to-indigo-500 text-slate-950 font-bold text-xs shadow-lg shadow-cyan-500/20 transition-all flex items-center justify-center space-x-2 disabled:opacity-50 hover:scale-[1.01]"
            >
              {isSubmitting ? (
                <span>Authenticating Credentials...</span>
              ) : (
                <>
                  <span>Sign In to SOC Console</span>
                  <ArrowRight className="w-4 h-4" />
                </>
              )}
            </button>
          </form>

          {/* Quick Demo Credentials helper chips */}
          <div className="pt-4 border-t border-slate-800/80 space-y-2">
            <div className="text-[10px] font-mono uppercase text-slate-500 text-center tracking-wider">
              Quick Autofill Demo Accounts
            </div>
            <div className="flex items-center justify-center gap-2">
              <button
                type="button"
                onClick={fillAdmin}
                className="px-2.5 py-1 rounded-lg bg-slate-800/70 hover:bg-slate-700/80 text-cyan-300 text-[11px] font-mono border border-slate-700 transition-colors flex items-center space-x-1"
              >
                <ShieldAlert className="w-3 h-3 text-cyan-400" />
                <span>SOC Admin</span>
              </button>
              <button
                type="button"
                onClick={fillAnalyst}
                className="px-2.5 py-1 rounded-lg bg-slate-800/70 hover:bg-slate-700/80 text-indigo-300 text-[11px] font-mono border border-slate-700 transition-colors flex items-center space-x-1"
              >
                <UserCheck className="w-3 h-3 text-indigo-400" />
                <span>Analyst User</span>
              </button>
            </div>
          </div>
        </div>

        {/* Link to Register */}
        <p className="text-center text-xs text-slate-400">
          Need an analyst account?{' '}
          <Link to="/register" className="text-cyan-400 hover:underline font-semibold">
            Create Account
          </Link>
        </p>
      </div>
    </div>
  );
};
export default LoginPage;

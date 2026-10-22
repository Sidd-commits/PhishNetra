import React, { useState, useEffect } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import {
  ShieldAlert,
  LayoutDashboard,
  Search,
  Layers,
  Globe,
  FileText,
  Sliders,
  History,
  ShieldCheck,
  LogOut,
  UserCheck,
  Menu,
  X,
  Sparkles
} from 'lucide-react';

export const Navbar: React.FC = () => {
  const { user, logout, isAuthenticated } = useAuth();
  const location = useLocation();
  const navigate = useNavigate();
  const [mobileMenuOpen, setMobileMenuOpen] = useState<boolean>(false);

  useEffect(() => {
    setMobileMenuOpen(false);
  }, [location.pathname]);

  const handleLogout = async () => {
    await logout();
    navigate('/login');
  };

  const isActive = (path: string) => {
    if (path === '/dashboard') return location.pathname === '/dashboard';
    return location.pathname.startsWith(path);
  };

  const navLinks = [
    {
      to: '/dashboard',
      label: 'Dashboard',
      icon: LayoutDashboard,
      active: isActive('/dashboard')
    },
    {
      to: '/analyze',
      label: 'URL Threat Scanner',
      icon: Search,
      active: isActive('/analyze') || isActive('/analysis')
    },
    {
      to: '/attachments',
      label: 'Attachment Scanner',
      icon: FileText,
      badge: 'Core',
      active: isActive('/attachments') || isActive('/email-scanner') || isActive('/attachment-scanner')
    },
    {
      to: '/domains',
      label: 'Domain Intelligence',
      icon: Globe,
      active: isActive('/domains')
    },
    {
      to: '/batch',
      label: 'Batch Scanner',
      icon: Layers,
      active: isActive('/batch')
    },
    {
      to: '/history',
      label: 'Telemetry History',
      icon: History,
      active: isActive('/history')
    },
    {
      to: '/extension',
      label: 'Browser Extension',
      icon: ShieldCheck,
      highlight: true,
      active: isActive('/extension')
    },
    {
      to: '/settings',
      label: 'Settings',
      icon: Sliders,
      active: isActive('/settings')
    }
  ];

  return (
    <nav className="border-b border-slate-800/80 bg-slate-950/85 backdrop-blur-xl sticky top-0 z-50">
      <div className="max-w-[1440px] mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Left: Brand Logo + Desktop Direct Navigation */}
          <div className="flex items-center space-x-6 xl:space-x-8">
            {/* Brand Logo */}
            <div className="flex items-center">
              <Link to="/dashboard" className="flex items-center space-x-2.5 group shrink-0">
                <div className="w-9 h-9 rounded-xl bg-gradient-to-tr from-cyan-500 to-indigo-600 p-[1px] shadow-md shadow-cyan-500/20 group-hover:shadow-cyan-500/40 transition-all">
                  <div className="w-full h-full bg-slate-950 rounded-[10px] flex items-center justify-center">
                    <ShieldAlert className="w-5 h-5 text-cyan-400 group-hover:scale-105 transition-transform" />
                  </div>
                </div>
                <div className="flex flex-col">
                  <span className="text-lg font-bold tracking-tight text-white leading-tight">
                    Phish<span className="text-cyan-400">Netra</span>
                  </span>
                  <span className="text-[9px] font-mono text-slate-400 tracking-wider uppercase font-semibold">
                    Zero-Trust Shield
                  </span>
                </div>
              </Link>
            </div>

            {/* Visual Divider between Brand and Nav */}
            {isAuthenticated && (
              <div className="hidden xl:block h-5 w-px bg-slate-800 shrink-0" />
            )}

            {/* Desktop Direct Navigation (Aligned with Academic Scope) */}
            {isAuthenticated && (
              <div className="hidden lg:flex items-center space-x-1 xl:space-x-1.5">
                {navLinks.map((link) => {
                  const Icon = link.icon;
                  if (link.highlight) {
                    return (
                      <Link
                        key={link.to}
                        to={link.to}
                        className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all border ${
                          link.active
                            ? 'bg-cyan-500/20 text-cyan-300 border-cyan-500/40 shadow-inner'
                            : 'bg-cyan-950/30 text-cyan-400 border-cyan-500/20 hover:bg-cyan-500/10 hover:border-cyan-500/40'
                        }`}
                      >
                        <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                        <Icon className="w-3.5 h-3.5 text-cyan-400" />
                        <span>{link.label}</span>
                      </Link>
                    );
                  }

                  return (
                    <Link
                      key={link.to}
                      to={link.to}
                      className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors ${
                        link.active
                          ? 'bg-slate-800 text-cyan-400 shadow-inner'
                          : 'text-slate-300 hover:bg-slate-800/60 hover:text-white'
                      }`}
                    >
                      <Icon className="w-3.5 h-3.5" />
                      <span>{link.label}</span>
                      {link.badge && (
                        <span className="px-1.5 py-0.2 rounded text-[9px] font-mono bg-purple-500/20 text-purple-300 border border-purple-500/30">
                          {link.badge}
                        </span>
                      )}
                    </Link>
                  );
                })}
              </div>
            )}
          </div>

          {/* Right Action Section: User Info & Mobile Hamburger */}
          <div className="flex items-center space-x-3">
            {isAuthenticated && user ? (
              <div className="flex items-center space-x-3">
                <div className="hidden md:flex flex-col text-right">
                  <span className="text-xs font-medium text-slate-200">{user.name}</span>
                  <span className="text-[11px] text-slate-400 font-mono">
                    {user.role === 'ADMIN' ? 'Researcher (Admin)' : 'Security Analyst'}
                  </span>
                </div>
                <div className="w-8 h-8 rounded-full bg-slate-800 border border-slate-700/80 flex items-center justify-center text-slate-200 text-xs font-semibold">
                  {user.name.charAt(0).toUpperCase()}
                </div>
                <button
                  onClick={handleLogout}
                  title="Sign out"
                  className="p-1.5 text-slate-400 hover:text-rose-400 hover:bg-rose-500/10 rounded-lg transition-colors"
                >
                  <LogOut className="w-4 h-4" />
                </button>
              </div>
            ) : (
              <div className="flex items-center space-x-2">
                <Link
                  to="/login"
                  className="px-4 py-2 text-xs font-semibold text-slate-300 hover:text-white rounded-lg hover:bg-slate-800/60 transition-colors"
                >
                  Sign In
                </Link>
                <Link
                  to="/register"
                  className="px-4 py-2 text-xs font-semibold text-slate-950 bg-cyan-400 hover:bg-cyan-300 rounded-lg shadow-sm shadow-cyan-500/20 transition-colors flex items-center space-x-1.5"
                >
                  <UserCheck className="w-3.5 h-3.5" />
                  <span>Register</span>
                </Link>
              </div>
            )}

            {/* Mobile Hamburger Toggle */}
            {isAuthenticated && (
              <button
                onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
                className="lg:hidden p-2 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800 transition-colors"
              >
                {mobileMenuOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Mobile Menu Drawer */}
      {isAuthenticated && mobileMenuOpen && (
        <div className="lg:hidden border-t border-slate-800 bg-slate-950/95 backdrop-blur-xl px-4 pt-3 pb-6 space-y-2 animate-in slide-in-from-top-4">
          <div className="text-[10px] font-mono uppercase text-slate-500 px-3 pb-1">
            Core Detection Framework
          </div>
          {navLinks.map((link) => {
            const Icon = link.icon;
            return (
              <Link
                key={link.to}
                to={link.to}
                className={`flex items-center justify-between px-3 py-2 rounded-lg text-xs font-semibold transition-colors ${
                  link.active
                    ? 'bg-slate-800 text-cyan-400'
                    : 'text-slate-300 hover:bg-slate-800/60'
                }`}
              >
                <div className="flex items-center space-x-2.5">
                  <Icon className="w-4 h-4" />
                  <span>{link.label}</span>
                </div>
                {link.badge && (
                  <span className="px-1.5 py-0.5 rounded text-[9px] font-mono bg-purple-500/20 text-purple-300 border border-purple-500/30">
                    {link.badge}
                  </span>
                )}
                {link.highlight && (
                  <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                )}
              </Link>
            );
          })}
        </div>
      )}
    </nav>
  );
};

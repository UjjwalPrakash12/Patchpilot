import { Outlet, Link, useLocation } from 'react-router-dom';
import { ShieldCheck, Plus, History, Code2, ExternalLink } from 'lucide-react';

export default function Layout() {
  const location = useLocation();

  const navLinks = [
    { to: '/', label: 'Overview' },
    { to: '/scan/new', label: 'New Scan' },
    { to: '/history', label: 'Recent Activity' },
  ];

  return (
    <div className="min-h-screen bg-[#0b0d10] text-stone-100 selection:bg-blue-500/30 flex flex-col font-sans">
      {/* Background radial glow */}
      <div className="pointer-events-none fixed inset-0 bg-[radial-gradient(circle_at_76%_4%,rgba(37,99,235,0.12),transparent_28%),radial-gradient(circle_at_8%_38%,rgba(16,185,129,0.05),transparent_22%)]" />

      {/* Top Navigation */}
      <header className="relative border-b border-white/[0.08] bg-[#0b0d10]/90 backdrop-blur-md sticky top-0 z-50">
        <nav className="mx-auto flex max-w-7xl items-center justify-between px-5 py-4 lg:px-8">
          <Link to="/" className="flex items-center gap-3 group">
            <div className="grid size-9 place-items-center rounded-sm border border-blue-400/30 bg-blue-400/10 text-blue-400 shadow-[0_0_20px_rgba(37,99,235,0.18)] transition group-hover:border-blue-400/50">
              <ShieldCheck className="size-5" />
            </div>
            <div>
              <p className="text-sm font-semibold tracking-wide text-white flex items-center gap-1">
                PatchPilot<span className="text-blue-400 text-xs">.engine</span>
              </p>
              <p className="font-mono text-[10px] uppercase tracking-[0.2em] text-slate-500">
                Security Scanner & Fix Assistant
              </p>
            </div>
          </Link>

          {/* Navigation Links */}
          <div className="hidden items-center gap-7 text-sm md:flex">
            {navLinks.map(({ to, label }) => {
              const isActive = location.pathname === to;
              return (
                <Link
                  key={to}
                  to={to}
                  className={`transition-colors font-medium ${
                    isActive ? 'text-white' : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {label}
                </Link>
              );
            })}
          </div>

          {/* Right Controls */}
          <div className="flex items-center gap-3">
            <span className="hidden items-center gap-2 rounded-full border border-emerald-400/20 bg-emerald-400/[0.06] px-3 py-1.5 text-xs text-emerald-400 sm:flex">
              <span className="size-1.5 rounded-full bg-emerald-400 shadow-[0_0_8px_#34d399]" />
              Engine active
            </span>

            <Link
              to="/history"
              title="Workspace (Ujjwal Prakash)"
              className="grid size-9 place-items-center rounded-full border border-white/10 bg-white/[0.04] text-xs font-semibold text-slate-300 transition hover:border-white/20 hover:bg-white/[0.08]"
              aria-label="Developer Workspace"
            >
              UP
            </Link>
          </div>
        </nav>
      </header>

      {/* Main Content Area */}
      <main className="flex-1 relative">
        <Outlet />
      </main>

      {/* Footer */}
      <footer className="relative border-t border-white/[0.07] bg-[#090b0e] text-xs text-slate-500 py-8">
        <div className="mx-auto flex max-w-7xl flex-col gap-4 px-5 sm:flex-row sm:items-center sm:justify-between lg:px-8">
          <div className="flex items-center gap-2">
            <ShieldCheck className="size-4 text-blue-400" />
            <span>PatchPilot · End-Term Software Engineering Project by Ujjwal Prakash</span>
          </div>
          <div className="flex items-center gap-6">
            <Link to="/history" className="hover:text-slate-300 transition-colors">
              Scan History
            </Link>
            <Link to="/scan/new" className="hover:text-slate-300 transition-colors">
              New Scan
            </Link>
            <a
              href="https://github.com/ujjwalprakash"
              target="_blank"
              rel="noreferrer"
              className="hover:text-slate-300 transition-colors flex items-center gap-1"
            >
              <span>GitHub</span>
              <ExternalLink className="size-3" />
            </a>
          </div>
        </div>
      </footer>
    </div>
  );
}

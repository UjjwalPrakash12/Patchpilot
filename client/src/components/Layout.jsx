import { Outlet, Link, useLocation } from 'react-router-dom';
import { ShieldCheck, ExternalLink } from 'lucide-react';

export default function Layout() {
  const location = useLocation();

  const navLinks = [
    { to: '/', label: 'Overview' },
    { to: '/scan/new', label: 'New Scan' },
    { to: '/history', label: 'Recent Activity' },
  ];

  return (
    <div className="min-h-screen bg-[#2F3A32] text-[#DB9F75] flex flex-col font-sans selection:bg-[#804012] selection:text-[#DB9F75]">
      {/* Top Navigation Bar */}
      <header className="border-b border-[#545748]/50 bg-[#091026]/95 backdrop-blur-md sticky top-0 z-50 shadow-md">
        <nav className="mx-auto flex max-w-7xl items-center justify-between px-5 py-4 lg:px-8">
          <Link to="/" className="flex items-center gap-3 group">
            <div className="grid size-9 place-items-center rounded-sm border border-[#804012] bg-[#3E2411] text-[#DB9F75] shadow-sm transition group-hover:border-[#DB9F75]">
              <ShieldCheck className="size-5 text-[#DB9F75]" />
            </div>
            <div>
              <p className="text-sm font-semibold tracking-wide text-[#DB9F75] flex items-center gap-1">
                PatchPilot<span className="text-[#804012] text-xs">.engine</span>
              </p>
              <p className="font-mono text-[10px] uppercase tracking-[0.2em] text-[#545748]">
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
                    isActive ? 'text-[#DB9F75] font-semibold border-b-2 border-[#DB9F75] pb-0.5' : 'text-[#DB9F75]/70 hover:text-[#DB9F75]'
                  }`}
                >
                  {label}
                </Link>
              );
            })}
          </div>

          {/* Right Status & Workspace */}
          <div className="flex items-center gap-3">
            <span className="hidden items-center gap-2 rounded-full border border-[#545748] bg-[#3E2411] px-3 py-1.5 text-xs text-[#DB9F75] sm:flex">
              <span className="size-1.5 rounded-full bg-[#DB9F75] animate-pulse" />
              Engine active
            </span>

            <Link
              to="/history"
              title="Workspace (Ujjwal Prakash)"
              className="grid size-9 place-items-center rounded-full border border-[#804012] bg-[#3E2411] text-xs font-semibold text-[#DB9F75] transition hover:bg-[#804012]"
              aria-label="Developer Workspace"
            >
              UP
            </Link>
          </div>
        </nav>
      </header>

      {/* Main Page Area */}
      <main className="flex-1">
        <Outlet />
      </main>

      {/* Footer */}
      <footer className="border-t border-[#545748]/50 bg-[#091026] text-xs text-[#545748] py-8">
        <div className="mx-auto flex max-w-7xl flex-col gap-4 px-5 sm:flex-row sm:items-center sm:justify-between lg:px-8">
          <div className="flex items-center gap-2 text-[#DB9F75]/80">
            <ShieldCheck className="size-4 text-[#804012]" />
            <span>PatchPilot · End-Term Software Engineering Project by Ujjwal Prakash</span>
          </div>
          <div className="flex items-center gap-6">
            <Link to="/history" className="text-[#545748] hover:text-[#DB9F75] transition-colors">
              Scan History
            </Link>
            <Link to="/scan/new" className="text-[#545748] hover:text-[#DB9F75] transition-colors">
              New Scan
            </Link>
            <a
              href="https://github.com/ujjwalprakash"
              target="_blank"
              rel="noreferrer"
              className="text-[#545748] hover:text-[#DB9F75] transition-colors flex items-center gap-1"
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

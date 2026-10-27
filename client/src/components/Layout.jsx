import { Outlet, Link, useLocation } from 'react-router-dom';
import { Shield, Plus, History, Home } from 'lucide-react';

export default function Layout() {
  const location = useLocation();

  const navLinks = [
    { to: '/', label: 'Home', icon: Home },
    { to: '/scan/new', label: 'New Scan', icon: Plus },
    { to: '/history', label: 'History', icon: History },
  ];

  return (
    <div className="min-h-screen bg-gray-950 text-gray-100 flex flex-col">
      <header className="bg-gray-900 border-b border-gray-800 sticky top-0 z-50">
        <nav className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            <Link to="/" className="flex items-center space-x-2 group">
              <Shield className="h-7 w-7 text-emerald-500 group-hover:text-emerald-400 transition-colors" />
              <span className="text-xl font-bold text-white">PatchPilot</span>
            </Link>
            <div className="flex items-center space-x-1">
              {navLinks.map(({ to, label, icon: Icon }) => (
                <Link
                  key={to}
                  to={to}
                  className={`flex items-center space-x-1.5 px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                    location.pathname === to
                      ? 'bg-emerald-500/10 text-emerald-400'
                      : 'text-gray-400 hover:text-gray-200 hover:bg-gray-800'
                  }`}
                >
                  <Icon className="h-4 w-4" />
                  <span className="hidden sm:inline">{label}</span>
                </Link>
              ))}
            </div>
          </div>
        </nav>
      </header>

      <main className="flex-1">
        <Outlet />
      </main>

      <footer className="bg-gray-900 border-t border-gray-800 py-6">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex flex-col sm:flex-row items-center justify-between space-y-2 sm:space-y-0">
            <div className="flex items-center space-x-2">
              <Shield className="h-4 w-4 text-emerald-500" />
              <span className="text-sm text-gray-500">PatchPilot</span>
            </div>
            <p className="text-xs text-gray-600 text-center">
              PatchPilot helps identify potential security issues. It cannot guarantee complete security.
            </p>
          </div>
        </div>
      </footer>
    </div>
  );
}

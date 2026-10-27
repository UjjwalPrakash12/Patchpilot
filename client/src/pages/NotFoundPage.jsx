import { Link } from 'react-router-dom';
import { ShieldAlert, Home, ArrowLeft } from 'lucide-react';

export default function NotFoundPage() {
  return (
    <div className="min-h-[70vh] flex items-center justify-center px-4 sm:px-6 lg:px-8 py-16">
      <div className="max-w-md w-full text-center space-y-6">
        <div className="mx-auto w-16 h-16 rounded-2xl bg-gray-900 border border-gray-800 flex items-center justify-center text-emerald-400">
          <ShieldAlert className="h-8 w-8" />
        </div>

        <div>
          <p className="text-6xl font-black text-emerald-400 tracking-tight font-mono">
            404
          </p>
          <h1 className="text-2xl font-bold text-gray-100 mt-2">
            Page Not Found
          </h1>
          <p className="text-sm text-gray-400 mt-2 leading-relaxed">
            The page or security report you are looking for doesn't exist, has been deleted, or is unavailable.
          </p>
        </div>

        <div className="flex flex-col sm:flex-row items-center justify-center gap-3 pt-2">
          <Link
            to="/"
            className="w-full sm:w-auto inline-flex items-center justify-center gap-2 px-5 py-2.5 rounded-lg text-sm font-semibold text-gray-950 bg-emerald-400 hover:bg-emerald-300 transition-colors"
          >
            <Home className="h-4 w-4" />
            <span>Return to Home</span>
          </Link>

          <Link
            to="/history"
            className="w-full sm:w-auto inline-flex items-center justify-center gap-2 px-5 py-2.5 rounded-lg text-sm font-medium text-gray-300 bg-gray-900 hover:bg-gray-800 border border-gray-800 transition-colors"
          >
            <ArrowLeft className="h-4 w-4" />
            <span>Scan History</span>
          </Link>
        </div>
      </div>
    </div>
  );
}

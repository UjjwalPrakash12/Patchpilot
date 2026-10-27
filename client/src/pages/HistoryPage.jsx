import { useState, useEffect, useCallback } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import {
  History,
  Plus,
  Trash2,
  ExternalLink,
  Github,
  FileArchive,
  ArrowRight,
  Shield,
  Clock,
  AlertCircle,
  Eye,
} from 'lucide-react';
import { getScans, deleteScan } from '../services/api';
import useOwnerToken from '../hooks/useOwnerToken';
import { formatDate, getStatusBadge } from '../utils/severity';
import LoadingSpinner from '../components/LoadingSpinner';
import EmptyState from '../components/EmptyState';
import ConfirmDialog from '../components/ConfirmDialog';

export default function HistoryPage() {
  const navigate = useNavigate();
  const ownerToken = useOwnerToken();

  const [scans, setScans] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [errorMessage, setErrorMessage] = useState(null);

  // Delete modal state
  const [scanToDelete, setScanToDelete] = useState(null);
  const [isDeleting, setIsDeleting] = useState(false);

  const fetchScans = useCallback(async () => {
    try {
      setIsLoading(true);
      const res = await getScans(ownerToken);
      const scanList = res?.data || (Array.isArray(res) ? res : []);
      setScans(Array.isArray(scanList) ? scanList : []);
      setErrorMessage(null);
    } catch (err) {
      console.error('Error fetching scans:', err);
      setErrorMessage(err.message || 'Failed to load scan history');
    } finally {
      setIsLoading(false);
    }
  }, [ownerToken]);

  useEffect(() => {
    fetchScans();
  }, [fetchScans]);

  const handleDeleteConfirm = async () => {
    if (!scanToDelete) return;
    try {
      setIsDeleting(true);
      await deleteScan(scanToDelete.scanId, ownerToken);
      setScans((prev) => prev.filter((s) => s.scanId !== scanToDelete.scanId));
      setScanToDelete(null);
    } catch (err) {
      alert(`Failed to delete scan: ${err.message}`);
    } finally {
      setIsDeleting(false);
    }
  };

  return (
    <div className="py-8 px-4 sm:px-6 lg:px-8 max-w-7xl mx-auto space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-[#545748]/50 pb-6">
        <div>
          <h1 className="text-2xl sm:text-3xl font-extrabold text-[#DB9F75] flex items-center gap-3">
            <History className="h-7 w-7 text-[#DB9F75]" />
            <span>Scan History</span>
          </h1>
          <p className="mt-1 text-sm text-[#545748]">
            Review past security scans, monitor vulnerability trends, and revisit remediation reports.
          </p>
        </div>

        <div>
          <Link
            to="/scan/new"
            className="inline-flex items-center gap-2 px-4 py-2.5 rounded-lg text-sm font-semibold text-[#122372] bg-[#DB9F75] hover:bg-[#804012] hover:text-[#DB9F75] transition-colors shadow-md border border-[#DB9F75]"
          >
            <Plus className="h-4 w-4" />
            <span>New Scan</span>
          </Link>
        </div>
      </div>

      {/* Error state */}
      {errorMessage && (
        <div className="p-4 rounded-xl bg-[#3E2411] border border-[#804012] flex items-start gap-3">
          <AlertCircle className="h-5 w-5 text-[#804012] flex-shrink-0 mt-0.5" />
          <div className="flex-1">
            <p className="text-sm font-medium text-[#DB9F75]">{errorMessage}</p>
            <button
              onClick={fetchScans}
              className="mt-2 text-xs font-semibold text-[#DB9F75] hover:underline"
            >
              Retry loading
            </button>
          </div>
        </div>
      )}

      {/* Scans Content */}
      {isLoading ? (
        <div className="py-24 text-center">
          <LoadingSpinner size="lg" />
          <p className="mt-4 text-sm text-[#545748]">Loading your scan history...</p>
        </div>
      ) : scans.length === 0 ? (
        <div className="bg-[#122372] border border-[#545748] rounded-2xl p-12 text-center shadow-lg">
          <EmptyState
            icon={Shield}
            title="No Scans Yet"
            description="You haven't scanned any projects yet. Upload a ZIP archive or paste a GitHub repo URL to get started."
            action={
              <Link
                to="/scan/new"
                className="mt-4 inline-flex items-center gap-2 px-5 py-2.5 rounded-lg text-sm font-semibold text-[#122372] bg-[#DB9F75] hover:bg-[#804012] hover:text-[#DB9F75] transition-colors border border-[#DB9F75]"
              >
                <Plus className="h-4 w-4" />
                <span>Start Your First Scan</span>
              </Link>
            }
          />
        </div>
      ) : (
        <div className="bg-[#122372] border border-[#545748] rounded-xl overflow-hidden shadow-lg">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="bg-[#3E2411] border-b border-[#545748] text-xs font-semibold text-[#545748] uppercase tracking-wider">
                <tr>
                  <th scope="col" className="px-6 py-4">Project</th>
                  <th scope="col" className="px-6 py-4">Type</th>
                  <th scope="col" className="px-6 py-4">Status</th>
                  <th scope="col" className="px-6 py-4">Findings</th>
                  <th scope="col" className="px-6 py-4">Date</th>
                  <th scope="col" className="px-6 py-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#545748]/40 text-[#DB9F75]">
                {scans.map((scan) => {
                  const isZip = scan.submissionType === 'zip';

                  return (
                    <tr
                      key={scan.scanId}
                      className="hover:bg-[#3E2411] transition-colors group cursor-pointer"
                      onClick={() => navigate(`/scan/${scan.scanId}`)}
                    >
                      {/* Project Name & Link */}
                      <td className="px-6 py-4">
                        <div className="font-semibold text-[#DB9F75] group-hover:text-[#DB9F75] transition-colors">
                          {scan.projectName || 'Untitled Project'}
                        </div>
                        {scan.repositoryUrl ? (
                          <div className="text-xs text-[#545748] font-mono truncate max-w-xs mt-0.5">
                            {scan.repositoryUrl.replace('https://github.com/', '')}
                          </div>
                        ) : (
                          <div className="text-xs text-[#545748] font-mono mt-0.5">
                            ID: {scan.scanId.slice(0, 8)}...
                          </div>
                        )}
                      </td>

                      {/* Type Badge */}
                      <td className="px-6 py-4">
                        <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-medium bg-[#3E2411] border border-[#545748] text-[#DB9F75]">
                          {isZip ? (
                            <>
                              <FileArchive className="h-3.5 w-3.5 text-[#545748]" />
                              <span>ZIP</span>
                            </>
                          ) : (
                            <>
                              <Github className="h-3.5 w-3.5 text-[#545748]" />
                              <span>GitHub</span>
                            </>
                          )}
                        </span>
                      </td>

                      {/* Status Badge */}
                      <td className="px-6 py-4">
                        <span className={getStatusBadge(scan.status)}>
                          {scan.status}
                        </span>
                      </td>

                      {/* Findings Count */}
                      <td className="px-6 py-4">
                        {scan.status === 'completed' ? (
                          <div className="flex items-center gap-2">
                            <span
                              className={`font-semibold font-mono text-sm ${
                                scan.totalFindings > 0 ? 'text-[#804012]' : 'text-[#DB9F75]'
                              }`}
                            >
                              {scan.totalFindings ?? 0}
                            </span>
                            {scan.criticalCount > 0 && (
                              <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-[#804012]/30 border border-[#804012] text-[#DB9F75]">
                                {scan.criticalCount} crit
                              </span>
                            )}
                          </div>
                        ) : (
                          <span className="text-xs text-[#545748] font-mono">—</span>
                        )}
                      </td>

                      {/* Date */}
                      <td className="px-6 py-4 text-xs text-[#545748] whitespace-nowrap">
                        {formatDate(scan.createdAt)}
                      </td>

                      {/* Actions */}
                      <td
                        className="px-6 py-4 text-right space-x-2 whitespace-nowrap"
                        onClick={(e) => e.stopPropagation()}
                      >
                        <Link
                          to={`/scan/${scan.scanId}`}
                          className="inline-flex items-center gap-1 px-3 py-1.5 rounded-lg text-xs font-medium bg-[#3E2411] text-[#DB9F75] hover:bg-[#804012] border border-[#545748] transition-colors"
                        >
                          <Eye className="h-3.5 w-3.5 text-[#DB9F75]" />
                          <span>View</span>
                        </Link>

                        <button
                          type="button"
                          onClick={() => setScanToDelete(scan)}
                          className="inline-flex items-center gap-1 p-1.5 rounded-lg text-[#545748] hover:text-[#804012] hover:bg-[#3E2411] transition-colors"
                          title="Delete Scan"
                        >
                          <Trash2 className="h-4 w-4" />
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Delete Confirmation Dialog */}
      <ConfirmDialog
        isOpen={Boolean(scanToDelete)}
        title="Delete Scan Record"
        message={`Are you sure you want to delete scan "${scanToDelete?.projectName || scanToDelete?.scanId}"? All discovered findings and associated reports will be permanently removed.`}
        confirmLabel={isDeleting ? 'Deleting...' : 'Delete'}
        danger={true}
        onConfirm={handleDeleteConfirm}
        onCancel={() => setScanToDelete(null)}
      />
    </div>
  );
}

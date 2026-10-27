import { useState, useEffect, useCallback, useMemo } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import {
  Shield,
  ShieldCheck,
  AlertTriangle,
  Download,
  Trash2,
  Plus,
  RefreshCw,
  Search,
  Filter,
  ArrowLeft,
  Calendar,
  Clock,
  Github,
  FileArchive,
  ExternalLink,
  Layers,
  AlertOctagon,
  CheckCircle2,
  XCircle,
  HelpCircle,
} from 'lucide-react';
import {
  getScan,
  getScanFindings,
  deleteScan,
  exportScan,
  rescan,
} from '../services/api';
import useOwnerToken from '../hooks/useOwnerToken';
import usePolling from '../hooks/usePolling';
import {
  formatDate,
  formatDuration,
  getSeverityBadgeClasses,
  getStatusBadge,
} from '../utils/severity';
import ScanStatusIndicator from '../components/ScanStatusIndicator';
import FindingCard from '../components/FindingCard';
import SeverityBadge from '../components/SeverityBadge';
import EmptyState from '../components/EmptyState';
import LoadingSpinner from '../components/LoadingSpinner';
import ConfirmDialog from '../components/ConfirmDialog';

const SCANNER_LABELS = {
  secrets: 'Secrets Detection',
  dependencies: 'Dependency CVEs',
  staticAnalysis: 'Static Code Analysis',
  configuration: 'Configuration Security',
  projectSpecific: 'Framework Rules',
};

export default function ScanPage() {
  const { scanId } = useParams();
  const navigate = useNavigate();
  const ownerToken = useOwnerToken();

  const [scan, setScan] = useState(null);
  const [findings, setFindings] = useState([]);
  const [isLoadingScan, setIsLoadingScan] = useState(true);
  const [isLoadingFindings, setIsLoadingFindings] = useState(false);
  const [scanError, setScanError] = useState(null);

  // Filters
  const [severityFilter, setSeverityFilter] = useState('');
  const [categoryFilter, setCategoryFilter] = useState('');
  const [searchQuery, setSearchQuery] = useState('');

  // Dialog & Action states
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [isDeleting, setIsDeleting] = useState(false);
  const [isExporting, setIsExporting] = useState(false);
  const [isRescanning, setIsRescanning] = useState(false);

  // Fetch scan details
  const fetchScan = useCallback(async () => {
    if (!scanId) return;
    try {
      const response = await getScan(scanId, ownerToken);
      const scanData = response?.data || response;
      setScan(scanData);
      setScanError(null);
      return scanData;
    } catch (err) {
      console.error('Error fetching scan:', err);
      setScanError(err.message || 'Failed to load scan details');
    } finally {
      setIsLoadingScan(false);
    }
  }, [scanId, ownerToken]);

  // Initial load
  useEffect(() => {
    fetchScan();
  }, [fetchScan]);

  // Polling condition: poll when status is not 'completed' and not 'failed'
  const isScanningActive = Boolean(
    scan && scan.status !== 'completed' && scan.status !== 'failed'
  );

  usePolling(
    () => {
      fetchScan();
    },
    3000,
    isScanningActive
  );

  // Fetch findings when scan is completed
  const fetchFindings = useCallback(async () => {
    if (!scanId || scan?.status !== 'completed') return;
    try {
      setIsLoadingFindings(true);
      const filters = {};
      if (severityFilter) filters.severity = severityFilter;
      if (categoryFilter) filters.category = categoryFilter;
      if (searchQuery.trim()) filters.search = searchQuery.trim();

      const response = await getScanFindings(scanId, ownerToken, filters);
      const findingsList = response?.data || (Array.isArray(response) ? response : []);
      setFindings(Array.isArray(findingsList) ? findingsList : []);
    } catch (err) {
      console.error('Error fetching findings:', err);
    } finally {
      setIsLoadingFindings(false);
    }
  }, [scanId, ownerToken, scan?.status, severityFilter, categoryFilter, searchQuery]);

  useEffect(() => {
    if (scan?.status === 'completed') {
      fetchFindings();
    }
  }, [scan?.status, fetchFindings]);

  // Actions
  const handleExport = async () => {
    try {
      setIsExporting(true);
      const reportData = await exportScan(scanId, ownerToken);
      const blob = new Blob(
        [typeof reportData === 'string' ? reportData : JSON.stringify(reportData, null, 2)],
        { type: 'application/json' }
      );
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `patchpilot-${scan?.projectName || 'scan'}-${scanId.slice(0, 8)}.json`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);
    } catch (err) {
      alert(`Export failed: ${err.message}`);
    } finally {
      setIsExporting(false);
    }
  };

  const handleDelete = async () => {
    try {
      setIsDeleting(true);
      await deleteScan(scanId, ownerToken);
      setShowDeleteConfirm(false);
      navigate('/history');
    } catch (err) {
      alert(`Failed to delete scan: ${err.message}`);
    } finally {
      setIsDeleting(false);
    }
  };

  const handleRescan = async () => {
    try {
      setIsRescanning(true);
      await rescan(scanId, ownerToken);
      await fetchScan();
    } catch (err) {
      alert(`Failed to rescan: ${err.message}`);
    } finally {
      setIsRescanning(false);
    }
  };

  // Severity Distribution calculations
  const totalFindingsCount = scan?.totalFindings || 0;
  const criticalCount = scan?.criticalCount || 0;
  const highCount = scan?.highCount || 0;
  const mediumCount = scan?.mediumCount || 0;
  const lowCount = scan?.lowCount || 0;
  const infoCount = scan?.infoCount || 0;

  const distributionPercents = useMemo(() => {
    if (totalFindingsCount === 0) return null;
    return {
      critical: (criticalCount / totalFindingsCount) * 100,
      high: (highCount / totalFindingsCount) * 100,
      medium: (mediumCount / totalFindingsCount) * 100,
      low: (lowCount / totalFindingsCount) * 100,
      info: (infoCount / totalFindingsCount) * 100,
    };
  }, [totalFindingsCount, criticalCount, highCount, mediumCount, lowCount, infoCount]);

  if (isLoadingScan && !scan) {
    return (
      <div className="py-24 text-center">
        <LoadingSpinner size="lg" />
        <p className="mt-4 text-sm text-[#545748]">Loading scan report...</p>
      </div>
    );
  }

  if (scanError && !scan) {
    return (
      <div className="py-16 px-4 max-w-xl mx-auto text-center">
        <div className="bg-[#3E2411] border border-[#804012] rounded-xl p-6">
          <AlertOctagon className="h-12 w-12 text-[#804012] mx-auto mb-3" />
          <h2 className="text-lg font-semibold text-[#DB9F75]">Unable to Load Scan</h2>
          <p className="text-sm text-[#DB9F75]/80 mt-2">{scanError}</p>
          <div className="mt-6 flex justify-center gap-3">
            <Link
              to="/history"
              className="px-4 py-2 text-sm font-medium bg-[#122372] text-[#DB9F75] hover:bg-[#3E2411] border border-[#545748] rounded-lg transition-colors"
            >
              Scan History
            </Link>
            <Link
              to="/scan/new"
              className="px-4 py-2 text-sm font-medium bg-[#DB9F75] text-[#122372] hover:bg-[#804012] hover:text-[#DB9F75] border border-[#DB9F75] rounded-lg transition-colors"
            >
              New Scan
            </Link>
          </div>
        </div>
      </div>
    );
  }

  const isCompleted = scan?.status === 'completed';
  const isFailed = scan?.status === 'failed';
  const isRunning = !isCompleted && !isFailed;

  return (
    <div className="py-8 px-4 sm:px-6 lg:px-8 max-w-7xl mx-auto space-y-8">
      {/* Top Header / Breadcrumb & Controls */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-[#545748]/50 pb-6">
        <div>
          <div className="flex items-center gap-2 mb-2">
            <Link
              to="/history"
              className="inline-flex items-center gap-1 text-xs text-[#545748] hover:text-[#DB9F75] transition-colors"
            >
              <ArrowLeft className="h-3.5 w-3.5" />
              <span>Back to Scan History</span>
            </Link>
          </div>
          <div className="flex items-center gap-3 flex-wrap">
            <h1 className="text-2xl sm:text-3xl font-extrabold text-[#DB9F75]">
              {scan?.projectName || 'Security Scan'}
            </h1>
            <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-semibold bg-[#122372] border border-[#545748] text-[#DB9F75]">
              {scan?.submissionType === 'github' ? (
                <>
                  <Github className="h-3.5 w-3.5 text-[#545748]" />
                  <span>GitHub</span>
                </>
              ) : (
                <>
                  <FileArchive className="h-3.5 w-3.5 text-[#545748]" />
                  <span>ZIP Archive</span>
                </>
              )}
            </span>
          </div>
          <div className="flex items-center gap-4 text-xs text-[#545748] mt-2 flex-wrap">
            <span className="flex items-center gap-1">
              <Calendar className="h-3.5 w-3.5" />
              <span>Created: {formatDate(scan?.createdAt)}</span>
            </span>
            {scan?.completedAt && (
              <span className="flex items-center gap-1">
                <Clock className="h-3.5 w-3.5" />
                <span>Duration: {formatDuration(scan?.startedAt || scan?.createdAt, scan?.completedAt)}</span>
              </span>
            )}
            {scan?.repositoryUrl && (
              <a
                href={scan.repositoryUrl}
                target="_blank"
                rel="noreferrer"
                className="flex items-center gap-1 text-[#DB9F75] hover:underline"
              >
                <span>Repo Link</span>
                <ExternalLink className="h-3 w-3" />
              </a>
            )}
          </div>
        </div>

        {/* Action Buttons */}
        <div className="flex items-center gap-2 flex-wrap sm:flex-nowrap">
          {isCompleted && (
            <button
              onClick={handleExport}
              disabled={isExporting}
              className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg text-sm font-medium bg-[#122372] text-[#DB9F75] border border-[#545748] hover:bg-[#3E2411] transition-colors disabled:opacity-50"
              title="Download full JSON report"
            >
              {isExporting ? (
                <LoadingSpinner size="sm" />
              ) : (
                <Download className="h-4 w-4 text-[#DB9F75]" />
              )}
              <span>Export Report</span>
            </button>
          )}

          <Link
            to="/scan/new"
            className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg text-sm font-semibold bg-[#DB9F75] text-[#122372] hover:bg-[#804012] hover:text-[#DB9F75] border border-[#DB9F75] transition-colors shadow-sm"
          >
            <Plus className="h-4 w-4" />
            <span>New Scan</span>
          </Link>

          {(isCompleted || isFailed) && (
            <button
              onClick={handleRescan}
              disabled={isRescanning}
              className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg text-sm font-medium bg-[#122372] text-[#DB9F75] border border-[#545748] hover:bg-[#3E2411] transition-colors disabled:opacity-50"
              title="Rerun scanners against codebase"
            >
              <RefreshCw className={`h-4 w-4 ${isRescanning ? 'animate-spin' : ''}`} />
              <span className="hidden sm:inline">Rescan</span>
            </button>
          )}

          <button
            onClick={() => setShowDeleteConfirm(true)}
            className="inline-flex items-center gap-1.5 px-3 py-2 rounded-lg text-sm font-medium bg-[#3E2411] text-[#804012] border border-[#804012] hover:bg-[#804012] hover:text-[#DB9F75] transition-colors"
            title="Delete this scan"
          >
            <Trash2 className="h-4 w-4" />
          </button>
        </div>
      </div>

      {/* 1. STATE: SCANNING IN PROGRESS */}
      {isRunning && (
        <div className="space-y-6">
          <div className="bg-[#122372] border border-[#545748] rounded-2xl p-6 sm:p-8 text-center space-y-4 shadow-xl">
            <div className="flex justify-center">
              <ScanStatusIndicator status={scan.status} className="text-lg" />
            </div>
            <p className="text-sm text-[#545748] max-w-md mx-auto">
              Scanning your project codebase. Results will update dynamically as each scanner completes its run.
            </p>
          </div>

          {/* Scanner Status Cards */}
          <div className="space-y-3">
            <h3 className="text-base font-semibold text-[#DB9F75] flex items-center gap-2">
              <Layers className="h-4 w-4 text-[#DB9F75]" />
              <span>Multi-Scanner Pipeline Status</span>
            </h3>

            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
              {scan.scannerResults &&
                Object.entries(scan.scannerResults).map(([scannerKey, resObj]) => {
                  const scannerStatus = resObj?.status || 'pending';
                  const findingCount = resObj?.findingCount ?? 0;
                  const label = SCANNER_LABELS[scannerKey] || scannerKey;

                  return (
                    <div
                      key={scannerKey}
                      className="bg-[#122372] border border-[#545748] rounded-xl p-4 flex items-center justify-between shadow-sm"
                    >
                      <div className="min-w-0">
                        <p className="text-sm font-medium text-[#DB9F75] truncate">{label}</p>
                        <p className="text-xs text-[#545748] mt-0.5">
                          Findings: <span className="text-[#DB9F75] font-mono">{findingCount}</span>
                        </p>
                      </div>
                      <span className={getStatusBadge(scannerStatus)}>
                        {scannerStatus}
                      </span>
                    </div>
                  );
                })}
            </div>
          </div>
        </div>
      )}

      {/* 2. STATE: SCAN FAILED */}
      {isFailed && (
        <div className="bg-[#3E2411] border border-[#804012] rounded-2xl p-6 sm:p-8 space-y-4 shadow-xl">
          <div className="flex items-start gap-3">
            <XCircle className="h-6 w-6 text-[#804012] flex-shrink-0 mt-0.5" />
            <div className="flex-1">
              <h2 className="text-lg font-semibold text-[#DB9F75]">Scan Execution Failed</h2>
              <p className="text-sm text-[#DB9F75]/80 mt-1">
                {scan?.errorMessage || 'An error occurred during archive extraction or scanner execution.'}
              </p>
              <div className="mt-6 flex items-center gap-3">
                <button
                  onClick={handleRescan}
                  disabled={isRescanning}
                  className="inline-flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-semibold bg-[#DB9F75] text-[#122372] hover:bg-[#804012] hover:text-[#DB9F75] border border-[#DB9F75] transition-colors shadow-sm"
                >
                  <RefreshCw className={`h-4 w-4 ${isRescanning ? 'animate-spin' : ''}`} />
                  <span>Retry Scan</span>
                </button>
                <Link
                  to="/scan/new"
                  className="px-4 py-2 rounded-lg text-sm font-medium bg-[#122372] text-[#DB9F75] hover:bg-[#3E2411] border border-[#545748] transition-colors"
                >
                  New Scan
                </Link>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* 3. STATE: SCAN COMPLETED DASHBOARD */}
      {isCompleted && (
        <div className="space-y-8">
          {/* Summary Cards Grid */}
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 sm:gap-4">
            <div className="bg-[#122372] border border-[#545748] rounded-xl p-4 text-center shadow-md">
              <p className="text-xs font-medium text-[#545748] uppercase tracking-wider">Total Issues</p>
              <p className="text-2xl sm:text-3xl font-extrabold text-[#DB9F75] mt-2 font-mono">
                {totalFindingsCount}
              </p>
            </div>
            <div className="bg-[#3E2411] border border-[#804012] rounded-xl p-4 text-center shadow-md">
              <p className="text-xs font-medium text-[#804012] uppercase tracking-wider">Critical</p>
              <p className="text-2xl sm:text-3xl font-extrabold text-[#804012] mt-2 font-mono">
                {criticalCount}
              </p>
            </div>
            <div className="bg-[#3E2411] border border-[#804012]/60 rounded-xl p-4 text-center shadow-md">
              <p className="text-xs font-medium text-[#804012] uppercase tracking-wider">High</p>
              <p className="text-2xl sm:text-3xl font-extrabold text-[#804012] mt-2 font-mono">
                {highCount}
              </p>
            </div>
            <div className="bg-[#122372] border border-[#545748] rounded-xl p-4 text-center shadow-md">
              <p className="text-xs font-medium text-[#DB9F75] uppercase tracking-wider">Medium</p>
              <p className="text-2xl sm:text-3xl font-extrabold text-[#DB9F75] mt-2 font-mono">
                {mediumCount}
              </p>
            </div>
            <div className="bg-[#122372] border border-[#545748]/50 rounded-xl p-4 text-center shadow-md">
              <p className="text-xs font-medium text-[#545748] uppercase tracking-wider">Low</p>
              <p className="text-2xl sm:text-3xl font-extrabold text-[#DB9F75] mt-2 font-mono">
                {lowCount}
              </p>
            </div>
            <div className="bg-[#122372] border border-[#545748]/30 rounded-xl p-4 text-center shadow-md">
              <p className="text-xs font-medium text-[#545748] uppercase tracking-wider">Info</p>
              <p className="text-2xl sm:text-3xl font-extrabold text-[#545748] mt-2 font-mono">
                {infoCount}
              </p>
            </div>
          </div>

          {/* Severity Distribution Bar */}
          <div className="bg-[#122372] border border-[#545748] rounded-xl p-5 space-y-3 shadow-md">
            <div className="flex items-center justify-between text-xs text-[#545748]">
              <span className="font-semibold text-[#DB9F75]">Severity Distribution</span>
              <span>{totalFindingsCount} Total Findings</span>
            </div>

            {totalFindingsCount > 0 && distributionPercents ? (
              <div className="w-full h-3 rounded-full overflow-hidden flex bg-[#3E2411] border border-[#545748]">
                {distributionPercents.critical > 0 && (
                  <div
                    className="bg-[#804012] transition-all"
                    style={{ width: `${distributionPercents.critical}%` }}
                    title={`Critical: ${criticalCount}`}
                  />
                )}
                {distributionPercents.high > 0 && (
                  <div
                    className="bg-[#804012]/80 transition-all"
                    style={{ width: `${distributionPercents.high}%` }}
                    title={`High: ${highCount}`}
                  />
                )}
                {distributionPercents.medium > 0 && (
                  <div
                    className="bg-[#DB9F75] transition-all"
                    style={{ width: `${distributionPercents.medium}%` }}
                    title={`Medium: ${mediumCount}`}
                  />
                )}
                {distributionPercents.low > 0 && (
                  <div
                    className="bg-[#545748] transition-all"
                    style={{ width: `${distributionPercents.low}%` }}
                    title={`Low: ${lowCount}`}
                  />
                )}
                {distributionPercents.info > 0 && (
                  <div
                    className="bg-[#545748]/60 transition-all"
                    style={{ width: `${distributionPercents.info}%` }}
                    title={`Info: ${infoCount}`}
                  />
                )}
              </div>
            ) : (
              <div className="w-full h-3 rounded-full bg-[#3E2411] border border-[#DB9F75]/40 flex items-center justify-center">
                <span className="text-[10px] text-[#DB9F75] font-semibold">Zero Vulnerabilities</span>
              </div>
            )}
          </div>

          {/* Scanner Coverage Section */}
          <div className="bg-[#122372] border border-[#545748] rounded-xl p-5 space-y-4 shadow-md">
            <h3 className="text-sm font-semibold text-[#DB9F75] flex items-center gap-2">
              <Layers className="h-4 w-4 text-[#DB9F75]" />
              <span>Scanner Coverage & Engine Results</span>
            </h3>

            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
              {scan.scannerResults &&
                Object.entries(scan.scannerResults).map(([key, val]) => (
                  <div
                    key={key}
                    className="bg-[#3E2411] border border-[#545748] rounded-lg p-3.5 flex items-center justify-between shadow-sm"
                  >
                    <div>
                      <p className="text-xs font-semibold text-[#DB9F75]">
                        {SCANNER_LABELS[key] || key}
                      </p>
                      <p className="text-xs text-[#545748] mt-0.5">
                        {val?.findingCount ?? 0} {val?.findingCount === 1 ? 'issue' : 'issues'} found
                      </p>
                    </div>
                    <span className={getStatusBadge(val?.status || 'completed')}>
                      {val?.status || 'completed'}
                    </span>
                  </div>
                ))}
            </div>
          </div>

          {/* Findings Filter Bar & List */}
          <div className="space-y-4">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 bg-[#122372] border border-[#545748] rounded-xl p-4 shadow-md">
              {/* Search */}
              <div className="relative flex-1">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-[#545748]">
                  <Search className="h-4 w-4" />
                </div>
                <input
                  type="text"
                  placeholder="Filter findings by title, rule, or file path..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="w-full bg-[#3E2411] border border-[#545748] rounded-lg pl-9 pr-4 py-2 text-xs text-[#DB9F75] placeholder-[#545748] focus:outline-none focus:border-[#DB9F75]"
                />
              </div>

              {/* Dropdowns */}
              <div className="flex items-center gap-2 flex-wrap">
                <select
                  value={severityFilter}
                  onChange={(e) => setSeverityFilter(e.target.value)}
                  className="bg-[#3E2411] border border-[#545748] text-[#DB9F75] text-xs rounded-lg px-3 py-2 focus:outline-none focus:border-[#DB9F75]"
                >
                  <option value="">All Severities</option>
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                  <option value="info">Info</option>
                </select>

                <select
                  value={categoryFilter}
                  onChange={(e) => setCategoryFilter(e.target.value)}
                  className="bg-[#3E2411] border border-[#545748] text-[#DB9F75] text-xs rounded-lg px-3 py-2 focus:outline-none focus:border-[#DB9F75]"
                >
                  <option value="">All Categories</option>
                  <option value="secrets">Secrets</option>
                  <option value="dependencies">Dependencies</option>
                  <option value="source-code">Source Code</option>
                  <option value="configuration">Configuration</option>
                </select>

                {(severityFilter || categoryFilter || searchQuery) && (
                  <button
                    onClick={() => {
                      setSeverityFilter('');
                      setCategoryFilter('');
                      setSearchQuery('');
                    }}
                    className="px-2.5 py-1.5 text-xs text-[#545748] hover:text-[#DB9F75] bg-[#3E2411] hover:bg-[#804012] rounded-lg transition-colors"
                  >
                    Reset
                  </button>
                )}
              </div>
            </div>

            {/* Findings Rendering */}
            {isLoadingFindings ? (
              <div className="py-12 text-center">
                <LoadingSpinner size="md" />
                <p className="mt-3 text-xs text-[#545748]">Filtering findings...</p>
              </div>
            ) : findings.length > 0 ? (
              <div className="space-y-3">
                {findings.map((finding) => (
                  <FindingCard
                    key={finding.findingId}
                    finding={finding}
                    onClick={() => navigate(`/findings/${finding.findingId}`)}
                  />
                ))}
              </div>
            ) : totalFindingsCount === 0 ? (
              <div className="bg-[#122372] border border-[#545748] rounded-xl p-12 text-center shadow-lg">
                <ShieldCheck className="h-16 w-16 text-[#DB9F75] mx-auto mb-4" />
                <h3 className="text-xl font-bold text-[#DB9F75]">Clean Bill of Health!</h3>
                <p className="text-sm text-[#545748] mt-2 max-w-md mx-auto">
                  No security vulnerabilities or weaknesses were detected across scanned files.
                </p>
                <div className="mt-6">
                  <Link
                    to="/scan/new"
                    className="inline-flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-semibold bg-[#DB9F75] text-[#122372] hover:bg-[#804012] hover:text-[#DB9F75] border border-[#DB9F75] transition-colors shadow-md"
                  >
                    Scan Another Repository
                  </Link>
                </div>
              </div>
            ) : (
              <div className="bg-[#122372] border border-[#545748] rounded-xl p-8 shadow-md">
                <EmptyState
                  title="No findings match your filters"
                  description="Try adjusting your severity filter, category filter, or search query."
                  action={
                    <button
                      onClick={() => {
                        setSeverityFilter('');
                        setCategoryFilter('');
                        setSearchQuery('');
                      }}
                      className="mt-4 px-4 py-2 text-xs font-semibold text-[#DB9F75] bg-[#3E2411] border border-[#545748] hover:bg-[#804012] rounded-lg transition-colors"
                    >
                      Clear Filters
                    </button>
                  }
                />
              </div>
            )}
          </div>
        </div>
      )}

      {/* Confirm Delete Dialog */}
      <ConfirmDialog
        isOpen={showDeleteConfirm}
        title="Delete Security Scan"
        message="Are you sure you want to permanently delete this scan and all associated findings? This action cannot be undone."
        confirmLabel={isDeleting ? 'Deleting...' : 'Delete Scan'}
        danger={true}
        onConfirm={handleDelete}
        onCancel={() => setShowDeleteConfirm(false)}
      />
    </div>
  );
}

import { useState, useEffect, useCallback } from 'react';
import { useParams, Link } from 'react-router-dom';
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { vscDarkPlus } from 'react-syntax-highlighter/dist/esm/styles/prism';
import {
  ArrowLeft,
  FileCode,
  Shield,
  Sparkles,
  Copy,
  Check,
  Download,
  AlertTriangle,
  ExternalLink,
  ShieldCheck,
  ShieldAlert,
  HelpCircle,
  FileText,
  Activity,
  Layers,
} from 'lucide-react';
import {
  getFinding,
  proposeFix,
  updateFindingStatus,
} from '../services/api';
import useOwnerToken from '../hooks/useOwnerToken';
import SeverityBadge from '../components/SeverityBadge';
import { getCategoryBadgeClasses } from '../utils/severity';
import LoadingSpinner from '../components/LoadingSpinner';

function getLanguageFromPath(filePath) {
  if (!filePath) return 'javascript';
  const ext = filePath.split('.').pop().toLowerCase();
  switch (ext) {
    case 'jsx':
    case 'js':
    case 'mjs':
    case 'cjs':
      return 'javascript';
    case 'ts':
    case 'tsx':
      return 'typescript';
    case 'json':
      return 'json';
    case 'html':
      return 'html';
    case 'css':
      return 'css';
    case 'py':
      return 'python';
    case 'sh':
      return 'bash';
    case 'yml':
    case 'yaml':
      return 'yaml';
    default:
      return 'javascript';
  }
}

function getVerificationBadgeClasses(status) {
  switch (status) {
    case 'passed':
      return 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30';
    case 'failed':
      return 'bg-red-500/20 text-red-400 border border-red-500/30';
    case 'inconclusive':
      return 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30';
    default:
      return 'bg-gray-800 text-gray-400 border border-gray-700';
  }
}

function getConfidenceBadgeClasses(confidence) {
  switch (confidence) {
    case 'high':
      return 'bg-orange-500/20 text-orange-400 border border-orange-500/30';
    case 'medium':
      return 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30';
    case 'low':
      return 'bg-blue-500/20 text-blue-400 border border-blue-500/30';
    default:
      return 'bg-gray-800 text-gray-400 border border-gray-700';
  }
}

export default function FindingDetailPage() {
  const { findingId } = useParams();
  const ownerToken = useOwnerToken();

  const [finding, setFinding] = useState(null);
  const [isLoading, setIsLoading] = useState(true);
  const [errorMessage, setErrorMessage] = useState(null);

  // Remediation / Fix generation states
  const [fixData, setFixData] = useState(null);
  const [isGeneratingFix, setIsGeneratingFix] = useState(false);
  const [fixError, setFixError] = useState(null);
  const [copied, setCopied] = useState(false);

  // Status update state
  const [isUpdatingStatus, setIsUpdatingStatus] = useState(false);

  // Fetch finding details
  const fetchFinding = useCallback(async () => {
    if (!findingId) return;
    try {
      setIsLoading(true);
      const res = await getFinding(findingId, ownerToken);
      const data = res?.data || res;
      setFinding(data);
      if (data?.fixedCode) {
        setFixData({
          originalCode: data.codeSnippet || data.evidence || '',
          fixedCode: data.fixedCode,
          explanation: data.remediation || 'Remediation fix generated.',
          risks: '',
        });
      }
      setErrorMessage(null);
    } catch (err) {
      console.error('Failed to load finding details:', err);
      setErrorMessage(err.message || 'Failed to load finding details');
    } finally {
      setIsLoading(false);
    }
  }, [findingId, ownerToken]);

  useEffect(() => {
    fetchFinding();
  }, [fetchFinding]);

  // Handle status update
  const handleStatusChange = async (newStatus) => {
    if (!newStatus || newStatus === finding?.status) return;
    try {
      setIsUpdatingStatus(true);
      const res = await updateFindingStatus(findingId, newStatus, ownerToken);
      const updated = res?.data || res;
      setFinding((prev) => ({
        ...prev,
        status: updated?.status || newStatus,
      }));
    } catch (err) {
      alert(`Failed to update status: ${err.message}`);
    } finally {
      setIsUpdatingStatus(false);
    }
  };

  // Handle Propose Fix API call
  const handleGenerateFix = async () => {
    try {
      setIsGeneratingFix(true);
      setFixError(null);
      const res = await proposeFix(findingId, ownerToken);
      const fix = res?.data || res;
      setFixData(fix);
      setFinding((prev) => ({
        ...prev,
        status: 'fix-proposed',
        fixedCode: fix?.fixedCode || prev?.fixedCode,
      }));
    } catch (err) {
      setFixError(err.message || 'Failed to generate remediation fix');
    } finally {
      setIsGeneratingFix(false);
    }
  };

  // Copy fixed code to clipboard
  const handleCopyFix = async () => {
    if (!fixData?.fixedCode) return;
    try {
      await navigator.clipboard.writeText(fixData.fixedCode);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (err) {
      console.error('Failed to copy to clipboard:', err);
    }
  };

  // Download Patch file
  const handleDownloadPatch = () => {
    if (!fixData?.fixedCode || !finding) return;
    const patchHeader = `# PatchPilot Remediation Patch
# Finding: ${finding.title}
# File: ${finding.filePath || 'unknown'} (Lines ${finding.startLine || 1}-${finding.endLine || finding.startLine || 1})
# Rule: ${finding.ruleId || 'N/A'}
# Date: ${new Date().toISOString()}

--- a/${finding.filePath || 'source-file'}
+++ b/${finding.filePath || 'source-file'}
@@ -${finding.startLine || 1},1 +${finding.startLine || 1},1 @@
${fixData.fixedCode}
`;
    const blob = new Blob([patchHeader], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `patch-${finding.findingId.slice(0, 8)}.txt`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  if (isLoading) {
    return (
      <div className="py-24 text-center">
        <LoadingSpinner size="lg" />
        <p className="mt-4 text-sm text-gray-400">Loading finding details...</p>
      </div>
    );
  }

  if (errorMessage || !finding) {
    return (
      <div className="py-16 px-4 max-w-xl mx-auto text-center">
        <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-6">
          <AlertTriangle className="h-12 w-12 text-red-400 mx-auto mb-3" />
          <h2 className="text-lg font-semibold text-gray-100">Finding Not Found</h2>
          <p className="text-sm text-red-300 mt-2">{errorMessage || 'Unable to locate finding details.'}</p>
          <div className="mt-6">
            <Link
              to="/history"
              className="inline-flex items-center gap-2 px-4 py-2 text-sm font-medium bg-gray-800 text-gray-300 hover:bg-gray-700 rounded-lg transition-colors"
            >
              <ArrowLeft className="h-4 w-4" />
              <span>Back to Scans</span>
            </Link>
          </div>
        </div>
      </div>
    );
  }

  const codeLang = getLanguageFromPath(finding.filePath);
  const displayEvidence = finding.codeSnippet || finding.evidence || '';

  return (
    <div className="py-8 px-4 sm:px-6 lg:px-8 max-w-5xl mx-auto space-y-6">
      {/* Breadcrumb Navigation */}
      <div>
        <Link
          to={`/scan/${finding.scanId}`}
          className="inline-flex items-center gap-1.5 text-sm font-medium text-gray-400 hover:text-gray-200 transition-colors"
        >
          <ArrowLeft className="h-4 w-4" />
          <span>Back to Scan Report</span>
        </Link>
      </div>

      {/* Main Finding Header Card */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-center gap-2 flex-wrap">
            <SeverityBadge severity={finding.severity} className="text-xs px-2.5 py-1" />
            <span className={getCategoryBadgeClasses(finding.category)}>
              {finding.category}
            </span>
            <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${getConfidenceBadgeClasses(finding.confidence)}`}>
              Confidence: {finding.confidence}
            </span>
            <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${getVerificationBadgeClasses(finding.verificationStatus)}`}>
              Verification: {finding.verificationStatus}
            </span>
          </div>

          {/* Status Dropdown */}
          <div className="flex items-center gap-2 self-start sm:self-auto">
            <span className="text-xs text-gray-500 font-medium">Status:</span>
            <select
              value={finding.status}
              disabled={isUpdatingStatus}
              onChange={(e) => handleStatusChange(e.target.value)}
              className="bg-gray-950 border border-gray-800 text-gray-200 text-xs rounded-lg px-3 py-1.5 focus:outline-none focus:border-emerald-500 disabled:opacity-50"
            >
              <option value="open">Open</option>
              <option value="accepted-risk">Accepted Risk</option>
              <option value="false-positive">False Positive</option>
              <option value="fix-proposed">Fix Proposed</option>
              <option value="fixed-verified">Fixed & Verified</option>
            </select>
          </div>
        </div>

        <div>
          <h1 className="text-2xl sm:text-3xl font-extrabold text-gray-100">
            {finding.title}
          </h1>

          <div className="flex items-center gap-4 text-xs text-gray-400 mt-2 flex-wrap">
            {finding.filePath && (
              <span className="flex items-center gap-1 font-mono text-gray-300">
                <FileCode className="h-3.5 w-3.5 text-emerald-400" />
                <span>{finding.filePath}</span>
                {finding.startLine && (
                  <span className="text-gray-500">
                    :L{finding.startLine}
                    {finding.endLine && finding.endLine !== finding.startLine ? `-${finding.endLine}` : ''}
                  </span>
                )}
              </span>
            )}

            {finding.ruleId && (
              <span className="font-mono text-gray-500">
                Rule ID: <span className="text-gray-400">{finding.ruleId}</span>
              </span>
            )}

            {finding.scanner && (
              <span className="text-gray-500">
                Scanner: <span className="text-gray-400 font-medium">{finding.scanner}</span>
              </span>
            )}
          </div>
        </div>
      </div>

      {/* Evidence Code Snippet Card */}
      {displayEvidence && (
        <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
          <div className="px-5 py-3.5 border-b border-gray-800 flex items-center justify-between bg-gray-950/40">
            <div className="flex items-center gap-2">
              <FileCode className="h-4 w-4 text-emerald-400" />
              <h2 className="text-sm font-semibold text-gray-200">Evidence & Code Snippet</h2>
            </div>
            {finding.filePath && (
              <span className="text-xs font-mono text-gray-500 truncate max-w-xs">
                {finding.filePath}
              </span>
            )}
          </div>

          <div className="p-4 bg-gray-950">
            <SyntaxHighlighter
              language={codeLang}
              style={vscDarkPlus}
              showLineNumbers={Boolean(finding.startLine)}
              startingLineNumber={finding.startLine || 1}
              customStyle={{
                margin: 0,
                borderRadius: '0.5rem',
                fontSize: '0.825rem',
                backgroundColor: 'transparent',
              }}
            >
              {displayEvidence}
            </SyntaxHighlighter>
          </div>
        </div>
      )}

      {/* Description Card */}
      {finding.description && (
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-5 space-y-2">
          <div className="flex items-center gap-2 text-gray-300">
            <FileText className="h-4 w-4 text-emerald-400" />
            <h2 className="text-sm font-semibold">Description</h2>
          </div>
          <p className="text-sm text-gray-300 leading-relaxed whitespace-pre-wrap">
            {finding.description}
          </p>
        </div>
      )}

      {/* Impact Card */}
      {finding.impact && (
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-5 space-y-2">
          <div className="flex items-center gap-2 text-gray-300">
            <ShieldAlert className="h-4 w-4 text-orange-400" />
            <h2 className="text-sm font-semibold">Security Impact</h2>
          </div>
          <p className="text-sm text-gray-300 leading-relaxed whitespace-pre-wrap">
            {finding.impact}
          </p>
        </div>
      )}

      {/* Remediation Instructions Card */}
      {finding.remediation && (
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-5 space-y-2">
          <div className="flex items-center gap-2 text-gray-300">
            <ShieldCheck className="h-4 w-4 text-emerald-400" />
            <h2 className="text-sm font-semibold">Remediation Guidance</h2>
          </div>
          <p className="text-sm text-gray-300 leading-relaxed whitespace-pre-wrap">
            {finding.remediation}
          </p>
        </div>
      )}

      {/* Generate Fix Proposal Section */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h2 className="text-base font-semibold text-gray-100 flex items-center gap-2">
              <Sparkles className="h-4 w-4 text-emerald-400" />
              <span>Automated Fix Proposal</span>
            </h2>
            <p className="text-xs text-gray-400 mt-0.5">
              Generate remediation code snippet and downloadable patch tailored to this vulnerability.
            </p>
          </div>

          <button
            onClick={handleGenerateFix}
            disabled={isGeneratingFix}
            className="inline-flex items-center justify-center gap-2 px-4 py-2 rounded-lg text-sm font-semibold text-gray-950 bg-emerald-400 hover:bg-emerald-300 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            {isGeneratingFix ? (
              <>
                <LoadingSpinner size="sm" className="text-gray-950" />
                <span>Generating Fix...</span>
              </>
            ) : (
              <>
                <Sparkles className="h-4 w-4 text-gray-950" />
                <span>{fixData ? 'Regenerate Fix' : 'Generate Fix'}</span>
              </>
            )}
          </button>
        </div>

        {fixError && (
          <div className="p-3.5 rounded-lg bg-red-500/10 border border-red-500/30 text-xs text-red-300">
            {fixError}
          </div>
        )}

        {/* Fix Display */}
        {fixData && (
          <div className="mt-4 space-y-4 pt-4 border-t border-gray-800">
            {/* Side-by-side or stacked diff: Original Code vs Fixed Code */}
            <div className="space-y-3">
              {fixData.originalCode && (
                <div className="rounded-lg border border-red-500/30 bg-red-950/20 overflow-hidden">
                  <div className="px-3.5 py-1.5 bg-red-500/10 border-b border-red-500/20 text-xs font-semibold text-red-400 flex items-center justify-between">
                    <span>Original Code</span>
                    <span className="text-[10px] uppercase font-mono">Vulnerable</span>
                  </div>
                  <div className="p-3">
                    <SyntaxHighlighter
                      language={codeLang}
                      style={vscDarkPlus}
                      customStyle={{
                        margin: 0,
                        backgroundColor: 'transparent',
                        fontSize: '0.8rem',
                      }}
                    >
                      {fixData.originalCode}
                    </SyntaxHighlighter>
                  </div>
                </div>
              )}

              {fixData.fixedCode && (
                <div className="rounded-lg border border-emerald-500/30 bg-emerald-950/20 overflow-hidden">
                  <div className="px-3.5 py-1.5 bg-emerald-500/10 border-b border-emerald-500/20 text-xs font-semibold text-emerald-400 flex items-center justify-between">
                    <span>Proposed Fixed Code</span>
                    <span className="text-[10px] uppercase font-mono">Remediated</span>
                  </div>
                  <div className="p-3">
                    <SyntaxHighlighter
                      language={codeLang}
                      style={vscDarkPlus}
                      customStyle={{
                        margin: 0,
                        backgroundColor: 'transparent',
                        fontSize: '0.8rem',
                      }}
                    >
                      {fixData.fixedCode}
                    </SyntaxHighlighter>
                  </div>
                </div>
              )}
            </div>

            {/* Explanation & Risks */}
            {fixData.explanation && (
              <div className="bg-gray-950 border border-gray-800 rounded-lg p-3.5 text-xs text-gray-300">
                <strong className="text-emerald-400">Fix Explanation: </strong>
                <span>{fixData.explanation}</span>
              </div>
            )}

            {fixData.risks && (
              <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-3.5 text-xs text-yellow-300 flex items-start gap-2">
                <AlertTriangle className="h-4 w-4 flex-shrink-0 mt-0.5 text-yellow-400" />
                <div>
                  <strong className="text-yellow-400">Implementation Considerations & Risks: </strong>
                  <span>{fixData.risks}</span>
                </div>
              </div>
            )}

            {/* Action Buttons for Fix */}
            <div className="flex items-center gap-3 pt-2 flex-wrap">
              <button
                type="button"
                onClick={handleCopyFix}
                className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg text-xs font-semibold bg-gray-800 hover:bg-gray-700 text-gray-200 border border-gray-700 transition-colors"
              >
                {copied ? (
                  <>
                    <Check className="h-3.5 w-3.5 text-emerald-400" />
                    <span className="text-emerald-400">Copied to Clipboard!</span>
                  </>
                ) : (
                  <>
                    <Copy className="h-3.5 w-3.5" />
                    <span>Copy Fix</span>
                  </>
                )}
              </button>

              <button
                type="button"
                onClick={handleDownloadPatch}
                className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg text-xs font-semibold bg-gray-800 hover:bg-gray-700 text-gray-200 border border-gray-700 transition-colors"
              >
                <Download className="h-3.5 w-3.5 text-emerald-400" />
                <span>Download Patch (.txt)</span>
              </button>
            </div>
          </div>
        )}
      </div>

      {/* External References Section */}
      {finding.references && finding.references.length > 0 && (
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-5 space-y-3">
          <h2 className="text-sm font-semibold text-gray-200 flex items-center gap-2">
            <ExternalLink className="h-4 w-4 text-emerald-400" />
            <span>References & Advisories</span>
          </h2>
          <ul className="space-y-1.5 text-xs">
            {finding.references.map((refUrl, idx) => (
              <li key={idx}>
                <a
                  href={refUrl}
                  target="_blank"
                  rel="noreferrer"
                  className="text-emerald-400 hover:underline flex items-center gap-1 truncate"
                >
                  <span className="truncate">{refUrl}</span>
                  <ExternalLink className="h-3 w-3 flex-shrink-0" />
                </a>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

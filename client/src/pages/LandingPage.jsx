import { useState, useEffect, useRef } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import {
  GitBranch,
  Upload,
  Play,
  LockKeyhole,
  Radar,
  Lock,
  Search,
  Code2,
  Terminal,
  Layers,
  ChevronRight,
  Sparkles,
  CloudUpload,
  FileArchive,
  AlertTriangle,
  CheckCircle2,
  ExternalLink,
} from 'lucide-react';
import { githubScan, uploadScan, getScans } from '../services/api';
import useOwnerToken from '../hooks/useOwnerToken';

const stages = [
  { label: 'Dependency audit', detail: 'Known CVEs & lockfile integrity', icon: Lock },
  { label: 'Secret detection', detail: 'Shannon entropy & token signatures', icon: Search },
  { label: 'AST static analysis', detail: 'Request-to-sink taint tracking', icon: Code2 },
  { label: 'Configuration review', detail: 'CORS, Helmet headers & cookie flags', icon: Terminal },
  { label: 'Framework hygiene', detail: 'Web storage tokens & console leaks', icon: Layers },
];

export default function LandingPage() {
  const [activeTab, setActiveTab] = useState('github'); // 'github' | 'upload'
  const [githubUrl, setGithubUrl] = useState('');
  const [selectedFile, setSelectedFile] = useState(null);
  const [isDragging, setIsDragging] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [errorMessage, setErrorMessage] = useState(null);

  const [recentScans, setRecentScans] = useState([]);
  const [isLoadingHistory, setIsLoadingHistory] = useState(true);

  const fileInputRef = useRef(null);
  const navigate = useNavigate();
  const ownerToken = useOwnerToken();

  // Load actual recent scans from MongoDB
  useEffect(() => {
    async function loadScans() {
      try {
        setIsLoadingHistory(true);
        const res = await getScans(ownerToken);
        const list = res?.data || res || [];
        setRecentScans(Array.isArray(list) ? list.slice(0, 5) : []);
      } catch (err) {
        console.warn('Unable to load recent scans:', err.message);
      } finally {
        setIsLoadingHistory(false);
      }
    }
    loadScans();
  }, [ownerToken]);

  // Handle GitHub Scan Submission
  const handleGithubSubmit = async (e) => {
    e.preventDefault();
    setErrorMessage(null);

    const trimmed = githubUrl.trim();
    if (!trimmed) {
      setErrorMessage('Please enter a public GitHub repository URL.');
      return;
    }

    if (!trimmed.startsWith('https://github.com/')) {
      setErrorMessage('Repository URL must begin with https://github.com/owner/repository');
      return;
    }

    try {
      setIsSubmitting(true);
      const res = await githubScan(trimmed, ownerToken);
      const scanId = res?.data?.scanId || res?.scanId;
      if (!scanId) throw new Error('Scan initiated but no scan ID was returned.');
      navigate(`/scan/${scanId}`);
    } catch (err) {
      setErrorMessage(err.message || 'Failed to start GitHub scan. Please verify repository is public.');
      setIsSubmitting(false);
    }
  };

  // Handle ZIP Archive Upload
  const handleFileProcess = async (file) => {
    if (!file) return;
    if (!file.name.toLowerCase().endsWith('.zip')) {
      setErrorMessage('Only .zip archive files are supported.');
      return;
    }
    if (file.size > 50 * 1024 * 1024) {
      setErrorMessage('Archive size exceeds the 50MB limit.');
      return;
    }

    try {
      setIsSubmitting(true);
      setErrorMessage(null);
      const res = await uploadScan(file, ownerToken);
      const scanId = res?.data?.scanId || res?.scanId;
      if (!scanId) throw new Error('Scan initiated but no scan ID was returned.');
      navigate(`/scan/${scanId}`);
    } catch (err) {
      setErrorMessage(err.message || 'Failed to upload archive. Please try again.');
      setIsSubmitting(false);
    }
  };

  const handleDragOver = (e) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = () => {
    setIsDragging(false);
  };

  const handleDrop = (e) => {
    e.preventDefault();
    setIsDragging(false);
    const file = e.dataTransfer.files?.[0];
    if (file) {
      setSelectedFile(file);
      handleFileProcess(file);
    }
  };

  return (
    <div className="min-h-screen text-stone-100">
      {/* Hero Section */}
      <section className="relative mx-auto max-w-7xl px-5 pb-16 pt-12 lg:px-8 lg:pt-18">
        <div className="max-w-3xl">
          <div className="mb-6 inline-flex items-center gap-2 rounded-full border border-blue-400/20 bg-blue-400/[0.06] px-3.5 py-1.5 font-mono text-[11px] uppercase tracking-[0.18em] text-blue-300">
            <Sparkles className="size-3.5" /> Deterministic Security Engine
          </div>

          <h1 className="text-balance text-4xl sm:text-5xl lg:text-6xl font-extrabold leading-[1.08] tracking-[-0.04em] text-white">
            Ship with confidence.<br />
            <span className="text-slate-500">Find vulnerabilities before they deploy.</span>
          </h1>

          <p className="mt-6 max-w-xl text-base leading-7 text-slate-400 sm:text-lg">
            A developer-first security scanner that analyzes AST code paths, detects leaked secrets via Shannon entropy, reviews configuration posture, and generates verified remediation patches.
          </p>
        </div>

        {/* Scan Input & Defense Layers Grid */}
        <div className="mt-12 grid gap-5 lg:grid-cols-[1.45fr_0.85fr]">
          {/* Main Action Widget */}
          <div className="rounded-md border border-white/10 bg-[#0e1319]/90 p-2 shadow-2xl shadow-black/40 backdrop-blur">
            {/* Tab Switcher */}
            <div className="flex gap-1 rounded-sm bg-black/30 p-1">
              <button
                type="button"
                onClick={() => { setActiveTab('github'); setErrorMessage(null); }}
                className={`flex flex-1 items-center justify-center gap-2 rounded-sm px-4 py-3 text-sm font-medium transition ${
                  activeTab === 'github'
                    ? 'bg-white/[0.09] text-white shadow-sm'
                    : 'text-slate-500 hover:text-slate-300'
                }`}
              >
                <GitBranch className="size-4" />
                <span>GitHub repository</span>
              </button>

              <button
                type="button"
                onClick={() => { setActiveTab('upload'); setErrorMessage(null); }}
                className={`flex flex-1 items-center justify-center gap-2 rounded-sm px-4 py-3 text-sm font-medium transition ${
                  activeTab === 'upload'
                    ? 'bg-white/[0.09] text-white shadow-sm'
                    : 'text-slate-500 hover:text-slate-300'
                }`}
              >
                <Upload className="size-4" />
                <span>Upload archive</span>
              </button>
            </div>

            {/* Tab 1: GitHub Repository Input */}
            <div className="p-6 sm:p-8">
              {errorMessage && (
                <div className="mb-5 flex items-start gap-2.5 rounded-sm border border-red-500/30 bg-red-500/10 p-3 text-xs text-red-300">
                  <AlertTriangle className="size-4 flex-shrink-0 mt-0.5" />
                  <span>{errorMessage}</span>
                </div>
              )}

              {activeTab === 'github' ? (
                <>
                  <div className="mb-5">
                    <p className="text-base font-semibold text-white">Scan a public repository</p>
                    <p className="mt-1 text-sm text-slate-400">
                      Paste a GitHub URL to trigger our 5-stage automated security analysis.
                    </p>
                  </div>

                  <form onSubmit={handleGithubSubmit} className="flex flex-col gap-3 sm:flex-row">
                    <div className="flex flex-1 items-center gap-3 rounded-sm border border-white/10 bg-black/30 px-4 py-3.5 focus-within:border-blue-400/50 transition-colors">
                      <GitBranch className="size-4 text-slate-500" />
                      <input
                        type="url"
                        value={githubUrl}
                        onChange={(e) => setGithubUrl(e.target.value)}
                        placeholder="https://github.com/expressjs/express"
                        className="min-w-0 flex-1 bg-transparent font-mono text-sm text-white outline-none placeholder:text-slate-600"
                        disabled={isSubmitting}
                      />
                    </div>

                    <button
                      type="submit"
                      disabled={isSubmitting}
                      className="inline-flex items-center justify-center gap-2 rounded-sm bg-blue-500 px-5 py-3.5 text-sm font-semibold text-white transition hover:bg-blue-400 disabled:opacity-50"
                    >
                      <Play className="size-4 fill-current" />
                      <span>{isSubmitting ? 'Analyzing...' : 'Start scan'}</span>
                    </button>
                  </form>

                  <div className="mt-4 flex flex-wrap items-center justify-between gap-2 text-xs text-slate-500">
                    <span className="flex items-center gap-1.5">
                      <LockKeyhole className="size-3 text-slate-400" />
                      Isolated container extraction · Zero code retention
                    </span>

                    <button
                      type="button"
                      onClick={() => setGithubUrl('https://github.com/expressjs/express')}
                      className="text-blue-400 hover:text-blue-300 transition-colors underline underline-offset-2"
                    >
                      Load demo repo (express)
                    </button>
                  </div>
                </>
              ) : (
                /* Tab 2: ZIP File Drag-and-Drop */
                <div>
                  <div className="mb-5">
                    <p className="text-base font-semibold text-white">Upload project archive</p>
                    <p className="mt-1 text-sm text-slate-400">
                      Upload your project codebase as a compressed .zip archive for on-premise style scanning.
                    </p>
                  </div>

                  <input
                    ref={fileInputRef}
                    type="file"
                    accept=".zip,application/zip"
                    onChange={(e) => {
                      const file = e.target.files?.[0];
                      if (file) {
                        setSelectedFile(file);
                        handleFileProcess(file);
                      }
                    }}
                    className="hidden"
                  />

                  <div
                    onDragOver={handleDragOver}
                    onDragLeave={handleDragLeave}
                    onDrop={handleDrop}
                    onClick={() => fileInputRef.current?.click()}
                    className={`group flex min-h-48 w-full flex-col items-center justify-center rounded-sm border border-dashed cursor-pointer transition p-6 text-center ${
                      isDragging
                        ? 'border-blue-400 bg-blue-400/[0.08]'
                        : 'border-white/15 bg-black/20 hover:border-blue-400/50 hover:bg-blue-400/[0.03]'
                    }`}
                  >
                    <CloudUpload className="mb-3 size-9 text-slate-500 transition group-hover:text-blue-300" />
                    <p className="text-sm font-medium text-slate-200">
                      {isSubmitting
                        ? 'Uploading & extracting archive...'
                        : selectedFile
                        ? selectedFile.name
                        : 'Drop your project .zip archive here'}
                    </p>
                    <p className="mt-1 text-xs text-slate-500">
                      or click to browse from device · up to 50 MB
                    </p>
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* Right Card: What We Check (5 Layers) */}
          <div className="rounded-md border border-white/10 bg-[#11161d] p-6 flex flex-col justify-between">
            <div>
              <div className="mb-6 flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className="grid size-10 place-items-center rounded-sm bg-blue-400/10 text-blue-400 border border-blue-400/20">
                    <Radar className="size-5" />
                  </div>
                  <div>
                    <p className="text-sm font-semibold text-white">What we inspect</p>
                    <p className="text-xs text-slate-500">Five defensive layers</p>
                  </div>
                </div>
                <span className="font-mono text-xs text-slate-500">v1.0.0</span>
              </div>

              <div className="flex flex-col gap-4">
                {stages.map((stage, index) => {
                  const Icon = stage.icon;
                  return (
                    <div key={stage.label} className="flex items-center gap-3">
                      <div className="relative grid size-8 place-items-center rounded-sm border border-white/10 bg-white/[0.03] text-slate-400 flex-shrink-0">
                        <Icon className="size-4" />
                        {index < stages.length - 1 && (
                          <span className="absolute left-1/2 top-full h-4 w-px bg-white/10" />
                        )}
                      </div>
                      <div className="min-w-0">
                        <p className="text-sm text-slate-200 font-medium truncate">{stage.label}</p>
                        <p className="font-mono text-[11px] text-slate-500 truncate">{stage.detail}</p>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            <div className="mt-6 pt-4 border-t border-white/[0.07] flex items-center justify-between text-xs text-slate-500">
              <span>AST Taint Engine Active</span>
              <span className="text-emerald-400 font-mono">100% On-Device</span>
            </div>
          </div>
        </div>
      </section>

      {/* Activity / Recent Scans Section */}
      <section className="relative border-t border-white/[0.07] bg-[#0d1015]">
        <div className="mx-auto max-w-7xl px-5 py-14 lg:px-8">
          <div className="mb-7 flex items-end justify-between">
            <div>
              <p className="font-mono text-[11px] uppercase tracking-[0.2em] text-blue-400">
                Workspace History
              </p>
              <h2 className="mt-2 text-2xl font-semibold tracking-tight text-white">
                Recent Scans
              </h2>
            </div>
            <Link
              to="/history"
              className="hidden items-center gap-1 text-sm text-slate-400 transition hover:text-white sm:flex"
            >
              <span>View all scans</span>
              <ChevronRight className="size-4" />
            </Link>
          </div>

          <div className="overflow-hidden rounded-md border border-white/10 bg-[#0e1319]">
            <div className="hidden grid-cols-[1.5fr_1fr_0.8fr_0.8fr_24px] gap-4 border-b border-white/[0.07] px-5 py-3 font-mono text-[10px] uppercase tracking-widest text-slate-500 sm:grid">
              <span>Project / Repository</span>
              <span>Source Type</span>
              <span>Date</span>
              <span>Security Result</span>
              <span />
            </div>

            {isLoadingHistory ? (
              <div className="py-8 text-center text-sm text-slate-500">
                Loading recent scan records...
              </div>
            ) : recentScans.length > 0 ? (
              recentScans.map((scan) => (
                <Link
                  key={scan.scanId}
                  to={`/scan/${scan.scanId}`}
                  className="grid grid-cols-[1fr_auto] items-center gap-4 border-b border-white/[0.06] px-5 py-4 last:border-0 hover:bg-white/[0.02] transition sm:grid-cols-[1.5fr_1fr_0.8fr_0.8fr_24px]"
                >
                  <div className="flex items-center gap-3">
                    <div className="grid size-8 place-items-center rounded-sm bg-white/[0.04] text-slate-400">
                      {scan.submissionType === 'github' ? (
                        <GitBranch className="size-4" />
                      ) : (
                        <FileArchive className="size-4" />
                      )}
                    </div>
                    <div>
                      <p className="text-sm font-medium text-slate-200">{scan.projectName}</p>
                      <p className="font-mono text-[11px] text-slate-500 sm:hidden">
                        {scan.submissionType} · {new Date(scan.createdAt).toLocaleDateString()}
                      </p>
                    </div>
                  </div>

                  <span className="hidden font-mono text-xs text-slate-400 sm:block uppercase">
                    {scan.submissionType}
                  </span>

                  <span className="hidden text-xs text-slate-500 sm:block">
                    {new Date(scan.createdAt).toLocaleDateString()}
                  </span>

                  <span
                    className={`text-right text-xs font-medium sm:text-left ${
                      scan.totalFindings > 0 ? 'text-amber-400' : 'text-emerald-400'
                    }`}
                  >
                    {scan.totalFindings > 0 ? `${scan.totalFindings} findings` : 'Clean'}
                  </span>

                  <ChevronRight className="hidden size-4 text-slate-600 sm:block" />
                </Link>
              ))
            ) : (
              <div className="py-12 text-center text-slate-500 text-sm">
                <FileArchive className="size-8 mx-auto mb-2 text-slate-600" />
                <p>No scans conducted yet in this workspace.</p>
                <p className="text-xs text-slate-600 mt-1">Paste a GitHub link above or upload a project ZIP to begin.</p>
              </div>
            )}
          </div>
        </div>
      </section>
    </div>
  );
}

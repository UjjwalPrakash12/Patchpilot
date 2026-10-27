import { useState, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  UploadCloud,
  Github,
  FileArchive,
  AlertCircle,
  X,
  ArrowRight,
  ShieldAlert,
  CheckCircle2,
  FileCode2,
} from 'lucide-react';
import { uploadScan, githubScan } from '../services/api';
import useOwnerToken from '../hooks/useOwnerToken';
import LoadingSpinner from '../components/LoadingSpinner';

function formatBytes(bytes) {
  if (!bytes || bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

const GITHUB_URL_REGEX = /^https:\/\/github\.com\/([a-zA-Z0-9_.-]+)\/([a-zA-Z0-9_.-]+?)(?:\.git|\/)?$/;

export default function NewScanPage() {
  const navigate = useNavigate();
  const ownerToken = useOwnerToken();

  const [activeTab, setActiveTab] = useState('zip'); // 'zip' | 'github'
  const [selectedFile, setSelectedFile] = useState(null);
  const [githubUrl, setGithubUrl] = useState('');
  const [urlTouched, setUrlTouched] = useState(false);
  const [isDragging, setIsDragging] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState(null);

  const fileInputRef = useRef(null);

  const isGithubValid = GITHUB_URL_REGEX.test(githubUrl.trim());
  const githubError =
    urlTouched && githubUrl.trim().length > 0 && !isGithubValid
      ? 'Please enter a valid GitHub repository URL in the format: https://github.com/owner/repository'
      : null;

  const handleDragOver = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(true);
  };

  const handleDragLeave = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);

    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      const file = e.dataTransfer.files[0];
      validateAndSetFile(file);
    }
  };

  const handleFileInputChange = (e) => {
    if (e.target.files && e.target.files.length > 0) {
      const file = e.target.files[0];
      validateAndSetFile(file);
    }
  };

  const validateAndSetFile = (file) => {
    setErrorMessage(null);
    if (!file.name.toLowerCase().endsWith('.zip')) {
      setErrorMessage('Only .zip archive files are supported.');
      return;
    }
    const maxSizeBytes = 50 * 1024 * 1024; // 50MB
    if (file.size > maxSizeBytes) {
      setErrorMessage('File size exceeds the 50MB limit.');
      return;
    }
    if (file.size === 0) {
      setErrorMessage('The selected file is empty.');
      return;
    }
    setSelectedFile(file);
  };

  const handleClearFile = (e) => {
    e.stopPropagation();
    setSelectedFile(null);
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  const handleZipSubmit = async (e) => {
    e.preventDefault();
    if (!selectedFile) {
      setErrorMessage('Please select a .zip archive to upload.');
      return;
    }

    try {
      setIsLoading(true);
      setErrorMessage(null);
      const response = await uploadScan(selectedFile, ownerToken);
      const scanId = response?.data?.scanId || response?.scanId;
      if (!scanId) {
        throw new Error('Scan initiated but no scan ID was returned.');
      }
      navigate(`/scan/${scanId}`);
    } catch (err) {
      setErrorMessage(err.message || 'Failed to upload archive. Please try again.');
      setIsLoading(false);
    }
  };

  const handleGithubSubmit = async (e) => {
    e.preventDefault();
    setUrlTouched(true);

    if (!githubUrl.trim()) {
      setErrorMessage('Please enter a GitHub repository URL.');
      return;
    }

    if (!isGithubValid) {
      setErrorMessage('Invalid GitHub repository URL. Must be in format: https://github.com/owner/repository');
      return;
    }

    try {
      setIsLoading(true);
      setErrorMessage(null);
      const response = await githubScan(githubUrl.trim(), ownerToken);
      const scanId = response?.data?.scanId || response?.scanId;
      if (!scanId) {
        throw new Error('Scan initiated but no scan ID was returned.');
      }
      navigate(`/scan/${scanId}`);
    } catch (err) {
      setErrorMessage(err.message || 'Failed to start GitHub scan. Please verify repository is public.');
      setIsLoading(false);
    }
  };

  return (
    <div className="py-12 px-4 sm:px-6 lg:px-8 max-w-3xl mx-auto">
      {/* Header */}
      <div className="text-center mb-8">
        <h1 className="text-3xl font-extrabold text-[#DB9F75]">Start New Security Scan</h1>
        <p className="mt-2 text-sm text-[#545748]">
          Upload your project files or link a public GitHub repository to run automated vulnerability checks.
        </p>
      </div>

      {/* Tabs */}
      <div className="bg-[#091026] border border-[#545748] rounded-xl overflow-hidden p-1 flex mb-6">
        <button
          type="button"
          onClick={() => {
            setActiveTab('zip');
            setErrorMessage(null);
          }}
          className={`flex-1 flex items-center justify-center gap-2 py-3 px-4 rounded-lg text-sm font-semibold transition-all ${
            activeTab === 'zip'
              ? 'bg-[#804012] text-[#DB9F75] shadow-sm'
              : 'text-[#DB9F75]/70 hover:text-[#DB9F75] hover:bg-[#3E2411]'
          }`}
        >
          <FileArchive className="h-4 w-4" />
          <span>Upload ZIP Archive</span>
        </button>
        <button
          type="button"
          onClick={() => {
            setActiveTab('github');
            setErrorMessage(null);
          }}
          className={`flex-1 flex items-center justify-center gap-2 py-3 px-4 rounded-lg text-sm font-semibold transition-all ${
            activeTab === 'github'
              ? 'bg-[#804012] text-[#DB9F75] shadow-sm'
              : 'text-[#DB9F75]/70 hover:text-[#DB9F75] hover:bg-[#3E2411]'
          }`}
        >
          <Github className="h-4 w-4" />
          <span>Public GitHub URL</span>
        </button>
      </div>

      {/* Error Message Banner */}
      {errorMessage && (
        <div className="mb-6 p-4 rounded-lg bg-[#3E2411] border border-[#804012] flex items-start justify-between gap-3">
          <div className="flex items-start gap-2.5 text-[#DB9F75] text-sm">
            <AlertCircle className="h-5 w-5 text-[#804012] flex-shrink-0 mt-0.5" />
            <span>{errorMessage}</span>
          </div>
          <button
            type="button"
            onClick={() => setErrorMessage(null)}
            className="text-[#545748] hover:text-[#DB9F75]"
          >
            <X className="h-4 w-4" />
          </button>
        </div>
      )}

      {/* Tab Panels */}
      <div className="bg-[#091026] border border-[#545748] rounded-xl p-6 sm:p-8 shadow-xl">
        {activeTab === 'zip' ? (
          <form onSubmit={handleZipSubmit} className="space-y-6">
            <div>
              <label className="block text-sm font-medium text-[#DB9F75] mb-2">
                Project Source Archive (.zip)
              </label>

              {/* Drag and Drop Zone */}
              <div
                onDragOver={handleDragOver}
                onDragLeave={handleDragLeave}
                onDrop={handleDrop}
                onClick={() => fileInputRef.current?.click()}
                className={`relative border-2 border-dashed rounded-xl p-8 text-center cursor-pointer transition-colors ${
                  isDragging
                    ? 'border-[#DB9F75] bg-[#3E2411]'
                    : selectedFile
                    ? 'border-[#DB9F75]/60 bg-[#3E2411]'
                    : 'border-[#545748] hover:border-[#DB9F75] bg-[#3E2411]'
                }`}
              >
                <input
                  ref={fileInputRef}
                  type="file"
                  accept=".zip,application/zip,application/x-zip-compressed"
                  onChange={handleFileInputChange}
                  className="hidden"
                />

                {selectedFile ? (
                  <div className="flex items-center justify-between bg-[#091026] border border-[#545748] rounded-lg p-4 text-left">
                    <div className="flex items-center gap-3 min-w-0">
                      <div className="p-2.5 rounded-lg bg-[#3E2411] text-[#DB9F75] border border-[#545748]">
                        <FileCode2 className="h-6 w-6" />
                      </div>
                      <div className="min-w-0">
                        <p className="text-sm font-semibold text-[#DB9F75] truncate">
                          {selectedFile.name}
                        </p>
                        <p className="text-xs text-[#545748]">
                          {formatBytes(selectedFile.size)}
                        </p>
                      </div>
                    </div>
                    <button
                      type="button"
                      onClick={handleClearFile}
                      className="p-1.5 text-[#545748] hover:text-[#DB9F75] hover:bg-[#3E2411] rounded-md transition-colors"
                      title="Remove file"
                    >
                      <X className="h-4 w-4" />
                    </button>
                  </div>
                ) : (
                  <div className="space-y-3">
                    <div className="mx-auto w-12 h-12 rounded-full bg-[#3E2411] border border-[#545748] flex items-center justify-center text-[#DB9F75]">
                      <UploadCloud className="h-6 w-6" />
                    </div>
                    <div>
                      <p className="text-sm font-medium text-[#DB9F75]">
                        <span className="text-[#DB9F75] underline decoration-dotted underline-offset-4 font-semibold">Click to browse</span> or drag and drop your ZIP file here
                      </p>
                      <p className="text-xs text-[#545748] mt-1">
                        Supported archive: .zip (Max size: 50MB)
                      </p>
                    </div>
                  </div>
                )}
              </div>
            </div>

            <div className="bg-[#3E2411] border border-[#545748] rounded-lg p-3 text-xs text-[#545748] flex items-center gap-2">
              <ShieldAlert className="h-4 w-4 text-[#804012] flex-shrink-0" />
              <span>
                Files are extracted in an isolated sandbox, scanned in-memory, and automatically deleted after processing.
              </span>
            </div>

            <button
              type="submit"
              disabled={isLoading || !selectedFile}
              className="w-full flex items-center justify-center gap-2 py-3 px-4 rounded-lg text-sm font-semibold text-[#091026] bg-[#DB9F75] hover:bg-[#804012] hover:text-[#DB9F75] border border-[#DB9F75] disabled:opacity-50 disabled:cursor-not-allowed transition-all shadow-md"
            >
              {isLoading ? (
                <>
                  <LoadingSpinner size="sm" className="text-[#091026]" />
                  <span>Uploading & Queuing Scan...</span>
                </>
              ) : (
                <>
                  <span>Start Security Scan</span>
                  <ArrowRight className="h-4 w-4" />
                </>
              )}
            </button>
          </form>
        ) : (
          <form onSubmit={handleGithubSubmit} className="space-y-6">
            <div>
              <label htmlFor="githubUrl" className="block text-sm font-medium text-[#DB9F75] mb-2">
                Public GitHub Repository URL
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-[#545748]">
                  <Github className="h-5 w-5" />
                </div>
                <input
                  id="githubUrl"
                  type="url"
                  placeholder="https://github.com/owner/repository"
                  value={githubUrl}
                  onChange={(e) => {
                    setGithubUrl(e.target.value);
                    if (!urlTouched) setUrlTouched(true);
                  }}
                  onBlur={() => setUrlTouched(true)}
                  className={`w-full bg-[#3E2411] border rounded-lg pl-11 pr-4 py-3 text-sm text-[#DB9F75] placeholder-[#545748] focus:outline-none focus:ring-1 transition-colors ${
                    githubError
                      ? 'border-[#804012] focus:border-[#804012] focus:ring-[#804012]'
                      : 'border-[#545748] focus:border-[#DB9F75] focus:ring-[#DB9F75]'
                  }`}
                />
              </div>

              {githubError && (
                <p className="mt-2 text-xs text-[#804012] flex items-center gap-1">
                  <AlertCircle className="h-3.5 w-3.5" />
                  <span>{githubError}</span>
                </p>
              )}

              <p className="mt-2 text-xs text-[#545748]">
                Only public repositories are currently supported. Enter the full URL, for example:{' '}
                <span className="font-mono text-[#DB9F75]">https://github.com/facebook/react</span>
              </p>
            </div>

            <div className="bg-[#3E2411] border border-[#545748] rounded-lg p-3 text-xs text-[#545748] flex items-center gap-2">
              <CheckCircle2 className="h-4 w-4 text-[#DB9F75] flex-shrink-0" />
              <span>
                PatchPilot will perform a shallow clone (depth 1) of the default branch and inspect project files.
              </span>
            </div>

            <button
              type="submit"
              disabled={isLoading || !githubUrl.trim() || !isGithubValid}
              className="w-full flex items-center justify-center gap-2 py-3 px-4 rounded-lg text-sm font-semibold text-[#091026] bg-[#DB9F75] hover:bg-[#804012] hover:text-[#DB9F75] border border-[#DB9F75] disabled:opacity-50 disabled:cursor-not-allowed transition-all shadow-md"
            >
              {isLoading ? (
                <>
                  <LoadingSpinner size="sm" className="text-[#091026]" />
                  <span>Cloning & Queuing Scan...</span>
                </>
              ) : (
                <>
                  <span>Start GitHub Scan</span>
                  <ArrowRight className="h-4 w-4" />
                </>
              )}
            </button>
          </form>
        )}
      </div>
    </div>
  );
}

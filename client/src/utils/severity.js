import { ShieldAlert, AlertTriangle, Info, ShieldX } from 'lucide-react';

export function getSeverityColor(severity) {
  const colors = {
    critical: 'text-[#804012]',
    high: 'text-[#804012]',
    medium: 'text-[#DB9F75]',
    low: 'text-[#545748]',
    info: 'text-[#545748]',
  };
  return colors[severity] || 'text-[#545748]';
}

export function getSeverityBg(severity) {
  const colors = {
    critical: 'bg-[#3E2411] border-[#804012]',
    high: 'bg-[#3E2411] border-[#804012]',
    medium: 'bg-[#122372] border-[#545748]',
    low: 'bg-[#122372] border-[#545748]',
    info: 'bg-[#2F3A32] border-[#545748]',
  };
  return colors[severity] || 'bg-[#2F3A32] border-[#545748]';
}

export function getSeverityBadgeClasses(severity) {
  const classes = {
    critical: 'bg-[#804012] text-[#DB9F75] border border-[#DB9F75]/40 shadow-sm',
    high: 'bg-[#3E2411] text-[#DB9F75] border border-[#804012]',
    medium: 'bg-[#122372] text-[#DB9F75] border border-[#DB9F75]/40',
    low: 'bg-[#2F3A32] text-[#DB9F75] border border-[#545748]',
    info: 'bg-[#2F3A32] text-[#545748] border border-[#545748]',
  };
  return `inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold ${classes[severity] || classes.info}`;
}

export function getSeverityIcon(severity) {
  const icons = {
    critical: ShieldX,
    high: ShieldAlert,
    medium: AlertTriangle,
    low: Info,
    info: Info,
  };
  return icons[severity] || Info;
}

export function getCategoryBadgeClasses(category) {
  const classes = {
    secrets: 'bg-[#3E2411] text-[#DB9F75] border border-[#804012]',
    dependencies: 'bg-[#122372] text-[#DB9F75] border border-[#545748]',
    'source-code': 'bg-[#122372] text-[#DB9F75] border border-[#804012]',
    configuration: 'bg-[#3E2411] text-[#DB9F75] border border-[#545748]',
  };
  return `inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${classes[category] || 'bg-[#122372] text-[#545748] border border-[#545748]'}`;
}

export function formatDate(dateString) {
  if (!dateString) return '—';
  const date = new Date(dateString);
  return date.toLocaleDateString('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
  });
}

export function formatDateTime(dateString) {
  if (!dateString) return '—';
  const date = new Date(dateString);
  return date.toLocaleString('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

export function getStatusBadgeClasses(status) {
  const classes = {
    open: 'bg-[#3E2411] text-[#DB9F75] border border-[#804012]',
    'fix-proposed': 'bg-[#122372] text-[#DB9F75] border border-[#DB9F75]/40',
    'fixed-verified': 'bg-[#122372] text-[#DB9F75] border border-[#545748]',
    'accepted-risk': 'bg-[#2F3A32] text-[#545748] border border-[#545748]',
    'false-positive': 'bg-[#2F3A32] text-[#545748] border border-[#122372]',
  };
  return `inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${classes[status] || classes.open}`;
}

export function formatDuration(start, end) {
  if (!start || !end) return '—';
  const diff = Math.max(0, new Date(end) - new Date(start));
  const seconds = Math.floor(diff / 1000);
  if (seconds < 60) return `${seconds}s`;
  const mins = Math.floor(seconds / 60);
  const remSec = seconds % 60;
  return `${mins}m ${remSec}s`;
}

export function getStatusBadge(status) {
  const map = {
    completed: 'inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold bg-[#122372] text-[#DB9F75] border border-[#545748]',
    pending: 'inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold bg-[#2F3A32] text-[#545748] border border-[#122372]',
    failed: 'inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold bg-[#3E2411] text-[#804012] border border-[#804012]',
  };
  return map[status] || map.pending;
}

export function getStatusColor(status) {
  const map = {
    completed: 'text-[#DB9F75]',
    preparing: 'text-[#DB9F75]',
    scanning: 'text-[#DB9F75]',
    analyzing: 'text-[#DB9F75]',
    failed: 'text-[#804012]',
    queued: 'text-[#545748]',
  };
  return map[status] || 'text-[#545748]';
}

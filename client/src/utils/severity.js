import { ShieldAlert, ShieldCheck, AlertTriangle, Info, ShieldX } from 'lucide-react';

export function getSeverityColor(severity) {
  const colors = {
    critical: 'text-red-400',
    high: 'text-orange-400',
    medium: 'text-yellow-400',
    low: 'text-blue-400',
    info: 'text-gray-400',
  };
  return colors[severity] || 'text-gray-400';
}

export function getSeverityBg(severity) {
  const colors = {
    critical: 'bg-red-500/10 border-red-500/30',
    high: 'bg-orange-500/10 border-orange-500/30',
    medium: 'bg-yellow-500/10 border-yellow-500/30',
    low: 'bg-blue-500/10 border-blue-500/30',
    info: 'bg-gray-500/10 border-gray-500/30',
  };
  return colors[severity] || 'bg-gray-500/10 border-gray-500/30';
}

export function getSeverityBadgeClasses(severity) {
  const classes = {
    critical: 'bg-red-500/20 text-red-400 border border-red-500/30',
    high: 'bg-orange-500/20 text-orange-400 border border-orange-500/30',
    medium: 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30',
    low: 'bg-blue-500/20 text-blue-400 border border-blue-500/30',
    info: 'bg-gray-500/20 text-gray-400 border border-gray-500/30',
  };
  return `inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${classes[severity] || classes.info}`;
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
    secrets: 'bg-purple-500/20 text-purple-400 border border-purple-500/30',
    dependencies: 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30',
    'source-code': 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30',
    configuration: 'bg-amber-500/20 text-amber-400 border border-amber-500/30',
  };
  return `inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${classes[category] || 'bg-gray-500/20 text-gray-400'}`;
}

export function formatDate(dateString) {
  if (!dateString) return '—';
  const date = new Date(dateString);
  return date.toLocaleDateString('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

export function formatDuration(start, end) {
  if (!start || !end) return '—';
  const ms = new Date(end) - new Date(start);
  if (ms < 1000) return `${ms}ms`;
  const seconds = Math.floor(ms / 1000);
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  const remainingSeconds = seconds % 60;
  return `${minutes}m ${remainingSeconds}s`;
}

export function getStatusColor(status) {
  const colors = {
    queued: 'text-gray-400',
    preparing: 'text-blue-400',
    scanning: 'text-yellow-400',
    analyzing: 'text-purple-400',
    completed: 'text-emerald-400',
    failed: 'text-red-400',
  };
  return colors[status] || 'text-gray-400';
}

export function getStatusBadge(status) {
  const classes = {
    queued: 'bg-gray-500/20 text-gray-400',
    preparing: 'bg-blue-500/20 text-blue-400',
    scanning: 'bg-yellow-500/20 text-yellow-400',
    analyzing: 'bg-purple-500/20 text-purple-400',
    completed: 'bg-emerald-500/20 text-emerald-400',
    failed: 'bg-red-500/20 text-red-400',
  };
  return `inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${classes[status] || classes.queued}`;
}

import { Loader2, CheckCircle, XCircle, Clock, Search, BarChart3, AlertTriangle } from 'lucide-react';
import { getStatusColor } from '../utils/severity';

const statusConfig = {
  queued: { icon: Clock, label: 'Queued' },
  preparing: { icon: Loader2, label: 'Preparing files...' },
  scanning: { icon: Search, label: 'Scanning...' },
  analyzing: { icon: BarChart3, label: 'Analyzing results...' },
  completed: { icon: CheckCircle, label: 'Completed' },
  failed: { icon: XCircle, label: 'Failed' },
};

export default function ScanStatusIndicator({ status, className = '' }) {
  const config = statusConfig[status] || statusConfig.queued;
  const Icon = config.icon;
  const isAnimated = ['preparing', 'scanning', 'analyzing'].includes(status);

  return (
    <div className={`flex items-center gap-2 ${className}`}>
      <Icon
        className={`h-5 w-5 ${getStatusColor(status)} ${isAnimated ? 'animate-spin' : ''}`}
      />
      <span className={`text-sm font-medium ${getStatusColor(status)}`}>
        {config.label}
      </span>
      {isAnimated && (
        <div className="flex space-x-1 ml-2">
          <div className="w-1.5 h-1.5 rounded-full bg-current animate-pulse-dot" style={{ animationDelay: '0ms' }} />
          <div className="w-1.5 h-1.5 rounded-full bg-current animate-pulse-dot" style={{ animationDelay: '300ms' }} />
          <div className="w-1.5 h-1.5 rounded-full bg-current animate-pulse-dot" style={{ animationDelay: '600ms' }} />
        </div>
      )}
    </div>
  );
}

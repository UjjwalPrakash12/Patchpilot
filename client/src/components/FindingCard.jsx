import SeverityBadge from './SeverityBadge';
import { getCategoryBadgeClasses } from '../utils/severity';
import { FileCode, ChevronRight } from 'lucide-react';

export default function FindingCard({ finding, onClick }) {
  return (
    <button
      onClick={() => onClick?.(finding)}
      className="w-full text-left bg-gray-900 border border-gray-800 rounded-lg p-4 hover:border-gray-700 hover:bg-gray-900/80 transition-all group"
    >
      <div className="flex items-start justify-between gap-3">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-2 flex-wrap">
            <SeverityBadge severity={finding.severity} />
            <span className={getCategoryBadgeClasses(finding.category)}>
              {finding.category}
            </span>
          </div>
          <h3 className="text-sm font-medium text-gray-200 mb-1 truncate">
            {finding.title}
          </h3>
          {finding.filePath && (
            <div className="flex items-center gap-1 text-xs text-gray-500">
              <FileCode className="h-3 w-3 flex-shrink-0" />
              <span className="truncate">{finding.filePath}</span>
              {finding.startLine && (
                <span className="text-gray-600">:L{finding.startLine}</span>
              )}
            </div>
          )}
          {finding.scanner && (
            <p className="text-xs text-gray-600 mt-1">
              Scanner: {finding.scanner}
            </p>
          )}
        </div>
        <ChevronRight className="h-4 w-4 text-gray-600 group-hover:text-gray-400 flex-shrink-0 mt-1" />
      </div>
    </button>
  );
}

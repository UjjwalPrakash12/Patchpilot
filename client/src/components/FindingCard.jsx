import SeverityBadge from './SeverityBadge';
import { getCategoryBadgeClasses } from '../utils/severity';
import { FileCode, ChevronRight } from 'lucide-react';

export default function FindingCard({ finding, onClick }) {
  return (
    <button
      onClick={() => onClick?.(finding)}
      className="w-full text-left bg-[#091026] border border-[#545748] rounded-lg p-4 hover:border-[#DB9F75] hover:bg-[#3E2411] transition-all group shadow-sm"
    >
      <div className="flex items-start justify-between gap-3">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-2 flex-wrap">
            <SeverityBadge severity={finding.severity} />
            <span className={getCategoryBadgeClasses(finding.category)}>
              {finding.category}
            </span>
          </div>
          <h3 className="text-sm font-semibold text-[#DB9F75] mb-1 truncate">
            {finding.title}
          </h3>
          {finding.filePath && (
            <div className="flex items-center gap-1 text-xs text-[#545748]">
              <FileCode className="h-3 w-3 flex-shrink-0 text-[#545748]" />
              <span className="truncate text-[#DB9F75]/80">{finding.filePath}</span>
              {finding.startLine && (
                <span className="text-[#DB9F75]">:L{finding.startLine}</span>
              )}
            </div>
          )}
          {finding.scanner && (
            <p className="text-xs text-[#545748] mt-1 font-mono">
              Scanner: <span className="text-[#DB9F75]/70">{finding.scanner}</span>
            </p>
          )}
        </div>
        <ChevronRight className="h-4 w-4 text-[#545748] group-hover:text-[#DB9F75] flex-shrink-0 mt-1 transition-colors" />
      </div>
    </button>
  );
}

import { getSeverityBadgeClasses } from '../utils/severity';

export default function SeverityBadge({ severity, className = '' }) {
  return (
    <span className={`${getSeverityBadgeClasses(severity)} ${className}`}>
      {severity}
    </span>
  );
}

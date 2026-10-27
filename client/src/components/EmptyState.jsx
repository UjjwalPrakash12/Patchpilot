import { FileQuestion } from 'lucide-react';

export default function EmptyState({ icon: Icon = FileQuestion, title, description, action }) {
  return (
    <div className="text-center py-12">
      <Icon className="h-12 w-12 text-[#545748] mx-auto mb-4" />
      <h3 className="text-lg font-semibold text-[#DB9F75] mb-2">{title}</h3>
      {description && (
        <p className="text-sm text-[#545748] mb-4 max-w-md mx-auto">{description}</p>
      )}
      {action}
    </div>
  );
}

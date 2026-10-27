import { AlertTriangle } from 'lucide-react';

export default function ConfirmDialog({ isOpen, title, message, onConfirm, onCancel, confirmLabel = 'Confirm', danger = false }) {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-[#2F3A32]/85 backdrop-blur-sm">
      <div className="bg-[#091026] border border-[#545748] rounded-xl p-6 max-w-md w-full mx-4 shadow-2xl">
        <div className="flex items-start gap-3 mb-4">
          <AlertTriangle className="h-5 w-5 flex-shrink-0 mt-0.5 text-[#804012]" />
          <div>
            <h3 className="text-lg font-semibold text-[#DB9F75]">{title}</h3>
            <p className="text-sm text-[#DB9F75]/80 mt-1">{message}</p>
          </div>
        </div>
        <div className="flex justify-end gap-3 mt-6">
          <button
            onClick={onCancel}
            className="px-4 py-2 text-sm font-medium text-[#DB9F75] hover:text-[#DB9F75] bg-[#3E2411] border border-[#545748] hover:bg-[#2F3A32] rounded-lg transition-colors"
          >
            Cancel
          </button>
          <button
            onClick={onConfirm}
            className="px-4 py-2 text-sm font-semibold rounded-lg transition-colors bg-[#804012] text-[#DB9F75] hover:bg-[#3E2411] border border-[#DB9F75]/30 shadow-md"
          >
            {confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}

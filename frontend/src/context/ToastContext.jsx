import { createContext, useContext, useState, useCallback } from 'react'
import { ShieldAlert, Info, CheckCircle, AlertTriangle, X } from 'lucide-react'

const ToastContext = createContext(null)

const ICONS = {
  critical: ShieldAlert,
  high:     AlertTriangle,
  medium:   AlertTriangle,
  low:      CheckCircle,
  info:     Info,
  success:  CheckCircle,
  error:    AlertTriangle,
}

const STYLES = {
  critical: 'border-critical/30 bg-critical/10',
  high:     'border-high/30 bg-high/10',
  medium:   'border-medium/30 bg-medium/10',
  low:      'border-low/30 bg-low/10',
  info:     'border-accent/30 bg-accent/10',
  success:  'border-low/30 bg-low/10',
  error:    'border-critical/30 bg-critical/10',
}

const ICON_COLORS = {
  critical: 'text-critical',
  high:     'text-high',
  medium:   'text-medium',
  low:      'text-low',
  info:     'text-accent',
  success:  'text-low',
  error:    'text-critical',
}

let _id = 0

export function ToastProvider({ children }) {
  const [toasts, setToasts] = useState([])

  const toast = useCallback((type, title, message, duration = 5000) => {
    const id = ++_id
    setToasts(prev => [...prev, { id, type, title, message }])
    setTimeout(() => setToasts(prev => prev.filter(t => t.id !== id)), duration)
  }, [])

  const dismiss = useCallback((id) => {
    setToasts(prev => prev.filter(t => t.id !== id))
  }, [])

  return (
    <ToastContext.Provider value={{ toast }}>
      {children}

      {/* Toast container */}
      <div className="fixed bottom-5 right-5 z-50 flex flex-col gap-2 max-w-sm w-full">
        {toasts.map(t => {
          const Icon = ICONS[t.type] ?? Info
          return (
            <div
              key={t.id}
              className={`flex items-start gap-3 px-4 py-3.5 rounded-xl border
                          backdrop-blur-sm shadow-xl animate-slide-in
                          ${STYLES[t.type] ?? STYLES.info}`}
            >
              <Icon size={15} className={`mt-0.5 shrink-0 ${ICON_COLORS[t.type]}`} />
              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium text-text">{t.title}</p>
                {t.message && (
                  <p className="text-xs text-dim mt-0.5 line-clamp-2">{t.message}</p>
                )}
              </div>
              <button
                onClick={() => dismiss(t.id)}
                className="text-subtle hover:text-dim shrink-0 mt-0.5"
              >
                <X size={13} />
              </button>
            </div>
          )
        })}
      </div>
    </ToastContext.Provider>
  )
}

export const useToast = () => useContext(ToastContext)

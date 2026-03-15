import { useState } from 'react'
import { Outlet } from 'react-router-dom'
import Sidebar from './Sidebar'
import { useSocket } from '../../hooks/useSocket'
import { useToast } from '../../context/ToastContext'
import { formatEventType } from '../../utils/helpers'

export default function Layout() {
  const [liveCount, setLiveCount] = useState(0)
  const { toast } = useToast()

  useSocket(
    (event) => {
      setLiveCount(c => c + 1)
      // Only toast critical and high to avoid noise
      if (['critical', 'high'].includes(event.severity)) {
        toast(
          event.severity,
          formatEventType(event.event_type),
          event.description,
          event.severity === 'critical' ? 8000 : 5000
        )
      }
    },
    null
  )

  return (
    <div className="flex h-screen overflow-hidden bg-bg">
      <Sidebar liveCount={liveCount} />
      <main className="ml-56 flex-1 overflow-y-auto">
        <div className="min-h-screen p-6">
          <Outlet />
        </div>
      </main>
    </div>
  )
}

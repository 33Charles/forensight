import { Navigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'
import { Spinner } from '../components/ui'

export function ProtectedRoute({ children, role }) {
  const { user, loading } = useAuth()

  if (loading) return (
    <div className="flex items-center justify-center h-screen">
      <Spinner size={24} />
    </div>
  )

  if (!user) return <Navigate to="/login" replace />

  if (role && user.role !== role) return (
    <div className="flex flex-col items-center justify-center h-screen gap-3">
      <p className="text-2xl font-display font-bold text-text">Access Denied</p>
      <p className="text-sm text-dim">You need <span className="font-mono text-accent">{role}</span> role to view this page.</p>
    </div>
  )

  return children
}

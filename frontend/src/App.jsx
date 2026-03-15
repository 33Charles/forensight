import { Routes, Route, Navigate } from 'react-router-dom'
import { AuthProvider } from './context/AuthContext'
import { ToastProvider } from './context/ToastContext'
import { ProtectedRoute } from './components/ProtectedRoute'
import Layout    from './components/layout/Layout'
import Login     from './pages/Login'
import Dashboard from './pages/Dashboard'
import Events    from './pages/Events'
import Logs      from './pages/Logs'
import Hosts     from './pages/Hosts'
import Users     from './pages/Users'
import Rules     from './pages/Rules'
import Ingest    from './pages/Ingest'

export default function App() {
  return (
    <AuthProvider>
      <ToastProvider>
        <Routes>
          <Route path="/login" element={<Login />} />

          <Route path="/" element={
            <ProtectedRoute>
              <Layout />
            </ProtectedRoute>
          }>
            <Route index          element={<Dashboard />} />
            <Route path="events"  element={<Events />} />
            <Route path="logs"    element={<Logs />} />
            <Route path="hosts"   element={<Hosts />} />
            <Route path="ingest"  element={
              <ProtectedRoute><Ingest /></ProtectedRoute>
            } />
            <Route path="users"   element={
              <ProtectedRoute role="admin"><Users /></ProtectedRoute>
            } />
            <Route path="rules"   element={
              <ProtectedRoute role="admin"><Rules /></ProtectedRoute>
            } />
          </Route>

          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </ToastProvider>
    </AuthProvider>
  )
}
